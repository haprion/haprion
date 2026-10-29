"""Issuing an ACME certificate: certbot with fixed parameters, then the registry, then publish.

Phase 11's gate is stated in minutes: a form, a button, and a usable
certificate on the chosen targets in under five. This module is the whole of
that path below the button, and it times itself so the gate is measured by
the code rather than by someone with a watch.

What the caller may say, and what it may not
--------------------------------------------
A domain, a challenge method, and targets that the registry already knows.
Nothing else reaches certbot. The credential file and the webroot come from
the runtime policy; the account, the key type and the lineage name are fixed
here. A caller that could pass an argument to certbot could pass
`--config-dir` and point every later renewal somewhere else, which is why the
argument list is assembled from validated pieces and never from the caller's
words.

The lineage is the certificate ID. `example.com` and `*.example.com` both
become the ID `example.com`; the wildcard form also covers the bare name, the
way the installation's existing wildcard does, and requires DNS-01 because no
CA issues a wildcard against an HTTP challenge (B36).

Order, and why
--------------
certbot first, the registry second, publish third. A registry entry for a
lineage that does not exist would make every later publish fail on that
entry; a lineage without an entry is invisible and harmless - `cert-list`
reports it as unregistered so it can be registered by hand. certbot's own
directory hooks are turned off for this one run: the renewal hook would
publish the whole registry before this entry is in it, and the publish that
follows here does that work once, with the entry present.

certbot's failure is the operator's failure message. Its output is captured
and returned verbatim in the error, because "the DNS record could not be
created" is what the operator needs to read, not "exit status 1".
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from haprion import (
    cert_delete,
    cert_registry,
    dns_profiles,
    dns_provider_catalog,
    exit_codes,
    ui_interface,
)
from haprion.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE, measure_registered
from haprion.cert_publish import (
    DEFAULT_LOCK_PATH,
    Deployer,
    Installer,
    PublishError,
    Report,
    publish,
    unpublished,
)
from haprion.config import (
    CERTIFICATE_ID,
    CLUSTER_ID,
    HOSTNAME,
    RECEIVER_FORMATS,
    RECEIVER_ID,
    PathPolicy,
    RuntimeConfig,
    load_runtime_config,
)

CERTBOT = "/usr/bin/certbot"
CERTBOT_TIMEOUT = 600
#
# What certbot needs on top of the provider's own wait: the ACME dialogue, the
# DNS API calls either side of the wait, and the deploy hook. The wait itself
# is the catalogue's and runs once per invocation, however many names.
#
CERTBOT_WORK_SECONDS = 300


def certbot_timeout(propagation_seconds: int) -> int:
    """How long one certbot run may take when its DNS plugin waits this long.

    Never below `CERTBOT_TIMEOUT`, which is what an HTTP-01 run or a fast
    provider has always had. A provider whose wait is 600 or 900 seconds would
    otherwise be killed during the wait, every time - and on the nightly
    renewal as much as on the form.
    """

    return max(CERTBOT_TIMEOUT, propagation_seconds + CERTBOT_WORK_SECONDS)


def longest_certbot_timeout() -> int:
    """The budget of the slowest provider in the catalogue: what a caller must outlast."""

    return max(
        certbot_timeout(provider.propagation_seconds)
        for provider in dns_provider_catalog.load_catalog()
    )


RENEWAL_DIRECTORY = Path("/etc/letsencrypt/renewal")
FIXED_ENVIRONMENT = {
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}
KEY_TYPE = "ecdsa"

type Method = Literal["dns-01", "http-01"]
METHODS: tuple[Method, ...] = ("dns-01", "http-01")


class IssueError(Exception):
    """A refusal or failure, with the code it is reported under.

    `details` is the envelope's `error.details`: evidence that does not fit a
    sentence. certbot's output goes there, under `diagnostics`, the same key
    `haprion-publish` puts the compiler's answer under - the interface already
    reads that key, and a message is capped at 2048 bytes while certbot's
    account of a failed DNS challenge is routinely longer.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_code: int = exit_codes.USAGE,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code
        self.details = details


@dataclass(frozen=True, slots=True)
class IssueRequest:
    certificate_id: str
    domains: tuple[str, ...]
    wildcard: bool
    method: Method
    clusters: tuple[str, ...]
    receivers: tuple[str, ...]
    dns_profile: str | None = None
    formats: Mapping[str, str] = field(default_factory=dict)
    """How each receiver is written; a receiver not named here gets `pem` (B159)."""
    interface: bool = False
    """The manager's own interface certificate (B188): no targets, published to nginx."""
    exportable: bool = False
    """To be taken out and installed by hand (B255): one name, no targets, an RSA key."""


@dataclass(frozen=True, slots=True)
class CertbotResult:
    returncode: int
    output: str


type Certbot = Callable[[Sequence[str], Mapping[str, str], int], CertbotResult]


@dataclass(frozen=True, slots=True)
class CertbotInvocation:
    arguments: tuple[str, ...]
    environment: Mapping[str, str]
    redactions: tuple[str, ...] = ()
    timeout: int = CERTBOT_TIMEOUT


@dataclass(frozen=True, slots=True)
class IssueResult:
    request: IssueRequest
    certbot_seconds: float
    total_seconds: float
    publish: Report
    #
    # True for a lineage that existed and was asked for again now (C9c):
    # the same act on the same names, forced before its time. Reported so
    # the row can say "renewed" rather than "issued" about it.
    #
    renewed: bool = False
    lineage: str | None = None
    #
    # D5: the entry that served the interface before this one, and what
    # became of it - deleted once this one is served, kept otherwise.
    #
    retired: Mapping[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.request.certificate_id,
            "lineage": self.lineage or self.request.certificate_id,
            "domains": list(self.request.domains),
            "method": self.request.method,
            "dns_profile": self.request.dns_profile,
            "targets": {
                "clusters": list(self.request.clusters),
                "receivers": list(self.request.receivers),
            },
            "certbot_seconds": round(self.certbot_seconds, 1),
            "total_seconds": round(self.total_seconds, 1),
            "publish": self.publish.as_dict(),
            "renewed": self.renewed,
            "interface": self.request.interface,
            "exportable": self.request.exportable,
            "retired": dict(self.retired) if self.retired is not None else None,
        }


#
# The request
#


def parse_domain(text: str) -> tuple[str, tuple[str, ...], bool]:
    """The certificate ID and the names the certificate must cover."""

    wildcard = text.startswith("*.")
    name = text[2:] if wildcard else text
    if not HOSTNAME.fullmatch(name) or not CERTIFICATE_ID.fullmatch(name):
        raise IssueError("bad_input", f"not a domain name: {text!r}")
    domains = (f"*.{name}", name) if wildcard else (name,)
    return name, domains, wildcard


def build_request(
    *,
    domain: str,
    method: str,
    clusters: Sequence[str],
    receivers: Sequence[str],
    runtime: RuntimeConfig,
    dns_profile: str | None = None,
    formats: Mapping[str, str] | None = None,
    interface: bool = False,
    exportable: bool = False,
) -> IssueRequest:
    certificate_id, domains, wildcard = parse_domain(domain)
    check_exportable(
        exportable, wildcard=wildcard, targets=bool(clusters or receivers), interface=interface
    )
    if method not in METHODS:
        raise IssueError("bad_input", f"method must be one of: {', '.join(METHODS)}")
    if wildcard and method != "dns-01":
        raise IssueError(
            "bad_input", "a wildcard certificate needs DNS-01; HTTP-01 cannot prove a wildcard"
        )
    if dns_profile is not None:
        try:
            dns_profile = dns_profiles.check_profile_id(dns_profile)
        except dns_profiles.ProfileError as exc:
            raise IssueError("bad_input", str(exc)) from exc
        if method != "dns-01":
            raise IssueError("bad_input", "a DNS profile belongs to DNS-01 only")
    if interface and (clusters or receivers):
        raise IssueError(
            "bad_input", "the interface certificate has no targets; name no cluster or receiver"
        )
    if not interface and not exportable and not clusters and not receivers:
        raise IssueError("bad_input", "at least one target (cluster or receiver) is required")
    if interface:
        try:
            ui_interface.refuse_unserved(domains)
        except PublishError as exc:
            raise IssueError(
                exc.code,
                str(exc),
                exit_code=exit_codes.USAGE if exc.code == "bad_input" else exit_codes.CONFIG,
            ) from exc

    registry = runtime.registry
    if registry is None:
        raise IssueError(
            "dependency_unavailable",
            "no certificate registry is configured. Add certificate_registry to the "
            "runtime policy.",
            exit_code=exit_codes.CONFIG,
        )
    for cluster_id in clusters:
        if not CLUSTER_ID.fullmatch(cluster_id):
            raise IssueError("bad_input", f"invalid cluster ID: {cluster_id!r}")
        if cluster_id not in runtime.clusters:
            raise IssueError("bad_input", f"unknown cluster: {cluster_id!r}")
    for receiver_id in receivers:
        if not RECEIVER_ID.fullmatch(receiver_id):
            raise IssueError("bad_input", f"invalid receiver ID: {receiver_id!r}")
        if receiver_id not in registry.receivers:
            raise IssueError("bad_input", f"unregistered receiver: {receiver_id!r}")
    if certificate_id in registry.certificates:
        raise IssueError(
            "already_exists", f"certificate {certificate_id!r} is already in the registry"
        )
    return IssueRequest(
        certificate_id=certificate_id,
        domains=domains,
        wildcard=wildcard,
        method=method,
        clusters=tuple(dict.fromkeys(clusters)),
        receivers=tuple(dict.fromkeys(receivers)),
        dns_profile=dns_profile,
        formats=check_formats(formats, receivers),
        interface=interface,
        exportable=exportable,
    )


def check_exportable(exportable: bool, *, wildcard: bool, targets: bool, interface: bool) -> None:
    """The limits an exportable certificate is made within (B255), shared by every way to make one.

    One name and no wildcard: its key leaves the manager, and a wildcard's key
    taken out answers for every name under it. No targets and not the
    interface's: a certificate this installation serves must not be one whose
    key can be downloaded.
    """

    if not exportable:
        return
    if wildcard:
        raise IssueError("bad_input", "an exportable certificate names one host; no wildcard")
    if targets or interface:
        raise IssueError(
            "bad_input",
            "an exportable certificate has no targets and does not serve the interface; "
            "name no cluster or receiver",
        )


def check_formats(formats: Mapping[str, str] | None, receivers: Sequence[str]) -> dict[str, str]:
    """A format per receiver the request names, and only those (B159)."""

    checked: dict[str, str] = {}
    for receiver_id, form in (formats or {}).items():
        if receiver_id not in receivers:
            raise IssueError("bad_input", f"format for a receiver not targeted: {receiver_id!r}")
        if form not in RECEIVER_FORMATS:
            raise IssueError("bad_input", f"invalid receiver format: {form!r}")
        checked[receiver_id] = form
    return checked


#
# certbot
#


def certbot_binary(policy: PathPolicy) -> str:
    """The certbot this installation runs: the locked environment's when the
    policy names it, the distribution's until then. Never the caller's."""

    if policy.acme is not None and policy.acme.certbot is not None:
        return str(policy.acme.certbot)
    return CERTBOT


def certbot_invocation(
    request: IssueRequest, policy: PathPolicy, *, require_secure: bool = True
) -> CertbotInvocation:
    """The certonly command, binary first, every part fixed here or read from
    the policy."""

    acme = policy.acme
    if request.method == "dns-01":
        if request.dns_profile is not None:
            profile_policy = acme.dns_profiles if acme is not None else None
            if profile_policy is None:
                raise IssueError(
                    "dependency_unavailable",
                    "DNS profiles need acme.dns_profiles in the runtime policy",
                    exit_code=exit_codes.CONFIG,
                )
            try:
                materialized = dns_profiles.read_materialized(
                    profile_policy, request.dns_profile, require_secure=require_secure
                )
                redactions = dns_profiles.materialized_secret_values(materialized)
            except dns_profiles.ProfileError as exc:
                raise IssueError(
                    "dependency_unavailable", str(exc), exit_code=exit_codes.CONFIG
                ) from exc
            provider = materialized.provider
            authenticator = [f"--{provider.plugin}"]
            environment = {}
            if provider.credentials_flag is not None:
                authenticator.extend([provider.credentials_flag, materialized.credentials_path])
            elif provider.credentials_env is not None:
                environment[provider.credentials_env] = materialized.credentials_path
            else:
                raise IssueError("dependency_unavailable", "the DNS provider has no delivery")
            authenticator.extend(
                [f"--{provider.plugin}-propagation-seconds", str(provider.propagation_seconds)]
            )
            timeout = certbot_timeout(provider.propagation_seconds)
        else:
            if acme is None or acme.dns_cloudflare_credentials is None:
                raise IssueError(
                    "dependency_unavailable",
                    "DNS-01 needs --dns-profile or acme.dns_cloudflare_credentials",
                    exit_code=exit_codes.CONFIG,
                )
            # The policy file predates profiles; the wait is still the
            # catalogue's, so both roads issue a lineage that renews alike.
            cloudflare = dns_provider_catalog.provider_by_id("cloudflare")
            authenticator = [
                "--dns-cloudflare",
                "--dns-cloudflare-credentials",
                str(acme.dns_cloudflare_credentials),
                "--dns-cloudflare-propagation-seconds",
                str(cloudflare.propagation_seconds),
            ]
            timeout = certbot_timeout(cloudflare.propagation_seconds)
            environment = {}
            redactions = ()
    else:
        if acme is None or acme.webroot is None:
            raise IssueError(
                "dependency_unavailable",
                "HTTP-01 needs acme.webroot in the runtime policy",
                exit_code=exit_codes.CONFIG,
            )
        authenticator = ["--webroot", "-w", str(acme.webroot)]
        environment = {}
        redactions = ()
        timeout = CERTBOT_TIMEOUT

    arguments = [
        certbot_binary(policy),
        "certonly",
        "--non-interactive",
        "--no-directory-hooks",
        "--cert-name",
        request.certificate_id,
        #
        # RSA for an exportable certificate (B255): it goes to a BMC, a NAS or
        # a printer, and several of them take no EC key at all.
        #
        *(
            ("--key-type", "rsa", "--rsa-key-size", "2048")
            if request.exportable
            else ("--key-type", KEY_TYPE)
        ),
        *authenticator,
    ]
    for domain in request.domains:
        arguments.extend(["-d", domain])
    return CertbotInvocation(
        tuple(arguments), {**FIXED_ENVIRONMENT, **environment}, redactions, timeout
    )


def renewal_invocation(
    lineage: str,
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    binary: str | None = None,
    dry_run: bool = False,
    run_deploy_hooks: bool = False,
    force: bool = False,
    require_secure: bool = True,
) -> CertbotInvocation:
    """One bounded `certbot renew` for one lineage, with the DNS profile's environment.

    The daily timer's command (`cli/cert_renew`), here since C9c so the
    interface's *Renew…* runs exactly the round the timer runs, with
    `--force-renewal` added: certbot itself declines a lineage that is not
    due, and a person pressing the button has decided it is. Most plugins
    persist their credentials flag in `renewal/<lineage>.conf`; Route53 does
    not, and only discovers its file through an environment variable, which
    is why the registry's `source.dns_profile` is materialised here.
    """

    if runtime.registry is None:
        raise IssueError(
            "dependency_unavailable",
            "no certificate registry is configured",
            exit_code=exit_codes.CONFIG,
        )
    profile_id = next(
        (
            certificate.source.dns_profile
            for certificate in runtime.registry.certificates.values()
            if certificate.source.kind == "acme"
            and (certificate.source.lineage or certificate.certificate_id) == lineage
        ),
        None,
    )
    arguments = [
        binary or certbot_binary(policy),
        "-q",
        "renew",
        "--no-random-sleep-on-renew",
        "--cert-name",
        lineage,
    ]
    if dry_run:
        arguments.append("--dry-run")
    if run_deploy_hooks:
        arguments.append("--run-deploy-hooks")
    if force:
        arguments.append("--force-renewal")
    environment = dict(FIXED_ENVIRONMENT)
    redactions: tuple[str, ...] = ()
    #
    # A lineage without a profile is the policy file's Cloudflare road or
    # HTTP-01; both fit the standing budget.
    #
    timeout = CERTBOT_TIMEOUT
    if profile_id is not None:
        profile_policy = policy.acme.dns_profiles if policy.acme is not None else None
        if profile_policy is None:
            raise IssueError(
                "dependency_unavailable",
                f"lineage {lineage!r} names DNS profile {profile_id!r}, but "
                "acme.dns_profiles is not configured",
                exit_code=exit_codes.CONFIG,
            )
        try:
            materialized = dns_profiles.read_materialized(
                profile_policy, profile_id, require_secure=require_secure
            )
            redactions = dns_profiles.materialized_secret_values(materialized)
        except dns_profiles.ProfileError as exc:
            raise IssueError(
                "dependency_unavailable", str(exc), exit_code=exit_codes.CONFIG
            ) from exc
        if materialized.provider.credentials_env is not None:
            environment[materialized.provider.credentials_env] = materialized.credentials_path
        timeout = certbot_timeout(materialized.provider.propagation_seconds)
    return CertbotInvocation(tuple(arguments), environment, redactions, timeout)


def renewal_method(conf: Path) -> Method:
    """Which challenge the lineage renews with, read off certbot's own renewal conf.

    The registry does not keep the method - certbot does, as
    `authenticator = webroot` or a DNS plugin's name - and the result of a
    renewal reports what certbot used.
    """

    try:
        for line in conf.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip() == "authenticator":
                return "http-01" if value.strip() == "webroot" else "dns-01"
    except OSError as exc:
        raise IssueError(
            "dependency_unavailable",
            f"the renewal conf could not be read: {exc}",
            exit_code=exit_codes.CONFIG,
        ) from exc
    return "dns-01"


def certbot_arguments(request: IssueRequest, policy: PathPolicy) -> list[str]:
    """Compatibility view used by callers that only need to inspect argv."""

    return list(certbot_invocation(request, policy, require_secure=False).arguments)


def run_certbot(
    command: Sequence[str], environment: Mapping[str, str], timeout: int = CERTBOT_TIMEOUT
) -> CertbotResult:
    try:
        completed = subprocess.run(  # noqa: S603 - binary from the policy, arguments assembled above
            list(command),
            capture_output=True,
            text=True,
            env=dict(environment),
            timeout=timeout,
            check=False,
        )
    except OSError as exc:
        return CertbotResult(127, f"certbot could not be started: {exc}")
    except subprocess.TimeoutExpired:
        return CertbotResult(
            exit_codes.TIMED_OUT, f"certbot did not finish within {timeout} seconds"
        )
    output = (completed.stdout or "") + (completed.stderr or "")
    return CertbotResult(completed.returncode, output.strip())


#
# The registry
#


def add_to_registry(
    path: Path,
    request: IssueRequest,
    runtime: RuntimeConfig,
    *,
    require_secure: bool = True,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> str | None:
    """Add the entry through the one writer the registry has.

    Returns the entry that served the interface until now, when this one
    takes the mark from it (D5).

    The atomic rewrite, the load-back and the cluster cross-check all live in
    `cert_registry`, which the registry helper uses too. This function is the
    shape of an issued entry and nothing else. Read and written under the
    certificate lock, so a renewal writing at the same moment cannot lose it.
    """

    try:
        with cert_registry.locked(lock_path):
            return _add_entry(path, request, runtime, require_secure=require_secure)
    except cert_registry.RegistryError as exc:
        #
        # The one failure that leaves something behind: certbot has issued the
        # certificate by now, and the lineage exists whether or not the
        # registry took the entry. Said in the message, because a second
        # attempt is refused on the lineage and the operator needs to know what
        # to do instead.
        #
        if exc.code == "already_exists":
            #
            # Registering the lineage by hand would write over the certificate
            # that took the name, which is what the refusal kept from happening
            # (review 26-10-25, 1-04). The lineage is the one thing to undo.
            #
            raise IssueError(
                exc.code,
                f"certbot issued {request.certificate_id!r}, and another certificate was "
                "registered under that name while it ran; nothing was written over it. The "
                "issued lineage is not registered: remove it with "
                f"'sudo certbot delete --cert-name {request.certificate_id}', then issue under "
                "another name.",
                exit_code=exit_codes.after_a_change(exc.exit_code),
            ) from exc
        raise IssueError(
            exc.code,
            f"certbot issued {request.certificate_id!r} but the registry did not take it: "
            f"{str(exc).rstrip('.')}. Register the lineage by hand, then publish it.",
            exit_code=exit_codes.after_a_change(exc.exit_code),
        ) from exc


def _add_entry(
    path: Path, request: IssueRequest, runtime: RuntimeConfig, *, require_secure: bool
) -> str | None:
    document = cert_registry.read_document(path)
    certificates = dict(document.get("certificates") or {})
    if request.certificate_id in certificates:
        #
        # `build_request` checked a snapshot from before certbot ran. An import,
        # a signing request or a SCEP entry may have taken the ID since, and
        # writing over it would drop its targets (review 26-10-24, 08-06).
        #
        raise cert_registry.RegistryError(
            "already_exists",
            f"certificate {request.certificate_id!r} was registered while certbot ran.",
            exit_code=exit_codes.BLOCKED,
        )
    entry: dict[str, Any] = {"source": {"kind": "acme"}}
    if request.dns_profile is not None:
        entry["source"]["dns_profile"] = request.dns_profile
    if request.clusters:
        entry["clusters"] = list(request.clusters)
    if request.receivers:
        entry["receivers"] = cert_registry.receiver_elements(request.receivers, request.formats)
    if request.exportable:
        entry["exportable"] = True
    certificates[request.certificate_id] = entry
    displaced = (
        cert_registry.claim_interface(certificates, request.certificate_id)
        if request.interface
        else None
    )
    cert_registry.write(
        path,
        document=document,
        certificates=certificates,
        runtime=runtime,
        require_secure=require_secure,
    )
    return displaced


#
# The run
#


def issue(
    *,
    domain: str,
    method: str,
    clusters: Sequence[str],
    receivers: Sequence[str],
    dns_profile: str | None = None,
    formats: Mapping[str, str] | None = None,
    interface: bool = False,
    exportable: bool = False,
    policy: PathPolicy,
    runtime: RuntimeConfig,
    certbot: Certbot = run_certbot,
    deployer: Deployer | None = None,
    installer: Installer | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
    require_secure: bool = True,
    now: datetime | None = None,
) -> IssueResult:
    started = time.monotonic()
    request = build_request(
        domain=domain,
        method=method,
        clusters=clusters,
        receivers=receivers,
        runtime=runtime,
        dns_profile=dns_profile,
        formats=formats,
        interface=interface,
        exportable=exportable,
    )
    if (live / request.certificate_id).exists():
        raise IssueError(
            "already_exists",
            f"certbot already has a lineage named {request.certificate_id!r}; register it "
            "in the registry instead of issuing it again",
        )
    invocation = certbot_invocation(request, policy, require_secure=require_secure)

    certbot_started = time.monotonic()
    result = certbot(invocation.arguments, invocation.environment, invocation.timeout)
    certbot_seconds = time.monotonic() - certbot_started
    if result.returncode != 0:
        #
        # The exit status is the sentence; the output is the evidence. The
        # operator needs to read "the DNS record could not be created", and
        # the envelope caps a message at 2048 bytes, so the output travels
        # whole under `details.diagnostics` rather than cut off mid-line in
        # the message.
        #
        diagnostics = result.output
        for value in sorted(invocation.redactions, key=len, reverse=True):
            diagnostics = diagnostics.replace(value, "[redacted]")
        raise IssueError(
            "certbot_failed",
            f"certbot exited {result.returncode} after {certbot_seconds:.0f}s",
            exit_code=exit_codes.FAILED,
            details={
                "diagnostics": diagnostics,
                "certbot_exit_code": result.returncode,
                "certbot_seconds": round(certbot_seconds, 1),
            },
        )

    assert policy.certificate_registry is not None  # noqa: S101 - build_request checked it
    displaced = add_to_registry(
        policy.certificate_registry,
        request,
        runtime,
        require_secure=require_secure,
        lock_path=lock_path,
    )
    #
    # Re-read rather than patched in memory: the publisher must see exactly
    # what the next renewal's hook will see.
    #
    refreshed = load_runtime_config(policy, require_secure=require_secure)

    try:
        report = publish(
            refreshed,
            policy,
            only=[request.certificate_id],
            live=live,
            store=store,
            lock_path=lock_path,
            deployer=deployer,
            installer=installer,
            now=now or datetime.now(UTC),
        )
    except PublishError as exc:
        #
        # Issued and registered: the answer an unfinished publish has, not a
        # failed issue (26-10-29, C01).
        #
        report = unpublished(request.certificate_id, exc)

    retired = cert_delete.retire_displaced_interface(
        displaced,
        served=ui_interface.served(report, request.certificate_id),
        policy=policy,
        certbot=certbot_binary(policy),
        require_secure=require_secure,
        store=store,
        lock_path=lock_path,
    )
    return IssueResult(
        request=request,
        certbot_seconds=certbot_seconds,
        total_seconds=time.monotonic() - started,
        publish=report,
        retired=retired,
    )


def renew(
    *,
    certificate_id: str,
    policy: PathPolicy,
    runtime: RuntimeConfig,
    certbot: Certbot = run_certbot,
    deployer: Deployer | None = None,
    installer: Installer | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
    renewal_directory: Path | None = None,
    require_secure: bool = True,
    now: datetime | None = None,
) -> IssueResult:
    """The whole round again, now, for a lineage the registry holds (C9c).

    What the daily timer does to a lineage that is due, forced: the same
    `certbot renew`, the same deploy hook publishing inside it, and then
    the publisher once more for this certificate alone - a verifying no-op
    when the hook has done the work, the work itself where the hook is
    missing. Nothing is added to the registry; the entry is what it was.
    """

    started = time.monotonic()
    if not CERTIFICATE_ID.fullmatch(certificate_id):
        raise IssueError("bad_input", f"invalid certificate ID: {certificate_id!r}")
    registry = runtime.registry
    if registry is None or policy.certificate_registry is None or policy.certificate_root is None:
        raise IssueError(
            "dependency_unavailable",
            "no certificate registry is configured",
            exit_code=exit_codes.CONFIG,
        )
    entry = registry.certificates.get(certificate_id)
    if entry is None:
        raise IssueError("not_registered", f"certificate {certificate_id!r} is not in the registry")
    if entry.source.kind != "acme":
        raise IssueError(
            "not_acme",
            f"certificate {certificate_id!r} is not certbot's ({entry.source.kind!r}); "
            "renew it where its material comes from (an NDES certificate: haprion-cert-scep)",
        )
    lineage = entry.source.lineage or certificate_id
    conf = (renewal_directory or RENEWAL_DIRECTORY) / f"{lineage}.conf"
    if not conf.is_file():
        raise IssueError(
            "no_lineage", f"certbot has no renewal configuration for lineage {lineage!r}"
        )
    measured = measure_registered(
        entry, certificate_root=policy.certificate_root, live=live, store=store
    )
    if isinstance(measured, str):
        raise IssueError("dependency_unavailable", measured, exit_code=exit_codes.CONFIG)
    _fingerprint, facts, _where = measured
    common = facts.common_name
    domains = tuple(
        dict.fromkeys(([common] if common else []) + [n for n in facts.sans if n != common])
    )
    request = IssueRequest(
        certificate_id=certificate_id,
        domains=domains,
        wildcard=any(name.startswith("*.") for name in domains),
        method=renewal_method(conf),
        clusters=entry.clusters,
        receivers=entry.receivers,
        dns_profile=entry.source.dns_profile,
        formats=dict(entry.formats),
        interface=entry.interface,
        exportable=entry.exportable,
    )
    invocation = renewal_invocation(
        lineage, policy, runtime, force=True, require_secure=require_secure
    )

    certbot_started = time.monotonic()
    result = certbot(invocation.arguments, invocation.environment, invocation.timeout)
    certbot_seconds = time.monotonic() - certbot_started
    if result.returncode != 0:
        diagnostics = result.output
        for value in sorted(invocation.redactions, key=len, reverse=True):
            diagnostics = diagnostics.replace(value, "[redacted]")
        raise IssueError(
            "certbot_failed",
            f"certbot exited {result.returncode} after {certbot_seconds:.0f}s",
            exit_code=exit_codes.FAILED,
            details={
                "diagnostics": diagnostics,
                "certbot_exit_code": result.returncode,
                "certbot_seconds": round(certbot_seconds, 1),
            },
        )

    refreshed = load_runtime_config(policy, require_secure=require_secure)
    try:
        report = publish(
            refreshed,
            policy,
            only=[certificate_id],
            live=live,
            store=store,
            lock_path=lock_path,
            deployer=deployer,
            installer=installer,
            now=now or datetime.now(UTC),
        )
    except PublishError as exc:
        report = unpublished(certificate_id, exc)
    return IssueResult(
        request=request,
        certbot_seconds=certbot_seconds,
        total_seconds=time.monotonic() - started,
        publish=report,
        renewed=True,
        lineage=lineage,
    )
