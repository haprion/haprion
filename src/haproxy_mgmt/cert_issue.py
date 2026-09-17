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
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from haproxy_mgmt import cert_registry, dns_profiles, dns_provider_catalog
from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cert_publish import (
    DEFAULT_LOCK_PATH,
    Deployer,
    PublishError,
    Report,
    publish,
)
from haproxy_mgmt.config import (
    CERTIFICATE_ID,
    CLUSTER_ID,
    HOSTNAME,
    RECEIVER_ID,
    PathPolicy,
    RuntimeConfig,
    load_runtime_config,
)

CERTBOT = "/usr/bin/certbot"
CERTBOT_TIMEOUT = 600
KEY_TYPE = "ecdsa"

type Method = Literal["dns-01", "http-01"]
METHODS: tuple[Method, ...] = ("dns-01", "http-01")


class IssueError(Exception):
    """A refusal or failure, with the code it is reported under.

    `details` is the envelope's `error.details`: evidence that does not fit a
    sentence. certbot's output goes there, under `diagnostics`, the same key
    `haproxy-publish` puts the compiler's answer under - the interface already
    reads that key, and a message is capped at 2048 bytes while certbot's
    account of a failed DNS challenge is routinely longer.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_code: int = 64,
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


@dataclass(frozen=True, slots=True)
class CertbotResult:
    returncode: int
    output: str


type Certbot = Callable[[Sequence[str], Mapping[str, str]], CertbotResult]


@dataclass(frozen=True, slots=True)
class CertbotInvocation:
    arguments: tuple[str, ...]
    environment: Mapping[str, str]
    redactions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class IssueResult:
    request: IssueRequest
    certbot_seconds: float
    total_seconds: float
    publish: Report

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.request.certificate_id,
            "lineage": self.request.certificate_id,
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
) -> IssueRequest:
    certificate_id, domains, wildcard = parse_domain(domain)
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
    if not clusters and not receivers:
        raise IssueError("bad_input", "at least one target (cluster or receiver) is required")

    registry = runtime.registry
    if registry is None:
        raise IssueError(
            "dependency_unavailable",
            "no certificate registry is configured. Add certificate_registry to the "
            "runtime policy.",
            exit_code=78,
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
    )


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
                    exit_code=78,
                )
            try:
                materialized = dns_profiles.read_materialized(
                    profile_policy, request.dns_profile, require_secure=require_secure
                )
                redactions = dns_profiles.materialized_secret_values(materialized)
            except dns_profiles.ProfileError as exc:
                raise IssueError("dependency_unavailable", str(exc), exit_code=78) from exc
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
        else:
            if acme is None or acme.dns_cloudflare_credentials is None:
                raise IssueError(
                    "dependency_unavailable",
                    "DNS-01 needs --dns-profile or acme.dns_cloudflare_credentials",
                    exit_code=78,
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
            environment = {}
            redactions = ()
    else:
        if acme is None or acme.webroot is None:
            raise IssueError(
                "dependency_unavailable",
                "HTTP-01 needs acme.webroot in the runtime policy",
                exit_code=78,
            )
        authenticator = ["--webroot", "-w", str(acme.webroot)]
        environment = {}
        redactions = ()

    arguments = [
        certbot_binary(policy),
        "certonly",
        "--non-interactive",
        "--no-directory-hooks",
        "--cert-name",
        request.certificate_id,
        "--key-type",
        KEY_TYPE,
        *authenticator,
    ]
    for domain in request.domains:
        arguments.extend(["-d", domain])
    fixed_environment = {
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        **environment,
    }
    return CertbotInvocation(tuple(arguments), fixed_environment, redactions)


def certbot_arguments(request: IssueRequest, policy: PathPolicy) -> list[str]:
    """Compatibility view used by callers that only need to inspect argv."""

    return list(certbot_invocation(request, policy, require_secure=False).arguments)


def run_certbot(command: Sequence[str], environment: Mapping[str, str]) -> CertbotResult:
    try:
        completed = subprocess.run(  # noqa: S603 - binary from the policy, arguments assembled above
            list(command),
            capture_output=True,
            text=True,
            env=dict(environment),
            timeout=CERTBOT_TIMEOUT,
            check=False,
        )
    except OSError as exc:
        return CertbotResult(127, f"certbot could not be started: {exc}")
    except subprocess.TimeoutExpired:
        return CertbotResult(124, f"certbot did not finish within {CERTBOT_TIMEOUT} seconds")
    output = (completed.stdout or "") + (completed.stderr or "")
    return CertbotResult(completed.returncode, output.strip())


#
# The registry
#


def add_to_registry(
    path: Path, request: IssueRequest, runtime: RuntimeConfig, *, require_secure: bool = True
) -> None:
    """Add the entry through the one writer the registry has.

    The atomic rewrite, the load-back and the cluster cross-check all live in
    `cert_registry`, which the registry helper uses too. This function is the
    shape of an issued entry and nothing else.
    """

    try:
        document = cert_registry.read_document(path)
        certificates = dict(document.get("certificates") or {})
        entry: dict[str, Any] = {"source": {"kind": "acme"}}
        if request.dns_profile is not None:
            entry["source"]["dns_profile"] = request.dns_profile
        if request.clusters:
            entry["clusters"] = list(request.clusters)
        if request.receivers:
            entry["receivers"] = list(request.receivers)
        certificates[request.certificate_id] = entry
        cert_registry.write(
            path,
            document=document,
            certificates=certificates,
            runtime=runtime,
            require_secure=require_secure,
        )
    except cert_registry.RegistryError as exc:
        #
        # The one failure that leaves something behind: certbot has issued the
        # certificate by now, and the lineage exists whether or not the
        # registry took the entry. Said in the message, because a second
        # attempt is refused on the lineage and the operator needs to know what
        # to do instead.
        #
        raise IssueError(
            exc.code,
            f"certbot issued {request.certificate_id!r} but the registry did not take it: "
            f"{exc} Register the lineage by hand, then publish it.",
            exit_code=exc.exit_code,
        ) from exc


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
    policy: PathPolicy,
    runtime: RuntimeConfig,
    certbot: Certbot = run_certbot,
    deployer: Deployer | None = None,
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
    )
    if (live / request.certificate_id).exists():
        raise IssueError(
            "already_exists",
            f"certbot already has a lineage named {request.certificate_id!r}; register it "
            "in the registry instead of issuing it again",
        )
    invocation = certbot_invocation(request, policy, require_secure=require_secure)

    certbot_started = time.monotonic()
    result = certbot(invocation.arguments, invocation.environment)
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
            exit_code=1,
            details={
                "diagnostics": diagnostics,
                "certbot_exit_code": result.returncode,
                "certbot_seconds": round(certbot_seconds, 1),
            },
        )

    assert policy.certificate_registry is not None  # noqa: S101 - build_request checked it
    add_to_registry(policy.certificate_registry, request, runtime, require_secure=require_secure)
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
            now=now or datetime.now(UTC),
        )
    except PublishError as exc:
        raise IssueError(exc.code, str(exc), exit_code=78) from exc

    return IssueResult(
        request=request,
        certbot_seconds=certbot_seconds,
        total_seconds=time.monotonic() - started,
        publish=report,
    )
