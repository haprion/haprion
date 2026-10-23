"""The form that asks for an ACME certificate, and what it may say.

Phase 11's gate is stated in minutes: a form, a button, and a usable
certificate on the chosen targets in under five. This is the form. What it
collects is exactly what `haprion-cert-issue` accepts - a domain, a challenge
method, and targets the registry already knows - and nothing it collects is
trusted further than the queue: the helper checks every field again against
the runtime policy, which the interface cannot read.

One implementation of the domain rule, not two. The name typed here becomes a
certbot lineage, a file under the distribution root and a registry key, and
the engine owns the rule that fits all three. The form calls that rule rather
than restating it, so a domain the form accepts is one the engine accepts, and
the two cannot drift apart between releases.

A receiver is chosen, never typed. A receiver is a directory, an account and a
key locked to that directory (B135), and none of those can be brought into
existence by a form. The page lists the ones the registry has (B141 says what
their names mean) and says where a missing one is made.
"""

from __future__ import annotations

import types
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from haprion.cert_issue import METHODS, IssueError, parse_domain
from haprion.cert_request_state import DEFAULT_KEY_TYPE, KEY_TYPES
from haprion.config import (
    DEFAULT_POLICY_PATH,
    DEFAULT_RECEIVER_FORMAT,
    RECEIVER_FORMATS,
    ConfigError,
    load_policy,
)
from haprion.ui_interface import covers


class FormProblem(Exception):
    """The submission cannot become a request, and saying so is the answer.

    The sentence names the field, never what was typed into it: the form is
    re-drawn with the typed values in place, so the reader can see them, and a
    refusal that echoed them would put request-derived text into a response.
    """


@dataclass(frozen=True, slots=True)
class IssueForm:
    """One submission, still in the browser's shape."""

    domain: str
    method: str
    clusters: tuple[str, ...]
    receivers: tuple[str, ...]
    dns_profile: str = ""
    ndes_profile: str = ""
    formats: tuple[str, ...] = ()
    """The page's `format` fields as submitted, `<receiver>=<format>` each (B159)."""
    key_type: str = ""
    """The CSR method's one setting (C9b); empty means the engine's default."""
    interface: bool = False
    """For the manager's own interface certificate (B188): no targets, published to nginx."""
    exportable: bool = False
    """To be taken out and installed by hand (B255): one name, no targets, its key exported."""

    @property
    def wildcard(self) -> bool:
        return self.domain.strip().startswith("*.")

    def format_of(self, receiver_id: str) -> str:
        """What the page should show selected for a receiver when drawn again."""

        for value in self.formats:
            name, _, form = value.partition("=")
            if name.strip() == receiver_id and form.strip() in RECEIVER_FORMATS:
                return form.strip()
        return DEFAULT_RECEIVER_FORMAT


#
# The third answer to "which CA": not an ACME challenge at all but the
# organisation's own Microsoft CA over NDES/SCEP (C6, B152). Same form, same
# domain rule, same targets; a different job behind the button.
#
NDES_METHOD = "ndes"
#
# The fourth answer (C9b): no CA the manager can talk to. The key is made
# here, the signing request leaves as text, and the signed certificate comes
# back through the row's upload. Same form, same names, same targets; a
# key type instead of a profile.
#
CSR_METHOD = "csr"
KEY_TYPE_LABELS = {
    "ec-p256": "EC P-256 (recommended)",
    "rsa-2048": "RSA 2048",
    "rsa-4096": "RSA 4096",
}


def operation_of(form: IssueForm) -> str:
    """Which job the submission becomes: certbot's, the NDES enrollment, or a CSR."""

    method = form.method.strip()
    if method == NDES_METHOD:
        return "cert_scep"
    if method == CSR_METHOD:
        return "cert_request"
    return "cert_issue"


@dataclass(frozen=True, slots=True)
class IssueChoices:
    """What the form may offer: the clusters and receivers that exist."""

    clusters: tuple[str, ...]
    receivers: tuple[str, ...]
    dns_profiles: tuple[str, ...] = ()
    profiles_required: bool = False
    #
    # NDES profiles in effect. The NDES choice is offered only where there is
    # at least one; the page names the reason otherwise.
    #
    ndes_profiles: tuple[str, ...] = ()
    #
    # Whether the runtime policy names a webroot, without which HTTP-01 is
    # refused by the engine (B36: the app does not own the HTTP path). Greyed
    # with the reason, as NDES is without a profile (review 2026-10-22, 7-4).
    #
    http01: bool = True
    #
    # Each receiver's transport, for the row it gets in the list (B142). A
    # receiver without one is drawn without a badge.
    #
    receiver_transports: Mapping[str, str] = types.MappingProxyType({})
    #
    # The certificate IDs the registry already holds. The engine refuses a
    # name it has (`already_exists`), but as a failed job on another page;
    # the form says it here and names the action that does what the person
    # most likely wanted - another target for the certificate that exists.
    #
    registered: tuple[str, ...] = ()
    #
    # Of those, the ones whose material is imported: the import page may
    # replace them (a rotated key, a renewed certificate), and no other.
    #
    imported: tuple[str, ...] = ()
    #
    # And the ones that are signing requests still waiting (C9b): the name
    # is taken, and the action that fits is on the row, not on this form.
    #
    waiting: tuple[str, ...] = ()
    #
    # The interface's own certificate (B188): the name it is served on, the
    # entry that serves it now, and every ID in use - the registry's, the
    # interface's and the waiting requests' - for the ID a new one gets.
    #
    manager: str | None = None
    interface_id: str | None = None
    taken: tuple[str, ...] = ()
    #
    # The CA certificates the registry holds (B276): an import of a CA file
    # may replace one of these, and nothing else.
    #
    authorities: tuple[str, ...] = ()


def interface_id_for(manager: str, taken: Iterable[str]) -> str:
    """The ID a new interface certificate from NDES, a CSR or an import is given.

    Not the domain: an ACME certificate's ID is its domain, so an interface
    certificate that took the domain would leave no way to replace it with
    one from Let's Encrypt (the entry that serves cannot be deleted first).
    The first label and `-ui`, then `-ui-2` and on while the name is in use.
    """

    base = manager.split(".", 1)[0] + "-ui"
    used = set(taken)
    if base not in used:
        return base
    number = 2
    while f"{base}-{number}" in used:
        number += 1
    return f"{base}-{number}"


EMPTY_FORM = IssueForm(domain="", method="dns-01", dns_profile="", clusters=(), receivers=())


def normalise(form: IssueForm) -> IssueForm:
    """The submission as it will be judged: trimmed, lowercased, deduplicated."""

    return IssueForm(
        domain=form.domain.strip().lower().rstrip("."),
        method=form.method.strip(),
        dns_profile=form.dns_profile.strip(),
        ndes_profile=form.ndes_profile.strip(),
        clusters=tuple(dict.fromkeys(name.strip() for name in form.clusters if name.strip())),
        receivers=tuple(dict.fromkeys(name.strip() for name in form.receivers if name.strip())),
        formats=tuple(value.strip() for value in form.formats if value.strip()),
        key_type=form.key_type.strip(),
        interface=form.interface,
        exportable=form.exportable,
    )


def formats_from_fields(values: Iterable[str], receivers: Iterable[str]) -> dict[str, str]:
    """The `format` fields as the page submits them: `<receiver>=<format>`, one per select.

    Every receiver's select is submitted whether or not its box is ticked, so
    a value for a receiver that was not chosen is dropped rather than refused;
    `pem` is the default and is not carried. A format that is not one the
    engine writes is a refusal: the page offered only the two.
    """

    chosen = set(receivers)
    formats: dict[str, str] = {}
    for value in values:
        receiver_id, separator, form = value.partition("=")
        receiver_id, form = receiver_id.strip(), form.strip()
        if not separator or receiver_id not in chosen:
            continue
        if form not in RECEIVER_FORMATS:
            raise FormProblem("A receiver's format must be PEM or PKCS#12.")
        if form != DEFAULT_RECEIVER_FORMAT:
            formats[receiver_id] = form
    return formats


def payload_from_form(form: IssueForm, choices: IssueChoices) -> dict[str, Any]:
    """The `cert_issue` job payload, or a problem naming the field.

    Refusals in the order a reader fills the form in: the name, the method,
    the targets. Each is a sentence about the form rather than about the
    engine, because the person reading it is looking at the form.
    """

    form = normalise(form)
    if not form.domain:
        raise FormProblem("A domain name is required.")
    try:
        name, _, wildcard = parse_domain(form.domain)
    except IssueError as problem:
        raise FormProblem(
            "That is not a domain name the engine can issue for: lowercase labels "
            "separated by dots, optionally starting with *. for a wildcard."
        ) from problem
    if form.interface:
        return _interface_payload(form, choices, name)
    if name in choices.waiting:
        raise FormProblem(
            f"A signing request named {name} is already waiting for its certificate. "
            "Download it from its row, or delete the row to start over."
        )
    if name in choices.registered:
        #
        # The ID is the base name, so *.example.com and example.com are the
        # same certificate. A second one is not what New certificate is for:
        # another target for it is Publish to… on its row, a fresh one is a
        # renewal at its source.
        #
        raise FormProblem(
            f"A certificate named {name} is already in the registry. To send it to "
            "another cluster or receiver, use Publish to… on its row."
        )
    if form.method == NDES_METHOD:
        if not choices.ndes_profiles:
            raise FormProblem(
                "No NDES provider profile is in effect; enrollment over NDES is unavailable."
            )
        if form.ndes_profile not in choices.ndes_profiles:
            raise FormProblem("Choose an NDES provider profile that is in effect.")
        if form.dns_profile:
            raise FormProblem("A DNS provider profile belongs to DNS-01 only.")
    elif form.method == CSR_METHOD:
        if form.dns_profile or form.ndes_profile:
            raise FormProblem("A provider profile belongs to a CA the manager talks to.")
        if form.key_type and form.key_type not in KEY_TYPES:
            raise FormProblem("Choose a key type from the list.")
    elif form.method not in METHODS:
        raise FormProblem("Choose a challenge method.")
    elif form.method == "http-01" and not choices.http01:
        raise FormProblem(
            "HTTP-01 needs a webroot in the runtime policy (acme.webroot), and this manager "
            "has none; use DNS-01."
        )
    elif form.ndes_profile:
        raise FormProblem("An NDES provider profile belongs to NDES enrollment only.")
    if form.key_type and form.method != CSR_METHOD:
        raise FormProblem("A key type belongs to a signing request only.")
    if wildcard and form.method not in {"dns-01", NDES_METHOD, CSR_METHOD}:
        #
        # Said here as well as by the engine: the engine's refusal would arrive
        # as a failed job on another page, and this is the one rule a reader
        # can act on before pressing the button.
        #
        raise FormProblem(
            "A wildcard certificate needs DNS-01. HTTP-01 cannot prove a wildcard, "
            "because no CA issues one against an HTTP challenge."
        )
    if form.method in {NDES_METHOD, CSR_METHOD}:
        pass
    elif form.method == "dns-01":
        if choices.profiles_required and not form.dns_profile:
            raise FormProblem("Choose a DNS provider profile that is in effect.")
        if choices.profiles_required and form.dns_profile not in choices.dns_profiles:
            raise FormProblem("The chosen DNS provider profile is not in effect.")
    elif form.dns_profile:
        raise FormProblem("A DNS provider profile belongs to DNS-01 only.")
    if form.exportable:
        #
        # B255: one host, no targets, and a CA the manager talks to - the key
        # is made here and handed out, so a signing request's own key stays
        # what it is.
        #
        if wildcard:
            raise FormProblem("An exportable certificate names one host; no wildcard.")
        if form.clusters or form.receivers:
            raise FormProblem(
                "An exportable certificate has no targets; it is downloaded and installed by hand."
            )
        if form.method == CSR_METHOD:
            raise FormProblem("An exportable certificate comes from ACME or NDES, not a CSR.")
    elif not form.clusters and not form.receivers:
        raise FormProblem("Choose at least one target: a cluster or a receiver.")
    #
    # A box that was not offered. The page draws only the targets that exist,
    # so a name outside that set was not chosen with a mouse - and the engine
    # would refuse it anyway, but as a failed job rather than here.
    #
    unknown_clusters = _unknown(form.clusters, choices.clusters)
    if unknown_clusters:
        raise FormProblem("One of the chosen clusters is not a cluster this manager has.")
    unknown_receivers = _unknown(form.receivers, choices.receivers)
    if unknown_receivers:
        raise FormProblem(
            "One of the chosen receivers is not registered. A receiver is registered "
            "on the manager, not from this form."
        )
    formats = formats_from_fields(form.formats, form.receivers)
    if form.method == CSR_METHOD:
        name, names, _ = parse_domain(form.domain)
        request: dict[str, Any] = {
            "id": name,
            "domains": [name, *[n for n in names if n != name]],
            "key_type": form.key_type or DEFAULT_KEY_TYPE,
            "clusters": list(form.clusters),
            "receivers": list(form.receivers),
        }
        if formats:
            request["formats"] = formats
        return request
    if form.method == NDES_METHOD:
        #
        # The engine's own reading of the name: the base name is the ID and
        # the CN, the wildcard a SAN beside it - the CN is never a wildcard.
        #
        name, names, _ = parse_domain(form.domain)
        enrollment: dict[str, Any] = {
            "id": name,
            "profile": form.ndes_profile,
            "domains": [name, *[n for n in names if n != name]],
            "clusters": list(form.clusters),
            "receivers": list(form.receivers),
        }
        if formats:
            enrollment["formats"] = formats
        if form.exportable:
            enrollment["exportable"] = True
        return enrollment
    payload: dict[str, Any] = {
        "domain": form.domain,
        "method": form.method,
        "clusters": list(form.clusters),
        "receivers": list(form.receivers),
    }
    if form.dns_profile:
        payload["dns_profile"] = form.dns_profile
    if formats:
        payload["formats"] = formats
    if form.exportable:
        payload["exportable"] = True
    return payload


def _interface_payload(form: IssueForm, choices: IssueChoices, name: str) -> dict[str, Any]:
    """The payload for the interface's own certificate (B188): no targets, the mark set.

    The name must serve the interface: the engine refuses to install one that
    does not, but only after the CA has issued it; this says so before.
    """

    if not choices.manager:
        raise FormProblem("The interface's server name is not known yet; try again shortly.")
    _base, names, _ = parse_domain(form.domain)
    if not covers(names, choices.manager):
        raise FormProblem(
            f"The certificate must name {choices.manager}, the name this interface is served on."
        )
    if form.clusters or form.receivers:
        raise FormProblem("The interface certificate has no targets.")
    if form.method == NDES_METHOD:
        if form.ndes_profile not in choices.ndes_profiles:
            raise FormProblem("Choose an NDES provider profile that is in effect.")
        identifier = interface_id_for(choices.manager, choices.taken)
        return {
            "id": identifier,
            "profile": form.ndes_profile,
            "domains": [name, *[n for n in names if n != name]],
            "clusters": [],
            "receivers": [],
            "interface": True,
        }
    if form.method == CSR_METHOD:
        if form.key_type and form.key_type not in KEY_TYPES:
            raise FormProblem("Choose a key type from the list.")
        return {
            "id": interface_id_for(choices.manager, choices.taken),
            "domains": [name, *[n for n in names if n != name]],
            "key_type": form.key_type or DEFAULT_KEY_TYPE,
            "clusters": [],
            "receivers": [],
            "interface": True,
        }
    if form.method not in METHODS:
        raise FormProblem("Choose a challenge method.")
    if name == choices.interface_id:
        raise FormProblem(
            f"{name} already serves this interface. Renew it on the settings page instead."
        )
    if name in choices.taken:
        raise FormProblem(
            f"A certificate named {name} is already in the registry. Let's Encrypt names a "
            "certificate after its domain, so this one cannot be issued beside it."
        )
    if form.wildcard and form.method != "dns-01":
        raise FormProblem("A wildcard certificate needs DNS-01.")
    if (
        form.method == "dns-01"
        and choices.profiles_required
        and form.dns_profile not in choices.dns_profiles
    ):
        raise FormProblem("Choose a DNS provider profile that is in effect.")
    payload: dict[str, Any] = {
        "domain": form.domain,
        "method": form.method,
        "clusters": [],
        "receivers": [],
        "interface": True,
    }
    if form.method == "dns-01" and form.dns_profile:
        payload["dns_profile"] = form.dns_profile
    return payload


def _unknown(chosen: Iterable[str], offered: Iterable[str]) -> tuple[str, ...]:
    known = set(offered)
    return tuple(name for name in chosen if name not in known)


def http01_offered(policy_path: Path = DEFAULT_POLICY_PATH) -> bool:
    """Whether the runtime policy names the webroot HTTP-01 is answered from.

    Read as the page is drawn, the way the engine will read it when the job
    runs; a policy that cannot be read offers nothing the job would refuse.
    """

    try:
        acme = load_policy(policy_path).acme
    except (ConfigError, OSError):
        return False
    return acme is not None and acme.webroot is not None
