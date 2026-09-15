"""The form that asks for an ACME certificate, and what it may say.

Phase 11's gate is stated in minutes: a form, a button, and a usable
certificate on the chosen targets in under five. This is the form. What it
collects is exactly what `haproxy-cert-issue` accepts - a domain, a challenge
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

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from haproxy_mgmt.cert_issue import METHODS, IssueError, parse_domain


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

    @property
    def wildcard(self) -> bool:
        return self.domain.strip().startswith("*.")


#
# The third answer to "which CA": not an ACME challenge at all but the
# organisation's own Microsoft CA over NDES/SCEP (C6, B152). Same form, same
# domain rule, same targets; a different job behind the button.
#
NDES_METHOD = "ndes"


def operation_of(form: IssueForm) -> str:
    """Which job the submission becomes: certbot's, or the NDES enrollment."""

    return "cert_scep" if form.method.strip() == NDES_METHOD else "cert_issue"


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
    )


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
        _, _, wildcard = parse_domain(form.domain)
    except IssueError as problem:
        raise FormProblem(
            "That is not a domain name the engine can issue for: lowercase labels "
            "separated by dots, optionally starting with *. for a wildcard."
        ) from problem
    if form.method == NDES_METHOD:
        if not choices.ndes_profiles:
            raise FormProblem(
                "No NDES provider profile is in effect; enrollment over NDES is unavailable."
            )
        if form.ndes_profile not in choices.ndes_profiles:
            raise FormProblem("Choose an NDES provider profile that is in effect.")
        if form.dns_profile:
            raise FormProblem("A DNS provider profile belongs to DNS-01 only.")
    elif form.method not in METHODS:
        raise FormProblem("Choose a challenge method.")
    elif form.ndes_profile:
        raise FormProblem("An NDES provider profile belongs to NDES enrollment only.")
    if wildcard and form.method not in {"dns-01", NDES_METHOD}:
        #
        # Said here as well as by the engine: the engine's refusal would arrive
        # as a failed job on another page, and this is the one rule a reader
        # can act on before pressing the button.
        #
        raise FormProblem(
            "A wildcard certificate needs DNS-01. HTTP-01 cannot prove a wildcard, "
            "because no CA issues one against an HTTP challenge."
        )
    if form.method == NDES_METHOD:
        pass
    elif form.method == "dns-01":
        if choices.profiles_required and not form.dns_profile:
            raise FormProblem("Choose a DNS provider profile that is in effect.")
        if choices.profiles_required and form.dns_profile not in choices.dns_profiles:
            raise FormProblem("The chosen DNS provider profile is not in effect.")
    elif form.dns_profile:
        raise FormProblem("A DNS provider profile belongs to DNS-01 only.")
    if not form.clusters and not form.receivers:
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
    if form.method == NDES_METHOD:
        #
        # The engine's own reading of the name: the base name is the ID and
        # the CN, the wildcard a SAN beside it - the CN is never a wildcard.
        #
        name, names, _ = parse_domain(form.domain)
        return {
            "id": name,
            "profile": form.ndes_profile,
            "domains": [name, *[n for n in names if n != name]],
            "clusters": list(form.clusters),
            "receivers": list(form.receivers),
        }
    payload = {
        "domain": form.domain,
        "method": form.method,
        "clusters": list(form.clusters),
        "receivers": list(form.receivers),
    }
    if form.dns_profile:
        payload["dns_profile"] = form.dns_profile
    return payload


def certificate_id_of(form: IssueForm) -> str:
    """The name the certificate will be listed under, the engine's way.

    Only called for a form `payload_from_form` accepted, so the domain has
    already parsed; the fallback keeps a bad one from raising here.
    """

    try:
        return parse_domain(form.domain)[0]
    except IssueError:
        return form.domain


def _unknown(chosen: Iterable[str], offered: Iterable[str]) -> tuple[str, ...]:
    known = set(offered)
    return tuple(name for name in chosen if name not in known)
