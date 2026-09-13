"""The form that takes a DNS provider's credentials once, and seals them.

What it collects is the catalogue's template for one provider - nothing the
form invents can become a key, a file or a flag - and what it keeps is a
sealed box the web cannot open (B146).  The values pass through the
catalogue's own renderer before they are sealed, so a profile this form
accepts is one the root helper accepts; the rendered file is discarded here
and only ever written by root.

Refusals name fields, never values.  The form is re-drawn with the typed
non-secret values in place; a secret field is always drawn empty, because a
refusal that echoed a token would put it into a response body and a browser
cache.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from haproxy_mgmt.dns_profile_keys import DnsProfilePublicKey
from haproxy_mgmt.dns_profiles import ProfileError, check_profile_id, seal_profile
from haproxy_mgmt.dns_provider_catalog import (
    CredentialField,
    DNSProvider,
    ProviderCatalogError,
    load_catalog,
    provider_by_id,
)

MAX_NAME = 80
MAX_VALUE = 4096
MAX_JSON_VALUE = 16384
MAX_LIST_ITEMS = 32


class FormProblem(Exception):
    """The submission cannot become a profile, and saying so is the answer."""


@dataclass(frozen=True, slots=True)
class ProfileForm:
    """One submission, still in the browser's shape."""

    profile_id: str
    name: str
    provider_id: str
    values: dict[str, str]
    """Every field as typed, keyed by field id; a list field is one value per line."""


@dataclass(frozen=True, slots=True)
class Sealed:
    """What the route stores: the box and its binding."""

    profile_id: str
    name: str
    provider_id: str
    key_id: str
    ciphertext: bytes


EMPTY_FORM = ProfileForm(profile_id="", name="", provider_id="", values={})


def providers() -> tuple[DNSProvider, ...]:
    """The catalogue as the page offers it: core first, then community, by name."""

    return tuple(
        sorted(
            load_catalog(), key=lambda provider: (provider.tier != "core", provider.name.lower())
        )
    )


def provider(provider_id: str) -> DNSProvider | None:
    try:
        return provider_by_id(provider_id)
    except ProviderCatalogError:
        return None


def redraw_values(chosen: DNSProvider | None, values: Mapping[str, str]) -> dict[str, str]:
    """The typed values a re-drawn form may show: everything but the secrets."""

    if chosen is None:
        return {}
    return {field.id: values.get(field.id, "") for field in chosen.fields if not field.secret}


def _field_value(field: CredentialField, raw: str) -> object:
    """One typed value in the shape the catalogue's renderer takes."""

    text = raw.replace("\r\n", "\n")
    if field.kind == "list":
        items = [line.strip() for line in text.split("\n") if line.strip()]
        if len(items) > MAX_LIST_ITEMS:
            raise FormProblem(f"{field.label} — at most {MAX_LIST_ITEMS} entries.")
        return items
    limit = MAX_JSON_VALUE if field.kind == "json" else MAX_VALUE
    if len(text) > limit:
        raise FormProblem(f"{field.label} — too long.")
    return text.strip()


def seal_submission(
    form: ProfileForm,
    public_key: DnsProfilePublicKey,
    *,
    revision: int,
    taken: Iterable[str] = (),
) -> Sealed:
    """Judge one submission and seal it, or say which field is wrong.

    `taken` is the set of existing profile IDs, so a duplicate is refused on
    the form rather than by the database's unique constraint after the box
    has been made.
    """

    profile_id = form.profile_id.strip().lower()
    name = " ".join(form.name.split())
    try:
        check_profile_id(profile_id)
    except ProfileError:
        raise FormProblem(
            "Profile ID — 1-32 lowercase letters, digits or hyphens. It names the "
            "credentials file and is used on the command line, so keep it short."
        ) from None
    if revision == 1 and profile_id in set(taken):
        raise FormProblem("Profile ID — a profile with this ID already exists.")
    if not name or len(name) > MAX_NAME:
        raise FormProblem(f"Name — 1-{MAX_NAME} characters.")
    chosen = provider(form.provider_id)
    if chosen is None:
        raise FormProblem("Choose a DNS provider from the list.")

    fields: dict[str, Any] = {}
    for field in chosen.fields:
        value = _field_value(field, form.values.get(field.id, ""))
        if value == "" or value == []:
            if field.required:
                raise FormProblem(f"{field.label} — required.")
            continue
        fields[field.id] = value
    try:
        ciphertext = seal_profile(
            public_key,
            profile_id=profile_id,
            provider_id=chosen.id,
            revision=revision,
            fields=fields,
        )
    except ProfileError as problem:
        raise FormProblem(_sentence(chosen, str(problem))) from problem
    return Sealed(
        profile_id=profile_id,
        name=name,
        provider_id=chosen.id,
        key_id=public_key.key_id,
        ciphertext=ciphertext,
    )


def _sentence(chosen: DNSProvider, message: str) -> str:
    """The engine's refusal with the field's label in front, when it names one."""

    for field in chosen.fields:
        prefix = f"field {field.id} "
        if message.startswith(prefix):
            return f"{field.label} — {message.removeprefix(prefix)}."
    if message.startswith("exactly one of"):
        labels = ", ".join(
            field.label for field in chosen.fields if field.id in chosen.exactly_one_of
        )
        return f"Give exactly one of: {labels}."
    return message


@dataclass(frozen=True, slots=True)
class ProfileStatus:
    """Whether the file certbot reads is the box the row holds (B147)."""

    label: str
    tone: str
    """`healthy`, `info`, `critical` or `muted` - the status dot the page draws."""

    usable: bool
    """True when the newest apply job for the current revision is done."""


def profile_status(profile_id: str, revision: int, jobs: Iterable[Any]) -> ProfileStatus:
    """Derive a profile's state from its apply jobs, newest first.

    "Saved" and "in effect" are the same thing only once the job that
    materialises the file is done for the current revision; until then the
    page says so rather than showing a profile the certificate form would
    let somebody pick and certbot would then not find.
    """

    for job in jobs:
        if job.operation != "dns_profile_apply" or job.payload.get("profile") != profile_id:
            continue
        job_revision = job.payload.get("revision")
        if job.state in {"pending", "running"}:
            return ProfileStatus("Applying", "info", False)
        if job.state == "done" and job_revision == revision:
            return ProfileStatus("In effect", "healthy", True)
        if job.state == "done":
            return ProfileStatus("Replaced; not applied", "critical", False)
        return ProfileStatus("Apply failed", "critical", False)
    return ProfileStatus("Not applied", "muted", False)
