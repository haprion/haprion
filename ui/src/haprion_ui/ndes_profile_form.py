"""Collect an NDES endpoint and challenge without retaining a readable secret."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from haprion import ndes_profiles
from haprion.dns_profile_keys import DnsProfilePublicKey
from haprion.dns_profiles import ProfileError, check_profile_id

from haprion_ui.dns_profile_form import FormProblem as FormProblem
from haprion_ui.dns_profile_form import ProfileStatus, Sealed
from haprion_ui.dns_profile_form import profile_status as _status


@dataclass(frozen=True, slots=True)
class ProfileForm:
    profile_id: str
    provider_id: str = "ndes"
    values: dict[str, str] = field(default_factory=dict, repr=False)


EMPTY_FORM = ProfileForm("")


def redraw_values(values: Mapping[str, str]) -> dict[str, str]:
    return {"endpoint": values.get("endpoint", "")}


def seal_submission(
    form: ProfileForm, public_key: DnsProfilePublicKey, *, revision: int, taken: Iterable[str] = ()
) -> Sealed:
    profile_id = form.profile_id.strip().lower()
    try:
        check_profile_id(profile_id)
        if revision == 1 and profile_id in set(taken):
            raise FormProblem("Profile ID already exists.")
        endpoint = ndes_profiles.check_endpoint(form.values.get("endpoint", ""))
        ciphertext = ndes_profiles.seal_profile(
            public_key,
            profile_id=profile_id,
            endpoint=endpoint,
            challenge=form.values.get("challenge", ""),
            revision=revision,
        )
    except ProfileError as exc:
        raise FormProblem(str(exc)) from None
    return Sealed(profile_id, profile_id, "ndes", public_key.key_id, ciphertext, endpoint)


def profile_status(profile_id: str, revision: int, jobs: Iterable[Any]) -> ProfileStatus:
    return _status(profile_id, revision, jobs, operation="ndes_profile_apply")
