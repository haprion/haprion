"""What a certificate's BMC page says (B526, B536), apart from the routes that draw it.

The page asks the BMC through root (`haprion.bmc_socket`): *Check* signs in
with the account the web sealed and shows what the BMC serves, for the
administrator to compare with the BMC's own web page; *Save and install*
writes what was confirmed and installs at once. Everything the routes need to
say about that answer, and about the target once it is saved, is here.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from haprion.config import ConfigError, bmc_target
from haprion.digits import is_digits

from haprion_ui import moments
from haprion_ui.certificates import BmcView

FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_PORT = 443
#
# Who started the last install, as the page says it.
#
STARTED_BY = {
    "timer": "automatically",
    "install_now": "by Install now",
    "save": "when the BMC was saved",
}


class BmcProblem(Exception):
    """Something the page says instead of going on: a field, or the BMC's answer."""


def fingerprint(value: str) -> str:
    """A SHA-256 as a BMC's web page shows it: pairs of capitals, colon between."""

    if not FINGERPRINT.fullmatch(value):
        return value
    return ":".join(value[index : index + 2] for index in range(0, 64, 2)).upper()


def address_of(value: str) -> str:
    """The address as typed, held to the registry's own rule for a BMC's host."""

    address = value.strip()
    if not address:
        raise BmcProblem("Enter the BMC's name or address.")
    try:
        bmc_target(
            {"address": address, "fingerprint_sha256": "0" * 64, "username": "-"},
            "address",
        )
    except ConfigError:
        raise BmcProblem(f"{address} is not a name or address.") from None
    return address


def port_of(value: str) -> int:
    """The port a target was saved with, carried through the form; 443 when none."""

    if not value:
        return DEFAULT_PORT
    if not is_digits(value) or not 1 <= int(value) <= 65535:
        raise BmcProblem("The port was not read.")
    return int(value)


@dataclass(frozen=True, slots=True)
class Checked:
    """The BMC's answer to *Check*: what it serves, its firmware, and the account."""

    address: str
    port: int
    served_sha256: str
    subject: str
    issuer: str
    expires: datetime | None
    model: str
    firmware: str
    may_upload: bool | None

    @property
    def served(self) -> str:
        """The certificate it serves, on one line: name, issuer, expiry."""

        parts = [self.subject or "no name", self.issuer or "unknown issuer"]
        if self.expires is not None:
            parts.append(f"expires {moments.day(self.expires)}")
        return " · ".join(parts)

    @property
    def firmware_line(self) -> str:
        return " · ".join(part for part in (self.model, self.firmware) if part) or "Not said"

    @property
    def account_line(self) -> str:
        if self.may_upload is True:
            return "Signed in, may upload certificates"
        if self.may_upload is False:
            return "Signed in, but may not upload certificates: the account needs the Administrator role"
        return "Signed in; whether it may upload certificates was not said"


def checked(result: Mapping[str, Any]) -> Checked:
    """The helper's answer as the page reads it; a broken one is said, not drawn."""

    served = result.get("served_sha256")
    address = result.get("address")
    port = result.get("port")
    if (
        not isinstance(served, str)
        or not FINGERPRINT.fullmatch(served)
        or not isinstance(address, str)
        or not isinstance(port, int)
    ):
        raise BmcProblem("The BMC service's answer was incomplete.")
    may_upload = result.get("may_upload")
    return Checked(
        address=address,
        port=port,
        served_sha256=served,
        subject=_text(result.get("subject")),
        issuer=_text(result.get("issuer")),
        expires=_moment(result.get("not_after")),
        model=_text(result.get("model")),
        firmware=_text(result.get("firmware")),
        may_upload=may_upload if isinstance(may_upload, bool) else None,
    )


def duration(seconds: float) -> str:
    whole = round(seconds)
    if whole < 60:
        return f"{whole} s"
    minutes, rest = divmod(whole, 60)
    return f"{minutes} min {rest} s" if rest else f"{minutes} min"


def last_install(view: BmcView) -> str:
    """When the last install was, who started it, and how it ended; empty when there was none."""

    if view.attempt_at is None or view.attempt_outcome is None:
        return ""
    parts = [moments.moment(view.attempt_at)]
    started = STARTED_BY.get(view.attempt_by or "")
    if started:
        parts[0] += f" {started}"
    if view.attempt_outcome == "done":
        if view.attempt_seconds is not None:
            parts.append(f"took {duration(view.attempt_seconds)}")
    elif view.attempt_outcome == "unreached":
        parts.append("the BMC did not answer; installs the next time it does")
    elif view.unreadable:
        parts.append(f"the BMC could not be read: {view.attempt_message or 'it did not say why'}")
    else:
        parts.append(f"failed: {view.attempt_message or 'the BMC did not say why'}")
    return " · ".join(parts)


def refusal(code: str, message: str, *, address: str, port: int, asked: str) -> str:
    """What the page says when the BMC service or the BMC said no; `asked` is check, save or remove."""

    if code == "bmc_unreachable":
        return (
            f"{address} did not answer on port {port}. Check that the BMC is on and that "
            f"nothing between this manager and the BMC blocks port {port}. ({message})"
        )
    if code == "bmc_login_refused":
        return (
            f"{address} refused the account. Check the user and the password, and that the "
            "account's type is Redfish."
        )
    if code == "expected_target_changed":
        return "The BMC now serves another certificate than the one shown. Check it again."
    if code == "unanswered":
        if asked == "check":
            return "The BMC service did not answer in time. Nothing was changed; check again."
        return (
            "The BMC service did not answer in time, and may have made the change. "
            "Open the certificate again to see what it holds."
        )
    return message


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _moment(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
