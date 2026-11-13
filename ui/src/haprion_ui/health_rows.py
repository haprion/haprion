"""One table for a backend's health: what the nodes report, and what was just tried.

The editor used to draw two. HAProxy's own verdict from the nodes, and below
or above it what the nodes answered when somebody pressed Test health check -
the same servers, the same columns, twice. To the reader they are one question,
"is this pool answering", and the second table read as a second opinion rather
than as the first one asked again (2026-09-30).

So a test writes its answers into the rows the nodes report: a server the test
reached shows what the test got, marked as tested, and one the nodes do not
know yet - a check never deployed, a server just typed - gets a row of its own.
The next reading from the poller takes the rows back. What the test could not
reproduce is said under the table, not in the colour of a row.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from haprion_ui import moments, server_card
from haprion_ui.health import BackendHealth, check_phrase
from haprion_ui.probe import NO_HOST_SENT, ProbeReport, Reached

UNREAD = "The certificate was not read: the check stops where verification fails."
#
# What a node says when verification stopped the handshake. A node of 1.0.1
# said `TLS failed:` for every TLS failure, and this reason for that one.
#
VERIFICATION_FAILED = "TLS verification failed:"
OLDER_NODE_VERIFICATION = "TLS failed: CERTIFICATE_VERIFY_FAILED"
UNVERIFIED = "not verified: the pool does not check the server's certificate"


@dataclass(frozen=True, slots=True)
class TlsLine:
    """The line under a tested TLS server: the certificate it presented (B496 nr 9).

    Either `unread` alone - verification failed, so the handshake stopped
    before a certificate could be read - or the certificate's parts.
    """

    unread: str = ""
    name: str = ""
    issuer: str = ""
    until: str = ""
    expired: bool = False
    version: str = ""
    verification: str = ""
    unverified: bool = False


def _version(version: str | None) -> str:
    if not version:
        return ""
    number = version.removeprefix("TLSv")
    return f"TLS {'1.0' if number == '1' else number}"


def _days(count: int) -> str:
    return f"{count} day" if count == 1 else f"{count} days"


def _until(not_after: str | None, now: datetime) -> tuple[str, bool]:
    """`valid until 27-02-01 (in 85 days)`, or `expired ... (3 days ago)` and True."""

    if not not_after:
        return "", False
    ends = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    days = (ends.date() - now.date()).days
    if ends <= now:
        return (
            f"expired {moments.day(ends)} ({'today' if days == 0 else f'{_days(-days)} ago'})",
            True,
        )
    return (
        f"valid until {moments.day(ends)} ({'today' if days == 0 else f'in {_days(days)}'})",
        False,
    )


def tls_line(entry: Reached, now: datetime | None = None) -> TlsLine | None:
    """The line for one tested server, or None: no TLS, or nothing the node said about it."""

    if entry.verified is None:
        return None
    certificate = entry.certificate
    if certificate is None:
        #
        # Only where verification is what stopped the handshake: a connection
        # refused never got that far, and a node older than the field read
        # nothing it could have said.
        #
        error = entry.error or ""
        failed = error.startswith(VERIFICATION_FAILED) or error == OLDER_NODE_VERIFICATION
        return TlsLine(unread=UNREAD) if entry.verified and failed else None
    until, expired = _until(certificate.not_after, now or datetime.now(UTC))
    if entry.verified and entry.authority:
        verification = "verified against the cluster's CA"
    elif entry.verified:
        verification = "verified against the node's trusted CAs"
    else:
        verification = UNVERIFIED
    return TlsLine(
        name=certificate.subject or (certificate.names[0] if certificate.names else ""),
        issuer=f"issued by {certificate.issuer}" if certificate.issuer else "",
        until=until,
        expired=expired,
        version=_version(certificate.version),
        verification=verification,
        unverified=not entry.verified,
    )


@dataclass(frozen=True, slots=True)
class HealthRow:
    node: str
    server: str
    #
    # None for a node that could not be asked at all: the row then carries the
    # reason in `state` and has no server to name.
    #
    up: bool | None
    state: str
    last: str
    code: str = ""
    tested: bool = False
    #
    # The lamp. Not `up`: a server with no check is usable - HAProxy sends it
    # traffic - but nothing has said it answers, and a green lamp there would
    # claim a check that was never made (2026-09-30).
    #
    tone: str = "unknown"
    tls: TlsLine | None = None


def _duration(ms: int | None) -> str:
    return f" · {ms} ms" if ms is not None else ""


def health_rows(backend: BackendHealth | None, probe: ProbeReport | None) -> list[HealthRow]:
    rows: dict[tuple[str, str], HealthRow] = {}
    if backend is not None and backend.known:
        for node in backend.nodes:
            for member in node.members:
                server = backend.address(member.server) or member.server
                code = " ".join(part for part in (member.check_status, member.check_code) if part)
                unchecked = (member.status or "").upper().startswith("NO CHECK")
                phrase = check_phrase(member.check_status or "", member.check_code or "") or "—"
                if (
                    backend.hostless_check
                    and member.check_status == "L7STS"
                    and member.check_code == "400"
                ):
                    phrase += f" · {NO_HOST_SENT}"
                rows[(node.node, server)] = HealthRow(
                    node=node.node,
                    server=server,
                    up=member.up,
                    #
                    # The server card's colour for the same server: a drain is
                    # a choice, yellow there and red here until 26-10-23
                    # (review 2026-10-22, 7-9).
                    #
                    tone="unknown" if unchecked else server_card.cell(member).tone,
                    state=member.status or "unknown",
                    last=phrase + _duration(member.check_duration_ms),
                    code=code,
                )
    if probe is not None and probe.ran:
        for report in probe.nodes:
            #
            # A node without the source address tried nothing; its row is the
            # nodes' own and stays as it was.
            #
            if report.source_held is False:
                continue
            if not report.reachable or report.error:
                rows[(report.node, "")] = HealthRow(
                    node=report.node,
                    server="",
                    up=None,
                    state=report.error or "The node could not be reached",
                    last="",
                    tested=True,
                )
                continue
            for entry in report.results:
                server = f"{entry.host}:{entry.port}"
                rows[(report.node, server)] = HealthRow(
                    node=report.node,
                    server=server,
                    up=entry.ok,
                    tone="healthy" if entry.ok else "critical",
                    state="UP" if entry.ok else "DOWN",
                    #
                    # A udp check that was not refused waited out its whole time
                    # for a refusal that did not come; the time says nothing.
                    #
                    last=f"{entry.phrase}{_duration(None if entry.udp and entry.ok else entry.ms)}"
                    " · tested",
                    tested=True,
                    tls=tls_line(entry),
                )
    return list(rows.values())
