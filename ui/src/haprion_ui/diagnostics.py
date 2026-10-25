"""Bounded, redacted diagnostics safe to persist with a job.

stderr crosses a privilege boundary in the wrong direction: a root helper may
name files and values the worker is not otherwise allowed to read.  Keeping a
useful excerpt is still operationally important, but it has to become safe
before it leaves the subprocess runner.
"""

from __future__ import annotations

import re
from typing import Any

LIMIT_BYTES = 65_536
TRUNCATION_MARKER = "\n...[diagnostics truncated]...\n"
REDACTED = "[REDACTED]"
#
# PostgreSQL stores no NUL: a text column refuses the byte and jsonb the
# escape. One in a helper's stderr or answer failed `finish_job` with a
# DataError that nothing caught, the worker stopped, and the job ended
# `unknown` with its real outcome lost (review 26-10-24, 05-08). It becomes
# the replacement character, which says a byte was there.
#
NUL = "\x00"
NUL_SHOWN = "\ufffd"

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?"
    r"(?:-----END [^-\r\n]*PRIVATE KEY-----|\Z)",
    re.IGNORECASE | re.DOTALL,
)
_PRIVATE_KEY_TAIL = re.compile(
    r"\A.*?-----END [^-\r\n]*PRIVATE KEY-----", re.IGNORECASE | re.DOTALL
)
#
# A credential's name, in the forms a credentials file or a tool's error spells
# it: certbot's DNS plugins name theirs `dns_<provider>_api_key`, `..._token`
# or `..._secret` (review 2026-10-22, 5-9). Not a bare `key`: HAProxy's
# refusals name `ssl-crt-key`-like keywords and key types, and masking them
# would hide the line that says what is wrong.
#
_SECRET_ASSIGNMENT = re.compile(
    r"(?im)(\b[a-z0-9_.-]*(?:token|password|passwd|secret|credential|api[_-]?key|access[_-]?key"
    r"|private[_-]?key)[a-z0-9_.-]*\s*(?:=|:)\s*)[^\r\n]*"
)
_SENSITIVE_PATH = re.compile(
    r"(?i)(?<![^\s\"'<>])(?=[^\s\"'<>]*(?:\.ssh(?:/|$)|/secrets/|/ui-secrets(?:/|$)|"
    r"/etc/ssl/private/|/srv/certificates(?:/|$)|"
    r"/srv/haprion/validation(?:/|$)))[^\s\"'<>]+"
)


def _prefix(encoded: bytes, size: int) -> str:
    """Return at most ``size`` bytes without splitting one UTF-8 character."""

    return encoded[:size].decode("utf-8", "ignore")


def _suffix(encoded: bytes, size: int) -> str:
    """Return at most ``size`` trailing bytes on a UTF-8 character boundary."""

    return encoded[-size:].decode("utf-8", "ignore")


def redact(value: str) -> str:
    """Mask the minimum secret and private-path classes in contract v1."""

    value = _PRIVATE_KEY.sub(REDACTED, value)
    value = _PRIVATE_KEY_TAIL.sub(REDACTED, value)
    value = _SECRET_ASSIGNMENT.sub(lambda match: match.group(1) + REDACTED, value)
    return _SENSITIVE_PATH.sub(REDACTED, value)


def safe_excerpt(value: str, *, limit_bytes: int = LIMIT_BYTES) -> str:
    """Redact and retain bounded first/last UTF-8 diagnostics.

    The marker consumes part of the byte budget, so the two retained edges are
    as close to 32 KiB each as the database's hard 65,536-byte cap permits.
    """

    if limit_bytes < len(TRUNCATION_MARKER.encode("utf-8")) + 2:
        raise ValueError("the diagnostics limit is too small for the truncation marker")

    redacted = redact(value.replace(NUL, NUL_SHOWN))
    encoded = redacted.encode("utf-8")
    if len(encoded) <= limit_bytes:
        return redacted

    marker_size = len(TRUNCATION_MARKER.encode("utf-8"))
    edge_budget = limit_bytes - marker_size
    first_size = edge_budget // 2
    last_size = edge_budget - first_size
    return _prefix(encoded, first_size) + TRUNCATION_MARKER + _suffix(encoded, last_size)


def redact_result(value: Any) -> Any:
    """The result document with every `diagnostics` text in it redacted, and no NUL in it.

    A helper's refusal carries its evidence under `error.details.diagnostics`
    and the job row stores the document as it arrived; the manual promises the
    same masking there as in the stderr excerpt (review 2026-10-22, 5-9). Every
    such text, at any depth, since a wrapped answer (`exit_mismatch`) carries
    the helper's envelope inside the worker's own.
    """

    if isinstance(value, dict):
        return {
            _stored(key) if isinstance(key, str) else key: redact(_stored(item))
            if key == "diagnostics" and isinstance(item, str)
            else redact_result(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_result(item) for item in value]
    if isinstance(value, str):
        return _stored(value)
    return value


def _stored(text: str) -> str:
    return text.replace(NUL, NUL_SHOWN)
