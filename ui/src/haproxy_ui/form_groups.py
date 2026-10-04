"""The object form's folded groups: which fields each holds, and what it says when closed.

The form shows what an object cannot do without - its name, where it listens,
its servers, what kind of check it has - and folds the rest into groups, all
closed when the page opens (2026-09-30). A folded group is only honest if it
says in one line what it holds, so the object can be read without opening
anything; that line is decided here rather than in the template.

A group is a title, the fields it carries and a function from the form to that
line. Adding a feature to the form is adding its fields to a group here, or a
group of its own, and a block in the template. A test holds every
field of the form to exactly one place - a group, or the short list that is
always shown - so a field cannot be added and forgotten in neither.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from haproxy_mgmt.config import DEFAULT_ABUSE_WINDOW


@dataclass(frozen=True, slots=True)
class FormGroup:
    title: str
    fields: tuple[str, ...]
    summary: Callable[[Mapping[str, Any]], str]
    badges: Callable[[Mapping[str, Any]], tuple[Badge, ...]] = lambda _form: ()


@dataclass(frozen=True, slots=True)
class Badge:
    """A count beside a closed group's line, coloured by what it means.

    With `icon` it is drawn as that icon alone, and `text` is its accessible name.
    """

    text: str
    kind: str
    icon: str = ""


@dataclass(frozen=True, slots=True)
class GroupState:
    title: str
    summary: str
    badges: tuple[Badge, ...] = ()


def _text(form: Mapping[str, Any], key: str) -> str:
    value = form.get(key, "")
    return value.strip() if isinstance(value, str) else ""


def _lines(form: Mapping[str, Any], key: str) -> int:
    return len([line for line in _text(form, key).splitlines() if line.strip()])


def _joined(parts: list[str], empty: str) -> str:
    return " · ".join(part for part in parts if part) or empty


LISTEN_POLICIES = {
    "tls12only": "TLS 1.2 only",
    "intermediate": "TLS 1.2 and 1.3",
    "modern": "TLS 1.3 only",
}
BACKEND_POLICIES = {"modern": "TLS 1.3 only", "legacy": "TLS 1.1 and up"}


def _tls(form: Mapping[str, Any]) -> str:
    parts = ["Redirects HTTP" if form.get("redirect_http") else "No HTTP redirect"]
    if form.get("hsts"):
        age = _text(form, "hsts_max_age")
        days = f" {int(age) // 86400} days" if age.isdigit() else ""
        parts.append(f"HSTS{days}{' with subdomains' if form.get('hsts_subdomains') else ''}")
    else:
        parts.append("no HSTS")
    policy = LISTEN_POLICIES.get(_text(form, "listen_tls_policy"))
    parts.append(policy or "the VIP's TLS")
    return _joined(parts, "")


def _access(form: Mapping[str, Any]) -> str:
    groups = [str(name) for name in form.get("allow_from", ()) or () if str(name).strip()]
    ranges = _lines(form, "allow_ranges")
    who = ", ".join(groups)
    if ranges:
        who = _joined([who, f"{ranges} address{'es' if ranges != 1 else ''}"], "")
    limit = _text(form, "rate_limit")
    window = _text(form, "rate_window") or DEFAULT_ABUSE_WINDOW
    body = _text(form, "max_request_body")
    return _joined(
        [
            f"From {who}" if who else "From everywhere",
            f"at most {limit} per {window}" if limit else "no rate limit",
            f"body ≤ {body}" if body else "",
        ],
        "",
    )


def _access_badges(form: Mapping[str, Any]) -> tuple[Badge, ...]:
    """What the access rules do, in the colours the logs use (Fas 21).

    Yellow counts what only looks - a rule or the deny list in `log` - and red
    what refuses, so a closed group says whether anything on the object is
    turning visitors away.
    """

    modes = [str(mode) for mode in form.get("rule_mode", ()) or ()]
    denied = any(str(name).strip() for name in form.get("deny_from", ()) or ())
    if denied or _lines(form, "deny_ranges"):
        modes.append(_text(form, "deny_mode") or "log")
    logging = sum(mode != "deny" for mode in modes)
    denying = sum(mode == "deny" for mode in modes)
    return tuple(
        Badge(text, kind)
        for text, kind, count in (
            (f"{logging} logging", "warning", logging),
            (f"{denying} denying", "critical", denying),
        )
        if count
    )


def waf_exception_count(form: Mapping[str, Any]) -> int:
    """How many exceptions the object carries, from the field that carries them."""

    try:
        listed = json.loads(_text(form, "waf_exceptions") or "[]")
    except ValueError:
        return 0
    return len(listed) if isinstance(listed, list) else 0


WAF_MODES = {"log": "Logging", "block": "Blocking"}


def _waf(form: Mapping[str, Any]) -> str:
    count = waf_exception_count(form)
    exceptions = f"{count} exception{'s' if count != 1 else ''}" if count else ""
    mode = WAF_MODES.get(_text(form, "waf_mode"))
    if mode is None:
        return _joined(["Off", exceptions], "Off")
    return _joined([mode, f"strictness {_text(form, 'waf_paranoia') or '1'}", exceptions], "")


def _waf_badges(form: Mapping[str, Any]) -> tuple[Badge, ...]:
    """A shield beside the line, in the colours the WAF page uses (26-10-04).

    The line already names the mode; the shield is there so that whether the
    engine is refusing visitors is seen at a glance rather than read.
    """

    mode = _text(form, "waf_mode")
    kind = {"log": "warning", "block": "critical"}.get(mode)
    return (Badge(WAF_MODES[mode], kind, icon="shield"),) if kind else ()


def _maintenance(form: Mapping[str, Any]) -> str:
    return _joined(
        [
            "Out of service" if form.get("maintenance") else "Serving",
            "own text when no server answers" if _text(form, "unavailable_message") else "",
        ],
        "",
    )


def _connections(form: Mapping[str, Any]) -> str:
    tls = {"system": "HTTPS, verified", "none": "HTTPS, not verified"}.get(
        _text(form, "backend_tls"), "Plain HTTP"
    )
    policy = BACKEND_POLICIES.get(_text(form, "backend_tls_policy"), "")
    source = _text(form, "source")
    cookie = _text(form, "cookie")
    limit = _text(form, "max_connections")
    ramp = _text(form, "slow_start")
    return _joined(
        [
            tls,
            policy,
            f"from {source}" if source else "",
            f"cookie {cookie}" if cookie else "",
            f"{limit} per server" if limit else "",
            f"slow start {ramp}" if ramp else "",
        ],
        "",
    )


def _redirect(form: Mapping[str, Any]) -> str:
    path, location = _text(form, "redirect_path"), _text(form, "redirect_location")
    if not path and not location:
        return "None"
    return f"{path or '?'} → {location or '?'} ({_text(form, 'redirect_status') or '301'})"


def _headers(form: Mapping[str, Any]) -> str:
    request, response = _lines(form, "request_headers"), _lines(form, "response_headers")
    return _joined(
        [
            f"{request} on requests" if request else "",
            f"{response} on responses" if response else "",
        ],
        "None",
    )


def _check(form: Mapping[str, Any]) -> str:
    port, host, body = (
        _text(form, "health_port"),
        _text(form, "health_host"),
        _text(form, "health_expect_body"),
    )
    return _joined(
        [
            f"port {port}" if port else "",
            f"Host {host}" if host else "",
            f"body contains {body}" if body else "",
        ],
        "The server's own port",
    )


def _timing(form: Mapping[str, Any]) -> str:
    interval = _text(form, "health_interval")
    rise, fall = _text(form, "health_rise"), _text(form, "health_fall")
    fast, down = _text(form, "health_fast_interval"), _text(form, "health_down_interval")
    return _joined(
        [
            f"every {interval}" if interval else "",
            f"rise {rise}" if rise else "",
            f"fall {fall}" if fall else "",
            f"fast {fast}" if fast else "",
            f"down {down}" if down else "",
        ],
        "Defaults",
    )


#
# In the order they appear on the page. The key is what the template names.
#
GROUPS: Mapping[str, FormGroup] = {
    "tls": FormGroup(
        "TLS and HSTS",
        ("listen_tls_policy", "redirect_http", "hsts", "hsts_subdomains", "hsts_max_age"),
        _tls,
    ),
    "access": FormGroup(
        "Access",
        (
            "allow_from",
            "allow_ranges",
            "rate_limit",
            "rate_window",
            "deny_from",
            "deny_ranges",
            "deny_mode",
            "max_request_body",
            "rule_index",
            "rule_name",
            "rule_mode",
            "rule_path",
            "rule_match",
            "rule_methods",
            "rule_header",
            "rule_header_match",
            "rule_header_value",
            "rule_source",
            "rule_negate",
        ),
        _access,
        _access_badges,
    ),
    "waf": FormGroup("WAF", ("waf_mode", "waf_engine_error", "waf_paranoia"), _waf, _waf_badges),
    "maintenance": FormGroup(
        "Maintenance", ("maintenance", "maintenance_message", "unavailable_message"), _maintenance
    ),
    "connections": FormGroup(
        "Connections",
        (
            "source",
            "backend_tls",
            "backend_tls_policy",
            "cookie",
            "max_connections",
            "slow_start",
        ),
        _connections,
    ),
    "redirect": FormGroup(
        "Redirect",
        ("redirect_path", "redirect_match", "redirect_location", "redirect_status"),
        _redirect,
    ),
    "headers": FormGroup("Headers", ("request_headers", "response_headers"), _headers),
    "check": FormGroup(
        "Check details", ("health_port", "health_host", "health_expect_body"), _check
    ),
    "timing": FormGroup(
        "Timing",
        (
            "health_interval",
            "health_rise",
            "health_fall",
            "health_fast_interval",
            "health_down_interval",
        ),
        _timing,
    ),
}

#
# What is never folded: the fields an object cannot be written without, and the
# ones whose meaning changes what the rest of the form asks.
#
ALWAYS_SHOWN = (
    "name",
    "hostnames",
    "protocol",
    "tcp_port",
    "vip",
    "certificate",
    "backend",
    "servers",
    "balance",
    "balance_key",
    "health_type",
    "health_path",
    "health_expect_status",
    "health_send",
    "health_expect",
)

#
# Never drawn as fields: handed back unchanged in hidden inputs (Fas 17). The
# advanced config is edited in the object's own dialog, and a pool it writes
# has no fields on this form.
#
CARRIED = ("advanced", "handwritten_pool", "waf_exceptions")


def form_groups(form: Mapping[str, Any]) -> dict[str, GroupState]:
    """Each group's title and the line it shows while closed."""

    return {
        key: GroupState(title=group.title, summary=group.summary(form), badges=group.badges(form))
        for key, group in GROUPS.items()
    }
