"""The WAF engine in the interface (Fas 21 del B, B231, B234).

Where the engine is installed, what each kind of attack means in words, what
it found per object and rule, and the exceptions objects carry. The page is a
place to work: a finding is read as what matched and where, and let through
with an exception that becomes a draft of the object.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from haproxy_mgmt.proxy_model import ModelError, dump_document, load_proxy, read_document

from haproxy_ui import objects
from haproxy_ui.preview import canonical_waf, canonical_waf_exception

#
# The rule set's files by number, as a person would name what each detects
# (B234, round 4). Ours, not the rule set's: its own names (`APPLICATION-ATTACK-
# LFI`) say nothing to somebody deciding whether a finding is a false alarm.
#
KINDS: Mapping[int, tuple[str, str]] = {
    911: (
        "Method",
        "The request used an HTTP method the site is not expected to accept.",
    ),
    913: (
        "Scanner",
        "The request came from a tool that searches sites for weaknesses.",
    ),
    920: (
        "Protocol",
        "The request breaks the rules of HTTP itself - a missing or odd header, "
        "an address where a name belongs. Often a client or a monitor, not an attack.",
    ),
    921: (
        "Protocol attack",
        "The request is shaped to make HTTP mean two things at once, such as "
        "smuggling a second request inside the first.",
    ),
    922: (
        "Multipart",
        "An uploaded form is put together in a way meant to confuse whoever reads it.",
    ),
    930: (
        "Path traversal",
        "The request tries to reach files outside the site, with ../ or a known system file.",
    ),
    931: (
        "Remote file inclusion",
        "The request hands the site an address of a file elsewhere, hoping it will load it.",
    ),
    932: (
        "Command injection",
        "The request carries operating system commands, hoping the site will run them.",
    ),
    933: (
        "PHP injection",
        "The request carries PHP code or names, hoping a PHP site will run them.",
    ),
    934: (
        "Generic attack",
        "The request carries code for other platforms - Node.js, Python, template "
        "engines - or points the site at its own internal addresses.",
    ),
    941: (
        "XSS",
        "The request carries script meant to run in another visitor's browser.",
    ),
    942: (
        "SQL injection",
        "The request carries database commands, hoping the site will pass them on.",
    ),
    943: (
        "Session fixation",
        "The request tries to give a visitor a session identifier chosen by somebody else.",
    ),
    944: (
        "Java attack",
        "The request carries Java code or class names, hoping a Java site will run them.",
    ),
}


def kind(file: int) -> tuple[str, str]:
    """A rule file's kind and its explanation; the number itself when it is none of ours."""

    return KINDS.get(file, (f"Rule set {file}", ""))


@dataclass(frozen=True, slots=True)
class Engine:
    """Where the engine is installed, from the manager's listing and the nodes' status."""

    engine: str | None
    rules: str | None
    missing: Mapping[str, tuple[str, ...]]
    """Per cluster, the nodes whose status says no engine."""

    def unavailable(self, cluster: str) -> str:
        """Why an object on this cluster cannot be given the engine; empty when it can."""

        places = list(self.missing.get(cluster, ()))
        if self.engine is None or self.rules is None:
            places.append("the manager")
        if not places:
            return ""
        joined = places[0] if len(places) == 1 else f"{', '.join(places[:-1])} and {places[-1]}"
        return f"The WAF engine is not installed on {joined}."

    def summary(self) -> str:
        """The Features row: the versions, or where the engine is missing."""

        places = sorted({node for nodes in self.missing.values() for node in nodes})
        if self.engine is None or self.rules is None:
            places.append("the manager")
        if places:
            joined = places[0] if len(places) == 1 else f"{', '.join(places[:-1])} and {places[-1]}"
            return f"Not installed on {joined}"
        return f"Engine {self.engine} · CRS {self.rules}"


def engine(object_rows: Iterable[Any], status_rows: Iterable[Any]) -> Engine:
    versions: Mapping[str, Any] = {}
    for row in object_rows:
        result = row.result if isinstance(row.result, Mapping) else {}
        found = result.get("waf")
        if isinstance(found, Mapping):
            versions = found
            break
    missing: dict[str, tuple[str, ...]] = {}
    for row in status_rows:
        result = row.result if isinstance(row.result, Mapping) else {}
        absent = []
        for entry in result.get("nodes") or ():
            if not isinstance(entry, Mapping):
                continue
            status = entry.get("status")
            waf = status.get("waf_engine") if isinstance(status, Mapping) else None
            #
            # A node from before the field, or one that did not answer, is a
            # node the engine cannot be counted on: the schema says so (B231).
            #
            if not isinstance(waf, Mapping) or not isinstance(waf.get("version"), str):
                absent.append(str(entry.get("name", "")))
        missing[row.cluster] = tuple(sorted(absent))
    engine_version = versions.get("engine")
    rules_version = versions.get("crs")
    return Engine(
        engine=engine_version if isinstance(engine_version, str) else None,
        rules=rules_version if isinstance(rules_version, str) else None,
        missing=missing,
    )


def objects_using(object_rows: Iterable[Any]) -> list[str]:
    """`cluster/object` for every stored object the engine inspects (B231).

    An object in `off` is not one: its settings are kept, and nothing the
    engine would filter is hidden by turning the switch off.
    """

    using = []
    for row in object_rows:
        for view in objects.cluster_object_views(row):
            if not view.readable:
                continue
            try:
                proxy = load_proxy(view.name, view.document.encode())
            except (ModelError, UnicodeError):
                continue
            if proxy.inspected is not None:
                using.append(f"{row.cluster}/{view.name}")
    return sorted(using)


#
# - Findings -----------------------------------------------------------------
#


@dataclass(frozen=True, slots=True)
class ObjectException:
    """One exception as an object carries it: a rule, and as narrow as it was made."""

    rule: int
    field: str
    paths: tuple[str, ...]
    by: str
    at: str

    def covers(self, rule: int, field: str, paths: Iterable[str]) -> bool:
        """Whether this lets the rule through wherever it was found."""

        if rule != self.rule or (self.field and self.field != field):
            return False
        return not self.paths or set(paths) <= set(self.paths)


def object_exceptions(document: str) -> tuple[ObjectException, ...] | None:
    """The exceptions in a stored or drafted object; None when it has no WAF settings."""

    try:
        data = read_document("object", document.encode())
    except (ModelError, UnicodeError):
        return None
    block = canonical_waf(data.get("waf"))
    if not isinstance(block, Mapping):
        return None
    return _exceptions_from(block)


def _exceptions_from(block: Mapping[str, Any]) -> tuple[ObjectException, ...]:
    """The exceptions in an object's `waf` block, as one reader reads them everywhere."""

    found = []
    for item in block.get("exceptions", []) or []:
        if not isinstance(item, Mapping) or not isinstance(item.get("rule"), int):
            continue
        paths = item.get("paths", [])
        found.append(
            ObjectException(
                rule=item["rule"],
                field=str(item.get("field", "") or ""),
                paths=tuple(str(p) for p in paths) if isinstance(paths, list) else (),
                by=str(item.get("by", "") or ""),
                at=str(item.get("at", "") or ""),
            )
        )
    return tuple(found)


def object_mode(document: str) -> str:
    """`log`, `block` or `off`, as the object says; `off` without WAF settings."""

    try:
        data = read_document("object", document.encode())
    except (ModelError, UnicodeError):
        return "off"
    block = canonical_waf(data.get("waf"))
    return str(block.get("mode", "log")) if isinstance(block, Mapping) else "off"


@dataclass(frozen=True, slots=True)
class Finding:
    rule: int
    kind: str
    explanation: str
    message: str
    severity: str
    field: str
    shown_field: str
    matched: str
    paths: tuple[str, ...]
    more_paths: int
    requests: int
    clients: int
    last_seen: Any
    in_draft: bool
    allow_href: str


@dataclass(frozen=True, slots=True)
class ObjectFindings:
    cluster: str
    name: str
    mode: str
    judged: int
    clients: int
    findings: tuple[Finding, ...]
    edit_href: str


def shown_field(field: str) -> str:
    """The part of the request as a person names it: `q` for `ARGS:q`, a header by its name."""

    collection, separator, key = field.partition(":")
    if not separator:
        return {
            "REQUEST_FILENAME": "path",
            "REQUEST_BASENAME": "file name",
            "REQUEST_URI": "address",
            "REQUEST_URI_RAW": "address",
            "REQUEST_LINE": "request line",
            "REQUEST_BODY": "body",
            "QUERY_STRING": "query",
        }.get(collection, field.lower())
    if collection in ("ARGS", "ARGS_GET", "ARGS_POST"):
        return key.removeprefix("json.")
    if collection in ("REQUEST_COOKIES", "REQUEST_COOKIES_NAMES"):
        return f"cookie {key}"
    if collection in ("ARGS_NAMES",):
        return f"field name {key}"
    return key


def _allow_href(cluster: str, name: str, row: Any) -> str:
    query = [("cluster", cluster), ("object", name), ("rule", str(row.rule_id))]
    if row.field:
        query.append(("field", row.field))
    query += [("path", path) for path in row.paths]
    return "/waf/allow?" + urlencode(query)


def build_findings(
    rows: Iterable[Any],
    verdicts: Mapping[tuple[str, str], tuple[int, int]],
    stored: Mapping[tuple[str, str], str],
    drafted: Mapping[tuple[str, str], str],
    rules: Mapping[int, Any],
) -> list[ObjectFindings]:
    """The Findings view: per object, its rules, without what a published exception covers.

    A finding the published object already lets through is left out - what
    remains is what still needs a decision. One the draft lets through but the
    nodes do not yet stays, saying so, until the draft is published. An object
    whose engine is off, or that has no WAF any more, is left out: an exception
    would change nothing there. Its counts are kept, and come back with the engine.
    """

    grouped: dict[tuple[str, str], list[Finding]] = {}
    for row in rows:
        key = (row.cluster, row.object)
        published = object_exceptions(stored.get(key, "")) or ()
        if any(e.covers(row.rule_id, row.field, row.paths) for e in published):
            continue
        draft = drafted.get(key)
        pending = object_exceptions(draft) or () if draft is not None else ()
        rule = rules.get(row.rule_id)
        name, explanation = kind(row.rule_id // 1000)
        grouped.setdefault(key, []).append(
            Finding(
                rule=row.rule_id,
                kind=name,
                explanation=explanation,
                message=(
                    rule.message if rule is not None and rule.message else f"Rule {row.rule_id}"
                ),
                severity=rule.severity if rule is not None else "",
                field=row.field,
                shown_field=shown_field(row.field) if row.field else "",
                matched=row.matched,
                paths=tuple(row.paths),
                more_paths=max(0, row.path_count - len(row.paths)),
                requests=row.requests,
                clients=row.clients,
                last_seen=row.last_seen,
                in_draft=any(e.covers(row.rule_id, row.field, row.paths) for e in pending),
                allow_href=_allow_href(row.cluster, row.object, row),
            )
        )
    cards = []
    for (cluster, name), findings in sorted(grouped.items()):
        document = drafted.get((cluster, name)) or stored.get((cluster, name), "")
        mode = object_mode(document)
        if mode == "off":
            continue
        judged, clients = verdicts.get((cluster, name), (0, 0))
        cards.append(
            ObjectFindings(
                cluster=cluster,
                name=name,
                mode=mode,
                judged=judged,
                clients=clients,
                findings=tuple(findings),
                edit_href=f"/proxies/{cluster}/{name}/edit",
            )
        )
    return cards


#
# - Exceptions ---------------------------------------------------------------
#


@dataclass(frozen=True, slots=True)
class ExceptionRow:
    cluster: str
    name: str
    exception: ObjectException
    kind: str
    explanation: str
    message: str
    severity: str
    in_draft: bool
    """Made in the draft and not yet published."""
    index: int = -1
    """Its place in the form's own list, which the editor's Remove names; -1 elsewhere."""


def build_exceptions(
    stored: Mapping[tuple[str, str], str],
    drafted: Mapping[tuple[str, str], str],
    rules: Mapping[int, Any],
) -> list[ExceptionRow]:
    """Every exception the objects carry: the draft's where there is one, marked when unpublished."""

    rows = []
    for key in sorted(set(stored) | set(drafted)):
        published = object_exceptions(stored.get(key, "")) or ()
        current = object_exceptions(drafted[key]) or () if key in drafted else published
        for exception in current:
            rule = rules.get(exception.rule)
            name, explanation = kind(exception.rule // 1000)
            rows.append(
                ExceptionRow(
                    cluster=key[0],
                    name=key[1],
                    exception=exception,
                    kind=name,
                    explanation=explanation,
                    message=rule.message
                    if rule is not None and rule.message
                    else f"Rule {exception.rule}",
                    severity=rule.severity if rule is not None else "",
                    in_draft=exception not in published,
                )
            )
    return rows


def form_exceptions(
    cluster: str,
    name: str,
    carried: str,
    published_document: str,
    rules: Mapping[int, Any],
) -> list[ExceptionRow]:
    """The exceptions the editor is about to publish, as the WAF page shows them.

    `carried` is the form's own field (JSON, as `preview` writes it), so the
    list is what Save and publish would send - not what is stored. An exception
    the published object lacks is marked, so the person sees what is new before
    they publish it (26-10-03).
    """

    try:
        listed = json.loads(carried or "[]")
    except ValueError:
        return []
    if not isinstance(listed, list):
        return []
    published = object_exceptions(published_document) or ()
    rows = []
    for index, item in enumerate(listed):
        parsed = _exceptions_from({"exceptions": [item]})
        if not parsed:
            continue
        exception = parsed[0]
        rule = rules.get(exception.rule)
        kind_name, explanation = kind(exception.rule // 1000)
        rows.append(
            ExceptionRow(
                cluster=cluster,
                name=name,
                exception=exception,
                kind=kind_name,
                explanation=explanation,
                message=rule.message
                if rule is not None and rule.message
                else f"Rule {exception.rule}",
                severity=rule.severity if rule is not None else "",
                in_draft=exception not in published,
                index=index,
            )
        )
    return rows


def without_form_exception(carried: str, index: int) -> str:
    """The form's exceptions without the one at that place; unchanged when there is none."""

    try:
        listed = json.loads(carried or "[]")
    except ValueError:
        return carried
    if not isinstance(listed, list) or not 0 <= index < len(listed):
        return carried
    del listed[index]
    return json.dumps(listed, separators=(",", ":")) if listed else ""


def where(exception: ObjectException, name: str) -> str:
    """Where an exception applies, in words."""

    field = shown_field(exception.field) if exception.field else ""
    paths = ", ".join(exception.paths)
    if field and paths:
        return f"{field} on {paths}"
    if field:
        return f"{field}, every path"
    if paths:
        return paths
    return f"Everywhere on {name}"


#
# - Changing the object ------------------------------------------------------
#

SCOPES = ("field_paths", "field", "paths", "object")


def exception_for(
    scope: str, *, rule: int, field: str, paths: Iterable[str], by: str, at: str
) -> dict[str, Any]:
    """The exception a choice in the Allow dialog makes."""

    if scope not in SCOPES or (scope.startswith("field") and not field):
        raise ValueError("choose where to let it through")
    chosen = sorted(set(paths))
    if scope in ("field_paths", "paths") and not chosen:
        raise ValueError("choose at least one path")
    exception: dict[str, Any] = {"rule": rule}
    if scope.startswith("field"):
        exception["field"] = field
    if scope in ("field_paths", "paths"):
        exception["paths"] = chosen
    exception["by"] = by
    exception["at"] = at
    return exception


def _scope(item: Any) -> tuple[Any, str, tuple[str, ...]]:
    if not isinstance(item, Mapping):
        return (None, "", ())
    paths = item.get("paths", [])
    return (
        item.get("rule"),
        str(item.get("field", "") or ""),
        tuple(sorted(str(p) for p in paths)) if isinstance(paths, list) else (),
    )


def with_exception(name: str, document: str, exception: Mapping[str, Any]) -> str:
    """The object's document with one exception more; unchanged if it already has that scope."""

    data: dict[str, Any] = dict(read_document(name, document.encode()))
    block = canonical_waf(data.get("waf"))
    if not isinstance(block, dict):
        raise ValueError(f"{name} no longer uses the WAF engine")
    listed = list(block.get("exceptions", []))
    if any(_scope(item) == _scope(exception) for item in listed):
        return document
    block["exceptions"] = [*listed, canonical_waf_exception(dict(exception))]
    data["waf"] = block
    return dump_document(data)


def without_exception(
    name: str, document: str, *, rule: int, field: str, paths: Iterable[str]
) -> str:
    """The object's document without the exception of that scope."""

    data: dict[str, Any] = dict(read_document(name, document.encode()))
    block = canonical_waf(data.get("waf"))
    if not isinstance(block, dict):
        raise ValueError(f"{name} has no WAF exceptions")
    wanted = (rule, field, tuple(sorted(paths)))
    listed = list(block.get("exceptions", []))
    kept = [item for item in listed if _scope(item) != wanted]
    if len(kept) == len(listed):
        raise ValueError("that exception is no longer on the object")
    if kept:
        block["exceptions"] = kept
    else:
        block.pop("exceptions", None)
    rewritten = canonical_waf(block)
    if rewritten is None:
        data.pop("waf", None)
    else:
        data["waf"] = rewritten
    return dump_document(data)
