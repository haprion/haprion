#!/usr/bin/env python3
"""Fail when a CodeQL SARIF result contains an alert, without printing source snippets.

A small number of alerts describe the privilege contract working as designed:
`PRIVILEGE.md` requires the config repository and the published releases to be
root-owned and group-readable, which CodeQL reports as an overly permissive
mask. Those are not suppressed in the source - a suppression comment would make
the next reader believe the query was wrong - but recorded in
`tools/codeql-accepted.json` with the reason and the date the decision was
taken, and printed on every run so the decision stays visible.

The record is deliberately narrow. An entry matches on rule, file and the exact
message text, so a group-readable acceptance never covers a world-readable
finding in the same file, and it carries no line number, which would otherwise
have to be rewritten every time the file moved a line. An entry that matches
nothing is itself a failure: an acceptance whose finding is gone has stopped
being a decision and become a hole.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, NamedTuple

ACCEPTED_PATH = Path(__file__).resolve().parent / "codeql-accepted.json"

REQUIRED_FIELDS = ("rule", "path", "message", "decided", "reason")


class Finding(NamedTuple):
    rule: str
    level: str
    path: str
    line: str
    message: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.rule, self.path, self.message)

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}"


class GateError(Exception):
    """The gate cannot reach a verdict."""


def _load_accepted(path: Path) -> dict[tuple[str, str, str], str]:
    """The recorded decisions, keyed the same way findings are."""

    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot read {path.name}: {exc}") from exc

    if not isinstance(document, dict) or not isinstance(document.get("accepted"), list):
        raise GateError(f"{path.name} must hold an object with an 'accepted' list")

    accepted: dict[tuple[str, str, str], str] = {}
    for index, entry in enumerate(document["accepted"]):
        if not isinstance(entry, dict):
            raise GateError(f"{path.name} entry {index} is not an object")
        missing = [field for field in REQUIRED_FIELDS if not str(entry.get(field, "")).strip()]
        if missing:
            raise GateError(f"{path.name} entry {index} is missing {', '.join(missing)}")
        key = (str(entry["rule"]), str(entry["path"]), str(entry["message"]))
        if key in accepted:
            raise GateError(f"{path.name} entry {index} repeats an earlier acceptance")
        accepted[key] = f"{entry['decided']}: {entry['reason']}"
    return accepted


def _read_findings(path: Path) -> list[Finding]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot read SARIF: {exc}") from exc

    findings: list[Finding] = []
    for run in document.get("runs", []):
        for result in run.get("results", []):
            locations = result.get("locations", [])
            physical = locations[0].get("physicalLocation", {}) if locations else {}
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            findings.append(
                Finding(
                    rule=str(result.get("ruleId", "unknown-rule")),
                    level=str(result.get("level", "warning")),
                    path=str(artifact.get("uri", "unknown")),
                    line=str(region.get("startLine", "?")),
                    message=str(result.get("message", {}).get("text", "")),
                )
            )
    return findings


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: check-codeql-sarif.py <results.sarif> [results.sarif ...]", file=sys.stderr)
        return 64

    #
    # Every result file in one verdict. The run analyses one database per
    # language, and an acceptance that matches nothing is itself a failure - so
    # judging the files one at a time would report every Python acceptance as
    # stale against the JavaScript results, and the gate would fail on its own
    # bookkeeping rather than on the code.
    #
    try:
        accepted = _load_accepted(ACCEPTED_PATH)
        findings = [finding for name in sys.argv[1:] for finding in _read_findings(Path(name))]
    except GateError as exc:
        print(f"CodeQL gate: {exc}", file=sys.stderr)
        return 2

    unaccepted = [finding for finding in findings if finding.key not in accepted]
    matched = {finding.key for finding in findings if finding.key in accepted}
    stale = [key for key in accepted if key not in matched]

    for finding in findings:
        if finding.key in accepted:
            print(f"CodeQL gate: accepted {finding.rule} at {finding.location}")
            print(f"  {accepted[finding.key]}")

    if stale:
        print("CodeQL gate: FAIL (acceptance no longer matches any alert)", file=sys.stderr)
        for rule, path, message in stale:
            print(f"- {rule} at {path}: {message}", file=sys.stderr)
        print(
            "Remove the entry from tools/codeql-accepted.json; the finding it documented is gone.",
            file=sys.stderr,
        )
        return 1

    if unaccepted:
        print(f"CodeQL gate: FAIL ({len(unaccepted)} alert(s))", file=sys.stderr)
        for finding in unaccepted:
            print(f"- {finding.level}: {finding.rule} at {finding.location}", file=sys.stderr)
        return 1

    print(f"CodeQL gate: OK (no alerts beyond {len(matched)} recorded acceptance(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
