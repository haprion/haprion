#!/usr/bin/env python3
"""Fail when a CodeQL SARIF result contains an alert, without printing source snippets."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: check-codeql-sarif.py <results.sarif>", file=sys.stderr)
        return 64

    path = Path(sys.argv[1])
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"CodeQL gate: cannot read SARIF: {exc}", file=sys.stderr)
        return 2

    findings: list[tuple[str, str, str]] = []
    for run in document.get("runs", []):
        for result in run.get("results", []):
            rule = str(result.get("ruleId", "unknown-rule"))
            level = str(result.get("level", "warning"))
            location = "unknown-location"
            locations = result.get("locations", [])
            if locations:
                physical = locations[0].get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})
                location = f"{artifact.get('uri', 'unknown')}:{region.get('startLine', '?')}"
            findings.append((rule, level, location))

    if findings:
        print(f"CodeQL gate: FAIL ({len(findings)} alert(s))", file=sys.stderr)
        for rule, level, location in findings:
            print(f"- {level}: {rule} at {location}", file=sys.stderr)
        return 1

    print("CodeQL gate: OK (no alerts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
