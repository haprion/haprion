#!/usr/bin/env python3
"""Rewrite the golden files from the objects they come from.

Run this after deliberately changing what the generator emits. It is the
command that makes such a change cheap: regenerate, then read the diff, which
shows exactly which routes, names or GUIDs changed behaviour. Reading that diff
is the review - the tool does not decide anything, it only removes the typing.

Files that no longer belong to a case are deleted, so a case cannot keep
asserting a file the generator stopped producing.
"""

from __future__ import annotations

import sys

from haproxy_mgmt.golden import (
    DNS_FILES,
    GOLDEN,
    IPVS_FILES,
    cases,
    produced,
    produced_dns,
    produced_ipvs,
)


def main() -> int:
    for case in cases(GOLDEN):
        files = {**produced(case), **produced_dns(case), **produced_ipvs(case)}
        for name, content in sorted(files.items()):
            path = case / name
            if not path.exists() or path.read_text() != content:
                print(f"writing {path.relative_to(GOLDEN.parent.parent)}")
            path.write_text(content)
        for path in sorted(
            [*case.glob("*.cfg"), *(case / name for name in (*DNS_FILES, *IPVS_FILES))]
        ):
            if not path.exists():
                continue
            if path.name not in files:
                print(f"removing {path.relative_to(GOLDEN.parent.parent)}")
                path.unlink()
    return 0


if __name__ == "__main__":
    sys.exit(main())
