"""Whether a UI release on disk can run on the database's schema (26-10-20).

    python -m haprion_ui.rollback_schema --platform-root <dir> --target <release-id>
                                         --revision <revision>

Asked by `haprion-rollback` before it switches, with the interpreter of the
release the package installed - the one that knows the newest migrations -
and never the target's: a release from before this question existed has no
answer to it. Every release's requirements are read from its own
`compatibility.json`.
Exit 0 when the target runs on the schema, 1 with the reason when it does not.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .compatibility import (
    CompatibilityError,
    Requirements,
    named_release,
    rollback_schema_problem,
    ui_requirements,
)


def owners(root: Path) -> list[Requirements]:
    found = []
    for release in sorted((root / "releases").iterdir()):
        try:
            found.append(ui_requirements(release))
        except CompatibilityError:
            continue  # a release that says nothing carries nothing
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--platform-root", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args(argv)
    try:
        target = ui_requirements(named_release(args.platform_root, args.target, "UI"))
    except CompatibilityError as exc:
        print(f"the target says nothing about its schema: {exc}", file=sys.stderr)
        return 1
    problem = rollback_schema_problem(target, owners(args.platform_root), args.revision)
    if problem is not None:
        print(problem, file=sys.stderr)
        return 1
    print(f"schema {args.revision}, target at {target.database_head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
