"""Where a restored database dump's schema goes (review 26-10-29, A1).

    python -m haprion_ui.restore_schema --platform-root <dir> --packaged <release-id>
                                        --revision <revision>

Asked by `haprion-backup restore` before it stops anything, and by its weekly
`verify-restore`, with the interpreter of the release the package installed.
That release's head is what the package's `03-verify` proves a restored
database against, and every update migrated the database to it; after a
rollback, `current` points at an older release that runs on it.

Prints `same <head> <release>` for a dump at that head, and `migrate <head>
<release>` for an older one the release's migrations take there. Exits 1 with
the reason for any other: a schema past the head, which no migration takes
back (B360); one from before the baseline; or a head the release `current`
points at does not run on, by the rule a rollback uses.
"""

from __future__ import annotations

import sys
from pathlib import Path

from haprion.cli import arguments
from haprion.digits import is_digits

from .compatibility import (
    CompatibilityError,
    before_baseline,
    current_release,
    named_release,
    owners,
    schema_problem,
    ui_requirements,
)


def plan(root: Path, packaged: str, revision: str) -> tuple[str, str]:
    """`("same" | "migrate", head)`; CompatibilityError with the reason otherwise."""

    release = ui_requirements(named_release(root, packaged, "UI"))
    head = release.database_head
    if revision == head:
        return "same", head
    dump = f"the dump is at schema {revision} and {packaged} at {head}"
    refusal = before_baseline(release, revision)
    if refusal is not None:
        raise CompatibilityError(f"{dump}: {refusal}")
    #
    # A dump migrates from any revision between the baseline and the head: the
    # migrations are one chain of consecutive numbers, each as long as the
    # head's (a test holds them to it). The revisions a release runs on are
    # fewer - from the oldest the code still reads - and the dump is not run
    # on, it is migrated first. A number that is not one of them - "01020" and
    # "0100999" sort between two real ones as text - is refused before any
    # service is stopped (review 2026-10-30, R5).
    #
    baseline = release.database_baseline
    migrates = revision in release.database_revisions or (
        baseline is not None
        and is_digits(revision)
        and len(revision) == len(head)
        and int(baseline) <= int(revision) < int(head)
    )
    if not migrates:
        if (
            is_digits(revision)
            and is_digits(head)
            and len(revision) == len(head)
            and int(revision) > int(head)
        ):
            raise CompatibilityError(
                f"{dump}: it comes from a newer release, and no migration goes back"
            )
        raise CompatibilityError(f"{dump}, which has no migration from {revision}")
    running = current_release(root, "UI")
    problem = schema_problem(ui_requirements(running), owners(root, packaged), head)
    if problem is not None:
        raise CompatibilityError(
            f"{dump}; {running.name}, which runs, would not run on {head}: {problem}"
        )
    return "migrate", head


def main(argv: list[str] | None = None) -> int:
    parser = arguments.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--platform-root", required=True, type=Path)
    parser.add_argument("--packaged", required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args(argv)
    try:
        verdict, head = plan(args.platform_root, args.packaged, args.revision)
    except (CompatibilityError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"{verdict} {head} {args.packaged}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
