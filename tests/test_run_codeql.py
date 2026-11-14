"""`tools/run-codeql` keeps the results and not the databases (2026-10-07).

The databases are a step towards the SARIF: nothing reads them afterwards, and
left behind they grew to 38 GB over 222 runs. A stand-in for the CodeQL binary
builds a database and then fails the analysis, which is the case a cleanup
written for the happy path would miss.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SCRIPT = BASE / "tools" / "run-codeql"

STAND_IN = """#!/bin/sh
if [ "$1" = database ] && [ "$2" = create ]; then
    mkdir -p "$3/python"
    echo data > "$3/python/db"
    exit 0
fi
exit 3
"""


class RunCodeqlTests(unittest.TestCase):
    def test_a_failed_analysis_leaves_no_database_behind(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            codeql = root / "codeql"
            codeql.write_text(STAND_IN, encoding="utf-8")
            codeql.chmod(0o755)
            output = root / "result"

            run = subprocess.run(
                [str(SCRIPT), str(output)],
                env={**os.environ, "CODEQL_BIN": str(codeql)},
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(run.returncode, 3, run.stderr)
            self.assertTrue(output.is_dir())
            self.assertFalse((output / "database").exists())

    def test_an_output_inside_the_repository_is_refused(self) -> None:
        run = subprocess.run(
            [str(SCRIPT), str(BASE / "codeql-out")],
            env={**os.environ, "CODEQL_BIN": "true"},
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(run.returncode, 64)
        self.assertFalse((BASE / "codeql-out").exists())

    def test_a_relative_path_or_a_link_into_the_repository_is_refused(self) -> None:
        # The plain string comparison let both through (review 2026-10-24).
        with tempfile.TemporaryDirectory() as raw:
            link = Path(raw) / "tree"
            link.symlink_to(BASE)
            for given, cwd in (("codeql-out", BASE), (str(link / "codeql-out"), None)):
                run = subprocess.run(
                    [str(SCRIPT), given],
                    env={**os.environ, "CODEQL_BIN": "true"},
                    cwd=cwd,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(run.returncode, 64, given)
        self.assertFalse((BASE / "codeql-out").exists())

    def test_every_language_in_the_tree_is_analysed(self) -> None:
        """GitHub's code scanning reads the workflows too; so does this (2026-11-14).

        The wrapper analysed Python and JavaScript only, while GitHub's own
        scanning also took the workflows as the language `actions`: its first
        alert on one stopped a release tag, found by nobody before the push.
        Each language the tree holds is created, analysed against its
        security-extended suite, and its results judged.
        """

        held = {"python": any(BASE.glob("src/haprion/*.py"))}
        held["javascript"] = any(BASE.glob("ui/src/haprion_ui/static/*.js"))
        held["actions"] = any(BASE.glob(".github/workflows/*.yml"))
        self.assertTrue(all(held.values()), held)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            calls = root / "calls"
            codeql = root / "codeql"
            codeql.write_text(RECORDER.replace("@CALLS@", str(calls)), encoding="utf-8")
            codeql.chmod(0o755)
            subprocess.run(
                [str(SCRIPT), str(root / "result")],
                env={**os.environ, "CODEQL_BIN": str(codeql)},
                text=True,
                capture_output=True,
                check=False,
            )
            recorded = calls.read_text(encoding="utf-8").splitlines()
        judged = next(
            line
            for line in SCRIPT.read_text(encoding="utf-8").splitlines()
            if "check-codeql-sarif.py" in line and not line.lstrip().startswith("#")
        )

        created = next(line for line in recorded if line.startswith("database create "))
        languages = next(word for word in created.split() if word.startswith("--language="))
        self.assertEqual(set(languages.removeprefix("--language=").split(",")), set(held), created)
        for language in held:
            with self.subTest(language=language):
                suite = f"codeql/{language}-queries:codeql-suites/{language}-security-extended.qls"
                self.assertTrue(
                    any(
                        line.startswith("database analyze ") and suite in line for line in recorded
                    ),
                    recorded,
                )
                # One judgement over every result file: an acceptance that
                # matches nothing fails, so the files are judged together.
                self.assertIn(f'"$output/{language}.sarif"', judged)


# Records every call and makes what the wrapper reads next: a database
# directory per language, and an empty result file per analysis.
RECORDER = """#!/bin/sh
echo "$*" >> "@CALLS@"
if [ "$1" = database ] && [ "$2" = create ]; then
    mkdir -p "$3"
    exit 0
fi
if [ "$1" = database ] && [ "$2" = analyze ]; then
    for argument in "$@"; do
        case "$argument" in
        --output=*) echo '{"runs": [{"results": []}]}' > "${argument#--output=}" ;;
        esac
    done
    exit 0
fi
exit 3
"""


if __name__ == "__main__":
    unittest.main()
