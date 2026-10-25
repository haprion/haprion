"""One grammar for the platform's KEY=value files, in Python and in the shell (review 2026-10-22, 6-10).

`ui-admin.conf` and `ui-tls.conf` were sourced by bash, cut after `=` by
`admin_value`, unquoted by the admin tool and matched strictly by the interface's
certificate code. Every reader now is `haprion.admin_file` or the shell's
`read_admin_file`; these hold the shell's copies to one text and both readers to
the same answer for the same file.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from haprion import admin_file

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "install" / "lib.sh"
COMMANDS = tuple(
    ROOT / "install" / "platform" / "bin" / name
    for name in (
        "haprion-backup",
        "haprion-drain",
        "haprion-retention",
        "haprion-rollback",
        "haprion-tls",
    )
)
FUNCTION = re.compile(r"^read_admin_file\(\) \{\n.*?^\}\n", re.M | re.S)

#
# What a writer writes, and what it must not: a quote, a space in a value, a
# shell's own characters, a line `splitlines` would break and bash would not.
#
FILES = {
    "plain": "# comment\nDB_NAME=haprion\nDB_ROLE=haprion_migrate\n\nUI_CONFIG=/etc/haprion/ui.toml\n",
    "indented": "  DB_NAME=haprion\t\n\tDB_ROLE=role\r\n",
    "last wins": "DB_NAME=first\nDB_NAME=second\nDB_ROLE=r\n",
    "no final newline": "DB_NAME=haprion\nDB_ROLE=r",
    "quoted": 'DB_NAME="haprion"\nDB_ROLE=r\n',
    "space": "DB_NAME=two words\nDB_ROLE=r\n",
    "expansion": "DB_NAME=$(id)\nDB_ROLE=r\n",
    "glob": "DB_NAME=*\nDB_ROLE=r\n",
    "lower key": "db_name=haprion\nDB_ROLE=r\n",
    "vertical tab": "DB_NAME=a\x0bDB_ROLE=r\n",
    "no value": "DB_NAME=\nDB_ROLE=r\n",
}


def _shell(script: Path, path: Path) -> tuple[int, dict[str, str]]:
    text = script.read_text()
    found = FUNCTION.search(text)
    assert found is not None, script
    done = subprocess.run(  # fixed interpreter, the function as the script holds it
        [
            "/bin/bash",
            "-c",
            found.group(0) + 'read_admin_file "$1" DB_NAME DB_ROLE UI_CONFIG || exit\n'
            'printf "DB_NAME=%s\\nDB_ROLE=%s\\nUI_CONFIG=%s\\n" "${DB_NAME-}" "${DB_ROLE-}" "${UI_CONFIG-}"',
            "read",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    values = dict(line.split("=", 1) for line in done.stdout.splitlines() if "=" in line)
    return done.returncode, {key: value for key, value in values.items() if value}


def _python(path: Path) -> tuple[int, dict[str, str]]:
    try:
        values = admin_file.read(path)
    except admin_file.AdminFileError:
        return 78, {}
    return 0, {
        key: value for key, value in values.items() if key in {"DB_NAME", "DB_ROLE", "UI_CONFIG"}
    }


class EveryReaderReadsTheSameFileTheSameWay(unittest.TestCase):
    def test_the_shell_s_copies_are_one_text(self) -> None:
        copies = {script.name: FUNCTION.search(script.read_text()) for script in (LIB, *COMMANDS)}
        self.assertTrue(all(copies.values()), [name for name, found in copies.items() if not found])
        self.assertEqual(len({found.group(0) for found in copies.values() if found}), 1)

    def test_python_and_the_shell_agree_on_every_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            for name, text in FILES.items():
                path = Path(raw) / "file.conf"
                path.write_bytes(text.encode())
                with self.subTest(file=name):
                    self.assertEqual(_shell(LIB, path), _python(path))

    def test_what_a_writer_writes_is_read_and_anything_else_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "file.conf"
            path.write_text(FILES["plain"])
            self.assertEqual(
                _python(path),
                (
                    0,
                    {
                        "DB_NAME": "haprion",
                        "DB_ROLE": "haprion_migrate",
                        "UI_CONFIG": "/etc/haprion/ui.toml",
                    },
                ),
            )
            for name in (
                "quoted",
                "space",
                "expansion",
                "glob",
                "lower key",
                "vertical tab",
                "no value",
            ):
                path.write_bytes(FILES[name].encode())
                with self.subTest(file=name):
                    self.assertEqual(_python(path)[0], 78)

    def test_no_command_sources_the_file(self) -> None:
        for script in COMMANDS:
            with self.subTest(script=script.name):
                self.assertIsNone(
                    re.search(
                        r'^\s*(source|\.) "\$(config|CONF|admin_config)"', script.read_text(), re.M
                    )
                )

    def test_the_steps_write_what_the_grammar_reads(self) -> None:
        written = {
            "02-platform-database": ("DB_NAME", "DB_ROLE", "DUMP_DIR", "UI_CONFIG"),
            "05-platform-nginx": ("TLS_CERT", "TLS_KEY", "SERVER_NAME", "HSTS"),
        }
        for step, keys in written.items():
            text = (ROOT / "install" / "platform" / step).read_text()
            for key in keys:
                with self.subTest(step=step, key=key):
                    self.assertIn(f"\n{key}=${{", text)


if __name__ == "__main__":
    unittest.main()
