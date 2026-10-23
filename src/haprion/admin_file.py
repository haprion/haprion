"""The root-owned `KEY=value` files the platform steps write, read one way (review 2026-10-22, 6-10).

`/etc/haprion/ui-admin.conf` (02-platform-database) and `/etc/haprion/ui-tls.conf`
(05-platform-nginx) are read by root shell commands and by Python. They were
read four ways: sourced by bash, cut after the `=` by `admin_value`, stripped of
quotes by the admin tool and matched strictly by the interface's certificate
code - so one file could mean different things to two readers of it. This is
the grammar, and the shell's `read_admin_file` (in `install/lib.sh` and each
command under `install/platform/bin/` that reads one) is the same pattern, held
to it by a test: comment and blank lines, and assignments whose value is a
plain word - a name, a path - with no quote, space or character a shell gives a
meaning to. Anything else is refused, not interpreted. The last assignment of a
key wins, as it did when the file was sourced.
"""

from __future__ import annotations

import re
from pathlib import Path

ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)=([A-Za-z0-9_./:@+,=-]+)$")
SPACE = " \t\r\v\f"


class AdminFileError(ValueError):
    """A line that is not a comment, blank, or a plain assignment."""


def parse(text: str, *, source: str) -> dict[str, str]:
    values: dict[str, str] = {}
    #
    # Lines and their edges as bash's `read` and `[:space:]` see them, not as
    # `splitlines` and `strip` do: those also break at a vertical tab and trim
    # Unicode spaces, and the two readers would then disagree about a line.
    #
    for number, line in enumerate(text.split("\n"), start=1):
        stripped = line.strip(SPACE)
        if not stripped or stripped.startswith("#"):
            continue
        match = ASSIGNMENT.fullmatch(stripped)
        if match is None:
            raise AdminFileError(f"{source}:{number}: not a plain assignment")
        values[match.group(1)] = match.group(2)
    return values


def read(path: Path) -> dict[str, str]:
    """The file's assignments; OSError when it cannot be read, AdminFileError when it is not this grammar."""

    return parse(path.read_text(encoding="utf-8"), source=str(path))
