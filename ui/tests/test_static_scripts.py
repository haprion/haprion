"""What the interface's own scripts must not do, read from their text.

A form's named controls shadow its properties: in a form with a button named
`action`, `form.action` is that button (or a RadioNodeList of them), not the
address the form posts to. `advanced.js` and `object-form.js` had learnt that
and read the attribute; `blocklist-form.js` did not, and *Test* on a blocklist
posted to `/settings/blocklists/[object RadioNodeList]` in 1.1.0 and said the
test got no answer (26-11-14). No browser test pressed it. So no script reads
`.action` at all: `getAttribute("action")` holds whatever the form's controls
are named.
"""

from __future__ import annotations

import re
import unittest

from haprion_ui.templates import STATIC_DIRECTORY

PROPERTY = re.compile(r"\.action\b(?!\s*\()")


def code(line: str) -> str:
    """The line without a `//` comment at its end, the way these scripts write them."""

    return line.split("//", 1)[0]


class NoScriptReadsAFormsActionProperty(unittest.TestCase):
    def test_the_attribute_is_read_instead(self) -> None:
        scripts = sorted(STATIC_DIRECTORY.glob("*.js"))
        self.assertTrue(scripts, STATIC_DIRECTORY)
        found = [
            f"{script.name}:{number}: {line.strip()}"
            for script in scripts
            for number, line in enumerate(script.read_text().splitlines(), start=1)
            if PROPERTY.search(code(line))
        ]
        self.assertEqual(
            found, [], 'read getAttribute("action"): a control named `action` shadows it'
        )


if __name__ == "__main__":
    unittest.main()
