"""A pipeline must not end in a reader that stops early, in a script with pipefail.

`writer | grep -q x` exits at the first match; a writer that still has output
gets SIGPIPE (exit 141), and under `set -o pipefail` the whole pipeline then
fails although grep found its line. Whether it does depends on timing, so it
shows under load only: node-prepare once read "the node does not have this
address" from a pipeline like that. The readers that read to the end do the same
job: `grep ... >/dev/null`, `awk 'NR == 1'`.
"""

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SHELL_DIRS = ("install", "examples", "tools", "ui/tools")
SHEBANG = re.compile(r"^#! ?(/usr)?/bin/(env )?(ba)?sh( |$)")


def shell_scripts() -> list[Path]:
    found = []
    for directory in SHELL_DIRS:
        for path in sorted((ROOT / directory).rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            try:
                first = path.read_text().split("\n", 1)[0]
            except UnicodeDecodeError:
                continue
            if path.suffix == ".sh" or SHEBANG.match(first):
                found.append(path)
    return found


def has_pipefail(path: Path) -> bool:
    # A library (*.sh under install/) is sourced by scripts that set it.
    text = path.read_text()
    return bool(re.search(r"pipefail", text)) or (path.suffix == ".sh" and "install" in path.parts)


def statements(text: str) -> list[tuple[int, str]]:
    """Logical lines: continuations joined, comments dropped."""
    out: list[tuple[int, str]] = []
    current, start = "", 0
    for number, line in enumerate(text.split("\n"), 1):
        if not current:
            start = number
        stripped = line.strip()
        if not current and stripped.startswith("#"):
            continue
        current += " " + stripped.removesuffix("\\")
        if line.rstrip().endswith("\\") or stripped.endswith("|"):
            continue
        out.append((start, current.strip()))
        current = ""
    return out


def segments(statement: str) -> list[str]:
    """Split on a pipe outside quotes; `||` is not a pipe."""
    parts, buffer, quote, index = [], "", "", 0
    while index < len(statement):
        char = statement[index]
        if quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "|":
            if statement[index + 1 : index + 2] == "|":
                buffer += "||"
                index += 2
                continue
            parts.append(buffer)
            buffer = ""
            index += 1
            continue
        buffer += char
        index += 1
    parts.append(buffer)
    return [part.strip() for part in parts]


def stops_early(segment: str) -> bool:
    words = segment.lstrip("{( ").split()
    if not words:
        return False
    if words[0] == "head":
        return True
    if words[0] in ("grep", "egrep", "fgrep"):
        for word in words[1:]:
            if word == "--quiet" or word == "--max-count" or word.startswith("--max-count="):
                return True
            if re.fullmatch(r"-[A-Za-z]*[qm][A-Za-z0-9]*", word):
                return True
        return False
    if words[0] == "awk":
        return bool(re.search(r"\bexit\b", segment))
    if words[0] == "sed":
        return bool(re.search(r"(^|[;{\s'])q\d*\s*[;}']|\bq'", segment)) and "-n" in words
    return False


def command_substitutions(statement: str) -> list[str]:
    """The statement itself, then the inside of each `$( )` in it, nested too."""
    found = [statement]
    index = statement.find("$(")
    while index != -1:
        depth, end = 1, index + 2
        while end < len(statement) and depth:
            depth += {"(": 1, ")": -1}.get(statement[end], 0)
            end += 1
        inner = statement[index + 2 : end - 1]
        found.extend(command_substitutions(inner))
        index = statement.find("$(", end)
    return found


def offences(path: Path) -> list[str]:
    return offences_in(path.read_text(), str(path.relative_to(ROOT)))


def workflow_scripts() -> list[tuple[str, str]]:
    """Each workflow step's script that runs under pipefail: `shell: bash` is
    `bash -eo pipefail` on GitHub (26-11-07: `apt-cache madison | awk '... exit'`
    failed a gate with apt's 100, and no scan read the workflows)."""

    found = []
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        for name, job in yaml.safe_load(path.read_text())["jobs"].items():
            for step in job.get("steps", []):
                script = step.get("run")
                if script and (step.get("shell") == "bash" or "pipefail" in script):
                    found.append((f"{path.name} {name} '{step.get('name', '')}'", script))
    return found


def offences_in(text: str, label: str) -> list[str]:
    found = []
    expanded = [
        (number, inner)
        for number, whole in statements(text)
        for inner in command_substitutions(whole)
    ]
    for number, statement in expanded:
        if "||" in statement and re.search(r"\|\|\s*(true|:)\b", statement):
            continue
        parts = segments(statement)
        for part in parts[1:]:
            if stops_early(part):
                found.append(f"{label}:{number}: {part[:70]}")
                break
    return found


class NoPipelineEndsInAnEarlyReader(unittest.TestCase):
    def test_scripts_are_found(self) -> None:
        self.assertGreater(len(shell_scripts()), 30)

    def test_no_pipeline_under_pipefail_ends_in_an_early_reader(self) -> None:
        found = [line for path in shell_scripts() if has_pipefail(path) for line in offences(path)]
        self.assertEqual([], found, "read to the end: grep ... >/dev/null, awk 'NR == 1'")

    def test_no_workflow_step_ends_a_pipeline_in_an_early_reader(self) -> None:
        scripts = workflow_scripts()
        self.assertGreater(len(scripts), 10)
        found = [line for label, script in scripts for line in offences_in(script, label)]
        self.assertEqual([], found, "read to the end: grep ... >/dev/null, awk 'NR == 1'")

    def test_the_scan_sees_the_pattern(self) -> None:
        self.assertTrue(stops_early("grep -qF x"))
        self.assertTrue(stops_early("head -n 1"))
        self.assertTrue(stops_early("grep -m1 x"))
        self.assertTrue(stops_early("awk '{ print; exit }'"))
        self.assertFalse(stops_early("grep -c ."))
        self.assertFalse(stops_early("grep x >/dev/null"))
        self.assertEqual(["a", "grep -E '^(a|b)'"], segments("a | grep -E '^(a|b)'"))


if __name__ == "__main__":
    unittest.main()
