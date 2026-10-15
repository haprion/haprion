"""The commands a package's scripts run, read from the scripts themselves.

A package states what it needs in `Depends`. Nothing checked that the list
matched what the scripts run, and a new node stopped on its first deploy on
`rsync: command not found` (Fas 18, finding 37) while every test passed: the
machines the tests ran on had rsync for other reasons. So the scripts are
read here and every command they run is named, and the gate holds each one
against the package that carries the script.

Shell is read the way a person reads it for this purpose, not parsed: the
first word of each simple command, after the separators, keywords, wrappers
(`sudo -n`, `exec`, `timeout`) and assignments in front of it, with quoted
text, here-documents, comments, tests and arithmetic left out - except
command substitutions, which run commands wherever they stand. A word is a
command only if it is not a function the script or its library defines, a
shell builtin or a keyword. Python scripts name their commands by absolute
path, and those paths are what is read.

What this cannot see is a command named through a variable (`"$IP" addr`).
The install test (`tools/install-test`) covers that from the other side: it
runs the scripts on a machine that has only what the packages bring.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from pathlib import Path

KEYWORDS = frozenset(
    [
        "if",
        "then",
        "else",
        "elif",
        "fi",
        "case",
        "esac",
        "for",
        "select",
        "while",
        "until",
        "do",
        "done",
        "in",
        "function",
        "time",
        "coproc",
        "{",
        "}",
        "!",
        "[[",
        "]]",
    ]
)
BUILTINS = frozenset(
    [
        "alias",
        "bg",
        "bind",
        "break",
        "builtin",
        "caller",
        "cd",
        "command",
        "compgen",
        "complete",
        "compopt",
        "continue",
        "declare",
        "dirs",
        "disown",
        "echo",
        "enable",
        "eval",
        "exec",
        "exit",
        "export",
        "false",
        "fc",
        "fg",
        "getopts",
        "hash",
        "help",
        "history",
        "jobs",
        "kill",
        "let",
        "local",
        "logout",
        "mapfile",
        "popd",
        "printf",
        "pushd",
        "pwd",
        "read",
        "readarray",
        "readonly",
        "return",
        "set",
        "shift",
        "shopt",
        "source",
        "suspend",
        "test",
        "times",
        "trap",
        "true",
        "type",
        "typeset",
        "ulimit",
        "umask",
        "unalias",
        "unset",
        "wait",
        ".",
        ":",
        "[",
    ]
)
#
# Words that run the command after them. The options they take before it are
# skipped; anything more unusual is left to the install test.
#
WRAPPERS = {
    "sudo": re.compile(r"^-[A-Za-z]+$|^-[ugC]$"),
    "exec": re.compile(r"^-[a-z]+$"),
    "nice": re.compile(r"^-n$|^-\d+$"),
    "timeout": re.compile(r"^-|^\d+[smhd]?$"),
    "env": re.compile(r"^-|^[A-Za-z_][A-Za-z0-9_]*="),
    "xargs": re.compile(r"^-"),
}
WRAPPER_ARGUMENT = {"sudo": {"-u", "-g", "-C"}, "nice": {"-n"}}
SEPARATORS = re.compile(r"\|\||&&|;;|[;|&\n]|\$\(|`|\(|\{|\}")
#
# A `case` label at the start of a line: `cert-pull)`, `*|"")`.
#
CASE_LABEL = re.compile(r"^[ \t]*[^\s()=]+\)", re.M)
COMMAND_NAME = re.compile(r"^[a-z][a-z0-9._+-]*$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=")
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
DEFINITION = re.compile(
    r"^[ \t]*(?:function[ \t]+)?([A-Za-z_][A-Za-z0-9_-]*)[ \t]*\(\)[ \t]*\{?", re.M
)
ABSOLUTE = re.compile(r"^(?:/usr)?/s?bin/([A-Za-z0-9_.+-]+)$")


def _without_heredocs(text: str) -> str:
    """The script with the body of every here-document blanked, lines kept."""

    lines = text.split("\n")
    kept: list[str] = []
    waiting: list[str] = []
    for line in lines:
        if waiting:
            if line.strip() == waiting[0]:
                waiting.pop(0)
            kept.append("")
            continue
        kept.append(line)
        waiting.extend(match.group(2) for match in HEREDOC.finditer(line))
    return "\n".join(kept)


def _blank(text: str) -> str:
    """Comments, quoted text, tests and arithmetic blanked; positions kept.

    A quoted word becomes `@` and spaces, so a command named by a quoted
    variable (`"$HELPER" reload`) is not mistaken for `reload`. Inside double
    quotes a command substitution is read again as a script of its own:
    `"$(awk '{ print $1 }')"` runs awk, and its program is quoted text.
    """

    out: list[str] = []
    stack: list[str] = ["script"]  # script, double, substitution
    depth: list[int] = []  # open parentheses inside each substitution
    index = 0
    length = len(text)
    newlines_owed = 0
    while index < length:
        char = text[index]
        context = stack[-1]
        if char == "\n" and newlines_owed and context != "double":
            out.append("\n" * newlines_owed)
            newlines_owed = 0
        if context == "double":
            if char == "\\" and index + 1 < length:
                out.append(" " + ("\n" if text[index + 1] == "\n" else " "))
                index += 2
            elif char == '"':
                stack.pop()
                out.append(" ")
                index += 1
            elif text.startswith("$(", index) and not text.startswith("$((", index):
                stack.append("substitution")
                depth.append(0)
                out.append("$(")
                index += 2
            else:
                out.append("\n" if char == "\n" else " ")
                index += 1
            continue
        # A script, or a substitution read as one.
        if context == "substitution":
            if char == "(":
                depth[-1] += 1
            elif char == ")":
                if depth[-1] == 0:
                    stack.pop()
                    depth.pop()
                    out.append(")")
                    index += 1
                    continue
                depth[-1] -= 1
        if char == "\\" and index + 1 < length:
            # A continued line is one command: the newline is not a separator.
            out.append("  ")
            newlines_owed += text[index + 1] == "\n"
            index += 2
            continue
        if char == "#" and (index == 0 or text[index - 1] in " \t\n;(|&"):
            end = text.find("\n", index)
            end = length if end == -1 else end
            out.append(" " * (end - index))
            index = end
            continue
        if char == "'":
            end = text.find("'", index + 1)
            end = length - 1 if end == -1 else end
            span = text[index : end + 1]
            out.append("@" + re.sub(r"[^\n]", " ", span[1:]))
            index = end + 1
            continue
        if char == '"':
            stack.append("double")
            out.append("@")
            index += 1
            continue
        for opening, closing in (("$((", "))"), ("((", "))"), ("[[", "]]")):
            if text.startswith(opening, index):
                end = text.find(closing, index + len(opening))
                if end != -1:
                    span = text[index : end + len(closing)]
                    out.append(re.sub(r"[^\n]", " ", span))
                    index = end + len(closing)
                    break
        else:
            out.append(char)
            index += 1
    return "".join(out)


def _arrays_blanked(text: str) -> str:
    """`name=( ... )`: the members are words, not commands."""

    return re.sub(
        r"[A-Za-z_][A-Za-z0-9_]*\+?=\(([^)]*)\)",
        lambda match: re.sub(r"[^\n]", " ", match.group(0)),
        text,
    )


def _first_word(segment: str) -> str | None:
    raw = segment.split()
    position = 0
    while position < len(raw):
        word = raw[position]
        if word in {"for", "case", "select", "in"}:
            return None
        if ASSIGNMENT.match(word) or word in KEYWORDS:
            position += 1
            continue
        if word in WRAPPERS and position + 1 < len(raw):
            options = WRAPPERS[word]
            position += 1
            while position < len(raw) and options.match(raw[position]):
                takes = raw[position] in WRAPPER_ARGUMENT.get(word, set())
                position += 2 if takes else 1
            continue
        if word == "command" and position + 1 < len(raw):
            # `command -v x` asks; `command x` runs.
            if raw[position + 1].startswith("-"):
                return None
            position += 1
            continue
        break
    if position >= len(raw):
        return None
    word = raw[position].strip("()")
    absolute = ABSOLUTE.match(word)
    if absolute:
        return absolute.group(1)
    return word if COMMAND_NAME.match(word) else None


def shell_commands(text: str, defined: Iterable[str] = ()) -> set[str]:
    """Every command a shell script runs by name."""

    functions = set(DEFINITION.findall(text)) | set(defined)
    body = _arrays_blanked(_blank(_without_heredocs(text)))
    body = DEFINITION.sub(lambda match: " " * len(match.group(0)), body)
    body = CASE_LABEL.sub(lambda match: " " * len(match.group(0)), body)
    found: set[str] = set()
    for segment in SEPARATORS.split(body):
        # What follows a closing parenthesis is still the command before it.
        word = _first_word(segment.split(")", 1)[0])
        if word is None or word in BUILTINS or word in KEYWORDS or word in functions:
            continue
        found.add(word)
    return found


def shell_functions(text: str) -> set[str]:
    return set(DEFINITION.findall(text))


def python_commands(text: str) -> set[str]:
    """The commands a Python script names by absolute path."""

    found: set[str] = set()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            match = ABSOLUTE.match(node.value)
            if match:
                found.add(match.group(1))
    return found


def script_commands(path: Path, defined: Iterable[str] = ()) -> set[str]:
    text = path.read_text()
    first = text.split("\n", 1)[0]
    if "python" in first:
        return python_commands(text)
    return shell_commands(text, defined)
