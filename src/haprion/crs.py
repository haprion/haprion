"""The OWASP Core Rule Set the manager publishes with a release (Fas 21 del B, B229).

Installed by its own package (`haprion-crs`) on the manager only. A
publish that has an object using the WAF engine copies it into the release's
`waf/crs/`, so the nodes run the rule set the manager validated, and which
rule set a cluster runs is in its release history like everything else.
"""

from __future__ import annotations

import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from haprion.digits import is_digits

ROOT = Path("/usr/share/haprion/crs")
#
# What the package holds, and what a release may carry (`release_layout`).
# Bounded so a damaged or substituted tree is refused rather than published.
#
RULE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.(conf|data)$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
MAX_FILES = 128
MAX_BYTES = 3 * 1024 * 1024


class RuleSetError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class RuleSet:
    version: str
    files: dict[str, bytes]
    """Paths relative to `waf/crs/`: `crs-setup.conf`, `VERSION`, `rules/<file>`."""


def installed(root: Path = ROOT) -> RuleSet | None:
    """The installed rule set, or None when the package is not installed."""

    if not root.exists():
        return None
    version = _read(root / "VERSION").decode("ascii", "replace").strip()
    if not VERSION.match(version):
        raise RuleSetError(f"{root}/VERSION does not name a version")
    files = {
        "VERSION": f"{version}\n".encode(),
        #
        # The package keeps upstream's name; the release names it for what it
        # is there. `coraza.yaml` includes it by this name.
        #
        "crs-setup.conf": _read(root / "crs-setup.conf.example"),
    }
    rules = root / "rules"
    names = sorted(path.name for path in rules.iterdir())
    if len(names) > MAX_FILES:
        raise RuleSetError(f"{rules} holds more files than a rule set does")
    for name in names:
        #
        # Upstream ships its exclusion templates beside the rules as
        # `.conf.example`; they are examples for a person, not rules.
        #
        if name.endswith(".example"):
            continue
        if not RULE_FILE.match(name):
            raise RuleSetError(f"{rules}/{name} is not a rule file")
        files[f"rules/{name}"] = _read(rules / name)
    if not any(name.endswith(".conf") for name in names):
        raise RuleSetError(f"{rules} holds no rules")
    if sum(len(content) for content in files.values()) > MAX_BYTES:
        raise RuleSetError(f"{root} is larger than a rule set is")
    return RuleSet(version=version, files=files)


def _read(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuleSetError(f"cannot read {path}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise RuleSetError(f"{path} is not a regular file")
    return path.read_bytes()


#
# What a rule means, for a person reading what it found (Fas 21 steg 4b, B234):
# the rule set's own message and severity, and the file it is in - the file
# number is the kind of attack (942 SQL injection, 930 path traversal ...),
# which the interface names in words. Read from the installed package, the
# same files a publish copies, so the description is of the rules the nodes
# run once published.
#
@dataclass(frozen=True, slots=True)
class Rule:
    id: int
    message: str
    severity: str
    """`critical`, `error`, `warning` or `notice`; empty where the rule names none."""
    file: int
    """The rule file's number, `942` for `REQUEST-942-APPLICATION-ATTACK-SQLI.conf`."""
    paranoia: int
    """The paranoia level the rule belongs to, 1-4; 0 where it is not tagged."""


RULE_FILE_NUMBER = re.compile(r"^rules/(?:REQUEST|RESPONSE)-([0-9]{3})-")
_DIRECTIVE = re.compile(r"^\s*Sec(?:Rule|Action)\b")
_ID = re.compile(r"[\"',\s]id:([0-9]{1,7})[\"',\s]")
_MESSAGE = re.compile(r"\bmsg:'((?:[^'\\]|\\.)*)'")
_SEVERITY = re.compile(r"\bseverity:'(CRITICAL|ERROR|WARNING|NOTICE)'")
_PARANOIA = re.compile(r"\btag:'paranoia-level/([1-4])'")
#
# A message may quote what the request held (`%{MATCHED_VAR}`); the catalog
# describes the rule, not a request, so a macro in parentheses goes and any
# other is shown as an ellipsis.
#
_MACRO_IN_PARENTHESES = re.compile(r"\s*\(%\{[^}]*\}\)")
_MACRO = re.compile(r"%\{[^}]*\}")


def catalog(rule_set: RuleSet) -> dict[int, Rule]:
    """Every rule with an ID in the rule set's `.conf` files."""

    rules: dict[int, Rule] = {}
    for name, content in sorted(rule_set.files.items()):
        number = RULE_FILE_NUMBER.match(name)
        if number is None or not name.endswith(".conf"):
            continue
        #
        # A directive continues over lines ending in a backslash; joined, each
        # is one line. A chained rule's continuation carries no ID and is
        # passed over: its message is the chain's first rule's.
        #
        text = content.decode("utf-8", "replace").replace("\\\n", " ")
        for line in text.splitlines():
            if not _DIRECTIVE.match(line):
                continue
            found = _ID.search(line)
            if found is None:
                continue
            message = _MESSAGE.search(line)
            severity = _SEVERITY.search(line)
            paranoia = _PARANOIA.search(line)
            text_message = message.group(1).replace("\\'", "'") if message else ""
            text_message = _MACRO.sub("…", _MACRO_IN_PARENTHESES.sub("", text_message))
            rule = Rule(
                id=int(found.group(1)),
                message=text_message,
                severity=severity.group(1).lower() if severity else "",
                file=int(number.group(1)),
                paranoia=int(paranoia.group(1)) if paranoia else 0,
            )
            rules.setdefault(rule.id, rule)
    return rules


@dataclass(frozen=True, slots=True)
class Link:
    """One `SecRule` of a rule: the first, or one its `chain` continues with.

    `operator` is the text between the quotes as written, escapes and all;
    `actions` are the comma-separated actions, each as written.
    """

    variables: str
    operator: str
    actions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Definition:
    """A rule as the rule set writes it: its links in order (B273)."""

    id: int
    links: tuple[Link, ...]

    @property
    def phase(self) -> int:
        for action in self.links[0].actions:
            name, _, value = action.partition(":")
            if name == "phase" and is_digits(value.strip()):
                return int(value.strip())
        return 2

    @property
    def paranoia(self) -> int:
        for action in self.links[0].actions:
            found = re.fullmatch(r"tag:'paranoia-level/([1-4])'", action)
            if found:
                return int(found.group(1))
        return 1


def _quoted(text: str, start: int) -> tuple[str, int]:
    """The double-quoted string at `start`, without its quotes, and the index after it."""

    if start >= len(text) or text[start] != '"':
        raise RuleSetError("a directive's argument is not quoted")
    index = start + 1
    while index < len(text):
        if text[index] == "\\" and index + 1 < len(text):
            index += 2
            continue
        if text[index] == '"':
            return text[start + 1 : index], index + 1
        index += 1
    raise RuleSetError("a directive's argument does not end")


def _actions(text: str) -> tuple[str, ...]:
    """Actions split on the commas outside single quotes, each stripped."""

    parts: list[str] = []
    current: list[str] = []
    quoted = False
    index = 0
    while index < len(text):
        character = text[index]
        if character == "\\" and index + 1 < len(text):
            current.append(text[index : index + 2])
            index += 2
            continue
        if character == "'":
            quoted = not quoted
        if character == "," and not quoted:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(character)
        index += 1
    parts.append("".join(current).strip())
    return tuple(part for part in parts if part)


def _link(line: str) -> Link:
    """One joined `SecRule` line as its three arguments."""

    rest = line.strip()[len("SecRule") :].lstrip()
    if rest.startswith('"'):
        variables, after = _quoted(rest, 0)
    else:
        end = rest.find(" ")
        if end < 0:
            raise RuleSetError("a rule has no operator")
        variables, after = rest[:end], end
    rest = rest[after:].lstrip()
    operator, after = _quoted(rest, 0)
    rest = rest[after:].lstrip()
    actions, _ = _quoted(rest, 0) if rest else ("", 0)
    return Link(variables=variables, operator=operator, actions=_actions(actions))


def definitions(rule_set: RuleSet) -> dict[int, Definition]:
    """Every rule with an ID in the rule set's request `.conf` files, with its chain.

    What a WAF exception's counter copies (B273). Lines ending in a backslash
    continue the directive; a rule whose actions say `chain` continues with
    the next `SecRule`.
    """

    found: dict[int, Definition] = {}
    for name, content in sorted(rule_set.files.items()):
        if not name.startswith("rules/REQUEST-") or not name.endswith(".conf"):
            continue
        text = content.decode("utf-8", "replace").replace("\\\n", " ")
        links: list[Link] = []
        for line in text.splitlines():
            if not line.lstrip().startswith("SecRule "):
                continue
            link = _link(line)
            links.append(link)
            if "chain" in link.actions:
                continue
            first = next((a for a in links[0].actions if a.startswith("id:")), "").removeprefix(
                "id:"
            )
            if is_digits(first):
                found.setdefault(int(first), Definition(id=int(first), links=tuple(links)))
            links = []
    return found


_catalogs: dict[tuple[Path, str], dict[int, Rule]] = {}


def installed_catalog(root: Path = ROOT) -> dict[int, Rule]:
    """The installed rule set's catalog, read once per installed version; empty without one.

    For the interface, which asks on every page: the version file is read each
    time, the rules only when it changes - a package upgrade is a new version.
    A rule set that cannot be read gives an empty catalog, and the page shows
    the rule's ID without its meaning rather than no page.
    """

    try:
        version = _read(root / "VERSION").decode("ascii", "replace").strip()
    except RuleSetError:
        return {}
    known = _catalogs.get((root, version))
    if known is not None:
        return known
    try:
        rule_set = installed(root)
    except RuleSetError:
        return {}
    rules = catalog(rule_set) if rule_set is not None else {}
    _catalogs[(root, version)] = rules
    return rules


ENGINE_PACKAGE = "haprion-coraza-spoa"
DPKG_QUERY = "/usr/bin/dpkg-query"


def manager_versions(root: Path = ROOT, dpkg_query: str = DPKG_QUERY) -> dict[str, str | None]:
    """The engine and the rule set on the manager, for the interface (B231).

    The engine is the package's version, as each node reports its own in its
    status, so the two read alike; the rule set is the version the package
    installed. None for what is not installed: publishing an object with WAF
    needs both here, as it needs the engine on every node.
    """

    engine = None
    try:
        answer = subprocess.run(  # noqa: S603 - fixed program and arguments
            [dpkg_query, "-W", "-f=${Status}\t${Version}", ENGINE_PACKAGE],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        status, _, version = answer.stdout.partition("\t")
        if answer.returncode == 0 and status.strip() == "install ok installed":
            engine = version.strip()[:64] or None
    except (OSError, subprocess.SubprocessError):
        engine = None
    rules = None
    try:
        found = _read(root / "VERSION").decode("ascii", "replace").strip()
        rules = found if VERSION.match(found) else None
    except RuleSetError:
        rules = None
    return {"engine": engine, "crs": rules}
