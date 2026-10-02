"""The OWASP Core Rule Set the manager publishes with a release (Fas 21 del B, B229).

Installed by its own package (`haproxy-manager-crs`) on the manager only. A
publish that has an object using the WAF engine copies it into the release's
`waf/crs/`, so the nodes run the rule set the manager validated, and which
rule set a cluster runs is in its release history like everything else.
"""

from __future__ import annotations

import re
import stat
from dataclasses import dataclass
from pathlib import Path

ROOT = Path("/usr/share/haproxy-manager/crs")
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
