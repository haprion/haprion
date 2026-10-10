"""Which nodes run an older HAProxy than they should (Fas 16 punkt 3b).

Two rules, both from the manual's *Keeping HAProxy current*: a cluster's nodes
run one version, and the management host - whose `haproxy -c` validates every
candidate - is upgraded last, so it is never newer than a node. A validator
newer than a node can accept a directive that node then refuses.

The versions compared are what each node's running process reports on its
runtime socket and what `haproxy -v` names on this host, compared by their
upstream part (`3.4.6` of `3.4.6-1ppa1~resolute`). One implementation, read
by `haprion-status` and the dashboard alike.

And the packages beside it (26-10-09): HAProxy's own package, keepalived,
dnsdist, the WAF engine and the OpenSSL library, as each node reports them. A
node patched a day before its partner - on purpose, to try a release before
the second node gets it - is told apart from the other until both match. They
are compared as dpkg orders versions, the whole version and not its upstream
part: a security update often changes only the revision (`3.0.13-0ubuntu3.4`
to `3.0.13-0ubuntu3.5`), and a PPA rebuild only its suffix.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

UPSTREAM = re.compile(r"\d+(?:\.\d+)*")

__all__ = ["PACKAGES", "compare", "notes", "package_notes", "packages_behind", "upstream"]

#
# The node status's `packages` keys, and how a note names each.
#
PACKAGES = {
    "haproxy": "HAProxy package",
    "keepalived": "keepalived",
    "dnsdist": "dnsdist",
    "waf_engine": "WAF engine",
    "openssl": "OpenSSL",
}


def upstream(version: object) -> str | None:
    """The upstream release a package version names, or None."""

    if not isinstance(version, str):
        return None
    found = UPSTREAM.match(version.strip())
    return found.group(0) if found else None


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


NON_DIGITS = re.compile(r"\D*")
DIGITS = re.compile(r"\d*")


def _lead(pattern: re.Pattern[str], text: str) -> str:
    found = pattern.match(text)
    return found.group(0) if found else ""


def _order(character: str) -> int:
    """dpkg's weight of one non-digit character: `~` before the end, letters before the rest."""

    if character == "~":
        return -1
    if character.isalpha():
        return ord(character)
    return ord(character) + 256


def _compare_part(left: str, right: str) -> int:
    """dpkg's comparison of an upstream version or a revision."""

    while left or right:
        letters_left, letters_right = _lead(NON_DIGITS, left), _lead(NON_DIGITS, right)
        for index in range(max(len(letters_left), len(letters_right))):
            a = _order(letters_left[index]) if index < len(letters_left) else 0
            b = _order(letters_right[index]) if index < len(letters_right) else 0
            if a != b:
                return -1 if a < b else 1
        left, right = left[len(letters_left) :], right[len(letters_right) :]
        digits_left, digits_right = _lead(DIGITS, left), _lead(DIGITS, right)
        a, b = int(digits_left or 0), int(digits_right or 0)
        if a != b:
            return -1 if a < b else 1
        left, right = left[len(digits_left) :], right[len(digits_right) :]
    return 0


def compare(left: str, right: str) -> int:
    """-1, 0 or 1 as `dpkg --compare-versions` orders two package versions."""

    def split(version: str) -> tuple[int, str, str]:
        epoch, _, rest = version.rpartition(":") if ":" in version else ("0", "", version)
        upstream_part, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
        return (int(epoch) if epoch.isdigit() else 0), upstream_part, revision

    epoch_left, upstream_left, revision_left = split(left)
    epoch_right, upstream_right, revision_right = split(right)
    if epoch_left != epoch_right:
        return -1 if epoch_left < epoch_right else 1
    return _compare_part(upstream_left, upstream_right) or _compare_part(
        revision_left, revision_right
    )


def packages_behind(packages: Mapping[str, object]) -> dict[str, list[tuple[str, str]]]:
    """Per node, each package it runs an older version of than another node, with the newest.

    `packages` is each node's `packages` from its status. A package a node does
    not have is not judged - it reports nothing to compare - and neither is a
    node that reported no packages at all, an older node bundle.
    """

    behind: dict[str, list[tuple[str, str]]] = {}
    for key, label in PACKAGES.items():
        versions = {
            node: version
            for node, found in packages.items()
            if isinstance(found, Mapping) and isinstance(version := found.get(key), str) and version
        }
        if len(set(versions.values())) < 2:
            continue
        newest = max(versions.values(), key=_Version)
        for node, version in versions.items():
            if compare(version, newest) < 0:
                behind.setdefault(node, []).append((label, newest))
    return behind


def package_notes(packages: Mapping[str, object]) -> dict[str, list[str]]:
    """Per node, a sentence for each package it runs an older version of than another node."""

    return {
        node: [f"{label} behind {newest}" for label, newest in found]
        for node, found in packages_behind(packages).items()
    }


class _Version:
    """A package version that sorts as dpkg sorts them."""

    def __init__(self, version: str) -> None:
        self.version = version

    def __lt__(self, other: _Version) -> bool:
        return compare(self.version, other.version) < 0


def notes(
    running: Mapping[str, object],
    validator: object = None,
    packages: Mapping[str, object] | None = None,
    *,
    short: bool = False,
) -> dict[str, str]:
    """A sentence per node that is behind, keyed by node name; nodes that are fine are absent.

    `running` is each node's runtime version, as the status reports it. A node
    whose version is unknown is not judged: an unreachable node is already
    reported for what it is.
    """

    known = {name: found for name, value in running.items() if (found := upstream(value))}
    newest = max(known.values(), key=_key) if known else ""
    checked = upstream(validator)
    said: dict[str, str] = {}
    for name, version in known.items():
        if _key(version) < _key(newest):
            said[name] = f"Behind {newest}"
        elif checked is not None and _key(checked) > _key(version):
            said[name] = f"Manager validates with {checked}"
    #
    # The packages after, one line per node. A HAProxy process already said to
    # be behind says what its package would: the package's note is left out.
    #
    #
    # `short` names the packages only, for a table cell; the versions are then
    # the cell's title (`notes` again without it).
    #
    for name, older in packages_behind(packages or {}).items():
        if name in said:
            older = [entry for entry in older if entry[0] != PACKAGES["haproxy"]]
        if not older:
            continue
        lines = (
            [f"Behind: {', '.join(label for label, _newest in older)}"]
            if short
            else [f"{label} behind {newest}" for label, newest in older]
        )
        said[name] = " · ".join([said[name], *lines] if name in said else lines)
    return said
