"""A node's `/etc/haproxy` as `install/04-node-prepare` leaves it, and a systemctl that remembers.

Two things the node scripts' tests used to build by hand, each its own way, and
both unlike a node (code review 2026-10-22, 1A-1, 1A-2 and 8-1):

* the configuration tree. On a node `haproxy.cfg`, `conf.d`, `maps`, `waf` and
  `dns` are links through `current` into a release, and `crt-lists` exists
  only inside the release. A test that made them plain directories passed a
  `find` that never looked behind a link, while the node it was written for
  searched nothing but `haproxy.cfg`
* systemd. A stub that answers every `is-active` the same way cannot show that
  `systemctl start` does nothing to a unit that already runs - which is how a
  rejoining node kept serving the release it had before

`NodeTree` builds the first, `SYSTEMCTL_STUB` is the second: it keeps one file
per unit under `$UNITS` and answers from it, records every call in `$RECORD`
as `systemctl <arguments>`, and fails what real systemd would fail - a reload of
a unit that is not running.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

#
# The links 04-node-prepare makes (`link_into_current`), in its order.
#
LINKED = ("haproxy.cfg", "conf.d", "maps", "waf", "dns")

#
# `FAIL_START` makes a start of haproxy fail and `FAIL_RELOAD` a reload of it,
# each when the file it names exists.
#
SYSTEMCTL_STUB = """#!/bin/sh
echo "systemctl $*" >> "$RECORD"
verb="$1"
shift
now=0
units=""
for argument; do
    case "$argument" in
        --now) now=1 ;;
        -*) ;;
        *) units="$units ${argument%.service}" ;;
    esac
done
start() {
    [ "$1" = haproxy ] && [ -e "${FAIL_START:-/nonexistent}" ] && exit 1
    touch "$UNITS/$1.active"
}
for unit in $units; do
    case "$verb" in
        start|restart) start "$unit" ;;
        stop) rm -f "$UNITS/$unit.active" ;;
        reload)
            [ -e "$UNITS/$unit.active" ] || { echo "$unit.service is not active" >&2; exit 1; }
            [ "$unit" = haproxy ] && [ -e "${FAIL_RELOAD:-/nonexistent}" ] && exit 1
            ;;
        enable)
            touch "$UNITS/$unit.enabled"
            [ "$now" = 1 ] && start "$unit"
            ;;
        disable)
            rm -f "$UNITS/$unit.enabled"
            [ "$now" = 1 ] && rm -f "$UNITS/$unit.active"
            ;;
        is-active) [ -e "$UNITS/$unit.active" ] || exit 3 ;;
        is-enabled) [ -e "$UNITS/$unit.enabled" ] || exit 1 ;;
    esac
done
exit 0
"""


@dataclass(frozen=True)
class NodeTree:
    """`/etc/haproxy` under a scratch root, and the unit state beside it."""

    haproxy: Path
    units: Path

    @property
    def releases(self) -> Path:
        return self.haproxy / "releases"

    @property
    def certs(self) -> Path:
        return self.haproxy / "certs"

    @property
    def current(self) -> Path:
        return self.haproxy / "current"

    @classmethod
    def build(cls, root: Path, *, running: tuple[str, ...] = ("haproxy", "keepalived")) -> NodeTree:
        """An empty node: no release yet, the links in place, `running` units active and enabled."""

        tree = cls(haproxy=root / "etc-haproxy", units=root / "units")
        tree.releases.mkdir(parents=True)
        tree.certs.mkdir()
        tree.units.mkdir()
        for name in LINKED:
            tree.haproxy.joinpath(name).symlink_to(Path("current") / name)
        for unit in running:
            tree.set_unit(unit, active=True)
        return tree

    def write_release(self, directory: Path, version: int, commit: str) -> Path:
        """A release as pull-deploy installs one, with what every release has.

        `waf`, `dns` and `crt-lists` are there only when the configuration uses
        them, so their links lead nowhere until then - as on a node. A test
        that needs one makes it.
        """

        for name in ("conf.d", "maps"):
            (directory / name).mkdir(parents=True, exist_ok=True)
        (directory / "haproxy.cfg").write_text(f"# version {version}\n")
        (directory / "RELEASE").write_text(
            f"schema=1\ncluster=alpha\nversion={version}\nhash={commit}\n"
            "timestamp=2026-10-04T09:00:00+00:00\n"
        )
        return directory

    def install(self, name: str, version: int, commit: str) -> Path:
        """A release under `releases/`, made `current`."""

        release = self.write_release(self.releases / name, version, commit)
        self.current.unlink(missing_ok=True)
        self.current.symlink_to(release)
        return release

    def set_unit(self, unit: str, *, active: bool) -> None:
        for state in ("active", "enabled"):
            path = self.units / f"{unit}.{state}"
            if active:
                path.touch()
            else:
                path.unlink(missing_ok=True)

    def is_active(self, unit: str) -> bool:
        return (self.units / f"{unit}.active").exists()
