"""The answers file a node restore gives 04-node-prepare, derived from the archive.

A restored node is prepared by the release's own node package (B178, B180): its
``04-node-prepare`` creates what the product owns on a node; dpkg has put the
node scripts of the running release in place. That step reads an answers file. The
operator's own is on another machine and may have moved on; the node's truth is
the ``node.conf`` the archive carries, which ``04-node-prepare`` rendered from
the answers it was given. This module reads those answers back out.

The mapping is the template in ``install/lib.sh`` (``render_node_conf``) read
backwards, and a test renders the derived file through that template and
expects the archived bytes - so the two cannot drift apart unnoticed.

The file is sourced by bash as root on the target. Every value is therefore
held to a pattern that cannot quote, expand or glob, and a value outside it
stops the restore rather than being escaped.
"""

from __future__ import annotations

import re
from pathlib import Path

from haprion import accounts
from haprion.config import CLUSTER_ID
from haprion.restore_source import RestoreSource, content

NODE_CONF = "/etc/haprion/node.conf"
#
# The account names are fixed (B266), so the archive's must be these. One from
# before the rename names others, and is refused rather than restored into a
# layout it was not made for.
#
SERVICE_ACCOUNTS = [accounts.TRIGGER, accounts.STATUS, accounts.BACKUP, accounts.LOGREAD]
LINE = re.compile(r'^(?P<key>[A-Z_]+)="(?P<value>[^"]*)"$')
SAFE = re.compile(r"^[A-Za-z0-9._@+/ -]*$")
NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
NODE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REQUIRED = (
    "CLUSTER",
    "MANAGER",
    "CONFIG_PULL_USER",
    "CONFIG_PULL_KEY",
    "CONFIG_REMOTE_PATH",
    "BACKUP_SERVICE_ACCOUNTS",
    "BACKUP_ACCOUNTS",
    "BACKUP_GROUPS",
)


class AnswersError(ValueError):
    """The archive's node.conf cannot be read back into answers."""


def _values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        matched = LINE.fullmatch(line.strip())
        if matched is None:
            continue
        value = matched.group("value")
        if not SAFE.fullmatch(value):
            raise AnswersError(f"node.conf gives {matched.group('key')} a value a restore refuses")
        values[matched.group("key")] = value
    missing = [key for key in REQUIRED if key not in values]
    if missing:
        raise AnswersError(f"node.conf in the archive does not set {', '.join(missing)}")
    return values


def _names(value: str, what: str) -> list[str]:
    names = value.split()
    for name in names:
        if not NAME.fullmatch(name):
            raise AnswersError(f"node.conf names an unusable {what}: {name!r}")
    return names


def derive(source: RestoreSource, cluster: str, publish_root: Path) -> str:
    """The answers file for this archive's node, for ``04-node-prepare <file> <cluster>``."""

    entry = source.entry(NODE_CONF)
    if entry is None or entry.kind != "file":
        raise AnswersError(f"the archive has no {NODE_CONF}")
    try:
        values = _values(content(source, entry).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise AnswersError(f"{NODE_CONF} in the archive is not UTF-8") from exc

    if values["CLUSTER"] != cluster:
        raise AnswersError(f"the archive's node belongs to {values['CLUSTER']}, not to {cluster}")
    if not CLUSTER_ID.fullmatch(cluster):
        raise AnswersError(f"cluster ID {cluster} is not one the engine accepts")
    prefix = f"{cluster}/current/"
    remote = values["CONFIG_REMOTE_PATH"]
    node_path = remote.removeprefix(prefix).removesuffix("/")
    if (
        not remote.startswith(prefix)
        or not remote.endswith("/")
        or not NODE_PATH.fullmatch(node_path)
    ):
        raise AnswersError(f"node.conf has a CONFIG_REMOTE_PATH a restore cannot read: {remote}")

    services = _names(values["BACKUP_SERVICE_ACCOUNTS"], "service account")
    if services != SERVICE_ACCOUNTS:
        raise AnswersError(
            "node.conf names other service accounts than this release's; the archive is from "
            "before the accounts were renamed"
        )
    listed = _names(values["BACKUP_ACCOUNTS"], "account")
    if listed[:4] != services:
        raise AnswersError("node.conf's BACKUP_ACCOUNTS does not begin with its service accounts")
    groups = _names(values["BACKUP_GROUPS"], "group")
    if not groups or groups[0] != accounts.LOGS_GROUP:
        raise AnswersError(f"node.conf's BACKUP_GROUPS does not begin with {accounts.LOGS_GROUP}")
    for key, fixed in (("CONFIG_PULL_USER", accounts.PULL), ("CERT_PULL_USER", accounts.CERT_PULL)):
        if key in values and values[key] != fixed:
            raise AnswersError(f"node.conf's {key} is not {fixed}")
    if not publish_root.is_absolute() or not SAFE.fullmatch(str(publish_root)):
        raise AnswersError("this manager's publish root cannot be written to an answers file")

    lines = [
        "# Derived by a node restore from the archive's node.conf; not an operator's answers file.",
        f'MANAGER_HOST="{values["MANAGER"]}"',
        f'NODE_CONFIG_PULL_KEY="{values["CONFIG_PULL_KEY"]}"',
        f'PUBLISH_ROOT="{publish_root}"',
        #
        # 04-node-prepare looks the node's path up as NODE_PATH_<cluster> with
        # each hyphen an underscore, since no shell variable name holds one
        # (`cluster_value` in install/lib.sh).
        #
        f'NODE_PATH_{cluster.replace("-", "_")}="{node_path}"',
        f'OPERATOR_ACCOUNTS="{" ".join(listed[4:])}"',
        f'EXTRA_BACKUP_GROUPS="{" ".join(groups[1:])}"',
        f'EXTRA_BACKUP_PATHS="{values.get("EXTRA_BACKUP_PATHS", "")}"',
    ]
    if "CERT_PULL_KEY" in values:
        lines.append(f'NODE_CERT_PULL_KEY="{values["CERT_PULL_KEY"]}"')
    return "\n".join(lines) + "\n"
