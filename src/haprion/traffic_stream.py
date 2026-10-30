"""Where HAProxy writes the structured traffic stream on a node, and what a core must allow.

A node holds the stream's socket at TRAFFIC_LOG_SOCKET, writable by the
haproxy account alone (`haprion-traffic-log.socket`, 04-node-prepare), and
its rsyslog trusts only what arrives there (B403): a line under the same tag
on the system's /dev/log is neither forwarded nor written to the day file.

The generated `log` line names the socket by its path on the host. A HAProxy
chrooted in /var/lib/haproxy looks that path up inside its chroot, where step 4
has put a link to the same socket (TRAFFIC_LOG_LINK), so the line is right
with Ubuntu's chroot and without one, and does not change when a core gains or
loses the chroot. What a core can still do is chroot somewhere else, or run
HAProxy as an account that may not write the socket; every traffic line would
then be dropped on every node with nothing said, so a publish that logs the
stream refuses such a core instead (review 2026-10-30-igen, R2).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

HAPROXY_CHROOT = "/var/lib/haproxy"
TRAFFIC_LOG_SOCKET = "/var/lib/haproxy/dev/haprion-traffic"
#
# The same socket as a HAProxy chrooted in /var/lib/haproxy finds the path
# above: a relative link, so it leads there from the host as well.
#
TRAFFIC_LOG_LINK = HAPROXY_CHROOT + TRAFFIC_LOG_SOCKET
#
# The profile the generator names on the line (`generate.TRAFFIC_LOG_PROFILE`;
# a test holds the two together).
#
TRAFFIC_LOG_PROFILE = "mgd-traffic-json"
ACCOUNT = "haproxy"
#
# The keywords that open a section. A `user` or `group` line means the
# account HAProxy runs as only in `global`: a userlist has lines of the same
# names.
#
SECTIONS = frozenset(
    {
        "acme",
        "backend",
        "cache",
        "crt-store",
        "defaults",
        "fcgi-app",
        "frontend",
        "global",
        "http-errors",
        "listen",
        "log-forward",
        "log-profile",
        "mailers",
        "peers",
        "program",
        "resolvers",
        "ring",
        "traces",
        "userlist",
    }
)
#
# `user` and `uid` name one setting, and so do `group` and `gid`: HAProxy keeps
# the first line of either and warns of the rest.
#
_GLOBAL_SLOTS = {
    "chroot": "chroot",
    "user": "user",
    "uid": "user",
    "group": "group",
    "gid": "group",
}
_TRAFFIC_LOG = re.compile(
    rf"^[ \t]*log[ \t]+(\S+)[ \t].*\bprofile[ \t]+{re.escape(TRAFFIC_LOG_PROFILE)}\b", re.MULTILINE
)
CORE_FILE = "core/haproxy.cfg"
GENERATED = "managed/generated/"
_CONF_LAYERS = ("core/conf.d/", GENERATED, "manual/conf.d/")


def node_order(files: Mapping[str, bytes]) -> list[str]:
    """A tree's HAProxy configuration in the order a node reads it: the core, then conf.d by name."""

    fragments = sorted(
        (path.rsplit("/", 1)[-1], content)
        for path, content in files.items()
        if path.startswith(_CONF_LAYERS) and path.endswith(".cfg")
    )
    texts = [files.get(CORE_FILE, b"")] + [content for _, content in fragments]
    return [text.decode("utf-8", errors="replace") for text in texts]


def global_settings(texts: Iterable[str]) -> dict[str, str]:
    """What `global` says of the chroot and the account HAProxy runs as, the first line winning.

    HAProxy keeps the first `chroot`, `user` or `uid`, and `group` or `gid`, it
    reads and warns of later ones (measured on 3.4.7), so the first is what runs.
    The key is the keyword that line used.
    """

    found: dict[str, str] = {}
    taken: set[str] = set()
    for text in texts:
        in_global = False
        for raw in text.splitlines():
            words = raw.split("#", 1)[0].split()
            if not words:
                continue
            if words[0] in SECTIONS:
                in_global = words[0] == "global"
                continue
            slot = _GLOBAL_SLOTS.get(words[0])
            if in_global and slot is not None and len(words) > 1 and slot not in taken:
                taken.add(slot)
                found[words[0]] = words[1]
    return found


def traffic_log_targets(texts: Iterable[str]) -> list[str]:
    """Every target a `log` line with the traffic stream's profile names."""

    return [target for text in texts for target in _TRAFFIC_LOG.findall(text)]


def reached(target: str, chroot: str | None) -> str:
    """The host path a HAProxy with this chroot reaches for a `log` target."""

    root = (chroot or "").rstrip("/")
    return root + target if root and target.startswith("/") else target


def chroot_reaches_socket(chroot: str | None) -> bool:
    """Whether a HAProxy with this chroot finds TRAFFIC_LOG_SOCKET by its host path."""

    root = (chroot or "").rstrip("/")
    return root in ("", HAPROXY_CHROOT)


def may_write_socket(settings: Mapping[str, str]) -> bool:
    """Whether the account `global` names may write a socket that is haproxy:haproxy 0660.

    No `user` or `uid` leaves HAProxy as root, as systemd starts it.
    """

    user = settings.get("user")
    uid = settings.get("uid")
    if settings.get("group") == ACCOUNT or user == ACCOUNT:
        return True
    return user is None and uid in (None, "0")


def problem(files: Mapping[str, bytes], *, cluster: str, config_path: str) -> str | None:
    """Why HAProxy with this core would not reach the traffic socket, if it would not.

    Only a release that logs the stream is held to it: one that sends nothing
    there is any core's business. Checked on what the release carries, so a
    core edited by hand is held to it as one the interface wrote.
    """

    generated = [
        content.decode("utf-8", errors="replace")
        for path, content in sorted(files.items())
        if path.startswith(GENERATED) and path.endswith(".cfg")
    ]
    if not traffic_log_targets(generated):
        return None
    settings = global_settings(node_order(files))
    chroot = settings.get("chroot")
    if not chroot_reaches_socket(chroot):
        return (
            f"{cluster}: core/haproxy.cfg chroots HAProxy in {chroot}, and the traffic log's socket "
            f"is {TRAFFIC_LOG_SOCKET}.\n"
            f"\n"
            f"  Fix it, then publish again:\n"
            f"    sudoedit {config_path}/core/haproxy.cfg\n"
            f"    in the `global` section, change the chroot line to:\n"
            f"      chroot {HAPROXY_CHROOT}\n"
            f"    or remove it.\n"
            f"\n"
            f"  Why this stops a publish: HAProxy looks the socket up inside its chroot, and\n"
            f"  only {HAPROXY_CHROOT} has it. Every traffic record would be dropped on every\n"
            f"  node, for the node's own log and for every log receiver, and nothing would say so."
        )
    if not may_write_socket(settings):
        runs_as = settings.get("user") or f"uid {settings.get('uid')}"
        return (
            f"{cluster}: core/haproxy.cfg runs HAProxy as {runs_as}, which may not write the "
            f"traffic log's socket.\n"
            f"\n"
            f"  Fix it, then publish again:\n"
            f"    sudoedit {config_path}/core/haproxy.cfg\n"
            f"    in the `global` section, set:\n"
            f"      user {ACCOUNT}\n"
            f"      group {ACCOUNT}\n"
            f"\n"
            f"  Why this stops a publish: the socket, {TRAFFIC_LOG_SOCKET}, is writable by the\n"
            f"  {ACCOUNT} account alone, so that no other account on a node can add lines to\n"
            f"  the traffic log. Every traffic record would be dropped on every node, for the\n"
            f"  node's own log and for every log receiver, and nothing would say so."
        )
    return None
