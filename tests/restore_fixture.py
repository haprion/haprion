"""A state archive shaped like the one install/node/haprion-state-export writes.

Built the way the exporter builds it: under umask 077, with each copied path's
parents created by `mkdir -p` and so recorded as 0700 - the property the restore
has to be careful about - and a manifest computed over the staged tree.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tarfile
from pathlib import Path

from haproxy_mgmt.backup_archive import REQUIRED_PATHS

SERVICE_ACCOUNTS = ("_haprion-trigger", "_haprion-status", "_haprion-backup", "_haprion-logread")

# Rendered by install/lib.sh's render_node_conf; a test holds the two together.
NODE_CONF = """# Node configuration for Haprion. Rendered by install/04-node-prepare.
#
# Read by the node-side scripts in /usr/sbin. Root-owned and not writable
# by anyone else: it names the account and key used to fetch configuration, so
# whoever can edit it can redirect this node to another source.

CLUSTER="alpha"
MANAGER="mgr.example.com"

# Where this node fetches its published configuration from.
CONFIG_PULL_USER="_haprion-pull"
CONFIG_PULL_KEY="/etc/haprion/keys/config-pull"
CONFIG_REMOTE_PATH="alpha/current/node-a/"

# Local accounts and groups a state backup captures. A rebuilt node with no way
# to log in is not a restored node, so operator accounts belong here too.
BACKUP_SERVICE_ACCOUNTS="_haprion-trigger _haprion-status _haprion-backup _haprion-logread"
BACKUP_ACCOUNTS="_haprion-trigger _haprion-status _haprion-backup _haprion-logread operator"
BACKUP_GROUPS="_haprion-logs"

# The operator's own files a state backup carries besides the product's -
# absolute paths, space-separated. A listed path that is missing fails the backup.
EXTRA_BACKUP_PATHS="/etc/default/grub.d/99-local.cfg"

# Where this node fetches certificates from. A separate account and key: a node
# that may read configuration has no business reading certificates it was not
# asked for.
CERT_PULL_USER="_haprion-cert-pull"
CERT_PULL_KEY="/etc/haprion/keys/cert-pull"
"""

NETPLAN = """network:
  version: 2
  ethernets:
    eth0:
      match:
        macaddress: "02:00:00:00:00:0a"
      set-name: eth0
      addresses:
        - 192.0.2.21/24
      routes:
        - to: default
          via: 192.0.2.1
"""

KEEPALIVED = """vrrp_instance VI_1 {
    state BACKUP
    nopreempt
    interface eth0
    virtual_router_id 51
    priority 110
    unicast_src_ip 192.0.2.21
    unicast_peer {
        192.0.2.22
    }
    virtual_ipaddress {
        192.0.2.20/24
    }
    include /etc/keepalived/addresses.conf
}
"""

OS_RELEASE = 'NAME="Ubuntu"\nVERSION_ID="26.04"\nID=ubuntu\nVERSION_CODENAME=resolute\n'


def _users() -> str:
    lines = [
        f"{name}:x:{990 - index}:{990 - index}::/var/lib/{name}:/bin/bash"
        for index, name in enumerate(SERVICE_ACCOUNTS)
    ]
    lines.append("operator:x:1000:1000:Operator:/home/operator:/bin/bash")
    return "\n".join(lines) + "\n"


def _groups() -> str:
    lines = [
        f"uid={990 - index}({name}) gid={990 - index}({name}) groups={990 - index}({name})"
        for index, name in enumerate(SERVICE_ACCOUNTS)
    ]
    lines[-1] += ",985(_haprion-logs)"
    lines.append("uid=1000(operator) gid=1000(operator) groups=1000(operator),27(sudo)")
    return "\n".join(lines) + "\n"


def _group_definitions() -> str:
    lines = [f"{name}:x:{990 - index}:" for index, name in enumerate(SERVICE_ACCOUNTS)]
    lines += ["_haprion-logs:x:985:_haprion-logread", "operator:x:1000:"]
    return "\n".join(sorted(lines)) + "\n"


def _shadow() -> str:
    lines = [f"{name}:!:20000:0:99999:7:::" for name in SERVICE_ACCOUNTS]
    lines.append("operator:$y$j9T$fixture$hash:20000:0:99999:7:::")
    return "\n".join(lines) + "\n"


FILES: dict[str, tuple[str, int]] = {
    "/etc/hostname": ("node-a\n", 0o644),
    "/etc/hosts": ("127.0.0.1 localhost\n127.0.1.1 node-a.example.com node-a\n", 0o644),
    "/etc/keepalived/keepalived.conf": (KEEPALIVED, 0o644),
    "/etc/keepalived/addresses.conf": (
        "# Generated. Do not edit.\n192.0.2.30/24 dev eth0 # vip a\n192.0.2.31/24 dev eth0\n",
        0o644,
    ),
    "/etc/default/haproxy": ("CONFIG=/etc/haproxy/haproxy.cfg\n", 0o644),
    "/etc/netplan/50-cloud-init.yaml": (NETPLAN, 0o600),
    "/etc/sysctl.d/60-haproxy.conf": ("net.ipv4.ip_nonlocal_bind = 1\n", 0o644),
    "/etc/apt/sources.list.d/haproxy.sources": ("Types: deb\n", 0o644),
    "/etc/sudoers.d/haprion-node": ("# rules\n", 0o440),
    "/etc/sudoers.d/90-cloud-init-users": ("# image\n", 0o440),
    "/etc/sysctl.d/99-cloudimg-ipv6.conf": ("net.ipv6.conf.all.use_tempaddr = 0\n", 0o644),
    "/etc/ssh/sshd_config.d/60-cloudimg-settings.conf": ("PasswordAuthentication no\n", 0o644),
    "/etc/haprion/node.conf": (NODE_CONF, 0o600),
    "/etc/haprion/node-installation.json": ('{"node_api": 1}\n', 0o644),
    "/etc/haprion/keys/config-pull": ("private\n", 0o600),
    "/etc/ssh/sshd_config": ("PermitRootLogin prohibit-password\n", 0o644),
    "/etc/ssh/ssh_host_ed25519_key": ("host private\n", 0o600),
    "/etc/ssh/ssh_host_ed25519_key.pub": ("ssh-ed25519 AAAA node-a\n", 0o644),
    "/root/.ssh/authorized_keys": ("ssh-ed25519 AAAA operator\n", 0o600),
    "/var/lib/_haprion-backup/.ssh/authorized_keys": ("restrict ssh-ed25519 AAAA\n", 0o644),
    "/home/operator/.ssh/authorized_keys": ("ssh-ed25519 AAAA operator\n", 0o600),
    "/etc/default/grub.d/99-local.cfg": ("GRUB_CMDLINE_LINUX_DEFAULT=x\n", 0o644),
    "/etc/cloud/cloud-init.disabled": ("", 0o644),
}

META: dict[str, str] = {
    "meta/backup-created.txt": "2026-01-01T04:00:00+00:00\n",
    "meta/hostname.txt": "node-a\n",
    "meta/fqdn.txt": "node-a.example.com\n",
    "meta/os-release": OS_RELEASE,
    "meta/users.txt": _users(),
    "meta/groups.txt": _groups(),
    "meta/group-definitions.txt": _group_definitions(),
    "meta/shadow.txt": _shadow(),
    "meta/packages.txt": "haproxy\nkeepalived\n",
    "meta/package-versions.txt": "haproxy\t3.4.4-1\n",
    "meta/services.txt": "[haproxy]\nenabled=enabled\n",
    "meta/extra-paths.txt": "/etc/default/grub.d/99-local.cfg\n",
}


def _write(path: Path, text: str, mode: int) -> None:
    # `mkdir -p` under umask 077: every parent the exporter did not copy is 0700.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def build(
    root: Path,
    *,
    files: dict[str, tuple[str, int]] | None = None,
    extra_paths: tuple[str, ...] = ("/etc/default/grub.d/99-local.cfg",),
) -> Path:
    stage = root / "stage"
    previous = os.umask(0o077)
    try:
        chosen = dict(FILES if files is None else files)
        for name in REQUIRED_PATHS:
            if name.startswith("rootfs/usr/sbin/"):
                chosen.setdefault(name.removeprefix("rootfs"), ("#!/bin/sh\n", 0o755))
        for path, (text, mode) in chosen.items():
            _write(stage / f"rootfs{path}", text, mode)
        # Copied directories carry their own mode, as `cp -a` preserves it.
        for directory in ("/etc/netplan", "/etc/sysctl.d", "/etc/haprion", "/root/.ssh"):
            target = stage / f"rootfs{directory}"
            if target.is_dir():
                target.chmod(0o700 if directory == "/root/.ssh" else 0o755)
        meta = {**META, "meta/extra-paths.txt": "".join(f"{path}\n" for path in extra_paths)}
        for name, text in meta.items():
            _write(stage / name, text, 0o644)
    finally:
        os.umask(previous)

    entries: list[dict[str, object]] = []
    for tree in (stage / "rootfs", stage / "meta"):
        for member in sorted(tree.rglob("*")):
            info = member.lstat()
            entry: dict[str, object] = {
                "path": member.relative_to(stage).as_posix(),
                "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid,
                "gid": info.st_gid,
                "type": "directory" if member.is_dir() else "file",
            }
            if member.is_file():
                content = member.read_bytes()
                entry.update(size=len(content), sha256=hashlib.sha256(content).hexdigest())
            entries.append(entry)
    (stage / "meta/manifest.json").write_text(
        json.dumps({"schema_version": 1, "entries": entries}, sort_keys=True), encoding="utf-8"
    )
    archive = root / "state.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        output.add(stage / "rootfs", arcname="rootfs")
        output.add(stage / "meta", arcname="meta")
    return archive
