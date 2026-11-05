"""The product's own directories, moved into a scratch directory for the length of a block.

A command is run in-process as if by root, so the paths it opens - the runtime
policy, the cluster file, the lock and run directories - must not be the
machine's: as an ordinary user they are refused, and as root they would be
written. Every call that takes a path under one of `PRODUCT_ROOTS` is given the
same path below the scratch directory instead; everything else, Python's own
libraries included, is left alone.
"""

from __future__ import annotations

import builtins
import contextlib
import io
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from unittest import mock

PRODUCT_ROOTS = (
    "/etc/haprion",
    "/run/haprion",
    "/var/lib/haprion",
    "/srv",
)

#
# The os functions that take a path first (and, for a rename, a second).
#
ONE_PATH = (
    "stat",
    "lstat",
    "open",
    "mkdir",
    "listdir",
    "scandir",
    "unlink",
    "remove",
    "rmdir",
    "chmod",
    "chown",
    "access",
    "utime",
    "readlink",
    "truncate",
)
TWO_PATHS = ("rename", "replace", "symlink", "link")


def _moved(scratch: Path, path: Any) -> Any:
    if isinstance(path, int):
        return path
    try:
        text = os.fspath(path)
    except TypeError:
        return path
    if isinstance(text, bytes):
        return path
    for root in PRODUCT_ROOTS:
        if text == root or text.startswith(root + "/") or text.startswith(root + "-"):
            return str(scratch) + text
    return path


def _wrapped(scratch: Path, function: Callable[..., Any], two: bool) -> Callable[..., Any]:
    def call(first: Any, *args: Any, **kwargs: Any) -> Any:
        if two and args:
            return function(_moved(scratch, first), _moved(scratch, args[0]), *args[1:], **kwargs)
        return function(_moved(scratch, first), *args, **kwargs)

    return call


@contextlib.contextmanager
def product_directories(scratch: Path) -> Iterator[None]:
    """Run the block with the product's directories below `scratch`."""

    patches = []
    for name in ONE_PATH:
        patches.append(mock.patch.object(os, name, _wrapped(scratch, getattr(os, name), False)))
    for name in TWO_PATHS:
        patches.append(mock.patch.object(os, name, _wrapped(scratch, getattr(os, name), True)))
    patches.append(mock.patch.object(builtins, "open", _wrapped(scratch, builtins.open, False)))
    patches.append(mock.patch.object(io, "open", _wrapped(scratch, io.open, False)))
    with contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        yield


POLICY = """\
schema_version: 1
cluster_file: /srv/haprion/config/clusters.yaml
config_root: /srv/haprion/config-repositories
publish_root: /srv/haprion/published
validation_certs_root: /srv/haprion/validation-certs
certificate_registry: /srv/haprion/config/certificates.yaml
deploy_identity:
  key: /root/.ssh/id_ed25519_example_deploy
backup_root: /srv/state-backups
backup_identity:
  key: /root/.ssh/id_ed25519_node_backup
"""

CLUSTERS = """\
schema_version: 1
clusters:
  alpha:
    display_name: Alpha
    vip: 192.0.2.20
    config_path: /srv/haprion/config-repositories/alpha
    publish_path: /srv/haprion/published/alpha
    node_path: alpha
    validation_certs: /srv/haprion/validation-certs
    nodes:
      - name: node-a
        mgmt_host: node-a.example.com
"""

REGISTRY = """\
schema_version: 1
certificates:
  example.com:
    source:
      kind: acme
    clusters:
      - alpha
"""

ADMIN = "DB_NAME=haprion_ui\nDB_ROLE=haprion_admin\n"


def write_installation(scratch: Path) -> None:
    """One cluster, one certificate and an administrator's database file, where the product keeps them.

    Enough for a command to read its configuration and get as far as judging
    what it was asked; nothing in it exists on a real host (RFC 5737, example.com).
    """

    files = {
        "etc/haprion/runtime-policy.yaml": POLICY,
        "etc/haprion/ui-admin.conf": ADMIN,
        "srv/haprion/config/clusters.yaml": CLUSTERS,
        "srv/haprion/config/certificates.yaml": REGISTRY,
    }
    for name, text in files.items():
        path = scratch / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for directory in ("run/haprion/locks", "var/lib/haprion/restore", "var/lib/haprion/answers"):
        (scratch / directory).mkdir(parents=True, exist_ok=True)
