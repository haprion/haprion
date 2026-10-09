#!/usr/bin/env python3
"""Create or inspect the key pair that seals DNS provider credentials.

    sudo /usr/bin/python3 tools/dns-profile-keys.py create \\
        --private /etc/haprion/ui-secrets/dns-profile-keys \\
        --public /etc/haprion/dns-profile-keys --group _haprion-ui
    /usr/bin/python3 tools/dns-profile-keys.py show --public <file>.pub

`create` generates a fresh pair, writes the private key root-only into the
first directory and the public key group-readable into the second, both named
`<key id>.key` / `<key id>.pub`, proves the pair by sealing and opening a
message through the files it wrote, and prints the key identifier. An existing
key is never touched: a second `create` adds a second pair, which is how a key
is replaced - the runtime policy lists both while profiles are re-entered.

Run by platform steps 15 and 17 with the system interpreter, which is why this
file imports the engine itself - from the source tree beside it, or, where it
was installed by the haprion-ui package and has none, from the installed CLI
release - and needs `python3-nacl` from the distribution, the same package the
installed CLI release uses.
"""

from __future__ import annotations

import argparse
import grp
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parent.parent / "src"
if not (SOURCE / "haproxy_mgmt").is_dir():
    SOURCE = Path("/opt/haprion/current/lib")
sys.path.insert(0, str(SOURCE))

from haproxy_mgmt.dns_profile_keys import (  # noqa: E402 - the path above is the import
    KeyFileError,
    open_sealed,
    read_private_key,
    read_public_key,
    seal,
    write_key_pair,
)


def _directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise KeyFileError(f"{label} must be absolute")
    if not path.is_dir() or path.is_symlink():
        raise KeyFileError(f"{label} {path} must be an existing directory, not a symlink")
    return path


def create(private_dir: Path, public_dir: Path, group: str | None) -> str:
    private_dir = _directory(private_dir, "--private")
    public_dir = _directory(public_dir, "--public")
    gid = grp.getgrnam(group).gr_gid if group else None
    # Written under a name the key id decides, so the pair is generated first
    # into holding names and renamed once the id is known.
    holding_private = private_dir / ".new.key"
    holding_public = public_dir / ".new.pub"
    for path in (holding_private, holding_public):
        if path.exists():
            raise KeyFileError(f"{path} is left over from an interrupted run; remove it first")
    written = write_key_pair(holding_private, holding_public, group=gid)
    private_path = private_dir / f"{written.key_id}.key"
    public_path = public_dir / f"{written.key_id}.pub"
    for path in (private_path, public_path):
        if path.exists():
            holding_private.unlink()
            holding_public.unlink()
            raise KeyFileError(f"{path} already exists")
    holding_private.rename(private_path)
    holding_public.rename(public_path)

    # The proof goes through the files, not the objects in memory.
    private_key = read_private_key(private_path, require_secure=False)
    public_key = read_public_key(public_path)
    message = b"dns-profile-key-proof"
    if (
        private_key.key_id != written.key_id
        or public_key.key_id != written.key_id
        or open_sealed(private_key, seal(public_key, message)) != message
    ):
        raise KeyFileError("the written pair did not round-trip; do not use it")
    return written.key_id


def show(public_path: Path) -> str:
    return read_public_key(public_path).key_id


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DNS profile key pair")
    commands = parser.add_subparsers(dest="command", required=True)
    creator = commands.add_parser("create", help="generate a new pair")
    creator.add_argument("--private", required=True, type=Path, help="root-only directory")
    creator.add_argument("--public", required=True, type=Path, help="group-readable directory")
    creator.add_argument("--group", help="group that may read the public key")
    shower = commands.add_parser("show", help="print a public key's identifier")
    shower.add_argument("--public", required=True, type=Path, help="the public key file")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "create":
            print(create(args.private, args.public, args.group))
        else:
            print(show(args.public))
    except (KeyFileError, KeyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
