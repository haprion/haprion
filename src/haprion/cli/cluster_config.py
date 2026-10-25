from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

from haprion import exit_codes
from haprion.cli import arguments
from haprion.cluster_definition import seed_files
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config

FIELDS = (
    "display_name",
    "vip",
    "config_path",
    "publish_path",
    "node_path",
    "validation_certs",
    "default_certificate",
    "certificate_ids",
    "trusted_proxy_cidrs",
    "nodes",
)


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    require_secure: bool = True,
) -> int:
    parser = arguments.ArgumentParser(prog="haprion-cluster-config")
    #
    # --list names the clusters the file holds, one per line, so an
    # installation step reads the clusters that exist - including those created
    # in the interface - rather than the ones an answers file once named.
    #
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("-c", "--cluster")
    which.add_argument("--list", action="store_true")
    #
    # --seed writes a new cluster's repository layout into an empty directory:
    # the same files Create cluster commits, for step 1's clusters from an
    # answers file. Reads no policy - step 1 runs before step 2 writes one.
    #
    which.add_argument("--seed", type=Path, metavar="DIRECTORY")
    parser.add_argument("--field", choices=FIELDS)
    parser.add_argument("--vip")
    parser.add_argument("--source")
    args = parser.parse_args(argv)
    if args.seed is not None:
        return _seed(parser, args.seed, args.vip, args.source)
    if args.vip is not None or args.source is not None:
        parser.error("--vip and --source go with --seed")
    if args.list == (args.field is not None):
        parser.error("give either --list, or -c with --field")

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
        if args.list:
            for name in runtime.clusters:
                print(name)
            return 0
        cluster = runtime.cluster(args.cluster)
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return exc.exit_code

    value = getattr(cluster, args.field)
    if args.field == "nodes":
        for node in value:
            print(f"{node.name}\t{node.mgmt_host}")
    elif isinstance(value, tuple):
        for item in value:
            print(item)
    else:
        print(value)
    return 0


def _seed(
    parser: argparse.ArgumentParser, directory: Path, vip: str | None, source: str | None
) -> int:
    if source and not vip:
        parser.error("--source needs --vip")
    for address in (vip, source):
        if address:
            try:
                ipaddress.ip_address(address)
            except ValueError:
                parser.error(f"not an IP address: {address}")
    if not directory.is_dir() or any(directory.iterdir()):
        print(f"ERROR: {directory} is not an empty directory", file=sys.stderr)
        return exit_codes.CANNOT_CREATE
    for relative, content in seed_files(vip or None, source or None).items():
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
