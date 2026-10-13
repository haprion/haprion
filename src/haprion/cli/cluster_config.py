from __future__ import annotations

import argparse
import sys
from pathlib import Path

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
    parser = argparse.ArgumentParser(prog="haprion-cluster-config")
    #
    # --list names the clusters the file holds, one per line, so an
    # installation step reads the clusters that exist - including those created
    # in the interface - rather than the ones an answers file once named.
    #
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("-c", "--cluster")
    which.add_argument("--list", action="store_true")
    parser.add_argument("--field", choices=FIELDS)
    args = parser.parse_args(argv)
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


if __name__ == "__main__":
    raise SystemExit(main())
