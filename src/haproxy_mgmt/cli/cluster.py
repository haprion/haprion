"""``haproxy-cluster`` - create a cluster with its first two nodes, or remove one (B211).

    haproxy-cluster add -c <id> --display-name <name> --vip <address>
                        --node-path <path> --certificate <id>
                        --host <first node> --host <second node>
                        [--prefix <length>] [--interface <name>] < blocks
    haproxy-cluster remove -c <id>

The blocks are what `04-node-prepare` printed on the two nodes, one after the
other on stdin, in the order of the `--host` options. Both go through the same
root helper the interface's Settings page uses: the cluster file, the
certificate registry, the repository, the release directory, the editing
policy and both nodes' files change as one, and a node that does not then
answer as itself takes all of it back.

Removing archives the cluster's repository, release directory and backups under
`.removed/` in their own roots and forgets the cluster; its nodes keep serving
their addresses until they are shut down.
"""

from __future__ import annotations

import argparse
import sys
from typing import TextIO

from haproxy_mgmt.cli import node_helper
from haproxy_mgmt.cli.node import RunHelper, _answer, run_helper
from haproxy_mgmt.envelope import new_request_id
from haproxy_mgmt.node_enrollment import BLOCK_PREFIX, MAX_BLOCK_BYTES


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="haproxy-cluster")
    actions = parser.add_subparsers(dest="action", required=True)
    create = actions.add_parser("add")
    create.add_argument("-c", "--cluster", required=True)
    create.add_argument("--display-name", required=True)
    create.add_argument("--vip", required=True)
    create.add_argument("--node-path", required=True)
    create.add_argument("--certificate", required=True)
    create.add_argument("--host", action="append", required=True)
    create.add_argument("--prefix", type=int)
    create.add_argument("--interface")
    remove = actions.add_parser("remove")
    remove.add_argument("-c", "--cluster", required=True)
    return parser


def split_blocks(text: str) -> list[str]:
    """The blocks on stdin, however a terminal folded them."""

    compact = "".join(text.split())
    return [BLOCK_PREFIX + part for part in compact.split(BLOCK_PREFIX) if part]


def main(
    argv: list[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    run: RunHelper = run_helper,
) -> int:
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    writer = stdout or sys.stdout
    errors = stderr or sys.stderr
    if args.action == "add":
        blocks = split_blocks((stdin or sys.stdin).read(2 * MAX_BLOCK_BYTES + 1))
        request = node_helper.build_define_request(
            args.cluster,
            new_request_id(),
            action="add",
            display_name=args.display_name,
            vip=args.vip,
            node_path=args.node_path,
            default_certificate=args.certificate,
            blocks=blocks,
            hosts=args.host,
            address_prefix=args.prefix,
            address_interface=args.interface,
        )
    else:
        request = node_helper.build_define_request(args.cluster, new_request_id(), action="remove")

    try:
        result = _answer(run(request), node_helper.DEFINE)
    except ValueError as exc:
        errors.write(f"ERROR: {exc}\n")
        return 1

    if result.get("action") == "added":
        names = ", ".join(str(node.get("name")) for node in result.get("nodes", []))
        writer.write(
            f"Created {args.cluster} with {names}.\n"
            f"Host keys: {', '.join(str(item) for item in result.get('host_key_fingerprints', []))}\n"
            f"Changed: {', '.join(str(item) for item in result.get('files', []))}\n"
            f"Next: publish its network and objects, then haproxy-deploy -c {args.cluster}\n"
        )
    else:
        writer.write(
            f"Removed {args.cluster}; archived as {result.get('archive')} under .removed/.\n"
            "Its nodes are untouched and keep serving until they are shut down.\n"
        )
        for warning in result.get("warnings", []):
            writer.write(f"WARNING: {warning}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
