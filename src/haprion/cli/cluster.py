"""``haprion-cluster`` - create a cluster with its first node or two, or remove one (B211, B302).

    haprion-cluster add -c <id> [--display-name <name>] --vip <address>
                        --node-path <path> [--certificate <id>]
                        --host <first node> [--host <second node>]
                        [--prefix <length>] [--interface <name>] [--json] < blocks
    haprion-cluster remove -c <id> [--json]

`--json` prints the helper's envelope (`schemas/v1/haprion-cluster-define`)
and leaves with its exit code.

The blocks are what `04-node-prepare` printed on the nodes, one after the
other on stdin, in the order of the `--host` options; a further node is added
with `haprion-node add`. A cluster may start without a certificate (B302):
`--certificate` names the one the certificate commands then refuse to take
away from it. The request goes through the same
root helper the interface's Settings page uses: the cluster file, the
certificate registry, the repository, the release directory, the editing
policy and the nodes' files change as one, and a node that does not then
answer as itself takes all of it back.

Removing archives the cluster's repository, release directory and backups under
`.removed/` in their own roots and forgets the cluster; its nodes keep serving
their addresses until they are shut down.
"""

from __future__ import annotations

import argparse
import sys
from typing import TextIO

from haprion import node_publish
from haprion.cli import arguments, node_helper
from haprion.cli.node import RunHelper, _answer, json_answer, run_helper
from haprion.envelope import new_request_id
from haprion.node_enrollment import BLOCK_PREFIX, MAX_BLOCK_BYTES, V2_PREFIXES


def _parser() -> argparse.ArgumentParser:
    parser = arguments.ArgumentParser(prog="haprion-cluster")
    actions = parser.add_subparsers(dest="action", required=True)
    create = actions.add_parser("add")
    create.add_argument("-c", "--cluster", required=True)
    create.add_argument("--display-name")
    create.add_argument("--vip", required=True)
    create.add_argument("--node-path", required=True)
    create.add_argument("--certificate")
    create.add_argument("--host", action="append", required=True)
    create.add_argument("--prefix", type=int)
    create.add_argument("--interface")
    create.add_argument("--json", action="store_true")
    remove = actions.add_parser("remove")
    remove.add_argument("-c", "--cluster", required=True)
    remove.add_argument("--json", action="store_true")
    return parser


def split_blocks(text: str) -> list[str]:
    """The blocks on stdin, however a terminal folded them."""

    compact = "".join(text.split())
    #
    # Split before each prefix, v1 or v2 (B317): base64 has no colon, so a
    # prefix is never inside a block.
    #
    marked = compact
    for prefix in (BLOCK_PREFIX, *V2_PREFIXES):
        marked = marked.replace(prefix, "\n" + prefix)
    return [part for part in marked.split("\n") if part]


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
            # The ID unless given, as the form does (review 2026-10-22, 7-16).
            display_name=args.display_name or args.cluster,
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

    completed = run(request)
    if args.json:
        return json_answer(completed, node_helper.DEFINE, args.cluster, writer, errors)
    try:
        result = _answer(completed, node_helper.DEFINE)
    except ValueError as exc:
        errors.write(f"ERROR: {exc}\n")
        return 1

    if result.get("action") == "added":
        names = ", ".join(str(node.get("name")) for node in result.get("nodes", []))
        writer.write(
            f"Created {args.cluster} with {names}.\n"
            f"Host keys: {', '.join(str(item) for item in result.get('host_key_fingerprints', []))}\n"
            f"Changed: {', '.join(str(item) for item in result.get('files', []))}\n"
            f"The nodes have no certificates yet: haprion-cert-deploy -c {args.cluster}\n"
            + node_publish.said(result.get("publication"), args.cluster)
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
