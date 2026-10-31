"""`haprion-block-client` - who may block an address on which objects, from outside (B412).

    list      every block client: its host, cluster, objects and key fingerprint
    add       a client: the host its key connects from, the objects it may block on
    remove    a client, and its key with it

The thin half, as the calling user. `list` reads the registry, which is
world-readable; `add` and `remove` go to `haprion-block-client-helper` through
sudo, as the settings page's do through the worker.

A client then blocks with
`ssh -i <key> _haprion-block@<manager> block <object> <address>...`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, TextIO

from haprion import block_clients
from haprion.block_clients import BlockClientError
from haprion.cli.block_client_helper import HELPER, OPERATION
from haprion.cli.caller import usage, without_answer
from haprion.cli.server_state_helper import SUDO
from haprion.envelope import new_request_id
from haprion.helper_protocol import write_document

USAGE = (
    "Usage:\n"
    "  haprion-block-client list [--json]\n"
    "  haprion-block-client add -c <cluster> --id <id> --host <host> --object <object>... "
    "--key <file.pub> [--json]\n"
    "  haprion-block-client remove -c <cluster> --id <id> [--json]\n"
    "\n"
    "Examples:\n"
    "  haprion-block-client add -c alpha --id app-f2b --host app.example.com "
    "--object shop --key app-f2b.pub\n"
    "  haprion-block-client remove -c alpha --id app-f2b\n"
)


def run_helper(request: str) -> subprocess.CompletedProcess[str]:
    """Through sudo without `-n`, as `haprion-server-state`: a person has a terminal."""

    return subprocess.run(  # noqa: S603 - fixed path, the request on stdin
        [SUDO, "--", HELPER],
        input=request,
        capture_output=True,
        text=True,
        check=False,
    )


def build_request(cluster_id: str, request_id: str, **parameters: Any) -> str:
    """The one request the helper reads, for the command line and the worker alike."""

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": cluster_id,
            "request_id": request_id,
            "parameters": parameters,
        },
        separators=(",", ":"),
    )


def _parse(argv: list[str]) -> dict[str, Any]:
    if not argv or argv[0] not in ("list", "add", "remove"):
        usage(USAGE)
    options: dict[str, Any] = {"verb": argv[0], "objects": [], "json": False}
    values = {
        "-c": "cluster",
        "--cluster": "cluster",
        "--id": "id",
        "--host": "host",
        "--key": "key",
    }
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument in values and index + 1 < len(argv):
            options[values[argument]] = argv[index + 1]
            index += 2
        elif argument == "--object" and index + 1 < len(argv):
            options["objects"].append(argv[index + 1])
            index += 2
        elif argument == "--json":
            options["json"] = True
            index += 1
        else:
            usage(USAGE)
    verb = options["verb"]
    if verb == "add" and not all(options.get(name) for name in ("cluster", "id", "host", "key")):
        usage(USAGE)
    if verb == "add" and not options["objects"]:
        usage(USAGE)
    if verb == "remove" and not (options.get("cluster") and options.get("id")):
        usage(USAGE)
    return options


def _list(json_mode: bool, out: TextIO, clients_file: Path) -> int:
    try:
        clients = block_clients.read(clients_file)
    except BlockClientError as exc:
        sys.stderr.write(f"ERROR: [{exc.code}] {exc}\n")
        return exc.exit_code
    shown = [clients[identifier].shown() for identifier in sorted(clients)]
    if json_mode:
        out.write(json.dumps({"clients": shown}, indent=2) + "\n")
        return 0
    if not shown:
        out.write("No block clients.\n")
    for entry in shown:
        out.write(
            f"{entry['id']}  from {entry['host']}  {entry['cluster']}: "
            f"{', '.join(entry['objects'])}  {entry['fingerprint']}\n"
        )
    return 0


def main(
    argv: list[str] | None = None,
    *,
    writer: TextIO | None = None,
    clients_file: Path = block_clients.CLIENTS_FILE,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out: TextIO = writer or sys.stdout
    options = _parse(argv)
    if options["verb"] == "list":
        return _list(bool(options["json"]), out, clients_file)
    if options["verb"] == "add":
        try:
            key = Path(options["key"]).read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError) as exc:
            sys.stderr.write(f"ERROR: the key could not be read: {exc}\n")
            return 2
        request = build_request(
            options["cluster"],
            new_request_id(),
            action="add",
            client=options["id"],
            host=options["host"],
            objects=options["objects"],
            key=key,
        )
    else:
        request = build_request(
            options["cluster"], new_request_id(), action="remove", client=options["id"]
        )
    completed = run_helper(request)
    try:
        envelope = json.loads(completed.stdout)
    except ValueError:
        return without_answer(
            completed,
            operation=OPERATION,
            cluster=options["cluster"],
            json_mode=bool(options["json"]),
            writer=out,
            errors=sys.stderr,
            fallback="the helper produced no answer",
        )
    if options["json"]:
        return write_document(out, envelope, completed.returncode)
    if envelope.get("result") is None:
        error = envelope.get("error") or {}
        sys.stderr.write(f"ERROR: [{error.get('code')}] {error.get('message')}\n")
        return completed.returncode
    client = envelope["result"]["client"]
    verb = "Added" if options["verb"] == "add" else "Removed"
    out.write(f"{verb} {client['id']} (from {client['host']}, {client['fingerprint']}).\n")
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
