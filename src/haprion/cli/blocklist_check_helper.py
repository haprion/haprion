"""`haprion-blocklist-check-helper` - *Test* and *Check address* for the web (B496 nr 13, B500).

The web asks over `/run/haprion/blocklist-check.sock`, one request per
connection, with one of two parameters:

- `list`: a blocklist as the form holds it, fetched once and read as the
  timer would, with nothing saved or kept. The password or token is the one
  typed, or with `keep_secret` the one saved for that name, which only root
  can read.
- `address`: which of the lists the timer keeps hold it, and in which
  clusters an exception keeps it off the nodes.

Root, because the saved secrets in `/etc/haprion/blocklists` and the kept
lists in `/var/lib/haprion/blocklists` are root's; the network, because a
test fetches. It writes nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haprion import blocklist_check, blocklist_store, blocklists, exit_codes
from haprion.cli import cert_job
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.envelope import envelope
from haprion.helper_protocol import HelperProtocolError, write_document

OPERATION = "blocklist_check"
PARAMETERS = frozenset({"address", "list"})
LIST_KEYS = frozenset(
    {"name", "url", "every_hours", "authorization", "username", "excepts", "secret", "keep_secret"}
)
LIST_OPTIONAL = frozenset({"username", "excepts", "secret", "keep_secret"})


def cluster_groups(
    policy_path: Path = DEFAULT_POLICY_PATH, *, require_secure: bool = True
) -> blocklist_check.Groups:
    """Each cluster's network groups, as the timer reads them for its exceptions."""

    policy = load_policy(policy_path, require_secure=require_secure)
    runtime = load_runtime_config(policy, require_secure=require_secure)
    return {
        cluster_id: runtime.clusters[cluster_id].network().networks
        for cluster_id in sorted(runtime.clusters)
    }


def _definition(fields: dict[str, Any]) -> blocklists.Definition:
    keys = set(fields)
    if not keys <= LIST_KEYS or not keys >= LIST_KEYS - LIST_OPTIONAL:
        raise HelperProtocolError(
            "parameters.list holds name, url, every_hours and authorization, and may hold "
            "username, excepts, secret or keep_secret",
            exit_code=exit_codes.REFUSED,
        )
    excepts = fields.get("excepts", [])
    if not isinstance(excepts, list) or not all(isinstance(entry, str) for entry in excepts):
        raise HelperProtocolError(
            "parameters.list.excepts is a list of strings", exit_code=exit_codes.REFUSED
        )
    try:
        return blocklists.definition(
            name=fields["name"],
            url=fields["url"],
            every_hours=fields["every_hours"],
            authorization=fields["authorization"],
            username=fields.get("username", ""),
            excepts=excepts,
        )
    except ValueError as exc:
        raise blocklist_check.CheckError("bad_input", str(exc)) from exc


def _secret(fields: dict[str, Any], item: blocklists.Definition, definitions: Path) -> str:
    """The typed secret, or with `keep_secret` the one saved for this name."""

    keep = fields.get("keep_secret", False)
    typed = fields.get("secret", "")
    if not isinstance(keep, bool) or not isinstance(typed, str):
        raise HelperProtocolError(
            "parameters.list.secret is a string and keep_secret true or false",
            exit_code=exit_codes.REFUSED,
        )
    if keep and typed:
        raise HelperProtocolError(
            "parameters.list has a secret or keep_secret, not both", exit_code=exit_codes.REFUSED
        )
    if item.authorization == "none" or not keep:
        return typed
    for stored in blocklist_store.read_all(directory=definitions):
        if stored.definition.name == item.name:
            return stored.secret
    raise blocklist_check.CheckError(
        "no_secret", f"no password or token is saved for {item.name}: type it to test"
    )


def perform(
    parameters: dict[str, Any],
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    definitions: Path = blocklist_store.DEFINITIONS,
    state: Path = blocklist_store.STATE,
    fetch: blocklist_check.Fetch = blocklists.fetch,
    require_secure: bool = True,
) -> dict[str, object]:
    if len(parameters) != 1:
        raise HelperProtocolError(
            "parameters hold address or list, one of them", exit_code=exit_codes.REFUSED
        )
    groups = cluster_groups(policy_path, require_secure=require_secure)
    if "address" in parameters:
        stored = blocklist_store.read_all(directory=definitions)
        return blocklist_check.check_address(
            blocklist_check.checked_address(parameters["address"]),
            [item.definition for item in stored],
            blocklist_store.read_state(directory=state),
            groups,
            kept=lambda name: blocklist_store.kept(name, directory=state),
        ).as_dict()
    fields = parameters["list"]
    if not isinstance(fields, dict):
        raise HelperProtocolError("parameters.list is an object", exit_code=exit_codes.REFUSED)
    item = _definition(fields)
    return blocklist_check.test(
        item, _secret(fields, item, definitions), groups, fetch=fetch
    ).as_dict()


def main(
    argv: list[str] | None = None,
    *,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    policy_path: Path = DEFAULT_POLICY_PATH,
    definitions: Path = blocklist_store.DEFINITIONS,
    state: Path = blocklist_store.STATE,
    fetch: blocklist_check.Fetch = blocklists.fetch,
    require_root: bool = True,
    require_secure: bool = True,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    try:
        request = cert_job.read_request(
            OPERATION,
            parameters=PARAMETERS,
            input_stream=input_stream,
            argv=argv,
            require_root=require_root,
            helper_name="haprion-blocklist-check-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        result = perform(
            dict(request.parameters),
            policy_path=policy_path,
            definitions=definitions,
            state=state,
            fetch=fetch,
            require_secure=require_secure,
        )
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)
    except blocklist_check.CheckError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    except blocklist_store.StoreError as exc:
        return refuse("bad_state", str(exc), exit_codes.CONFIG)
    except ConfigError as exc:
        return refuse("bad_policy", str(exc), exc.exit_code)
    #
    # The journal's line (stderr is the journal): what was asked, never the
    # secret. A test names its list, a check its address.
    #
    subject = result.get("name") if result["kind"] == "list" else result.get("address")
    errors.write(f"blocklist_check: {result['kind']} {subject}\n")
    errors.flush()
    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result=result,
        ),
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
