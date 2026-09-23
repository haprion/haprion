"""``haproxy-node-restore`` - restore a node's state archive onto an empty VM.

Runs as root: it reads the root-only archives and holds the run's one-time key.
Three steps, in order, each a separate command (B175):

  prepare   choose node, archive and target; print the line to paste on the
            target's console
  preview   compare the host key with the one read on the console, and show
            exactly what the restore would write and rewrite
  run       carry out what the preview showed - refused if anything changed
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from haproxy_mgmt import node_restore
from haproxy_mgmt.backup_archive import ArchiveError
from haproxy_mgmt.cli import node_restore_helper
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.node_restore import Request, RestoreError

EXIT_USAGE = 64
EXIT_NOT_ROOT = 77

USAGE = """\
Usage:
  haproxy-node-restore prepare -c <cluster> --node <node> --archive <version> --target <address>
                               [--test --test-hostname <name> --test-address <addr/prefix>
                                --test-vip <addr/prefix>]
  haproxy-node-restore preview --run <id> --fingerprint <SHA256:...>
  haproxy-node-restore run     --run <id> --confirm <hostname>
  haproxy-node-restore forget  --run <id>

  prepare   prints a line to paste on the target's console as its administrator.
            It authorizes this run's one-time key for root, from this host only,
            and prints the target's host key fingerprint.
  preview   --fingerprint is the one the pasted line printed on the console.
  run       --confirm is the name the node will have: the archived node's, or
            the test hostname.
  forget    removes the run and its one-time key.

  Add --json to any step for one JSON document instead of text.
"""


def _options(argv: list[str], flags: set[str], values: set[str]) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    index = 0
    while index < len(argv):
        name = argv[index]
        if name in flags and name not in parsed:
            parsed[name] = True
            index += 1
        elif name in values and name not in parsed and index + 1 < len(argv):
            parsed[name] = argv[index + 1]
            index += 2
        else:
            raise ValueError(name)
    return parsed


def _test(options: dict[str, Any]) -> dict[str, str] | None:
    fields = ("--test-hostname", "--test-address", "--test-vip")
    if "--test" not in options:
        if any(field in options for field in fields):
            raise ValueError("test fields without --test")
        return None
    if not all(field in options for field in fields):
        raise ValueError("--test needs --test-hostname, --test-address and --test-vip")
    return {
        "hostname": options["--test-hostname"],
        "address": options["--test-address"],
        "vip": options["--test-vip"],
    }


def _parameters(step: str, options: dict[str, Any], run: str) -> dict[str, Any]:
    """What the socket helper would be sent - held to the same checks it applies."""

    if step == "prepare":
        parameters = {
            "run": run,
            "node": options["--node"],
            "archive": options["--archive"],
            "target": options["--target"],
            "test": _test(options),
        }
        operation = node_restore_helper.PREPARE
    elif step == "preview":
        parameters = {"run": run, "fingerprint": options["--fingerprint"]}
        operation = node_restore_helper.PREVIEW
    elif step == "run":
        parameters = {"run": run, "confirm": options["--confirm"]}
        operation = node_restore_helper.RUN
    else:
        return {"run": run}
    node_restore_helper.validate(operation, parameters)
    return parameters


def _text_preview(summary: dict[str, Any], out: TextIO) -> None:
    plan = summary["plan"]
    target = summary["target"]
    archive = summary["archive"]
    out.write(f"Run {summary['run']}\n\n")
    out.write(
        f"  archive   {archive['node']} {archive['version']} "
        f"({archive['os_release']['ID']} {archive['os_release']['VERSION_ID']})\n"
    )
    out.write(
        f"  target    {target['hostname']} {', '.join(target['interface']['addresses'])} "
        f"{target['interface']['name']} {target['interface']['mac']} "
        f"({target['os_release']['ID']} {target['os_release']['VERSION_ID']})\n"
    )
    out.write(f"  host key  {target['fingerprint']}\n")
    out.write(f"  mode      {plan['mode']}\n")
    out.write(f"  becomes   {plan['hostname']} at {plan['address']}\n")
    out.write(f"  keepalived {plan['keepalived']}\n\n")
    out.write(f"  packages  {' '.join(plan['packages'])}\n")
    out.write(
        f"  files     {len(plan['files'])} written, network last: {', '.join(plan['network'])}\n"
    )
    out.write(
        f"  made equal to the archive (the rest to quarantine): {', '.join(plan['equal_directories'])}\n"
    )
    if archive["extra_paths"]:
        out.write(f"  operator's own paths: {', '.join(archive['extra_paths'])}\n")
    out.write("  accounts:\n")
    for account in plan["accounts"]:
        kind = "service" if account["service"] else "operator"
        # A fixed phrase chosen by a boolean; the hash itself never reaches the preview.
        restored = (
            ", password from the archive if none on the target" if account["has_password"] else ""
        )
        out.write(
            f"    {account['name']} {account['uid']}:{account['gid']} {account['home']} "
            f"({kind}; {', '.join(account['groups'])}{restored})\n"
        )
    if plan["rewrites"]:
        out.write("  rewritten:\n")
        for item in plan["rewrites"]:
            out.write(f"    {item['path']} {item['field']}: {item['old']} -> {item['new']}\n")
    if summary["problems"]:
        out.write("\nSTOPPED - run will refuse:\n")
        for problem in summary["problems"]:
            out.write(f"  - {problem}\n")
    else:
        out.write(
            f"\nNext: haproxy-node-restore run --run {summary['run']} --confirm {plan['hostname']}\n"
        )


def _text_result(result: dict[str, Any], out: TextIO) -> None:
    out.write(f"\n=== restore {result['run']}: {result['outcome']} ===\n")
    if result["outcome"] == "done":
        out.write(
            f"  {result['hostname']} answers at {result['address']}; the one-time key is gone.\n"
        )
    else:
        out.write(f"  stage: {result.get('stage')}\n  error: {result.get('error')}\n")
        out.write(f"  rolled back: {'yes' if result.get('rolled_back') else 'no'}\n")
    for session in result.get("sessions", {}).values():
        for warning in session.get("warnings", []):
            out.write(f"  warning: {warning}\n")


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    run_root: Path = node_restore.RUN_ROOT,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_root: bool = True,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    if not argv or argv[0] not in {"prepare", "preview", "run", "forget"}:
        errors.write(USAGE)
        return EXIT_USAGE
    step, rest = argv[0], argv[1:]
    try:
        if step == "prepare":
            options = _options(
                rest,
                {"--test", "--json"},
                {
                    "-c",
                    "--node",
                    "--archive",
                    "--target",
                    "--test-hostname",
                    "--test-address",
                    "--test-vip",
                },
            )
            if not all(name in options for name in ("-c", "--node", "--archive", "--target")):
                raise ValueError("missing")
        else:
            options = _options(rest, {"--json"}, {"--run", "--fingerprint", "--confirm"})
            needed = {
                "preview": ("--run", "--fingerprint"),
                "run": ("--run", "--confirm"),
                "forget": ("--run",),
            }
            if not all(name in options for name in needed[step]):
                raise ValueError("missing")
        run_id = node_restore.new_run_id() if step == "prepare" else options["--run"]
        parameters = _parameters(step, options, run_id)
    except node_restore_helper.ParameterProblem as problem:
        errors.write(f"ERROR: {problem}\n\n{USAGE}")
        return EXIT_USAGE
    except ValueError:
        errors.write(USAGE)
        return EXIT_USAGE

    if require_root and os.geteuid() != 0:
        errors.write("ERROR: haproxy-node-restore must run as root\n")
        return EXIT_NOT_ROOT

    as_json = "--json" in options
    try:
        if step == "forget":
            node_restore.forget(run_root, options["--run"])
            out.write(f"run {options['--run']} removed\n")
            return 0
        policy = load_policy(policy_path)
        runtime = load_runtime_config(policy)
        if policy.backup_root is None:
            raise RestoreError("the runtime policy declares no backup_root")
        if step == "prepare":
            cluster = runtime.cluster(options["-c"])
            profile = node_restore_helper.test_profile(parameters["test"])
            request = Request(
                run=run_id,
                cluster=options["-c"],
                node=options["--node"],
                archive=options["--archive"],
                target=options["--target"],
                mode="test" if profile is not None else "new_vm",
                profile=profile,
            )
            node_restore.archive_path(
                policy.backup_root, node_restore.node_of(cluster, request.node), request.archive
            )
            prepared = node_restore.prepare(run_root, request)
            if as_json:
                out.write(json.dumps(prepared) + "\n")
            else:
                out.write(
                    f"Run {prepared['run']}\n\nOn {request.target}'s console, as its administrator:\n\n"
                    f"{prepared['paste']}\n\n"
                    f"Then: haproxy-node-restore preview --run {prepared['run']} "
                    "--fingerprint <the SHA256:... it printed>\n"
                )
            return 0
        directory = node_restore.run_directory(run_root, options["--run"])
        request = Request.from_dict(node_restore.read_json(directory / "request.json"))
        cluster = runtime.cluster(request.cluster)
        if step == "preview":
            summary = node_restore.preview(
                run_root,
                options["--run"],
                options["--fingerprint"],
                cluster,
                policy.backup_root,
                progress=errors,
            )
            if as_json:
                out.write(json.dumps(summary) + "\n")
            else:
                _text_preview(summary, out)
            return 1 if summary["problems"] else 0
        result = node_restore.run(
            run_root,
            options["--run"],
            options["--confirm"],
            cluster,
            policy.backup_root,
            progress=errors,
        )
        if as_json:
            out.write(json.dumps(result) + "\n")
        else:
            _text_result(result, out)
        return 0 if result["outcome"] == "done" else 1
    except ConfigError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code
    except (RestoreError, ArchiveError) as exc:
        errors.write(f"ERROR: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
