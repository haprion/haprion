"""`haprion-cert-publish` - publish registered certificates to their targets.

Runs as root, directly: its callers are certbot's deploy hook, which is root,
and an operator at a root shell. It takes no request on stdin and offers no
way to name a file, a directory or an account - every one of those comes from
the registry and the runtime policy, which is what makes "the interface can
choose targets but cannot invent them" a property of this command rather than
of its callers.

With `--deploy`, every cluster that received a new version is rolled out
afterwards with `haprion-cert-deploy`, the same command an operator runs by
hand, found beside this one in the installed release - and so is every cluster
an earlier run published to without a rollout that answered 0, so running the
command again finishes what a failed rollout left (`cert_pending`). That is what the certbot
hook asks for; an operator checking what a run *would* change leaves it off.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import TextIO

from haprion import exit_codes, ui_interface
from haprion.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haprion.cert_publish import (
    DEFAULT_LOCK_PATH,
    Deployer,
    Installer,
    PublishError,
    Report,
    publish,
)
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.envelope import Message, envelope, failure, new_request_id
from haprion.helper_protocol import config_error_code, write_document

OPERATION = "cert_publish"
CERT_DEPLOY = "haprion-cert-deploy"

USAGE = (
    "Usage:\n"
    "  haprion-cert-publish [--certificate <id>]... [--deploy] [--json]\n"
    "\n"
    "Publishes every certificate in the registry to every cluster and receiver\n"
    "it names, writing only what changed. Runs as root.\n"
    "\n"
    "Options:\n"
    "  --certificate <id>\n"
    "        Publish this registered certificate only. May be repeated.\n"
    "  --deploy\n"
    "        Roll out every cluster that received a new version, and every\n"
    "        cluster an earlier run published to without a successful rollout,\n"
    "        with haprion-cert-deploy. This is what the certbot deploy hook passes.\n"
    "  --json\n"
    "        Print the result envelope on stdout instead of a summary.\n"
)


def _parse(argv: list[str], writer: TextIO) -> tuple[list[str] | None, bool, bool]:
    only: list[str] = []
    deploy = False
    json_mode = False
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--certificate":
            if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
                raise SystemExit(_usage(writer))
            only.append(argv[index + 1])
            index += 2
        elif argument == "--deploy":
            deploy = True
            index += 1
        elif argument == "--json":
            json_mode = True
            index += 1
        else:
            raise SystemExit(_usage(writer))
    return (only or None), deploy, json_mode


def _usage(writer: TextIO) -> int:
    writer.write(USAGE)
    return exit_codes.USAGE


def default_deployer(errors: TextIO) -> Deployer:
    """`haprion-cert-deploy -c <cluster>`, from the same bin directory as this command.

    Beside this executable rather than on PATH: the hook runs from certbot's
    environment, whose PATH is not the operator's, and "the release this
    command came from" is the only release it makes sense to deploy with.
    """

    command = Path(sys.argv[0]).resolve().parent / CERT_DEPLOY

    def deploy(cluster_id: str) -> int:
        errors.write(f"=== deploying {cluster_id} ===\n")
        errors.flush()
        completed = subprocess.run(  # noqa: S603 - fixed path, cluster ID from the registry
            [str(command), "-c", cluster_id],
            stdout=errors,
            stderr=errors,
            check=False,
        )
        return completed.returncode

    return deploy


def _summary(report: Report, writer: TextIO) -> None:
    for entry in report.certificates:
        line = f"{entry.certificate_id}: {entry.status}"
        if entry.targets:
            line += (
                " ("
                + ", ".join(
                    f"{target.kind} {target.name}" + (" *" if target.changed else "")
                    for target in entry.targets
                )
                + ")"
            )
        if entry.error:
            line += f" - [{entry.error[0]}] {entry.error[1]}"
        writer.write(line + "\n")
    if report.changed_clusters:
        writer.write("changed clusters: " + ", ".join(report.changed_clusters) + "\n")
    for deployment in report.deployments:
        state = "ok" if deployment.exit_code == 0 else f"exit {deployment.exit_code}"
        writer.write(f"deploy {deployment.cluster}: {state}\n")
    for code, message in report.warnings:
        writer.write(f"WARNING: [{code}] {message}\n")


def publish_exit_code(exc: PublishError) -> int:
    """The publisher's refusal, in the contract's exit codes.

    Three cases and no default that guesses: a lock is the one refusal the
    contract calls `blocked` rather than `failed`, a bad request is the caller's,
    and everything else is the installation's. Written out so a new refusal code
    in the publisher lands as a decision somebody makes here.
    """

    if exc.code == "operation_locked":
        return exit_codes.BLOCKED
    return exit_codes.USAGE if exc.code == "bad_input" else exit_codes.CONFIG


def result_envelope(report: Report, *, request_id: str) -> tuple[dict[str, object], int]:
    """One report, turned into the one envelope and exit code it means.

    Shared by this command, its helper and the target helper, which
    publishes the certificate it just retargeted and has to answer in exactly
    these terms. The command kept a copy of its own until 2026-10-23.
    """

    warnings = tuple(
        Message(code=entry.error[0], message=entry.error[1], node=entry.certificate_id)
        for entry in report.skipped
        if entry.error
    ) + tuple(Message(code=code, message=message) for code, message in report.warnings)
    failed = [entry.certificate_id for entry in report.failed]
    not_deployed = [item.cluster for item in report.deployments if item.exit_code != 0]
    if not failed and not not_deployed:
        return (
            envelope(
                operation=OPERATION,
                outcome="partial" if warnings else "done",
                cluster=None,
                request_id=request_id,
                result=report.as_dict(),
                warnings=warnings,
            ),
            exit_codes.PARTIAL if warnings else exit_codes.OK,
        )
    parts = []
    if failed:
        parts.append("not published: " + ", ".join(failed))
    if not_deployed:
        parts.append("not deployed: " + ", ".join(not_deployed))
    return (
        envelope(
            operation=OPERATION,
            outcome="failed",
            cluster=None,
            request_id=request_id,
            result=report.as_dict(),
            warnings=warnings,
            error=Message(code="publish_failed", message="; ".join(parts)),
        ),
        exit_codes.FAILED,
    )


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
    deployer: Deployer | None = None,
    installer: Installer | None = None,
    now: datetime | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    request_id = new_request_id()

    try:
        only, deploy, json_mode = _parse(argv, writer)
    except SystemExit as exc:
        return int(exc.code or 0)

    def refuse(code: str, message: str, exit_code: int) -> int:
        errors.write(f"ERROR: [{code}] {message}\n")
        if json_mode:
            document = failure(
                operation=OPERATION,
                cluster=None,
                request_id=request_id,
                code=code,
                message=message,
                exit_code=exit_code,
            )
            write_document(writer, document, exit_code)
        return exit_code

    if require_root and os.geteuid() != 0:
        return refuse("not_root", "haprion-cert-publish must run as root", exit_codes.NOT_ROOT)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(
            config_error_code(exc.exit_code),
            str(exc),
            exc.exit_code,
        )

    if deploy and deployer is None:
        deployer = default_deployer(errors)

    try:
        report = publish(
            runtime,
            policy,
            only=only,
            live=live,
            store=store,
            lock_path=lock_path,
            deployer=deployer if deploy else None,
            #
            # Always, not only with --deploy: this command runs as root outside
            # any sandbox, and writing nginx's pair is this target's publish
            # step - the one that makes the file it writes the file served.
            #
            installer=installer or ui_interface.install,
            now=now,
        )
    except PublishError as exc:
        return refuse(exc.code, str(exc), publish_exit_code(exc))

    document, exit_code = result_envelope(report, request_id=request_id)
    if json_mode:
        return write_document(writer, document, exit_code)
    _summary(report, writer)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
