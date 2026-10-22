"""Renew every Certbot lineage with the DNS profile environment it needs.

Most plugins persist a credentials-file flag in ``renewal/*.conf``. Route53
has no such flag: boto3 only discovers its file through an environment
variable, which Certbot cannot persist.  The timer therefore invokes each
lineage separately and reconstructs only that fixed environment from the
registry's ``source.dns_profile`` binding.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from haprion import cert_issue, ndes_renew, ui_interface
from haprion.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haprion.cert_issue import (
    CERTBOT_TIMEOUT,
    RENEWAL_DIRECTORY,
    IssueError,
    renewal_invocation,
)
from haprion.cli import cert_scep
from haprion.cli.cert_publish import default_deployer
from haprion.config import (
    CERTIFICATE_ID,
    DEFAULT_POLICY_PATH,
    ConfigError,
    PathPolicy,
    RuntimeConfig,
    load_policy,
    load_runtime_config,
)
from haprion.envelope import new_request_id
from haprion.ndes_state import request_is_pending


@dataclass(frozen=True, slots=True)
class RenewalInvocation:
    lineage: str
    arguments: tuple[str, ...]
    environment: Mapping[str, str]
    redactions: tuple[str, ...] = ()
    timeout: int = CERTBOT_TIMEOUT


@dataclass(frozen=True, slots=True)
class Renewals:
    commands: tuple[RenewalInvocation, ...]
    #
    # (lineage, why) for each lineage whose command could not be built.
    #
    problems: tuple[tuple[str, str], ...]


def invocations(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    renewal_directory: Path | None = None,
    binary: str | None = None,
    dry_run: bool = False,
    run_deploy_hooks: bool = False,
    require_secure: bool = True,
) -> Renewals:
    """Build one bounded renewal command for every on-disk lineage.

    Certbot creates the renewal directory with its first certificate; until
    then there is nothing to renew, as for certbot itself and for the DNS
    profile helper's reading of the same directory (26-10-14).

    A lineage whose command cannot be built - its DNS profile missing or
    unreadable - is a problem of its own and the others are still renewed:
    one stopped the whole pass, NDES included (logic review 26-10-22, L3).
    What every lineage needs, the registry, still stops it.
    """

    renewal_directory = renewal_directory or RENEWAL_DIRECTORY
    try:
        if not renewal_directory.exists():
            return Renewals((), ())
        if not renewal_directory.is_dir():
            raise ConfigError(
                f"certbot renewal directory is not a directory: {renewal_directory}", exit_code=78
            )
        lineages = tuple(sorted(path.stem for path in renewal_directory.glob("*.conf")))
    except OSError as exc:
        raise ConfigError(
            f"cannot list certbot renewal configurations: {exc}", exit_code=78
        ) from exc

    if lineages and runtime.registry is None:
        raise ConfigError("no certificate registry is configured", exit_code=78)
    commands: list[RenewalInvocation] = []
    problems: list[tuple[str, str]] = []
    for lineage in lineages:
        try:
            built = renewal_invocation(
                lineage,
                policy,
                runtime,
                binary=binary,
                dry_run=dry_run,
                run_deploy_hooks=run_deploy_hooks,
                require_secure=require_secure,
            )
        except IssueError as exc:
            problems.append((lineage, str(exc)))
            continue
        commands.append(
            RenewalInvocation(
                lineage, built.arguments, built.environment, built.redactions, built.timeout
            )
        )
    return Renewals(tuple(commands), tuple(problems))


def _scrub(text: str, values: Sequence[str]) -> str:
    for value in sorted(values, key=len, reverse=True):
        text = text.replace(value, "[redacted]")
    return text


def renew_ndes(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    only: Sequence[str] = (),
    dry_run: bool = False,
    now: datetime | None = None,
    enroll: ndes_renew.Enroller | None = None,
    errors: TextIO = sys.stderr,
    policy_path: Path = DEFAULT_POLICY_PATH,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
) -> bool:
    """The NDES pass: renew what is due, or what `only` names. True when anything failed.

    Runs after certbot's pass and independently of it, from the same daily
    timer. Certbot's lineages are certbot's; these are the manager's own
    requests, made again through `cert_scep.enroll` - one code path.
    """

    if policy.ndes is None:
        if only:
            print("ERROR: --ndes-now needs an ndes policy", file=errors)
            return True
        return False
    moment = now or datetime.now(UTC)
    due, problems = ndes_renew.candidates(
        runtime,
        policy,
        now=moment,
        threshold_days=policy.ndes.renew_days,
        only=only,
        live=live,
        store=store,
    )
    for problem in problems:
        if problem.certificate_id in only:
            print(f"ERROR: {problem.certificate_id}: {problem.message}", file=errors)
        else:
            print(f"ndes: {problem.certificate_id}: skipped, {problem.message}", file=errors)
    for candidate in due:
        print(
            f"ndes: {candidate.certificate_id} expires in {candidate.days_left} days; "
            + ("would renew" if dry_run else "renewing"),
            file=errors,
        )
    if dry_run:
        return any(p.certificate_id in only for p in problems)

    def enroll_again(candidate: ndes_renew.Candidate) -> tuple[dict[str, Any], int]:
        #
        # A request the CA is still holding from an earlier pass is resumed,
        # not replaced: asking anew was refused as `already_exists` and the
        # row went from "Renewal pending" to "Renewal failed" the next day
        # (review 2026-09-17, finding 2).
        #
        assert policy.ndes is not None  # noqa: S101 - checked above
        try:
            return cert_scep.enroll(
                certificate_id=candidate.certificate_id,
                profile_id=candidate.profile_id,
                domains=candidate.domains,
                clusters=candidate.clusters,
                receivers=candidate.receivers,
                interface=candidate.interface,
                resume=request_is_pending(policy.ndes.state_root, candidate.certificate_id),
                request_id=new_request_id(),
                policy_path=policy_path,
                deployer=default_deployer(errors),
                #
                # The timer is root outside any sandbox, so the interface
                # certificate (B188) is installed directly, as the certbot
                # hook's `haprion-cert-publish` does.
                #
                installer=ui_interface.install,
                live=live,
                store=store,
            )
        except cert_scep.ScepRefusal as exc:
            return {
                "outcome": "failed",
                "error": {"code": exc.code, "message": str(exc)},
            }, exc.exit_code

    outcomes = ndes_renew.renew(
        due, state_root=policy.ndes.state_root, enroll=enroll or enroll_again, now=moment
    )
    failed = any(p.certificate_id in only for p in problems)
    for outcome in outcomes:
        print(
            f"ndes: {outcome.certificate_id}: {outcome.outcome} {outcome.message}".rstrip(),
            file=errors,
        )
        failed = failed or outcome.outcome == "failed"
    return failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Renew Certbot lineages with DNS profiles")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--certbot", help="certbot binary used by the upgrade gate")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--run-deploy-hooks", action="store_true")
    parser.add_argument(
        "--ndes-now",
        action="append",
        default=[],
        metavar="ID",
        help="renew this NDES certificate now, whatever its expiry; certbot's pass is skipped",
    )
    parser.add_argument(
        "--acme-now",
        action="append",
        default=[],
        metavar="ID",
        help="renew this certbot certificate now, whatever its expiry (--force-renewal); "
        "the ordinary pass is skipped",
    )
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("must run as root")
    if any(not CERTIFICATE_ID.fullmatch(item) for item in args.acme_now):
        parser.error("--acme-now takes a certificate ID")
    if args.certbot is not None and not Path(args.certbot).is_absolute():
        parser.error("--certbot must be an absolute path")
    if any(not CERTIFICATE_ID.fullmatch(item) for item in args.ndes_now):
        parser.error("--ndes-now takes a certificate ID")
    try:
        policy = load_policy(args.policy)
        runtime = load_runtime_config(policy)
        renewals = (
            Renewals((), ())
            if args.ndes_now or args.acme_now
            else invocations(
                policy,
                runtime,
                binary=args.certbot,
                dry_run=args.dry_run,
                run_deploy_hooks=args.run_deploy_hooks,
            )
        )
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return exc.exit_code

    failed = bool(renewals.problems)
    for lineage, problem in renewals.problems:
        print(f"ERROR: renewal of {lineage!r} could not be prepared: {problem}", file=sys.stderr)
    for invocation in renewals.commands:
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv plus validated lineage/path
                invocation.arguments,
                capture_output=True,
                text=True,
                env=dict(invocation.environment),
                timeout=invocation.timeout,
                check=False,
            )
            output = (completed.stdout or "") + (completed.stderr or "")
            if output:
                print(_scrub(output.rstrip(), invocation.redactions), file=sys.stderr)
            failed = failed or completed.returncode != 0
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"ERROR: renewal of {invocation.lineage!r} could not run: {exc}", file=sys.stderr)
            failed = True
    #
    # The forced renewal of one lineage (C9c): the same command as above with
    # `--force-renewal`, through the engine the interface's button uses.
    #
    for certificate_id in args.acme_now:
        try:
            result = cert_issue.renew(
                certificate_id=certificate_id,
                policy=policy,
                runtime=runtime,
                deployer=default_deployer(sys.stderr),
                installer=ui_interface.install,
            )
        except cert_issue.IssueError as exc:
            print(f"ERROR: [{exc.code}] {certificate_id}: {exc}", file=sys.stderr)
            diagnostics = exc.details.get("diagnostics") if exc.details else None
            if isinstance(diagnostics, str) and diagnostics.strip():
                print(diagnostics.rstrip(), file=sys.stderr)
            failed = True
        else:
            print(
                f"acme: {certificate_id}: renewed in {result.certbot_seconds:.0f}s; "
                f"certificates {len(result.publish.certificates)}, "
                f"failed {len(result.publish.failed)}",
                file=sys.stderr,
            )
            failed = failed or bool(result.publish.failed)
    #
    # After certbot, not instead of it: a failure in one pass does not spare
    # the other, and the exit code says whether either had one.
    #
    ndes_failed = renew_ndes(
        policy, runtime, only=tuple(args.ndes_now), dry_run=args.dry_run, policy_path=args.policy
    )
    return 1 if failed or ndes_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
