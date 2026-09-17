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

from haproxy_mgmt import dns_profiles, ndes_renew
from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cert_issue import CERTBOT_TIMEOUT, certbot_binary
from haproxy_mgmt.cli import cert_scep
from haproxy_mgmt.cli.cert_publish import default_deployer
from haproxy_mgmt.config import (
    CERTIFICATE_ID,
    DEFAULT_POLICY_PATH,
    ConfigError,
    PathPolicy,
    RuntimeConfig,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.envelope import new_request_id
from haproxy_mgmt.ndes_state import request_is_pending

RENEWAL_DIRECTORY = Path("/etc/letsencrypt/renewal")
FIXED_ENVIRONMENT = {
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}


@dataclass(frozen=True, slots=True)
class RenewalInvocation:
    lineage: str
    arguments: tuple[str, ...]
    environment: Mapping[str, str]
    redactions: tuple[str, ...] = ()


def invocations(
    policy: PathPolicy,
    runtime: RuntimeConfig,
    *,
    renewal_directory: Path = RENEWAL_DIRECTORY,
    binary: str | None = None,
    dry_run: bool = False,
    run_deploy_hooks: bool = False,
    require_secure: bool = True,
) -> tuple[RenewalInvocation, ...]:
    """Build one bounded renewal command for every on-disk lineage."""

    try:
        if not renewal_directory.is_dir():
            raise ConfigError(
                f"certbot renewal directory does not exist: {renewal_directory}", exit_code=78
            )
        lineages = tuple(sorted(path.stem for path in renewal_directory.glob("*.conf")))
    except OSError as exc:
        raise ConfigError(
            f"cannot list certbot renewal configurations: {exc}", exit_code=78
        ) from exc

    if runtime.registry is None:
        raise ConfigError("no certificate registry is configured", exit_code=78)
    profiles_by_lineage = {
        certificate.source.lineage: certificate.source.dns_profile
        for certificate in runtime.registry.certificates.values()
        if certificate.source.kind == "acme"
    }
    commands: list[RenewalInvocation] = []
    for lineage in lineages:
        arguments = [
            binary or certbot_binary(policy),
            "-q",
            "renew",
            "--no-random-sleep-on-renew",
            "--cert-name",
            lineage,
        ]
        if dry_run:
            arguments.append("--dry-run")
        if run_deploy_hooks:
            arguments.append("--run-deploy-hooks")
        environment = dict(FIXED_ENVIRONMENT)
        redactions: tuple[str, ...] = ()
        profile_id = profiles_by_lineage.get(lineage)
        if profile_id is not None:
            profile_policy = policy.acme.dns_profiles if policy.acme is not None else None
            if profile_policy is None:
                raise ConfigError(
                    f"lineage {lineage!r} names DNS profile {profile_id!r}, but "
                    "acme.dns_profiles is not configured",
                    exit_code=78,
                )
            try:
                materialized = dns_profiles.read_materialized(
                    profile_policy, profile_id, require_secure=require_secure
                )
                redactions = dns_profiles.materialized_secret_values(materialized)
            except dns_profiles.ProfileError as exc:
                raise ConfigError(str(exc), exit_code=78) from exc
            if materialized.provider.credentials_env is not None:
                environment[materialized.provider.credentials_env] = materialized.credentials_path
        commands.append(RenewalInvocation(lineage, tuple(arguments), environment, redactions))
    return tuple(commands)


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
                resume=request_is_pending(policy.ndes.state_root, candidate.certificate_id),
                request_id=new_request_id(),
                policy_path=policy_path,
                deployer=default_deployer(errors),
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
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("must run as root")
    if args.certbot is not None and not Path(args.certbot).is_absolute():
        parser.error("--certbot must be an absolute path")
    if any(not CERTIFICATE_ID.fullmatch(item) for item in args.ndes_now):
        parser.error("--ndes-now takes a certificate ID")
    try:
        policy = load_policy(args.policy)
        runtime = load_runtime_config(policy)
        commands = (
            ()
            if args.ndes_now
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

    failed = False
    for invocation in commands:
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv plus validated lineage/path
                invocation.arguments,
                capture_output=True,
                text=True,
                env=dict(invocation.environment),
                timeout=CERTBOT_TIMEOUT,
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
    # After certbot, not instead of it: a failure in one pass does not spare
    # the other, and the exit code says whether either had one.
    #
    ndes_failed = renew_ndes(
        policy, runtime, only=tuple(args.ndes_now), dry_run=args.dry_run, policy_path=args.policy
    )
    return 1 if failed or ndes_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
