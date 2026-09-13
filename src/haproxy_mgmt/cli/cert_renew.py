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
from pathlib import Path

from haproxy_mgmt import dns_profiles
from haproxy_mgmt.cert_issue import CERTBOT_TIMEOUT, certbot_binary
from haproxy_mgmt.config import (
    DEFAULT_POLICY_PATH,
    ConfigError,
    PathPolicy,
    RuntimeConfig,
    load_policy,
    load_runtime_config,
)

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Renew Certbot lineages with DNS profiles")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--certbot", help="certbot binary used by the upgrade gate")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--run-deploy-hooks", action="store_true")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("must run as root")
    if args.certbot is not None and not Path(args.certbot).is_absolute():
        parser.error("--certbot must be an absolute path")
    try:
        policy = load_policy(args.policy)
        runtime = load_runtime_config(policy)
        commands = invocations(
            policy,
            runtime,
            binary=args.certbot,
            dry_run=args.dry_run,
            run_deploy_hooks=args.run_deploy_hooks,
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
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
