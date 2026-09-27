from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from haproxy_mgmt.config import ConfigError, _mapping, _only_keys, _secure_yaml

ACCOUNT_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")
ACCOUNT_PREFIX = re.compile(r"^[a-z_][a-z0-9_-]{1,14}[-_]$")
ROLES = ("web", "worker", "poller")
RESERVED_ACCOUNTS = frozenset({"root"})


@dataclass(frozen=True, slots=True)
class IdentityPolicy:
    account_prefix: str
    config_group: str
    web: str
    worker: str
    poller: str
    collector: str | None = None
    #
    # The OIDC helper's account (Fas 13 part 4, O3). Optional like the
    # collector, and like it in no group: it reads its own key directory and
    # nothing of the configuration.
    #
    oidc: str | None = None

    def account(self, role: str) -> str:
        if role not in ROLES:
            raise ConfigError(f"unknown application role: {role}", exit_code=64)
        return {"web": self.web, "worker": self.worker, "poller": self.poller}[role]


def _account_name(value: Any, location: str) -> str:
    if not isinstance(value, str) or not ACCOUNT_NAME.fullmatch(value):
        raise ConfigError(f"{location} must be a valid system account name")
    if value in RESERVED_ACCOUNTS:
        raise ConfigError(f"{location} may not use a reserved account")
    return value


def load_identity_policy(path: Path, *, require_secure: bool = True) -> IdentityPolicy:
    data = _secure_yaml(path, require_secure=require_secure)
    _only_keys(
        data,
        {"schema_version", "account_prefix", "config_group", "roles"},
        "identity policy",
    )
    schema_version = data.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise ConfigError("identity policy schema_version must be 1")

    account_prefix = data.get("account_prefix")
    if not isinstance(account_prefix, str) or not ACCOUNT_PREFIX.fullmatch(account_prefix):
        raise ConfigError("identity policy.account_prefix is invalid")
    config_group = _account_name(data.get("config_group"), "identity policy.config_group")
    roles = _mapping(data.get("roles"), "identity policy.roles")
    _only_keys(roles, {*ROLES, "collector", "oidc"}, "identity policy.roles")
    missing = sorted(set(ROLES) - roles.keys())
    if missing:
        raise ConfigError(f"identity policy.roles is missing role(s): {', '.join(missing)}")

    accounts = {role: _account_name(roles[role], f"identity policy.roles.{role}") for role in ROLES}
    collector = (
        _account_name(roles["collector"], "identity policy.roles.collector")
        if "collector" in roles
        else None
    )
    oidc = _account_name(roles["oidc"], "identity policy.roles.oidc") if "oidc" in roles else None
    optional = tuple(name for name in (collector, oidc) if name is not None)
    all_names = [config_group, *accounts.values(), *optional]
    if any(not name.startswith(account_prefix) for name in all_names):
        raise ConfigError("identity policy group and role accounts must use account_prefix")
    if len(set(all_names)) != len(all_names):
        raise ConfigError("identity policy group and role accounts must all be distinct")

    return IdentityPolicy(
        account_prefix=account_prefix,
        config_group=config_group,
        collector=collector,
        oidc=oidc,
        **accounts,
    )


def render_sysusers(policy: IdentityPolicy) -> str:
    """Render app identities; human operator membership remains a separate admin action."""

    # Type "u", not "u!": both set an invalid password, but "u!" additionally
    # marks the account expired, which makes PAM's account stage reject it. The
    # app identities must pass that stage to reach their exact roothelpers
    # through sudo. Remote login is denied explicitly in sshd configuration
    # instead of as a side effect of an expiry flag; the accounts also keep an
    # invalid password and a nologin shell.
    lines = [
        "# Generated from the protected HAProxy Manager identity policy.",
        f"g {policy.config_group} -",
        f'u {policy.web} - "HAProxy Manager web service" - /usr/sbin/nologin',
        f'u {policy.worker} - "HAProxy Manager worker service" - /usr/sbin/nologin',
        f'u {policy.poller} - "HAProxy Manager poller service" - /usr/sbin/nologin',
    ]
    if policy.collector is not None:
        lines.append(
            f'u {policy.collector} - "HAProxy Manager traffic log collector" - /usr/sbin/nologin'
        )
    if policy.oidc is not None:
        lines.append(f'u {policy.oidc} - "HAProxy Manager OIDC helper" - /usr/sbin/nologin')
    lines.extend((f"m {policy.worker} {policy.config_group}", ""))
    return "\n".join(lines)
