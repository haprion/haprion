"""What the interface is told, and what it refuses to be told.

One file, read once at startup, held to the same rule as the engine's runtime
policy: root-owned, a regular file, not group- or world-writable, and small. The
services run as unprivileged accounts that can read it and cannot change it,
which is what makes the values below something the deployment decided rather
than something a compromised process can rewrite.

There is no database password here, and no place to put one. Connections use the
local socket and peer authentication, so the identity of the connecting process
is established by the kernel rather than by a secret the process holds.
"""

from __future__ import annotations

import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from haprion import accounts, exit_codes

#
# A cluster ID is the engine's (`haprion.config.CLUSTER_ID`), and the database's
# CHECK holds the same pattern (0084). The poller passes these to a privileged
# helper, so a value that has not been checked here is a value the helper has
# to refuse - and it does, but the refusal reads as a broken poller rather than
# as a typo in a file.
#
from haprion.config import CLUSTER_ID

from haprion_ui import labels

DEFAULT_CONFIG_PATH = Path(accounts.UI_CONFIG)
DEFAULT_LOG_DIRECTORY = f"{accounts.UI_DATA}/logs/mirror"
MAX_CONFIG_BYTES = 1024 * 1024

ALLOWED_KEYS = frozenset(
    {
        "database",
        "listen",
        "management_writes",
        "session",
        "throttle",
        "clusters",
        "poller",
        "demo_fixture",
        "traffic_logs",
        "dns_profiles",
        "oidc",
    }
)
ALLOWED_DATABASE_KEYS = frozenset({"name", "socket_directory"})
ALLOWED_LISTEN_KEYS = frozenset({"host", "port"})
ALLOWED_SESSION_KEYS = frozenset(
    {"inactivity_minutes", "absolute_hours", "cookie_secure", "oidc_absolute_hours"}
)
ALLOWED_THROTTLE_KEYS = frozenset({"max_failures", "window_minutes"})
ALLOWED_POLLER_KEYS = frozenset({"interval_seconds"})
ALLOWED_TRAFFIC_LOG_KEYS = frozenset({"enabled", "directory", "max_lines", "retention_days"})
ALLOWED_DNS_PROFILE_KEYS = frozenset({"public_key"})
ALLOWED_OIDC_KEYS = frozenset({"public_key"})


class ConfigError(ValueError):
    """The configuration cannot be used. Exit 78, as the contract says for it."""

    def __init__(self, message: str, *, exit_code: int = exit_codes.CONFIG):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class Database:
    name: str
    socket_directory: str

    @property
    def connection_string(self) -> str:
        """libpq keyword form, with no user and no password.

        The user is deliberately absent: libpq then asks for a role named after
        the operating-system user, which is exactly right here because each
        service account is named after its role. Naming it as well would be a
        second place for that fact to be wrong.
        """

        return f"dbname={self.name} host={self.socket_directory}"


@dataclass(frozen=True, slots=True)
class Session:
    """How long a login lasts, and on what terms.

    Two limits, not one, because they answer different questions. The inactivity
    timeout is the phase gate's roughly ten hours and is enforced against
    `last_seen_at`; the absolute lifetime caps a session that is kept warm
    forever by a browser tab nobody is watching.

    The absolute limit is `expires_at`, which the web role holds no `update` on -
    so a session can be shortened by revoking it but never extended past what it
    was issued for.
    """

    inactivity_minutes: int
    absolute_hours: int
    #
    # The cookie is Secure in any installation that a person logs into, which is
    # why nginx and a certificate are part of phase 4 rather than a later
    # nicety: a Secure cookie is never sent over plain HTTP, so turning TLS off
    # does not weaken the login, it removes it.
    #
    # Settable only so a developer instance on loopback can be used at all. It
    # is reported at startup when it is off, because "logged in over plain HTTP"
    # must never be a quiet state.
    #
    cookie_secure: bool
    #
    # A session made through the provider carries the role its groups gave at
    # sign-in, and the provider is not asked again until the next one. This
    # caps how long a group taken away at the provider still counts here
    # (B203); the provider's own token lifetime is not used, as other OIDC
    # applications do not use it either.
    #
    oidc_absolute_hours: int = 10


@dataclass(frozen=True, slots=True)
class Throttle:
    """What a wrong password costs.

    Counted per normalised username and client IP together, as the phase gate
    says. Per username alone would let one attacker lock every real user out;
    per IP alone would let one address work through a list of names as long as
    it changed the name each time.
    """

    max_failures: int
    window_minutes: int


@dataclass(frozen=True, slots=True)
class Poller:
    """How often the interface asks the clusters how they are.

    Not a tuning knob so much as a statement about staleness: nothing renders a
    reading without saying how old it is, and this decides how old that gets.
    """

    interval_seconds: int


@dataclass(frozen=True, slots=True)
class TrafficLogs:
    """Where the collector's mirror is, and how much of it may be rendered.

    Reading only. This process never asks a node anything: it reads files the
    collector already placed here, so a node that is slow or hostile cannot make
    a page slow or make a request hang.
    """

    enabled: bool
    directory: Path
    max_lines: int
    retention_days: int = 7


@dataclass(frozen=True, slots=True)
class Config:
    database: Database
    #
    # Phase 4 installs the platform without management writes. The flag is here
    # rather than in a release so it can be turned off without deploying: the
    # documented rollback for the write path is to switch it off and be back in
    # a read-only interface, which is not a rollback that should require a build.
    #
    management_writes: bool
    # A synthetic display source for review and tests. It is never a poller
    # input, and can only coexist with the read-only, no-real-cluster configuration.
    demo_fixture: bool
    session: Session
    throttle: Throttle
    #
    # Named here rather than discovered from the engine's configuration, which
    # the application identities cannot read - that tree is private, and the
    # poller reaching into it directly is exactly what the privilege split
    # exists to prevent. The deployment states which clusters exist; the
    # privileged helper still decides whether each one is real.
    #
    clusters: tuple[str, ...]
    poller: Poller
    #
    # Off unless a deployment says otherwise, and defaulted to the mirror the
    # platform step creates (B123).
    #
    traffic_logs: TrafficLogs = TrafficLogs(
        enabled=False,
        directory=Path(DEFAULT_LOG_DIRECTORY),
        max_lines=500,
        retention_days=7,
    )
    #
    # The public half of the pair platform step 15 made (B146): what DNS
    # provider credentials entered here are sealed against before they are
    # stored. The private half is root's, among the secrets, and this process
    # never learns it. Absent, the interface offers no provider profiles.
    #
    dns_profiles_public_key: Path | None = None
    #
    # The public half of the pair platform step 17 made: what the OIDC client
    # secret is sealed against. The helper holds the private half. Absent, the
    # OIDC configuration page says the helper is not installed.
    #
    oidc_public_key: Path | None = None


def _section(data: Any, key: str, allowed: frozenset[str]) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"[{key}] is missing or is not a table")
    unknown = sorted(set(value) - allowed)
    if unknown:
        #
        # Refused rather than ignored, for the same reason the engine refuses
        # them: a key that is silently dropped is a setting somebody believes is
        # in effect. A typo must be an error at startup, not a surprise later.
        #
        raise ConfigError(
            f"[{key}] has unknown {labels.noun(len(unknown), 'key')}: {', '.join(unknown)}"
        )
    return value


def _bounded_int(
    section: dict[str, Any], key: str, location: str, *, low: int, high: int, default: int
) -> int:
    """An integer inside a range, with the range stated rather than implied.

    Bounded in both directions on purpose. A zero inactivity timeout is a
    session that expires before it is used, and a throttle allowing millions of
    failures is a throttle that is off - both are configuration mistakes that
    should be refused at startup rather than discovered by their effects.
    """

    value = section.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ConfigError(f"{location}.{key} must be an integer between {low} and {high}")
    return value


def _boolean(section: dict[str, Any], key: str, location: str, *, default: bool) -> bool:
    value = section.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{location}.{key} must be true or false")
    return value


def _optional_section(data: Any, key: str, allowed: frozenset[str]) -> dict[str, Any]:
    """A section that may be absent, but may not be wrong when present."""

    if key not in data:
        return {}
    return _section(data, key, allowed)


def _string(section: dict[str, Any], key: str, location: str) -> str:
    value = section.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{location}.{key} must be a non-empty string")
    return value


def load(path: Path = DEFAULT_CONFIG_PATH, *, require_secure: bool = True) -> Config:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ConfigError(f"cannot stat configuration file: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ConfigError("configuration file must be a regular non-symlink")
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise ConfigError("configuration file exceeds 1 MiB")
    if require_secure and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022):
        raise ConfigError("configuration file must be root-owned and not group/other-writable")

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read configuration file: {exc}") from exc

    unknown = sorted(set(data) - ALLOWED_KEYS)
    if unknown:
        raise ConfigError(
            f"unknown top-level {labels.noun(len(unknown), 'key')}: {', '.join(unknown)}"
        )

    database = _section(data, "database", ALLOWED_DATABASE_KEYS)
    #
    # Where the web listened, until it took its connections on a socket only
    # nginx may open (review 2026-10-22, 5-8). An installation's file still
    # carries it, and a release before that one needs it to roll back to, so
    # it is read as it always was and used for nothing.
    #
    listen = _optional_section(data, "listen", ALLOWED_LISTEN_KEYS)
    #
    # Optional sections, unlike the two above. Both carry defaults that are the
    # documented policy, so an installation that says nothing about sessions
    # gets the phase gate's numbers rather than none.
    #
    session = _optional_section(data, "session", ALLOWED_SESSION_KEYS)
    throttle = _optional_section(data, "throttle", ALLOWED_THROTTLE_KEYS)
    poller = _optional_section(data, "poller", ALLOWED_POLLER_KEYS)
    traffic_logs = _optional_section(data, "traffic_logs", ALLOWED_TRAFFIC_LOG_KEYS)
    dns_profiles = _optional_section(data, "dns_profiles", ALLOWED_DNS_PROFILE_KEYS)
    oidc = _optional_section(data, "oidc", ALLOWED_OIDC_KEYS)

    clusters = data.get("clusters", [])
    if not isinstance(clusters, list) or not all(isinstance(name, str) for name in clusters):
        raise ConfigError("clusters must be a list of strings")
    for name in clusters:
        if not CLUSTER_ID.fullmatch(name):
            raise ConfigError(f"not a valid cluster id: {name!r}")
    if len(set(clusters)) != len(clusters):
        raise ConfigError("clusters contains a duplicate")

    if listen:
        _string(listen, "host", "listen")
        port = listen.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ConfigError("listen.port must be an integer between 1 and 65535")

    writes = data.get("management_writes", False)
    if not isinstance(writes, bool):
        raise ConfigError("management_writes must be true or false")
    demo_fixture = data.get("demo_fixture", False)
    if not isinstance(demo_fixture, bool):
        raise ConfigError("demo_fixture must be true or false")
    if demo_fixture and writes:
        raise ConfigError("demo_fixture requires management_writes = false")
    if demo_fixture and clusters:
        raise ConfigError("demo_fixture requires clusters = []")

    log_directory_value = traffic_logs.get("directory", DEFAULT_LOG_DIRECTORY)
    if not isinstance(log_directory_value, str) or not log_directory_value:
        raise ConfigError("traffic_logs.directory must be a non-empty string")
    log_directory = Path(log_directory_value)
    if not log_directory.is_absolute() or ".." in log_directory.parts:
        raise ConfigError("traffic_logs.directory must be an absolute path without '..'")
    #
    # The fixture has no collector, no key and no node access, so a mirror it
    # could read would have to have arrived some other way. Refusing is better
    # than rendering whatever that was.
    #
    if traffic_logs.get("enabled") and demo_fixture:
        raise ConfigError("traffic_logs cannot be combined with demo_fixture")

    oidc_public_key: Path | None = None
    if oidc:
        oidc_key_value = oidc.get("public_key")
        if not isinstance(oidc_key_value, str) or not oidc_key_value:
            raise ConfigError("oidc.public_key must be a non-empty string")
        oidc_public_key = Path(oidc_key_value)
        if not oidc_public_key.is_absolute() or ".." in oidc_public_key.parts:
            raise ConfigError("oidc.public_key must be an absolute path without '..'")

    public_key: Path | None = None
    if dns_profiles:
        public_key_value = dns_profiles.get("public_key")
        if not isinstance(public_key_value, str) or not public_key_value:
            raise ConfigError("dns_profiles.public_key must be a non-empty string")
        public_key = Path(public_key_value)
        if not public_key.is_absolute() or ".." in public_key.parts:
            raise ConfigError("dns_profiles.public_key must be an absolute path without '..'")

    return Config(
        database=Database(
            name=_string(database, "name", "database"),
            socket_directory=_string(database, "socket_directory", "database"),
        ),
        management_writes=writes,
        demo_fixture=demo_fixture,
        session=Session(
            inactivity_minutes=_bounded_int(
                session, "inactivity_minutes", "session", low=1, high=1440, default=600
            ),
            absolute_hours=_bounded_int(
                session, "absolute_hours", "session", low=1, high=720, default=168
            ),
            cookie_secure=_boolean(session, "cookie_secure", "session", default=True),
            oidc_absolute_hours=_bounded_int(
                session, "oidc_absolute_hours", "session", low=1, high=720, default=10
            ),
        ),
        throttle=Throttle(
            max_failures=_bounded_int(
                throttle, "max_failures", "throttle", low=1, high=1000, default=10
            ),
            window_minutes=_bounded_int(
                throttle, "window_minutes", "throttle", low=1, high=1440, default=15
            ),
        ),
        clusters=tuple(clusters),
        poller=Poller(
            interval_seconds=_bounded_int(
                #
                # The same value the shipped example carries. Two numbers for
                # one setting is how an installation that deleted the line ends
                # up behaving unlike the one beside it, for a reason nobody can
                # see in either file.
                #
                poller,
                "interval_seconds",
                "poller",
                low=10,
                high=3600,
                default=20,
            )
        ),
        traffic_logs=TrafficLogs(
            enabled=_boolean(traffic_logs, "enabled", "traffic_logs", default=False),
            directory=log_directory,
            max_lines=_bounded_int(
                traffic_logs, "max_lines", "traffic_logs", low=1, high=10000, default=500
            ),
            retention_days=_bounded_int(
                traffic_logs, "retention_days", "traffic_logs", low=1, high=90, default=7
            ),
        ),
        dns_profiles_public_key=public_key,
        oidc_public_key=oidc_public_key,
    )
