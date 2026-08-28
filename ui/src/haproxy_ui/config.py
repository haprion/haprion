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

DEFAULT_CONFIG_PATH = Path("/apps/haproxy-manager/config/ui.toml")
MAX_CONFIG_BYTES = 1024 * 1024

ALLOWED_KEYS = frozenset({"database", "listen", "management_writes"})
ALLOWED_DATABASE_KEYS = frozenset({"name", "socket_directory"})
ALLOWED_LISTEN_KEYS = frozenset({"host", "port"})


class ConfigError(ValueError):
    """The configuration cannot be used. Exit 78, as the contract says for it."""

    def __init__(self, message: str, *, exit_code: int = 78):
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
class Listen:
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class Config:
    database: Database
    listen: Listen
    #
    # Phase 4 installs the platform without management writes. The flag is here
    # rather than in a release so it can be turned off without deploying: the
    # documented rollback for the write path is to switch it off and be back in
    # a read-only interface, which is not a rollback that should require a build.
    #
    management_writes: bool


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
        raise ConfigError(f"[{key}] has unknown key(s): {', '.join(unknown)}")
    return value


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
        raise ConfigError(f"unknown top-level key(s): {', '.join(unknown)}")

    database = _section(data, "database", ALLOWED_DATABASE_KEYS)
    listen = _section(data, "listen", ALLOWED_LISTEN_KEYS)

    port = listen.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ConfigError("listen.port must be an integer between 1 and 65535")

    writes = data.get("management_writes", False)
    if not isinstance(writes, bool):
        raise ConfigError("management_writes must be true or false")

    return Config(
        database=Database(
            name=_string(database, "name", "database"),
            socket_directory=_string(database, "socket_directory", "database"),
        ),
        listen=Listen(host=_string(listen, "host", "listen"), port=port),
        management_writes=writes,
    )
