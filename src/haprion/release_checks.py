"""The checks a release is held to before it is recorded, in one place.

A release that HAProxy accepts can still be one the nodes serve wrongly: a core
that allows fewer stick counters than the objects use, a core that chroots
HAProxy away from the traffic log's socket, a core whose TLS defaults have
drifted from the generator's. Three publishing loops and the regeneration read
asked these by hand, each with its own copy, and the copies drifted (a revert
asked none of them). This is the one list.

The order is the point of two functions. `before_the_sandbox` is what HAProxy
would refuse in words that name neither the file nor the line, so it is said
first. `after_the_sandbox` is the TLS defaults: a core can be both stale and
syntactically broken, and the broken half is the one that stops HAProxy from
starting, so the cipher lists must not hide it behind the smaller problem.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass

from haprion import tls_policy, traffic_stream

CORE = "core/haproxy.cfg"


@dataclass(frozen=True, slots=True)
class Problem:
    """One thing wrong with a release: a stable code and the words for a person."""

    code: str
    message: str


type Check = Callable[..., str | None]

#
# In the order a publish says them.
#
BEFORE_THE_SANDBOX: tuple[tuple[str, Check], ...] = (
    ("stick_counters_short", tls_policy.stick_counters_problem),
    ("traffic_log_unreachable", traffic_stream.problem),
)


def _tls_defaults(files: Mapping[str, bytes], *, cluster: str, config_path: str) -> str | None:
    """The core's TLS defaults. A release without a core has none to be stale."""

    core = files.get(CORE)
    if core is None:
        return None
    return tls_policy.core_defaults_problem(core, cluster=cluster, config_path=config_path)


AFTER_THE_SANDBOX: tuple[tuple[str, Check], ...] = (("tls_defaults_stale", _tls_defaults),)


def _run(
    checks: tuple[tuple[str, Check], ...],
    files: Mapping[str, bytes],
    cluster: str,
    config_path: str,
) -> Iterator[Problem]:
    """Lazily, so a caller that wants the first verdict does not ask the rest."""

    for code, check in checks:
        message = check(files, cluster=cluster, config_path=config_path)
        if message is not None:
            yield Problem(code, message)


def before_the_sandbox(
    files: Mapping[str, bytes], *, cluster: str, config_path: str
) -> Problem | None:
    """Stick counters, then the traffic stream; the first that is wrong."""

    return next(_run(BEFORE_THE_SANDBOX, files, cluster, config_path), None)


def after_the_sandbox(
    files: Mapping[str, bytes], *, cluster: str, config_path: str
) -> Problem | None:
    """The TLS defaults, when the core's are not the generator's."""

    return next(_run(AFTER_THE_SANDBOX, files, cluster, config_path), None)


def first(files: Mapping[str, bytes], *, cluster: str, config_path: str) -> Problem | None:
    """What a publish would refuse the release for, in a publish's order."""

    return before_the_sandbox(files, cluster=cluster, config_path=config_path) or after_the_sandbox(
        files, cluster=cluster, config_path=config_path
    )


def all_problems(files: Mapping[str, bytes], *, cluster: str, config_path: str) -> list[Problem]:
    """Every check's verdict, for the caller that reports instead of refusing."""

    return list(_run(BEFORE_THE_SANDBOX + AFTER_THE_SANDBOX, files, cluster, config_path))
