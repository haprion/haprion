"""`python -m unittest`, and then a failure for what the run left open or reached of this machine.

Every run of the two suites goes through this: the gate's pool starts each
module with it in place of `-m unittest` (tools/run_test_modules.py), and the
database tests (ui/tools/test-database), the run without HAProxy (run-tests)
and a targeted run (`python tools/unittest_left_open.py tests.<module>`) call
it by name. The rule is here once; docs/SECURITY-CHECKS.md says what it covers.

A run fails for a file or socket it left open, seen two ways:

- a ResourceWarning said while it ran, at import, or in the collection after
  it - counted here, so a run fails on it whoever reads the output. A file
  held only in a reference cycle is closed in that last collection (review
  26-10-29, CC03);
- a descriptor still open once every test and every class and module fixture
  has ended, beyond those the process was started with. One that a module or
  class variable, or a cache, keeps until exit is let go when Python promises
  no warning at all - and one daemon thread still blocked in `accept()` was
  measured to silence every such warning for the whole module (C02).

And for a reach under /etc/haprion, made from Python in this process (A09,
CC01): an opening, a listing, a stat, an existence or access check, a link
read, or a change to a path there. A realpath of one is let through as long as
it follows no link there.

What it does not see: a child that starts a program - a script, a shell
command, another Python - as the hook and the wrappers end with the exec; an
opening made from C, such as ssl's `load_verify_locations`; and what a child
keeps open.
"""

from __future__ import annotations

import gc
import os
import stat
import sys
import threading
import unittest
import warnings
from collections.abc import Callable
from typing import Any

#
# The interpreter's own binary, which a library opens from C to read itself
# and keeps for the life of the process - measured 26-10-29: importing psycopg
# does, with no audit event to say from where. No test opens it.
#
INTERPRETER = os.path.realpath(sys.executable)
#
# No test reads this machine's configuration (review 26-10-29, A09). The
# suites run on a manager, where /etc/haprion exists, and a test that read it
# passed here and failed in CI - twice on 2026-10-28. Every reach for a path
# there is refused before it is tried, with an error no `except OSError` takes
# for a missing file, and named after the run: one a broader handler
# swallowed still fails the module.
#
MACHINE_CONFIGURATION = "/etc/haprion"
#
# The audit events that name a path, and which of their arguments are paths.
# A symlink's target is only text until something follows it.
#
PATH_EVENTS = {
    "open": (0,),
    "os.listdir": (0,),
    "os.scandir": (0,),
    "os.chdir": (0,),
    "os.mkdir": (0,),
    "os.rmdir": (0,),
    "os.remove": (0,),
    "os.rename": (0, 1),
    "os.link": (0, 1),
    "os.symlink": (1,),
    "os.chmod": (0,),
    "os.chown": (0,),
    "os.utime": (0,),
    "os.truncate": (0,),
}
#
# And the calls that have no audit event at all (26-10-29, AA08): every
# `exists`, `is_file`, `is_dir`, `lexists` and `is_symlink`, in os.path and
# pathlib alike, is one of these underneath.
#
UNAUDITED = ("stat", "lstat", "access", "readlink")


class MachineConfigurationRead(AssertionError):
    """A test reached for this machine's configuration."""


machine_reads: list[str] = []
resource_warnings: list[str] = []
#
# A realpath finds the links in a path by an lstat of each part. That reads
# no file, and the policy loader resolves every path a policy names - its
# defaults under /etc/haprion among them - so those are let through while it
# walks. A link it would follow is not: what it reads there differs by machine.
#
_resolving = threading.local()


def _reach(path: object) -> None:
    if not isinstance(path, str | bytes | os.PathLike):
        return
    try:
        name = os.fsdecode(path)
        if not os.path.isabs(name):
            name = os.path.join(os.getcwd(), name)
    except (OSError, TypeError, ValueError):
        return
    name = os.path.normpath(name)
    if name == MACHINE_CONFIGURATION or name.startswith(MACHINE_CONFIGURATION + "/"):
        machine_reads.append(name)
        raise MachineConfigurationRead(f"a test reached for this machine's configuration: {name}")


def _machine_configuration(event: str, args: tuple[object, ...]) -> None:
    for index in PATH_EVENTS.get(event, ()):
        if index < len(args):
            _reach(args[index])


def _guarded(original: Callable[..., Any]) -> Callable[..., Any]:
    walked = original is os.lstat

    def guarded(path: Any, *args: Any, **kwargs: Any) -> Any:
        if not (walked and getattr(_resolving, "depth", 0) > 0):
            _reach(path)
        return original(path, *args, **kwargs)

    guarded.__name__ = original.__name__
    guarded.__qualname__ = original.__qualname__
    guarded.__doc__ = original.__doc__
    return guarded


def _guard_unaudited() -> None:
    for name in UNAUDITED:
        original = getattr(os, name)
        guarded = _guarded(original)
        #
        # shutil and os choose their fd-based paths by these sets (rmtree's
        # symlink-safe one among them): the wrapper stands where the call did.
        #
        for supported in (
            os.supports_dir_fd,
            os.supports_fd,
            os.supports_follow_symlinks,
            os.supports_effective_ids,
        ):
            if original in supported:
                supported.add(guarded)
        setattr(os, name, guarded)
    realpath = os.path.realpath

    def resolved(path: Any, *args: Any, **kwargs: Any) -> Any:
        _resolving.depth = getattr(_resolving, "depth", 0) + 1
        try:
            return realpath(path, *args, **kwargs)
        finally:
            _resolving.depth -= 1

    # The same call, counted while it runs.
    os.path.realpath = resolved  # type: ignore[assignment]


def _count_resource_warnings() -> None:
    show = warnings.showwarning

    def counted(
        message: Warning | str,
        category: type[Warning],
        filename: str,
        lineno: int,
        file: Any = None,
        line: str | None = None,
    ) -> None:
        if issubclass(category, ResourceWarning):
            resource_warnings.append(f"{filename}:{lineno}: {message}")
        show(message, category, filename, lineno, file, line)

    warnings.showwarning = counted
    #
    # unittest says them while its tests run; this says them at import and
    # after, where Python's own filter would drop them.
    #
    warnings.simplefilter("always", ResourceWarning)


def _collect() -> None:
    """Collect what only a reference cycle held, and count what that closed."""

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        gc.collect()
    for warning in caught:
        if issubclass(warning.category, ResourceWarning):
            resource_warnings.append(f"{warning.filename}:{warning.lineno}: {warning.message}")
            print(
                warnings.formatwarning(
                    warning.message, warning.category, warning.filename, warning.lineno
                ),
                end="",
                file=sys.stderr,
            )


def descriptors() -> dict[int, str]:
    """What this process has open, by number, each with what it points at."""

    found = {}
    directory = "/proc/self/fd"
    for name in os.listdir(directory):
        descriptor = int(name)
        try:
            target = os.readlink(f"{directory}/{name}")
            mode = os.fstat(descriptor).st_mode
        except OSError:
            # The listing's own descriptor, closed by the time it is read.
            continue
        if stat.S_ISDIR(mode) and target == "/proc/self/fd":
            continue
        if stat.S_ISREG(mode) and target == INTERPRETER:
            continue
        found[descriptor] = target
    return found


def left_open(started_with: dict[int, str]) -> list[str]:
    """What this process has open that it was not started with, one line each."""

    return [
        f"{descriptor} -> {target}"
        for descriptor, target in sorted(descriptors().items())
        if started_with.get(descriptor) != target
    ]


def main() -> int:
    #
    # What the process was handed: the standard streams, and whatever else a
    # terminal, an editor or a CI agent passes down. The pool closes the rest;
    # a targeted run does not (review 26-10-29, CC04).
    #
    started_with = descriptors()
    #
    # Where `python -m` would have put the start directory: the suites import
    # their helpers from it (`tests.spawned`), and a script's own directory
    # would be first instead.
    #
    sys.path[0] = os.getcwd()
    _count_resource_warnings()
    sys.addaudithook(_machine_configuration)
    _guard_unaudited()
    program = unittest.main(module=None, argv=["python -m unittest", *sys.argv[1:]], exit=False)
    result = program.result
    del program
    if result.testsRun == 0 and not result.skipped:
        # As `python -m unittest` ends a run that found nothing to run.
        return 5
    if machine_reads:
        print(
            "tests reached for this machine's configuration:\n  "
            + "\n  ".join(sorted(set(machine_reads))),
            file=sys.stderr,
        )
        return 1
    _collect()
    failed = False
    if resource_warnings:
        print(
            "a ResourceWarning - something the run opened was left to the garbage collector:\n  "
            + "\n  ".join(resource_warnings),
            file=sys.stderr,
        )
        failed = True
    kept = left_open(started_with)
    if kept:
        print(
            "left open after its tests ran - a module or class variable, a cache or a"
            " fixture that never closed it:\n  " + "\n  ".join(kept),
            file=sys.stderr,
        )
        failed = True
    return 1 if failed or not result.wasSuccessful() else 0


if __name__ == "__main__":
    sys.exit(main())
