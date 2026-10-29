"""`python -m unittest`, and then a failure for what the run left open or read of this machine.

The gate's runner starts each test module with this in place of `-m unittest`
(tools/run_test_modules.py). A file or socket a test leaves to the garbage
collector is said as a ResourceWarning while the tests run; one that a module
or class variable, or a cache, keeps until the process exits is let go after
the run, when Python promises no warning at all - and one daemon thread still
blocked in `accept()` was measured to silence every such warning for the whole
module (review 26-10-29, C02). So the descriptors are read instead: once every
test and every class and module fixture has ended, whatever the process still
has open was opened by the run and kept.
"""

from __future__ import annotations

import gc
import os
import stat
import sys
import unittest

#
# What the interpreter itself holds: the three standard streams, which the
# runner gave it.
#
STANDARD = frozenset({0, 1, 2})
#
# And the interpreter's own binary, which a library opens from C to read itself
# and keeps for the life of the process - measured 26-10-29: importing psycopg
# does, with no audit event to say from where. No test opens it.
#
INTERPRETER = os.path.realpath(sys.executable)
#
# No test reads this machine's configuration (review 26-10-29, A09). The
# suites run on a manager, where /etc/haprion exists, and a test that read it
# passed here and failed in CI - twice on 2026-10-28. Every opening or listing
# of a path there is refused before it is tried, with an error no
# `except OSError` takes for a missing file, and named after the run: one a
# broader handler swallowed still fails the module.
#
MACHINE_CONFIGURATION = "/etc/haprion"


class MachineConfigurationRead(AssertionError):
    """A test reached for this machine's configuration."""


machine_reads: list[str] = []


def _machine_configuration(event: str, args: tuple[object, ...]) -> None:
    if event not in ("open", "os.listdir", "os.scandir") or not args:
        return
    path = args[0]
    if not isinstance(path, str | bytes | os.PathLike):
        return
    name = os.path.normpath(os.fsdecode(path))
    if name == MACHINE_CONFIGURATION or name.startswith(MACHINE_CONFIGURATION + "/"):
        machine_reads.append(name)
        raise MachineConfigurationRead(f"a test read this machine's configuration: {name}")


def left_open() -> list[str]:
    """What this process has open beyond its standard streams, one line each."""

    found = []
    directory = "/proc/self/fd"
    for name in sorted(os.listdir(directory), key=int):
        descriptor = int(name)
        if descriptor in STANDARD:
            continue
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
        found.append(f"{descriptor} -> {target}")
    return found


def main() -> int:
    #
    # Where `python -m` would have put the start directory: the suites import
    # their helpers from it (`tests.spawned`), and a script's own directory
    # would be first instead.
    #
    sys.path[0] = os.getcwd()
    sys.addaudithook(_machine_configuration)
    program = unittest.main(module=None, argv=["python -m unittest", *sys.argv[1:]], exit=False)
    result = program.result
    del program
    if result.testsRun == 0 and not result.skipped:
        # As `python -m unittest` ends a run that found nothing to run.
        return 5
    if machine_reads:
        print(
            "tests read this machine's configuration:\n  "
            + "\n  ".join(sorted(set(machine_reads))),
            file=sys.stderr,
        )
        return 1
    gc.collect()
    kept = left_open()
    if kept:
        print(
            "left open after its tests ran - a module or class variable, a cache or a"
            " fixture that never closed it:\n  " + "\n  ".join(kept),
            file=sys.stderr,
        )
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
