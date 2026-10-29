#!/usr/bin/env python3
"""Run unittest suites one module per process, several at a time.

The gate's two suites are CPU-bound and were run one test at a time, which on
a four-core host left three cores idle for five minutes. Each module here is
started with the command the suite used before plus `-p <module>`, so
discovery, imports and the test's working directory are what they were; only
how many run at once changes, and `-m unittest` runs as unittest_left_open,
which fails a module that leaves a file or socket open.

Modules of both suites share one pool, heaviest first: the gate's wall time is
bounded by its slowest module, so that module must not be the last to start.
How heavy a module is comes from the previous run's timings, kept outside the
repository; without them the order is alphabetical and only slower.

A module's own output is printed only when it fails. A passing module is one
line; the whole verbose listing of two thousand tests was never read.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

RAN = re.compile(r"^Ran (\d+) tests? in ", re.MULTILINE)
SKIPPED = re.compile(r"skipped=(\d+)")

#
# Chromium's shared memory. Playwright starts it with `--disable-dev-shm-usage`,
# so the blocks are files in TMPDIR, unlinked once mapped - and now and then one
# outlives a browser that is closing (measured 26-10-10: one in two runs of one
# module, zero-filled, 128 KiB multiples). Chromium's race rather than a missing
# cleanup in a test, and removed with the module's directory either way.
#
CHROMIUM_SHARED_MEMORY = ".org.chromium.Chromium."


@dataclass(frozen=True)
class Module:
    suite: str
    directory: Path
    command: tuple[str, ...]
    name: str


@dataclass(frozen=True)
class Outcome:
    module: Module
    returncode: int
    seconds: float
    output: str

    @property
    def ran(self) -> int:
        found = RAN.findall(self.output)
        return int(found[-1]) if found else 0

    @property
    def skipped(self) -> int:
        tail = self.output.rstrip().rsplit("\n", 1)[-1]
        found = SKIPPED.search(tail)
        return int(found.group(1)) if found else 0


def modules(suites: list[list[str]]) -> list[Module]:
    found = []
    for name, directory, command in suites:
        path = Path(directory).resolve()
        # unittest's own default pattern, so that a module discover would
        # have found is never left out by this runner.
        files = sorted(path.glob("test*.py"))
        if not files:
            raise SystemExit(f"run-test-modules: no test modules in {path}")
        found += [Module(name, path, tuple(shlex.split(command)), f.name) for f in files]
    return found


def load_durations(path: Path | None) -> dict[str, float]:
    if path is None:
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(loaded, dict):
        return {}
    return {k: float(v) for k, v in loaded.items() if isinstance(v, int | float)}


def save_durations(path: Path | None, previous: dict[str, float], outcomes: list[Outcome]) -> None:
    if path is None:
        return
    # Merged, so that running one suite alone keeps the other's timings.
    durations = previous | {key(o.module): round(o.seconds, 2) for o in outcomes}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(durations, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as error:
        # Only the next run's order depends on it.
        print(f"run-test-modules: timings not kept: {error}", file=sys.stderr)


def key(module: Module) -> str:
    return f"{module.suite}/{module.name}"


#
# How long a module may take: ten times its last run, never less than FLOOR,
# and UNTIMED for one with no timing yet. A test that hangs stood the whole gate
# still and said nothing of which test it was (review 26-10-25, 5-03); now it is
# a named failure.
#
FACTOR = 10
FLOOR = 120.0
UNTIMED = 900.0
TIMED_OUT = 124


#
# Each module runs under unittest_left_open in place of `-m unittest`: the same
# unittest, which then fails the module for any file or socket still open once
# its tests have ended (review 26-10-29, C02).
#
LEFT_OPEN = Path(__file__).resolve().with_name("unittest_left_open.py")


def gated(command: tuple[str, ...]) -> list[str]:
    """The suite's command, with `-m unittest` run as unittest_left_open."""

    for index in range(len(command) - 1):
        if command[index : index + 2] == ("-m", "unittest"):
            return [*command[:index], str(LEFT_OPEN), *command[index + 2 :]]
    raise SystemExit(f"run-test-modules: the command does not run -m unittest: {command}")


def budget(previous: float | None, floor: float = FLOOR) -> float:
    return UNTIMED if previous is None else max(floor, FACTOR * previous)


def run(module: Module, limit: float = UNTIMED) -> Outcome:
    #
    # Each module gets a temporary directory of its own and fails if anything
    # is left in it. A test that forgot its cleanup used to leave it in /tmp,
    # which held ten thousand entries by 26-10-10 - among them key files - and
    # nothing said which module wrote them.
    #
    scratch = Path(tempfile.mkdtemp(prefix=f"gate-{module.suite}-{module.name}-"))
    try:
        started = time.monotonic()
        #
        # A session of its own, so a module that runs out of time is stopped
        # with everything it started: a child left holding the output pipe
        # would keep the reading below waiting as the test did.
        #
        process = subprocess.Popen(  # noqa: S603 - the gate's own suite commands
            [*gated(module.command), "-p", module.name],
            cwd=module.directory.parent,
            env={**os.environ, "TMPDIR": str(scratch)},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            output, _ = process.communicate(timeout=limit)
            returncode = process.returncode
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate()
            returncode = TIMED_OUT
            output = f"{output or ''}\nstopped after {limit:.0f} s: a test in it did not finish\n"
        left = sorted(
            entry.name
            for entry in scratch.iterdir()
            if not entry.name.startswith(CHROMIUM_SHARED_MEMORY)
        )
        if left:
            returncode = returncode or 1
            output += f"\nleft in its temporary directory: {', '.join(left)}\n"
        #
        # A socket or file a test left open is said as a ResourceWarning, which
        # unittest shows and nothing fails: an OIDC error answer stayed open
        # through every gate until a review read the output (26-10-28, F04).
        #
        if "ResourceWarning" in output:
            returncode = returncode or 1
            output += "\na ResourceWarning: something the module opened was left open\n"
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return Outcome(module, returncode, time.monotonic() - started, output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--suite",
        nargs=3,
        action="append",
        required=True,
        metavar=("NAME", "DIRECTORY", "COMMAND"),
        help="a suite: its test directory, and the unittest discover command run from its parent",
    )
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--durations", type=Path, help="where the previous run's timings are kept")
    parser.add_argument(
        "--floor", type=float, default=FLOOR, help="the least time a module with a timing is given"
    )
    arguments = parser.parse_args()

    pending = modules(arguments.suite)
    previous = load_durations(arguments.durations)
    # A module without a timing is new and of unknown weight: start it early.
    pending.sort(key=lambda m: -previous.get(key(m), float("inf")))

    started = time.monotonic()
    outcomes: list[Outcome] = []
    with ThreadPoolExecutor(max_workers=max(1, arguments.jobs)) as pool:
        futures = [
            pool.submit(run, m, budget(previous.get(key(m)), arguments.floor)) for m in pending
        ]
        try:
            for future in as_completed(futures):
                outcome = future.result()
                outcomes.append(outcome)
                status = "ok  " if outcome.returncode == 0 else "FAIL"
                print(
                    f"{status} {outcome.module.suite:<8} {outcome.module.name:<48}"
                    f" {outcome.ran:>4} tests {outcome.seconds:6.1f} s",
                    flush=True,
                )
                if outcome.returncode != 0:
                    print(outcome.output, flush=True)
        except KeyboardInterrupt:
            pool.shutdown(wait=False, cancel_futures=True)
            raise
    elapsed = time.monotonic() - started
    save_durations(arguments.durations, previous, outcomes)

    # Named in a fixed order, not in whichever order they happened to finish.
    failed = sorted((o for o in outcomes if o.returncode != 0), key=lambda o: key(o.module))
    for suite in dict.fromkeys(m.suite for m in pending):
        mine = [o for o in outcomes if o.module.suite == suite]
        print(
            f"{suite}: {sum(o.ran for o in mine)} tests, {sum(o.skipped for o in mine)} skipped,"
            f" {len(mine)} modules"
        )
    print(f"{len(outcomes)} modules in {elapsed:.1f} s on {arguments.jobs} processes")
    if failed:
        print("failed: " + ", ".join(key(o.module) for o in failed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
