#!/usr/bin/env python3
"""Run unittest suites one module per process, several at a time.

The gate's two suites are CPU-bound and were run one test at a time, which on
a four-core host left three cores idle for five minutes. Each module here is
started with exactly the command the suite used before plus `-p <module>`, so
discovery, imports and the test's working directory are what they were; only
how many run at once changes.

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
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

RAN = re.compile(r"^Ran (\d+) tests? in ", re.MULTILINE)
SKIPPED = re.compile(r"skipped=(\d+)")


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


def run(module: Module) -> Outcome:
    started = time.monotonic()
    completed = subprocess.run(  # noqa: S603 - the gate's own suite commands
        [*module.command, "-p", module.name],
        cwd=module.directory.parent,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return Outcome(module, completed.returncode, time.monotonic() - started, completed.stdout)


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
    arguments = parser.parse_args()

    pending = modules(arguments.suite)
    previous = load_durations(arguments.durations)
    # A module without a timing is new and of unknown weight: start it early.
    pending.sort(key=lambda m: -previous.get(key(m), float("inf")))

    started = time.monotonic()
    outcomes: list[Outcome] = []
    with ThreadPoolExecutor(max_workers=max(1, arguments.jobs)) as pool:
        futures = [pool.submit(run, m) for m in pending]
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
