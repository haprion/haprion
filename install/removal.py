"""What the two removal commands share (B372): the machine, a step, and how a run is said.

`remove-manager` (haprion-setup --remove) and `node-remove` (haprion-node-prepare
--remove) each list what an installation made as steps; without --yes they print
them and change nothing, with --yes each step's action takes its part away and
names what it could not.
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path


class Host:
    """The machine: its files under `root`, its commands. A test gives another one."""

    def __init__(self, root: str = "/") -> None:
        self.root = Path(root)

    def path(self, name: str) -> Path:
        return self.root / name.lstrip("/")

    def run(
        self, argv: list[str], *, input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed commands with arguments read from the installation
            argv, input=input_text, capture_output=True, text=True, check=False
        )

    def users(self) -> list[pwd.struct_passwd]:
        return list(pwd.getpwall())

    def group_exists(self, name: str) -> bool:
        return self.run(["/usr/bin/getent", "group", name]).returncode == 0

    def is_mount(self, path: Path) -> bool:
        return os.path.ismount(path)


@dataclass
class Step:
    """One part of the removal: what it found, and how it takes it away."""

    title: str
    found: list[str] = field(default_factory=list)
    action: Callable[[], list[str]] | None = None


def public_key(line: str) -> str:
    """The key on an authorized_keys line, without the options before it or a comment after."""

    fields = line.split()
    for index, word in enumerate(fields[:-1]):
        if word.startswith(("ssh-", "ecdsa-", "sk-")):
            return f"{word} {fields[index + 1]}"
    return ""


def with_copies(host: Host, name: str) -> list[Path]:
    """A file and the `.replaced-*` copies install_file kept beside it."""

    path = host.path(name)
    found = [path] if path.exists() or path.is_symlink() else []
    if path.parent.is_dir():
        found += sorted(path.parent.glob(path.name + ".replaced-*"))
    return found


def size_of(path: Path) -> str:
    if path.is_symlink() or not path.is_dir():
        return ""
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except OSError:
            continue
    return f"  ({total / 1_000_000:.1f} MB)" if total >= 1_000_000 else f"  ({total} bytes)"


def remove(paths: Iterable[Path]) -> list[str]:
    failed = []
    for path in paths:
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
        except OSError as exc:
            failed.append(f"{path}: {exc}")
    return failed


def ran(host: Host, argv: list[str], what: str, failed: list[str]) -> bool:
    done = host.run(argv)
    if done.returncode != 0:
        failed.append(f"{what}: {(done.stderr or done.stdout).strip() or done.returncode}")
    return done.returncode == 0


def tidy_root_ssh(host: Host) -> None:
    """known_hosts and root's .ssh, when Haprion's lines were all they held.

    Step 3 (and step 4) made them; the operator's own lines or keys keep them.
    """

    ssh = host.path("/root/.ssh")
    known = ssh / "known_hosts"
    if known.is_file() and not known.read_text(encoding="utf-8").strip():
        known.unlink()
    if ssh.is_dir() and not any(ssh.iterdir()):
        ssh.rmdir()


#
# Directories a step makes when it puts the first file in, which the
# distribution does not ship: removed when Haprion's files were all they held.
#
EMPTY_DIRS = (
    "/etc/sysusers.d",
    # The traffic log's AppArmor rule, on a node without AppArmor (Debian).
    "/etc/apparmor.d/rsyslog.d",
    "/etc/apparmor.d",
)


def tidy_empty(host: Host) -> None:
    for name in EMPTY_DIRS:
        path = host.path(name)
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()


def report(steps: list[Step], closing: list[str], *, yes: bool, subject: str, command: str) -> int:
    """Print the steps; with `yes`, carry each out. The exit code says whether all of it went."""

    if not steps:
        print(f"Nothing of a Haprion {subject} installation was found here.")
        return 0
    print(
        f"Removing Haprion from this {subject}:" if yes else f"What `{command} --yes` would remove:"
    )
    failed: list[str] = []
    for step in steps:
        print(f"\n== {step.title}")
        for line in step.found:
            print(f"  {line}")
        if yes and step.action is not None:
            failed += step.action()
    print()
    for line in closing:
        print(line)
    if not yes:
        print("\nNothing was changed. Run it again with --yes to remove what is listed.")
        return 0
    if failed:
        print("\nThese could not be removed:")
        for line in failed:
            print(f"  {line}")
        return 1
    print("\nDone.")
    return 0
