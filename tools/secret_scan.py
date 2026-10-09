#!/usr/bin/env python3
"""Fail-closed scanner for the Haprion source tree.

The environment denylist is deliberately external to Git. Findings print only
rule names and locations, never the matched content.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

GENERIC_RULES = (
    ("private-key", re.compile("-----" + r"BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("certificate", re.compile("-----" + r"BEGIN CERTIFICATE-----")),
    (
        "ssh-key-material",
        re.compile(r"(?:ssh-(?:rsa|ed25519)|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/]{40,}={0,3}"),
    ),
    (
        "assigned-secret",
        re.compile(
            #
            # A lookbehind rather than \b at the front. A word boundary does not
            # fire between an underscore and a letter, so `DB_PASSWORD=...` and
            # `API_TOKEN=...` - the two most ordinary names a real secret is
            # assigned to - went unmatched. Found 2026-08-28 while narrowing the
            # value side of this rule.
            #
            r"(?i)(?<![A-Za-z0-9])(?P<name>password|passwd|secret|token|api[_-]?key|private[_-]?key)\b"
            r"\s*[:=]\s*"
            #
            # A value that is the key again is a variable, not a secret:
            # `claim_token=claim_token` passes one along, and
            # `claim_token = job.claim_token` reads one off a row. Written as a
            # backreference so the exemption is exact - it fires only when the
            # value ends in the very word that named it, which no real secret
            # does. A dotted JWT segment therefore keeps matching, which is why
            # bare dotted values are still reported below.
            #
            r"(?!(?:[A-Za-z_][A-Za-z0-9_]*\.)*(?:[A-Za-z0-9]+_)*(?P=name)\b)"
            #
            # A value that is a function call or a subscript is code, not a
            # literal: `password = read_new_password()` and
            # `token = request.cookies.get(NAME)` name a secret without
            # containing one. Excluded by shape rather than by an allowlist of
            # files, so the exemption cannot rot into "this directory is
            # trusted".
            #
            # Deliberately narrow. Only a call or a subscript is exempt - a bare
            # dotted value is still reported, and so is anything quoted, because
            # a real secret with dots in it (a JWT, for one) must keep matching.
            #
            r"(?!(?:[A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s*[(\[])"
            #
            # A bound-parameter placeholder is not a value at all - it is the
            # mechanism that keeps the value out of the statement text. psycopg
            # writes them as `%(name)s` or `%s`, and a colon form appears in
            # other drivers. Matching them reported the fencing predicate
            # `claim_token = %(claim_token)s` as an assigned secret, which is the
            # opposite of what it is. Excluded by shape, like the call above.
            #
            r"(?!%\(?[A-Za-z_][A-Za-z0-9_]*\)?s\b)"
            r"(?!%s\b)"
            r"(?!:[A-Za-z_][A-Za-z0-9_]*\b)"
            r"['\"]?[^\s'\"${}]{8,}"
        ),
    ),
)

FORBIDDEN_BASENAMES = {
    ".env",
    "AGENTS.md",
    "authorized_keys",
    "known_hosts",
}
FORBIDDEN_SUFFIXES = {".cer", ".crt", ".key", ".pem", ".p12", ".pfx"}
#
# The RFC 5737 documentation ranges, plus loopback.
#
# Loopback is here because the rule this scanner enforces is "no address out of
# a real environment", and 127.0.0.0/8 is not out of any environment - it means
# "this machine" wherever it is read. Excluding it forced documentation to be
# wrong to pass: the web service binds loopback and nginx is the only thing that
# reaches it, so an example that says otherwise teaches the wrong deployment,
# and `localhost` is ambiguous for a listen address because it may resolve to
# ::1 instead.
#
# 0.0.0.0/8 is here by the same argument. RFC 1122 reserves it for "this host
# on this network": it is never a destination and never names a machine in any
# environment, so a match in it is not an address at all. What it matched, in
# practice, was version numbers - a four-part `0.0.0.2` or `0.4.9.6` in a lock
# file has the shape of an address and cannot be one.
#
# Nothing else joins this list without the same argument. A private address is
# still an address out of somebody's network, and RFC 1918 ranges stay refused.
#
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "127.0.0.0/8",
        "0.0.0.0/8",
    )
)
IPV4_CANDIDATE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")


class ScanFailure(RuntimeError):
    pass


def load_private_rules(path: Path) -> list[tuple[str, re.Pattern[str]]]:
    if not path.is_file():
        raise ScanFailure(f"required private denylist is missing: {path}")
    if path.is_symlink():
        raise ScanFailure(f"private denylist must not be a symlink: {path}")

    rules: list[tuple[str, re.Pattern[str]]] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            label, expression = line.split("\t", 1)
        except ValueError as exc:
            raise ScanFailure(f"invalid denylist row {number}: expected label<TAB>regex") from exc
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", label):
            raise ScanFailure(f"invalid denylist label on row {number}")
        try:
            rules.append((label, re.compile(expression)))
        except re.error as exc:
            raise ScanFailure(f"invalid regex for {label} on row {number}: {exc}") from exc

    if not rules:
        raise ScanFailure("private denylist contains no active rules")
    return rules


def git(repo: Path, *args: str, binary: bool = False) -> bytes | str:
    git_binary = shutil.which("git")
    if git_binary is None:
        raise ScanFailure("required command is missing: git")
    completed = subprocess.run(  # noqa: S603 - no shell; callers supply fixed git verbs
        [git_binary, "-C", str(repo), *args],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ScanFailure(f"git {' '.join(args)} failed: {detail}")
    if binary:
        return completed.stdout
    return completed.stdout.decode("utf-8", errors="strict")


def staged_files(repo: Path) -> list[tuple[str, bytes]]:
    raw_names = git(
        repo,
        "diff",
        "--cached",
        "--name-only",
        "--diff-filter=ACMR",
        "-z",
        binary=True,
    )
    if not isinstance(raw_names, bytes):
        raise ScanFailure("internal error: staged filename list is not bytes")
    result: list[tuple[str, bytes]] = []
    for raw_name in raw_names.split(b"\0"):
        if not raw_name:
            continue
        name = raw_name.decode("utf-8", errors="strict")
        blob = git(repo, "show", f":{name}", binary=True)
        if not isinstance(blob, bytes):
            raise ScanFailure("internal error: staged blob is not bytes")
        result.append((name, blob))
    return result


def worktree_files(repo: Path) -> list[tuple[str, bytes]]:
    result: list[tuple[str, bytes]] = []
    for root, directories, filenames in os.walk(repo, followlinks=False):
        directories[:] = sorted(directory for directory in directories if directory != ".git")
        for filename in sorted(filenames):
            path = Path(root) / filename
            relative = path.relative_to(repo).as_posix()
            if path.is_symlink():
                continue
            try:
                result.append((relative, path.read_bytes()))
            except OSError as exc:
                raise ScanFailure(f"cannot read {relative}: {exc}") from exc
    return result


def is_forbidden_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not any(address in network for network in DOCUMENTATION_NETWORKS)


def scan_file(
    name: str,
    content: bytes,
    private_rules: list[tuple[str, re.Pattern[str]]],
) -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    path = Path(name)
    if path.name in FORBIDDEN_BASENAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
        findings.append((name, 0, "forbidden-filename"))

    if b"\0" in content:
        return findings
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return findings

    rules = [*GENERIC_RULES, *private_rules]
    for number, line in enumerate(text.splitlines(), start=1):
        for label, expression in rules:
            if expression.search(line):
                findings.append((name, number, label))
        for candidate in IPV4_CANDIDATE.findall(line):
            if is_forbidden_ip(candidate):
                findings.append((name, number, "non-documentation-ipv4"))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--staged", type=Path, metavar="REPO")
    source.add_argument("--worktree", type=Path, metavar="REPO")
    parser.add_argument("--rules", required=True, type=Path)
    args = parser.parse_args()

    try:
        rules = load_private_rules(args.rules)
        repo = (args.staged or args.worktree).resolve()
        if not repo.is_dir():
            raise ScanFailure(f"repository directory is missing: {repo}")
        if args.staged:
            if not (repo / ".git").exists():
                raise ScanFailure(f"not a Git worktree: {repo}")
            files = staged_files(repo)
            scope = "staged content"
        else:
            files = worktree_files(repo)
            scope = "worktree"

        findings: list[tuple[str, int, str]] = []
        for name, content in files:
            findings.extend(scan_file(name, content, rules))

        if findings:
            print(f"secret scan: BLOCKED ({len(findings)} finding(s))", file=sys.stderr)
            for name, line, label in findings:
                location = f"{name}:{line}" if line else name
                print(f"  {location}: {label}", file=sys.stderr)
            return 1

        print(f"secret scan: OK ({scope}, files={len(files)})")
        return 0
    except (OSError, UnicodeError, ScanFailure) as exc:
        print(f"secret scan: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
