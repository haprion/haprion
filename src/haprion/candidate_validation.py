from __future__ import annotations

import hashlib
import os
import re
import select
import stat
import subprocess
import tempfile
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from haprion import exit_codes, haproxy_versions
from haprion.certificates import AUTHORITY_DIRECTORY, leaf_block
from haprion.config import ConfigError
from haprion.helper_protocol import HelperProtocolError, JsonValue
from haprion.release_layout import (
    CRT_LIST_ALLOWED_SUFFIX,
    CRT_LIST_TARGET,
    DNS_NAME,
    DNS_TARGET,
    KEEPALIVED_ALLOWED_SUFFIX,
    KEEPALIVED_TARGET,
    RSYSLOG_NAME,
    RSYSLOG_TARGET,
    WAF_NAME,
    WAF_TARGET,
)

#
# The binary that validates every candidate, and whose version the status
# reading reports beside the nodes' (the manual: nodes first, this host last).
#
HAPROXY = "/usr/sbin/haproxy"
#
# The directory of the `shm-stats-file` a cluster's core names
# (`cluster_definition.SHM_STATS_FILE`): the HAProxy package's own runtime
# directory on a node, which its tmpfiles entry makes at boot.
#
SHM_STATS_DIRECTORY = "/run/haproxy"
#
# The WAF engine, from its own package (B229, B230). The manager has it for
# this one purpose: a rule the engine cannot compile is refused here, at
# publication, rather than on a node.
#
WAF_ENGINE = "/usr/sbin/coraza-spoa"
#
# dnsdist, from PowerDNS's repository (B249), for the same one purpose: a dns
# listener's file dnsdist would not load is refused here. Its check exits 0 on
# a key it does not know and only warns (`Unknown key, ignored`, measured on
# 2.1.2), so a warning or an error in its output refuses as well.
#
DNSDIST = "/usr/bin/dnsdist"
#
# A `peer` line, as the generator writes them (B270). The first one names the
# node the check runs as.
#
PEER_LINE = re.compile(r"^\s*peer\s+([A-Za-z0-9][A-Za-z0-9._-]{0,63})\s")
DNSDIST_REFUSALS = ('prio="Warning"', 'prio="Error"')


def validator_version(
    run: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
) -> str | None:
    """`haproxy -v`'s version on this host, as the nodes' runtime reports theirs; None if unreadable."""

    def default(argv: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed path, no input
            argv, capture_output=True, text=True, check=False, timeout=10
        )

    try:
        completed = (run or default)([HAPROXY, "-v"])
    except (OSError, subprocess.TimeoutExpired):
        return None
    first = completed.stdout.splitlines()[0] if completed.stdout else ""
    words = first.split()
    if completed.returncode != 0 or len(words) < 3 or words[:2] != ["HAProxy", "version"]:
        return None
    return words[2][:128]


MAX_CANDIDATE_BYTES = 4 * 1024 * 1024
MAX_CANDIDATE_FILES = 512
MAX_FILE_BYTES = 1024 * 1024

#
# Both privileged helpers validate, and both must validate the same way: the
# same certificate, the same run root, the same sandbox. The environment is
# therefore prepared here rather than in either command.
#
DEFAULT_RUN_ROOT = Path("/run/haprion-validation")
#
# A sandboxed check: how long the caller waits, how long the unit may run -
# shorter, so systemd ends it before the caller gives up - how much memory and
# how many tasks it may use, and how much of its output is kept (S07).
#
CLIENT_SECONDS = 30
RUNTIME_SECONDS = 25
MEMORY_MAX = "256M"
TASKS_MAX = 32
WAF_GOMAXPROCS = 2
DIAGNOSTICS_BYTES = 16384
VALIDATION_CERTIFICATE = "validation.pem"


@dataclass(frozen=True, slots=True)
class Candidate:
    files: Mapping[str, bytes]
    sha256: str


@dataclass(frozen=True, slots=True)
class ValidationResult:
    valid: bool
    diagnostics: str


def _allowed_path(raw: str) -> str:
    path = PurePosixPath(raw)
    #
    # A control character in a name - `conf.d/1001-shop\n.cfg`, which a
    # `.match` on the object's name once let through - is refused here too,
    # where the candidate crosses into the privileged side (review 2026-10-22,
    # 5-12).
    #
    if (
        not raw
        or path.is_absolute()
        or str(path) != raw
        or any(part in (".", "..") for part in path.parts)
        or any(unicodedata.category(character) == "Cc" for character in raw)
    ):
        raise HelperProtocolError(
            "candidate contains an invalid relative path", exit_code=exit_codes.REFUSED
        )
    if raw == "haproxy.cfg":
        return raw
    if len(path.parts) == 2 and path.parts[0] == "conf.d" and path.suffix == ".cfg":
        return raw
    if path.parts[0] == "maps" and len(path.parts) >= 2:
        return raw
    #
    # The keepalived address list. Widening this allowlist is not a small
    # decision - it is the list that says what may cross into the privileged
    # side - so it is widened by exactly one shape: one directory, one level
    # deep, `.conf` only. The helper still validates the candidate as HAProxy
    # configuration and this file takes no part in that; it rides along to the
    # node, which validates it with keepalived's own parser before using it.
    #
    if (
        len(path.parts) == 2
        and path.parts[0] == KEEPALIVED_TARGET
        and path.suffix == KEEPALIVED_ALLOWED_SUFFIX
    ):
        return raw
    #
    # The certificate lists, widened by the same one shape for the same reason:
    # one directory, one level deep, `.list` only. Unlike the keepalived file
    # this one *is* part of the validation - a bind line names it, and HAProxy
    # refuses to start on a list it cannot read - so a candidate that omits it
    # fails in the sandbox rather than on the node.
    #
    if (
        len(path.parts) == 2
        and path.parts[0] == CRT_LIST_TARGET
        and path.suffix == CRT_LIST_ALLOWED_SUFFIX
    ):
        return raw
    #
    # The WAF engine's directory: its shapes, the release layout's own rule -
    # not a free tree, for the same reason as the two above.
    #
    if path.parts[0] == WAF_TARGET and WAF_NAME.fullmatch(raw.removeprefix(f"{WAF_TARGET}/")):
        return raw
    #
    # dnsdist's one file (B249), and nothing else in its directory.
    #
    if len(path.parts) == 2 and path.parts[0] == DNS_TARGET and DNS_NAME.fullmatch(path.parts[1]):
        return raw
    #
    # rsyslog's forwarding (B286), one file. Checked with `rsyslogd -N1` on the
    # node, where it runs: the manager's rsyslogd is confined by AppArmor to
    # its own directories and cannot read a candidate (measured 26-10-12).
    #
    if (
        len(path.parts) == 2
        and path.parts[0] == RSYSLOG_TARGET
        and RSYSLOG_NAME.fullmatch(path.parts[1])
    ):
        return raw
    raise HelperProtocolError(
        "candidate contains a path outside its allowlist", exit_code=exit_codes.REFUSED
    )


def candidate_from_files(files: Mapping[str, bytes]) -> Candidate:
    """The same candidate, built from bytes that never were JSON.

    The publishing helper derives the node artifact itself, on root's side of
    the boundary, and then has to validate it. Routing that through the JSON
    parser would mean encoding bytes back into strings only to decode them
    again - so the checks and the digest live here, and `parse_candidate` is the
    JSON front door onto the same code. One implementation, one digest.
    """

    if not files:
        raise HelperProtocolError(
            "candidate must contain at least one file", exit_code=exit_codes.REFUSED
        )
    if len(files) > MAX_CANDIDATE_FILES:
        raise HelperProtocolError("candidate contains too many files", exit_code=exit_codes.REFUSED)

    checked: dict[str, bytes] = {}
    total = 0
    digest = hashlib.sha256()
    for raw_path in sorted(files):
        content = files[raw_path]
        path = _allowed_path(raw_path)
        if b"\x00" in content:
            raise HelperProtocolError(
                "candidate files may not contain NUL", exit_code=exit_codes.REFUSED
            )
        if len(content) > MAX_FILE_BYTES:
            raise HelperProtocolError(
                "candidate contains an oversized file", exit_code=exit_codes.REFUSED
            )
        total += len(content)
        if total > MAX_CANDIDATE_BYTES:
            raise HelperProtocolError(
                "candidate exceeds the total size limit", exit_code=exit_codes.REFUSED
            )
        checked[path] = content
        path_bytes = path.encode()
        digest.update(len(path_bytes).to_bytes(4, "big"))
        digest.update(path_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)

    if "haproxy.cfg" not in checked:
        raise HelperProtocolError(
            "candidate must contain haproxy.cfg", exit_code=exit_codes.REFUSED
        )
    return Candidate(files=checked, sha256=digest.hexdigest())


def parse_candidate(parameters: Mapping[str, JsonValue]) -> Candidate:
    """The JSON front door: decode, then hand over to `candidate_from_files`."""

    raw_files = parameters.get("files")
    if not isinstance(raw_files, dict) or not raw_files:
        raise HelperProtocolError(
            "parameters.files must be a non-empty object", exit_code=exit_codes.REFUSED
        )
    if len(raw_files) > MAX_CANDIDATE_FILES:
        raise HelperProtocolError("candidate contains too many files", exit_code=exit_codes.REFUSED)

    decoded: dict[str, bytes] = {}
    for raw_path in sorted(raw_files):
        content = raw_files[raw_path]
        if not isinstance(raw_path, str) or not isinstance(content, str):
            raise HelperProtocolError(
                "candidate paths and contents must be strings", exit_code=exit_codes.REFUSED
            )
        decoded[raw_path] = content.encode("utf-8")
    return candidate_from_files(decoded)


def materialize_candidate(
    candidate: Candidate,
    root: Path,
    *,
    certificate_ids: Sequence[str],
    validation_certificate: bytes,
    authority_ids: Sequence[str] = (),
) -> None:
    root.mkdir(mode=0o700)
    for directory in (root / "conf.d", root / "maps", root / "certs"):
        directory.mkdir(mode=0o700)

    for relative, original in candidate.files.items():
        target = root / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        content = original
        #
        # The certificate lists are rewritten too, and that is not a detail. A
        # `crt-list` names its certificates by absolute path inside the file,
        # so a bind line pointing at a list validated fine while every line in
        # the list still pointed at `/etc/haproxy/certs` - which this sandbox
        # deliberately does not have. Measured 2026-09-04: the first object to
        # choose its own TLS level produced a list, and the publish was refused
        # with `unable to stat SSL certificate`.
        #
        if relative == "haproxy.cfg" or relative.startswith(("conf.d/", f"{CRT_LIST_TARGET}/")):
            content = content.replace(b"/etc/haproxy/maps/", b"/candidate/maps/")
            content = content.replace(b"/etc/haproxy/certs/", b"/candidate/certs/")
        #
        # The SPOE file a frontend names and the rules `coraza.yaml` includes,
        # pointed at the candidate's own copies - the node does the same.
        #
        if relative == "haproxy.cfg" or relative.startswith("conf.d/"):
            content = content.replace(b"/etc/haproxy/waf/", b"/candidate/waf/")
        if relative == f"{WAF_TARGET}/coraza.yaml":
            content = content.replace(b"/etc/haproxy/waf/", b"/candidate/waf/")
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)

    for certificate_id in certificate_ids:
        target = root / "certs" / f"{certificate_id}.pem"
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(validation_certificate)

    #
    # The cluster's CA files (B276), each the validation certificate's own
    # certificate block: `haproxy -c` loads a `ca-file` and refuses one that
    # is missing, and a self-signed certificate is a CA to it like any other.
    # The real files are not copied in, for the reason the certificates are
    # not: the sandbox proves the configuration, not the material.
    #
    if authority_ids:
        (root / "certs" / AUTHORITY_DIRECTORY).mkdir(mode=0o700)
        stand_in = leaf_block(validation_certificate.decode("ascii")).encode("ascii")
    for authority_id in authority_ids:
        target = root / "certs" / AUTHORITY_DIRECTORY / f"{authority_id}.pem"
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(stand_in)


def peer_arguments(configuration: Path) -> list[str]:
    """`-L <node>` when the configuration shares its tables, else nothing (B270).

    A node finds its own `peer` line by its host name; the manager's is none of
    them, and `haproxy -c` then drops the whole section with a warning and
    checks the rest (measured on 3.4.6). Run as the first node, the section is
    checked like every other.
    """

    for path in sorted(configuration.glob("*.cfg")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = PEER_LINE.match(line)
            if match is not None:
                return ["-L", match.group(1)]
    return []


def sandbox_command(
    candidate_root: Path, request_id: str, program: Sequence[str] | None = None
) -> list[str]:
    """The sandboxed run of a parser over the candidate: `haproxy -c` unless told.

    The WAF engine's check runs in the same sandbox, as a second unit: it reads
    the same unreviewed candidate, and nothing about it needs more.
    """

    suffix = "" if program is None else ("-dns" if program[0] == DNSDIST else "-waf")
    unit = f"haprion-validation-{request_id.replace('-', '')}{suffix}"
    properties = (
        "NoNewPrivileges=yes",
        "PrivateDevices=yes",
        "PrivateNetwork=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectKernelLogs=yes",
        "ProtectControlGroups=yes",
        "ProtectClock=yes",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "RestrictAddressFamilies=AF_UNIX",
        "IPAddressDeny=any",
        "UMask=0077",
        #
        # An empty root, with exactly what parsing a configuration needs bound
        # back in. This used to be a denylist of top-level directories, which
        # had two problems with one cause: it was incomplete by construction -
        # a directory created next year is not in a list written this year - and
        # the list had to name the deployment's own trees, in a repository that
        # is meant to be public.
        #
        # An allowlist has neither problem. A path that is not listed does not
        # exist inside the unit, whatever it is called. It is the same move
        # already made for /etc below, for the same reason, and it is strictly
        # tighter than the list it replaces.
        #
        # /usr carries the binary and its shared libraries. The merged-usr
        # symlinks are bound separately: a tmpfs root has none of them, and the
        # dynamic loader path compiled into the binary is absolute. They are
        # optional binds because a system without merged /usr has them inside
        # /usr already.
        #
        # Measured 2026-08-27 against both production clusters, including the
        # one whose configuration names two certificates and a live map file:
        # `haproxy -c` passes identically under this and under the denylist.
        #
        "TemporaryFileSystem=/:ro",
        "BindReadOnlyPaths=/usr",
        "BindReadOnlyPaths=-/lib",
        "BindReadOnlyPaths=-/lib64",
        "BindReadOnlyPaths=-/bin",
        "BindReadOnlyPaths=-/sbin",
        "TemporaryFileSystem=/tmp",
        "TemporaryFileSystem=/run",
        #
        # Where `shm-stats-file` keeps the counters (N3, 2026-10-09). A check
        # opens that file too - creates it, maps it and writes - and refuses
        # the configuration when it cannot, measured on 3.4.6. Its own empty
        # directory here, so the check finds the path the nodes use and the
        # file it makes dies with the sandbox.
        #
        f"TemporaryFileSystem={SHM_STATS_DIRECTORY}",
        #
        # /etc is replaced rather than hidden. It used to be listed above as
        # inaccessible, and that measured wrong against a real cluster
        # configuration on 2026-08-26: every production config names
        # "user haproxy", "group haproxy" and seven errorfile paths under
        # /etc/haproxy/errors, so haproxy -c failed on all nine before it ever
        # looked at what was being validated.
        #
        # An inaccessible /etc cannot be poked a hole in - the overmount has no
        # paths inside it to bind onto - so the fix is an empty /etc containing
        # exactly what parsing a configuration needs. That is strictly tighter
        # than hiding /etc would have been if it had worked: nothing else in
        # /etc exists at all, including /etc/haproxy/certs, which is what the
        # substituted certificates under /candidate/certs are there to replace.
        #
        # The errorfiles are the manager host's copies, which is what the shell
        # path validated against too. They are read-only and world readable.
        #
        "TemporaryFileSystem=/etc",
        "BindReadOnlyPaths=-/etc/ld.so.cache",
        "BindReadOnlyPaths=/etc/passwd",
        "BindReadOnlyPaths=/etc/group",
        "BindReadOnlyPaths=-/etc/nsswitch.conf",
        "BindReadOnlyPaths=/etc/haproxy/errors",
        #
        # The system trust store, for the same reason the errorfiles are here:
        # a configuration names it, so parsing fails without it. A backend that
        # verifies its pool writes `ca-file @system-ca`, which OpenSSL resolves
        # through OPENSSLDIR - and on this host that is a symlink into
        # /etc/ssl/certs, which an empty /etc does not contain. Measured
        # 2026-09-04: `unable to load @system-ca`, on every server line.
        #
        # Optional, like the other host-shaped paths: a machine that keeps its
        # trust store elsewhere validates a configuration that does not name
        # one, and a missing bind must not stop that.
        #
        "BindReadOnlyPaths=-/etc/ssl/certs",
        "BindReadOnlyPaths=-/etc/ssl/openssl.cnf",
        f"BindReadOnlyPaths={candidate_root}:/candidate",
        #
        # Its own time limit, inside the caller's: a client that gave up does
        # not stop the parser (security review 26-10-13, S07). And memory and
        # tasks, from what the checks use (measured 26-10-15 on both clusters'
        # candidates): haproxy 17-18 MB, 38 MB with three 1 MiB maps; the WAF
        # engine 41-44 MB; dnsdist 4 MB; one task each, the engine four at two
        # Go threads. No swap, so a parser that runs away is stopped rather
        # than slowed until the time limit.
        #
        f"RuntimeMaxSec={RUNTIME_SECONDS}",
        f"MemoryMax={MEMORY_MAX}",
        "MemorySwapMax=0",
        f"TasksMax={TASKS_MAX}",
        #
        # Go starts a thread per core, so the engine's task count followed the
        # host - nine on eight cores. Two are plenty for a check of a tenth of
        # a second, and make the limit above the same on any manager.
        #
        *((f"Environment=GOMAXPROCS={WAF_GOMAXPROCS}",) if suffix == "-waf" else ()),
    )
    command = [
        "/usr/bin/systemd-run",
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--service-type=exec",
        f"--unit={unit}",
    ]
    for value in properties:
        command.extend(("--property", value))
    if program is not None:
        command.extend(program)
        return command
    command.extend(
        (
            HAPROXY,
            "-c",
            *peer_arguments(candidate_root / "conf.d"),
            #
            # Ignore server address resolution failures. The sandbox has no
            # network at all, so every `server` line naming a hostname would
            # otherwise fail here - measured against a production cluster on
            # 2026-08-26, where a single backend server named by hostname was
            # enough to fail the whole validation.
            #
            # Nothing is lost by this that was ever worth much. The shell path
            # resolved those names on the MANAGER, which says nothing about
            # whether the nodes can resolve them - and the nodes check for
            # themselves: haprion-pull-deploy runs `haproxy -c` before the
            # symlink swap and again after it, and rolls back if either fails.
            # That check runs with the node's own resolver, which is the only
            # one whose answer matters.
            #
            # The alternative was to give this sandbox a network, and a parser
            # reading an unreviewed candidate is exactly what should not have
            # one.
            #
            "-dr",
            "-f",
            "/candidate/haproxy.cfg",
            "-f",
            "/candidate/conf.d",
        )
    )
    return command


#
# The oldest HAProxy the generated configuration is written for. It must
# match `HAPROXY_BRANCH` in install/lib.sh, which installs it; a test holds
# the two together.
#
REQUIRED_BRANCH = (3, 4)


def too_old(version: str | None) -> str | None:
    """Why this host's HAProxy cannot validate, or None.

    An unreadable version is left to `haproxy -c` itself: refusing on what
    could not be read would stop every publish over a parsing detail, and the
    check that follows says what is wrong in its own words.
    """

    found = haproxy_versions.upstream(version)
    if found is None:
        return None
    parts = tuple(int(part) for part in found.split(".")[:2])
    if parts >= REQUIRED_BRANCH:
        return None
    required = ".".join(str(part) for part in REQUIRED_BRANCH)
    return (
        f"HAProxy {found} on the management host is older than {required}, which the "
        "generated configuration is written for. Run install step 01 again: it installs "
        f"{required} from the HAProxy maintainer's repository."
    )


def validate_in_sandbox(
    candidate_root: Path,
    request_id: str,
    version: Callable[[], str | None] = validator_version,
) -> ValidationResult:
    #
    # Said in words before HAProxy says it as an unknown keyword (Fas 18,
    # 26-10-15: Debian's own 3.0 refused `shm-stats-file`).
    #
    reason = too_old(version())
    if reason is not None:
        return ValidationResult(False, reason)
    result = _sandboxed(sandbox_command(candidate_root, request_id))
    if result.valid and (candidate_root / WAF_TARGET / "coraza.yaml").exists():
        result = _then(result, _waf_engine(candidate_root, request_id))
    if result.valid and (candidate_root / DNS_TARGET / "dnsdist.conf").exists():
        result = _then(result, _dnsdist(candidate_root, request_id))
    return result


def _then(first: ValidationResult, second: ValidationResult) -> ValidationResult:
    return ValidationResult(
        valid=second.valid, diagnostics=(first.diagnostics + second.diagnostics)[:16384]
    )


def _waf_engine(candidate_root: Path, request_id: str) -> ValidationResult:
    if not Path(WAF_ENGINE).is_file():
        return ValidationResult(
            valid=False,
            diagnostics="the candidate carries WAF rules, and the WAF engine is not installed "
            "on the manager: install the haprion-coraza-spoa package",
        )
    return _sandboxed(
        sandbox_command(
            candidate_root,
            request_id,
            (WAF_ENGINE, "-validate", "-config", f"/candidate/{WAF_TARGET}/coraza.yaml"),
        )
    )


def _dnsdist(candidate_root: Path, request_id: str) -> ValidationResult:
    if not Path(DNSDIST).is_file():
        return ValidationResult(
            valid=False,
            diagnostics="the candidate carries a dns listener, and dnsdist is not installed on "
            "the manager: run the manager's preparation again, which installs it",
        )
    checked = _sandboxed(
        sandbox_command(
            candidate_root,
            request_id,
            (DNSDIST, "--check-config", "-C", f"/candidate/{DNS_TARGET}/dnsdist.conf"),
        )
    )
    if checked.valid and any(word in checked.diagnostics for word in DNSDIST_REFUSALS):
        return ValidationResult(
            valid=False,
            diagnostics=checked.diagnostics
            + "\nrefused: dnsdist warned about the dns listener's configuration\n",
        )
    return checked


def _sandboxed(command: list[str]) -> ValidationResult:
    finished = _run_unit(command)
    if finished is None:
        return ValidationResult(
            valid=False,
            diagnostics=f"refused: the check did not finish within {CLIENT_SECONDS} s\n",
        )
    returncode, diagnostics = finished
    return ValidationResult(valid=returncode == 0, diagnostics=diagnostics)


def _run_unit(command: list[str]) -> tuple[int, str] | None:
    """Run one sandboxed check: its exit code and output, or None past the deadline.

    The output is kept to DIAGNOSTICS_BYTES as it arrives rather than collected
    whole and cut afterwards: a parser that floods it must not grow this
    process. Past the deadline the unit itself is stopped - the client giving
    up stops nothing else (security review 26-10-13, S07).
    """

    unit = next(arg.removeprefix("--unit=") for arg in command if arg.startswith("--unit="))
    process = subprocess.Popen(  # noqa: S603 - argv is entirely constructed above
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={"PATH": "/usr/sbin:/usr/bin"},
    )
    assert process.stdout is not None  # noqa: S101 - PIPE was asked for
    kept = bytearray()
    deadline = time.monotonic() + CLIENT_SECONDS
    try:
        with process.stdout:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, CLIENT_SECONDS)
                ready, _, _ = select.select([process.stdout], [], [], remaining)
                if not ready:
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                kept += chunk[: max(0, DIAGNOSTICS_BYTES - len(kept))]
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        subprocess.run(  # noqa: S603 - fixed argv, a unit name this module made
            ["/usr/bin/systemctl", "stop", f"{unit}.service"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=15,
            check=False,
        )
        return None
    return returncode, kept.decode("utf-8", "replace")


type SandboxValidator = Callable[[Path, str], ValidationResult]


def read_validation_certificate(path: Path, *, require_secure: bool) -> bytes:
    """The certificate the sandbox substitutes for the real ones.

    Root-only by construction: it is the one secret this path touches, and a
    candidate that could name a readable copy of it could name anything.
    """

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ConfigError(
            f"cannot stat validation certificate: {exc}", exit_code=exit_codes.UNAVAILABLE
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ConfigError(
            "validation certificate must be a regular non-symlink", exit_code=exit_codes.UNAVAILABLE
        )
    if require_secure and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise ConfigError(
            "validation certificate must be mode 600 root:root", exit_code=exit_codes.UNAVAILABLE
        )
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ConfigError(
            f"cannot read validation certificate: {exc}", exit_code=exit_codes.UNAVAILABLE
        ) from exc


def prepare_run_root(path: Path, *, require_secure: bool) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ConfigError(
            "validation run root must be a non-symlink directory", exit_code=exit_codes.UNAVAILABLE
        )
    if require_secure and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise ConfigError(
            "validation run root must be mode 700 root:root", exit_code=exit_codes.UNAVAILABLE
        )


def validate_candidate(
    candidate: Candidate,
    *,
    run_root: Path,
    certificate_ids: Sequence[str],
    validation_certificate: bytes,
    request_id: str,
    validator: SandboxValidator = validate_in_sandbox,
    authority_ids: Sequence[str] = (),
) -> ValidationResult:
    """Materialize the candidate somewhere private and run the sandbox on it.

    The directory is removed whether validation passed, failed or raised: a
    candidate left on disk is a copy of the substituted certificate left on
    disk with it.
    """

    with tempfile.TemporaryDirectory(prefix="request-", dir=run_root) as temporary:
        candidate_root = Path(temporary) / "candidate"
        materialize_candidate(
            candidate,
            candidate_root,
            certificate_ids=certificate_ids,
            validation_certificate=validation_certificate,
            authority_ids=authority_ids,
        )
        return validator(candidate_root, request_id)
