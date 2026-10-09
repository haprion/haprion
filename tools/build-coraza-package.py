#!/usr/bin/env python3
"""Build the WAF engine and rule set packages from pinned upstream sources.

Two Debian packages, one tool (B229):

    coraza  haprion-coraza-spoa  the Coraza SPOA engine, built from source
                                         with a pinned Go; installed on the manager
                                         (validation only) and on every node
    crs     haprion-crs          the OWASP Core Rule Set files; installed on
                                         the manager only - releases carry the rules
                                         to the nodes (managed/waf)

Every input is pinned by SHA-256 below, the Go toolchain by version, and the Go
modules by the source's own go.sum. The same inputs give the same package bytes:
file times are clamped to the newest time in the source archive, owners are
root, and the Go build drops paths and build IDs. Build twice and compare.

Before the engine is built, govulncheck (pinned by version) reads the source
against the Go vulnerability database as it stands that day, and the build is
refused if the engine can reach a known vulnerability in its modules or in the
pinned Go's standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haproxy_mgmt.debian_package import package, write  # noqa: E402 - the path above comes first

#
# Each package counts its own revision: it moves when our part of the package
# changes (the unit, the build), not when the other package does.
#
CORAZA_REVISION = "6"
CRS_REVISION = "2"
#
# The names the packages had before the product was renamed (B266). Each
# conflicts with and replaces its old name, so installing it removes the old
# package that owns the same files instead of failing on them.
#
RENAMED = {
    "haprion-coraza-spoa": "haproxy-manager-coraza-spoa",
    "haprion-crs": "haproxy-manager-crs",
}
GO_VERSION = "go1.26.9"
GOVULNCHECK_VERSION = "v1.8.0"
MAX_SOURCE_BYTES = 64 * 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}")
UNIT = "coraza-spoa.service"
LIBEXEC = "usr/lib/haprion-coraza-spoa"
#
# The engine logs one JSON line per matched rule, and a line carries the
# matched value whole - as long as the request field it came from. rsyslog
# cuts at 8 KiB and the default journal splits at 48 KiB, so the engine logs
# into a journal of its own, with lines long enough for any field it can be
# handed and the traffic log's retention. Measured on a node (26-10-03): a
# 150 000 character line arrives whole, and nothing reaches rsyslog.
#
JOURNAL_NAMESPACE = "haprion-waf"
JOURNAL_CONF = f"""\
# Installed by haprion-coraza-spoa. Override in
# /etc/systemd/journald@{JOURNAL_NAMESPACE}.conf.d/ rather than editing this file.
[Journal]
Storage=persistent
LineMax=256K
MaxRetentionSec=14day
SystemMaxUse=512M
"""
#
# The engine compiles every object's rules before it opens its port: about a
# tenth of a second for one object and three tenths for twenty (measured on
# two cores, 26-10-03). Started as `simple`, systemd would call it up the moment
# the process exists, and HAProxy - ordered after it - would take requests the
# engine cannot yet answer. This holds the start until the port listens. It
# reads /proc/net, so it needs nothing the sandbox does not already give.
#
WAIT_LISTENING = """\
#!/bin/sh
#
# wait-listening CONFIG [SECONDS]: return once something listens on the TCP
# port of CONFIG's `bind:` line, or fail after SECONDS (default 60).
#
set -eu
config="$1"
limit="${2:-60}"
port="$(sed -n 's/^bind:[[:space:]]*[^[:space:]]*:\\([0-9][0-9]*\\)[[:space:]]*$/\\1/p' "$config" | head -n 1)"
if [ -z "$port" ]; then
    echo "no bind port in $config" >&2
    exit 1
fi
hex="$(printf '%04X' "$port")"
# A kernel booted with ipv6.disable=1 has no tcp6, and awk stops at the first
# file it cannot open - a node with IPv6 off never saw the engine listen
# (26-10-03). Read only the tables there are.
tables=""
for table in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$table" ] && tables="$tables $table"
done
if [ -z "$tables" ]; then
    echo "no socket table to read under /proc/net" >&2
    exit 1
fi
tries=$((limit * 10))
while [ "$tries" -gt 0 ]; do
    # shellcheck disable=SC2086 # the table list splits on purpose
    if awk -v want=":$hex" '$4 == "0A" && substr($2, length($2) - 4) == want { found = 1 }
                            END { exit !found }' $tables 2>/dev/null; then
        exit 0
    fi
    sleep 0.1
    tries=$((tries - 1))
done
echo "the engine did not listen on port $port within $limit seconds" >&2
exit 1
"""


@dataclass(frozen=True)
class Source:
    file: str
    sha256: str
    top: str
    version: str
    url: str


CORAZA = Source(
    file="coraza-spoa-0.9.0.tar.gz",
    sha256="4cb1a39b0f6d8d44ef570b2668da060826206139d7c24d26442852cb99ac44fb",
    top="coraza-spoa-0.9.0",
    version="0.9.0",
    url="https://github.com/corazawaf/coraza-spoa/archive/refs/tags/v0.9.0.tar.gz",
)
#
# The LTS line (B227). The minimal archive is signed by the CRS release key,
# fingerprint 3600 6F0E 0BA1 6783 2158 8211 38EE ACA1 AB8A 6E72; the signature
# was checked once, when this digest was pinned.
#
CRS = Source(
    file="coreruleset-4.25.1-minimal.tar.gz",
    sha256="e314bc5b64a268ae4264822bc93db24eb93c5eb648ff80aed96b23f3fce2c701",
    top="coreruleset-4.25.1",
    version="4.25.1",
    url="https://github.com/coreruleset/coreruleset/releases/download/v4.25.1/"
    "coreruleset-4.25.1-minimal.tar.gz",
)

#
# The engine reads a configuration only a release provides, so the unit stays
# inert until one does; the node's deploy script enables and disables it with
# the release (B230). DynamicUser gives the process an account systemd creates
# at start and forgets at stop - nothing to add, nothing to clean up.
#
#
# The engine's memory is held to a share of the node's, not to a fixed size:
# systemd takes a percentage of the memory the kernel sees when it loads the
# unit, so a node given more memory and restarted gives the engine more too.
# HAProxy keeps at least 60 %. Above MemoryHigh the engine is slowed and made
# to give memory back; at MemoryMax it is killed and restarted, and each
# object's on-engine-error setting decides what its traffic gets meanwhile
# (B240, 26-10-03). Measured: 35-52 MB for one object on a 1 GB node, 122 MB
# for twenty.
#
UNIT_FILE = f"""\
[Unit]
Description=Coraza SPOA web application firewall engine for HAProxy
Documentation=https://github.com/corazawaf/coraza-spoa
After=network.target
Before=haproxy.service
ConditionPathExists=/etc/haproxy/waf/coraza.yaml

[Service]
Type=simple
ExecStart=/usr/sbin/coraza-spoa -config /etc/haproxy/waf/coraza.yaml
ExecStartPost=/{LIBEXEC}/wait-listening /etc/haproxy/waf/coraza.yaml
ExecReload=/bin/kill -HUP $MAINPID
TimeoutStartSec=90
LogNamespace={JOURNAL_NAMESPACE}
Restart=on-failure
RestartSec=2s
DynamicUser=yes
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
MemoryHigh=30%
MemoryMax=40%

[Install]
WantedBy=multi-user.target
"""

#
# An upgrade replaces the binary under a running engine, which keeps the old
# one until restarted: try-restart restarts it only if it runs. Removal stops
# it; what HAProxy then does is the object's on_engine_error (B232).
#
POSTINST = f"""\
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    if [ "$1" = configure ] && [ -n "$2" ]; then
        systemctl try-restart {UNIT}
    fi
fi
"""
PRERM = f"""\
#!/bin/sh
set -e
if [ -d /run/systemd/system ] && [ "$1" = remove ]; then
    systemctl disable --now {UNIT} || true
fi
"""
POSTRM = """\
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
"""


def verified(directory: Path, source: Source) -> Path:
    """The source archive, refused unless its bytes are the pinned ones."""
    path = directory / source.file
    if DIGEST.fullmatch(source.sha256) is None:
        raise ValueError("invalid pinned digest")
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError(f"{source.file} exceeds its size limit")
    if hashlib.sha256(path.read_bytes()).hexdigest() != source.sha256:
        raise ValueError(f"{source.file} does not match its pinned SHA-256")
    return path


def unpack(archive: Path, source: Source, into: Path) -> tuple[Path, int]:
    """Unpack under the data filter; return the tree and its newest file time."""
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        if not members or any(
            not (m.name == source.top or m.name.startswith(source.top + "/")) for m in members
        ):
            raise ValueError(f"{source.file} must hold exactly one {source.top}/ tree")
        epoch = max(int(m.mtime) for m in members)
        tar.extractall(into, filter="data")
    return into / source.top, epoch


def go_environment(go_root: Path, work: Path) -> dict[str, str]:
    return {
        "PATH": f"{go_root / 'bin'}:/usr/bin:/bin",
        "HOME": str(work / "home"),
        "GOROOT": str(go_root),
        "GOPATH": str(work / "gopath"),
        "GOCACHE": str(work / "gocache"),
        "GOMODCACHE": str(work / "gomodcache"),
        "GOTOOLCHAIN": "local",
        "GOFLAGS": "-mod=readonly",
        "GOOS": "linux",
        "GOARCH": "amd64",
        "CGO_ENABLED": "0",
        "GOPROXY": "https://proxy.golang.org",
        "GOSUMDB": "sum.golang.org",
    }


def vulnerability_check(tree: Path, go_root: Path, govulncheck: Path, work: Path) -> str:
    """Refuse a source from which the engine reaches a known vulnerability.

    govulncheck's default reports what the engine's code can call, in its
    modules and in the standard library of the Go that runs it; a module that
    is required but never reached is not a finding. Exit 3 means findings,
    anything else but 0 means the check itself failed - both refuse the build.
    Returns the report, which names the database's date.
    """
    go_root = go_root.resolve()  # the check runs inside the source tree
    environment = go_environment(go_root, work)
    scanner = subprocess.run(  # noqa: S603 - pinned scanner, fixed arguments
        [str(govulncheck.resolve()), "-version"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        timeout=120,
    ).stdout
    if f"Scanner: govulncheck@{GOVULNCHECK_VERSION}\n" not in scanner:
        raise ValueError(f"govulncheck is not {GOVULNCHECK_VERSION}")
    done = subprocess.run(  # noqa: S603 - pinned scanner, fixed arguments
        [str(govulncheck.resolve()), "./..."],
        capture_output=True,
        text=True,
        cwd=tree,
        env=environment,
        timeout=1800,
    )
    report = (done.stdout + done.stderr).strip()
    if done.returncode == 3:
        raise ValueError(f"the engine reaches known vulnerabilities:\n{report}")
    if done.returncode != 0:
        raise ValueError(f"govulncheck failed (exit {done.returncode}):\n{report}")
    return f"{scanner.strip()}\n{report}"


def go_build(tree: Path, go_root: Path, work: Path, version: str) -> Path:
    """Build the engine statically with exactly the pinned Go."""
    go_root = go_root.resolve()  # the build runs inside the source tree
    go = go_root / "bin" / "go"
    environment = go_environment(go_root, work)
    toolchain = subprocess.run(  # noqa: S603 - pinned toolchain, fixed arguments
        [str(go), "env", "GOVERSION"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    ).stdout.strip()
    if toolchain != GO_VERSION:
        raise ValueError(f"Go is {toolchain or 'unknown'}, the package is pinned to {GO_VERSION}")
    output = work / "coraza-spoa"
    subprocess.run(  # noqa: S603 - pinned toolchain, fixed arguments
        [
            str(go),
            "build",
            "-trimpath",
            "-buildvcs=false",
            f"-ldflags=-buildid= -X main.version=v{version}",
            "-o",
            str(output),
            ".",
        ],
        check=True,
        cwd=tree,
        env=environment,
        timeout=1800,
    )
    if not output.read_bytes()[:4] == b"\x7fELF":
        raise ValueError("the engine build did not produce an ELF binary")
    return output


def build_coraza(
    source_dir: Path,
    go_root: Path,
    output_dir: Path,
    *,
    govulncheck: Path | None = None,
    source: Source = CORAZA,
    built: Path | None = None,
) -> Path:
    """`built` skips the check and the Go build - for tests, which have neither network nor Go."""
    archive = verified(source_dir, source)
    with tempfile.TemporaryDirectory(prefix="coraza-package-") as directory:
        work = Path(directory)
        tree, epoch = unpack(archive, source, work / "src")
        if built is None:
            if govulncheck is None:
                raise ValueError("building the engine needs govulncheck")
            print(vulnerability_check(tree, go_root, govulncheck, work), file=sys.stderr)
        binary = built or go_build(tree, go_root, work, source.version)
        root = work / "root"
        doc = "usr/share/doc/haprion-coraza-spoa"
        write(root, "usr/sbin/coraza-spoa", binary.read_bytes(), 0o755)
        write(root, f"usr/lib/systemd/system/{UNIT}", UNIT_FILE.encode(), 0o644)
        write(root, f"{LIBEXEC}/wait-listening", WAIT_LISTENING.encode(), 0o755)
        write(
            root,
            f"usr/lib/systemd/journald@{JOURNAL_NAMESPACE}.conf.d/haprion.conf",
            JOURNAL_CONF.encode(),
            0o644,
        )
        write(root, f"{doc}/copyright", (tree / "LICENSE").read_bytes(), 0o644)
        write(
            root,
            f"{doc}/BUILD",
            (
                f"source: {source.url}\nsource_sha256: {source.sha256}\ngo: {GO_VERSION}\n"
                f"flags: CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags='-buildid= -X main.version=v{source.version}'\n"
                "rules: none - the embedded rule set is not used; releases carry the CRS\n"
            ).encode(),
            0o644,
        )
        for name, script in (("postinst", POSTINST), ("prerm", PRERM), ("postrm", POSTRM)):
            write(root, f"DEBIAN/{name}", script.encode(), 0o755)
        return package(
            root,
            {
                "Package": "haprion-coraza-spoa",
                "Version": f"{source.version}-{CORAZA_REVISION}",
                "Architecture": "amd64",
                "Conflicts": RENAMED["haprion-coraza-spoa"],
                "Replaces": RENAMED["haprion-coraza-spoa"],
                "Section": "net",
                "Priority": "optional",
                "Homepage": "https://github.com/corazawaf/coraza-spoa",
                "Description": "Coraza SPOA web application firewall engine for HAProxy\n"
                " Built by Haprion from the pinned upstream source. The rules\n"
                " arrive with each published cluster release.",
            },
            output_dir,
            epoch,
        )


def build_crs(source_dir: Path, output_dir: Path, *, source: Source = CRS) -> Path:
    archive = verified(source_dir, source)
    with tempfile.TemporaryDirectory(prefix="crs-package-") as directory:
        work = Path(directory)
        tree, epoch = unpack(archive, source, work / "src")
        root = work / "root"
        share = "usr/share/haprion/crs"
        write(
            root,
            f"{share}/crs-setup.conf.example",
            (tree / "crs-setup.conf.example").read_bytes(),
            0o644,
        )
        rules = sorted(
            p for p in (tree / "rules").iterdir() if p.suffix in {".conf", ".data", ".example"}
        )
        if not any(p.suffix == ".conf" for p in rules):
            raise ValueError("the rule set holds no rules")
        for path in rules:
            if not path.is_file():
                raise ValueError(f"{path.name} is not a regular file")
            write(root, f"{share}/rules/{path.name}", path.read_bytes(), 0o644)
        write(
            root,
            "usr/share/doc/haprion-crs/copyright",
            (tree / "LICENSE").read_bytes(),
            0o644,
        )
        write(root, f"{share}/VERSION", f"{source.version}\n".encode(), 0o644)
        return package(
            root,
            {
                "Package": "haprion-crs",
                "Version": f"{source.version}-{CRS_REVISION}",
                "Architecture": "all",
                "Conflicts": RENAMED["haprion-crs"],
                "Replaces": RENAMED["haprion-crs"],
                "Section": "net",
                "Priority": "optional",
                "Homepage": "https://coreruleset.org",
                "Description": "OWASP Core Rule Set for Haprion\n"
                " The rule files the manager copies into each published cluster release.",
            },
            output_dir,
            epoch,
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("package", choices=("coraza", "crs"))
    parser.add_argument(
        "--source-dir", type=Path, required=True, help="directory holding the pinned archive"
    )
    parser.add_argument("--go-root", type=Path, help=f"a {GO_VERSION} toolchain (coraza only)")
    parser.add_argument(
        "--govulncheck",
        type=Path,
        help=f"a govulncheck {GOVULNCHECK_VERSION} binary (coraza only)",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.package == "coraza":
            if args.go_root is None or args.govulncheck is None:
                parser.error("coraza needs --go-root and --govulncheck")
            target = build_coraza(
                args.source_dir, args.go_root, args.output_dir, govulncheck=args.govulncheck
            )
        else:
            target = build_crs(args.source_dir, args.output_dir)
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        parser.exit(1, f"package build failed: {exc}\n")
    print(f"{hashlib.sha256(target.read_bytes()).hexdigest()}  {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
