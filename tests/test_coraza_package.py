"""The WAF packages: pinned inputs, bounded archives, contents and reproducible bytes."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any

TOOLS = Path(__file__).resolve().parents[1] / "tools"


def tool() -> Any:
    spec = importlib.util.spec_from_file_location(
        "build_coraza_package", TOOLS / "build-coraza-package.py"
    )
    assert spec is not None and spec.loader is not None  # noqa: S101 - local test tool must exist
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their module by name
    spec.loader.exec_module(module)
    return module


def archive(path: Path, members: dict[str, bytes], *, mtime: int = 1_700_000_000) -> str:
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = mtime
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def listing(deb: Path) -> dict[str, str]:
    """Path -> 'mode owner' for every member, as dpkg-deb sees it."""
    out = subprocess.run(  # noqa: S603 - fixed reader, test package
        ["/usr/bin/dpkg-deb", "--contents", str(deb)], check=True, capture_output=True, text=True
    ).stdout
    rows = {}
    for line in out.splitlines():
        fields = line.split()
        rows[fields[5].removeprefix(".")] = f"{fields[0]} {fields[1]}"
    return rows


def field(deb: Path, name: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed reader, test package
        ["/usr/bin/dpkg-deb", "--field", str(deb), name], check=True, capture_output=True, text=True
    ).stdout.strip()


class Packages(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = tool()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sources = self.root / "sources"
        self.sources.mkdir()
        self.binary = self.root / "coraza-spoa"
        self.binary.write_bytes(b"\x7fELF example engine")

    def coraza_source(self, members: dict[str, bytes] | None = None) -> Any:
        members = members or {
            "coraza-spoa-9.9.9/main.go": b"package main\n",
            "coraza-spoa-9.9.9/LICENSE": b"example license\n",
        }
        digest = archive(self.sources / "coraza.tar.gz", members)
        return self.tool.Source(
            "coraza.tar.gz", digest, "coraza-spoa-9.9.9", "9.9.9", "https://example.org/c"
        )

    def crs_source(self) -> Any:
        digest = archive(
            self.sources / "crs.tar.gz",
            {
                "coreruleset-9.9.9/LICENSE": b"example license\n",
                "coreruleset-9.9.9/crs-setup.conf.example": b"# setup\n",
                "coreruleset-9.9.9/rules/REQUEST-901-INITIALIZATION.conf": b"# rules\n",
                "coreruleset-9.9.9/rules/sql-errors.data": b"error\n",
                "coreruleset-9.9.9/docs/README.md": b"docs\n",
                "coreruleset-9.9.9/plugins/README.md": b"plugins\n",
            },
        )
        return self.tool.Source(
            "crs.tar.gz", digest, "coreruleset-9.9.9", "9.9.9", "https://example.org/r"
        )

    def build_coraza(self, source: Any, output: str) -> Path:
        out = self.root / output
        out.mkdir()
        return Path(
            self.tool.build_coraza(self.sources, self.root, out, source=source, built=self.binary)
        )

    def test_the_engine_package_holds_the_binary_the_unit_and_the_licence(self) -> None:
        deb = self.build_coraza(self.coraza_source(), "out")
        self.assertEqual(deb.name, "haprion-coraza-spoa_9.9.9-4_amd64.deb")
        rows = listing(deb)
        self.assertEqual(rows["/usr/sbin/coraza-spoa"], "-rwxr-xr-x root/root")
        self.assertEqual(
            rows["/usr/lib/systemd/system/coraza-spoa.service"], "-rw-r--r-- root/root"
        )
        self.assertIn("/usr/share/doc/haprion-coraza-spoa/copyright", rows)
        self.assertEqual(
            rows["/usr/lib/haprion-coraza-spoa/wait-listening"], "-rwxr-xr-x root/root"
        )
        self.assertEqual(
            rows["/usr/lib/systemd/journald@haprion-waf.conf.d/haprion.conf"],
            "-rw-r--r-- root/root",
        )
        self.assertEqual(field(deb, "Version"), "9.9.9-4")
        self.assertEqual(field(deb, "Architecture"), "amd64")

    def test_the_unit_waits_for_a_release_and_runs_without_privilege(self) -> None:
        unit = self.tool.UNIT_FILE
        for line in (
            "ConditionPathExists=/etc/haproxy/waf/coraza.yaml",
            "ExecStart=/usr/sbin/coraza-spoa -config /etc/haproxy/waf/coraza.yaml",
            "ExecReload=/bin/kill -HUP $MAINPID",
            "DynamicUser=yes",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "ProtectSystem=strict",
            # HAProxy starts after the engine, and the engine counts as started
            # only once its port listens.
            "Before=haproxy.service",
            "ExecStartPost=/usr/lib/haprion-coraza-spoa/wait-listening "
            "/etc/haproxy/waf/coraza.yaml",
            "LogNamespace=haprion-waf",
            # A share of the node's memory, not a fixed size (B240).
            "MemoryHigh=30%",
            "MemoryMax=40%",
        ):
            self.assertIn(line + "\n", unit)
        self.assertIn("LineMax=256K\n", self.tool.JOURNAL_CONF)
        self.assertIn("MaxRetentionSec=14day\n", self.tool.JOURNAL_CONF)
        # The package never enables the engine; the node's deploy does (B230).
        for script in (self.tool.POSTINST, self.tool.PRERM, self.tool.POSTRM):
            self.assertNotIn("enable --now", script)

    def wait_listening(
        self, bind: str, *extra: str, tables: tuple[str, str] = ("/proc/net/tcp", "/proc/net/tcp6")
    ) -> subprocess.CompletedProcess[str]:
        script = self.root / "wait-listening"
        text = self.tool.WAIT_LISTENING
        self.assertIn("for table in /proc/net/tcp /proc/net/tcp6; do", text)
        script.write_text(text.replace("/proc/net/tcp /proc/net/tcp6", " ".join(tables)))
        script.chmod(0o755)
        config = self.root / "coraza.yaml"
        config.write_text(f"# example\n{bind}log_level: info\n")
        return subprocess.run(  # noqa: S603 - the script under test, fixed arguments
            ["/bin/sh", str(script), str(config), *extra],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_the_start_waits_until_the_engine_listens(self) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            done = self.wait_listening(f"bind: 127.0.0.1:{port}\n", "5")
            self.assertEqual(done.returncode, 0, done.stderr)
        with socket.socket() as closed:
            closed.bind(("127.0.0.1", 0))  # bound, never listening
            port = closed.getsockname()[1]
            done = self.wait_listening(f"bind: 127.0.0.1:{port}\n", "1")
        self.assertEqual(done.returncode, 1)
        self.assertIn(f"did not listen on port {port} within 1 seconds", done.stderr)

    def test_the_start_sees_the_engine_on_a_node_without_ipv6(self) -> None:
        # A kernel booted with ipv6.disable=1 has no tcp6 (26-10-03).
        missing = str(self.root / "no-tcp6")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            done = self.wait_listening(
                f"bind: 127.0.0.1:{port}\n", "5", tables=("/proc/net/tcp", missing)
            )
            self.assertEqual(done.returncode, 0, done.stderr)
        done = self.wait_listening("bind: 127.0.0.1:9\n", "1", tables=(missing, missing))
        self.assertEqual(done.returncode, 1)
        self.assertIn("no socket table", done.stderr)

    def test_the_start_fails_without_a_bind_port(self) -> None:
        done = self.wait_listening("")
        self.assertEqual(done.returncode, 1)
        self.assertIn("no bind port", done.stderr)

    def test_the_rule_set_package_holds_rules_and_setup_but_not_docs(self) -> None:
        out = self.root / "out"
        out.mkdir()
        deb = self.tool.build_crs(self.sources, out, source=self.crs_source())
        self.assertEqual(deb.name, "haprion-crs_9.9.9-1_all.deb")
        rows = listing(deb)
        share = "/usr/share/haprion/crs"
        for path in (
            f"{share}/crs-setup.conf.example",
            f"{share}/rules/REQUEST-901-INITIALIZATION.conf",
            f"{share}/rules/sql-errors.data",
            f"{share}/VERSION",
        ):
            self.assertIn(path, rows)
        self.assertFalse(any("/docs/" in p or "/plugins/" in p for p in rows))

    def test_the_same_inputs_give_the_same_bytes(self) -> None:
        source = self.coraza_source()
        first = self.build_coraza(source, "a")
        second = self.build_coraza(source, "b")
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_a_source_that_is_not_the_pinned_one_is_refused(self) -> None:
        source = self.coraza_source()
        (self.sources / "coraza.tar.gz").write_bytes(b"something else")
        with self.assertRaisesRegex(ValueError, "pinned SHA-256"):
            self.build_coraza(source, "out")

    def test_an_archive_with_anything_outside_its_tree_is_refused(self) -> None:
        source = self.coraza_source(
            {"coraza-spoa-9.9.9/LICENSE": b"x", "elsewhere/main.go": b"package main\n"}
        )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.build_coraza(source, "out")

    def test_an_existing_package_is_never_overwritten(self) -> None:
        source = self.coraza_source()
        deb = self.build_coraza(source, "out")
        with self.assertRaisesRegex(ValueError, "exists"):
            self.tool.build_coraza(
                self.sources, self.root, deb.parent, source=source, built=self.binary
            )

    def scanner(self, *, version: str | None = None, exit_code: int = 0) -> Path:
        """A govulncheck stand-in: answers -version, then the scan with a fixed exit."""
        version = version or self.tool.GOVULNCHECK_VERSION
        path = self.root / "govulncheck"
        path.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = -version ]; then\n'
            f"    printf 'Scanner: govulncheck@{version}\\nDB updated: example\\n'\n"
            "    exit 0\n"
            "fi\n"
            'echo "scanned $(pwd) $*"\n'
            f"exit {exit_code}\n"
        )
        path.chmod(0o755)
        return path

    def check(self, scanner: Path) -> str:
        tree = self.root / "tree"
        tree.mkdir(exist_ok=True)
        return str(self.tool.vulnerability_check(tree, self.root, scanner, self.root))

    def test_a_clean_scan_passes_and_names_the_scanner(self) -> None:
        report = self.check(self.scanner())
        self.assertIn(f"Scanner: govulncheck@{self.tool.GOVULNCHECK_VERSION}", report)
        self.assertIn(f"scanned {self.root / 'tree'} ./...", report)

    def test_a_reachable_vulnerability_refuses_the_build(self) -> None:
        with self.assertRaisesRegex(ValueError, "reaches known vulnerabilities"):
            self.check(self.scanner(exit_code=3))

    def test_a_scan_that_fails_refuses_the_build(self) -> None:
        with self.assertRaisesRegex(ValueError, r"govulncheck failed \(exit 1\)"):
            self.check(self.scanner(exit_code=1))

    def test_a_scanner_other_than_the_pinned_one_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "is not"):
            self.check(self.scanner(version="v0.0.1"))

    def test_building_the_engine_needs_the_scanner(self) -> None:
        out = self.root / "out"
        out.mkdir()
        with self.assertRaisesRegex(ValueError, "needs govulncheck"):
            self.tool.build_coraza(self.sources, self.root, out, source=self.coraza_source())

    def test_the_pinned_sources_are_well_formed(self) -> None:
        for source in (self.tool.CORAZA, self.tool.CRS):
            self.assertRegex(source.sha256, "^[0-9a-f]{64}$")
            self.assertIn(source.version, source.file)
            self.assertTrue(source.url.startswith("https://"))


if __name__ == "__main__":
    unittest.main()
