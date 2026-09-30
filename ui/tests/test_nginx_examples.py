"""The nginx examples: request bodies stay in memory (review 2026-09-28 F09), and a proxy
in front is believed about the client only when the answers file names it (Fas 16 punkt 5)."""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ("haproxy-ui.nginx.example", "haproxy-ui-dev.nginx.example")


def directive(text: str, name: str) -> list[str]:
    return re.findall(rf"^\s*{name}\s+(\S+);", text, re.MULTILINE)


class RequestBodiesStayInMemory(unittest.TestCase):
    def test_the_buffer_holds_the_largest_body_nginx_accepts(self) -> None:
        """A certificate import carries a private key; nginx must not spool it to disk."""

        for name in EXAMPLES:
            with self.subTest(example=name):
                text = (ROOT / "install/platform/examples" / name).read_text()
                self.assertEqual(directive(text, "client_max_body_size"), ["1m"])
                self.assertEqual(directive(text, "client_body_buffer_size"), ["1m"])
                self.assertEqual(directive(text, "client_body_in_file_only"), [])


NGINX = shutil.which("nginx") or "/usr/sbin/nginx"
SNIPPET = "/etc/nginx/snippets/haproxy-manager-real-ip.conf"


def render_real_ip(trusted: str) -> subprocess.CompletedProcess[str]:
    """The installer's own rendering, as step 05 runs it."""

    return subprocess.run(  # noqa: S603 - fixed interpreter, the repository's own library
        [
            "/bin/bash",
            "-c",
            'source "$1"; render_real_ip "$2"',
            "_",
            str(ROOT / "install/lib.sh"),
            trusted,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


class TheSiteIncludesWhatStepFiveWrites(unittest.TestCase):
    def test_the_site_and_the_step_name_one_file(self) -> None:
        site = (ROOT / "install/platform/examples/haproxy-ui.nginx.example").read_text()
        step = (ROOT / "install/platform/05-platform-nginx").read_text()
        self.assertEqual(directive(site, "include").count(SNIPPET), 1)
        self.assertIn(f"install_file {SNIPPET} ", step)


class RenderingTheTrustedProxies(unittest.TestCase):
    def test_nothing_named_believes_nobody(self) -> None:
        rendered = render_real_ip("")
        self.assertEqual(rendered.returncode, 0)
        self.assertNotIn("set_real_ip_from", rendered.stdout)
        self.assertNotIn("real_ip_header", rendered.stdout)

    def test_anything_but_an_address_or_a_bounded_network_is_refused(self) -> None:
        for value in ("proxy.example.com", "0.0.0.0/0", "::/0", "192.0.2.10;", "*", "192.0.2.300"):
            with self.subTest(value=value):
                self.assertNotEqual(render_real_ip(f"192.0.2.10 {value}").returncode, 0)


@unittest.skipUnless(Path(NGINX).exists(), "nginx is not installed where the tests run")
class ARealNginxBelievesOnlyTheProxy(unittest.TestCase):
    """What the snippet makes nginx do, measured on a real nginx rather than read."""

    def serve(self, trusted: str) -> int:
        rendered = render_real_ip(trusted)
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (root / "real-ip.conf").write_text(rendered.stdout)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        temporary = " ".join(
            f"{kind}_temp_path {root / kind};"
            for kind in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
        )
        (root / "nginx.conf").write_text(
            f"""
pid {root / "nginx.pid"};
error_log {root / "error.log"};
events {{ worker_connections 16; }}
http {{
    access_log off;
    {temporary}
    server {{
        listen 127.0.0.1:{port};
        include {root / "real-ip.conf"};
        location / {{ default_type text/plain; return 200 "$remote_addr"; }}
    }}
}}
"""
        )
        process = subprocess.Popen(  # noqa: S603 - the installed nginx, on a configuration written here
            [
                NGINX,
                "-p",
                str(root),
                "-e",
                str(root / "error.log"),
                "-c",
                str(root / "nginx.conf"),
                "-g",
                "daemon off;",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        if process.stderr is not None:
            self.addCleanup(process.stderr.close)
        self.addCleanup(process.wait, 10)
        self.addCleanup(process.terminate)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail(
                    f"nginx did not start: {process.stderr.read().decode() if process.stderr else ''}"
                )
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return port
            except OSError:
                time.sleep(0.05)
        self.fail("nginx did not listen")

    def seen(self, port: int, forwarded: str | None) -> str:
        request = urllib.request.Request(f"http://127.0.0.1:{port}/")
        if forwarded is not None:
            request.add_header("X-Forwarded-For", forwarded)
        with urllib.request.urlopen(request, timeout=5) as answer:  # noqa: S310 - loopback
            return answer.read().decode()

    def test_a_client_that_is_not_the_proxy_is_known_by_its_own_address(self) -> None:
        port = self.serve("192.0.2.10")
        self.assertEqual(self.seen(port, "198.51.100.7"), "127.0.0.1")

    def test_without_a_proxy_the_header_is_never_believed(self) -> None:
        port = self.serve("")
        self.assertEqual(self.seen(port, "198.51.100.7"), "127.0.0.1")

    def test_the_proxy_names_the_client_and_what_the_client_claimed_is_skipped(self) -> None:
        port = self.serve("127.0.0.1")
        self.assertEqual(self.seen(port, "198.51.100.7"), "198.51.100.7")
        # The client sent 203.0.113.66 itself; the proxy appended the address
        # it actually saw. The last address that is not a proxy is the client.
        self.assertEqual(self.seen(port, "203.0.113.66, 198.51.100.7"), "198.51.100.7")


if __name__ == "__main__":
    unittest.main()
