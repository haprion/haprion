"""The nginx examples: request bodies stay in memory (review 2026-09-28 F09), and a proxy
in front is believed about the client only when the answers file names it (Fas 16 punkt 5)."""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ("haprion.nginx.example",)


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
SNIPPET = "/etc/nginx/snippets/haprion-real-ip.conf"


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
        site = (ROOT / "install/platform/examples/haprion.nginx.example").read_text()
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
            port = int(probe.getsockname()[1])
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
            return str(answer.read().decode())

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


def api_location() -> str:
    """The site's `location /api/` block, as written."""

    text = (ROOT / "install/platform/examples" / EXAMPLES[0]).read_text()
    found = re.search(r"^    location /api/ \{\n.*?^    \}\n", text, re.MULTILINE | re.DOTALL)
    if found is None:
        raise AssertionError("the site has no `location /api/` in the shape this reads")
    return found.group(0)


def api_error_locations() -> str:
    """The named locations that answer for nginx on `/api/`, as written."""

    text = (ROOT / "install/platform/examples" / EXAMPLES[0]).read_text()
    found = re.findall(r"^    location @api_\d+ \{\n.*?^    \}\n", text, re.MULTILINE | re.DOTALL)
    if len(found) != 5:
        raise AssertionError("the site has not the five `location @api_<status>` this reads")
    return "".join(found)


@unittest.skipUnless(Path(NGINX).exists(), "nginx is not installed where the tests run")
class TheApiLocationCarriesNoCookie(unittest.TestCase):
    """B416: the API reads no cookie; nginx keeps it so whatever the application does.

    The site's own block, behind a real nginx, in front of a server that
    echoes the cookie it was given and tries to set one.
    """

    def serve(self, *, backend_up: bool = True) -> int:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        backend = root / "backend.sock"
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = int(probe.getsockname()[1])
        location = (api_location() + api_error_locations()).replace(
            "http://unix:/run/haprion-web.sock", f"http://unix:{backend}"
        )
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
    limit_req_zone $binary_remote_addr zone=haprion_api:1m rate=10r/s;
    {
                f'''server {{
        listen unix:{backend};
        location / {{
            add_header Set-Cookie "planted=1; Path=/";
            default_type text/plain;
            return 200 "cookie=[$http_cookie] auth=[$http_authorization]";
        }}
    }}'''
                if backend_up
                else ""
            }
    server {{
        listen 127.0.0.1:{port};
        client_max_body_size 1m;
{location}
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

    def test_a_cookie_is_not_passed_on_and_none_is_set(self) -> None:
        port = self.serve()
        request = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1/token")
        request.add_header("Cookie", "__Host-haprion_ui_session=stolen")
        request.add_header("Authorization", "Bearer hap_x")
        with urllib.request.urlopen(request, timeout=5) as answer:  # noqa: S310 - loopback
            self.assertEqual(answer.read().decode(), "cookie=[] auth=[Bearer hap_x]")
            self.assertIsNone(answer.headers.get("Set-Cookie"))

    def refused(self, port: int, *, body: bytes | None = None) -> tuple[int, str, dict[str, Any]]:
        request = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1/token", data=body)
        try:
            urllib.request.urlopen(request, timeout=5)  # noqa: S310 - loopback
        except urllib.error.HTTPError as refusal:
            with refusal:
                return refusal.code, refusal.headers["Content-Type"], json.load(refusal)
        raise AssertionError("nginx let the request through")

    def assert_envelope(self, answer: dict[str, Any], outcome: str, code: str) -> None:
        self.assertEqual(
            (answer["schema_version"], answer["ok"], answer["outcome"], answer["operation"]),
            (1, False, outcome, "api"),
        )
        self.assertEqual((answer["result"], answer["warnings"]), (None, []))
        self.assertEqual(answer["error"]["code"], code)
        self.assertRegex(answer["request_id"], r"^[0-9a-f]{32}$")

    def test_a_manager_that_does_not_answer_is_a_502_in_the_envelope_not_a_page(self) -> None:
        status, kind, answer = self.refused(self.serve(backend_up=False))
        self.assertEqual((status, kind), (502, "application/json"))
        self.assert_envelope(answer, "failed", "unavailable")

    def test_the_rate_is_a_429_in_the_envelope_with_a_wait(self) -> None:
        port = self.serve()
        for _ in range(70):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/token", timeout=5).close()
            except urllib.error.HTTPError as refusal:
                with refusal:
                    self.assertEqual(refusal.code, 429)
                    self.assertEqual(refusal.headers["Content-Type"], "application/json")
                    self.assertEqual(refusal.headers["Retry-After"], "1")
                    self.assert_envelope(json.load(refusal), "blocked", "rate_limited")
                return
        self.fail("nginx never limited the rate")

    def test_a_body_over_a_megabyte_is_a_413_in_the_envelope(self) -> None:
        status, kind, answer = self.refused(self.serve(), body=b"x" * (1024 * 1024 + 1))
        self.assertEqual((status, kind), (413, "application/json"))
        self.assert_envelope(answer, "blocked", "too_large")

    def test_every_status_nginx_answers_is_wired_to_its_location(self) -> None:
        block = api_location()
        for status in (413, 429, 502, 503, 504):
            self.assertIn(f"error_page {status} @api_{status};", block)


if __name__ == "__main__":
    unittest.main()
