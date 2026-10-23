"""The interface's nginx site, rendered as step 05 renders it and checked by nginx.

Nothing ran the template through `nginx -t` before an installation did, so a
directive in the wrong context was found by step 05 on a manager (added with
the sign-in limit, B305). Skipped where nginx is not installed; the gate's
machine has it. The site needs nginx 1.25.1 or newer (`http2 on;`), which the
supported distributions ship (Ubuntu 26.04, Debian 13); the check is skipped on
an older one, such as Ubuntu 24.04's 1.24, rather than failing on a version the
product does not run on.
"""

from __future__ import annotations

import base64
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from http.client import HTTPConnection
from pathlib import Path

from haprion import cert_receiver

TEMPLATE = Path(__file__).resolve().parents[1] / "install" / "platform" / "examples"
NGINX = shutil.which("nginx") or "/usr/sbin/nginx"
#
# `http2 on;`, the form the site uses: older versions know only `listen ... http2`.
#
NGINX_MINIMUM = (1, 25, 1)


def nginx_version() -> tuple[int, ...] | None:
    answer = subprocess.run(  # fixed binary
        [NGINX, "-v"], capture_output=True, text=True, check=False
    )
    found = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", answer.stderr + answer.stdout)
    return tuple(int(part) for part in found.groups()) if found else None


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class TheSiteParses(unittest.TestCase):
    def setUp(self) -> None:
        if not Path(NGINX).exists():
            self.skipTest("nginx is not installed here")

    def render(self, root: Path) -> Path:
        key, cert = root / "tls.key", root / "tls.pem"
        subprocess.run(  # fixed argv, a throwaway pair for the check
            [
                "/usr/bin/openssl", "req", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
                "-subj", "/CN=mgr.example.com", "-keyout", str(key), "-out", str(cert),
            ],
            check=True,
            capture_output=True,
        )  # fmt: skip
        site = (TEMPLATE / "haprion.nginx.example").read_text()
        for name, value in (("SERVER_NAME", "mgr.example.com"), ("TLS_CERT", str(cert))):
            site = site.replace(name, value)
        site = site.replace("TLS_KEY", str(key))
        #
        # The paths outside the site that a check opens, moved under the
        # throwaway root: nginx -t opens every log and include it names.
        #
        for snippet in ("haprion-real-ip.conf", "haprion-receivers.conf"):
            (root / snippet).write_text("")
            site = site.replace(f"/etc/nginx/snippets/{snippet}", str(root / snippet))
        site = site.replace("/var/log/nginx/", f"{root}/")
        #
        # nginx -t binds what it listens on, which 80 and 443 are not to an
        # unprivileged check: free loopback ports instead, the IPv6 ones dropped.
        #
        for port in ("80", "443"):
            site = site.replace(f"    listen [::]:{port}", "    # listen [::]")
            site = site.replace(f"    listen {port}", f"    listen 127.0.0.1:{free_port()}")
        (root / "site.conf").write_text(site)
        conf = root / "nginx.conf"
        conf.write_text(
            f"pid {root}/nginx.pid;\n"
            f"error_log {root}/error.log;\n"
            "events {}\n"
            f"http {{\n  access_log {root}/access.log;\n  include {root}/site.conf;\n}}\n"
        )
        return conf

    def test_the_rendered_site_passes_nginx_t(self) -> None:
        version = nginx_version()
        if version is None or version < NGINX_MINIMUM:
            self.skipTest(f"nginx {version} is older than the site needs, 1.25.1")
        with tempfile.TemporaryDirectory() as raw:
            conf = self.render(Path(raw))
            checked = subprocess.run(  # fixed binary, a file made above
                [NGINX, "-t", "-q", "-p", raw, "-c", str(conf)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_only_a_sign_in_and_its_start_at_the_provider_are_limited(self) -> None:
        site = (TEMPLATE / "haprion.nginx.example").read_text()
        self.assertIn("POST/login       $binary_remote_addr;", site)
        self.assertIn("GET/login/oidc   $binary_remote_addr;", site)
        self.assertNotIn("callback", site.split("map $request_method$uri")[1].split("}")[0])
        self.assertIn('default          "";', site)
        self.assertIn("limit_req zone=haprion_sign_in", site)


class AReceiversSecretIsWhatNginxChecks(unittest.TestCase):
    """B306: nginx checks the receiver's `$y$` hash through crypt(3); this asks
    a running nginx rather than trusting that it does."""

    def setUp(self) -> None:
        if not Path(NGINX).exists():
            self.skipTest("nginx is not installed here")

    def test_the_right_password_fetches_and_a_wrong_one_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "files").mkdir()
            (root / "files" / "fullchain.pem").write_text("material\n")
            hashed = cert_receiver.secret_hash("receiver password")
            (root / "receiver.htpasswd").write_text(f"192.0.2.9:{hashed}\n")
            port = free_port()
            (root / "nginx.conf").write_text(
                f"pid {root}/nginx.pid;\nerror_log {root}/error.log;\nevents {{}}\n"
                f"http {{\n  access_log off;\n  server {{\n    listen 127.0.0.1:{port};\n"
                f"    location /r/ {{\n      alias {root}/files/;\n"
                '      auth_basic "192.0.2.9";\n'
                f"      auth_basic_user_file {root}/receiver.htpasswd;\n    }}\n  }}\n}}\n"
            )
            server = subprocess.Popen(  # fixed binary, a file made above
                [NGINX, "-p", raw, "-c", str(root / "nginx.conf"), "-g", "daemon off;"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                self.assertEqual(self.fetch(port, "receiver password"), 200)
                self.assertEqual(self.fetch(port, "not the password"), 401)
            finally:
                server.terminate()
                server.wait(timeout=5)

    def fetch(self, port: int, password: str) -> int:
        token = base64.b64encode(f"192.0.2.9:{password}".encode()).decode()
        for _ in range(50):
            try:
                connection = HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request(
                    "GET", "/r/fullchain.pem", headers={"Authorization": f"Basic {token}"}
                )
                status = connection.getresponse().status
                connection.close()
                return status
            except ConnectionRefusedError:
                time.sleep(0.1)
        self.fail("nginx did not listen")


if __name__ == "__main__":
    unittest.main()
