"""The interface's nginx site, rendered as step 05 renders it and checked by nginx.

Nothing ran the template through `nginx -t` before an installation did, so a
directive in the wrong context was found by step 05 on a manager (added with
the sign-in limit, B305). Skipped where nginx is not installed; the gate's
machine has it.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[1] / "install" / "platform" / "examples"
NGINX = shutil.which("nginx") or "/usr/sbin/nginx"


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
        subprocess.run(  # noqa: S603 - fixed argv, a throwaway pair for the check
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
        with tempfile.TemporaryDirectory() as raw:
            conf = self.render(Path(raw))
            checked = subprocess.run(  # noqa: S603 - fixed binary, a file made above
                [NGINX, "-t", "-q", "-p", raw, "-c", str(conf)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_only_a_sign_in_post_is_limited(self) -> None:
        site = (TEMPLATE / "haprion.nginx.example").read_text()
        self.assertIn("POST/login   $binary_remote_addr;", site)
        self.assertIn('default      "";', site)
        self.assertIn("limit_req zone=haprion_sign_in", site)


if __name__ == "__main__":
    unittest.main()
