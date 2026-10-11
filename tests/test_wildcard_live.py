"""One object for a whole subdomain, put to a real HAProxy (B278).

`*.apps.example.com` stands for exactly one label, as a wildcard certificate
does, and an exact name another object claims is that object's - wholly:
not only where the request goes, but whose rules it meets. The subdomain
object here admits nobody (its `allow_from` names a network the test client
is not in), so a request for the exact object's name that met its rules
would be refused, and one that is not proves the exclusion.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

from haprion.config import UnknownHost, Vip
from haprion.generate import generate
from haprion.proxy_model import load_proxy
from tests.spawned import wait_for
from tests.test_generate_behaviour import echo_server, free_port, start_haproxy, write_release

SUBDOMAIN = """
schema: 1
name: apps
hostnames: ["*.apps.example.com"]
listen:
  protocol: http
allow_from: [office]
routes:
  - path: /
    backend: apps-pool
backends:
  apps-pool:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 127.0.0.1
        port: {apps}
"""

EXACT = """
schema: 1
name: grafana
hostnames: [grafana.apps.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: grafana-pool
backends:
  grafana-pool:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 127.0.0.1
        port: {grafana}
"""


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
class ASubdomainStandsForOneLabelAndYieldsToExactNames(unittest.TestCase):
    directory: tempfile.TemporaryDirectory[str]
    servers: list[ThreadingHTTPServer]
    haproxy: subprocess.Popen[bytes]
    port: int

    @classmethod
    def setUpClass(cls) -> None:
        apps, grafana = free_port(), free_port()
        cls.servers = [echo_server("apps", apps), echo_server("grafana", grafana)]
        wait_for(apps)
        wait_for(grafana)
        cls.port = free_port()
        cls.directory = tempfile.TemporaryDirectory()
        layer = generate(
            [
                load_proxy("apps", SUBDOMAIN.format(apps=apps).encode()),
                load_proxy("grafana", EXACT.format(grafana=grafana).encode()),
            ],
            vips={"main": Vip(name="main", address="127.0.0.1")},
            default_vip="main",
            ports={"http": cls.port},
            networks={"office": ("198.51.100.0/24",)},
            unknown_host=UnknownHost(status=404),
        )
        arguments = write_release(Path(cls.directory.name), layer)
        binary = shutil.which("haproxy")
        assert binary is not None
        cls.haproxy = start_haproxy(binary, arguments, cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.haproxy.terminate()
        cls.haproxy.wait(timeout=5)
        for server in cls.servers:
            server.shutdown()
        cls.directory.cleanup()

    def get(self, host: str) -> tuple[int, str]:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", host)
            connection.endheaders()
            response = connection.getresponse()
            return response.status, response.read().decode()
        finally:
            connection.close()

    def test_one_label_under_it_is_the_subdomains_and_meets_its_rules(self) -> None:
        self.assertEqual(self.get("shop.apps.example.com")[0], 403)
        self.assertEqual(self.get("Shop.Apps.Example.com:80")[0], 403)

    def test_an_exact_name_under_it_is_the_other_objects_and_only_its(self) -> None:
        self.assertEqual(self.get("grafana.apps.example.com"), (200, "grafana /"))

    def test_the_bare_suffix_and_two_labels_deep_are_nobodys(self) -> None:
        self.assertEqual(self.get("apps.example.com")[0], 404)
        self.assertEqual(self.get("a.b.apps.example.com")[0], 404)


if __name__ == "__main__":
    unittest.main()
