"""A pool that speaks HTTP/2 keeps WebSockets on HTTP/1.1.

HAProxy sends a WebSocket upgrade to an HTTP/2 server as an extended CONNECT
(RFC 8441), which many servers do not take. `ws h1` on the server line keeps
the upgrade on HTTP/1.1 while ordinary requests go over HTTP/2.
"""

from __future__ import annotations

import unittest

from haprion.generate import _http2
from haprion.proxy_model import load_proxy

POOL = b"""
schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    http_version: "2"
    health:
      type: disabled
%s    servers:
      - host: 192.0.2.10
        port: 8080
"""


class AnHttp2PoolKeepsWebSocketsOnHttp1(unittest.TestCase):
    def test_in_plain_the_server_line_says_ws_h1(self) -> None:
        backend = load_proxy("shop", POOL % b"").backends["web"]
        self.assertEqual(_http2(backend), " proto h2 ws h1")

    def test_over_tls_the_server_line_says_ws_h1(self) -> None:
        document = (POOL % b"    tls:\n      verify: system\n").replace(
            b"192.0.2.10", b"app.example.net"
        )
        backend = load_proxy("shop", document).backends["web"]
        self.assertEqual(_http2(backend), " alpn h2 ws h1")

    def test_a_pool_on_http_1_1_says_nothing(self) -> None:
        document = (POOL % b"").replace(b'    http_version: "2"\n', b"")
        self.assertEqual(_http2(load_proxy("shop", document).backends["web"]), "")


if __name__ == "__main__":
    unittest.main()
