"""Ports other programs hold on every address, refused at publish (26-10-15).

Checkmk's agent on `0.0.0.0:6556` holds 6556 on the VIP too, and an object
there would fail every deploy on `cannot bind socket`. The node reports such
ports in its status; the publish reads them the way the deploy reads the nodes
and refuses the object, naming the program and the node. A node that does not
answer is named in the result instead of stopping the publish.

The node half is extracted from `install/node/haprion-node-status` verbatim, as
`test_forward_file` does.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from haprion.cluster_status import parse_status
from haprion.config import Vip
from haprion.generate import GeneratorError, generate
from haprion.held_ports import HeldPorts, from_status
from haprion.proxy_model import load_proxy
from tests.test_changes_publish_objects import ObjectsPublishFixture
from tests.test_status_addresses import envelope, node_status

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"
READING = re.compile(
    r"^WILDCARD_LOCAL = .*?(?=^def read_wildcard_listeners\()", re.DOTALL | re.MULTILINE
)

#
# `ss -Hlntup` as a node answers it.
#
LISTENING = """\
tcp   LISTEN 0 4096        0.0.0.0:22     0.0.0.0:* users:(("sshd",pid=457,fd=3),("systemd",pid=1,fd=238))
tcp   LISTEN 0 4096           [::]:6556      [::]:* users:(("cmk-agent-ctl",pid=900,fd=9))
tcp   LISTEN 0 4096        0.0.0.0:6556   0.0.0.0:* users:(("cmk-agent-ctl",pid=900,fd=8))
tcp   LISTEN 0 4096        0.0.0.0:8405   0.0.0.0:* users:(("haproxy",pid=2934,fd=9))
tcp   LISTEN 0 4096     192.0.2.20:443    0.0.0.0:* users:(("haproxy",pid=2934,fd=12))
tcp   LISTEN 0 4096      127.0.0.1:9520   0.0.0.0:* users:(("coraza-spoa",pid=800,fd=7))
tcp   LISTEN 0 511               *:5000         *:*
udp   UNCONN 0 0     0.0.0.0%eth0:68      0.0.0.0:* users:(("dhclient",pid=600,fd=6))
udp   UNCONN 0 0        127.0.0.53%lo:53  0.0.0.0:* users:(("systemd-resolve",pid=500,fd=13))
"""


def parse(text: str) -> list[dict[str, Any]]:
    found = READING.search(SCRIPT.read_text())
    assert found is not None, "haprion-node-status has no wildcard reading"
    namespace: dict[str, Any] = {"re": re}
    exec(found.group(0), namespace)  # noqa: S102 - verbatim code from the node script
    listeners: list[dict[str, Any]] = namespace["parse_wildcard_listeners"](text)
    return listeners


def reported(listeners: object, **entry: object) -> dict[str, Any]:
    status = node_status({"active": True})
    if listeners is not ...:
        status["wildcard_listeners"] = listeners
    document = envelope(status)
    document["result"]["nodes"][0].update(entry)  # type: ignore[index]
    return document


class TheNodeReportsWhatItHoldsOnEveryAddress(unittest.TestCase):
    def test_every_address_by_protocol_and_port_once_and_haproxy_left_out(self) -> None:
        self.assertEqual(
            parse(LISTENING),
            [
                {"protocol": "tcp", "port": 22, "program": "sshd"},
                {"protocol": "tcp", "port": 5000, "program": None},
                {"protocol": "tcp", "port": 6556, "program": "cmk-agent-ctl"},
                {"protocol": "udp", "port": 68, "program": "dhclient"},
            ],
        )

    def test_nothing_on_every_address_is_an_empty_list(self) -> None:
        self.assertEqual(parse(""), [])


class TheManagerReadsIt(unittest.TestCase):
    def test_the_ports_come_through_and_garbage_does_not(self) -> None:
        status = parse_status(
            reported(
                [
                    {"protocol": "tcp", "port": 6556, "program": "cmk-agent-ctl"},
                    {"protocol": "sctp", "port": 9, "program": "x"},
                    {"protocol": "udp", "port": "68", "program": "dhclient"},
                    "nonsense",
                ]
            )
        )
        self.assertEqual(status.nodes[0].wildcard_listeners, (("tcp", 6556, "cmk-agent-ctl"),))

    def test_a_node_that_did_not_say_is_none_not_empty(self) -> None:
        self.assertIsNone(parse_status(reported(...)).nodes[0].wildcard_listeners)
        self.assertIsNone(parse_status(reported(None)).nodes[0].wildcard_listeners)

    def test_held_ports_name_the_node_and_the_unread(self) -> None:
        held = from_status(
            parse_status(reported([{"protocol": "tcp", "port": 6556, "program": "cmk-agent-ctl"}]))
        )
        self.assertEqual(held.held, {("tcp", 6556): (("node-a", "cmk-agent-ctl"),)})
        self.assertEqual(held.unread, ())

        silent = from_status(parse_status(reported(...)))
        self.assertEqual((silent.held, silent.unread), ({}, ("node-a",)))


def tcp_object(port: int, protocol: str = "tcp") -> Any:
    return load_proxy(
        "agent",
        f"""schema: 1
name: agent
listen: {{protocol: {protocol}, port: {port}}}
backend: pool
backends:
  pool: {{balance: roundrobin, servers: [{{host: 198.51.100.9, port: 9}}]}}
""".encode(),
    )


VIPS = {"main": Vip(name="main", address="192.0.2.20")}
CMK = {("tcp", 6556): (("node-a", "cmk-agent-ctl"),)}


class ThePublishRefusesAnObjectOnAHeldPort(unittest.TestCase):
    def test_a_tcp_object_on_a_held_port_is_refused_with_program_and_node(self) -> None:
        with self.assertRaises(GeneratorError) as raised:
            generate([tcp_object(6556)], vips=VIPS, default_vip="main", held_ports=CMK)
        message = str(raised.exception)
        for words in ("agent", "main port 6556/tcp", "cmk-agent-ctl", "node-a", "cannot bind"):
            self.assertIn(words, message)

    def test_the_advice_is_one_the_program_can_follow(self) -> None:
        """R2 26-10-27 (F23): the Checkmk agent and resolved's LLMNR take no address."""

        with self.assertRaises(GeneratorError) as raised:
            generate([tcp_object(6556)], vips=VIPS, default_vip="main", held_ports=CMK)
        self.assertIn("move it to another port with pull_port", str(raised.exception))
        self.assertNotIn("listen on the node's own address", str(raised.exception))
        held = {("tcp", 5355): (("node-a", "systemd-resolve"),)}
        with self.assertRaisesRegex(GeneratorError, "Turn off its LLMNR: LLMNR=no"):
            generate([tcp_object(5355)], vips=VIPS, default_vip="main", held_ports=held)
        held = {("tcp", 2222): (("node-a", "sshd"),)}
        with self.assertRaisesRegex(GeneratorError, "Have sshd listen on the node's own address"):
            generate([tcp_object(2222)], vips=VIPS, default_vip="main", held_ports=held)

    def test_a_dns_object_is_asked_on_udp_and_tcp(self) -> None:
        held = {("udp", 53): (("node-b", "named"),)}
        with self.assertRaisesRegex(GeneratorError, "53/udp, which named holds"):
            generate([tcp_object(53, "dns")], vips=VIPS, default_vip="main", held_ports=held)

    def test_an_http_object_is_asked_on_the_cluster_s_port(self) -> None:
        held = {("tcp", 80): (("node-a", None),)}
        site = load_proxy(
            "shop",
            b"""schema: 1
name: shop
hostnames: [shop.example.com]
listen: {protocol: http}
routes: [{path: /, backend: web}]
backends:
  web: {balance: roundrobin, servers: [{host: 198.51.100.10, port: 8080}]}
""",
        )
        with self.assertRaisesRegex(GeneratorError, "port 80/tcp, which another program holds"):
            generate([site], vips=VIPS, default_vip="main", held_ports=held)

    def test_other_ports_and_no_reading_are_left_alone(self) -> None:
        generate([tcp_object(2222)], vips=VIPS, default_vip="main", held_ports=CMK)
        generate([tcp_object(6556)], vips=VIPS, default_vip="main")


class ThePublishAsksTheNodes(ObjectsPublishFixture):
    def test_a_held_port_refuses_the_publish_before_anything_is_written(self) -> None:
        held = HeldPorts(held={("tcp", 80): (("node-a", "cmk-agent-ctl"),)})
        with tempfile.TemporaryDirectory() as raw, mock.patch("haprion.held_ports.read") as read:
            read.return_value = held
            policy = self.runtime(Path(raw))
            self.seed()
            head = self.head()

            code, document, _err = self.publish_objects(policy, self.request())

            self.assertEqual(code, 65)
            self.assertIn("cmk-agent-ctl holds on every address of node-a", json.dumps(document))
            self.assertEqual(self.head(), head)

    def test_a_node_that_did_not_answer_is_named_and_the_publish_goes_on(self) -> None:
        with tempfile.TemporaryDirectory() as raw, mock.patch("haprion.held_ports.read") as read:
            read.return_value = HeldPorts(unread=("node-b",))
            policy = self.runtime(Path(raw))
            self.seed()

            code, document, err = self.publish_objects(policy, self.request())

            self.assertEqual((code, err), (0, ""))
            self.assertEqual(document["result"]["ports_unchecked"], ["node-b"])

    def test_without_a_status_identity_every_node_is_unchecked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()

            code, document, _err = self.publish_objects(policy, self.request())

            self.assertEqual(code, 0)
            self.assertEqual(document["result"]["ports_unchecked"], ["node-a", "node-b"])

    def head(self) -> str:
        from tests.test_publish_helper import git

        return git(self.repo, "rev-parse", "HEAD")


if __name__ == "__main__":
    unittest.main()
