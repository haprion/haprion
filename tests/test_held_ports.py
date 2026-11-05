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
from types import SimpleNamespace
from typing import Any
from unittest import mock

from haprion.cluster_status import StatusError, parse_status
from haprion.config import Vip
from haprion.generate import GeneratorError, generate
from haprion.held_ports import HeldPorts, from_status, node_refusal, read, unchecked_warning
from haprion.proxy_model import load_proxy
from tests.test_changes_publish_objects import ObjectsPublishFixture, proxy
from tests.test_publish_helper import git
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

    def test_held_ports_name_the_node_and_leave_out_the_unread(self) -> None:
        held = from_status(
            parse_status(reported([{"protocol": "tcp", "port": 6556, "program": "cmk-agent-ctl"}]))
        )
        self.assertEqual(held.held, {("tcp", 6556): (("node-a", "cmk-agent-ctl"),)})

        silent = from_status(parse_status(reported(...)))
        self.assertEqual(silent.held, {})


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

    def test_a_node_that_did_not_answer_does_not_stop_the_publish(self) -> None:
        with tempfile.TemporaryDirectory() as raw, mock.patch("haprion.held_ports.read") as read:
            read.return_value = HeldPorts()
            policy = self.runtime(Path(raw))
            self.seed()

            code, document, err = self.publish_objects(policy, self.request())

            self.assertEqual((code, err), (0, ""))
            self.assertNotIn("ports_unchecked", document["result"])

    def test_without_a_status_identity_the_publish_goes_on_unchecked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()

            code, document, _err = self.publish_objects(policy, self.request())

            self.assertEqual(code, 0)
            self.assertNotIn("ports_unchecked", document["result"])

    def head(self) -> str:
        from tests.test_publish_helper import git

        return git(self.repo, "rev-parse", "HEAD")


def node_that_serves(**withheld: bool) -> dict[str, Any]:
    """A status that carries the WAF engine, dnsdist and the syslog include, less what is withheld."""

    status = node_status({"active": True})
    if not withheld.get("waf"):
        status["waf_engine"] = {"version": "0.9.0", "active": True}
    if not withheld.get("dns"):
        status["dns_listener"] = {"version": "2.0.0", "active": True}
    status["ipvs"] = {"included": not withheld.get("syslog")}
    return status


def two_nodes(second: dict[str, Any], *, answered: bool = True) -> Any:
    document = envelope(node_that_serves())
    nodes = document["result"]["nodes"]  # type: ignore[index]
    nodes.append({**nodes[0], "name": "node-b", "status": second, "status_ok": answered})
    return parse_status(document)


class TheNodesSayWhatTheyServe(unittest.TestCase):
    def test_a_node_that_answered_without_a_feature_lacks_it(self) -> None:
        held = from_status(two_nodes(node_that_serves(waf=True, dns=True, syslog=True)))

        self.assertEqual(
            held.lacking, {"waf": ("node-b",), "dns": ("node-b",), "syslog": ("node-b",)}
        )

    def test_a_node_that_serves_everything_lacks_nothing(self) -> None:
        self.assertEqual(from_status(two_nodes(node_that_serves())).lacking, {})

    def test_a_node_that_gave_no_answer_is_not_counted_as_lacking(self) -> None:
        held = from_status(two_nodes(node_that_serves(waf=True), answered=False))

        self.assertEqual(held.lacking, {})


def written(listen: str, extra: str = "") -> Any:
    return load_proxy(
        "agent",
        f"""schema: 1
name: agent
listen: {listen}
backend: pool
{extra}backends:
  pool: {{balance: roundrobin, servers: [{{host: 198.51.100.9, port: 9}}]}}
""".encode(),
    )


def http_with_waf() -> Any:
    return load_proxy(
        "agent", proxy("agent", "agent.example.com").replace("routes:", "waf: {}\nroutes:").encode()
    )


class AnObjectIsHeldToWhatTheNodesServe(unittest.TestCase):
    LACKING = HeldPorts(
        lacking={"waf": ("node-b",), "dns": ("node-a", "node-b"), "syslog": ("node-b",)}
    )

    def test_what_an_object_starts_to_need_is_named_with_the_nodes(self) -> None:
        for subject, words in (
            (
                http_with_waf(),
                "The WAF engine is not installed on node-b, so agent cannot start using it.",
            ),
            (written("{protocol: dns, port: 53}"), "dnsdist is not installed on node-a and node-b"),
            (
                written("{protocol: syslog, vip: main, port: 514}"),
                "keepalived on node-b does not read the file",
            ),
        ):
            with self.subTest(words):
                self.assertIn(words, node_refusal(self.LACKING, "agent", subject, None))

    def test_an_object_that_already_needed_it_is_not_held_again(self) -> None:
        waf = http_with_waf()

        self.assertEqual(node_refusal(self.LACKING, "agent", waf, waf), "")

    def test_an_object_that_needs_nothing_more_is_not_held(self) -> None:
        plain = written("{protocol: tcp, port: 9000}")

        self.assertEqual(node_refusal(self.LACKING, "agent", plain, None), "")
        self.assertEqual(
            node_refusal(HeldPorts(), "agent", written("{protocol: dns, port: 53}"), None), ""
        )


class ThePublishSaysWhatItCouldNotCheck(ObjectsPublishFixture):
    """W05: a node that has not answered is not a refusal, and not silence."""

    def publish_with(self, held: HeldPorts, document: str) -> tuple[int, Any]:
        with tempfile.TemporaryDirectory() as raw, mock.patch("haprion.held_ports.read") as read:
            read.return_value = held
            policy = self.runtime(Path(raw))
            self.seed()
            code, answer, _ = self.publish_objects(
                policy, self.request(objects={"agent": document})
            )
            return code, answer

    def test_a_node_not_asked_is_named_when_an_object_starts_to_need_the_engine(self) -> None:
        waf = proxy("agent", "agent.example.com").replace("routes:", "waf: {}\nroutes:")

        code, answer = self.publish_with(HeldPorts(unchecked=("node-b",)), waf)

        self.assertEqual(code, 0)
        self.assertEqual(answer["result"]["unchecked_nodes"], ["node-b"])
        self.assertEqual(answer["result"]["unchecked_features"], ["waf"])

    def test_nothing_is_said_when_the_object_needs_nothing_of_the_nodes(self) -> None:
        code, answer = self.publish_with(
            HeldPorts(unchecked=("node-b",)), proxy("agent", "agent.example.com")
        )

        self.assertEqual(code, 0)
        self.assertNotIn("unchecked_nodes", answer["result"])

    def test_the_words_name_the_nodes_and_what_was_not_checked(self) -> None:
        said = unchecked_warning(("node-a", "node-b"), ("waf", "syslog"))

        self.assertEqual(
            said,
            "node-a and node-b did not answer, so the WAF engine and the syslog file's include "
            "could not be checked there; the deploy refuses the release on a node that lacks it",
        )


class TheReadingSaysWhoWasNotAsked(unittest.TestCase):
    cluster = SimpleNamespace(
        nodes=(SimpleNamespace(name="node-b"), SimpleNamespace(name="node-a"))
    )

    def test_a_node_that_gave_no_answer_is_unchecked(self) -> None:
        self.assertEqual(
            from_status(two_nodes(node_that_serves(), answered=False)).unchecked, ("node-b",)
        )
        self.assertEqual(from_status(two_nodes(node_that_serves())).unchecked, ())

    def test_a_reading_that_failed_leaves_every_node_unchecked(self) -> None:
        policy = SimpleNamespace(status_identity=object())
        with mock.patch("haprion.cli.deploy_helper.read_status", side_effect=StatusError("no key")):
            held = read(policy, self.cluster)  # type: ignore[arg-type]

        self.assertEqual(held.unchecked, ("node-a", "node-b"))

    def test_no_identity_to_ask_with_leaves_every_node_unchecked(self) -> None:
        held = read(SimpleNamespace(status_identity=None), self.cluster)  # type: ignore[arg-type]

        self.assertEqual(held.unchecked, ("node-a", "node-b"))


class ThePublishRefusesWhatANodeCannotServe(ObjectsPublishFixture):
    def head(self) -> str:
        return git(self.repo, "rev-parse", "HEAD")

    def publish_lacking(self, document: str, **seeded: str) -> tuple[int, Any, str, str]:
        lacking = HeldPorts(lacking={"waf": ("node-b",), "dns": ("node-b",), "syslog": ("node-b",)})
        with tempfile.TemporaryDirectory() as raw, mock.patch("haprion.held_ports.read") as read:
            read.return_value = lacking
            policy = self.runtime(Path(raw))
            self.seed(**seeded)
            head = self.head()
            code, answer, err = self.publish_objects(
                policy, self.request(objects={"agent": document})
            )
            return code, answer, err, "same" if self.head() == head else "moved"

    def test_a_dns_object_is_refused_before_anything_is_written(self) -> None:
        document = """schema: 1
name: agent
listen: {protocol: dns, port: 53}
backend: pool
allow_from: [192.0.2.0/24]
backends:
  pool: {balance: roundrobin, servers: [{host: 198.51.100.53, port: 53}]}
"""

        code, answer, _, head = self.publish_lacking(document)

        self.assertEqual(code, 65)
        self.assertEqual(answer["error"]["code"], "changes_invalid")
        self.assertIn("dnsdist is not installed on node-b", answer["error"]["message"])
        self.assertEqual(head, "same")

    def test_a_waf_object_is_refused_and_a_plain_one_is_published(self) -> None:
        waf = proxy("agent", "agent.example.com").replace("routes:", "waf: {}\nroutes:")

        code, answer, _, head = self.publish_lacking(waf)

        self.assertEqual((code, answer["error"]["code"]), (65, "changes_invalid"))
        self.assertIn("The WAF engine is not installed on node-b", answer["error"]["message"])
        self.assertEqual(head, "same")
        code, answer, _, head = self.publish_lacking(proxy("agent", "agent.example.com"))
        self.assertEqual((code, head), (0, "moved"))

    def test_an_object_that_already_used_the_engine_is_not_refused_for_it(self) -> None:
        waf = proxy("agent", "agent.example.com").replace("routes:", "waf: {}\nroutes:")

        code, answer, _, _ = self.publish_lacking(waf, agent=waf)

        self.assertNotIn("not installed on node-b", json.dumps(answer))
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
