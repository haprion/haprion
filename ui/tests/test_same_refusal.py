"""The terminal and the API refuse the same documents the same way (K04, 26-11-05).

`test_cli_parity` holds that each write has its command and that a command's
refusal is a document in its contract. This holds the third thing: one document
that breaks one rule is refused by `haprion-objects apply` and by the API's
`POST /clusters/{cluster}/objects` in the same class of refusal - the CLI's 65
and the API's 400 `bad_input` - and a node that cannot serve a feature is judged
the same by the engine's publish and by the page's offer of it.
"""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from haprion import exit_codes
from haprion.cli import objects_apply
from haprion.cli.apply_common import Refused
from haprion.cluster_status import parse_status
from haprion.held_ports import from_status

from haprion_ui import health, waf
from tests.test_api_changes import ChangesTestCase
from tests.test_editor_page import SHOP

ROOT = Path(__file__).resolve().parents[2]
CHANGES_PUBLISH = ROOT / "src" / "haprion" / "cli" / "changes_publish.py"
#
# Every refusal the publishing helper makes, and who judges it. The terminal and
# the web both send their documents to this helper, so what it refuses is refused
# alike; what this list holds is that no refusal is added without being named
# here, where it is decided whether the page and the API also judge it first
# (W02, 26-11-05).
#
PUBLISH_REFUSALS: dict[str, str] = {
    "changes_invalid": "an object, or the package as a whole: RULES above are what the terminal,"
    " the page and the API judge before the helper; the ports, certificates and nodes are the"
    " helper's alone",
    "network_invalid": "the network document: the page and `network apply` both send it to the helper",
    "settings_invalid": "the settings document: the page and `settings apply` both send it to the"
    " helper",
}

NEW = SHOP.replace("shop", "console")
RULES: dict[str, str] = {
    "an allow list with host bits": NEW.replace("routes:", "allow_from: [192.0.2.1/24]\nroutes:"),
    "a key the model does not have": NEW.replace("routes:", "colour: red\nroutes:"),
    "the WAF on a raw tcp object": NEW.replace("protocol: http", "protocol: tcp\n  port: 9000")
    .replace("hostnames:\n- shop.example.com\n", "")
    .replace("routes:\n- path: /\n  backend: web\n", "backend: web\n")
    + "waf: {}\n",
    "a server port nothing has": NEW.replace("8080", "70000"),
}


class ADocumentThatBreaksARuleIsRefusedByBoth(ChangesTestCase):
    def test_the_terminal_and_the_api_refuse_what_breaks_the_same_rule(self) -> None:
        for rule, document in RULES.items():
            with self.subTest(rule):
                with tempfile.TemporaryDirectory() as raw:
                    path = Path(raw) / "console.yaml"
                    path.write_text(document)
                    try:
                        wanted = objects_apply.read_files([str(path)])
                        objects_apply.plan_apply(wanted, {}, prune=False)
                    except Refused as refused:
                        terminal = refused.exit_code
                    else:
                        terminal = exit_codes.OK
                response = self.send("POST", "/clusters/alpha/objects", body=document)
                code = response.json().get("error", {}).get("code")

                self.assertEqual(
                    (terminal, response.status_code, code),
                    (exit_codes.REFUSED, 400, "bad_input"),
                    rule,
                )

    def test_a_usable_document_is_taken_by_both(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "console.yaml"
            path.write_text(NEW)
            wanted = objects_apply.read_files([str(path)])
            self.assertEqual(objects_apply.plan_apply(wanted, {}, prune=False).added, ("console",))
        self.assertEqual(self.send("POST", "/clusters/alpha/objects", body=NEW).status_code, 201)

    def test_an_object_name_nobody_may_use_is_refused_with_the_same_reason(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "Bad Name.yaml"
            path.write_text(NEW)
            with self.assertRaises(Refused) as terminal:
                objects_apply.read_files([str(path)])
        response = self.send(
            "POST", "/clusters/alpha/objects", body=NEW.replace("name: console", "name: Bad Name")
        )

        self.assertEqual(
            (terminal.exception.exit_code, response.status_code), (exit_codes.REFUSED, 400)
        )
        self.assertIn("not a usable object name", str(terminal.exception))


def _helper_refusals() -> dict[str, str]:
    """Each `Refusal("code", ...)` the helper raises, with the exit code it names."""

    found: dict[str, str] = {}
    for node in ast.walk(ast.parse(CHANGES_PUBLISH.read_text(encoding="utf-8"))):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "Refusal"
            and len(node.args) >= 3
            and isinstance(node.args[0], ast.Constant)
        ):
            found[str(node.args[0].value)] = ast.unparse(node.args[2])
    return found


class EveryRefusalOfThePublishIsNamed(unittest.TestCase):
    def test_the_helper_refuses_only_what_is_named_here(self) -> None:
        refusals = _helper_refusals()

        self.assertEqual(sorted(set(refusals) ^ set(PUBLISH_REFUSALS)), [])

    def test_every_refusal_is_the_one_class_the_terminal_and_the_api_report(self) -> None:
        """The CLI's 65 and the API's `bad_input`: a refusal with another exit would be told apart."""

        self.assertEqual(set(_helper_refusals().values()), {"exit_codes.REFUSED"})


def status_without(feature: str, *, answered: bool = True) -> dict[str, object]:
    """The status of a cluster of two nodes, the second lacking one feature."""

    def node(name: str, lacks: str | None, ok: bool = True) -> dict[str, object]:
        status: dict[str, object] = {
            "schema_version": 1,
            "node": name,
            "cluster": "alpha",
            "haproxy": {"active": True},
            "keepalived": {"active": True},
            "vip": {"address": "192.0.2.10", "interface": "eth0", "owner": name == "node-a"},
            "certificates": [],
        }
        if lacks != "waf":
            status["waf_engine"] = {"version": "0.9.0", "active": True}
        if lacks != "dns":
            status["dns_listener"] = {"version": "2.0.0", "active": True}
        status["ipvs"] = {"included": lacks != "syslog"}
        return {
            "name": name,
            "mgmt_host": f"{name}.example.com",
            "reachable": ok,
            "status_ok": ok,
            "status": status if ok else None,
            "error": None,
        }

    return {
        "schema_version": 1,
        "ok": True,
        "outcome": "done",
        "operation": "status",
        "cluster": "alpha",
        "request_id": "01JQ0000000000000000000000",
        "result": {
            "nodes": [node("node-a", None), node("node-b", feature, answered)],
            "summary": {"vip_state": "single_owner", "vip_owners": ["node-a"]},
        },
        "warnings": [],
        "error": None,
    }


class TheNodesAreJudgedTheSameWay(unittest.TestCase):
    class Row:
        cluster = "alpha"

        def __init__(self, result: dict[str, object]) -> None:
            self.result = result

    def judged(
        self, document: dict[str, object]
    ) -> tuple[dict[str, bool], dict[str, tuple[str, ...]]]:
        row = self.Row(document["result"])  # type: ignore[arg-type]
        page = {
            "waf": not waf.engine([], [row]).missing.get("alpha"),
            "dns": health.dns_everywhere([row], cluster="alpha"),
            "syslog": health.syslog_everywhere([row], cluster="alpha"),
        }
        return page, dict(from_status(parse_status(document)).lacking)

    def test_a_feature_a_node_lacks_is_not_offered_and_is_refused(self) -> None:
        for feature in ("waf", "dns", "syslog"):
            with self.subTest(feature):
                offered, lacking = self.judged(status_without(feature))

                self.assertEqual(
                    {
                        name: not nodes
                        for name, nodes in {f: lacking.get(f, ()) for f in offered}.items()
                    },
                    offered,
                )
                self.assertFalse(offered[feature])
                self.assertEqual(lacking[feature], ("node-b",))

    def test_nodes_that_serve_everything_are_offered_everything_and_refused_nothing(self) -> None:
        offered, lacking = self.judged(status_without("nothing"))

        self.assertEqual((set(offered.values()), lacking), ({True}, {}))

    def test_the_one_difference_is_a_node_that_did_not_answer(self) -> None:
        """The page cannot count on a feature a node has not confirmed; the publish does not stop for a node it cannot ask."""

        offered, lacking = self.judged(status_without("nothing", answered=False))

        self.assertEqual(set(offered.values()), {False})
        self.assertEqual(lacking, {})
