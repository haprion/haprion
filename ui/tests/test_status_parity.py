"""The status helper, `haprion-status` and the dashboard read a node reading the same way (B455).

They each carried their own copy of the rules and drifted apart: a stopped
dnsdist was in the helper's warnings and the command and on no page. Every
finding `haprion.cluster_status` can return is asked of the same reading in all
three, and a finding one of them leaves out fails here.
"""

from __future__ import annotations

import io
import unittest
from datetime import timedelta
from typing import Any

from haprion import cluster_status
from haprion.cli import status

from haprion_ui.dashboard import build_dashboard
from tests.test_dashboard import NOW, reading


def broken_reading() -> Any:
    """The single-owner reading with every finding there is: both engines stopped, a peer cut off."""

    base = reading("done-single-owner.json")
    result = dict(base.result)
    nodes = [dict(node) for node in result["nodes"]]
    for node, peer in zip(nodes, ("node-b", "node-a"), strict=True):
        node["status"] = {
            **node["status"],
            "waf_engine": {"version": "0.9.0-4", "active": node["name"] != "node-a"},
            "dns_listener": {"version": "2.1.2-1pdns", "active": node["name"] != "node-a"},
            "peers": [{"name": peer, "connected": False}],
            "runtime": {"version": "3.2.9", "uptime_sec": 600},
        }
    result["nodes"] = nodes
    result["summary"] = {**result["summary"], "waf_published": True, "dns_published": True}
    return base.__class__(
        cluster=base.cluster,
        observed_at=base.observed_at,
        outcome="done",
        result=result,
        warnings=[],
        error=None,
        poll_error=None,
    )


class ThreeReadersOneReading(unittest.TestCase):
    def test_every_finding_is_on_the_page_and_in_the_command(self) -> None:
        status_reading = broken_reading()
        nodes = status_reading.result["nodes"]
        summary = status_reading.result["summary"]
        findings = {entry["name"]: cluster_status.node_findings(entry, summary) for entry in nodes}
        counters = cluster_status.counter_findings(nodes)
        self.assertEqual(
            {finding.code for found in findings.values() for finding in found}
            | {finding.code for finding in counters.values()},
            set(cluster_status.FINDING_CODES),
        )

        page = build_dashboard(
            ("alpha",), (status_reading,), now=NOW, stale_after=timedelta(seconds=120)
        ).clusters[0]
        shown = {node.name: node for node in page.nodes}
        for name, found in findings.items():
            first = found[0] if found else counters[name]
            self.assertEqual(shown[name].label, first.label)

        out = io.StringIO()
        status._render({"cluster": "alpha", "result": status_reading.result, "warnings": []}, out)
        text = out.getvalue()
        self.assertIn("WAF engine:   STOPPED", text)
        self.assertIn("DNS listener: STOPPED", text)
        for finding in counters.values():
            self.assertIn(finding.detail, text)

    def test_a_stopped_engine_is_stopped_in_the_command_exactly_when_it_is_a_finding(self) -> None:
        """V06: the command had its own rule, and a release that could not be read made them differ."""

        base = broken_reading()
        for published in (True, False, None):
            for key, summary_key, code, label in (
                ("waf_engine", "waf_published", cluster_status.WAF_ENGINE_STOPPED, "WAF engine:"),
                (
                    "dns_listener",
                    "dns_published",
                    cluster_status.DNS_LISTENER_STOPPED,
                    "DNS listener:",
                ),
            ):
                for engine in (
                    {"version": "1.0-1", "active": False},
                    {"version": "1.0-1", "active": True},
                ):
                    with self.subTest(published=published, key=key, engine=engine):
                        result = dict(base.result)
                        node = dict(result["nodes"][0])
                        node["status"] = {**node["status"], key: engine}
                        summary = {k: v for k, v in result["summary"].items() if k != summary_key}
                        if published is not None:
                            summary[summary_key] = published
                        result["nodes"] = [node]
                        result["summary"] = summary
                        stopped = code in {
                            finding.code for finding in cluster_status.node_findings(node, summary)
                        }
                        out = io.StringIO()
                        status._render({"cluster": "alpha", "result": result, "warnings": []}, out)
                        line = next(x for x in out.getvalue().splitlines() if label in x)
                        self.assertEqual("STOPPED" in line, stopped, line)


if __name__ == "__main__":
    unittest.main()
