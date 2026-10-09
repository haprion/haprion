"""What a node makes of `show stat`, and what it refuses to make of it.

The parsing is extracted from `install/node/haprion-node-status` verbatim and
run against captured output, the way `test_node_vip_detection` extracts the VIP
parser. That is deliberate: the script is installed on the nodes rather than
imported, so a test that reimplemented the parsing would prove nothing about
what the nodes actually run.

Why this is worth pinning down. a site answered 503 with all three servers UP,
and nothing in the server rows could say whether the listener had received the
request at all - only a counter per frontend could. So the frontend rows are no
longer skipped, and the counters are read by column name rather than position,
because `show stat` has grown columns between HAProxy versions.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"
PARSING = re.compile(r"^MAX_STAT_ROWS = .*?(?=^def ask_runtime\()", re.DOTALL | re.MULTILINE)

#
# A real header from HAProxy 3.4.4, cut to the columns this parser names plus
# two it does not, in an order that is not the order the parser lists them in.
# The point of the test is that neither the extra columns nor the order matter.
#
HEADER = (
    "# pxname,svname,scur,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,"
    "status,weight,chkfail,lastchg,check_status,check_code,check_duration,"
    "hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,req_tot,qcur"
)


def row(**cell: str) -> str:
    columns = HEADER.lstrip("# ").split(",")
    return ",".join(cell.get(name, "") for name in columns)


class ReadingShowStat(unittest.TestCase):
    def setUp(self) -> None:
        found = PARSING.search(SCRIPT.read_text())
        assert found, "the parsing is no longer where the test extracts it from"
        namespace: dict[str, Any] = {}
        exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
        self.parse = namespace["parse_stat"]

    def stat(self, *rows: str) -> dict[str, Any]:
        parsed: dict[str, Any] | None = self.parse("\n".join((HEADER, *rows)) + "\n")
        assert parsed is not None
        return parsed

    def test_a_listener_is_reported_and_no_longer_skipped(self) -> None:
        """The row that says whether the request arrived at all."""

        parsed = self.stat(
            row(pxname="mgd-vip-https", svname="FRONTEND", status="OPEN", req_tot="41")
        )

        self.assertEqual(len(parsed["frontends"]), 1)
        self.assertEqual(parsed["frontends"][0]["frontend"], "mgd-vip-https")
        self.assertEqual(parsed["frontends"][0]["counters"]["req_tot"], 41)
        self.assertEqual(parsed["servers"], [])

    def test_a_pool_member_keeps_its_verdict_and_gains_counters(self) -> None:
        parsed = self.stat(
            row(
                pxname="mgd-site-web",
                svname="s1",
                status="UP",
                check_status="L7OK",
                check_code="200",
                check_duration="12",
                lastchg="900",
                stot="7",
                econ="0",
            )
        )

        member = parsed["servers"][0]
        self.assertEqual(member["backend"], "mgd-site-web")
        self.assertEqual(member["server"], "s1")
        self.assertEqual(member["check_status"], "L7OK")
        self.assertEqual(member["check_duration_ms"], 12)
        self.assertEqual(member["last_change_sec"], 900)
        self.assertEqual(member["counters"]["stot"], 7)
        self.assertEqual(member["counters"]["econ"], 0)

    def test_zero_is_not_the_same_answer_as_nothing(self) -> None:
        """A column with no value is None; a column with `0` is a real zero.

        This is the distinction the whole read depends on. A listener that
        received nothing and a listener nobody asked about must not arrive as
        the same number.
        """

        parsed = self.stat(row(pxname="front", svname="FRONTEND", req_tot="0"))

        counters = parsed["frontends"][0]["counters"]
        self.assertEqual(counters["req_tot"], 0)
        self.assertIsNone(counters["econ"])

    def test_columns_are_found_by_name_and_not_by_position(self) -> None:
        """A version that grew a column must not shift every field after it."""

        header = "# svname,pxname,newcolumn,req_tot,status"
        parsed = self.parse(f"{header}\nFRONTEND,front,whatever,5,OPEN\n")

        assert parsed is not None
        self.assertEqual(parsed["frontends"][0]["frontend"], "front")
        self.assertEqual(parsed["frontends"][0]["status"], "OPEN")
        self.assertEqual(parsed["frontends"][0]["counters"]["req_tot"], 5)

    def test_a_count_that_is_not_a_count_is_dropped_rather_than_guessed(self) -> None:
        parsed = self.stat(row(pxname="front", svname="FRONTEND", req_tot="not a number"))

        self.assertIsNone(parsed["frontends"][0]["counters"]["req_tot"])

    def test_a_row_that_names_neither_a_pool_nor_a_member_is_dropped(self) -> None:
        parsed = self.stat(",,,", row(pxname="front", svname="FRONTEND"))

        self.assertEqual(len(parsed["frontends"]), 1)
        self.assertEqual(parsed["servers"], [])

    def test_output_without_a_header_is_refused_rather_than_half_read(self) -> None:
        """None, not an empty answer: unreadable is not "this node has none"."""

        self.assertIsNone(self.parse("mgd-site-web,s1,UP\n"))
        self.assertIsNone(self.parse(""))

    def test_the_row_cap_covers_both_kinds_of_row(self) -> None:
        rows = [row(pxname=f"p{n}", svname="srv") for n in range(600)]
        parsed = self.stat(*rows)

        self.assertEqual(len(parsed["servers"]), 500)


#
# `show servers state` from HAProxy 3.4.6, captured 26-10-09 with s1 drained
# and then put in maintenance, s2 untouched, s3 drained, and c/x2 written
# `disabled` in the configuration.
#
SERVERS_STATE = """1
# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port
2 b 1 s1 127.0.0.1 0 1 50 50 1 8 2 0 14 0 0 0 - 1 - 0 0 - - 0
2 b 2 s2 127.0.0.1 0 0 1 1 1 8 2 0 6 0 0 0 - 2 - 0 0 - - 0
2 b 3 s3 127.0.0.1 2 8 1 1 1 1 0 0 0 0 0 0 - 3 - 0 0 - - 0
4 c 2 x2 127.0.0.1 0 5 1 1 1 1 0 0 8 0 0 0 - 6 - 0 0 - - 0
"""  # noqa: E501 - HAProxy's own line


class ReadingAdminState(unittest.TestCase):
    """Drain and maintenance, which `show stat` loses for a server that is down (B263)."""

    def setUp(self) -> None:
        found = PARSING.search(SCRIPT.read_text())
        assert found, "the parsing is no longer where the test extracts it from"
        namespace: dict[str, Any] = {}
        exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
        self.states = namespace["parse_servers_state"]
        self.merge = namespace["with_admin_state"]
        self.parse = namespace["parse_stat"]

    def test_each_member_reads_its_admin_state(self) -> None:
        found = self.states(SERVERS_STATE)

        self.assertEqual(found[("b", "s1")], {"admin": "maint"})
        self.assertEqual(found[("b", "s2")], {"admin": "ready"})
        self.assertEqual(found[("b", "s3")], {"admin": "drain"})
        self.assertEqual(found[("c", "x2")]["admin"], "maint")

    def test_a_drained_server_that_is_down_still_reads_drained(self) -> None:
        """The case `show stat` cannot answer: its status column says DOWN."""

        stat = self.parse(f"{HEADER}\n{row(pxname='b', svname='s3', status='DOWN')}\n")
        merged = self.merge(stat, self.states(SERVERS_STATE))

        self.assertEqual(merged["servers"][0]["status"], "DOWN")
        self.assertEqual(merged["servers"][0]["admin"], "drain")

    def test_unread_is_unknown_and_not_ready(self) -> None:
        stat = self.parse(f"{HEADER}\n{row(pxname='b', svname='s9', status='UP')}\n")

        for states in (None, self.states(SERVERS_STATE)):
            merged = self.merge(stat, states)
            self.assertIsNone(merged["servers"][0]["admin"])

    def test_output_without_the_columns_is_refused(self) -> None:
        self.assertIsNone(self.states(""))
        self.assertIsNone(self.states("1\n# be_id be_name srv_name\n2 b s1\n"))


UNAPPLIED_READER = re.compile(
    r"^def read_server_state_unapplied\(\):.*?(?=^def read_resources\()", re.DOTALL | re.MULTILINE
)


class ReadingUnappliedStates(unittest.TestCase):
    """Review 26-10-09, F1: a kept drain a reload could not put back is reported."""

    def setUp(self) -> None:
        import json
        import tempfile

        found = UNAPPLIED_READER.search(SCRIPT.read_text())
        assert found, "the reader is no longer where the test extracts it from"
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "unapplied"
        namespace: dict[str, Any] = {
            "json": json,
            "SERVER_STATE_UNAPPLIED": self.path,
            "SERVER_GUID": re.compile(r"^srv:[a-z][a-z0-9_-]{0,39}\.[0-9a-f]{16}$"),
            "MAX_STAT_ROWS": 500,
        }
        exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
        self.read = namespace["read_server_state_unapplied"]

    def test_no_file_is_nothing_unapplied(self) -> None:
        self.assertEqual(self.read(), {})

    def test_the_kept_states_are_reported_and_anything_else_dropped(self) -> None:
        self.path.write_text(
            '{"schema_version": 1, "servers": {"srv:shop.1111111111111111": "drain",'
            ' "srv:shop.2222222222222222": "ready", "not-a-guid": "maint"}}'
        )

        self.assertEqual(self.read(), {"srv:shop.1111111111111111": "drain"})

    def test_an_unreadable_record_is_unknown(self) -> None:
        self.path.write_text("not json")

        self.assertIsNone(self.read())


PACKAGE_READER = re.compile(
    r"^PACKAGES = \{.*?^def read_packages\(\):.*?^    return found\n", re.DOTALL | re.MULTILINE
)


class ReadingPackages(unittest.TestCase):
    """26-10-09: what a node runs beside HAProxy's process, for the version notes."""

    def test_each_package_is_read_and_openssl_by_either_name(self) -> None:
        found = PACKAGE_READER.search(SCRIPT.read_text())
        assert found, "the reader is no longer where the test extracts it from"
        installed = {"haproxy": "3.4.6-1ppa1~resolute", "libssl3": "3.0.13-0ubuntu3.5"}
        namespace: dict[str, Any] = {
            "DNS_PACKAGE": "dnsdist",
            "WAF_PACKAGE": "haproxy-manager-coraza-spoa",
            "package_version": installed.get,
        }
        exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk

        self.assertEqual(
            namespace["read_packages"](),
            {
                "haproxy": "3.4.6-1ppa1~resolute",
                "keepalived": None,
                "dnsdist": None,
                "waf_engine": None,
                "openssl": "3.0.13-0ubuntu3.5",
            },
        )


if __name__ == "__main__":
    unittest.main()
