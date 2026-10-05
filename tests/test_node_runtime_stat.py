"""What a node makes of `show stat`, and what it refuses to make of it.

The parsing is extracted from `install/node/haproxy-node-status` verbatim and
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

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haproxy-node-status"
PARSING = re.compile(r"^MAX_STAT_ROWS = .*?(?=^def runtime_stat\()", re.DOTALL | re.MULTILINE)

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


if __name__ == "__main__":
    unittest.main()
