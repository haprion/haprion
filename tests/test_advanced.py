"""Where each line of an object's advanced config goes, and what is refused (B223, B224).

Every refusal here is a case HAProxy itself would have let through: a line
ignored with a warning `-c` does not fail on, a line accepted without a word
that does nothing, or a line that would quietly change the cluster's counters
or another object's. The tests are named after the rule, so a failure points at
a sentence in the plan.
"""

from __future__ import annotations

import gzip
import shutil
import subprocess
import unittest
from pathlib import Path

from haprion import advanced
from haprion.advanced import IGNORED, PLACED, REFUSED_FATE, SKIPPED, place

MANUAL = Path("/usr/share/doc/haproxy/configuration.txt.gz")


def fates(text: str, **options: object) -> list[tuple[int, str, str]]:
    arguments: dict[str, object] = {
        "name": "shop",
        "protocol": "http",
        "rate_limit": False,
        "handwritten": False,
    }
    arguments.update(options)
    placement = place(text, **arguments)  # type: ignore[arg-type]
    return [(line.number, line.fate, line.where) for line in placement.lines]


def fate(line: str, **options: object) -> str:
    return fates(line + "\n", **options)[0][1]


#
# A table, a ring and a cache of the text's own, for a line that names one.
#
OWN = "backend shop-t\nring shop-r\ncache shop-c\n"


def fate_beside_own(line: str, **options: object) -> str:
    return fates(line + "\n" + OWN, **options)[0][1]


class TheKeywordTableIsTheManualS(unittest.TestCase):
    @unittest.skipUnless(MANUAL.exists(), "the HAProxy manual is not installed here")
    def test_the_matrix_equals_section_4_1_of_the_installed_manual(self) -> None:
        with gzip.open(MANUAL, "rt", encoding="utf-8") as manual:
            text = manual.read().split("\n")
        start = text.index("4.1. Proxy keywords matrix")
        end = text.index("4.2. Alphabetically sorted keywords reference", start)

        self.assertEqual(advanced.parse_matrix(text[start:end]), advanced.KEYWORDS)

    def test_the_longest_keyword_wins(self) -> None:
        self.assertEqual(
            advanced.keyword_of(["capture", "request", "header", "Host"])[0],
            ("capture", "request", "header"),
        )
        self.assertEqual(advanced.keyword_of(["timeout", "server", "5s"])[0], ("timeout", "server"))

    def test_no_and_default_only_invert_what_haproxy_lets_be_inverted(self) -> None:
        self.assertEqual(
            advanced.keyword_of(["no", "option", "redispatch"])[0], ("option", "redispatch")
        )
        self.assertEqual(advanced.keyword_of(["no", "option", "httpchk"]), (None, None))


class LinesAreSplitTheWayHAProxySplitsThem(unittest.TestCase):
    def test_quotes_group_and_an_unquoted_hash_ends_the_line(self) -> None:
        self.assertEqual(
            advanced.words("http-request set-header X 'a # b' \"c d\" # comment"),
            ["http-request", "set-header", "X", "a # b", "c d"],
        )

    def test_a_backslash_escapes_outside_single_quotes(self) -> None:
        self.assertEqual(advanced.words(r"acl a path /a\ b"), ["acl", "a", "path", "/a b"])

    def test_an_open_quote_is_refused(self) -> None:
        self.assertEqual(fate("http-request deny if { path 'x }"), REFUSED_FATE)

    def test_a_word_inside_quotes_is_not_a_parameter(self) -> None:
        self.assertEqual(fate("http-request set-header X 'track-sc0'"), PLACED)


class TheEscapesAreReadAsHAProxyReadsThem(unittest.TestCase):
    """Code review 26-10-22, 5-1 (B349): HAProxy decodes `\\xNN`, `\\n`, `\\r` and `\\t`
    outside single quotes. Read as a backslash and a letter, `\\x67lobal` was the word
    `x67lobal` here and the section `global` on the node - with `insecure-fork-wanted`
    and an `external-check command` under it, a command on every node."""

    def test_the_escapes_are_decoded_outside_single_quotes(self) -> None:
        self.assertEqual(advanced.words(r"\x67lobal"), ["global"])
        self.assertEqual(advanced.words(r'x "a\x41\tb"'), ["x", "aA\tb"])
        self.assertEqual(advanced.words(r"x a\nb\rc"), ["x", "a\nb\rc"])
        self.assertEqual(advanced.words(r"x '\x67'"), ["x", r"\x67"])

    def test_a_hex_escape_that_is_not_two_digits_is_refused(self) -> None:
        self.assertEqual(fate(r"http-request set-header X a\xZZ"), REFUSED_FATE)

    def test_a_section_spelled_with_an_escape_is_the_section(self) -> None:
        text = "cache shop-c\n    \\x67lobal\n    insecure-fork-wanted\n    external-check\n"
        self.assertEqual(
            [entry[1] for entry in fates(text)], [PLACED, REFUSED_FATE, REFUSED_FATE, REFUSED_FATE]
        )

    def test_a_parameter_spelled_with_an_escape_is_the_parameter(self) -> None:
        for line in (
            r"http-request \x74rack-sc0 src table shop-t",
            r"http-request set-var(txn\x2ecoraza.action) str(allow)",
            r"\x73ource 192.0.2.1",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), REFUSED_FATE)


class AFileTheTextNamesIsAnErrorPage(unittest.TestCase):
    """Code review 26-10-22, 5-2 (B349): HAProxy reads a file it is told to serve as
    root, at load, and the sandbox checked it against a placeholder - so a `return
    file` naming another object's key served the key to anyone who asked."""

    def test_return_and_error_files_outside_the_error_pages_are_refused(self) -> None:
        for line in (
            "http-request return status 200 file /etc/haproxy/certs/other.pem if { path /x }",
            "http-request return status 200 lf-file /etc/shadow",
            "http-response return status 503 errorfile /etc/haproxy/certs/other.pem",
            "http-error status 503 file /etc/haproxy/errors/../certs/other.pem",
            "errorfile 503 /etc/haproxy/maps/../certs/other.pem",
            "errorfile 503 errors/503.http",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), REFUSED_FATE)

    def test_the_packaged_error_pages_may_be_named(self) -> None:
        self.assertEqual(fate("errorfile 503 /etc/haproxy/errors/503.http"), PLACED)
        self.assertEqual(
            fate("http-request return status 503 file /etc/haproxy/errors/503.http"), PLACED
        )

    def test_the_rule_holds_in_the_sections_the_text_adds(self) -> None:
        for text in (
            "http-errors shop-e\n    errorfile 503 /etc/haproxy/certs/other.pem\n",
            "backend shop-b\n    http-request return status 200 file /etc/shadow\n",
        ):
            with self.subTest(text):
                self.assertEqual(fates(text)[1][1], REFUSED_FATE)


class AFileIsNamedTheWayTheGeneratorNamesIt(unittest.TestCase):
    """Code review 26-10-30 again, R1: HAProxy reads a converter's arguments a second
    time and takes `'` and `"` away again, so `\\'..\\'` passed the path check as a
    name and was `..` to HAProxy - a map read any file on the node as root, and the
    candidate's rewrite of `/etc/haproxy/certs/` put a cluster certificate in reach.
    Every path the text may name is now a directory and one plain name."""

    def test_a_quoted_dot_dot_is_refused_wherever_a_file_is_named(self) -> None:
        for line in (
            r"http-request set-var(txn.x) req.hdr(x),map_str(/etc/haproxy/maps/\'..\'/certs/a.pem)",
            r"http-request set-var(txn.x) req.hdr(x),map_str(/etc/haproxy/maps/\"..\"/certs/a.pem)",
            r"http-request set-var(txn.x) req.hdr(x),map(/etc/haproxy/maps/\..)",
            "http-request set-var(txn.x) req.hdr(x),map(/etc/haproxy/maps/..)",
            "http-request set-var(txn.x) req.hdr(x),map(/etc/haproxy/maps/.)",
            "http-request set-var(txn.x) req.hdr(x),map(/etc/haproxy/maps/sub/a.map)",
            r"acl a req.hdr(x) -f /etc/haproxy/maps/\'..\'/x",
            r"http-request return status 200 file /etc/haproxy/errors/\'..\'/hostname",
            "http-request return status 200 file /etc/haproxy/errors/503.html",
            r"server s1 192.0.2.5:443 ssl verify required ca-file /etc/haproxy/certs/ca/\'..\'",
            "server s1 192.0.2.5:443 ssl verify required ca-file /etc/haproxy/certs/ca/x/../a",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line, handwritten=True), REFUSED_FATE)

    def test_a_cluster_certificate_cannot_be_read_as_a_list(self) -> None:
        up = "/".join([r"\'..\'"] * 3)
        for line in (
            rf"http-request set-var(txn.x) req.hdr(x),map_str(/etc/haproxy/maps/{up}/etc/haproxy/certs/site.pem)",
            "http-request set-var(txn.x) req.hdr(x),map_str(/etc/haproxy/certs/site.pem)",
            "acl a req.hdr(x) -f /etc/haproxy/certs/site.pem",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), REFUSED_FATE)

    def test_the_generator_s_own_names_pass(self) -> None:
        for line in (
            "acl se src -f /etc/haproxy/maps/geo-se.lst",
            "http-request set-var(txn.x) req.hdr(host),map_dom(/etc/haproxy/maps/hosts.map,none)",
            "http-request return status 503 file /etc/haproxy/errors/503.http",
            "server s1 192.0.2.5:443 ssl verify required ca-file /etc/haproxy/certs/ca/root-1.pem",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line, handwritten=True), PLACED)

    @unittest.skipUnless(shutil.which("haproxy"), "HAProxy is not installed here")
    def test_haproxy_itself_reads_the_quoted_dot_dot_as_dot_dot(self) -> None:
        """What makes the refusal needed: the line `place` now refuses opens the file."""

        import tempfile

        haproxy = shutil.which("haproxy")
        assert haproxy is not None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "maps").mkdir()
            (root / "secret.txt").write_text("k v\n")
            line = (
                r"http-request set-var(txn.x) req.hdr(x),"
                rf"map_str({root}/maps/\'..\'/secret.txt)"
            )
            config = root / "t.cfg"
            config.write_text(
                "defaults\n    mode http\n    timeout client 1s\n    timeout server 1s\n"
                f"    timeout connect 1s\nbackend b\n    {line}\n"
            )
            checked = subprocess.run(
                [haproxy, "-c", "-f", str(config)],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            (root / "secret.txt").unlink()
            missing = subprocess.run(
                [haproxy, "-c", "-f", str(config)],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

        self.assertNotIn("failed to open pattern file", checked.stdout + checked.stderr)
        self.assertIn("/maps/../secret.txt", missing.stdout + missing.stderr)
        self.assertEqual(
            fate(line.replace(str(root), "/etc/haproxy").replace("/secret.txt", "/x")),
            REFUSED_FATE,
        )


class TheObjectSRowsLandInItsOwnSections(unittest.TestCase):
    def test_http_rows_go_to_every_pool(self) -> None:
        self.assertEqual(fates("http-request deny\n"), [(1, PLACED, "every pool")])

    def test_a_frontend_header_says_the_object_s_rows_follow(self) -> None:
        self.assertEqual(
            fates("frontend whatever\n    http-request deny\n"),
            [(1, IGNORED, ""), (2, PLACED, "every pool")],
        )

    def test_a_frontend_only_keyword_on_http_is_refused_because_the_frontend_is_shared(
        self,
    ) -> None:
        self.assertEqual(fate("capture request header Host len 20"), REFUSED_FATE)
        self.assertEqual(fate("timeout client 5s"), REFUSED_FATE)

    def test_tcp_rows_go_to_the_frontend_when_haproxy_takes_them_there(self) -> None:
        self.assertEqual(
            fates("tcp-request content reject\nretries 5\n", protocol="tcp"),
            [(1, PLACED, advanced.FRONTEND), (2, PLACED, "pool")],
        )

    def test_comments_and_blank_lines_are_not_written(self) -> None:
        self.assertEqual(
            fates("# note\n\nhttp-request deny\n")[:2], [(1, IGNORED, ""), (2, IGNORED, "")]
        )

    def test_an_unknown_keyword_is_refused_rather_than_guessed(self) -> None:
        self.assertEqual(fate("frobnicate on"), REFUSED_FATE)

    def test_a_line_of_more_words_than_haproxy_reads_is_refused(self) -> None:
        networks = " ".join(f"192.0.2.{host}" for host in range(1, 63))
        self.assertEqual(fate(f"acl a src {networks[: networks.rindex(' ')]}"), PLACED)
        self.assertEqual(fate(f"acl a src {networks}"), REFUSED_FATE)

    def test_conditional_blocks_are_refused(self) -> None:
        self.assertEqual(fate(".if defined(X)"), REFUSED_FATE)


class WhatIsAlwaysTheInterfaceS(unittest.TestCase):
    def test_address_routing_source_and_identity_are_refused(self) -> None:
        for line in (
            "bind :8080",
            "use_backend other",
            "default_backend other",
            "source 192.0.2.1",
            "guid x",
            "option transparent",
        ):
            with self.subTest(line=line):
                self.assertEqual(fate(line), REFUSED_FATE)

    def test_the_protocol_is_skipped(self) -> None:
        self.assertEqual(fate("mode tcp"), SKIPPED)


class ThePoolIsTheFormSUnlessWrittenByHand(unittest.TestCase):
    def test_pool_lines_are_skipped_when_the_form_has_the_pool(self) -> None:
        for line in (
            "server s9 192.0.2.9:80",
            "balance leastconn",
            "timeout server 5s",
            "option httpchk",
            "http-check expect status 200",
            "cookie SRV insert",
        ):
            with self.subTest(line=line):
                self.assertEqual(fate(line), SKIPPED)

    def test_pool_lines_are_the_pool_when_it_is_written_by_hand(self) -> None:
        placement = place(
            "balance leastconn\nserver a 192.0.2.1:80 check\nserver b [2001:db8::1]:80\n",
            name="shop",
            protocol="http",
            rate_limit=False,
            handwritten=True,
        )

        self.assertEqual([line.where for line in placement.lines], ["pool"] * 3)
        self.assertEqual(placement.servers, (("a", "192.0.2.1:80"), ("b", "2001:db8::1:80")))

    def test_a_server_may_not_name_its_own_source_or_identity(self) -> None:
        self.assertEqual(
            fate("server a 192.0.2.1:80 source 192.0.2.9", handwritten=True), REFUSED_FATE
        )
        self.assertEqual(fate("default-server usesrc client", handwritten=True), REFUSED_FATE)
        self.assertEqual(fate("server a 192.0.2.1:80 guid x", handwritten=True), REFUSED_FATE)


class TheCountersBelongToWhoeverTracksThemFirst(unittest.TestCase):
    def test_sc0_is_the_cluster_s_and_never_the_text_s(self) -> None:
        self.assertEqual(fate("http-request track-sc0 src table shop-t"), REFUSED_FATE)
        self.assertEqual(fate("http-request sc-inc-gpc0(0)"), REFUSED_FATE)

    def test_sc1_is_the_text_s_only_while_the_form_has_no_rate_limit(self) -> None:
        line = "http-request track-sc1 src table shop-t"
        self.assertEqual(fate(line, rate_limit=True), REFUSED_FATE)
        self.assertEqual(fate_beside_own(line, rate_limit=False), PLACED)
        self.assertEqual(fate("http-request sc-set-gpt(0,1) 1", rate_limit=True), REFUSED_FATE)

    def test_sc3_and_sc4_are_the_text_s_only_while_the_form_has_no_dynamic_blocking(self) -> None:
        for slot in (3, 4):
            line = f"http-request track-sc{slot} src table shop-t"
            with self.subTest(slot):
                self.assertEqual(fate(line, dynamic_block=True), REFUSED_FATE)
                self.assertEqual(fate_beside_own(line, dynamic_block=False), PLACED)
                self.assertEqual(
                    fate(f"http-request sc-inc-gpc0({slot})", dynamic_block=True), REFUSED_FATE
                )
        section = "backend shop-t\n    http-request track-sc4 src\n"
        self.assertEqual(fates(section, dynamic_block=True)[1][1], REFUSED_FATE)

    def test_a_slot_is_read_as_haproxy_reads_it(self) -> None:
        """Code review 26-10-30 again, R4: HAProxy reads `+0` and `-0` as slot 0."""

        for line in (
            "http-request sc-inc-gpc0(+0)",
            "http-request sc-inc-gpc0",
            "http-request sc-set-gpt0 1",
            "http-request sc-inc-gpc0(-0)",
            "http-request sc-inc-gpc(0,+0)",
            "http-request sc-set-gpt0(+0) 1",
            "http-request sc-inc-gpc0(0x0)",
            "http-request deny if { sc_inc_gpc0(+0) gt 1 }",
            "http-request deny if { sc0_inc_gpc0 gt 1 }",
            "http-request deny if { sc0_clr_gpc1 ge 0 }",
            "http-request deny if { sc_clr_gpc(1,0) ge 0 }",
            "http-request deny if { sc_inc_gpc1(00) gt 1 }",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line, rate_limit=True), REFUSED_FATE)
        for line in (
            "http-request deny if { sc1_inc_gpc0 gt 1 }",
            "http-request deny if { sc_inc_gpc(1,+1) gt 1 }",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line, rate_limit=True), REFUSED_FATE)
                self.assertEqual(fate(line, rate_limit=False), PLACED)
        self.assertEqual(fate("http-request deny if { sc_inc_gpc(3,4) gt 1 }"), PLACED)
        self.assertEqual(
            fate("http-request deny if { sc_inc_gpc(3,4) gt 1 }", dynamic_block=True), REFUSED_FATE
        )

    def test_the_counters_may_be_read(self) -> None:
        self.assertEqual(
            fate("http-request deny if { sc_http_req_rate(1) gt 5 }", rate_limit=True), PLACED
        )

    def test_a_counter_on_the_object_s_rows_names_a_table_of_the_text_s(self) -> None:
        self.assertEqual(fate("http-request track-sc2 src"), REFUSED_FATE)
        self.assertEqual(fate("http-request track-sc2 src table other-t"), REFUSED_FATE)
        self.assertEqual(fate_beside_own("http-request track-sc2 src table shop-t"), PLACED)

    def test_a_stick_rule_on_the_object_s_rows_names_a_table_of_the_text_s(self) -> None:
        self.assertEqual(fate("stick on src"), REFUSED_FATE)
        self.assertEqual(fate_beside_own("stick on src table shop-t"), PLACED)

    def test_a_table_on_the_object_s_rows_is_refused(self) -> None:
        self.assertEqual(fate("stick-table type ip size 1k"), REFUSED_FATE)


class ALineWritesOnlyToSectionsOfItsOwnText(unittest.TestCase):
    """Code review 26-10-30 again, R2 and R5: a table was the text's when its name began
    with the object's, so object `shop` counted into `shop-api`'s tables, and a
    `stick-table ... write-to` copied every peer update into another object's dynamic
    blocking table - a visitor of one object was blocked on another. A name is now held
    to the sections the same text adds."""

    def test_a_table_another_text_adds_is_refused_though_its_name_begins_with_ours(
        self,
    ) -> None:
        for line in (
            "http-request track-sc2 src table shop-api-t",
            "stick on src table shop-api-t",
            "log ring@shop-api-r local0",
        ):
            with self.subTest(line):
                self.assertEqual(fate_beside_own(line), REFUSED_FATE)

    def test_the_same_table_added_by_the_text_is_placed(self) -> None:
        text = "http-request track-sc2 src table shop-api-t\nbackend shop-api-t\n"
        self.assertEqual(fates(text)[0][1], PLACED)

    def test_write_to_names_a_table_of_the_text_s_own(self) -> None:
        for table in ("mgd-x-dynblock", "shop-api-t"):
            with self.subTest(table):
                text = f"backend shop-t\n    stick-table type ip size 1k write-to {table}\n"
                self.assertEqual(fates(text)[1][1], REFUSED_FATE)
        text = (
            "backend shop-t\n    stick-table type ip size 1k write-to shop-u store gpc0\n"
            "backend shop-u\n    stick-table type ip size 1k store gpc0\n"
        )
        self.assertEqual({entry[1] for entry in fates(text)}, {PLACED})

    def test_a_table_is_read_parameter_by_parameter(self) -> None:
        refused = "backend shop-t\n    stick-table type ip size 1k frobnicate 1\n"
        self.assertEqual(fates(refused)[1][1], REFUSED_FATE)
        placed = (
            "backend shop-t\n    stick-table type string len 64 size 1k expire 10m nopurge "
            "srvkey name brates-factor 2 store gpc0,http_req_rate(10s) store gpt0 recv-only\n"
        )
        self.assertEqual(fates(placed)[1][1], PLACED)

    def test_a_fetch_or_converter_that_creates_entries_writes_only_to_its_own_table(
        self,
    ) -> None:
        for line in (
            "http-request deny if { src,table_inc_gpc0(mgd-bank-dynblock) gt 0 }",
            "http-request deny if { src,table_inc_gpc(1,mgd-bank-dynblock) gt 0 }",
            "http-request deny if { src,table_clr_gpc1(other-t) ge 0 }",
            "http-request deny if { src_inc_gpc0(other-t) gt 0 }",
            "http-request deny if { src_updt_conn_cnt(other-t) gt 0 }",
            "http-request deny if { sc_inc_gpc0(2,other-t) gt 0 }",
            "http-request deny if { sc_inc_gpc(1,2,other-t) gt 0 }",
            "http-request deny if { sc2_clr_gpc0(other-t) ge 0 }",
            r"http-request deny if { src,table_inc_gpc0(\'mgd-x\') gt 0 }",
            "http-request deny if { src,table_inc_gpc0 gt 0 }",
            "http-request deny if { src_inc_gpc0 gt 0 }",
            "http-request set-var(txn.x) src,debug(x,other-r)",
            "http-request set-var(txn.x) src,debug(x,stderr)",
        ):
            with self.subTest(line):
                self.assertEqual(fate_beside_own(line), REFUSED_FATE)
        for line in (
            "http-request deny if { src,table_inc_gpc0(shop-t) gt 0 }",
            "http-request deny if { src,table_inc_gpc(1,shop-t) gt 0 }",
            "http-request deny if { sc_inc_gpc(1,2,shop-t) gt 0 }",
            "http-request deny if { sc2_inc_gpc0 gt 0 }",
            "http-request deny if { src,table_http_req_rate(other-t) gt 10 }",
            "http-request set-var(txn.x) src,debug(x,shop-r)",
            "http-request set-var(txn.x) src,debug(x)",
        ):
            with self.subTest(line):
                self.assertEqual(fate_beside_own(line), PLACED)
        in_own_backend = "backend shop-t\n    http-request deny if { src,table_inc_gpc0 gt 0 }\n"
        self.assertEqual(fates(in_own_backend)[1][1], PLACED)

    @unittest.skipUnless(MANUAL.exists(), "the HAProxy manual is not installed here")
    def test_the_table_parameters_are_the_manual_s_synopsis(self) -> None:
        import re

        with gzip.open(MANUAL, "rt", encoding="utf-8") as manual:
            text = manual.read()
        chapter = text[text.index("11.1. stick-table declaration") :]
        synopsis = chapter[chapter.index("stick-table type") : chapter.index('In a "peers"')]
        named = set(re.findall(r"(?:^|[\s\[])([a-z][a-z-]+) <", synopsis))
        named |= set(re.findall(r"\[([a-z-]+)\]", synopsis))
        self.assertEqual(named | {"len"}, set(advanced.STICK_TABLE_PARAMETERS))


class WhatASectionAsksOfTheNodesMemoryIsBounded(unittest.TestCase):
    """Code review 26-10-30 again, R3: `cache ... total-max-size 4095` was placed.
    `haproxy -c` allocates no cache, so the check passed, and the reload maps the
    whole size at once on every node together."""

    def test_a_size_beyond_the_most_is_refused(self) -> None:
        for text in (
            "cache shop-c\n    total-max-size 4095\n",
            "cache shop-c\n    total-max-size 65\n",
            "cache shop-c\n    total-max-size +4\n",
            "cache shop-c\n    max-object-size 33554433\n",
            "ring shop-r\n    size 1g\n",
            "ring shop-r\n    size 16777217\n",
            "backend shop-t\n    stick-table type ip size 2000m\n",
            "backend shop-t\n    stick-table type ip size 102401\n",
            "backend shop-t\n    stick-table type string len 300000 size 1k\n",
            "backend shop-t\n    stick-table type ip size 0x10\n",
        ):
            with self.subTest(text):
                self.assertEqual(fates(text)[1][1], REFUSED_FATE)

    def test_a_size_within_the_most_is_placed(self) -> None:
        for text in (
            "cache shop-c\n    total-max-size 64\n    max-object-size 33554432\n",
            "ring shop-r\n    size 16m\n",
            "backend shop-t\n    stick-table type ip size 100k\n",
            "backend shop-t\n    stick-table type string len 256 size 102400\n",
        ):
            with self.subTest(text):
                self.assertEqual({entry[1] for entry in fates(text)}, {PLACED})

    def test_a_table_is_counted_by_what_it_stores(self) -> None:
        """Code review 26-10-30 again, S4: `store gpc(100),gpc_rate(100,1m),gpt(100)` is
        about 2.5 KB an entry, 250 MB full, and the cap counted none of it."""

        table = "backend shop-t\n    stick-table type string len 256 size 100k {}\n"
        for stored in (
            "store gpc(100),gpc_rate(100,1m),gpt(100)",
            "store gpc(100),gpc_rate(100,1m)",
            "store gpc(100) store gpt(100) store http_req_rate(10s)",
            "store gpc(100),frobnicate",
            "store gpc(x)",
        ):
            with self.subTest(stored):
                self.assertEqual(fates(table.format(stored))[1][1], REFUSED_FATE)
        for stored in (
            "store gpc0,http_req_rate(10s)",
            "store gpc(4),gpc_rate(4,1m),gpt0,server_id",
            "",
        ):
            with self.subTest(stored):
                self.assertEqual(
                    {entry[1] for entry in fates(table.format(stored).replace("256", "64"))},
                    {PLACED},
                )

    def test_a_text_adds_few_tables_and_rings(self) -> None:
        tables = "".join(f"backend shop-t{n}\n    stick-table type ip size 1k\n" for n in range(5))
        self.assertEqual([entry[1] for entry in fates(tables)][-1], REFUSED_FATE)
        self.assertEqual([entry[1] for entry in fates(tables)][-2], PLACED)
        self.assertEqual({entry[1] for entry in fates(tables.rsplit("backend", 1)[0])}, {PLACED})
        rings = "".join(f"ring shop-r{n}\n    size 1k\n" for n in range(5))
        self.assertEqual(fates(rings)[-2][1], REFUSED_FATE)

    def test_the_tables_and_rings_of_a_cluster_are_bounded_together(self) -> None:
        from haprion.generate import GeneratorError

        def grown(name: str) -> tuple[str, str]:
            table = f"backend {name}-t\n    stick-table type integer size 100k store gpc(50)"
            return name, _object(name, table)

        names = "abcdefgh"
        _generate(*(grown(name) for name in names[:7]))
        with self.assertRaisesRegex(
            GeneratorError, "tables and rings .* have 256 MB|256 MB for them"
        ):
            _generate(*(grown(name) for name in names))

    def test_debug_arguments_are_read_without_quotes(self) -> None:
        """Code review 26-10-30 again, S2: HAProxy unquotes `debug`'s arguments a second
        time, so `'a,shop-r,b',bank-r` wrote to the ring `bank-r`."""

        for line in (
            r"http-request set-var(txn.x) src,debug(\'a,shop-r,b\',other-r)",
            r"http-request set-var(txn.x) src,debug(\"a,shop-r,b\",other-r)",
        ):
            with self.subTest(line):
                self.assertEqual(fate_beside_own(line), REFUSED_FATE)
        self.assertEqual(
            fate_beside_own("http-request set-var(txn.x) src,debug(msg,shop-r)"), PLACED
        )

    def test_a_keyword_written_twice_is_refused(self) -> None:
        """Code review 26-10-30 again, S1: the cap read the first `total-max-size`, HAProxy
        takes the last, so `0` then `64` counted as nothing and took 64 MB."""

        for text in (
            "cache shop-c\n    total-max-size 0\n    total-max-size 64\n",
            "cache shop-c\n    max-age 1\n    max-age 2\n",
            "ring shop-r\n    size 1k\n    size 16m\n",
            "ring shop-r\n    timeout connect 1s\n    timeout connect 2s\n",
            "backend shop-t\n    stick-table type ip size 1\n    stick-table type ip size 2\n",
            "backend shop-t\n    stick-table type ip size 1 size 100k\n",
        ):
            with self.subTest(text):
                self.assertEqual(fates(text)[-1][1], REFUSED_FATE)
        for text in (
            "ring shop-r\n    timeout connect 1s\n    timeout server 2s\n",
            "ring shop-r\n    server a 192.0.2.1:514\n    server b 192.0.2.2:514\n",
            "backend shop-t\n    stick-table type ip size 1 store gpc0 store gpt0\n",
        ):
            with self.subTest(text):
                self.assertEqual({entry[1] for entry in fates(text)}, {PLACED})

    def test_the_caches_of_a_cluster_are_bounded_together(self) -> None:
        from haprion.generate import GeneratorError

        def cached(name: str) -> tuple[str, str]:
            return name, _object(name, f"cache {name}-c\n    total-max-size 64")

        _generate(*(cached(name) for name in ("a", "b", "c", "d")))
        with self.assertRaisesRegex(GeneratorError, "come to 320 MB, and a cluster has 256 MB"):
            _generate(*(cached(name) for name in ("a", "b", "c", "d", "e")))


class TheWafEngineNamesAreTheGenerators(unittest.TestCase):
    """B232: the engine's verdict is read from `txn.coraza.*`; nothing else writes it."""

    def test_the_coraza_spoe_engine_is_refused(self) -> None:
        self.assertEqual(
            fate("filter spoe engine coraza config /etc/haproxy/waf/spoe.conf"), REFUSED_FATE
        )

    def test_the_engine_s_variables_and_group_are_refused_on_every_line(self) -> None:
        for line in (
            "http-request unset-var(txn.coraza.action)",
            "http-request set-var(txn.coraza.app) str(other)",
            "http-request send-spoe-group coraza coraza-req",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), REFUSED_FATE)

    def test_another_spoe_engine_is_refused_for_the_file_it_reads(self) -> None:
        self.assertEqual(
            fate("filter spoe engine mine config /etc/haproxy/mine.conf"), REFUSED_FATE
        )


class TheGeneratorSVariablesAreReadNotWritten(unittest.TestCase):
    """Code review 26-10-30 again, R6: `set-var(txn.rule)` and `set-var(txn.hsts)` were
    placed, and the pool runs after the frontend - the traffic log named the text's
    rule and the HSTS header was the text's."""

    def test_setting_or_clearing_one_is_refused(self) -> None:
        for line in (
            "http-request set-var(txn.rule) str(waf-engine:deny)",
            "http-request set-var(txn.traffic_host) str(bank.example.com)",
            "http-response set-var(txn.hsts) str(max-age=0)",
            'http-request set-var-fmt(txn.client) "%[src]"',
            "http-request unset-var(txn.access_path)",
            "http-request set-var(txn.x) str(a),set-var(txn.waf_body)",
            r"http-request set-var(txn.x) str(a),set-var(\'txn.rule\')",
            "http-request do-resolve(txn.client,dns) str(example.com)",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), REFUSED_FATE)

    def test_reading_one_is_placed(self) -> None:
        for line in (
            "http-request deny if { var(txn.rule) -m found }",
            "http-request set-var(txn.mine) var(txn.traffic_host)",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), PLACED)

    def test_the_list_is_every_variable_the_generator_names(self) -> None:
        import re

        from haprion import generate

        named = set(re.findall(r"txn\.[a-z_]+", Path(generate.__file__).read_text()))
        self.assertEqual(named - {"txn.coraza"}, advanced.GENERATED_VARIABLES)


class WhatShowsOrChangesOtherObjectsIsRefused(unittest.TestCase):
    """B405. B1: an anonymous POST to one object's stats page put another object's
    server in maintenance. B3: one object stored its content into another object's
    cache, which then served it to that object's visitors."""

    def test_every_stats_keyword_and_the_exporter_are_refused(self) -> None:
        for line in (
            "stats enable",
            "stats uri /hap-stats",
            "stats admin if TRUE",
            "stats http-request allow",
            "stats auth admin:secret",
            "stats scope shop",
            "http-request use-service prometheus-exporter if { path /metrics }",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), REFUSED_FATE)
                self.assertEqual(fate(line, protocol="tcp"), REFUSED_FATE)
                self.assertEqual(fates(f"backend shop-b\n    {line}\n")[1][1], REFUSED_FATE)

    def test_a_cache_is_used_only_by_the_text_that_adds_it(self) -> None:
        for line in (
            "http-request cache-use bank-c",
            "http-response cache-store bank-c",
            "filter cache bank-c",
            "http-request cache-use shop-api-c",
        ):
            with self.subTest(line):
                self.assertEqual(fate_beside_own(line), REFUSED_FATE)
        for line in (
            "http-request cache-use shop-c",
            "http-response cache-store shop-c if { status 200 }",
            "filter cache shop-c",
        ):
            with self.subTest(line):
                self.assertEqual(fate_beside_own(line), PLACED)

    def test_shared_variables_are_allowed(self) -> None:
        for line in (
            "http-request set-var(proc.shared) str(1)",
            "http-request set-var(sess.flag) str(1)",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), PLACED)


class SectionsTheTextAddsKeepTheirNames(unittest.TestCase):
    def test_a_backend_named_after_the_object_is_written_as_it_stands(self) -> None:
        placement = place(
            "backend shop-t\n    stick-table type ip size 1k\n    http-request track-sc2 src\n",
            name="shop",
            protocol="http",
            rate_limit=False,
            handwritten=False,
        )

        self.assertEqual([line.fate for line in placement.lines], [PLACED] * 3)
        self.assertEqual(placement.sections[0].name, "shop-t")
        self.assertEqual(len(placement.sections[0].lines), 2)

    def test_another_name_is_refused_with_everything_under_it(self) -> None:
        self.assertEqual(
            [entry[1] for entry in fates("backend waf\n    mode tcp\n")], [REFUSED_FATE] * 2
        )

    def test_the_cluster_s_and_the_process_s_sections_are_refused(self) -> None:
        for kind in ("global", "defaults", "program", "peers", "resolvers", "mailers", "crt-store"):
            with self.subTest(kind=kind):
                self.assertEqual(fate(f"{kind} shop-x"), REFUSED_FATE)

    def test_cache_errors_userlist_and_ring_are_allowed(self) -> None:
        for kind in ("cache", "http-errors", "userlist", "ring"):
            with self.subTest(kind=kind):
                self.assertEqual(fate(f"{kind} shop-x"), PLACED)

    def test_an_added_backend_gets_its_source_and_identity_from_the_generator(self) -> None:
        self.assertEqual(fates("backend shop-t\n    source 192.0.2.1\n")[1][1], REFUSED_FATE)

    def test_a_name_used_twice_is_refused(self) -> None:
        self.assertEqual(fates("backend shop-t\nbackend shop-t\n")[1][1], REFUSED_FATE)


class ATcpObjectHasNoRequests(unittest.TestCase):
    def test_what_3_4_6_ignores_in_tcp_mode_is_refused(self) -> None:
        for line in (
            "http-request deny",
            "http-error status 503",
            "capture request header Host len 9",
            "compression algo gzip",
            "errorfile 503 /dev/null",
            "option forwardfor",
            "timeout http-request 5s",
            "filter compression",
        ):
            with self.subTest(line=line):
                self.assertEqual(fate(line, protocol="tcp"), REFUSED_FATE)

    def test_a_health_check_over_http_is_still_a_tcp_pool_s_to_have(self) -> None:
        self.assertEqual(fate("option httpchk", protocol="tcp", handwritten=True), PLACED)


class TheGeneratedFileMapsBackToTheText(unittest.TestCase):
    def test_a_block_and_its_reading_are_inverses(self) -> None:
        placement = place(
            "# note\nhttp-request deny\nserver x 192.0.2.1:80\nhttp-response del-header X\n",
            name="shop",
            protocol="http",
            rate_limit=False,
            handwritten=False,
        )
        content = "\n".join(
            ["backend mgd-shop-web", "    mode http", *advanced.block("shop", placement.backend)]
        )

        self.assertEqual(advanced.text_lines(content), {4: ("shop", 2), 5: ("shop", 4)})

    def test_a_diagnostic_is_said_in_the_text_s_terms_and_a_warning_there_is_reported(self) -> None:
        files = {
            "1001-shop.cfg": "backend b\n    # advanced config of shop: lines 7\n    capture x\n"
        }
        diagnostics = (
            "[WARNING]  (1) : config : parsing [/candidate/conf.d/1001-shop.cfg:3] : 'capture' ignored\n"
            "[WARNING]  (1) : config : parsing [/candidate/conf.d/1001-shop.cfg:1] : other"
        )

        annotated, warnings = advanced.annotate(diagnostics, files)

        self.assertIn("(advanced config of shop, line 7)", annotated.split("\n")[0])
        self.assertNotIn("advanced config", annotated.split("\n")[1])
        self.assertEqual(len(warnings), 1)


class TheStoredTextIsNormalised(unittest.TestCase):
    def test_line_ends_trailing_blanks_and_trailing_lines_go(self) -> None:
        self.assertEqual(advanced.normalise("a  \r\nb\t\n\n\n"), "a\nb\n")

    def test_nothing_is_nothing(self) -> None:
        self.assertEqual(advanced.normalise(" \n\n"), "")


class EveryLineIsHeldToAListOfWhatItMayBe(unittest.TestCase):
    """Code review 26-10-30, E1: the sections the text adds other than a backend were held
    to nothing but `errorfile`, so `backing-file /etc/shadow` in a ring was written, and
    `haproxy -c` - run as root on every node - truncated the file and mapped the ring
    into it. Every section is now held to the keywords it may hold."""

    def test_a_ring_s_backing_file_is_refused(self) -> None:
        text = "ring shop-r\n    size 32768\n    backing-file /etc/shadow\n"

        self.assertEqual([entry[1] for entry in fates(text)], [PLACED, PLACED, REFUSED_FATE])
        placement = place(text, name="shop", protocol="http", rate_limit=False, handwritten=False)
        self.assertEqual([line.text for line in placement.sections[0].lines], ["size 32768"])

    def test_an_unknown_word_in_every_added_section_is_refused(self) -> None:
        for kind in advanced.SECTION_KEYWORDS:
            with self.subTest(kind=kind):
                self.assertEqual(fates(f"{kind} shop-x\n    frobnicate 1\n")[1][1], REFUSED_FATE)

    def test_what_each_added_section_takes_is_written(self) -> None:
        for text in (
            "cache shop-c\n    total-max-size 4\n    max-object-size 10000\n    max-age 60\n"
            "    process-vary on\n    max-secondary-entries 10\n",
            "http-errors shop-e\n    errorfile 503 /etc/haproxy/errors/503.http\n",
            "userlist shop-u\n    group admins\n    user a password '$6$salt$hash' groups admins\n",
            "ring shop-r\n    description 'the shop log'\n    format rfc5424\n    maxlen 1200\n"
            "    size 32768\n    timeout connect 5s\n    timeout server 10s\n"
            "    server syslog 192.0.2.5:6514 log-proto octet-count\n",
        ):
            with self.subTest(text):
                self.assertEqual({entry[1] for entry in fates(text)}, {PLACED})

    def test_a_ring_s_server_is_held_to_the_server_rules(self) -> None:
        for server in (
            "server s /run/haproxy/manager.sock",
            "server s 192.0.2.5:6514 ssl crt /etc/haproxy/certs/other.pem",
        ):
            with self.subTest(server):
                self.assertEqual(fates(f"ring shop-r\n    {server}\n")[1][1], REFUSED_FATE)

    def test_a_line_the_node_s_environment_would_fill_in_is_refused(self) -> None:
        for line in (
            'log "${NOTIFY_SOCKET}" local0',
            'http-request return status 200 file "/etc/haproxy/errors/${X}"',
            'server s1 "$HOME":80',
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), REFUSED_FATE)
        self.assertEqual(
            fates('ring shop-r\n    "${X-backing-file}" /etc/shadow\n')[1][1], REFUSED_FATE
        )

    def test_the_env_fetch_is_refused_wherever_an_expression_goes(self) -> None:
        """Code review 26-10-30, slutkoll P3-1: `%[env(PATH)]` put the node's environment
        into a response, as `"${PATH}"` would have."""

        for line in (
            "http-request set-header X-Env %[env(PATH)] if { path /x }",
            'http-request return status 200 content-type text/plain lf-string "%[env(PATH)]" '
            "if { path /x }",
            "http-request set-header X-Env %[env(PATH)]",
            "http-request set-var(txn.x) env(PATH)",
            "http-request deny if { env(STOP) -m found }",
            "acl stop env(STOP) -m found",
            "http-response set-header X %[str(a),concat(-,txn.x,)]%[ env(HOME)]",
            "tcp-check connect port 8081 sni env(HOME)",
            "server s1 192.0.2.5:443 ssl verify none sni env(HOME)",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line, handwritten=True), REFUSED_FATE)
        self.assertEqual(fate('log-format "%[env(PATH)]"', protocol="tcp"), REFUSED_FATE)
        self.assertEqual(
            fates("backend shop-b\n    http-request set-header X %[env(PATH)]\n")[1][1],
            REFUSED_FATE,
        )
        self.assertEqual(
            fates("ring shop-r\n    server s 192.0.2.5:514 sni env(HOME)\n")[1][1], REFUSED_FATE
        )
        for line in (
            "http-request set-header X-Env %[req.hdr(env)]",
            "http-request set-header X-Server %[hostname]",
            "http-request set-var(txn.x) str(environment)",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), PLACED)

    def test_a_dollar_haproxy_does_not_expand_is_text(self) -> None:
        for line in (
            "http-request set-header X '${HOME}'",
            'http-request deny if { path_reg "^/a$" }',
            "http-request set-header X $HOME",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), PLACED)

    def test_a_server_state_file_is_refused(self) -> None:
        for line in ("server-state-file-name /etc/shadow", "load-server-state-from-file local"):
            with self.subTest(line):
                self.assertEqual(fate(line, handwritten=True), REFUSED_FATE)
                self.assertEqual(fates(f"backend shop-b\n    {line}\n")[1][1], REFUSED_FATE)

    def test_an_external_check_is_refused_whoever_writes_the_pool(self) -> None:
        for line in (
            "external-check command /bin/sh",
            "external-check path /usr/bin",
            "option external-check",
        ):
            for handwritten in (False, True):
                with self.subTest(line, handwritten=handwritten):
                    self.assertEqual(fate(line, handwritten=handwritten), REFUSED_FATE)

    def test_a_log_goes_to_the_network_or_a_ring_of_the_text_s(self) -> None:
        for line in (
            "log /dev/log local0",
            "log unix@/run/haproxy/x.sock local0",
            "log fd@1 local0",
            "log stdout format raw local0",
            "log backend@shop-b local0",
            "log ring@other-r local0",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), REFUSED_FATE)
        for line in (
            "log global",
            "no log",
            "log 192.0.2.5:514 local0",
            "log udp@192.0.2.5:514 len 2048 local0 info",
            "log syslog.example.com:514 local0",
            "log ring@shop-r local0",
        ):
            with self.subTest(line):
                self.assertEqual(fate_beside_own(line), PLACED)

    def test_a_server_is_reached_at_a_network_address(self) -> None:
        for line in (
            "server s1 /run/haproxy/manager.sock",
            "server s1 unix@/run/haproxy/manager.sock",
            "server s1 abns@x",
            "server-template s 1-3 /run/x",
            "server s1 192.0.2.5:80 addr /run/x",
            "server s1 192.0.2.5:80 socks4 unix@/run/x",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line, handwritten=True), REFUSED_FATE)

    def test_a_health_check_connects_to_its_own_server(self) -> None:
        """Code review 26-10-30, slutkoll P1-1: `tcp-check connect addr unix@...` was placed,
        and on 3.4.7 the check opened the socket, wrote to it and read the answer."""

        review = (
            "option tcp-check\n"
            "tcp-check connect addr unix@/run/haproxy/manager.sock\n"
            'tcp-check send "prompt\\n"\n'
            "tcp-check expect string OK\n"
            "server s1 198.51.100.20:8080 check\n"
        )
        self.assertEqual(
            [entry[1] for entry in fates(review, handwritten=True)],
            [PLACED, REFUSED_FATE, PLACED, PLACED, PLACED],
        )
        for line in (
            "tcp-check connect addr unix@/run/haproxy/manager.sock",
            "http-check connect addr unix@/run/haproxy/manager.sock",
            "tcp-check connect addr 203.0.113.9 port 25",
            "http-check connect port 8081 addr 192.0.2.5",
            "tcp-check connect port req.hdr(x)",
            "tcp-check connect port 70000",
            "tcp-check connect frobnicate",
        ):
            for protocol in ("http", "tcp"):
                for handwritten in (False, True):
                    with self.subTest(line, protocol=protocol, handwritten=handwritten):
                        self.assertEqual(
                            fate(line, handwritten=handwritten, protocol=protocol), REFUSED_FATE
                        )
            with self.subTest(line, section="backend"):
                self.assertEqual(fates(f"backend shop-b\n    {line}\n")[1][1], REFUSED_FATE)
        for line in (
            "tcp-check connect",
            "tcp-check connect port 8081 ssl sni str(a.example.com) alpn h2 linger",
            "tcp-check connect default send-proxy via-socks4 proto none comment x",
            "http-check connect port 443 ssl alpn h2 comment x",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line, handwritten=True), PLACED)

    def test_a_server_names_no_file_but_its_authority(self) -> None:
        for line in (
            "server s1 192.0.2.5:443 ssl crt /etc/haproxy/certs/other.pem",
            "server s1 192.0.2.5:443 ssl verify required ca-file /etc/shadow",
            "server s1 192.0.2.5:443 ssl verify required ca-file /etc/haproxy/certs/ca/../a.pem",
            "server s1 192.0.2.5:443 ssl verify required ca-file @system-ca crl-file /x.pem",
            "server s1 192.0.2.5:443 namespace other",
            "default-server crt /etc/haproxy/certs/other.pem",
            "server s1 192.0.2.5:443 frobnicate 1",
            "crt /etc/haproxy/certs/other.pem",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line, handwritten=True, protocol="tcp"), REFUSED_FATE)
        for line in (
            "server s1 192.0.2.5:443 ssl verify required ca-file @system-ca sni str(a.example.com)",
            "server s1 192.0.2.5:443 ssl verify required ca-file /etc/haproxy/certs/ca/root.pem",
            "server s1 [2001:db8::5]:80 check inter 2s weight 10",
            "server s1 www.example.com:80 send-proxy-v2 set-proxy-v2-tlv-fmt(0x20) %[fc_pp_tlv(0x20)]",
            "server-template s 1-3 www.example.com:80 check",
            "default-server inter 3s fall 2 rise 3",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line, handwritten=True), PLACED)

    def test_a_filter_that_reads_a_file_is_refused(self) -> None:
        for line in (
            "filter spoe engine mine config /etc/shadow",
            "filter opentracing id x config /etc/shadow",
            "filter fcgi-app shop-f",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), REFUSED_FATE)
        self.assertEqual(fate("filter compression"), PLACED)

    def test_a_list_the_text_reads_is_one_of_the_cluster_s(self) -> None:
        for line in (
            "acl bad src -f /etc/shadow",
            "http-request deny if { src -f /etc/haproxy/maps/../certs/a.pem }",
            'http-request return status 200 lf-string "%[req.hdr(x),map(/etc/shadow)]"',
            "http-request set-header X %[src,map_ip(/etc/haproxy/certs/a.pem,none)]",
            "http-request set-map(/etc/haproxy/maps/hosts.map) %[req.hdr(k)] %[req.hdr(v)]",
            "http-request del-acl(/etc/haproxy/maps/geo-se.lst) %[src]",
            "http-request deny unless { var(txn.t),jwt_verify(RS256,/etc/shadow) -m int 1 }",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), REFUSED_FATE)
        for line in (
            "acl se src -f /etc/haproxy/maps/geo-se.lst",
            "http-request set-header X %[req.hdr(host),map_dom(/etc/haproxy/maps/hosts.map,none)]",
            "http-request deny unless { var(txn.t),jwt_verify(txn.alg,txn.key) -m int 1 }",
        ):
            with self.subTest(line):
                self.assertEqual(fate(line), PLACED)

    def test_the_directories_are_the_generator_s(self) -> None:
        from haprion import certificates, generate

        self.assertEqual(advanced.MAPS, f"{generate.MAPS_DIRECTORY}/")
        self.assertEqual(
            advanced.AUTHORITIES,
            f"{generate.NODE_CERTIFICATE_DIR}/{certificates.AUTHORITY_DIRECTORY}/",
        )


#
# Where the manual defines each added section's keywords (HAProxy 3.4).
#
_CHAPTERS = {
    "cache": ("6.2.1. Cache section", "6.2.2. Proxy section"),
    "userlist": ("12.2. Userlists", "12.3. Mailers"),
    "http-errors": ("12.4. HTTP-errors", "12.5. Rings"),
    "ring": ("12.5. Rings", "12.6. Log forwarding"),
}


def _registered() -> str:
    haproxy = shutil.which("haproxy")
    if haproxy is None:
        raise unittest.SkipTest("HAProxy is not installed here")
    return subprocess.run(
        [haproxy, "-dKall", "-q", "-c", "-f", "/dev/null"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    ).stdout


class EveryAllowedKeywordIsHAProxyS(unittest.TestCase):
    """The lists are written out, not derived, so they are held to the installed HAProxy:
    a keyword on them that HAProxy does not know would be one invented here."""

    @unittest.skipUnless(MANUAL.exists(), "the HAProxy manual is not installed here")
    def test_each_section_s_keywords_are_defined_in_its_chapter(self) -> None:
        with gzip.open(MANUAL, "rt", encoding="utf-8") as manual:
            text = manual.read().split("\n")
        self.assertEqual(set(_CHAPTERS), set(advanced.SECTION_KEYWORDS))
        for kind, (first, last) in _CHAPTERS.items():
            chapter = text[text.index(first) : text.index(last)]
            defined = {line.split()[0] for line in chapter if line[:1].isalpha()}
            defined |= {" ".join(line.split()[:2]) for line in chapter if line[:1].isalpha()}
            for words in advanced.SECTION_KEYWORDS[kind] | {
                refused[1:] for refused in advanced.SECTION_REFUSED if refused[0] == kind
            }:
                with self.subTest(kind=kind, keyword=words):
                    self.assertIn(" ".join(words), defined)

    def test_each_server_parameter_is_one_haproxy_registers_with_its_width(self) -> None:
        registered = advanced.parse_server_list(
            line.split("server <name> <addr> ", 1)[1]
            for line in _registered().splitlines()
            if "server <name> <addr> " in line
        )
        for parameter, width in advanced.SERVER_PARAMETERS.items():
            with self.subTest(parameter):
                self.assertEqual(registered.get(parameter), width)
        self.assertEqual(
            set(registered) - set(advanced.SERVER_PARAMETERS),
            {*advanced.SERVER_REFUSED, "set-proxy-v2-tlv-fmt"},
        )

    @unittest.skipUnless(MANUAL.exists(), "the HAProxy manual is not installed here")
    def test_a_check_connect_s_parameters_are_the_manual_s_synopsis(self) -> None:
        import re

        with gzip.open(MANUAL, "rt", encoding="utf-8") as manual:
            text = manual.read()
        for keyword in ("tcp-check connect", "http-check connect"):
            with self.subTest(keyword):
                start = text.index(f"\n{keyword} [")
                synopsis = text[start : text.index("\n  Opens a new connection", start)]
                named = set(re.findall(r"\[([a-z0-9-]+)(?: <[a-z]+>)?\]", synopsis))
                self.assertEqual(
                    named, {*advanced.CHECK_CONNECT_PARAMETERS, *advanced.CHECK_CONNECT_REFUSED}
                )

    def test_each_filter_and_userlist_keyword_is_one_haproxy_registers(self) -> None:
        lines = _registered().splitlines()
        start = lines.index("# List of registered filter names:")
        filters = set()
        for line in lines[start + 1 :]:
            if line.startswith("#"):
                break
            filters.add(line.split()[0])
        self.assertLessEqual(advanced.FILTERS, filters)

        start = lines.index("userlist")
        userlist = set()
        for line in lines[start + 1 :]:
            if not line.startswith("\t"):
                break
            userlist.add((line.split()[0],))
        self.assertEqual(advanced.SECTION_KEYWORDS["userlist"], userlist)


def _object(name: str, advanced_text: str, *, source: bool = False, by_hand: bool = False) -> str:
    pool = (
        "    servers: []"
        if by_hand
        else "    balance: roundrobin\n    servers: [{host: 198.51.100.10, port: 80}]"
    )
    listen = "  protocol: http" + ("\n  source: outbound" if source else "")
    indented = "".join(f"  {line}\n" for line in advanced_text.splitlines())
    return (
        f"schema: 1\nname: {name}\nhostnames: [{name}.example.com]\nlisten:\n{listen}\n"
        f"backends:\n  web-{name}:\n{pool}\nroutes:\n  - path: /\n    backend: web-{name}\n"
        f"advanced: |\n{indented}"
    )


def _generate(*documents: tuple[str, str]) -> dict[str, str]:
    from haprion import golden
    from haprion.generate import generate
    from haprion.proxy_model import load_proxy

    proxies = [load_proxy(name, document.encode()) for name, document in documents]
    return generate(proxies, **golden.arguments(Path("/nonexistent"))).configuration


class TheGeneratorWritesTheTextWhereThePlacementSays(unittest.TestCase):
    def test_two_objects_may_not_add_a_section_of_the_same_name(self) -> None:
        from haprion.generate import GeneratorError

        with self.assertRaisesRegex(GeneratorError, "both add a section called a-b-x"):
            _generate(
                ("a", _object("a", "backend a-b-x\n    mode tcp")),
                ("a-b", _object("a-b", "backend a-b-x\n    mode tcp")),
            )

    def test_the_generator_s_prefix_is_not_the_text_s(self) -> None:
        from haprion.generate import GeneratorError

        with self.assertRaisesRegex(GeneratorError, "generator's"):
            _generate(("mgd", _object("mgd", "backend mgd-x\n    mode tcp")))

    def test_an_added_backend_is_reached_from_the_object_s_source(self) -> None:
        files = _generate(("shop", _object("shop", "backend shop-t\n    mode tcp", source=True)))

        added = files["1001-shop.cfg"].split("backend shop-t\n", 1)[1]
        self.assertIn("    source 192.0.2.35\n", added)
        self.assertNotIn("guid", added)

    def test_a_pool_written_by_hand_says_each_thing_once(self) -> None:
        files = _generate(
            (
                "shop",
                _object(
                    "shop",
                    "balance leastconn\ntimeout server 2m\nserver a 198.51.100.20:80",
                    by_hand=True,
                ),
            )
        )

        pool = files["1001-shop.cfg"]
        self.assertEqual(pool.count("timeout server"), 1)
        self.assertEqual(pool.count("balance"), 1)
        self.assertNotIn("timeout tunnel", pool)
        self.assertNotIn(" s1 ", pool)

    def test_the_text_comes_after_what_the_form_generates(self) -> None:
        pool = _generate(("shop", _object("shop", "http-request deny if { path /x }")))[
            "1001-shop.cfg"
        ]

        self.assertLess(pool.index("server s1"), pool.index("http-request deny if { path /x }"))


class AStoredObjectWithALineNowRefused(unittest.TestCase):
    def test_is_refused_whole_with_the_line_and_the_reason(self) -> None:
        from haprion.proxy_model import ModelError, load_proxy

        document = _object("shop", "ring shop-r\n    size 32768\n    backing-file /etc/shadow")

        with self.assertRaisesRegex(
            ModelError,
            r"shop\.advanced has lines that cannot be written - line 3: a ring's backing file",
        ):
            load_proxy("shop", document.encode())


if __name__ == "__main__":
    unittest.main()
