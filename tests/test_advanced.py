"""Where each line of an object's advanced config goes, and what is refused (B223, B224).

Every refusal here is a case HAProxy itself would have let through: a line
ignored with a warning `-c` does not fail on, a line accepted without a word
that does nothing, or a line that would quietly change the cluster's counters
or another object's. The tests are named after the rule, so a failure points at
a sentence in the plan.
"""

from __future__ import annotations

import gzip
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
        self.assertEqual(fate(line, rate_limit=False), PLACED)
        self.assertEqual(fate("http-request sc-set-gpt(0,1) 1", rate_limit=True), REFUSED_FATE)

    def test_the_counters_may_be_read(self) -> None:
        self.assertEqual(
            fate("http-request deny if { sc_http_req_rate(1) gt 5 }", rate_limit=True), PLACED
        )

    def test_a_counter_on_the_object_s_rows_names_a_table_of_the_text_s(self) -> None:
        self.assertEqual(fate("http-request track-sc2 src"), REFUSED_FATE)
        self.assertEqual(fate("http-request track-sc2 src table other-t"), REFUSED_FATE)
        self.assertEqual(fate("http-request track-sc2 src table shop-t"), PLACED)

    def test_a_stick_rule_on_the_object_s_rows_names_a_table_of_the_text_s(self) -> None:
        self.assertEqual(fate("stick on src"), REFUSED_FATE)
        self.assertEqual(fate("stick on src table shop-t"), PLACED)

    def test_a_table_on_the_object_s_rows_is_refused(self) -> None:
        self.assertEqual(fate("stick-table type ip size 1k"), REFUSED_FATE)


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

    def test_another_spoe_engine_is_the_text_s_own(self) -> None:
        self.assertEqual(fate("filter spoe engine mine config /etc/haproxy/mine.conf"), PLACED)


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


if __name__ == "__main__":
    unittest.main()


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
