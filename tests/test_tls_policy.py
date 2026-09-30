"""The cipher lists, and the two things that can quietly go wrong with them.

They can be *edited* by accident, and they can go *stale* while looking exactly
as they did the day somebody checked. Neither shows up in a diff of behaviour:
HAProxy accepts an old list as readily as a current one, and every test that
serves traffic goes on passing.

So one test pins what is there and the other pins when it was last looked at.
"""

from __future__ import annotations

import re
import unittest
from datetime import date, timedelta
from hashlib import sha256
from pathlib import Path

from haproxy_mgmt import tls_policy


def digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


class TheListsAreTheOnesThatWereChecked(unittest.TestCase):
    """Pinned as a digest rather than as a second copy.

    A verbatim copy here would be the third place this list lives, and the
    reason this module exists at all is that it lived in two. A digest fails on
    an accidental edit without being something another reader could mistake for
    the list itself.
    """

    INTERMEDIATE = "f46e3787a2d4958b6591377caaa50f23959d648e310ee3fbde277719f35cdb33"
    CIPHERSUITES = "0298a462f55e65f8beea629c16d8192f310564c256b9303c23377e5e1a2b2386"

    def test_the_intermediate_ciphers_have_not_been_edited(self) -> None:
        self.assertEqual(
            digest(tls_policy.TLS_1_2_CIPHERS),
            self.INTERMEDIATE,
            "the TLS 1.2 cipher list changed - if that was deliberate, update this digest "
            "and tls_policy.REVIEWED in the same commit",
        )

    def test_the_tls_1_3_suites_have_not_been_edited(self) -> None:
        self.assertEqual(
            digest(tls_policy.TLS_1_3_CIPHERSUITES),
            self.CIPHERSUITES,
            "the TLS 1.3 ciphersuites changed - if that was deliberate, update this digest "
            "and tls_policy.REVIEWED in the same commit",
        )


class NothingHereCanReachBelowTls1_2(unittest.TestCase):
    """A property, not a copy, and the reason the lowest listener step is 1.2.

    TLS 1.1 has no AEAD suites: AES-GCM needs 1.2, so an old client can only be
    served with CBC and HMAC-SHA1. If one of those ever appears in these lists,
    the claim that a listener built from them cannot negotiate below TLS 1.2
    has stopped being true, whatever the `ssl-min-ver` beside it says.
    """

    def test_no_cbc_and_no_sha1_suite_is_offered(self) -> None:
        offered = f"{tls_policy.TLS_1_2_CIPHERS}:{tls_policy.TLS_1_3_CIPHERSUITES}".split(":")

        self.assertEqual([name for name in offered if "CBC" in name], [])
        self.assertEqual([name for name in offered if name.endswith("-SHA")], [])

    def test_every_policy_names_a_floor(self) -> None:
        """A policy without `ssl-min-ver` would inherit whatever core/ decided."""

        for name, line in tls_policy.TLS_POLICIES.items():
            with self.subTest(policy=name):
                self.assertIn("ssl-min-ver TLSv1.", line)


class SomebodyLooksAtThemNowAndThen(unittest.TestCase):
    """The trip-wire, and it is meant to go off.

    These lists change on the order of years, which is exactly what makes them
    easy to forget: nothing fails, nothing degrades visibly, and the day they
    matter is the day somebody reads them in an incident. There is no automatic
    update - a generator that reached the network to emit a configuration would
    be worse than a stale list - so the substitute is a test that expires.

    Confirming the list is unchanged *is* a review. Move `REVIEWED` when you
    look, whether or not you edit anything.
    """

    def test_the_review_has_not_expired(self) -> None:
        due = tls_policy.REVIEWED + timedelta(days=tls_policy.REVIEW_INTERVAL_DAYS)

        self.assertGreaterEqual(
            due,
            date.today(),
            f"the cipher lists were last checked against Mozilla's guidelines on "
            f"{tls_policy.REVIEWED} (v{tls_policy.MOZILLA_GUIDELINE}). Compare them with "
            f"{tls_policy.MOZILLA_GUIDELINE_URL}, then move tls_policy.REVIEWED - "
            f"confirming they are unchanged counts",
        )

    def test_the_recorded_date_is_not_in_the_future(self) -> None:
        """A typo in the year would otherwise silence the check for a century."""

        self.assertLessEqual(tls_policy.REVIEWED, date.today())


class WhatCoreIsHeldTo(unittest.TestCase):
    """The comparison itself: what it accepts, and what it says when it does not."""

    def problem(self, core: str) -> str | None:
        return tls_policy.core_defaults_problem(
            core.encode(), cluster="alpha", config_path="/configs/haproxy/alpha"
        )

    def correct(self) -> str:
        return (
            f"global\n  daemon\n  {tls_policy.DEFAULT_PATH_LINE}\n"
            + tls_policy.core_defaults_lines("  ")
        )

    def test_a_cluster_that_agrees_is_not_stopped(self) -> None:
        self.assertIsNone(self.problem(self.correct()))

    def test_a_cluster_that_sets_nothing_is_stopped(self) -> None:
        """The state `external` was in: no cipher policy on the internet-facing side."""

        message = self.problem(f"global\n  daemon\n  {tls_policy.DEFAULT_PATH_LINE}\n")

        self.assertIsNotNone(message)
        assert message is not None
        self.assertIn("does not set ssl-default-bind-ciphers at all", message)

    def test_a_cluster_without_the_path_rule_is_stopped_first(self) -> None:
        """Said before the ciphers, because it fails later and harder.

        A missing cipher is a listener with the wrong terms; a missing
        `default-path` is a node that refuses to start, after a publish and a
        validation that both passed.
        """

        message = self.problem("global\n  daemon\n" + tls_policy.core_defaults_lines("  "))

        assert message is not None
        self.assertIn(tls_policy.DEFAULT_PATH_LINE, message)
        self.assertIn("refuse to start", message)

    def test_a_missing_cipher_is_named(self) -> None:
        """The state `internal` was in: one short, and correct-looking either way."""

        short = self.correct().replace(":DHE-RSA-CHACHA20-POLY1305", "", 1)
        message = self.problem(short)

        assert message is not None
        self.assertIn("missing DHE-RSA-CHACHA20-POLY1305", message)

    def test_a_different_order_is_stopped_and_said_to_be_about_order(self) -> None:
        """Same ciphers, reversed preference. Nothing is missing, and it still matters."""

        reversed_list = ":".join(reversed(tls_policy.TLS_1_2_CIPHERS.split(":")))
        message = self.problem(self.correct().replace(tls_policy.TLS_1_2_CIPHERS, reversed_list))

        assert message is not None
        self.assertIn("in a different order", message)

    def test_the_message_says_how_to_fix_it(self) -> None:
        """Somebody meets this during a publish and it has to be enough on its own."""

        message = self.problem(f"global\n  daemon\n  {tls_policy.DEFAULT_PATH_LINE}\n")

        assert message is not None
        self.assertIn("sudoedit /configs/haproxy/alpha/core/haproxy.cfg", message)
        self.assertIn(tls_policy.TLS_1_2_CIPHERS, message)
        self.assertIn(tls_policy.MOZILLA_GUIDELINE_URL, message)
        self.assertIn("A revert is never stopped by this", message)

    def test_the_lines_it_offers_are_the_lines_it_accepts(self) -> None:
        """The guide, the fixtures and the refusal all render from one function."""

        self.assertIsNone(
            self.problem(
                f"global\n    {tls_policy.DEFAULT_PATH_LINE}\n" + tls_policy.core_defaults_lines()
            )
        )


class WhichPathsAskTheQuestion(unittest.TestCase):
    """A publish is checked; a revert is not, and that is the whole point.

    Every path that builds a node artifact reads a tree that contains
    `core/haproxy.cfg`, so the check could have gone in one place and covered
    them all. It must not: `revert_helper` builds one too, and a revert is what
    somebody runs while something is on fire. Going back to a release that was
    good before cannot depend on a file being current.

    Held here because the difference is a decision, not something the code
    shows: a fourth publish path added later would be silently unchecked.
    """

    #
    # `managed_helper` is the one loop the network, settings and objects
    # helpers publish through (Fas 16 punkt 8); none of the three builds an
    # artifact of its own any more.
    #
    CHECKED = (
        "publish_helper",
        "managed_helper",
    )
    DELIBERATELY_NOT = ("revert_helper",)

    def source(self, module: str) -> str:
        here = Path(__file__).resolve().parents[1]
        return (here / "src" / "haproxy_mgmt" / "cli" / f"{module}.py").read_text(encoding="utf-8")

    def test_every_publish_path_checks(self) -> None:
        for module in self.CHECKED:
            with self.subTest(module=module):
                self.assertIn("core_defaults_problem", self.source(module))

    def test_a_revert_is_never_checked(self) -> None:
        for module in self.DELIBERATELY_NOT:
            with self.subTest(module=module):
                self.assertNotIn("core_defaults_problem", self.source(module))

    def test_the_list_names_every_path_that_builds_an_artifact(self) -> None:
        """So a new one has to be classified rather than forgotten."""

        here = Path(__file__).resolve().parents[1] / "src" / "haproxy_mgmt" / "cli"
        builders = sorted(
            path.stem
            for path in here.glob("*.py")
            if "build_node_artifact" in path.read_text(encoding="utf-8")
        )

        self.assertEqual(builders, sorted((*self.CHECKED, *self.DELIBERATELY_NOT)))


class TheProbeIsHeldToTheSameFloorAsHaproxy(unittest.TestCase):
    """Every policy a pool may name is a floor the probe can ask for.

    This is the coupling B83 exists to keep. HAProxy reaches a pool under the
    policy the object names; the probe asks whether that reach would work. A
    probe holding a floor of its own refuses a backend HAProxy accepts and
    reports a healthy pool as down - and somebody acts on that during an
    incident, which is the worst possible time to be told a wrong thing
    confidently.

    Held as a matching of two mappings rather than as a comment, because the
    failure it prevents is silent: both sides go on working, they just answer
    differently.
    """

    def test_every_backend_policy_has_a_floor_the_probe_can_name(self) -> None:
        self.assertEqual(
            sorted(tls_policy.BACKEND_POLICIES), sorted(tls_policy.BACKEND_MIN_VERSION)
        )

    def test_the_floor_the_probe_asks_for_is_the_one_haproxy_is_told(self) -> None:
        for name, line in tls_policy.BACKEND_POLICIES.items():
            with self.subTest(policy=name):
                self.assertIn(
                    f"ssl-min-ver {tls_policy.BACKEND_MIN_VERSION[name]}",
                    line,
                    "the server line and the probe disagree about how old this may be",
                )

    def test_the_node_script_accepts_exactly_those_floors(self) -> None:
        """The third copy, and the one that is not Python this suite imports.

        The node script is executed, not imported - it runs under whatever
        Python the node has, with no dependency on this package. So the list it
        carries is read out of its source, which is the only way to notice a
        policy added here and not there.
        """

        script = (
            Path(__file__).resolve().parents[1] / "install" / "node" / "haproxy-health-probe"
        ).read_text(encoding="utf-8")
        named = set(re.findall(r'"(TLSv1\.[123])":\s*ssl\.TLSVersion', script))

        self.assertEqual(named, set(tls_policy.BACKEND_MIN_VERSION.values()))

    def test_the_lowest_policy_also_lowers_the_security_level(self) -> None:
        """Measured, not assumed: without it the list reaches nothing.

        OpenSSL's security level is a second gate, independent of `ssl-min-ver`.
        On HAProxy 3.4.4 against a TLS 1.1 backend the cipher list alone
        answered 503 and the list with this answered 200, so a `legacy` policy
        missing it would be a setting that reads correctly and changes nothing.
        """

        self.assertIn(tls_policy.SECURITY_LEVEL_OFF, tls_policy.BACKEND_POLICIES["legacy"])
        for name in ("modern", "intermediate"):
            with self.subTest(policy=name):
                self.assertNotIn(tls_policy.SECURITY_LEVEL_OFF, tls_policy.BACKEND_POLICIES[name])

    def test_no_listener_policy_reaches_below_tls_1_2(self) -> None:
        """`legacy` is a backend answer only, and this is where that is enforced."""

        self.assertNotIn("legacy", tls_policy.TLS_POLICIES)
        for name, line in tls_policy.TLS_POLICIES.items():
            with self.subTest(policy=name):
                self.assertNotIn("TLSv1.1", line)
                self.assertNotIn(tls_policy.SECURITY_LEVEL_OFF, line)
