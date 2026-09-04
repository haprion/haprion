"""The cipher lists, and the two things that can quietly go wrong with them.

They can be *edited* by accident, and they can go *stale* while looking exactly
as they did the day somebody checked. Neither shows up in a diff of behaviour:
HAProxy accepts an old list as readily as a current one, and every test that
serves traffic goes on passing.

So one test pins what is there and the other pins when it was last looked at.
"""

from __future__ import annotations

import unittest
from datetime import date, timedelta
from hashlib import sha256

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
