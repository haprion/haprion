"""Comparing two releases, one object at a time.

The manifest replaces a claim that was derived from history - "no publish job
names this object, so it is unchanged" - with one derived from the releases
themselves. These tests hold the properties that made the swap worth making,
and the refusals that keep it from inventing an answer it does not have.
"""

from __future__ import annotations

import unittest

from haproxy_mgmt.object_manifest import (
    ABSENT,
    CHANGED,
    CURRENT,
    Difference,
    build,
    compare,
    fingerprint,
    parse,
    render,
    worst,
)

SHOP = {
    "backends": "backend mgd-shop-web\n",
    "routing": "    use_backend mgd-shop-web if host\n",
    "listener": "frontend mgd-main-http\n",
    "certificate": "",
}
INTRANET = {**SHOP, "backends": "backend mgd-intranet-portal\n"}


def release(objects):
    return build(objects)


class WhatTwoReleasesSayAboutOneObject(unittest.TestCase):
    def test_the_same_bytes_are_the_same_object(self) -> None:
        published = release({"shop": SHOP})
        observed = release({"shop": dict(SHOP)})
        self.assertEqual(compare(published, observed)["shop"], Difference(CURRENT, ()))

    def test_a_changed_part_is_named(self) -> None:
        """ "Changed" sends somebody to read a configuration; this says where."""

        moved = {**SHOP, "listener": "frontend mgd-main-http\n    bind 192.0.2.30:80\n"}
        difference = compare(release({"shop": SHOP}), release({"shop": moved}))["shop"]
        self.assertEqual(difference, Difference(CHANGED, ("listener",)))

    def test_an_object_the_nodes_have_never_seen_is_absent(self) -> None:
        difference = compare(release({"shop": SHOP}), release({}))["shop"]
        self.assertEqual(difference, Difference(ABSENT, ()))

    def test_a_neighbours_change_leaves_this_object_current(self) -> None:
        """The false claim the job window used to produce, held against."""

        before = release({"shop": SHOP})
        after = release({"shop": SHOP, "intranet": INTRANET})
        self.assertEqual(compare(before, after)["shop"], Difference(CURRENT, ()))

    def test_an_emptied_part_is_not_the_same_as_one_that_never_existed(self) -> None:
        served = {**SHOP, "certificate": "/etc/haproxy/certs/example.com.pem\n"}
        difference = compare(release({"shop": served}), release({"shop": SHOP}))["shop"]
        self.assertEqual(difference, Difference(CHANGED, ("certificate",)))

    def test_a_missing_part_hashes_rather_than_disappears(self) -> None:
        self.assertEqual(
            sorted(fingerprint({}).parts),
            ["backends", "certificate", "listener", "routing"],
        )


class OneAnswerForSeveralNodes(unittest.TestCase):
    def test_a_single_node_behind_decides_the_answer(self) -> None:
        readings = [Difference(CURRENT, ()), Difference(CHANGED, ("routing",))]
        self.assertEqual(worst(readings), Difference(CHANGED, ("routing",)))

    def test_absent_outranks_changed(self) -> None:
        readings = [Difference(CHANGED, ("routing",)), Difference(ABSENT, ())]
        self.assertEqual(worst(readings), Difference(ABSENT, ()))

    def test_differing_parts_are_merged_in_a_fixed_order(self) -> None:
        readings = [
            Difference(CHANGED, ("listener",)),
            Difference(CHANGED, ("backends",)),
        ]
        self.assertEqual(worst(readings), Difference(CHANGED, ("backends", "listener")))

    def test_nothing_read_is_not_agreement(self) -> None:
        self.assertIsNone(worst([]))


class AManifestReadBack(unittest.TestCase):
    def test_a_rendered_manifest_survives_the_round_trip(self) -> None:
        manifest = release({"shop": SHOP, "intranet": INTRANET})
        self.assertEqual(parse(render(manifest).decode()), manifest)

    def test_the_rendering_is_stable(self) -> None:
        """Two builds of one release must not produce a diff to review."""

        first = render(release({"shop": SHOP, "intranet": INTRANET}))
        second = render(release({"intranet": INTRANET, "shop": SHOP}))
        self.assertEqual(first, second)

    def test_a_document_that_is_not_a_manifest_is_refused(self) -> None:
        for text in ("", "{", "[]", '{"schema": 2}', '{"schema": 1}'):
            with self.subTest(text=text):
                self.assertIsNone(parse(text))

    def test_a_half_readable_manifest_is_refused_whole(self) -> None:
        """Half a manifest would report the unreadable objects as unchanged."""

        document = render(release({"shop": SHOP})).decode()
        broken = document.replace('"fingerprint"', '"fingerprints"')
        self.assertIsNone(parse(broken))


if __name__ == "__main__":
    unittest.main()
