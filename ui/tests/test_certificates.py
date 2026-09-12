"""What the certificate page says, and what it deliberately stays quiet about.

The thresholds are the interesting part. A certificate four weeks from expiry is
either normal or a failed renewal depending on what is supposed to renew it, and
the tests below pin both readings so a later simplification to one deadline has
to argue with a failing test rather than with a comment.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from haproxy_ui.certificates import RegistryView, build_certificate_overview
from haproxy_ui.db import ClusterCertificates, ClusterStatus

NOW = datetime(2026, 8, 29, 10, 0, tzinfo=UTC)
STALE_AFTER = timedelta(minutes=2)


def certificate(
    identifier: str = "example.com.pem",
    *,
    days_left: int = 60,
    lifecycle: str = "acme",
    referenced: bool = True,
    deployable: bool = True,
    valid: bool = True,
    fingerprint: str | None = None,
    validation_error: str | None = None,
) -> dict[str, object]:
    not_after = NOW + timedelta(days=days_left)
    return {
        "id": identifier,
        "fingerprint_sha256": fingerprint or ("c" * 64),
        "common_name": "*.example.com",
        "sans": ["*.example.com", "example.com"],
        "not_before": (not_after - timedelta(days=90)).isoformat().replace("+00:00", "Z"),
        "not_after": not_after.isoformat().replace("+00:00", "Z"),
        "issuer": "Example Test CA",
        "lifecycle": lifecycle,
        "valid": valid,
        "referenced_by_cluster": referenced,
        "deployable": deployable,
        "validation_error": validation_error,
    }


def reading(
    *,
    cluster: str = "alpha",
    age_seconds: int = 15,
    outcome: str = "done",
    poll_error: str | None = None,
    certificates: list[dict[str, object]] | None = None,
) -> ClusterCertificates:
    return ClusterCertificates(
        cluster=cluster,
        observed_at=NOW - timedelta(seconds=age_seconds),
        outcome=outcome,
        result={"certificates": [certificate()] if certificates is None else certificates},
        warnings=[],
        error=None,
        poll_error=poll_error,
    )


def overview(
    *readings: ClusterCertificates,
    clusters: tuple[str, ...] = ("alpha",),
    status: tuple[ClusterStatus, ...] = (),
):
    return build_certificate_overview(
        clusters, readings, status_readings=status, now=NOW, stale_after=STALE_AFTER
    )


def registered(
    identifier: str = "example.com",
    *,
    kind: str = "acme",
    clusters: tuple[str, ...] = ("alpha",),
    receivers: tuple[dict[str, object], ...] = (),
    distribution: dict[str, object] | None = None,
    readable: bool = True,
    validation_error: str | None = None,
    days_left: int = 60,
    fingerprint: str | None = None,
    sans: list[str] | None = None,
) -> dict[str, object]:
    not_after = NOW + timedelta(days=days_left)
    if distribution is None and clusters:
        distribution = {"published_at": _stamp(NOW - timedelta(days=1)), "current": True}
    return {
        "id": identifier,
        "source": {"kind": kind, "lineage": f"{identifier}-wildcard" if kind == "acme" else None},
        "targets": {"clusters": list(clusters), "receivers": list(receivers)},
        "distribution": distribution,
        "readable": readable,
        "validation_error": validation_error,
        "fingerprint_sha256": (fingerprint or "c" * 64) if readable else None,
        "common_name": "*.example.com",
        "sans": ["*.example.com", "example.com"] if sans is None else sans,
        "not_before": _stamp(not_after - timedelta(days=90)),
        "not_after": _stamp(not_after),
        "issuer": "Example Test CA",
        "lifecycle": "acme" if kind == "acme" else "static",
        "valid": readable,
    }


def _stamp(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def with_registry(
    reading_: ClusterCertificates,
    *entries: dict[str, object],
    receivers: tuple[str, ...] = (),
) -> ClusterCertificates:
    result = dict(reading_.result)
    result["registry"] = {"certificates": list(entries), "receivers": list(receivers)}
    return replace(reading_, result=result)


def node(*carried: tuple[str, str], reachable: bool = True) -> dict[str, object]:
    """One node as the status helper reports it, carrying these certificates."""

    entry: dict[str, object] = {"node": "node-a"}
    if reachable:
        entry["certificates"] = [
            {"id": identifier, "fingerprint_sha256": fingerprint, "valid": True}
            for identifier, fingerprint in carried
        ]
    return entry


def status(*nodes: dict[str, object], cluster: str = "alpha") -> ClusterStatus:
    return ClusterStatus(
        cluster=cluster,
        observed_at=NOW - timedelta(seconds=15),
        outcome="done",
        result={"nodes": list(nodes)},
        warnings=[],
        error=None,
        poll_error=None,
    )


class ExpiryTests(unittest.TestCase):
    def test_the_same_days_left_means_something_different_per_lifecycle(self) -> None:
        #
        # Four weeks out, a certificate somebody renews by hand is due and one
        # certbot renews is still inside the renewal timer's own lag. Five days
        # further down, certbot has failed roughly ten attempts and that is
        # worth saying.
        #
        for days, expected in ((27, "healthy"), (20, "warning")):
            with self.subTest(days=days):
                acme = overview(
                    reading(certificates=[certificate(days_left=days, lifecycle="acme")])
                )
                self.assertEqual(acme.clusters[0].certificates[0].tone, expected)

        static = overview(reading(certificates=[certificate(days_left=27, lifecycle="static")]))
        self.assertEqual(static.clusters[0].certificates[0].tone, "warning")

    def test_the_last_week_is_critical_whatever_renews_it(self) -> None:
        for lifecycle in ("acme", "static"):
            with self.subTest(lifecycle=lifecycle):
                view = overview(
                    reading(certificates=[certificate(days_left=5, lifecycle=lifecycle)])
                )
                entry = view.clusters[0].certificates[0]
                self.assertEqual(entry.tone, "critical")
                self.assertEqual(entry.expiry_label, "in 5 days")

    def test_an_expired_certificate_says_so_rather_than_counting_backwards(self) -> None:
        view = overview(reading(certificates=[certificate(days_left=-3)]))
        entry = view.clusters[0].certificates[0]

        self.assertEqual(entry.expiry_label, "Expired")
        self.assertEqual(entry.tone, "critical")

    def test_a_healthy_certificate_still_states_how_long_it_has(self) -> None:
        entry = overview(reading()).clusters[0].certificates[0]

        self.assertEqual(entry.tone, "healthy")
        self.assertEqual(entry.expiry_label, "in 60 days")
        self.assertEqual(entry.expires, (NOW + timedelta(days=60)).strftime("%Y-%m-%d"))


class UnreadableCertificateTests(unittest.TestCase):
    def test_nothing_measured_is_read_from_an_undeployable_certificate(self) -> None:
        #
        # Schema v1 requires all nine measured fields, so an unreadable
        # certificate carries inert placeholders in them. The view must not
        # render a placeholder expiry as if it had been measured.
        #
        entry = (
            overview(
                reading(
                    certificates=[
                        certificate(
                            deployable=False,
                            validation_error="the leaf block could not be parsed",
                        )
                    ]
                )
            )
            .clusters[0]
            .certificates[0]
        )

        self.assertFalse(entry.usable)
        self.assertEqual(entry.expires, "—")
        self.assertEqual(entry.expiry_label, "Unusable")
        self.assertEqual(entry.sans, ())
        self.assertEqual(entry.problem, "the leaf block could not be parsed")

    def test_a_certificate_the_helper_could_not_name_is_dropped(self) -> None:
        view = overview(reading(certificates=[{"id": "", "deployable": True}]))

        self.assertEqual(view.clusters[0].certificates, ())


class ClusterBadgeTests(unittest.TestCase):
    def test_only_referenced_certificates_decide_the_badge(self) -> None:
        #
        # An expired certificate nobody serves is housekeeping. It keeps its own
        # red row, but a card coloured by something the operator cannot act on
        # is how a badge stops being read.
        #
        view = overview(
            reading(
                certificates=[
                    certificate(days_left=60, referenced=True),
                    certificate("legacy.example.com.pem", days_left=-30, referenced=False),
                ]
            )
        )
        cluster = view.clusters[0]

        self.assertEqual(cluster.tone, "healthy")
        self.assertEqual(cluster.label, "Current")
        self.assertEqual(cluster.certificates[1].tone, "critical")

    def test_a_referenced_certificate_that_cannot_be_read_is_critical(self) -> None:
        cluster = overview(
            reading(certificates=[certificate(deployable=False, validation_error="unreadable")])
        ).clusters[0]

        self.assertEqual(cluster.tone, "critical")
        self.assertEqual(cluster.label, "1 unusable")

    def test_a_cluster_referencing_nothing_is_not_a_failure(self) -> None:
        cluster = overview(reading(certificates=[certificate(referenced=False)])).clusters[0]

        self.assertEqual(cluster.tone, "unknown")
        self.assertEqual(cluster.label, "None referenced")

    def test_a_failed_read_and_a_failed_poll_are_told_apart(self) -> None:
        failed = overview(reading(outcome="failed")).clusters[0]
        unpolled = overview(reading(poll_error="sudo refused")).clusters[0]

        self.assertEqual(failed.label, "Certificates unavailable")
        self.assertEqual(unpolled.label, "Collection unavailable")

    def test_old_data_is_marked_stale_before_it_is_believed(self) -> None:
        cluster = overview(reading(age_seconds=600)).clusters[0]

        self.assertTrue(cluster.stale)
        self.assertEqual(cluster.label, "Stale data")

    def test_a_configured_cluster_without_a_reading_still_renders(self) -> None:
        view = build_certificate_overview(
            ("alpha", "beta"), (reading(),), now=NOW, stale_after=STALE_AFTER
        )

        self.assertEqual([cluster.cluster for cluster in view.clusters], ["alpha", "beta"])
        self.assertEqual(view.clusters[1].label, "No certificate data yet")
        self.assertEqual(view.clusters[1].age_label, "Never")

    def test_a_reading_for_a_cluster_no_longer_configured_is_still_shown(self) -> None:
        view = build_certificate_overview(
            (), (reading(cluster="beta"),), now=NOW, stale_after=STALE_AFTER
        )

        self.assertEqual(view.clusters[0].cluster, "beta")
        self.assertFalse(view.clusters[0].configured)


class OrderAndCountTests(unittest.TestCase):
    def test_referenced_certificates_come_first_and_the_worst_leads_each_group(self) -> None:
        view = overview(
            reading(
                certificates=[
                    certificate("spare.example.com.pem", days_left=90, referenced=False),
                    certificate("healthy.example.com.pem", days_left=90, referenced=True),
                    certificate("expiring.example.com.pem", days_left=2, referenced=True),
                ]
            )
        )

        self.assertEqual(
            [entry.identifier for entry in view.clusters[0].certificates],
            [
                "expiring.example.com.pem",
                "healthy.example.com.pem",
                "spare.example.com.pem",
            ],
        )

    def test_one_certificate_read_by_two_clusters_is_counted_once(self) -> None:
        #
        # Every cluster reads the same distribution directory and differs only
        # in what it references. Counting per listing would report one wildcard
        # twice, and the number would grow with the cluster count rather than
        # with the material somebody has to look after.
        #
        shared = certificate(fingerprint="a" * 64)
        view = build_certificate_overview(
            ("alpha", "beta"),
            (
                reading(cluster="alpha", certificates=[shared]),
                reading(cluster="beta", certificates=[{**shared, "referenced_by_cluster": False}]),
            ),
            now=NOW,
            stale_after=STALE_AFTER,
        )

        self.assertEqual(view.cluster_count, 2)
        self.assertEqual(view.certificate_count, 1)
        self.assertEqual(view.acme_count, 1)

    def test_two_certificates_sharing_a_fingerprint_prefix_are_two(self) -> None:
        #
        # The identity of the material is the whole digest. A shortened key
        # would fold two certificates into one, and the symptom would be a
        # counter that is quietly too low rather than an error anybody sees.
        #
        view = build_certificate_overview(
            ("alpha",),
            (
                reading(
                    cluster="alpha",
                    certificates=[
                        certificate("a.example.com.pem", fingerprint="a" * 12 + "1" * 52),
                        certificate("b.example.com.pem", fingerprint="a" * 12 + "2" * 52),
                    ],
                ),
            ),
            now=NOW,
            stale_after=STALE_AFTER,
        )

        self.assertEqual(view.certificate_count, 2)

    def test_certificates_needing_attention_are_counted_across_clusters(self) -> None:
        view = build_certificate_overview(
            ("alpha",),
            (
                reading(
                    certificates=[
                        certificate("a.example.com.pem", days_left=90, fingerprint="a" * 64),
                        certificate("b.example.com.pem", days_left=3, fingerprint="b" * 64),
                        certificate(
                            "c.example.com.pem",
                            days_left=20,
                            lifecycle="acme",
                            fingerprint="c" * 64,
                        ),
                    ]
                ),
            ),
            now=NOW,
            stale_after=STALE_AFTER,
        )

        self.assertEqual(view.certificate_count, 3)
        self.assertEqual(view.attention_count, 2)


class LifecycleLabelTests(unittest.TestCase):
    def test_the_label_names_what_actually_renews_the_certificate(self) -> None:
        labels = {
            "acme": "Certbot",
            "static": "Manual",
            "something-else": "Unknown",
        }
        for lifecycle, expected in labels.items():
            with self.subTest(lifecycle=lifecycle):
                entry = (
                    overview(reading(certificates=[certificate(lifecycle=lifecycle)]))
                    .clusters[0]
                    .certificates[0]
                )
                self.assertEqual(entry.lifecycle_label, expected)


if __name__ == "__main__":
    unittest.main()


def registry_of(view) -> RegistryView:
    """The overview's registry, or a clear failure instead of an AttributeError."""

    if view.registry is None:
        raise AssertionError("the overview carried no registry")
    return view.registry


class TheRegistryViewSaysOnlyWhatIsMeasured(unittest.TestCase):
    """The C5 central view. Its whole risk is claiming more than it knows.

    The mockup that preceded it said "On all targets" on every row, including
    for receivers that fetch on their own schedule and report nothing back.
    These pin the two kinds of certainty apart so that phrasing cannot return.
    """

    def test_a_cluster_certificate_reports_what_the_nodes_carry(self) -> None:
        entry = registered(fingerprint="a" * 64)
        view = overview(
            with_registry(reading(), entry),
            status=(status(node(("example.com", "a" * 64)), node(("example.com", "a" * 64))),),
        )

        certificate_view = registry_of(view).certificates[0]
        self.assertEqual(certificate_view.state_label, "On all 2 nodes")
        self.assertEqual(certificate_view.state_tone, "healthy")

    def test_a_node_that_is_behind_is_counted_and_named_as_such(self) -> None:
        entry = registered(fingerprint="a" * 64)
        view = overview(
            with_registry(reading(), entry),
            status=(status(node(("example.com", "a" * 64)), node()),),
        )

        self.assertEqual(registry_of(view).certificates[0].state_label, "On 1 of 2 nodes")
        self.assertEqual(registry_of(view).certificates[0].state_tone, "warning")

    def test_an_unreachable_node_is_not_counted_as_missing_the_certificate(self) -> None:
        #
        # "One of two nodes" would otherwise mean both "a node is behind" and
        # "a node is down". They are different problems with different answers,
        # so a node that reported no certificate list at all leaves the
        # denominator rather than joining it as a failure.
        #
        entry = registered(fingerprint="a" * 64)
        view = overview(
            with_registry(reading(), entry),
            status=(status(node(("example.com", "a" * 64)), node(reachable=False)),),
        )

        self.assertEqual(registry_of(view).certificates[0].state_label, "On the node")

    def test_a_node_holding_the_same_name_with_different_bytes_is_not_deployed(self) -> None:
        entry = registered(fingerprint="a" * 64)
        view = overview(
            with_registry(reading(), entry),
            status=(status(node(("example.com", "b" * 64))),),
        )

        self.assertEqual(registry_of(view).certificates[0].state_label, "Nodes hold an older copy")
        self.assertEqual(registry_of(view).certificates[0].state_tone, "warning")

    def test_a_receiver_certificate_reports_publication_and_never_arrival(self) -> None:
        entry = registered(
            "lb-01.example.net",
            clusters=(),
            receivers=({"id": "lb-01", "published_at": _stamp(NOW), "current": True},),
        )
        view = overview(with_registry(reading(), entry, receivers=("lb-01",)))

        certificate_view = registry_of(view).certificates[0]
        self.assertEqual(certificate_view.state_label, "Published 2026-08-29")
        self.assertEqual(certificate_view.state_tone, "healthy")
        #
        # The words the mockup used, which the manager cannot know for a
        # receiver. Asserted as absent rather than trusted to review.
        #
        for claim in ("on all targets", "installed", "deployed", "arrived"):
            self.assertNotIn(claim, certificate_view.state_label.lower())
            self.assertNotIn(claim, certificate_view.state_detail.lower())

    def test_a_receiver_with_no_copy_yet_says_so(self) -> None:
        entry = registered(
            "lb-01.example.net",
            clusters=(),
            receivers=({"id": "lb-01", "published_at": None, "current": None},),
        )
        view = overview(with_registry(reading(), entry, receivers=("lb-01",)))

        self.assertEqual(registry_of(view).certificates[0].state_label, "Not published")

    def test_an_unreadable_certificate_never_renders_its_placeholder_fields(self) -> None:
        #
        # Schema v1 fills the measured fields of an unreadable entry with inert
        # values, so an expiry drawn from one would be a date nobody measured.
        #
        entry = registered(readable=False, validation_error="no material at its source yet")
        view = overview(with_registry(reading(), entry))

        certificate_view = registry_of(view).certificates[0]
        self.assertEqual(certificate_view.state_label, "Unreadable")
        self.assertEqual(certificate_view.expires, "—")
        self.assertEqual(certificate_view.expiry_label, "Unknown")
        self.assertIsNone(certificate_view.material_note)

    def test_facts_read_off_the_published_copy_say_so(self) -> None:
        #
        # The engine measures the published cluster copy when an import's own
        # source is still empty. The facts are real - they are the nodes' -
        # but the reader is told which file they came from.
        #
        entry = registered(kind="import")
        entry["measured_at"] = "distribution"
        view = overview(with_registry(reading(), entry))

        certificate_view = registry_of(view).certificates[0]
        self.assertTrue(certificate_view.readable)
        self.assertIn("published cluster copy", certificate_view.material_note or "")

        for measured_at in ("source", None, "something-new"):
            with self.subTest(measured_at=measured_at):
                entry = registered(kind="import")
                if measured_at is not None:
                    entry["measured_at"] = measured_at
                view = overview(with_registry(reading(), entry))
                self.assertIsNone(registry_of(view).certificates[0].material_note)

    def test_the_counters_count_the_registry_and_not_one_cluster_listing(self) -> None:
        #
        # The number the page reported before C5 came from a cluster's
        # distribution directory, so a certificate that goes only to a receiver
        # was counted by nothing. It is material this manager looks after, and
        # the summary is the one place that says how much of it there is.
        #
        view = overview(
            with_registry(
                reading(),
                registered(),
                registered("lb-01.example.net", clusters=(), receivers=()),
                registered("internal", kind="import", clusters=("alpha",)),
            )
        )

        self.assertEqual(view.certificate_count, 3)
        self.assertEqual(view.acme_count, 2)

    def test_the_freshest_cluster_row_supplies_the_registry(self) -> None:
        #
        # Every cluster's listing carries the same block. Taking the newest
        # rather than merging them means a registry rewritten between two polls
        # is shown whole rather than half from each.
        #
        old = with_registry(reading(cluster="alpha", age_seconds=300), registered("older"))
        fresh = with_registry(reading(cluster="beta", age_seconds=10), registered("newer"))
        view = overview(old, fresh, clusters=("alpha", "beta"))

        self.assertEqual([entry.identifier for entry in registry_of(view).certificates], ["newer"])

    def test_an_installation_without_a_registry_keeps_the_page_it_had(self) -> None:
        view = overview(reading())

        self.assertIsNone(view.registry)
        self.assertEqual(view.certificate_count, 1)
