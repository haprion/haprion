"""What the certificate page says, and what it deliberately stays quiet about.

The thresholds are the interesting part. A certificate four weeks from expiry is
either normal or a failed renewal depending on what is supposed to renew it, and
the tests below pin both readings so a later simplification to one deadline has
to argue with a failing test rather than with a comment.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from haproxy_ui.certificates import build_certificate_overview
from haproxy_ui.db import ClusterCertificates

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


def overview(*readings: ClusterCertificates, clusters: tuple[str, ...] = ("alpha",)):
    return build_certificate_overview(clusters, readings, now=NOW, stale_after=STALE_AFTER)


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
