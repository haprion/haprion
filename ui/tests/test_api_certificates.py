"""`GET /api/v1/certificates`: the Certificates page's registry as JSON."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

from haprion_ui.db import ClusterCertificates
from tests.test_api import ApiTestCase
from tests.test_certificates import registered, with_registry

NOW = datetime.now(UTC)


def entry(identifier: str, *, days_left: int = 60, **kept: Any) -> dict[str, Any]:
    """A registry entry that expires a given number of whole days (and an hour) from now."""

    made = registered(identifier, **kept)
    not_after = NOW + timedelta(days=days_left, hours=1)
    made["not_before"] = (not_after - timedelta(days=90)).isoformat()
    made["not_after"] = not_after.isoformat()
    return made


def registry(*entries: dict[str, Any]) -> list[ClusterCertificates]:
    return [
        with_registry(
            ClusterCertificates(
                cluster="alpha",
                observed_at=NOW - timedelta(seconds=15),
                outcome="done",
                result={"certificates": []},
                warnings=[],
                error=None,
                poll_error=None,
            ),
            *entries,
            receivers=("web-host",),
        )
    ]


class TheCertificateList(ApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.entries = [
            entry("web", clusters=("alpha",)),
            entry("intranet", kind="import", clusters=("beta",), days_left=3),
            entry("both", clusters=("alpha", "beta")),
            entry(
                "offline",
                kind="import",
                clusters=(),
                receivers=({"id": "web-host", "published_at": NOW.isoformat(), "current": True},),
            ),
            entry(
                "broken",
                kind="import",
                clusters=("alpha",),
                readable=False,
                validation_error="Not a certificate",
            ),
        ]
        patch = mock.patch(
            "haprion_ui.db.cluster_certificates",
            side_effect=lambda *_a, **_k: registry(*self.entries),
        )
        patch.start()
        self.addCleanup(patch.stop)

    def get(self, secret: str, query: str = "") -> Any:
        return self.api().get(
            f"/api/v1/certificates{query}", headers={"Authorization": f"Bearer {secret}"}
        )

    def by_id(self, response: Any) -> dict[str, dict[str, Any]]:
        return {row["id"]: row for row in response.json()["result"]["certificates"]}

    def test_an_unlimited_token_gets_the_whole_registry_in_the_pages_words(self) -> None:
        response = self.get(self.issue())
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["operation"], "certificate_list")
        result = body["result"]
        self.assertEqual((result["count"], result["truncated"], result["stale"]), (5, False, False))
        self.assertEqual(result["observed_at"], (NOW - timedelta(seconds=15)).isoformat())
        rows = self.by_id(response)
        self.assertEqual(sorted(rows), ["both", "broken", "intranet", "offline", "web"])
        web = rows["web"]
        self.assertEqual(
            web,
            {
                "id": "web",
                "common_name": "*.example.com",
                "names": ["*.example.com", "example.com"],
                "issuer": "Example Test CA",
                "source": "acme",
                "lifecycle": "acme",
                "readable": True,
                "problem": None,
                "not_after": web["not_after"],
                "days_left": 60,
                "expired": False,
                "expiry_state": "healthy",
                "state": {
                    "label": "Published",
                    "detail": "No node has reported yet, so deployment is unknown",
                    "tone": "unknown",
                },
                "needs_publish": False,
                "targets": [
                    {"name": "alpha", "kind": "cluster", "published_at": None, "current": None}
                ],
            },
        )
        self.assertEqual(
            datetime.fromisoformat(web["not_after"]), (NOW + timedelta(days=60, hours=1))
        )

    def test_the_expiry_state_and_the_unreadable_are_the_pages(self) -> None:
        rows = self.by_id(self.get(self.issue()))
        self.assertEqual(
            (rows["intranet"]["days_left"], rows["intranet"]["expiry_state"]), (3, "critical")
        )
        broken = rows["broken"]
        self.assertEqual(
            (broken["readable"], broken["problem"], broken["not_after"], broken["days_left"]),
            (False, "Not a certificate", None, None),
        )
        self.assertEqual(broken["issuer"], None)
        self.assertEqual(broken["state"]["label"], "Unreadable")

    def test_a_certificate_that_ran_out_says_so(self) -> None:
        self.entries = [entry("old", days_left=-2)]
        old = self.by_id(self.get(self.issue()))["old"]
        self.assertEqual((old["expired"], old["expiry_state"]), (True, "critical"))
        self.assertLess(old["days_left"], 0)

    def test_where_it_goes_includes_the_receivers_for_an_unlimited_token(self) -> None:
        rows = self.by_id(self.get(self.issue()))
        self.assertEqual(
            rows["offline"]["targets"],
            [
                {
                    "name": "web-host",
                    "kind": "receiver",
                    "published_at": NOW.isoformat(),
                    "current": True,
                }
            ],
        )

    def test_a_limited_token_sees_only_what_is_deployed_to_its_clusters(self) -> None:
        response = self.get(self.issue(clusters=["alpha"]))
        rows = self.by_id(response)
        self.assertEqual(sorted(rows), ["both", "broken", "web"])
        self.assertEqual(response.json()["result"]["count"], 3)
        # The other cluster a shared certificate also goes to is not named.
        self.assertEqual([t["name"] for t in rows["both"]["targets"]], ["alpha"])
        beta = self.by_id(self.get(self.issue(clusters=["beta"])))
        self.assertEqual(sorted(beta), ["both", "intranet"])

    def test_a_limited_tokens_state_leaves_out_the_receivers_and_the_other_clusters(self) -> None:
        self.entries = [
            entry(
                "both",
                clusters=("alpha", "beta"),
                receivers=({"id": "web-host", "published_at": None, "current": None},),
            )
        ]
        whole = self.by_id(self.get(self.issue()))["both"]["state"]
        alpha = self.by_id(self.get(self.issue(clusters=["alpha"])))["both"]
        # The combined State counts the receiver that has no copy ...
        self.assertIn("receiver", whole["detail"])
        # ... which alpha's token is not told about, nor is it told of beta.
        self.assertNotIn("receiver", json.dumps(alpha["state"]))
        self.assertEqual([t["name"] for t in alpha["targets"]], ["alpha"])
        self.assertNotEqual(alpha["state"], whole)

    def test_a_limited_tokens_needs_publish_counts_its_own_clusters_only(self) -> None:
        """Review 26-10-31, P3-3: a receiver without a copy showed through `needs_publish`."""

        self.entries = [
            entry(
                "receiver-only",
                clusters=("alpha", "beta"),
                receivers=({"id": "web-host", "published_at": None, "current": None},),
            ),
            entry(
                "distribution",
                clusters=("alpha", "beta"),
                distribution={"published_at": None, "current": None},
            ),
        ]
        whole = self.by_id(self.get(self.issue()))
        alpha = self.by_id(self.get(self.issue(clusters=["alpha"])))
        self.assertTrue(whole["receiver-only"]["needs_publish"])
        self.assertFalse(alpha["receiver-only"]["needs_publish"])
        # The clusters read one distribution copy, so a missing one is theirs too.
        self.assertTrue(whole["distribution"]["needs_publish"])
        self.assertTrue(alpha["distribution"]["needs_publish"])

    def test_a_limited_token_is_given_the_worst_state_of_its_own_clusters(self) -> None:
        self.entries = [entry("both", clusters=("alpha", "beta"))]
        states = {
            "alpha": ("On all 2 nodes", "", "healthy"),
            "beta": ("On 1 of 2 nodes", "node-d is behind", "warning"),
        }
        for cluster, expected in (("alpha", "healthy"), ("beta", "warning")):
            with self.subTest(cluster=cluster):
                with mock.patch(
                    "haprion_ui.certificates._registry_state",
                    side_effect=lambda _e, targets, **_k: states[targets[0].name],
                ):
                    row = self.by_id(self.get(self.issue(clusters=[cluster])))["both"]
                self.assertEqual(row["state"]["tone"], expected)
                self.assertEqual(row["state"]["label"], states[cluster][0])
        with mock.patch(
            "haprion_ui.certificates._registry_state",
            side_effect=lambda _e, targets, **_k: (
                states[targets[0].name] if len(targets) == 1 else ("Combined", "", "unknown")
            ),
        ):
            both = self.by_id(self.get(self.issue(clusters=["alpha", "beta"])))["both"]
            whole = self.by_id(self.get(self.issue()))["both"]
        self.assertEqual(both["state"]["tone"], "warning")
        self.assertEqual(whole["state"]["label"], "Combined")

    def test_a_certificate_deployed_nowhere_is_for_an_unlimited_token_only(self) -> None:
        self.entries = [entry("offline", kind="import", clusters=())]
        self.assertEqual(sorted(self.by_id(self.get(self.issue()))), ["offline"])
        self.assertEqual(self.by_id(self.get(self.issue(clusters=["alpha"]))), {})

    def test_the_list_is_cut_at_the_limit_and_says_so(self) -> None:
        result = self.get(self.issue(), "?limit=2").json()["result"]
        self.assertEqual(
            (len(result["certificates"]), result["count"], result["truncated"]), (2, 5, True)
        )
        refused = self.get(self.issue(), "?limit=0")
        self.assertEqual((refused.status_code, refused.json()["error"]["code"]), (400, "bad_input"))

    def test_no_registry_is_an_empty_list(self) -> None:
        self.entries = []
        with mock.patch("haprion_ui.db.cluster_certificates", return_value=[]):
            result = self.get(self.issue()).json()["result"]
        self.assertEqual(
            result,
            {
                "certificates": [],
                "count": 0,
                "truncated": False,
                "observed_at": None,
                "stale": False,
            },
        )
