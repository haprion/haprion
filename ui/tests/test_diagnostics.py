"""The only form of helper diagnostics that may reach the database."""

from __future__ import annotations

import unittest

from haproxy_ui import diagnostics


class RedactionHappensBeforePersistence(unittest.TestCase):
    def test_private_keys_assignments_and_private_paths_are_masked(self) -> None:
        begin = "-----BEGIN " + "PRIVATE KEY-----"
        end = "-----END " + "PRIVATE KEY-----"
        private_key = "\n".join((begin, "synthetic-key-material", end))
        assignment = "=".join(("api_" + "token", "synthetic-assigned-value"))
        password_assignment = ": ".join(("pass" + "word", "synthetic-password-value"))
        value = "\n".join(
            (
                private_key,
                assignment,
                password_assignment,
                "read /root/.ssh/id_example",
                "read /run/secrets/example",
                "read /etc/haprion/ui-secrets/dns-profile-keys/example.key",
                "read /etc/ssl/private/example.pem",
                "read /srv/certificates/haproxy/example.pem",
                "read /srv/haprion/validation/certs/example.pem",
            )
        )

        excerpt = diagnostics.safe_excerpt(value)

        for private in (
            "synthetic-key-material",
            "synthetic-assigned-value",
            "synthetic-password-value",
            "id_example",
            "/run/secrets/",
            "/etc/haprion/ui-secrets/",
            "/etc/ssl/private/",
            "/srv/certificates/",
            "/srv/haprion/validation/",
        ):
            self.assertNotIn(private, excerpt)
        self.assertGreaterEqual(excerpt.count(diagnostics.REDACTED), 9)

    def test_a_private_key_cut_at_either_capture_edge_is_still_masked(self) -> None:
        beginning = "-----BEGIN " + "PRIVATE KEY-----\nsynthetic-key-prefix"
        ending = "synthetic-key-suffix\n-----END " + "PRIVATE KEY-----\nafter"

        self.assertEqual(diagnostics.redact(beginning), diagnostics.REDACTED)
        redacted_ending = diagnostics.redact(ending)
        self.assertNotIn("synthetic-key-suffix", redacted_ending)
        self.assertTrue(redacted_ending.endswith("\nafter"))


class TheDatabaseByteLimitIsKept(unittest.TestCase):
    def test_utf8_is_cut_by_bytes_with_both_edges_and_a_marker(self) -> None:
        value = "first-line\n" + ("å" * 40_000) + "\nlast-line"

        excerpt = diagnostics.safe_excerpt(value)

        self.assertLessEqual(len(excerpt.encode("utf-8")), diagnostics.LIMIT_BYTES)
        self.assertTrue(excerpt.startswith("first-line"))
        self.assertTrue(excerpt.endswith("last-line"))
        self.assertIn(diagnostics.TRUNCATION_MARKER, excerpt)


if __name__ == "__main__":
    unittest.main()
