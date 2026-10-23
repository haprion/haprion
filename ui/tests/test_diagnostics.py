"""The only form of helper diagnostics that may reach the database."""

from __future__ import annotations

import unittest

from haprion_ui import diagnostics


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


class TheDiagnosticsInAResultAreMaskedToo(unittest.TestCase):
    """Review 2026-10-22, 5-9: `error.details.diagnostics` was stored and shown as it came."""

    BEGIN = "-----BEGIN " + "PRIVATE KEY-----"
    END = "-----END " + "PRIVATE KEY-----"

    def text(self) -> str:
        return "\n".join(
            (
                "pass" + "word=synthetic-password-value",
                self.BEGIN,
                "synthetic-key-material",
                self.END,
                "dns_example_api_" + "key = synthetic-api-value",
                "ssl-crt-key: kept",
            )
        )

    def assert_masked(self, text: str) -> None:
        for private in (
            "synthetic-password-value",
            "synthetic-key-material",
            "synthetic-api-value",
        ):
            self.assertNotIn(private, text)
        self.assertIn("ssl-crt-key: kept", text)

    def test_every_diagnostics_text_in_a_result_is_redacted(self) -> None:
        result = {
            "error": {"code": "exit_mismatch", "details": {"diagnostics": self.text()}},
            "answer": {"error": {"details": {"diagnostics": self.text()}}},
            "nodes": [{"diagnostics": self.text(), "name": "node-a"}],
        }
        redacted = diagnostics.redact_result(result)
        self.assert_masked(redacted["error"]["details"]["diagnostics"])
        self.assert_masked(redacted["answer"]["error"]["details"]["diagnostics"])
        self.assert_masked(redacted["nodes"][0]["diagnostics"])
        self.assertEqual(redacted["nodes"][0]["name"], "node-a")
        self.assertIsNone(diagnostics.redact_result(None))

    def test_the_job_page_masks_a_row_stored_before(self) -> None:
        from types import SimpleNamespace

        from haprion_ui import jobs

        job = SimpleNamespace(
            result={"error": {"details": {"diagnostics": self.text()}}}, stderr_excerpt=None
        )
        shown = jobs.diagnostics_of(job)  # type: ignore[arg-type]
        self.assertIsNotNone(shown)
        self.assert_masked(str(shown))


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
