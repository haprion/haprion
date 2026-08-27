from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from haproxy_mgmt.candidate_validation import (
    materialize_candidate,
    parse_candidate,
    sandbox_command,
)
from haproxy_mgmt.helper_protocol import HelperProtocolError


class CandidateValidationTests(unittest.TestCase):
    def test_manifest_is_deterministic_and_materialized_with_rewrites(self):
        files = {
            "maps/hosts.map": "example.com backend-a\n",
            "conf.d/site.cfg": "bind :443 ssl crt /etc/haproxy/certs/example.com.pem\n",
            "haproxy.cfg": "map(/etc/haproxy/maps/hosts.map)\n",
        }
        first = parse_candidate({"files": files})
        second = parse_candidate({"files": dict(reversed(list(files.items())))})
        self.assertEqual(first.sha256, second.sha256)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "candidate"
            materialize_candidate(
                first,
                root,
                certificate_ids=("example.com",),
                validation_certificate=b"dummy PEM\n",
            )
            self.assertIn(b"/candidate/maps/", (root / "haproxy.cfg").read_bytes())
            self.assertIn(b"/candidate/certs/", (root / "conf.d/site.cfg").read_bytes())
            self.assertEqual((root / "certs/example.com.pem").read_bytes(), b"dummy PEM\n")
            self.assertEqual(os.stat(root / "haproxy.cfg").st_mode & 0o777, 0o600)

    def test_invalid_paths_content_and_shape_are_rejected(self):
        invalid = (
            ({"files": {}}, "non-empty"),
            ({"files": {"conf.d/site.cfg": "x"}}, "haproxy.cfg"),
            ({"files": {"haproxy.cfg": "x", "/etc/shadow": "x"}}, "relative path"),
            ({"files": {"haproxy.cfg": "x", "../escape": "x"}}, "relative path"),
            ({"files": {"haproxy.cfg": "x", "scripts/run": "x"}}, "allowlist"),
            ({"files": {"haproxy.cfg": "bad\x00value"}}, "NUL"),
            ({"files": {"haproxy.cfg": 4}}, "strings"),
        )
        for parameters, message in invalid:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(HelperProtocolError, message),
            ):
                parse_candidate(parameters)

    def test_sandbox_command_has_fixed_executable_and_denies_private_roots(self):
        command = sandbox_command(Path("/run/candidate"), "11111111-1111-4111-8111-111111111111")
        self.assertEqual(command[0], "/usr/bin/systemd-run")
        self.assertEqual(
            command[-7:],
            [
                "/usr/sbin/haproxy",
                "-c",
                "-dr",
                "-f",
                "/candidate/haproxy.cfg",
                "-f",
                "/candidate/conf.d",
            ],
        )
        joined = " ".join(command)
        self.assertIn("CapabilityBoundingSet=", command)
        #
        # An allowlist, not a denylist: the root is an empty tmpfs and only what
        # parsing needs is bound back. A denylist of top-level directories is
        # incomplete the moment a new one exists, and had to name the
        # deployment's own trees in a public repository.
        #
        self.assertIn("TemporaryFileSystem=/:ro", joined)
        self.assertIn("BindReadOnlyPaths=/usr", joined)
        self.assertNotIn("InaccessiblePaths", joined)
        #
        # Nothing in here may name a real deployment's directories.
        #
        for private_tree in ("/apps", "/configs"):
            self.assertNotIn(private_tree, joined)
        #
        # /etc is an empty tmpfs holding exactly what parsing needs. Measured
        # 2026-08-26: without these a real cluster configuration fails on
        # "user haproxy", "group haproxy" and every errorfile.
        #
        self.assertIn("TemporaryFileSystem=/etc", joined)
        #
        # No network means no name resolution. The nodes check that themselves,
        # with the resolver whose answer actually matters.
        #
        self.assertIn("-dr", command)
        for required in ("/etc/passwd", "/etc/group", "/etc/haproxy/errors"):
            self.assertIn(f"BindReadOnlyPaths={required}", joined)
        self.assertNotIn("/etc/haproxy/certs", joined)
        self.assertIn("BindReadOnlyPaths=/run/candidate:/candidate", joined)


if __name__ == "__main__":
    unittest.main()
