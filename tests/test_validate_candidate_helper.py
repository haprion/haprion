from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from haproxy_mgmt.candidate_validation import ValidationResult
from haproxy_mgmt.cli.validate_candidate_helper import main

BASE = Path(__file__).resolve().parents[1]
REQUEST_ID = "11111111-1111-4111-8111-111111111111"


class ValidateCandidateHelperTests(unittest.TestCase):
    def runtime(self, root: Path) -> tuple[Path, Path]:
        config_root = root / "config"
        publish_root = root / "published"
        cert_root = root / "validation-certs"
        for directory in (config_root / "alpha", publish_root / "alpha", cert_root):
            directory.mkdir(parents=True)
        (cert_root / "validation.pem").write_text("dummy PEM\n", encoding="utf-8")

        clusters = yaml.safe_load((BASE / "examples/clusters.yaml").read_text())
        cluster = clusters["clusters"]["alpha"]
        cluster["config_path"] = str(config_root / "alpha")
        cluster["publish_path"] = str(publish_root / "alpha")
        cluster["validation_certs"] = str(cert_root)
        cluster_path = root / "clusters.yaml"
        cluster_path.write_text(yaml.safe_dump(clusters), encoding="utf-8")
        policy = {
            "schema_version": 1,
            "cluster_file": str(cluster_path),
            "config_root": str(config_root),
            "publish_root": str(publish_root),
            "validation_certs_root": str(cert_root),
        }
        policy_path = root / "runtime-policy.yaml"
        policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        return policy_path, root / "run"

    def request(self) -> io.BytesIO:
        return io.BytesIO(
            json.dumps(
                {
                    "schema_version": 1,
                    "operation": "validate_candidate",
                    "cluster": "alpha",
                    "request_id": REQUEST_ID,
                    "parameters": {"files": {"haproxy.cfg": "global\n  daemon\n"}},
                }
            ).encode()
        )

    def test_valid_result_and_cleanup(self):
        with tempfile.TemporaryDirectory() as raw:
            policy_path, run_root = self.runtime(Path(raw))
            seen: list[Path] = []

            def validate(candidate_root: Path, request_id: str) -> ValidationResult:
                self.assertEqual(request_id, REQUEST_ID)
                self.assertTrue((candidate_root / "haproxy.cfg").is_file())
                seen.append(candidate_root)
                return ValidationResult(valid=True, diagnostics="Configuration file is valid\n")

            stdout = io.StringIO()
            stderr = io.StringIO()
            code = main(
                [],
                policy_path=policy_path,
                run_root=run_root,
                input_stream=self.request(),
                output_stream=stdout,
                error_stream=stderr,
                require_secure=False,
                require_root=False,
                validator=validate,
            )
            result = json.loads(stdout.getvalue())
        self.assertEqual((code, stderr.getvalue()), (0, ""))
        self.assertTrue(result["valid"])
        self.assertEqual(result["request_id"], REQUEST_ID)
        self.assertFalse(seen[0].exists())

    def test_argv_and_invalid_candidate_fail_closed(self):
        stderr = io.StringIO()
        code = main(
            ["--path", "/tmp/candidate"],
            input_stream=self.request(),
            output_stream=io.StringIO(),
            error_stream=stderr,
            require_secure=False,
            require_root=False,
        )
        self.assertEqual(code, 64)
        self.assertIn("no command-line arguments", stderr.getvalue())

        process_stderr = io.StringIO()
        with patch("sys.argv", ["haproxy-validate-candidate-helper", "--unexpected"]):
            process_code = main(
                input_stream=self.request(),
                output_stream=io.StringIO(),
                error_stream=process_stderr,
                require_secure=False,
                require_root=False,
            )
        self.assertEqual(process_code, 64)
        self.assertIn("no command-line arguments", process_stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
