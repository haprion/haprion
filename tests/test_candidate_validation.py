from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar
from unittest import mock

from haprion import candidate_validation
from haprion.candidate_validation import (
    materialize_candidate,
    parse_candidate,
    sandbox_command,
)
from haprion.helper_protocol import HelperProtocolError, JsonValue


class CandidateValidationTests(unittest.TestCase):
    def test_manifest_is_deterministic_and_materialized_with_rewrites(self) -> None:
        files: dict[str, JsonValue] = {
            "maps/hosts.map": "example.com backend-a\n",
            "conf.d/0074-site.cfg": "bind :443 ssl crt /etc/haproxy/certs/example.com.pem\n",
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
            self.assertIn(b"/candidate/certs/", (root / "conf.d/0074-site.cfg").read_bytes())
            self.assertEqual((root / "certs/example.com.pem").read_bytes(), b"dummy PEM\n")
            self.assertEqual(os.stat(root / "haproxy.cfg").st_mode & 0o777, 0o600)

    def test_invalid_paths_content_and_shape_are_rejected(self) -> None:
        invalid: tuple[tuple[dict[str, JsonValue], str], ...] = (
            ({"files": {}}, "non-empty"),
            ({"files": {"conf.d/0074-site.cfg": "x"}}, "haproxy.cfg"),
            ({"files": {"haproxy.cfg": "x", "/etc/shadow": "x"}}, "relative path"),
            ({"files": {"haproxy.cfg": "x", "../escape": "x"}}, "relative path"),
            ({"files": {"haproxy.cfg": "x", "scripts/run": "x"}}, "allowlist"),
            # The keepalived directory is one shape and not a second free-form
            # tree: one level deep, and .conf only.
            ({"files": {"haproxy.cfg": "x", "keepalived/a/b.conf": "x"}}, "allowlist"),
            ({"files": {"haproxy.cfg": "x", "keepalived/run.sh": "x"}}, "allowlist"),
            ({"files": {"haproxy.cfg": "bad\x00value"}}, "NUL"),
            ({"files": {"haproxy.cfg": 4}}, "strings"),
        )
        for parameters, message in invalid:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(HelperProtocolError, message),
            ):
                parse_candidate(parameters)

    def test_the_keepalived_address_list_may_cross_the_boundary(self) -> None:
        #
        # It is not HAProxy configuration and takes no part in the validation
        # the helper runs; it rides along to the node, which checks it with
        # keepalived's own parser before using it. What it must not do is
        # arrive by a path of its own - a release and its address list have to
        # be one thing, or they can be published separately and disagree.
        #
        candidate = parse_candidate(
            {"files": {"haproxy.cfg": "x", "keepalived/addresses.conf": "    192.0.2.20\n"}}
        )

        self.assertIn("keepalived/addresses.conf", candidate.files)

    def test_sandbox_command_has_fixed_executable_and_denies_private_roots(self) -> None:
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


class TheWafLayerIsValidatedByTheEngine(unittest.TestCase):
    """B230: the candidate's rules are compiled on the manager, in the same sandbox."""

    FILES: ClassVar[dict[str, JsonValue]] = {
        "haproxy.cfg": "global\n",
        "conf.d/1000-frontends.cfg": "filter spoe engine coraza config /etc/haproxy/waf/spoe.conf\n",
        "waf/coraza.yaml": "      Include /etc/haproxy/waf/crs/rules/*.conf\n",
        "waf/spoe.conf": "[coraza]\n",
        "waf/crs/crs-setup.conf": "# setup\n",
        "waf/crs/rules/REQUEST-901-INITIALIZATION.conf": "# rules\n",
    }

    def test_the_waf_shapes_cross_and_nothing_else_under_waf(self) -> None:
        self.assertIn("waf/coraza.yaml", parse_candidate({"files": self.FILES}).files)
        for path in ("waf/run.sh", "waf/crs/rules/x.sh", "waf/crs/x/y.conf", "waf/../haproxy.cfg"):
            with self.subTest(path), self.assertRaises(HelperProtocolError):
                parse_candidate({"files": {"haproxy.cfg": "x", path: "x"}})

    def test_the_engine_and_the_frontend_read_the_candidate_s_own_rules(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "candidate"
            materialize_candidate(
                parse_candidate({"files": self.FILES}),
                root,
                certificate_ids=(),
                validation_certificate=b"",
            )
            self.assertIn(
                b"/candidate/waf/spoe.conf", (root / "conf.d/1000-frontends.cfg").read_bytes()
            )
            self.assertIn(b"/candidate/waf/crs/rules", (root / "waf/coraza.yaml").read_bytes())

    def test_the_engine_check_runs_in_the_same_sandbox_as_its_own_unit(self) -> None:
        command = sandbox_command(
            Path("/run/candidate"),
            "11111111-1111-4111-8111-111111111111",
            ("/usr/sbin/coraza-spoa", "-validate", "-config", "/candidate/waf/coraza.yaml"),
        )
        self.assertEqual(
            command[-4:],
            ["/usr/sbin/coraza-spoa", "-validate", "-config", "/candidate/waf/coraza.yaml"],
        )
        self.assertIn("--unit=haprion-validation-11111111111141118111111111111111-waf", command)
        self.assertIn("TemporaryFileSystem=/:ro", " ".join(command))
        self.assertNotIn("/usr/sbin/haproxy", command)

    def test_rules_without_the_engine_on_the_manager_are_refused(self) -> None:
        calls: list[list[str]] = []

        def ran(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "waf").mkdir()
            (root / "waf" / "coraza.yaml").write_text("x")
            with (
                mock.patch.object(subprocess, "run", ran),
                mock.patch.object(candidate_validation, "WAF_ENGINE", str(root / "absent")),
            ):
                result = candidate_validation.validate_in_sandbox(root, "1111")
        self.assertFalse(result.valid)
        self.assertIn("haprion-coraza-spoa", result.diagnostics)
        self.assertEqual(len(calls), 1)


class TheDnsListenerIsValidatedByDnsdist(unittest.TestCase):
    """B249: `dns/dnsdist.conf` crosses alone and is checked by dnsdist, warnings refusing."""

    FILES = TheWafLayerIsValidatedByTheEngine.FILES

    def test_dnsdist_checks_the_dns_listener_in_a_unit_of_its_own(self) -> None:
        command = sandbox_command(
            Path("/run/candidate"),
            "11111111-1111-4111-8111-111111111111",
            ("/usr/bin/dnsdist", "--check-config", "-C", "/candidate/dns/dnsdist.conf"),
        )
        self.assertEqual(
            command[-4:],
            ["/usr/bin/dnsdist", "--check-config", "-C", "/candidate/dns/dnsdist.conf"],
        )
        self.assertIn("--unit=haprion-validation-11111111111141118111111111111111-dns", command)

    def dns_validation(
        self, output: str, code: int = 0, *, installed: bool = True
    ) -> tuple[candidate_validation.ValidationResult, list[list[str]]]:
        calls: list[list[str]] = []

        def ran(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            dns = "--check-config" in command
            return subprocess.CompletedProcess(
                command, code if dns else 0, output if dns else "", ""
            )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "dns").mkdir()
            (root / "dns" / "dnsdist.conf").write_text("x")
            binary = root / "dnsdist"
            if installed:
                binary.write_text("")
            with (
                mock.patch.object(subprocess, "run", ran),
                mock.patch.object(candidate_validation, "DNSDIST", str(binary)),
            ):
                return candidate_validation.validate_in_sandbox(root, "1111"), calls

    def test_a_clean_dnsdist_check_passes(self) -> None:
        result, calls = self.dns_validation('msg="Configuration OK" prio="Info"')
        self.assertTrue(result.valid, result.diagnostics)
        self.assertEqual(len(calls), 2)

    def test_a_dnsdist_warning_refuses_although_it_exits_0(self) -> None:
        # Measured on 2.1.2: an unknown key is ignored with a warning and exit 0.
        result, _ = self.dns_validation('msg="Unknown key, ignored" prio="Warning" key="x"')
        self.assertFalse(result.valid)
        self.assertIn("dnsdist warned", result.diagnostics)

    def test_a_failed_dnsdist_check_refuses(self) -> None:
        result, _ = self.dns_validation('msg="Fatal Lua error" prio="Error"', code=1)
        self.assertFalse(result.valid)

    def test_a_dns_listener_without_dnsdist_on_the_manager_is_refused(self) -> None:
        result, calls = self.dns_validation("", installed=False)
        self.assertFalse(result.valid)
        self.assertIn("dnsdist is not installed", result.diagnostics)
        self.assertEqual(len(calls), 1)

    def test_only_dnsdists_one_file_crosses_into_its_directory(self) -> None:
        self.assertEqual(
            parse_candidate({"files": {**self.FILES, "dns/dnsdist.conf": "x"}}).files[
                "dns/dnsdist.conf"
            ],
            b"x",
        )
        for name in ("dns/dnsdist.yml", "dns/sub/dnsdist.conf", "dns/other.conf"):
            with self.subTest(name), self.assertRaises(HelperProtocolError):
                parse_candidate({"files": {**self.FILES, name: "x"}})


if __name__ == "__main__":
    unittest.main()


class TheValidatorVersion(unittest.TestCase):
    """What `haproxy -v` names on this host, for the status reading (Fas 16 punkt 3b)."""

    def answer(
        self, stdout: str, code: int = 0
    ) -> Callable[[list[str]], subprocess.CompletedProcess[str]]:
        return lambda argv: subprocess.CompletedProcess(argv, code, stdout, "")

    def test_the_version_is_the_third_word_of_the_first_line(self) -> None:
        text = "HAProxy version 3.4.6-1ppa1~resolute 2026/09/28 - https://haproxy.org/\nStatus: long-term\n"
        self.assertEqual(
            candidate_validation.validator_version(self.answer(text)), "3.4.6-1ppa1~resolute"
        )

    def test_anything_else_is_none(self) -> None:
        for stdout, code in (("", 0), ("something else\n", 0), ("HAProxy version 3.4.6\n", 1)):
            with self.subTest(stdout=stdout, code=code):
                self.assertIsNone(candidate_validation.validator_version(self.answer(stdout, code)))

        def missing(_argv: list[str]) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError("/usr/sbin/haproxy")

        self.assertIsNone(candidate_validation.validator_version(missing))
