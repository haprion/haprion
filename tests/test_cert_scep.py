"""The SCEP job helper and the engine's resume-by-ID and pending requests."""

from __future__ import annotations

import io
import json
import os
from typing import Any
from unittest import mock

import yaml

from haproxy_mgmt import ndes, ndes_profiles
from haproxy_mgmt.cli import cert_scep, cert_scep_helper
from haproxy_mgmt.config import NdesPolicy, load_policy
from haproxy_mgmt.dns_profile_keys import generate, render_private_key
from haproxy_mgmt.ndes_state import (
    request_directory,
    request_formats,
    request_targets,
    write_targets,
)
from tests.test_cert_import import ImportFixture

ENDPOINT = "https://ca.example.com/certsrv/mscep/mscep.dll"
REQUEST_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff"


class ScepFixture(ImportFixture):
    """The import fixture plus an NDES policy block and one applied profile."""

    def setUp(self) -> None:
        super().setUp()
        self.private, self.public = generate()
        self.ndes_root = self.root / "ndes"
        for name in ("profiles", "requests", "client"):
            (self.ndes_root / name).mkdir(parents=True, mode=0o700)
        key_path = self.ndes_root / "private.key"
        key_path.write_text(render_private_key(self.private))
        os.chmod(key_path, 0o600)
        ca = self.ndes_root / "ca.crt"
        ca.write_text(self.pki.root.read_text())
        policy = yaml.safe_load(self.policy_path.read_text())
        policy["ndes"] = {
            "endpoint": ENDPOINT,
            "tls_ca": str(ca),
            "issuing_ca": str(ca),
            "client_root": str(self.ndes_root / "client"),
            "state_root": str(self.ndes_root / "requests"),
            "profiles": {
                "directory": str(self.ndes_root / "profiles"),
                "private_keys": [str(key_path)],
            },
        }
        self.policy_path.write_text(yaml.safe_dump(policy))
        self.ndes_policy: NdesPolicy = load_policy(self.policy_path, require_secure=False).ndes  # type: ignore[assignment]
        assert self.ndes_policy is not None
        opened = ndes_profiles.open_profile(
            self.private,
            ndes_profiles.seal_profile(
                self.public,
                profile_id="certserver1",
                endpoint=ENDPOINT,
                challenge="example-challenge",
                revision=1,
            ),
            profile_id="certserver1",
            revision=1,
        )
        ndes_profiles.materialize(self.ndes_policy, opened, require_secure=False)

    def helper(self, parameters: dict[str, Any]) -> tuple[int, dict[str, Any], str]:
        request = json.dumps(
            {
                "schema_version": 1,
                "operation": "cert_scep",
                "cluster": None,
                "request_id": REQUEST_ID,
                "parameters": parameters,
            }
        )
        output, errors = io.StringIO(), io.StringIO()
        code = cert_scep_helper.main(
            [],
            policy_path=self.policy_path,
            input_stream=io.BytesIO(request.encode()),
            output_stream=output,
            error_stream=errors,
            require_root=False,
            require_secure=False,
            deployer=self.deploy,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
        )
        return code, json.loads(output.getvalue()), errors.getvalue()

    def pending(
        self,
        certificate_id: str = "web.example.com",
        *,
        profile: str = "certserver1",
        wildcard: bool = True,
    ) -> None:
        """A request the CA is holding, as the engine leaves it on the disk."""

        directory = request_directory(self.ndes_policy.state_root, certificate_id)
        directory.mkdir(mode=0o700)
        record = {
            "certificate": certificate_id,
            "profile": profile,
            "revision": 1,
            "key_id": self.public.key_id,
            "endpoint": ENDPOINT,
            "domains": [certificate_id, *(["*." + certificate_id] if wildcard else [])],
        }
        (directory / "request.json").write_text(json.dumps(record))
        os.chmod(directory / "request.json", 0o600)


class HelperBoundary(ScepFixture):
    def test_bad_shapes_are_refused_before_anything_runs(self) -> None:
        with mock.patch.object(cert_scep, "enroll") as engine:
            for parameters in (
                {"id": "../x", "profile": "certserver1", "domains": ["a.example.com"]},
                {"id": "a.example.com", "profile": "certserver1", "domains": []},
                {
                    "id": "a.example.com",
                    "profile": "certserver1",
                    "domains": ["a.example.com"],
                    "resume": "yes",
                },
                {"id": "a.example.com", "profile": "No Profile", "domains": ["a.example.com"]},
            ):
                with self.subTest(parameters=parameters):
                    code, doc, _ = self.helper(parameters)
                    self.assertEqual(code, 65)
                    self.assertEqual(doc["outcome"], "failed")
        engine.assert_not_called()

    def test_a_pending_request_keeps_its_targets_beside_it_and_is_not_registered(self) -> None:
        """Review 2026-09-17, finding 1: an entry without material refused
        every rollout to the clusters it named, so a request the CA holds is
        not in the registry. Its targets wait beside the request instead."""

        directory = request_directory(self.ndes_policy.state_root, "web.example.com")
        pending = ndes.Enrollment("pending", directory)

        @mock.patch.object(ndes, "enroll")
        def run(enroll_mock: Any) -> tuple[int, dict[str, Any], str]:
            directory.mkdir(mode=0o700)
            enroll_mock.return_value.__enter__.return_value = pending
            return self.helper(
                {
                    "id": "web.example.com",
                    "profile": "certserver1",
                    "domains": ["web.example.com", "*.web.example.com"],
                    "clusters": ["alpha"],
                    "receivers": ["lb-01"],
                }
            )

        code, doc, errors = run()
        self.assertEqual(code, 0, errors)
        self.assertEqual(doc["outcome"], "partial")
        self.assertEqual(doc["result"]["state"], "pending")
        self.assertEqual(doc["warnings"][0]["code"], "request_pending")
        self.assertNotIn("web.example.com", self.registered())
        self.assertEqual(
            request_targets(self.ndes_policy.state_root, "web.example.com"),
            (("alpha",), ("lb-01",)),
        )
        self.assertNotIn("example-challenge", json.dumps(doc) + errors)

    def test_a_resume_that_is_issued_registers_with_the_targets_the_request_kept(self) -> None:
        self.pending("web.example.com")
        write_targets(
            self.ndes_policy.state_root, "web.example.com", clusters=("alpha",), receivers=()
        )
        directory = request_directory(self.ndes_policy.state_root, "web.example.com")
        # The fixture's leaf is shop.example; validation is the engine's own
        # test, so it is stood aside here and the material is what matters.
        issued = ndes.Enrollment("issued", directory, self.material())
        with (
            mock.patch.object(ndes, "enroll") as engine,
            mock.patch.object(ndes, "validate_certificate"),
        ):
            engine.return_value.__enter__.return_value = issued
            code, doc, errors = self.helper({"id": "web.example.com", "resume": True})
        self.assertEqual(code, 0, errors)
        self.assertEqual(doc["result"]["state"], "issued")
        entry = self.registered()["web.example.com"]
        self.assertEqual(entry["source"], {"kind": "import", "ndes_profile": "certserver1"})
        self.assertEqual(entry["clusters"], ["alpha"])
        self.assertEqual(self.deployed, ["alpha"])
        # The request is over: its directory goes with it.
        self.assertFalse(directory.exists())

    def test_an_exportable_request_keeps_its_mark_through_the_wait(self) -> None:
        """B255: decided at the request, registered with it when the CA answers."""

        self.pending("bmc01.example.com", wildcard=False)
        write_targets(
            self.ndes_policy.state_root,
            "bmc01.example.com",
            clusters=(),
            receivers=(),
            exportable=True,
        )
        directory = request_directory(self.ndes_policy.state_root, "bmc01.example.com")
        issued = ndes.Enrollment("issued", directory, self.material())
        with (
            mock.patch.object(ndes, "enroll") as engine,
            mock.patch.object(ndes, "validate_certificate"),
        ):
            engine.return_value.__enter__.return_value = issued
            code, doc, errors = self.helper({"id": "bmc01.example.com", "resume": True})

        self.assertEqual(code, 0, errors)
        entry = self.registered()["bmc01.example.com"]
        self.assertTrue(entry["exportable"])
        self.assertNotIn("clusters", entry)
        self.assertEqual(self.deployed, [])

    def test_an_exportable_request_names_one_host_and_no_target(self) -> None:
        for extra in (
            {"domains": ["bmc01.example.com", "*.bmc01.example.com"]},
            {"clusters": ["alpha"]},
        ):
            with self.subTest(extra=extra), mock.patch.object(ndes, "enroll") as engine:
                code, doc, _ = self.helper(
                    {
                        "id": "bmc01.example.com",
                        "profile": "certserver1",
                        "domains": ["bmc01.example.com"],
                        "exportable": True,
                        **extra,
                    }
                )
                self.assertEqual(code, 65)
                engine.assert_not_called()

    def test_a_format_waits_beside_the_request_and_is_registered_on_resume(self) -> None:
        """B159: the form chosen at the request survives the CA's wait."""

        directory = request_directory(self.ndes_policy.state_root, "web.example.com")
        pending = ndes.Enrollment("pending", directory)
        with mock.patch.object(ndes, "enroll") as engine:
            directory.mkdir(mode=0o700)
            engine.return_value.__enter__.return_value = pending
            code, doc, errors = self.helper(
                {
                    "id": "web.example.com",
                    "profile": "certserver1",
                    "domains": ["web.example.com"],
                    "receivers": ["lb-01"],
                    "formats": {"lb-01": "pkcs12"},
                }
            )
        self.assertEqual(code, 0, errors)
        self.assertEqual(
            request_formats(self.ndes_policy.state_root, "web.example.com"), {"lb-01": "pkcs12"}
        )

        record = {
            "certificate": "web.example.com",
            "profile": "certserver1",
            "revision": 1,
            "key_id": self.public.key_id,
            "endpoint": ENDPOINT,
            "domains": ["web.example.com"],
        }
        (directory / "request.json").write_text(json.dumps(record))
        os.chmod(directory / "request.json", 0o600)
        issued = ndes.Enrollment("issued", directory, self.material())
        with (
            mock.patch.object(ndes, "enroll") as engine,
            mock.patch.object(ndes, "validate_certificate"),
        ):
            engine.return_value.__enter__.return_value = issued
            code, doc, errors = self.helper({"id": "web.example.com", "resume": True})
        self.assertEqual(code, 0, errors)
        self.assertEqual(
            self.registered()["web.example.com"]["receivers"],
            [{"id": "lb-01", "format": "pkcs12"}],
        )

    def test_a_format_for_a_receiver_not_named_is_refused(self) -> None:
        with mock.patch.object(cert_scep, "enroll") as engine:
            code, doc, _ = self.helper(
                {
                    "id": "a.example.com",
                    "profile": "certserver1",
                    "domains": ["a.example.com"],
                    "receivers": ["lb-01"],
                    "formats": {"lb-02": "pkcs12"},
                }
            )
        self.assertEqual(code, 65)
        self.assertEqual(doc["error"]["code"], "bad_input")
        engine.assert_not_called()

    def test_abandon_removes_a_request_the_ca_never_answered(self) -> None:
        self.pending("web.example.com")
        directory = request_directory(self.ndes_policy.state_root, "web.example.com")
        output = io.StringIO()
        code = cert_scep.main(
            ["--id", "web.example.com", "--abandon", "--json"],
            policy_path=self.policy_path,
            output_stream=output,
            error_stream=io.StringIO(),
            require_secure=False,
            require_root=False,
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["result"]["state"], "abandoned")
        self.assertFalse(directory.exists())
        code = cert_scep.main(
            ["--id", "web.example.com", "--abandon", "--json"],
            policy_path=self.policy_path,
            output_stream=io.StringIO(),
            error_stream=io.StringIO(),
            require_secure=False,
            require_root=False,
        )
        self.assertEqual(code, 65)
        code = cert_scep.main(
            ["--id", "web.example.com", "--abandon", "--resume"],
            policy_path=self.policy_path,
            output_stream=io.StringIO(),
            error_stream=io.StringIO(),
            require_secure=False,
            require_root=False,
        )
        self.assertEqual(code, 65)

    def test_a_resume_names_only_the_certificate_and_takes_the_rest_from_the_record(
        self,
    ) -> None:
        self.pending("web.example.com")
        seen: dict[str, Any] = {}

        def fake_enroll(policy: Any, **kwargs: Any) -> Any:
            seen.update(kwargs)
            context = mock.MagicMock()
            context.__enter__.return_value = ndes.Enrollment(
                "pending", self.ndes_root / "requests" / "x"
            )
            return context

        with mock.patch.object(ndes, "enroll", side_effect=fake_enroll):
            code, doc, errors = self.helper({"id": "web.example.com", "resume": True})
        self.assertEqual(code, 0, errors)
        self.assertEqual(seen["domains"], ("web.example.com", "*.web.example.com"))
        self.assertEqual(seen["profile"].profile_id, "certserver1")
        self.assertTrue(seen["resume"])

    def test_a_resume_with_no_request_is_a_refusal(self) -> None:
        with mock.patch.object(ndes, "enroll") as engine:
            code, doc, _ = self.helper({"id": "nothing.example.com", "resume": True})
        self.assertEqual(code, 65)
        self.assertEqual(doc["error"]["code"], "bad_input")
        engine.assert_not_called()

    def test_the_terminal_command_resumes_by_id_too(self) -> None:
        self.pending("web.example.com")
        with mock.patch.object(ndes, "enroll") as engine:
            engine.return_value.__enter__.return_value = ndes.Enrollment(
                "pending", self.ndes_root / "requests" / "x"
            )
            output = io.StringIO()
            code = cert_scep.main(
                ["--id", "web.example.com", "--resume", "--json"],
                policy_path=self.policy_path,
                output_stream=output,
                error_stream=io.StringIO(),
                require_secure=False,
                require_root=False,
                live=self.live,
                store=self.store,
                lock_path=self.lock,
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["result"]["state"], "pending")
