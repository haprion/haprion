"""``haprion-profiles apply`` without a database: the file and the answer (Fas 23, B293).

The rows and jobs are held against the real schema in
`test_database_integration` (`TheProfilesFromAFile`).
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from haprion_ui import profile_apply, tool_answer
from haprion_ui.profile_apply import ApplyError, Change, Plan
from tests.contract_schema import assert_contract

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures/haprion-profiles-apply/valid/done.json"


class TheFile(unittest.TestCase):
    def write(self, text: str, mode: int = 0o600) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "profiles.yaml"
        path.write_text(text)
        path.chmod(mode)
        return path

    def test_a_good_file_is_read_by_section(self) -> None:
        found = profile_apply.read_file(
            self.write(
                "dns_profiles:\n  - {id: CF-Main, provider: cloudflare, fields: {api_token: t}}\n"
            )
        )

        (wanted,) = found["dns_profiles"]
        self.assertEqual((wanted.profile_id, wanted.provider_id), ("cf-main", "cloudflare"))
        self.assertNotIn("ndes_profiles", found)

    def test_what_the_file_refuses(self) -> None:
        for text, said in (
            ("{}\n", "holds dns_profiles"),
            ("acme_profiles: []\n", "unknown section"),
            (
                "ndes_profiles:\n  - {id: a, endpoint: https://x.example/, colour: red}\n",
                "unknown field",
            ),
            ("dns_profiles:\n  - {id: a, provider: x}\n  - {id: A, provider: x}\n", "twice"),
            ("dns_profiles:\n  - {id: a, provider: 7}\n", "must be text"),
            (
                "dns_profiles:\n  - {id: a, provider: x, fields: {algorithm: null}}\n",
                "fields.algorithm must be text",
            ),
            (
                "dns_profiles:\n  - {id: a, provider: x, fields: {port: true}}\n",
                "fields.port must be text",
            ),
        ):
            with self.subTest(said), self.assertRaises(ApplyError) as raised:
                profile_apply.read_file(self.write(text))
            self.assertIn(said, str(raised.exception))

    def test_credentials_others_may_read_are_refused(self) -> None:
        with self.assertRaises(ApplyError) as raised:
            profile_apply.read_file(
                self.write("dns_profiles:\n  - {id: a, provider: x}\n", mode=0o640)
            )

        self.assertIn("0600", str(raised.exception))
        profile_apply.read_file(self.write("dns_profiles: []\n", mode=0o644))


class TheAnswer(unittest.TestCase):
    def test_it_has_the_shape_the_contract_holds(self) -> None:
        plan = Plan((Change(profile_apply.DNS, "cf-main", "create", 1),), ("ndes/corp-ca",))
        jobs = [{"kind": "dns", "profile": "cf-main", "job": 41, "state": "done"}]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = tool_answer.done(
                profile_apply.OPERATION, profile_apply.summary(plan, check=False, applied=jobs)
            )
        self.assertEqual(code, 0)
        answer = assert_contract("haprion-profiles-apply", out.getvalue())
        fixture = json.loads(FIXTURE.read_text())

        self.assertEqual(answer["result"], fixture["result"])


if __name__ == "__main__":
    unittest.main()


class AnNdesProfileNeedsAConfirmedServer(unittest.TestCase):
    """B385: the file is refused for an address the form would not offer, before anything is sealed."""

    def test_an_address_not_confirmed_is_refused_and_a_confirmed_one_passes_the_check(self) -> None:
        wanted = profile_apply.Wanted(
            profile_apply.NDES,
            "internal-ca",
            "ndes",
            {"endpoint": "https://ca.example.com/certsrv/mscep/mscep.dll", "challenge": "x"},
        )
        with self.assertRaisesRegex(ApplyError, "not an NDES server confirmed on this manager"):
            profile_apply.plan(
                {"ndes_profiles": [wanted]},
                {},
                object(),  # type: ignore[arg-type]
                replace=(),
                prune=False,
                servers=["https://ca2.example.com/certsrv/mscep/mscep.dll"],
            )
        with self.assertRaises(Exception) as sealed:
            profile_apply.plan(
                {"ndes_profiles": [wanted]},
                {},
                object(),  # type: ignore[arg-type]
                replace=(),
                prune=False,
                servers=["https://ca.example.com/certsrv/mscep/mscep.dll"],
            )
        self.assertNotIn("not an NDES server", str(sealed.exception))
