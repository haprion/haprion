"""NDES servers confirmed from their CA, and written into the policy's ndes block (B383, B385)."""

from __future__ import annotations

import fcntl
import hashlib
import io
import json
import multiprocessing
import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any
from unittest import mock

import yaml

from haprion import exit_codes, ndes_servers, safe_yaml
from haprion.cli import ndes_server, ndes_server_helper
from haprion.config import load_policy
from tests.contract_schema import assert_contract
from tests.test_cert_import import OPENSSL, Pki

ENDPOINT = "https://ca.example.com/certsrv/mscep/mscep.dll"
OTHER = "https://ca2.example.com/certsrv/mscep/mscep.dll"
POLICY = """\
# Runtime policy, rendered by the installation.
schema_version: 1
cluster_file: {root}/clusters.yaml
config_root: {root}/config
publish_root: {root}/publish
validation_certs_root: {root}/validation
acme:
  dns_profiles:
    directory: {root}/dns-profiles
    private_keys:
    - {root}/keys/0123456789abcdef.key
"""


class Answer:
    """GetCACert as an AD CS NDES answers it: the CAs and the RA certificate, PKCS#7 DER."""

    def __init__(self, root: Path) -> None:
        # The intermediate plays the issuing CA, the leaf its RA certificate.
        self.pki = Pki(root / "pki", names=("ndes-ra.example.com",))
        bundle = root / "bundle.pem"
        bundle.write_text(
            self.pki.intermediate.read_text()
            + self.pki.root.read_text()
            + self.pki.leaf.read_text()
        )
        self.der = subprocess.run(
            [OPENSSL, "crl2pkcs7", "-nocrl", "-certfile", str(bundle), "-outform", "DER"],
            capture_output=True,
            check=True,
        ).stdout
        self.asked: list[str] = []

    def __call__(self, endpoint: str) -> bytes:
        self.asked.append(endpoint)
        return self.der

    def sha256(self, path: Path) -> str:
        der = subprocess.run(
            [OPENSSL, "x509", "-in", str(path), "-outform", "DER"], capture_output=True, check=True
        ).stdout
        return hashlib.sha256(der).hexdigest()


class TheAuthorities(unittest.TestCase):
    def test_the_cas_the_issuing_one_first_and_never_the_ra(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            answer = Answer(Path(raw))
            found = ndes_servers.authorities(ENDPOINT, fetch=answer)
            issuing = answer.sha256(answer.pki.intermediate)

        self.assertEqual(len(found), 2)
        self.assertTrue(found[0].issues_ra)
        self.assertEqual(found[0].subject, "CN=Test Issuing CA")
        self.assertFalse(found[1].issues_ra)
        self.assertEqual(found[0].sha256, issuing)
        self.assertRegex(found[0].sha1, r"^[0-9a-f]{40}$")
        self.assertEqual(answer.asked, [ENDPOINT])

    def test_an_address_that_is_not_https_is_refused_before_anything_is_asked(self) -> None:
        asked: list[str] = []
        with self.assertRaises(ndes_servers.NdesServerError) as caught:
            ndes_servers.authorities("http://ca.example.com/", fetch=asked.append)  # type: ignore[arg-type]
        self.assertEqual(caught.exception.code, "bad_input")
        self.assertEqual(asked, [])

    def test_an_answer_without_a_ca_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            leaf = Answer(Path(raw)).pki.leaf.read_bytes()
            with self.assertRaises(ndes_servers.NdesServerError) as caught:
                ndes_servers.authorities(ENDPOINT, fetch=lambda _: leaf)
        self.assertEqual(caught.exception.code, "bad_answer")


class ThePolicy(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.policy = self.root / "runtime-policy.yaml"
        self.policy.write_text(POLICY.format(root=self.root))
        self.policy.chmod(0o644)
        self.cas = self.root / "ndes-ca"
        self.answer = Answer(self.root)
        self.issuing = self.answer.sha256(self.answer.pki.intermediate)
        self.chain = [self.issuing, self.answer.sha256(self.answer.pki.root)]
        self.lock = self.root / "locks" / "ndes-policy.lock"
        patch = mock.patch.object(ndes_servers, "LOCK_PATH", self.lock)
        patch.start()
        self.addCleanup(patch.stop)

    def add(
        self, endpoint: str = ENDPOINT, fingerprints: list[str] | None = None
    ) -> dict[str, object]:
        return ndes_servers.add(
            endpoint,
            self.chain if fingerprints is None else fingerprints,
            policy_path=self.policy,
            ca_directory=self.cas,
            fetch=self.answer,
        )

    def servers(self) -> list[str]:
        ndes = load_policy(self.policy, require_secure=False).ndes
        assert ndes is not None
        return [server.endpoint for server in ndes.servers]

    def test_a_first_server_makes_the_block_and_keeps_the_rest_of_the_file(self) -> None:
        added = self.add()

        text = self.policy.read_text()
        self.assertTrue(text.startswith("# Runtime policy, rendered by the installation.\n"))
        self.assertEqual(self.servers(), [ENDPOINT])
        ndes = yaml.safe_load(text)["ndes"]
        self.assertEqual(ndes["client_root"], "/opt/haprion-scep/current")
        self.assertEqual(
            ndes["profiles"]["private_keys"], [f"{self.root}/keys/0123456789abcdef.key"]
        )
        written = Path(str(added["issuing_ca"]))
        self.assertEqual(written.parent, self.cas)
        self.assertIn(self.answer.pki.intermediate.read_text(), written.read_text())
        self.assertNotIn(self.answer.pki.leaf.read_text(), written.read_text())
        self.assertEqual(written.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.policy.stat().st_mode & 0o777, 0o644)

    def test_a_second_server_is_added_and_the_form_before_it_becomes_the_first(self) -> None:
        with self.policy.open("a") as policy:
            policy.write(
                "ndes:\n"
                f"  endpoint: {ENDPOINT}\n"
                f"  tls_ca: {self.root}/tls.pem\n"
                f"  issuing_ca: {self.root}/ca.pem\n"
                "  client_root: /opt/haprion-scep/current\n"
                "  state_root: /etc/haprion/ndes-requests\n"
                "  profiles:\n"
                "    directory: /etc/haprion/ndes-profiles\n"
                "    private_keys: [/etc/haprion/keys/0123456789abcdef.key]\n"
                f"backup_root: {self.root}/backup\n"
            )
        self.add(OTHER)

        self.assertEqual(self.servers(), [ENDPOINT, OTHER])
        data = yaml.safe_load(self.policy.read_text())
        self.assertEqual(data["ndes"]["servers"][0]["tls_ca"], f"{self.root}/tls.pem")
        self.assertEqual(data["backup_root"], f"{self.root}/backup")

    def test_a_fingerprint_the_server_no_longer_gives_changes_nothing(self) -> None:
        before = self.policy.read_text()
        with self.assertRaises(ndes_servers.NdesServerError) as caught:
            self.add(fingerprints=["0" * 64])
        self.assertEqual(caught.exception.code, "changed")
        self.assertEqual(self.policy.read_text(), before)
        self.assertFalse(self.cas.exists())

    def test_every_ca_certificate_saved_is_one_confirmed(self) -> None:
        # Review 2026-10-28, U02: the server's whole chain is saved, so the
        # issuing CA alone, or the chain with one more, confirms nothing.
        before = self.policy.read_text()
        for fingerprints in ([self.issuing], [*self.chain, "0" * 64], []):
            with self.assertRaises(ndes_servers.NdesServerError):
                self.add(fingerprints=fingerprints)
        self.assertEqual(self.policy.read_text(), before)
        added = self.add(fingerprints=list(reversed(self.chain)))
        self.assertEqual(added["sha256"], self.chain)

    def test_a_server_in_use_stays_and_the_last_one_takes_the_block(self) -> None:
        self.add()
        self.add(OTHER)
        with self.assertRaises(ndes_servers.NdesServerError) as caught:
            ndes_servers.remove(OTHER, used_by=lambda: ("internal-ca",), policy_path=self.policy)
        self.assertEqual(caught.exception.code, "in_use")

        ndes_servers.remove(OTHER, used_by=lambda: (), policy_path=self.policy)
        self.assertEqual(self.servers(), [ENDPOINT])
        ndes_servers.remove(ENDPOINT, used_by=lambda: (), policy_path=self.policy)
        self.assertNotIn("ndes", yaml.safe_load(self.policy.read_text()))
        self.assertIsNone(load_policy(self.policy, require_secure=False).ndes)

    def test_the_profiles_using_a_server_are_read_from_their_records(self) -> None:
        records = self.root / "ndes-profiles"
        records.mkdir()
        (records / "internal-ca.json").write_text(
            f'{{"profile_id": "internal-ca", "endpoint": "{ENDPOINT}"}}'
        )
        (records / "other.json").write_text(f'{{"profile_id": "other", "endpoint": "{OTHER}"}}')
        self.assertEqual(ndes_servers.profiles_using(records, ENDPOINT), ("internal-ca",))

    def test_the_profiles_using_a_server_are_asked_under_the_lock(self) -> None:
        self.add()
        held = []

        def used_by() -> tuple[str, ...]:
            handle = os.open(self.lock, os.O_RDWR)
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                held.append(False)
            except BlockingIOError:
                held.append(True)
            finally:
                os.close(handle)
            return ()

        ndes_servers.remove(ENDPOINT, used_by=used_by, policy_path=self.policy)
        self.assertEqual(held, [True])

    def test_two_processes_adding_servers_at_once_keep_both(self) -> None:
        # Review 2026-10-28, F05: the command and the web's helper are two
        # processes. The first reads the policy and waits for the second to
        # read it too; the second writes only after the first has. Without the
        # lock both read the same file and the second write loses the first
        # server; with it the second cannot read until the first has written.
        context = multiprocessing.get_context("fork")
        first_read, second_read, first_written = (context.Event() for _ in range(3))
        real_load, real_write = safe_yaml.load, ndes_servers._write_policy

        def first() -> None:
            def load(text: str) -> Any:
                first_read.set()
                second_read.wait(2)
                return real_load(text)

            def write(policy_path: Path, text: str) -> None:
                real_write(policy_path, text)
                first_written.set()

            with (
                mock.patch.object(safe_yaml, "load", load),
                mock.patch.object(ndes_servers, "_write_policy", write),
            ):
                self.add(ENDPOINT)

        def second() -> None:
            def load(text: str) -> Any:
                second_read.set()
                first_written.wait(10)
                return real_load(text)

            with mock.patch.object(safe_yaml, "load", load):
                self.add(OTHER)

        def run(work: Any) -> None:
            status = 1
            try:
                work()
                status = 0
            finally:
                os._exit(status)

        one = context.Process(target=run, args=(first,))
        one.start()
        self.assertTrue(first_read.wait(30))
        two = context.Process(target=run, args=(second,))
        two.start()
        one.join(30)
        two.join(30)
        self.assertEqual((one.exitcode, two.exitcode), (0, 0))
        self.assertEqual(sorted(self.servers()), sorted([ENDPOINT, OTHER]))


if __name__ == "__main__":
    unittest.main()


class TheHelperAndTheCommand(unittest.TestCase):
    """The web's socket and the operator's command: one module, one contract (CLI parity)."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.policy = self.root / "runtime-policy.yaml"
        self.policy.write_text(POLICY.format(root=self.root))
        self.answer = Answer(self.root)
        self.issuing = self.answer.sha256(self.answer.pki.intermediate)
        self.chain = [self.issuing, self.answer.sha256(self.answer.pki.root)]
        for patch in (
            mock.patch.object(
                ndes_server_helper,
                "load_policy",
                side_effect=lambda path: load_policy(path, require_secure=False),
            ),
            mock.patch.object(ndes_servers, "CA_DIRECTORY", self.root / "ndes-ca"),
            mock.patch.object(ndes_servers, "LOCK_PATH", self.root / "ndes-policy.lock"),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def ask(self, **parameters: object) -> tuple[int, dict[str, Any]]:
        request = {
            "schema_version": 1,
            "operation": "ndes_server",
            "cluster": None,
            "request_id": str(uuid.uuid4()),
            "parameters": parameters,
        }
        out, err = io.StringIO(), io.StringIO()
        code = ndes_server_helper.main(
            [],
            input_stream=io.BytesIO(json.dumps(request).encode() + b"\n"),
            output_stream=out,
            error_stream=err,
            policy_path=self.policy,
            fetch=self.answer,
            require_root=False,
        )
        return code, assert_contract("haprion-ndes-server", out.getvalue())

    def test_fetch_shows_the_cas_and_add_confirms_one(self) -> None:
        code, fetched = self.ask(action="fetch", endpoint=ENDPOINT)
        self.assertEqual(code, 0)
        self.assertFalse(fetched["result"]["confirmed"])
        self.assertEqual(fetched["result"]["authorities"][0]["sha256"], self.issuing)

        code, added = self.ask(action="add", endpoint=ENDPOINT, sha256=self.chain)
        self.assertEqual((code, added["outcome"]), (0, "done"))
        _code, again = self.ask(action="fetch", endpoint=ENDPOINT)
        self.assertTrue(again["result"]["confirmed"])

    def test_a_changed_ca_and_a_bad_action_are_refused_by_the_contract(self) -> None:
        code, refused = self.ask(action="add", endpoint=ENDPOINT, sha256=["0" * 64])
        self.assertEqual(code, exit_codes.REFUSED)
        self.assertEqual(refused["error"]["code"], "changed")
        code, refused = self.ask(action="add", endpoint=ENDPOINT, sha256=self.issuing)
        self.assertEqual((code, refused["error"]["code"]), (exit_codes.REFUSED, "bad_input"))
        code, refused = self.ask(action="drop", endpoint=ENDPOINT)
        self.assertEqual((code, refused["error"]["code"]), (exit_codes.REFUSED, "bad_input"))

    def command(self, *argv: str, root: bool = True) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("os.geteuid", return_value=0 if root else 1000):
            code = ndes_server.main(
                list(argv),
                stream_out=out,
                stream_err=err,
                fetch=self.answer,
                policy_path=self.policy,
            )
        return code, out.getvalue() + err.getvalue()

    def test_the_command_shows_without_changing_and_confirms_only_as_root(self) -> None:
        before = self.policy.read_text()
        code, said = self.command("add", ENDPOINT, root=False)
        self.assertEqual(code, 0)
        self.assertIn(f"SHA-256  {self.issuing}", said)
        self.assertIn("Nothing was changed", said)
        confirm = " ".join(f"--sha256 {each}" for each in self.chain)
        self.assertIn(f"add {ENDPOINT} {confirm}", said)
        self.assertEqual(self.policy.read_text(), before)

        code, said = self.command("add", ENDPOINT, *confirm.split(), root=False)
        self.assertEqual(code, exit_codes.NOT_ROOT)
        code, said = self.command("add", ENDPOINT, "--sha256", self.issuing)
        self.assertEqual(code, exit_codes.REFUSED, said)
        code, said = self.command(
            "add", ENDPOINT, *confirm.upper().replace("--SHA256", "--sha256").split()
        )
        self.assertEqual(code, 0, said)
        code, said = self.command("list")
        self.assertIn(ENDPOINT, said)
        code, said = self.command("remove", ENDPOINT)
        self.assertEqual(code, 0, said)
        self.assertIn("No NDES server", self.command("list")[1])

    def test_the_command_answers_in_the_helper_s_contract(self) -> None:
        code, said = self.command("add", ENDPOINT, "--json", root=False)
        self.assertEqual(code, 0)
        document = assert_contract("haprion-ndes-server", said)
        self.assertEqual(document["result"]["authorities"][0]["sha256"], self.issuing)
        code, said = self.command("remove", ENDPOINT, "--json", root=False)
        self.assertEqual(code, exit_codes.NOT_ROOT)
        self.assertEqual(assert_contract("haprion-ndes-server", said)["error"]["code"], "not_root")
