"""Registering a receiver: the four layers, and what happens when one of them refuses.

The tests run as an ordinary user. What would be root's is patched to the
test's own uid and gid the way `test_cert_publish` patches the publisher, and
`useradd`, `sshd -t`, `nginx -t` and `systemctl` are a fake runner that
records what it was asked - so the modes, the ownership, the file contents and
the order of the layers are all checked, and only the numbers and the
privilege differ from an installation.

What is deliberately not proved here is that sshd accepts the key or that the
host fetches: that is the evidence in the design's §8, on a machine, and it
needs root and a second host.
"""

from __future__ import annotations

import dataclasses
import grp
import json
import os
import pwd
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any, ClassVar
from unittest import mock

import yaml

from haprion import cert_receiver, cert_registry, exit_codes
from haprion.cert_receiver import Locations, ReceiverError, Result, Tools
from haprion.cli import cert_receiver as command
from haprion.config import PathPolicy, RuntimeConfig, load_policy, load_runtime_config
from tests.contract_schema import assert_contract
from tests.test_cert_publish import ME, Fixture, issue

KEEPER = {"keeper.example": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
#
# A public key of the right shape and deliberately too short to be one: the
# repository's own secret scanner refuses key material by shape, and a test
# fixture that had to be exempted would be the beginning of an exemption list.
#
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB5s root@lb-01.example.net"


class Runner:
    """Every command this module would run, recorded rather than run."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.failures: dict[str, tuple[int, str]] = {}
        # What `useradd --home-dir` was told, so `Tools.home` answers as the
        # system would once the account exists.
        self.homes: dict[str, Path] = {}

    def __call__(self, argv: Sequence[str]) -> tuple[int, str]:
        self.calls.append(tuple(argv))
        for fragment, answer in self.failures.items():
            if fragment in " ".join(argv):
                return answer
        if argv[0].endswith("useradd"):
            self.homes[argv[-1]] = Path(argv[argv.index("--home-dir") + 1])
        if argv[0].endswith("userdel"):
            self.homes.pop(argv[-1], None)
        return 0, ""

    def ran(self, fragment: str) -> bool:
        return any(fragment in " ".join(call) for call in self.calls)


class ReceiverFixture(Fixture):
    def setUp(self) -> None:
        super().setUp()
        for name, value in (("ROOT_UID", os.getuid()), ("ROOT_GID", os.getgid())):
            patcher = mock.patch.object(cert_receiver, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        #
        # nginx's group, which owns the receivers' secrets, is the test's own:
        # a test that is not root can give a file to no one else.
        #
        group = mock.patch.object(grp, "getgrnam", lambda _name: mock.Mock(gr_gid=os.getgid()))
        group.start()
        self.addCleanup(group.stop)
        self.runner = Runner()
        self.etc = self.root / "etc"
        (self.etc / "nginx" / "sites-enabled").mkdir(parents=True)
        (self.etc / "haprion").mkdir(parents=True)
        (self.etc / "haprion" / "ui-tls.conf").write_text(
            "TLS_CERT=/etc/haprion/tls/ui.crt\n"
            "TLS_KEY=/etc/haprion/tls/ui.key\n"
            "SERVER_NAME=mgr.example.net\n",
            encoding="utf-8",
        )
        self.locations = Locations(
            sshd_dropin=self.etc / "ssh" / "sshd_config.d" / "haprion-receivers.conf",
            nginx_snippet=self.etc / "nginx" / "snippets" / "haprion-receivers.conf",
            ui_site=self.etc / "nginx" / "sites-available" / "haprion",
            ui_tls=self.etc / "haprion" / "ui-tls.conf",
            receiver_secrets=self.etc / "nginx" / "haprion-receivers",
        )
        # The interface's site as 05-platform-nginx renders it: with the line
        # that makes the snippet reachable at all.
        self.locations.ui_site.parent.mkdir(parents=True, exist_ok=True)
        self.locations.ui_site.write_text(
            "server {\n    listen 443 ssl;\n"
            f"    include {self.locations.nginx_snippet};\n"
            "    location / { proxy_pass http://127.0.0.1:8080; }\n}\n",
            encoding="utf-8",
        )
        self.key_file = self.root / "receiver.pub"
        self.key_file.write_text(KEY + "\n", encoding="ascii")
        #
        # Every name in these tests resolves to one address, so the lock is
        # written without asking the network anything.
        #
        #
        # An account this run created answers with the home it was given; the
        # test's own account (a `legacy` receiver's) answers with a separate
        # home under the fixture, as the old shared account has on a machine.
        #
        self.tools = Tools(
            run=self.runner,
            forward=lambda name: ("192.0.2.10",),
            home=lambda owner: self.runner.homes.get(owner, self.root / "home" / owner),
        )
        self.policy_path = self.write_config(dict(KEEPER))
        #
        # The publisher's fixture always registers `lb-01` to the test's own
        # account. These tests register their own receivers, and an account
        # that already fetches for one is a refusal they mean to control.
        #
        registry_file = self.root / "certificates.yaml"
        document = yaml.safe_load(registry_file.read_text())
        document["receivers"] = {}
        registry_file.write_text(yaml.safe_dump(document), encoding="utf-8")
        registry_file.chmod(0o640)
        issue(self.live / "keeper.example", "keeper.example")

    def loaded(self) -> tuple[PathPolicy, RuntimeConfig]:
        policy = load_policy(self.policy_path, require_secure=False)
        return policy, load_runtime_config(policy, require_secure=False)

    def add(self, receiver_id: str = "lb-02.example.net", **options: Any) -> Result:
        policy, runtime = self.loaded()
        arguments: dict[str, Any] = {
            "transport": "rsync",
            "public_key": self.key_file,
            "owner": ME,
            **options,
        }
        if arguments["transport"] == "https":
            arguments.setdefault("hashed_secret", cert_receiver.secret_hash("receiver password"))
        return cert_receiver.add(
            policy,
            runtime,
            receiver_id=receiver_id,
            tools=self.tools,
            locations=self.locations,
            require_secure=False,
            lock_path=self.root / "cert-publish.lock",
            **arguments,
        )

    def registered(self) -> dict[str, Any]:
        document: dict[str, Any] = yaml.safe_load((self.root / "certificates.yaml").read_text())
        return dict(document["receivers"])

    def keys_file(self, receiver_id: str = "lb-02.example.net") -> Path:
        """The lock, inside the receiver's own directory (B160)."""

        return self.root / "receivers" / receiver_id / ".ssh" / "authorized_keys"


class AddingAReceiver(ReceiverFixture):
    def test_rsync_gets_a_directory_a_locked_key_and_an_entry(self) -> None:
        result = self.add()

        self.assertEqual(
            [layer.name for layer in result.layers], ["account", "directory", "lock", "registry"]
        )
        directory = self.root / "receivers" / "lb-02.example.net"
        self.assertTrue(directory.is_dir())
        self.assertEqual(directory.stat().st_mode & 0o777, 0o750)
        self.assertEqual(directory.stat().st_gid, pwd.getpwnam(ME).pw_gid)
        # One directory per receiver: the lock sits in a root-owned `.ssh`
        # inside the directory the receiver fetches from (B160).
        self.assertEqual((directory / ".ssh").stat().st_mode & 0o777, 0o755)

        line = self.keys_file().read_text(encoding="ascii").splitlines()[-1]
        # The lock names the host and its address both: sshd matches `from=`
        # against the address unless `UseDNS yes` is set, and against the name
        # only then, so a lock naming the host alone would refuse it.
        self.assertTrue(line.startswith('restrict,from="lb-02.example.net,192.0.2.10",command="'))
        self.assertIn(f"/usr/bin/rrsync -ro {directory}", line)
        self.assertTrue(line.endswith(KEY))
        self.assertEqual(self.keys_file().stat().st_mode & 0o777, 0o644)

        entry = self.registered()["lb-02.example.net"]
        self.assertEqual(entry["transport"], "rsync")
        self.assertEqual(entry["layout"], "per-certificate")
        self.assertEqual(entry["path"], str(directory))
        self.assertNotIn("allow", entry)
        self.assertFalse(self.runner.ran("sshd"))

    def test_a_new_rsync_account_gets_a_shell_for_its_forced_command(self) -> None:
        with (
            mock.patch.object(cert_receiver, "account_exists", return_value=False),
            mock.patch.object(cert_receiver, "_own"),
        ):
            self.add(owner="crx-lb-02")

        directory = self.root / "receivers" / "lb-02.example.net"
        self.assertIn(
            (
                "/usr/sbin/useradd",
                "--system",
                "--home-dir",
                str(directory),
                "--shell",
                "/bin/sh",
                "crx-lb-02",
            ),
            self.runner.calls,
        )
        self.assertEqual(self.runner.homes["crx-lb-02"], directory)

    def test_a_new_sftp_account_keeps_nologin(self) -> None:
        with (
            mock.patch.object(cert_receiver, "account_exists", return_value=False),
            mock.patch.object(cert_receiver, "_own"),
        ):
            self.add(owner="crx-lb-02", transport="sftp")

        directory = self.root / "receivers" / "lb-02.example.net"
        self.assertIn(
            (
                "/usr/sbin/useradd",
                "--system",
                "--home-dir",
                str(directory),
                "--shell",
                "/usr/sbin/nologin",
                "crx-lb-02",
            ),
            self.runner.calls,
        )

    def test_sftp_also_writes_a_chrooted_match_block_sshd_accepted(self) -> None:
        result = self.add(transport="sftp")

        block = self.locations.sshd_dropin.read_text(encoding="utf-8")
        self.assertIn(f"Match User {ME}", block)
        self.assertIn(f"ChrootDirectory {self.root / 'receivers' / 'lb-02.example.net'}", block)
        self.assertIn("ForceCommand internal-sftp -R", block)
        self.assertTrue(self.runner.ran("/usr/sbin/sshd -t"))
        self.assertTrue(self.runner.ran("systemctl reload ssh"))
        # No forced command: the chroot and the read-only flag are the lock.
        self.assertNotIn("command=", self.keys_file().read_text(encoding="ascii"))
        self.assertEqual(self.registered()["lb-02.example.net"]["transport"], "sftp")
        self.assertEqual(result.action, "added")

    def test_an_address_id_is_its_own_lock(self) -> None:
        # An address is what sshd compares against directly, so it stands
        # alone in `from=` and no lookup is asked for.
        def refuse(name: str) -> tuple[str, ...]:
            raise AssertionError(f"looked up {name}")

        self.tools = dataclasses.replace(self.tools, forward=refuse)
        self.add(receiver_id="192.0.2.40", transport="sftp")

        line = self.keys_file("192.0.2.40").read_text(encoding="ascii").splitlines()[-1]
        self.assertTrue(line.startswith('restrict,from="192.0.2.40" '))

    def test_a_name_with_several_addresses_locks_to_all_of_them(self) -> None:
        self.tools = dataclasses.replace(
            self.tools, forward=lambda name: ("192.0.2.10", "2001:db8::10")
        )
        self.add(transport="sftp")

        line = self.keys_file().read_text(encoding="ascii").splitlines()[-1]
        self.assertTrue(
            line.startswith('restrict,from="lb-02.example.net,192.0.2.10,2001:db8::10" ')
        )

    def test_https_gets_a_whitelisted_location_and_no_key_at_all(self) -> None:
        # www-data's directory cannot be chowned by a test that is not root.
        with mock.patch.object(cert_receiver, "_own"):
            result = self.add(
                transport="https",
                public_key=None,
                owner=None,
                allow=["192.0.2.0/24", "198.51.100.7"],
            )

        snippet = self.locations.nginx_snippet.read_text(encoding="utf-8")
        # Locations only: the server block - port, certificate, name - is the
        # interface's, and this file is what its include line pulls in.
        self.assertNotIn("server {", snippet)
        self.assertNotIn("listen", snippet)
        self.assertIn("location /certdist/lb-02.example.net/ {", snippet)
        self.assertIn(f"alias {self.root / 'receivers' / 'lb-02.example.net'}/;", snippet)
        self.assertIn("allow 192.0.2.0/24;", snippet)
        self.assertIn("allow 198.51.100.7;", snippet)
        self.assertIn("deny all;", snippet)
        self.assertTrue(self.runner.ran("/usr/sbin/nginx -t"))
        self.assertTrue(self.runner.ran("systemctl reload nginx"))
        self.assertFalse(self.keys_file().exists())
        self.assertEqual(self.registered()["lb-02.example.net"]["owner"], "www-data")
        self.assertTrue(
            any(
                line.startswith("url: https://mgr.example.net/certdist/lb-02.example.net/")
                for line in result.instructions
            ),
            result.instructions,
        )

    def test_https_is_refused_while_the_interface_does_not_include_the_snippet(self) -> None:
        self.locations.ui_site.write_text(
            "server {\n    listen 443 ssl;\n    location / { }\n}\n", encoding="utf-8"
        )

        with (
            mock.patch.object(cert_receiver, "_own"),
            self.assertRaises(ReceiverError) as caught,
        ):
            self.add(transport="https", public_key=None, owner=None, allow=["192.0.2.0/24"])

        self.assertEqual(caught.exception.code, "dependency_unavailable")
        self.assertIn("05-platform-nginx", str(caught.exception))
        self.assertFalse(self.locations.nginx_snippet.exists())
        self.assertNotIn("lb-02.example.net", self.registered())

    def test_an_allow_entry_that_is_not_an_address_is_refused_before_nginx_is_touched(
        self,
    ) -> None:
        #
        # `allow all;` is valid nginx. Until the review of 2026-09-20 the
        # registry loader was the first thing to judge the entry, and by then
        # the snippet had been written, tested and reloaded; the undo put the
        # file back without a reload. Now the loader's rule runs first.
        #
        for bad in (["all"], ["192.0.2.1/24"], ["192.0.2.9", "192.0.2.9"]):
            with self.subTest(allow=bad):
                self.runner.calls.clear()
                with (
                    mock.patch.object(cert_receiver, "_own"),
                    self.assertRaises(ReceiverError) as caught,
                ):
                    self.add(transport="https", public_key=None, owner=None, allow=bad)
                self.assertEqual(caught.exception.code, "bad_input")
                self.assertIn("--allow", str(caught.exception))
                self.assertFalse(self.runner.ran("/usr/sbin/nginx -t"))
                self.assertFalse(self.runner.ran("systemctl reload nginx"))
                self.assertFalse(self.locations.nginx_snippet.exists())
                self.assertFalse((self.root / "receivers" / "lb-02.example.net").exists())
                self.assertNotIn("lb-02.example.net", self.registered())

    def test_a_refused_registration_reloads_the_service_it_had_reloaded(self) -> None:
        #
        # The registry can still refuse after nginx or sshd has taken the
        # candidate - here, the registry file is made unwritable - and then
        # the service must run the restored configuration, not the refused
        # one. One reload for the candidate, one for the restore.
        #
        registry_file = self.root / "certificates.yaml"
        with (
            mock.patch.object(cert_receiver, "_own"),
            mock.patch.object(
                cert_registry, "set_receiver", side_effect=OSError("registry is read-only")
            ),
            self.assertRaises(ReceiverError),
        ):
            self.add(transport="https", public_key=None, owner=None, allow=["192.0.2.0/24"])
        reloads = [call for call in self.runner.calls if "reload nginx" in " ".join(call)]
        self.assertEqual(len(reloads), 2, self.runner.calls)
        self.assertFalse(self.locations.nginx_snippet.exists())
        self.assertTrue(registry_file.exists())

    def test_what_could_not_be_undone_is_named_and_the_rest_is_still_undone(self) -> None:
        """Review 2026-10-22, 4-12: each undo step ran under `suppress(Exception)`."""

        with (
            mock.patch.object(cert_receiver, "_own"),
            mock.patch.object(
                cert_registry, "set_receiver", side_effect=OSError("registry is read-only")
            ),
            mock.patch.object(
                cert_receiver, "_restore", side_effect=RuntimeError("nginx did not reload")
            ),
            self.assertRaises(ReceiverError) as caught,
        ):
            self.add(transport="https", public_key=None, owner=None, allow=["192.0.2.0/24"])

        left = (caught.exception.details or {}).get("not_undone") or []
        self.assertEqual(len(left), 1, left)
        self.assertIn("nginx snippet", left[0])
        self.assertIn("nginx did not reload", left[0])
        self.assertEqual(caught.exception.code, "write_failed")
        self.assertIn("not undone: nginx snippet", str(caught.exception))
        self.assertFalse(cert_receiver.secret_file("lb-02.example.net", self.locations).exists())

    def test_the_instructions_name_what_the_receiver_needs(self) -> None:
        result = self.add()

        self.assertTrue(any("rsync" in line for line in result.instructions))
        self.assertTrue(
            any(
                "bound to lb-02.example.net and its addresses" in line
                for line in result.instructions
            )
        )


class TheKeyAsText(ReceiverFixture):
    """B142: the interface pastes the `.pub` line; the same shape rules apply."""

    def test_the_pasted_line_is_written_as_the_lock(self) -> None:
        with (
            mock.patch.object(cert_receiver, "account_exists", return_value=False),
            mock.patch.object(cert_receiver, "_own"),
        ):
            self.add(public_key=KEY + "\n", owner=None)

        lock = self.keys_file().read_text(encoding="ascii")
        self.assertIn(KEY, lock)
        self.assertEqual(self.registered()["lb-02.example.net"]["owner"], "crx-lb-02-example-net")

    def test_two_pasted_lines_are_refused(self) -> None:
        with self.assertRaises(ReceiverError) as caught:
            self.add(public_key=f"{KEY}\n{KEY}\n")
        self.assertEqual(caught.exception.code, "bad_input")
        self.assertIn("2 keys", str(caught.exception))
        self.assertEqual(self.registered(), {})

    def test_a_private_key_pasted_by_mistake_is_refused(self) -> None:
        with self.assertRaises(ReceiverError) as caught:
            # The header a private key file starts with, assembled so the
            # repository's own secret scanner does not read the test as one.
            header = "-----BEGIN " + "OPENSSH PRIVATE" + " KEY-----"
            self.add(public_key=f"{header}\nabc\n-----END\n")
        self.assertEqual(caught.exception.code, "bad_input")

    def test_a_non_ascii_paste_is_refused(self) -> None:
        with self.assertRaises(ReceiverError) as caught:
            self.add(public_key=KEY.replace("root", "rööt"))
        self.assertIn("ASCII", str(caught.exception))


class WhatRegistrationRefuses(ReceiverFixture):
    def refusal(self, **options: Any) -> ReceiverError:
        with self.assertRaises(ReceiverError) as caught:
            self.add(**options)
        return caught.exception

    def test_an_id_that_is_not_a_host(self) -> None:
        self.assertEqual(self.refusal(receiver_id="pve-cluster").code, "bad_input")

    def test_a_name_that_does_not_resolve(self) -> None:
        self.tools = dataclasses.replace(self.tools, forward=lambda name: ())
        error = self.refusal()
        self.assertEqual(error.code, "receiver_unresolvable")
        self.assertIn("does not resolve", str(error))

    def test_a_second_registration_of_the_same_id(self) -> None:
        self.add()
        self.assertEqual(self.refusal().code, "already_exists")

    def test_https_without_a_whitelist_and_a_whitelist_without_https(self) -> None:
        self.assertEqual(
            self.refusal(transport="https", public_key=None, owner=None).code, "bad_input"
        )
        self.assertEqual(self.refusal(allow=["192.0.2.1"]).code, "bad_input")

    def test_a_key_file_holding_more_than_one_key(self) -> None:
        self.key_file.write_text(KEY + "\n" + KEY + "\n", encoding="ascii")
        error = self.refusal()
        self.assertEqual(error.code, "bad_input")
        self.assertIn("exactly one", str(error))

    def test_a_private_key_where_the_public_one_belongs(self) -> None:
        self.key_file.write_text("-----" + "BEGIN OPENSSH PRIVATE KEY-----\n", encoding="ascii")
        self.assertEqual(self.refusal().code, "bad_input")

    def test_an_account_that_already_fetches_for_another_receiver(self) -> None:
        self.add()
        error = self.refusal(receiver_id="lb-03.example.net")
        self.assertEqual(error.code, "already_exists")
        self.assertIn("One account per receiver", str(error))


class WhenALayerRefuses(ReceiverFixture):
    """The property that makes `add` safe to run again: it leaves nothing behind."""

    def test_an_sshd_that_will_not_take_the_block_takes_nothing_with_it(self) -> None:
        self.locations.sshd_dropin.parent.mkdir(parents=True)
        self.locations.sshd_dropin.write_text("# nothing yet\n", encoding="utf-8")
        self.runner.failures["sshd -t"] = (1, "bad configuration directive")

        with self.assertRaises(ReceiverError) as caught:
            self.add(transport="sftp")

        self.assertEqual(caught.exception.code, "config_refused")
        self.assertEqual(self.locations.sshd_dropin.read_text(encoding="utf-8"), "# nothing yet\n")
        self.assertNotIn("lb-02.example.net", self.registered())
        self.assertFalse((self.root / "receivers" / "lb-02.example.net").exists())
        self.assertFalse(self.keys_file().exists())

    def test_an_nginx_that_will_not_reload_leaves_no_entry(self) -> None:
        self.runner.failures["nginx -t"] = (1, "unknown directive")

        with self.assertRaises(ReceiverError):
            self.add(transport="https", public_key=None, owner=None, allow=["192.0.2.0/24"])

        self.assertNotIn("lb-02.example.net", self.registered())
        self.assertFalse(self.locations.nginx_snippet.exists())


class AnHttpsReceiversSecret(ReceiverFixture):
    """B306 (security review S03): an address list alone let any host on an
    allowed network fetch private keys. Both locks now, and only the hash here."""

    HTTPS: ClassVar[dict[str, Any]] = {
        "transport": "https",
        "public_key": None,
        "owner": None,
        "allow": ["192.0.2.0/24"],
    }

    def secret(self, receiver_id: str = "lb-02.example.net") -> Path:
        return self.locations.receiver_secrets / f"{receiver_id}.htpasswd"

    def test_the_location_asks_for_both_and_the_file_holds_only_the_hash(self) -> None:
        hashed = cert_receiver.secret_hash("receiver password")
        with mock.patch.object(cert_receiver, "_own"):
            self.add(**self.HTTPS, hashed_secret=hashed)

        snippet = self.locations.nginx_snippet.read_text(encoding="utf-8")
        self.assertIn("    satisfy all;", snippet)
        self.assertIn("    deny all;", snippet)
        self.assertIn(f"    auth_basic_user_file {self.secret()};", snippet)
        self.assertEqual(self.secret().read_text(), f"lb-02.example.net:{hashed}\n")
        self.assertEqual(self.secret().stat().st_mode & 0o777, 0o640)
        self.assertNotIn("receiver password", self.secret().read_text())

    def test_the_hash_is_the_form_nginx_checks(self) -> None:
        """yescrypt, checked by the same crypt(3) nginx calls (CodeQL: no fast hash)."""

        hashed = cert_receiver.secret_hash("receiver password")
        self.assertRegex(hashed, cert_receiver.SECRET_HASH)
        self.assertEqual(cert_receiver.crypt("receiver password", hashed), hashed)
        self.assertNotEqual(cert_receiver.crypt("not the password", hashed), hashed)
        self.assertNotEqual(cert_receiver.secret_hash("receiver password"), hashed)
        with self.assertRaises(cert_receiver.ReceiverError):
            cert_receiver.crypt("receiver password", "$unknown$")
        self.assertRegex(cert_receiver.new_secret(), r"^[A-Za-z0-9_-]{32}$")

    def test_https_without_a_secret_and_a_secret_without_https_are_refused(self) -> None:
        with mock.patch.object(cert_receiver, "_own"), self.assertRaises(ReceiverError) as no:
            self.add(**self.HTTPS, hashed_secret="not a hash")  # noqa: S106 - a refusal
        self.assertEqual(no.exception.code, "bad_input")
        with self.assertRaises(ReceiverError) as wrong:
            self.add(hashed_secret=cert_receiver.secret_hash("x"))
        self.assertEqual(wrong.exception.code, "bad_input")
        self.assertFalse(self.secret().exists())

    def test_a_new_secret_replaces_the_old_and_a_refusal_puts_it_back(self) -> None:
        with mock.patch.object(cert_receiver, "_own"):
            self.add(**self.HTTPS)
        old = self.secret().read_text()
        _, runtime = self.loaded()
        newer = cert_receiver.secret_hash("another password")
        result = cert_receiver.set_secret(
            runtime,
            receiver_id="lb-02.example.net",
            hashed_secret=newer,
            tools=self.tools,
            locations=self.locations,
        )
        self.assertEqual(result.action, "secret")
        self.assertIn(newer, self.secret().read_text())

        self.runner.failures["nginx -t"] = (1, "unknown directive")
        with self.assertRaises(ReceiverError):
            cert_receiver.set_secret(
                runtime,
                receiver_id="lb-02.example.net",
                hashed_secret=cert_receiver.secret_hash("third"),
                tools=self.tools,
                locations=self.locations,
            )
        self.assertIn(newer, self.secret().read_text())
        self.assertNotEqual(old, self.secret().read_text())

    def test_removing_the_receiver_removes_its_secret(self) -> None:
        with mock.patch.object(cert_receiver, "_own"):
            self.add(**self.HTTPS)
        policy, runtime = self.loaded()
        with mock.patch.object(cert_receiver, "_remove_directory", return_value=None):
            cert_receiver.remove(
                policy,
                runtime,
                receiver_id="lb-02.example.net",
                tools=self.tools,
                locations=self.locations,
                require_secure=False,
                lock_path=self.root / "cert-publish.lock",
            )
        self.assertFalse(self.secret().exists())


NEW_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB6t root@lb-02.example.net"


class AReceiversNewKey(ReceiverFixture):
    """26-10-18: a host installed again keeps its receiver and gets a new key."""

    def replace(self, key: str = NEW_KEY, receiver_id: str = "lb-02.example.net") -> Result:
        _, runtime = self.loaded()
        return cert_receiver.set_key(
            runtime, receiver_id=receiver_id, public_key=key + "\n", tools=self.tools
        )

    def test_only_the_key_changes_and_the_lock_stays_where_it_was(self) -> None:
        self.add()
        before = self.keys_file().read_text(encoding="ascii").splitlines()[-1]
        #
        # The name has moved since it was registered: the lock is not worked
        # out again, so the address it was issued for is the one it keeps.
        #
        self.tools = dataclasses.replace(self.tools, forward=lambda name: ("198.51.100.99",))

        result = self.replace()

        after = self.keys_file().read_text(encoding="ascii").splitlines()[-1]
        self.assertEqual(
            (result.action, [layer.state for layer in result.layers]), ("key", ["created"])
        )
        self.assertEqual(after, before.replace(KEY, NEW_KEY))
        self.assertIn('from="lb-02.example.net,192.0.2.10"', after)
        self.assertNotIn(KEY, self.keys_file().read_text(encoding="ascii"))
        self.assertEqual(self.keys_file().stat().st_mode & 0o777, 0o644)
        self.assertEqual(list(self.keys_file().parent.glob(".authorized_keys.*")), [])
        self.assertEqual(self.registered()["lb-02.example.net"]["transport"], "rsync")

    def test_an_sftp_receiver_keeps_its_lock_without_a_command(self) -> None:
        with mock.patch.object(cert_receiver, "_own"):
            self.add(transport="sftp")

        self.replace()

        line = self.keys_file().read_text(encoding="ascii").splitlines()[-1]
        self.assertEqual(line, f'restrict,from="lb-02.example.net,192.0.2.10" {NEW_KEY}')

    def test_the_same_key_again_changes_nothing(self) -> None:
        self.add()
        written = self.keys_file().stat().st_mtime_ns

        result = self.replace(KEY)

        self.assertEqual([layer.state for layer in result.layers], ["kept"])
        self.assertEqual(self.keys_file().stat().st_mtime_ns, written)

    def test_https_and_an_unknown_receiver_are_refused(self) -> None:
        with mock.patch.object(cert_receiver, "_own"):
            self.add(transport="https", allow=["192.0.2.0/24"], public_key=None)
        with self.assertRaises(ReceiverError) as https:
            self.replace()
        with self.assertRaises(ReceiverError) as unknown:
            self.replace(receiver_id="lb-09.example.net")

        self.assertEqual(
            (https.exception.code, unknown.exception.code), ("bad_input", "unknown_receiver")
        )

    def test_a_lock_that_is_not_the_one_written_is_refused_and_left(self) -> None:
        self.add()
        self.keys_file().write_text(f"{KEY}\n", encoding="ascii")

        with self.assertRaises(ReceiverError) as caught:
            self.replace()

        self.assertIn("register it again", str(caught.exception))
        self.assertEqual(self.keys_file().read_text(encoding="ascii"), f"{KEY}\n")

    def test_a_write_that_fails_leaves_the_old_key_working(self) -> None:
        self.add()
        before = self.keys_file().read_text(encoding="ascii")

        with (
            mock.patch("os.replace", side_effect=OSError("disk full")),
            self.assertRaises(ReceiverError) as caught,
        ):
            self.replace()

        self.assertEqual(caught.exception.code, "write_failed")
        self.assertEqual(self.keys_file().read_text(encoding="ascii"), before)
        self.assertEqual(list(self.keys_file().parent.glob(".authorized_keys.*")), [])

    def test_a_pasted_private_key_is_refused(self) -> None:
        self.add()
        header = "-----BEGIN " + "OPENSSH PRIVATE" + " KEY-----"

        with self.assertRaises(ReceiverError) as caught:
            self.replace(f"{header}\nabc\n-----END")

        self.assertEqual(caught.exception.code, "bad_input")


class RemovingAReceiver(ReceiverFixture):
    def remove(self, receiver_id: str = "lb-02.example.net") -> Result:
        policy, runtime = self.loaded()
        return cert_receiver.remove(
            policy,
            runtime,
            receiver_id=receiver_id,
            tools=self.tools,
            locations=self.locations,
            require_secure=False,
            lock_path=self.root / "cert-publish.lock",
        )

    def test_a_receiver_a_certificate_still_names_is_refused(self) -> None:
        self.add()
        document = yaml.safe_load((self.root / "certificates.yaml").read_text())
        document["certificates"]["keeper.example"]["receivers"] = ["lb-02.example.net"]
        (self.root / "certificates.yaml").write_text(yaml.safe_dump(document), encoding="utf-8")

        with self.assertRaises(ReceiverError) as caught:
            self.remove()

        self.assertEqual(caught.exception.code, "receiver_in_use")
        self.assertIn("keeper.example", str(caught.exception))
        self.assertIn("lb-02.example.net", self.registered())

    def test_every_layer_goes_and_the_block_is_written_without_it(self) -> None:
        self.add(transport="sftp")
        directory = self.root / "receivers" / "lb-02.example.net"

        result = self.remove()

        self.assertEqual(result.action, "removed")
        self.assertNotIn("lb-02.example.net", self.registered())
        self.assertFalse(directory.exists())
        self.assertFalse(self.keys_file().exists())
        self.assertNotIn(
            "lb-02.example.net", self.locations.sshd_dropin.read_text(encoding="utf-8")
        )
        self.assertTrue(self.runner.ran("userdel"))

    def test_a_receiver_nobody_registered(self) -> None:
        with self.assertRaises(ReceiverError) as caught:
            self.remove("nobody.example.net")

        self.assertEqual(caught.exception.code, "unknown_receiver")

    def test_a_snippet_that_cannot_be_written_keeps_the_registry_entry(self) -> None:
        """Job 776 (B163): the registry lost the receiver while nginx still served it.

        The snippet is the layer nginx reads; the registry is the layer the
        others are rebuilt from. So the registry goes last, and a write that
        fails on the way is a `write_failed` envelope with the entry intact -
        never a traceback the worker reads as an invalid document.
        """

        # www-data's directory cannot be chowned by a test that is not root.
        with mock.patch.object(cert_receiver, "_own"):
            self.add(transport="https", public_key=None, owner=None, allow=["192.0.2.0/24"])
        self.locations.nginx_snippet.chmod(0o444)
        self.locations.nginx_snippet.parent.chmod(0o555)
        self.addCleanup(self.locations.nginx_snippet.parent.chmod, 0o755)
        self.addCleanup(self.locations.nginx_snippet.chmod, 0o644)

        with self.assertRaises(ReceiverError) as caught:
            self.remove()

        self.assertEqual(caught.exception.code, "write_failed")
        self.assertIn("lb-02.example.net", self.registered())
        self.assertIn("lb-02.example.net", self.locations.nginx_snippet.read_text(encoding="utf-8"))


class Listing(ReceiverFixture):
    def rows(self) -> list[dict[str, Any]]:
        policy, runtime = self.loaded()
        return cert_receiver.listing(policy, runtime)

    def test_a_receiver_is_listed_with_its_transport_and_what_it_holds(self) -> None:
        self.add()

        by_id = {row["id"]: row for row in self.rows()}

        self.assertEqual(by_id["lb-02.example.net"]["transport"], "rsync")
        self.assertEqual(by_id["lb-02.example.net"]["layout"], "per-certificate")
        self.assertEqual(by_id["lb-02.example.net"]["certificates"], [])


class TheCommand(ReceiverFixture):
    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        import io

        out, err = io.StringIO(), io.StringIO()
        code = command.main(
            list(argv),
            policy_path=self.policy_path,
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            tools=self.tools,
            locations=self.locations,
            lock_path=self.root / "cert-publish.lock",
        )
        return code, out.getvalue(), err.getvalue()

    def test_an_https_receiver_s_password_is_printed_once_and_kept_nowhere(self) -> None:
        """B306: made by the command, shown here, and only its hash on disk."""

        with mock.patch.object(cert_receiver, "_own"):
            code, out, _ = self.run_cli(
                "add", "lb-02.example.net", "--transport", "https", "--allow", "192.0.2.0/24",
                "--show-password",
            )  # fmt: skip
        self.assertEqual(code, 0, out)
        password = re.search(r"^password: (\S+)$", out, re.MULTILINE)
        assert password is not None, out
        stored = (self.locations.receiver_secrets / "lb-02.example.net.htpasswd").read_text()
        self.assertNotIn(password.group(1), stored)
        self.assertNotIn(password.group(1), (self.root / "certificates.yaml").read_text())

        code, out, _ = self.run_cli("secret", "lb-02.example.net", "--show-password", "--json")
        self.assertEqual(code, 0, out)
        document = json.loads(out)
        self.assertEqual(document["result"]["action"], "secret")
        self.assertNotEqual(document["result"]["password"], password.group(1))
        assert_contract("haprion-cert-receiver", out)

    def test_a_new_key_from_the_pub_file_keeps_the_contract(self) -> None:
        self.add()
        new_key = self.root / "new.pub"
        new_key.write_text(NEW_KEY + "\n", encoding="ascii")

        code, out, _ = self.run_cli(
            "key", "lb-02.example.net", "--public-key", str(new_key), "--json"
        )

        self.assertEqual(code, 0, out)
        self.assertEqual(json.loads(out)["result"]["action"], "key")
        self.assertIn(NEW_KEY, self.keys_file().read_text(encoding="ascii"))
        assert_contract("haprion-cert-receiver", out)

    def test_a_new_key_without_one_is_refused(self) -> None:
        self.add()

        code, _, err = self.run_cli("key", "lb-02.example.net")

        self.assertEqual(code, 64)
        self.assertIn("--public-key", err)

    def test_a_password_is_made_only_when_it_may_be_printed(self) -> None:
        """Without --show-password nothing is made, and nothing is replaced."""

        for argv in (
            ("add", "lb-02.example.net", "--transport", "https", "--allow", "192.0.2.0/24"),
            ("secret", "lb-02.example.net", "--json"),
        ):
            with mock.patch.object(command, "set_secret") as replaced:
                code, out, err = self.run_cli(*argv)
            self.assertEqual(code, 64, err)
            self.assertIn("--show-password", err)
            self.assertNotIn('password":', out)
            replaced.assert_not_called()
        self.assertFalse(
            self.locations.receiver_secrets.joinpath("lb-02.example.net.htpasswd").exists()
        )

    def test_add_then_list_then_remove(self) -> None:
        code, out, _ = self.run_cli(
            "add",
            "lb-02.example.net",
            "--transport",
            "rsync",
            "--public-key",
            str(self.key_file),
            "--owner",
            ME,
        )
        self.assertEqual(code, 0, out)
        self.assertIn("added lb-02.example.net", out)

        code, out, _ = self.run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn("lb-02.example.net", out)
        self.assertIn("rsync", out)

        code, out, _ = self.run_cli("remove", "lb-02.example.net")
        self.assertEqual(code, 0, out)
        self.assertNotIn("lb-02.example.net", self.registered())

    def test_a_removal_that_left_the_account_is_partial(self) -> None:
        """Review 26-10-24, 13-02: the command said done when userdel had failed."""

        self.run_cli(
            "add",
            "lb-02.example.net",
            "--transport",
            "rsync",
            "--public-key",
            str(self.key_file),
            "--owner",
            ME,
        )
        self.runner.failures["userdel"] = (8, "userdel: user is currently used by process 1")

        code, out, _ = self.run_cli("remove", "lb-02.example.net", "--json")

        self.assertEqual(code, exit_codes.PARTIAL, out)
        document = assert_contract("haprion-cert-receiver", out)
        self.assertEqual(document["outcome"], "partial")
        self.assertEqual([warning["code"] for warning in document["warnings"]], ["account_failed"])
        code, out, _ = self.run_cli("list")
        self.assertNotIn("lb-02.example.net", out)

    def test_there_is_no_migrate_verb(self) -> None:
        code, out, _ = self.run_cli("migrate", "lb-02.example.net", "--finish")

        self.assertEqual(code, 64)
        self.assertIn("Usage:", out)

    def test_the_json_envelope_carries_the_layers(self) -> None:
        code, out, _ = self.run_cli(
            "add",
            "lb-02.example.net",
            "--transport",
            "rsync",
            "--public-key",
            str(self.key_file),
            "--owner",
            ME,
            "--json",
        )

        self.assertEqual(code, 0, out)
        document = json.loads(out)
        self.assertEqual(document["operation"], "cert_receiver")
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(
            [layer["layer"] for layer in document["result"]["layers"]],
            ["account", "directory", "lock", "registry"],
        )

    def test_a_refusal_is_an_envelope_too(self) -> None:
        code, out, err = self.run_cli(
            "add",
            "pve-cluster",
            "--transport",
            "rsync",
            "--public-key",
            str(self.key_file),
            "--json",
        )

        self.assertEqual(code, 64)
        self.assertIn("bad_input", err)
        self.assertEqual(json.loads(out)["error"]["code"], "bad_input")

    def test_usage_is_printed_for_an_action_that_is_not_one(self) -> None:
        code, out, _ = self.run_cli("rename", "lb-02.example.net")

        self.assertEqual(code, 64)
        self.assertIn("Usage:", out)
