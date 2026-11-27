"""The BMC targets as root keeps them: the account, the install and the sweep (B526, B536).

Real parts throughout: a registry and an exportable certificate made the way
the export tests make them, an installation key pair, and the fake BMC of
`test_bmc_redfish` over real TLS, which serves its own certificate until the
exportable one is installed on it.
"""

from __future__ import annotations

import fcntl
import functools
import os
import stat
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

from haprion import bmc_redfish, bmc_targets, cert_registry, exit_codes
from haprion.bmc_targets import Root, TargetError
from haprion.config import BmcTarget, load_registry
from haprion.dns_profile_keys import generate
from tests.test_bmc_redfish import PASSWORD, USER, FakeBmc, make_pair
from tests.test_cert_export import DEVICE, ExportableFixture

LOCAL = "127.0.0.1"


class TargetCase(ExportableFixture):
    def setUp(self) -> None:
        super().setUp()
        self.make_exportable()
        self.private, self.public = generate()
        old_cert, old_key = make_pair(self.root, "bmc-old")
        self.bmc = FakeBmc(self.root, old_cert, old_key)
        self.addCleanup(self.bmc.stop)
        self.old = bmc_redfish.pem_fingerprint(old_cert)
        self.current = bmc_redfish.pem_fingerprint(self.device.leaf.read_text())
        self.moment = datetime(2026, 11, 26, 3, 0, tzinfo=UTC)
        self.set_target(self.old)
        bmc_targets.write_account(
            DEVICE,
            self.public.key_id,
            self.sealed(),
            directory=self.root / "accounts",
        )

    def sealed(self, **overrides: str) -> bytes:
        fields = {
            "certificate_id": DEVICE,
            "address": LOCAL,
            "username": USER,
            "password": PASSWORD,
            **overrides,
        }
        return bmc_targets.seal_account(self.public, **fields)

    def set_target(self, pinned: str) -> None:
        _policy, runtime = self.runtime()
        cert_registry.set_bmc(
            self.root / "certificates.yaml",
            certificate_id=DEVICE,
            target=BmcTarget(
                address=LOCAL, port=self.bmc.port, fingerprint_sha256=pinned, username="admin"
            ),
            runtime=runtime,
            require_secure=False,
            lock_path=self.lock,
        )

    def root_side(self) -> Root:
        _policy, runtime = self.runtime()
        return Root(
            runtime=runtime,
            registry_path=self.root / "certificates.yaml",
            private_keys=[self.private],
            accounts=self.root / "accounts",
            state=self.root / "state",
            live=self.live,
            store=self.store,
            require_secure=False,
            lock_path=self.lock,
        )

    def now(self) -> datetime:
        self.moment += timedelta(minutes=15)
        return self.moment

    def sweep(self, **installer: Any) -> dict[str, str]:
        return bmc_targets.sweep(
            self.root_side(),
            now=self.now,
            installer=functools.partial(bmc_redfish.install, wait=0.0, interval=0.0, **installer),
        )

    def pinned(self) -> str:
        target = (
            load_registry(self.root / "certificates.yaml", require_secure=False)
            .certificates[DEVICE]
            .bmc
        )
        assert target is not None
        return target.fingerprint_sha256

    def state(self) -> bmc_targets.TargetState:
        return bmc_targets.read_state(self.root / "state")[DEVICE]

    def uploads(self) -> int:
        return sum(1 for method, path, *_ in self.bmc.requests if path == bmc_redfish.UPLOAD)


class TheSweep(TargetCase):
    def test_a_bmc_serving_the_confirmed_certificate_gets_the_current_one_and_the_pin_moves(
        self,
    ) -> None:
        self.assertEqual(self.sweep(), {DEVICE: "installed"})

        self.assertEqual(bmc_redfish.served(LOCAL, self.bmc.port).fingerprint_sha256, self.current)
        self.assertEqual(self.pinned(), self.current)
        state = self.state()
        self.assertEqual(state.served_sha256, self.current)
        self.assertIsNotNone(state.answered_at)
        assert state.attempt is not None
        self.assertEqual(
            (state.attempt.by, state.attempt.outcome, state.attempt.fingerprint_sha256),
            ("timer", "done", self.current),
        )
        self.assertEqual(state.attempt.firmware, "X13SCL-IF 01.09.06")

    def test_a_bmc_that_serves_the_current_certificate_is_left_alone(self) -> None:
        self.sweep()
        uploads = self.uploads()

        self.assertEqual(self.sweep(), {DEVICE: "installed"})
        self.assertEqual(self.uploads(), uploads)

    def test_a_bmc_that_does_not_answer_is_no_fault_however_long(self) -> None:
        self.sweep()
        answered = self.state().answered_at
        self.bmc.stop()
        for _ in range(3):
            self.assertEqual(self.sweep(), {DEVICE: "installed"})
        state = self.state()
        self.assertEqual(state.answered_at, answered)
        self.assertNotEqual(state.checked_at, answered)

    def test_a_bmc_off_before_its_first_install_is_waiting(self) -> None:
        self.bmc.stop()
        self.assertEqual(self.sweep(), {DEVICE: "waiting"})
        self.assertIsNone(self.state().attempt)

    def test_a_failed_install_is_said_and_not_tried_again_until_asked(self) -> None:
        self.bmc.upload_answer = (
            400,
            {
                "error": {
                    "@Message.ExtendedInfo": [{"Message": "SSL certificate validation failed."}]
                }
            },
        )
        self.assertEqual(self.sweep(), {DEVICE: "failed"})
        state = self.state()
        assert state.attempt is not None
        self.assertEqual((state.attempt.outcome, state.attempt.code), ("failed", "refused"))
        self.assertIn("SSL certificate validation failed.", state.attempt.message or "")
        self.assertEqual(self.pinned(), self.old)

        self.assertEqual(self.sweep(), {DEVICE: "failed"})
        self.assertEqual(self.uploads(), 1)

        self.bmc.upload_answer = (200, {})
        attempt = bmc_targets.install(
            self.root_side(),
            DEVICE,
            by="install_now",
            now=self.now,
            installer=functools.partial(bmc_redfish.install, wait=0.0, interval=0.0),
        )
        self.assertEqual(attempt.outcome, "done")
        self.assertEqual(self.sweep(), {DEVICE: "installed"})

    def test_a_bmc_serving_a_certificate_nobody_confirmed_is_sent_nothing(self) -> None:
        self.set_target("0" * 64)

        self.assertEqual(self.sweep(), {DEVICE: "untrusted"})
        self.assertEqual(self.bmc.requests, [])

    def test_a_job_does_not_wait_behind_another_install(self) -> None:
        """A job behind the timer's install of minutes would outlast its unit and say nothing."""

        with (
            bmc_targets.install_lock(self.root / "state"),
            self.assertRaises(TargetError) as refused,
        ):
            bmc_targets.install(
                self.root_side(),
                DEVICE,
                by="install_now",
                now=self.now,
                installer=functools.partial(bmc_redfish.install, wait=0.0, interval=0.0),
            )
        self.assertEqual(
            (refused.exception.code, refused.exception.exit_code),
            ("bmc_busy", exit_codes.BLOCKED),
        )
        self.assertEqual(self.bmc.requests, [])
        self.assertEqual(bmc_targets.read_state(self.root / "state"), {})

    def test_an_account_that_cannot_be_opened_fails_that_bmc_and_no_other(self) -> None:
        """A key replaced without the account entered again: said on the row, the sweep goes on."""

        bmc_targets.write_account(DEVICE, "0" * 16, self.sealed(), directory=self.root / "accounts")

        self.assertEqual(self.sweep(), {DEVICE: "failed"})

        attempt = self.state().attempt
        assert attempt is not None
        self.assertEqual((attempt.outcome, attempt.code), ("failed", "account_unreadable"))
        self.assertEqual(self.uploads(), 0)

    def test_a_bmc_that_answers_and_cannot_be_read_fails_that_bmc_and_no_other(self) -> None:
        """Review 26-11-27, BX02: a reading fault other than silence stopped the whole sweep."""

        def no_tls(address: str, port: int) -> bmc_redfish.Served:
            raise bmc_redfish.BmcError("tls_failed", f"{address}:{port} answered, but TLS failed")

        said = bmc_targets.sweep(self.root_side(), now=self.now, reader=no_tls)

        self.assertEqual(said, {DEVICE: "failed"})
        attempt = self.state().attempt
        assert attempt is not None
        self.assertEqual((attempt.outcome, attempt.code), ("failed", "tls_failed"))
        self.assertEqual(self.uploads(), 0)

    def test_an_upload_cut_off_is_a_failed_install_that_waits_for_install_now(self) -> None:
        """Review 26-11-27, BX01: it read as a BMC that was off, and was tried again for ever."""

        self.bmc.drop_upload = True
        self.assertEqual(self.sweep(), {DEVICE: "failed"})
        attempt = self.state().attempt
        assert attempt is not None
        self.assertEqual(attempt.code, "interrupted")
        self.bmc.drop_upload = False
        self.assertEqual(self.sweep(), {DEVICE: "failed"})
        self.assertEqual(self.uploads(), 1)

    def test_a_bmc_seen_serving_the_current_certificate_is_trusted_with_it(self) -> None:
        """Review 26-11-27, BX04: an install whose wait ran out kept the old pin, and the
        next renewal read as an untrusted BMC."""

        self.bmc.context = self.bmc._context(
            self.device.leaf.read_text(), self.device.leaf_key.read_text()
        )
        self.assertEqual(self.pinned(), self.old)

        self.assertEqual(self.sweep(), {DEVICE: "installed"})

        self.assertEqual(self.pinned(), self.current)
        self.assertEqual(self.uploads(), 0)

    def test_a_target_removed_during_the_sweep_is_passed_over(self) -> None:
        def removed_while_asked(address: str, port: int) -> bmc_redfish.Served:
            served = bmc_redfish.served(address, port)
            _policy, runtime = self.runtime()
            cert_registry.set_bmc(
                self.root / "certificates.yaml",
                certificate_id=DEVICE,
                target=None,
                runtime=runtime,
                require_secure=False,
                lock_path=self.lock,
            )
            return served

        said = bmc_targets.sweep(self.root_side(), now=self.now, reader=removed_while_asked)

        self.assertNotIn(DEVICE, said)
        self.assertEqual(self.uploads(), 0)

    def test_the_state_file_is_read_and_written_one_writer_at_a_time(self) -> None:
        """The timer's reading outside the install lock and a job's attempt inside it."""

        self.sweep()
        state = self.root / "state"
        descriptor = os.open(state / bmc_targets.STATE_LOCK_FILE, os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            writer = threading.Thread(
                target=bmc_targets.forget, args=(DEVICE,), kwargs={"directory": state}
            )
            writer.start()
            writer.join(0.5)
            self.assertTrue(writer.is_alive())
            self.assertIn(DEVICE, bmc_targets.read_state(state))
        finally:
            os.close(descriptor)
        writer.join(5)
        self.assertFalse(writer.is_alive())
        self.assertNotIn(DEVICE, bmc_targets.read_state(state))

    def test_a_bmc_that_keeps_the_old_certificate_failed(self) -> None:
        self.bmc.keep_old_after_reset = True

        self.assertEqual(self.sweep(), {DEVICE: "failed"})
        assert self.state().attempt is not None
        self.assertEqual(self.state().attempt.code, "not_served")  # type: ignore[union-attr]


class TheAccount(TargetCase):
    def test_the_file_is_roots_alone_and_holds_no_password(self) -> None:
        path = self.root / "accounts" / f"{DEVICE}.json"
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertNotIn(PASSWORD, path.read_text())

    def test_a_box_opens_only_for_its_certificate_and_address(self) -> None:
        box = self.sealed()
        self.assertEqual(
            bmc_targets.open_account(
                [self.private], self.public.key_id, box, certificate_id=DEVICE, address=LOCAL
            ),
            (USER, PASSWORD),
        )
        other_private, _ = generate()
        for keys, key_id, certificate_id, address in (
            ([self.private], self.public.key_id, "other.example", LOCAL),
            ([self.private], self.public.key_id, DEVICE, "192.0.2.9"),
            ([other_private], other_private.key_id, DEVICE, LOCAL),
            ([self.private], "f" * 16, DEVICE, LOCAL),
        ):
            with (
                self.subTest(certificate_id=certificate_id, address=address),
                self.assertRaises(TargetError) as refused,
            ):
                bmc_targets.open_account(
                    keys, key_id, box, certificate_id=certificate_id, address=address
                )
            self.assertEqual(refused.exception.code, "account_unreadable")

    def test_an_account_is_held_to_its_shape_before_it_is_sealed(self) -> None:
        for username, password in (
            ("", PASSWORD),
            (" admin", PASSWORD),
            (USER, ""),
            (USER, "a\nb"),
        ):
            with self.subTest(username=username), self.assertRaises(TargetError):
                bmc_targets.seal_account(
                    self.public,
                    certificate_id=DEVICE,
                    address=LOCAL,
                    username=username,
                    password=password,
                )

    def test_a_target_without_an_account_is_said_as_such(self) -> None:
        bmc_targets.remove_account(DEVICE, directory=self.root / "accounts")
        with self.assertRaises(TargetError) as refused:
            bmc_targets.install(self.root_side(), DEVICE, by="install_now")
        self.assertEqual(refused.exception.code, "account_missing")


class TheListing(TargetCase):
    def listed(self, states: Any) -> dict[str, Any]:
        from haprion.cert_inventory import registry_result

        result = registry_result(
            load_registry(self.root / "certificates.yaml", require_secure=False),
            certificate_root=self.dist,
            renewed=frozenset(),
            now=datetime.now(UTC),
            live=self.live,
            store=self.store,
            bmc_state=bmc_targets.row_state(states),
        )
        bmc: dict[str, Any] = next(row for row in result["certificates"] if row["id"] == DEVICE)[
            "bmc"
        ]
        return bmc

    def test_the_row_carries_the_timers_reading_held_against_the_certificate(self) -> None:
        self.assertEqual(self.listed({})["status"], "unknown")
        self.sweep()
        row = self.listed(bmc_targets.read_state(self.root / "state"))
        self.assertEqual((row["status"], row["served_sha256"]), ("installed", self.current))
        self.assertEqual(row["attempt"]["outcome"], "done")
        self.assertEqual(row["fingerprint_sha256"], self.current)

    def test_a_state_file_that_cannot_be_read_leaves_every_bmc_unknown(self) -> None:
        self.assertEqual(self.listed(None)["status"], "unknown")
