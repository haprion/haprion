"""haprion-blocklist-refresh: one pass of the timer, against a manager in a scratch directory (B500)."""

from __future__ import annotations

import datetime as dt
import io
import json
from pathlib import Path

from haprion import blocklist_store, blocklists, exit_codes
from haprion.blocklist_store import Stored
from haprion.cli import blocklist_refresh as command
from tests.test_cert_publish import Fixture

NOW = dt.datetime(2026, 11, 10, 6, 0, tzinfo=dt.UTC)


class TheCommand(Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.policy = self.write_config(self.keeper())
        self.definitions = self.root / "definitions"
        self.definitions.mkdir(mode=0o700)
        self.state = self.root / "state"
        self.body = b"192.0.2.0/24\n"
        self.failure: Exception | None = None
        self.deployed: list[str] = []
        self.answer = 0

    def define(self, name: str = "crowdsec", **fields: object) -> None:
        item = blocklists.definition(
            name=name,
            url="https://example.com/list.txt",
            every_hours=24,
            **fields,  # type: ignore[arg-type]
        )
        blocklist_store.write(
            Stored(definition=item, secret="", revision=1),
            directory=self.definitions,
            require_secure=False,
        )

    def fetch(self, item: blocklists.Definition, secret: str) -> bytes:
        if self.failure is not None:
            raise self.failure
        return self.body

    def deployer(self, cluster: str) -> int:
        self.deployed.append(cluster)
        return self.answer

    def refresh(self, *argv: str, now: dt.datetime = NOW) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = command.main(
            list(argv),
            policy_path=self.policy,
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            definitions=self.definitions,
            state=self.state,
            lock_path=self.root / "refresh.lock",
            deployer=self.deployer,
            fetch=self.fetch,
            now=now,
        )
        return code, out.getvalue(), err.getvalue()

    def test_a_new_list_is_written_for_the_cluster_and_deployed(self) -> None:
        self.define()

        code, out, err = self.refresh()

        self.assertEqual(code, exit_codes.OK, err)
        self.assertEqual((self.alpha / "blocklists" / "crowdsec.lst").read_bytes(), self.body)
        self.assertEqual(self.deployed, ["alpha"])
        self.assertIn("crowdsec: 1 entries", out)
        self.assertIn("deploy alpha: ok", out)

    def test_nothing_due_and_nothing_changed_deploys_nothing(self) -> None:
        self.define()
        self.refresh()

        code, out, _ = self.refresh(now=NOW + dt.timedelta(hours=1))

        self.assertEqual(code, exit_codes.OK)
        self.assertEqual(self.deployed, ["alpha"])

    def test_a_deploy_that_did_not_finish_is_tried_by_the_next_pass(self) -> None:
        self.define()
        self.answer = exit_codes.BLOCKED
        code, out, _ = self.refresh()
        self.assertEqual(code, exit_codes.FAILED)
        self.assertIn("deploy alpha: exit 75", out)

        self.answer = 0
        code, _, _ = self.refresh(now=NOW + dt.timedelta(minutes=10))

        self.assertEqual(code, exit_codes.OK)
        self.assertEqual(self.deployed, ["alpha", "alpha"])
        pending = json.loads((self.state / command.PENDING).read_text())
        self.assertEqual(pending, {"clusters": []})

    def test_an_unreadable_pending_file_deploys_every_cluster(self) -> None:
        self.state.mkdir()
        (self.state / command.PENDING).write_text("not json")

        answers = command.deploy((), ["alpha"], directory=self.state, deployer=self.deployer)

        self.assertEqual(answers, {"alpha": 0})

    def test_a_failed_fetch_keeps_the_last_list_and_says_so(self) -> None:
        self.define()
        self.refresh()
        self.failure = blocklists.BlocklistError("refused", "example.com answered 503")

        code, out, _ = self.refresh("--force", now=NOW + dt.timedelta(hours=1))

        self.assertEqual(code, exit_codes.PARTIAL)
        self.assertIn("crowdsec: failed: example.com answered 503; kept the list of", out)
        self.assertEqual((self.alpha / "blocklists" / "crowdsec.lst").read_bytes(), self.body)

    def test_an_exception_naming_a_group_the_cluster_lacks_is_said(self) -> None:
        self.define(excepts=["partner-sites"])

        _, out, _ = self.refresh()

        self.assertIn("the exception names partner-sites, which the cluster does not define", out)

    def test_list_fetches_that_list_now(self) -> None:
        self.define()
        self.refresh()
        self.body = b"192.0.2.0/24\n198.51.100.0/24\n"

        code, _, err = self.refresh("--list", "crowdsec", now=NOW + dt.timedelta(minutes=1))

        self.assertEqual(code, exit_codes.OK, err)
        self.assertIn(b"198.51.100.0/24", (self.alpha / "blocklists" / "crowdsec.lst").read_bytes())

    def test_an_unknown_list_or_argument_is_refused(self) -> None:
        self.define()
        self.assertEqual(self.refresh("--list", "other")[0], exit_codes.USAGE)
        self.assertEqual(self.refresh("--list", "Bad")[0], exit_codes.USAGE)
        self.assertEqual(self.refresh("--everything")[0], exit_codes.USAGE)

    def test_no_definitions_is_a_quiet_pass(self) -> None:
        code, out, _ = self.refresh()

        self.assertEqual((code, out), (exit_codes.OK, ""))
        self.assertFalse((self.alpha / "blocklists").exists())

    def test_it_must_run_as_root(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        code = command.main(
            [], policy_path=Path("/nonexistent"), output_stream=out, error_stream=err
        )
        if code != exit_codes.NOT_ROOT:
            self.skipTest("the tests run as root")
        self.assertIn("must run as root", err.getvalue())
