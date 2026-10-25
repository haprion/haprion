"""The update check (B334, B342): what is asked of GitHub, when, and what the pages say."""

from __future__ import annotations

import http.client
import http.server
import json
import threading
import time
import unittest
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

from haprion_ui import features, update_check
from haprion_ui.db import FeatureSwitch, UpdateCheck
from tests.test_login import LoginTestCase, configuration

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
PAGE = "https://github.com/haprion/haprion/releases/tag/v0.9.3"


def answer(tag: str = "v0.9.3", url: str = PAGE, **more: Any) -> bytes:
    return json.dumps({"tag_name": tag, "html_url": url, **more}).encode()


def row(**overrides: Any) -> UpdateCheck:
    values: dict[str, Any] = {
        "latest_tag": "v0.9.3",
        "latest_url": PAGE,
        "checked_at": NOW - timedelta(hours=2),
        "attempted_at": NOW - timedelta(hours=2),
        "failing_since": None,
    }
    values.update(overrides)
    return UpdateCheck(**values)


class TheAnswer(unittest.TestCase):
    def test_a_release_is_its_tag_and_its_page(self) -> None:
        self.assertEqual(update_check.parse(answer()), update_check.Release("v0.9.3", PAGE))

    def test_anything_else_is_no_answer(self) -> None:
        for body in (
            b"not json",
            b"[]",
            answer(tag="latest"),
            answer(tag="v0.9.3-rc1"),
            # The header links to it: only the project's own release page.
            answer(url="https://example.com/haprion/releases/tag/v0.9.3"),
            answer(url="https://github.com/haprion/haprion/releases/tag/v0.9.3/../../x"),
        ):
            with self.subTest(body=body[:60]), self.assertRaises(update_check.NoAnswer):
                update_check.parse(body)

    def test_newer_is_by_number_not_by_text(self) -> None:
        self.assertTrue(update_check.newer("0.9.2", "v0.9.3"))
        self.assertTrue(update_check.newer("0.9.2", "v0.10.0"))
        self.assertFalse(update_check.newer("0.9.2", "v0.9.2"))
        self.assertFalse(update_check.newer("0.10.0", "v0.9.9"))
        # A package's local version after the release's.
        self.assertFalse(update_check.newer("0.9.2+git20261020.abc", "v0.9.2"))


class WhenItAsks(unittest.TestCase):
    def test_once_a_day_after_an_answer(self) -> None:
        self.assertTrue(update_check.due(None, NOW))
        self.assertFalse(update_check.due(row(checked_at=NOW - timedelta(hours=23)), NOW))
        self.assertTrue(update_check.due(row(checked_at=NOW - timedelta(hours=24)), NOW))

    def test_hourly_while_github_does_not_answer(self) -> None:
        failing = row(failing_since=NOW - timedelta(hours=5))
        self.assertFalse(
            update_check.due(replace(failing, attempted_at=NOW - timedelta(minutes=59)), NOW)
        )
        self.assertTrue(
            update_check.due(replace(failing, attempted_at=NOW - timedelta(hours=1)), NOW)
        )


class OnePass(unittest.TestCase):
    """`check` as the poller calls it, against a recorded database."""

    def setUp(self) -> None:
        self.on = True
        self.row: UpdateCheck | None = None
        self.answers: list[dict[str, Any]] = []
        self.failures: list[dict[str, Any]] = []
        self.asked: list[str] = []
        for target, effect in (
            ("switch_enabled", lambda _c, name: self.on and name == "update_check"),
            ("update_check", lambda _c: self.row),
            ("record_update_answer", lambda _c, **values: self.answers.append(values)),
            ("record_update_failure", lambda _c, **values: self.failures.append(values)),
        ):
            patch = mock.patch(f"haprion_ui.db.{target}", side_effect=effect)
            patch.start()
            self.addCleanup(patch.stop)
        self.pool = mock.MagicMock()

    def run_with(self, ask: Callable[[], bytes]) -> None:
        def asked(installed: str) -> bytes:
            self.asked.append(installed)
            return ask()

        update_check.check(self.pool, installed="0.9.2", now=NOW, ask=asked)

    def test_off_asks_nothing(self) -> None:
        self.on = False
        self.run_with(answer)
        self.assertEqual((self.asked, self.answers, self.failures), ([], [], []))

    def test_not_due_asks_nothing(self) -> None:
        self.row = row()
        self.run_with(answer)
        self.assertEqual(self.asked, [])

    def test_an_answer_is_recorded(self) -> None:
        self.run_with(answer)
        self.assertEqual(self.asked, ["0.9.2"])
        self.assertEqual(self.answers, [{"tag": "v0.9.3", "url": PAGE, "at": NOW}])

    def test_no_answer_is_a_failure_and_never_raises(self) -> None:
        def unreachable() -> bytes:
            raise update_check.NoAnswer("GitHub could not be reached: timed out")

        self.run_with(unreachable)
        self.assertEqual(self.answers, [])
        self.assertEqual(
            self.failures, [{"error": "GitHub could not be reached: timed out", "at": NOW}]
        )

    def test_a_database_that_fails_does_not_stop_the_pass(self) -> None:
        self.pool.connection.side_effect = RuntimeError("gone")
        self.run_with(answer)  # no exception: the clusters are still polled


class _Drip(http.server.BaseHTTPRequestHandler):
    """An answer a byte at a time: every read is quick, the answer never ends."""

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "1000")
        self.end_headers()
        for _ in range(1000):
            self.wfile.write(b" ")
            self.wfile.flush()
            time.sleep(0.02)

    def log_message(self, *_args: Any) -> None:
        pass


class TheAskHasADeadline(unittest.TestCase):
    """Review 2026-10-20, A1: the socket's timeout bounds a read, not the answer."""

    def test_an_answer_that_drips_is_given_up_on_by_the_deadline(self) -> None:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Drip)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        with mock.patch.object(update_check, "TIMEOUT_SECONDS", 0.3):
            started = time.monotonic()
            with self.assertRaisesRegex(update_check.NoAnswer, "took longer"):
                update_check.fetch("0.9.2", url=url)
            self.assertLess(time.monotonic() - started, 1.0)


class ABrokenAnswerIsNoAnswer(unittest.TestCase):
    """Review 26-10-24, 07-08: a protocol error escaped, and every pass asked again."""

    def test_an_answer_cut_short_or_without_a_status_line(self) -> None:
        for broken in (http.client.IncompleteRead(b"{"), http.client.BadStatusLine("garbage")):
            with (
                self.subTest(type(broken).__name__),
                mock.patch("urllib.request.urlopen", side_effect=broken),
                self.assertRaises(update_check.NoAnswer),
            ):
                update_check.fetch("0.9.2")


class ThePollerDoesNotWait(OnePass):
    """`Asker` as the poller holds it: started each pass, one thread at most."""

    def test_a_pass_goes_on_while_github_has_not_answered(self) -> None:
        release = threading.Event()

        def stuck(_installed: str) -> bytes:
            release.wait(5)
            return answer()

        asker = update_check.Asker()
        started = time.monotonic()
        self.assertTrue(asker.start(self.pool, installed="0.9.2", now=NOW, ask=stuck))
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertFalse(asker.start(self.pool, installed="0.9.2", now=NOW, ask=stuck))
        release.set()
        asker.join(5)
        self.assertEqual(self.answers, [{"tag": "v0.9.3", "url": PAGE, "at": NOW}])
        self.assertTrue(asker.start(self.pool, installed="0.9.2", now=NOW, ask=stuck))
        asker.join(5)


class WhatThePagesSay(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.switches = {
            features.UPDATE_CHECK: FeatureSwitch(features.UPDATE_CHECK, True, {}, NOW, None)
        }

    def admin(self) -> Any:
        client = self.client(replace(configuration(), management_writes=True))
        self.assertEqual(self.sign_in(client).status_code, 303)
        return client

    def test_the_header_links_a_newer_release(self) -> None:
        self.update_row = row(latest_tag="v99.0.0", latest_url=PAGE.replace("v0.9.3", "v99.0.0"))
        text = self.admin().get("/").text
        self.assertIn(
            '<a class="update-available" href="https://github.com/haprion/haprion/releases/tag/'
            'v99.0.0" target="_blank" rel="noopener noreferrer">· v99.0.0 available</a>',
            text,
        )

    def test_nothing_when_the_release_is_not_newer_or_the_switch_is_off(self) -> None:
        self.update_row = row(latest_tag="v0.0.1", latest_url=PAGE.replace("v0.9.3", "v0.0.1"))
        self.assertNotIn("update-available", self.admin().get("/").text)
        self.update_row = row(latest_tag="v99.0.0", latest_url=PAGE.replace("v0.9.3", "v99.0.0"))
        self.switches = {
            features.UPDATE_CHECK: FeatureSwitch(features.UPDATE_CHECK, False, {}, NOW, None)
        }
        self.assertNotIn("update-available", self.admin().get("/").text)

    def test_the_switch_row_says_when_github_last_answered(self) -> None:
        self.update_row = row()
        self.assertIn("Last checked", self.admin().get("/settings").text)
        self.update_row = row(failing_since=NOW - timedelta(hours=3))
        self.assertIn("GitHub has not answered since", self.admin().get("/settings").text)


if __name__ == "__main__":
    unittest.main()
