"""R3 - the ten failure cases of plan §6, proved rather than argued.

One class per case, named for the case it answers, so a reader can put the
plan and the suite side by side. The harness beside this file says what is
real here and what is not; nothing in this suite may be reported as covering
the transport, the authentication or the node's isolation.
"""

from __future__ import annotations

import errno
import io
import json
import os
import threading
import time
import unittest
from contextlib import redirect_stderr
from datetime import timedelta
from unittest.mock import patch

from haprion.traffic_collector import RETENTION_DAYS, NodeTarget
from tests.traffic_chain_harness import (
    HOST_KEY_CHANGED,
    ChainTestCase,
    load_node_prune,
    record,
)

PRUNE = load_node_prune()


def quietly(action: object) -> str:
    """Run a collection that is expected to fail and return what it complained."""

    held = io.StringIO()
    with redirect_stderr(held):
        action()  # type: ignore[operator]
    return held.getvalue()


class ANodeThatCannotBeReached(ChainTestCase):
    """§6.1 - unreachable for minutes, for hours, and for longer than retention."""

    def test_an_outage_holds_the_mirror_still_rather_than_emptying_it(self) -> None:
        self.chain.node.append(self.chain.today, 20)
        self.assertEqual(self.collect(), 0)
        before = self.chain.mirror_path().read_bytes()
        first_success = self.chain.meta()["last_success"]

        with self.chain.unreachable():
            for minutes in (5, 60, 180):
                moment = self.NOW + timedelta(minutes=minutes)
                quietly(lambda moment=moment: self.assertEqual(self.collect(now=moment), 1))
                self.assertEqual(self.chain.mirror_path().read_bytes(), before)
                meta = self.chain.meta()
                self.assertEqual(meta["last_success"], first_success)
                self.assertEqual(meta["last_attempt"], moment.isoformat())
                self.assertNotEqual(meta["outcome"], "ok")

        #
        # The page must say "we could not reach it", never show an empty table
        # that reads as a quiet node. Both halves of that are asserted here.
        #
        reading = self.chain.ui()
        self.assertEqual(len(reading.entries), 20)
        freshness = reading.nodes[0]
        self.assertNotEqual(freshness.outcome, "ok")
        self.assertGreaterEqual(
            freshness.stale_seconds(now=self.NOW + timedelta(minutes=180)), 3 * 3600
        )

    def test_an_outage_longer_than_retention_recovers_to_what_the_node_still_has(self) -> None:
        self.chain.node.append(self.chain.today, 10)
        self.assertEqual(self.collect(), 0)
        lost = self.chain.requests_seen()

        with self.chain.unreachable():
            quietly(lambda: self.collect(now=self.NOW + timedelta(days=1)))

        #
        # Twenty days later the node's own prune has deleted every day this
        # mirror holds. That data is gone at the source; what R3 checks is that
        # the manager says so instead of presenting the stale copy as current.
        #
        later = self.advance(20)
        self.chain.node.append(self.chain.today, 7)
        started = time.monotonic()
        self.assertEqual(self.collect(now=later), 0)
        self.chain.measured.seconds = time.monotonic() - started

        self.assertClean()
        self.assertNoLitter()
        self.assertEqual(self.chain.meta()["last_success"], later.isoformat())
        seen = self.chain.requests_seen()
        self.assertEqual(len(seen), 7)
        self.assertFalse(set(seen) & set(lost), "the mirror kept days the node no longer has")
        stale = list(self.chain.staging.glob("*--*--*.jsonl"))
        self.assertEqual(
            [item.name for item in stale],
            [f"alpha--node-a--{self.chain.today.isoformat()}.jsonl"],
            "a part from outside the window survived the outage",
        )


class ADayThatRollsOverMidTransfer(ChainTestCase):
    """§6.2 - the file the collector is reading stops being today's file."""

    def test_the_old_day_is_finished_and_the_new_day_is_picked_up(self) -> None:
        self.chain.node.append(self.chain.today, 12)
        self.settle()
        self.assertEqual(len(self.chain.requests_seen()), 12)

        # Midnight UTC: the node writes a few last records into the day that is
        # ending, then starts a new file. Neither file is ever renamed.
        yesterday = self.chain.today
        self.chain.node.append(yesterday, 4)
        tomorrow = self.advance(1)
        self.chain.node.append(self.chain.today, 6)

        #
        # One run carries both halves of the midnight: today is always fetched
        # first, and the day that just closed is the only unclaimed one left, so
        # a settled collector loses nothing to the rollover.
        #
        self.assertEqual(self.collect(now=tomorrow), 0)

        self.assertClean()
        self.assertEqual(len(self.chain.requests_seen()), 22)
        self.assertEqual(
            self.chain.requests_seen(),
            sorted(self.chain.requests_seen()),
            "the assembled mirror is not in day order",
        )

    def test_a_cold_start_costs_one_run_per_day_of_the_window(self) -> None:
        """Measured, and the number R4 should expect on the pilot node.

        The closed days are claimed oldest first, one per run, whether or not
        the node has a file for that day. A collector installed today therefore
        shows the current day immediately and fills the fortnight behind it over
        the next thirteen timer ticks - fourteen minutes at the planned
        interval. Bounded and one-time, but it is not instant, and an operator
        watching a fresh install would otherwise read it as data loss.
        """

        for age in reversed(range(4)):
            self.chain.node.append(self.chain.today - timedelta(days=age), 3)

        runs = self.settle()
        self.assertEqual(runs, RETENTION_DAYS, "a cold start should cost one run per window day")
        self.assertClean()
        self.assertEqual(len(self.chain.requests_seen()), 12)

        # From then on a run is one request, and an idle minute carries nothing.
        before = self.chain.measured.requests
        self.assertEqual(self.collect(), 0)
        self.assertEqual(self.chain.measured.requests - before, 1)


class ACollectorThatIsInterrupted(ChainTestCase):
    """§6.3 - killed before the rename, and killed after it."""

    def test_a_failed_publish_leaves_the_previous_snapshot_and_no_debris(self) -> None:
        self.chain.node.append(self.chain.today, 8)
        self.assertEqual(self.collect(), 0)
        published = self.chain.mirror_path().read_bytes()

        self.chain.node.append(self.chain.today, 5)
        with patch(
            "haprion.traffic_collector.os.replace",
            side_effect=OSError(errno.EIO, "interrupted"),
        ):
            message = quietly(lambda: self.assertEqual(self.collect(), 1))
        self.assertIn("node-a", message)

        self.assertEqual(self.chain.mirror_path().read_bytes(), published)
        self.assertNoLitter()

        # The next run publishes everything, exactly once.
        self.assertEqual(self.collect(), 0)
        self.assertClean()
        self.assertEqual(len(self.chain.requests_seen()), 13)

    def test_a_published_snapshot_with_unwritten_metadata_is_not_fetched_again(self) -> None:
        self.chain.node.append(self.chain.today, 6)
        with patch(
            "haprion.traffic_collector._write_meta",
            side_effect=OSError(errno.EIO, "interrupted"),
        ):
            quietly(lambda: self.assertEqual(self.collect(), 1))
        self.assertEqual(len(self.chain.requests_seen()), 6)
        self.assertEqual(self.chain.meta(), {})

        #
        # The cursor lives in the size of the committed part, never in the
        # metadata. A run that published and then died must therefore not
        # re-fetch the day it already holds.
        #
        before = self.chain.measured.payload_bytes
        self.assertEqual(self.collect(), 0)
        self.assertEqual(self.chain.measured.payload_bytes, before, "the day was fetched twice")
        self.assertClean()
        self.assertEqual(self.chain.meta()["outcome"], "ok")


class TheSameDayFetchedTwice(ChainTestCase):
    """§6.4 - idempotence, measured rather than assumed."""

    def test_a_second_run_transfers_a_header_and_changes_nothing(self) -> None:
        payload = self.chain.node.append(self.chain.today, 15)
        self.settle()
        first = self.chain.mirror_path().read_bytes()
        self.assertEqual(self.chain.measured.payload_bytes, len(payload))

        before = self.chain.measured.requests
        for _ in range(3):
            self.assertEqual(self.collect(), 0)
        self.assertEqual(self.chain.mirror_path().read_bytes(), first)
        self.assertEqual(self.chain.measured.payload_bytes, len(payload), "records were resent")
        self.assertClean()
        self.assertEqual(self.chain.duplicates(), 0)

        # Three runs, three requests, and not one record among them.
        self.assertEqual(self.chain.measured.requests - before, 3)
        overhead = self.chain.measured.wire_bytes - self.chain.measured.payload_bytes
        self.assertLess(
            overhead, self.chain.measured.requests * 200, "the empty answer is not a small header"
        )


class ANodeFileThatIsTruncatedOrReplaced(ChainTestCase):
    """§6.5 - the cursor points somewhere the file no longer has."""

    def test_truncation_rebuilds_the_day_instead_of_inventing_records(self) -> None:
        self.chain.node.append(self.chain.today, 10)
        self.assertEqual(self.collect(), 0)
        self.assertEqual(len(self.chain.requests_seen()), 10)

        # The file is emptied and written again - a smaller file than the cursor.
        self.chain.node.truncate(self.chain.today)
        self.chain.node.append(self.chain.today, 4)

        self.assertEqual(self.collect(), 0)  # sees the reset, drops the day
        self.assertEqual(self.chain.requests_seen(), [])
        self.assertEqual(self.collect(), 0)  # and refills it from zero
        self.assertClean()
        self.assertEqual(len(self.chain.requests_seen()), 4)

    def test_a_replaced_file_that_lands_the_cursor_mid_record_is_rebuilt_whole(self) -> None:
        self.chain.node.append(self.chain.today, 10)
        self.assertEqual(self.collect(), 0)
        held = self.chain.node.size(self.chain.today)

        # Same day, different content, and long enough that the old cursor still
        # points inside it - but no longer at a record boundary.
        self.chain.node.truncate(self.chain.today)
        self.chain.node.append_raw(self.chain.today, b"x" * (held // 2))
        self.chain.node.append(self.chain.today, 12)
        self.assertGreater(self.chain.node.size(self.chain.today), held)

        self.assertEqual(self.collect(), 0)
        self.assertEqual(self.chain.mirrored(), [], "a hole was preserved instead of rebuilt")
        self.assertEqual(self.collect(), 0)

        self.assertNoLitter()
        self.assertEqual(
            self.chain.mirror_path().read_bytes(),
            self.chain.node.day(self.chain.today).read_bytes(),
            "the rebuilt day is not what the node holds",
        )
        # The junk has no newline of its own, so it swallows the record after it.
        # That is one line the interface refuses; the rest survive it.
        reading = self.chain.ui()
        self.assertEqual(len(reading.entries), 11)
        self.assertEqual(reading.malformed, 1)


class ARecordThatIsNotWhatItShouldBe(ChainTestCase):
    """§6.6 - too large, malformed, or not UTF-8."""

    def test_bad_records_are_carried_and_counted_rather_than_stopping_the_page(self) -> None:
        self.chain.node.append(self.chain.today, 2)
        self.chain.node.append_raw(self.chain.today, b'{"schema":1,"at":not json}\n')
        self.chain.node.append_raw(self.chain.today, b'{"schema":1,"path":"\xff\xfe"}\n')
        oversized = record(at=1789000000, request=99, path="/" + "p" * (20 * 1024))
        self.chain.node.append_raw(self.chain.today, oversized)
        self.chain.node.append(self.chain.today, 2)

        self.assertEqual(self.collect(), 0)
        self.assertEqual(len(self.chain.mirrored()), 7)

        reading = self.chain.ui()
        self.assertEqual(len(reading.entries), 4, "a good record was lost with a bad one")
        self.assertEqual(reading.malformed, 3)
        self.assertFalse(reading.unavailable)

    def test_one_record_larger_than_a_whole_transfer_is_refused_loudly(self) -> None:
        """The measured hard limit: a single line of 8 MiB stops that day."""

        self.chain.node.append_raw(self.chain.today, b"y" * (9 * 1024 * 1024))
        message = quietly(lambda: self.assertEqual(self.collect(), 1))
        self.assertIn("exit 65", message)
        self.assertEqual(self.chain.mirrored(), [])
        self.assertNotEqual(self.chain.meta()["outcome"], "ok")

    def test_a_day_larger_than_one_transfer_arrives_in_order_across_runs(self) -> None:
        """Above 8 MiB the day needs a second request; it must not lose a record."""

        wanted = 8 * 1024 * 1024 + 512 * 1024
        written = 0
        while written < wanted:
            written += len(self.chain.node.append(self.chain.today, 2000))

        self.assertEqual(self.collect(), 0)
        first = len(self.chain.requests_seen())
        self.assertGreater(first, 0)
        self.assertLess(first, self.chain.node.next_request)
        self.assertEqual(self.collect(), 0)

        self.assertClean()
        self.assertEqual(len(self.chain.requests_seen()), self.chain.node.next_request)
        self.assertEqual(self.chain.measured.payload_bytes, written)


class ADiskThatFillsUp(ChainTestCase):
    """§6.7 - no room on the manager, and nothing new on the node."""

    def test_a_full_manager_disk_keeps_the_last_good_mirror_and_recovers(self) -> None:
        self.chain.node.append(self.chain.today, 9)
        self.assertEqual(self.collect(), 0)
        published = self.chain.mirror_path().read_bytes()

        self.chain.node.append(self.chain.today, 9)
        with patch(
            "haprion.traffic_collector.os.write",
            side_effect=OSError(errno.ENOSPC, "no space left on device"),
        ):
            quietly(lambda: self.assertEqual(self.collect(), 1))

        self.assertEqual(self.chain.mirror_path().read_bytes(), published)
        self.assertNotEqual(self.chain.meta()["outcome"], "ok")
        self.assertNoLitter()

        self.assertEqual(self.collect(), 0)
        self.assertClean()
        self.assertEqual(len(self.chain.requests_seen()), 18)

    def test_a_node_that_has_stopped_writing_is_success_and_not_an_error(self) -> None:
        self.chain.node.append(self.chain.today, 3)
        self.assertEqual(self.collect(), 0)
        for _ in range(3):
            self.assertEqual(self.collect(), 0)
        self.assertEqual(self.chain.meta()["outcome"], "ok")
        self.assertEqual(len(self.chain.requests_seen()), 3)


class AHostKeyThatChanged(ChainTestCase):
    """§6.8 - the node is answering, but it is not provably the same node."""

    def test_a_changed_host_key_is_a_failure_and_never_a_quiet_empty_log(self) -> None:
        self.chain.node.append(self.chain.today, 5)
        self.assertEqual(self.collect(), 0)
        published = self.chain.mirror_path().read_bytes()
        good = self.chain.meta()["last_success"]

        self.chain.node.append(self.chain.today, 5)
        with self.chain.unreachable(HOST_KEY_CHANGED):
            message = quietly(lambda: self.assertEqual(self.collect(), 1))
        self.assertIn("IDENTIFICATION HAS CHANGED", message)

        self.assertEqual(self.chain.mirror_path().read_bytes(), published)
        self.assertEqual(self.chain.meta()["last_success"], good)
        self.assertEqual(self.chain.measured.refusals, 1)
        self.assertEqual(len(self.chain.ui().entries), 5)


class AnInventoryThatChanged(ChainTestCase):
    """§6.9 - a node leaves, and its management address comes back as another."""

    def test_a_reused_address_starts_its_own_mirror_and_never_joins_the_old_one(self) -> None:
        self.chain.node.append(self.chain.today, 6)
        self.assertEqual(self.collect(), 0)
        retired = self.chain.mirror_path().read_bytes()

        #
        # Same address, decommissioned and rebuilt under a new name. Destination
        # comes from the manager's inventory, so the new identity gets its own
        # cursor, its own part and its own mirror - locked requirement 4.
        #
        self.chain.config = self.retire(NodeTarget("alpha", "node-b", self.chain.target.host))
        self.chain.node.append(self.chain.today, 4)
        self.assertEqual(self.collect(), 0)

        new_mirror = self.chain.mirror / "alpha--node-b.jsonl"
        self.assertEqual(len(new_mirror.read_bytes().splitlines()), 10)
        self.assertEqual(self.chain.mirror_path().read_bytes(), retired)

        # Both are listed, and the retired one is visibly stale rather than gone.
        reading = self.chain.ui()
        self.assertEqual(sorted(item.node for item in reading.nodes), ["node-a", "node-b"])

    def test_a_node_out_of_inventory_dies_of_old_age_rather_than_at_once(self) -> None:
        """R3's third finding, decided rather than left open.

        Nothing is deleted the moment a node leaves inventory - its last
        fortnight is exactly what an operator may want to read afterwards. It is
        deleted when a whole retention window has passed without a collection,
        because by then every record in it is older than the node's own
        retention and the data no longer exists at the source either.
        """

        self.chain.node.append(self.chain.today, 4)
        self.assertEqual(self.collect(), 0)
        self.chain.config = self.retire(NodeTarget("alpha", "node-b", "node-b.example.com"))

        # Still inside the window: listed, readable, and visibly stale.
        moment = self.advance(RETENTION_DAYS - 2)
        quietly(lambda: self.collect(now=moment))
        self.assertTrue(self.chain.mirror_path().exists())
        reading = self.chain.ui()
        self.assertEqual(len(reading.nodes), 2)
        self.assertEqual(len(reading.entries), 4)

        # A whole window later there is nothing left of it anywhere.
        moment = self.advance(3)
        quietly(lambda: self.collect(now=moment))
        self.assertFalse(self.chain.mirror_path().exists())
        self.assertEqual(list(self.chain.mirror.glob("alpha--node-a.*")), [])
        self.assertEqual(list(self.chain.staging.glob("alpha--node-a--*")), [])
        self.assertEqual([item.node for item in self.chain.ui().nodes], ["node-b"])

    def test_an_active_node_is_never_swept_however_long_it_is_silent(self) -> None:
        self.chain.node.append(self.chain.today, 4)
        self.assertEqual(self.collect(), 0)
        with self.chain.unreachable():
            for step in (RETENTION_DAYS, RETENTION_DAYS):
                moment = self.advance(step)
                quietly(lambda moment=moment: self.assertEqual(self.collect(now=moment), 1))
        self.assertEqual(len(self.chain.ui().entries), 4, "a silent node lost its last records")


class APageReadDuringASnapshotSwap(ChainTestCase):
    """§6.10 - the interface reads while the collector is replacing the mirror."""

    ROUNDS = 40

    def test_every_read_sees_one_whole_snapshot(self) -> None:
        self.chain.node.append(self.chain.today, 5)
        self.assertEqual(self.collect(), 0)

        stop = threading.Event()
        failures: list[BaseException] = []

        def collecting() -> None:
            try:
                for _ in range(self.ROUNDS):
                    self.chain.node.append(self.chain.today, 3)
                    if self.collect() != 0:  # pragma: no cover - would be the finding
                        raise AssertionError("a collection failed during the read loop")
            except BaseException as exc:  # pragma: no cover - reported below
                failures.append(exc)
            finally:
                stop.set()

        worker = threading.Thread(target=collecting)
        worker.start()
        counts: list[int] = []
        try:
            while not stop.is_set():
                reading = self.chain.ui()
                self.assertEqual(reading.malformed, 0, "a read caught a half-written mirror")
                self.assertFalse(reading.unavailable)
                counts.append(len(reading.entries))
        finally:
            worker.join(timeout=120)

        self.assertEqual(failures, [])
        self.assertFalse(worker.is_alive())
        self.assertGreater(len(counts), 5, "the reader never got a turn")
        self.assertEqual(counts, sorted(counts), "a read saw fewer records than an earlier one")
        self.assertClean()
        self.assertEqual(len(self.chain.requests_seen()), 5 + 3 * self.ROUNDS)

    def test_two_collectors_do_not_run_at_once(self) -> None:
        """The lock is what keeps §6.10 a swap and not a race."""

        self.chain.node.append(self.chain.today, 3)
        held = self.chain.staging / ".collector.lock"
        descriptor = os.open(held, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.collect(), 0, "a busy collector should exit quietly")
            self.assertEqual(self.chain.mirrored(), [], "the second collector ran anyway")
            self.assertEqual(self.chain.measured.requests, 0)
        finally:
            os.close(descriptor)
        self.assertEqual(self.collect(), 0)
        self.assertEqual(len(self.chain.requests_seen()), 3)


class RotationRetentionAndReadingAtOnce(ChainTestCase):
    """R3's third bullet: a day change and a prune while fetching and reading."""

    def test_the_day_change_and_the_prune_do_not_disturb_a_reader(self) -> None:
        # A fortnight of history, then one more midnight than the window holds.
        for age in reversed(range(RETENTION_DAYS)):
            self.chain.node.append(self.chain.today - timedelta(days=age), 2)
        for _ in range(RETENTION_DAYS):
            self.assertEqual(self.collect(), 0)
        self.assertEqual(len(self.chain.requests_seen()), 2 * RETENTION_DAYS)
        oldest = self.chain.requests_seen()[0]

        moment = self.advance(1)
        self.chain.node.append(self.chain.today, 2)
        removed = PRUNE.prune(self.chain.node.root, today=self.chain.today)
        self.assertEqual(len(removed), 1, "exactly one day should leave the window")

        self.assertEqual(self.collect(now=moment), 0)
        reading = self.chain.ui()
        self.assertEqual(reading.malformed, 0)
        self.assertClean()

        #
        # The pruned day is gone from the node and from the manager's window, so
        # it leaves the mirror too - and takes its staging part with it.
        #
        self.assertNotIn(oldest, self.chain.requests_seen())
        names = sorted(item.name for item in self.chain.staging.glob("*--*--*.jsonl"))
        self.assertEqual(len(names), RETENTION_DAYS)

    def test_completion_markers_leave_the_window_with_their_day(self) -> None:
        """R3 found staging growing one empty marker per node-day, for ever.

        The prune globbed `*.jsonl`, which the `.done` markers that record a
        finished closed day are not. Nothing else ever removed them, so the
        directory grew for as long as the collector ran. Both kinds of leftover
        are pruned by the window now, and this is what holds that.
        """

        self.chain.node.append(self.chain.today, 1)
        self.settle()
        markers = sorted(item.name for item in self.chain.staging.glob("*.done"))
        self.assertEqual(len(markers), RETENTION_DAYS - 1, "one marker per closed day")

        moment = self.advance(RETENTION_DAYS + 2)
        self.chain.node.append(self.chain.today, 1)
        self.settle(now=moment)

        kept = sorted(item.name for item in self.chain.staging.glob("*.done"))
        self.assertEqual(
            [name for name in markers if name in kept], [], "a marker outside the window survived"
        )
        self.assertEqual(len(kept), RETENTION_DAYS - 1, "the new window lost its markers")
        self.assertEqual(len(list(self.chain.staging.glob("*--*--*.jsonl"))), 1)


class WhatARunHoldsOpen(ChainTestCase):
    """R3 found the transport leaking its pipes; this is what keeps them closed."""

    def test_fetching_many_days_does_not_accumulate_open_files(self) -> None:
        for age in reversed(range(RETENTION_DAYS)):
            self.chain.node.append(self.chain.today - timedelta(days=age), 2)
        self.assertEqual(self.collect(), 0)

        held = len(os.listdir("/proc/self/fd"))
        requests = self.chain.measured.requests
        self.settle()
        self.assertGreater(self.chain.measured.requests - requests, 4, "too few fetches to judge")
        self.assertLessEqual(
            len(os.listdir("/proc/self/fd")),
            held + 2,
            "the transport is leaving its pipes to the garbage collector",
        )


class WhatOneRunCosts(ChainTestCase):
    """The numbers R3 is asked to measure, in one place and as assertions."""

    def test_the_measured_envelope_of_a_normal_minute(self) -> None:
        self.settle()
        written = len(self.chain.node.append(self.chain.today, 600))

        before_requests = self.chain.measured.requests
        before_payload = self.chain.measured.payload_bytes
        before_wire = self.chain.measured.wire_bytes
        started = time.monotonic()
        self.assertEqual(self.collect(), 0)
        elapsed = time.monotonic() - started

        measured = self.chain.measured
        self.assertEqual(measured.requests - before_requests, 1)
        self.assertEqual(measured.payload_bytes - before_payload, written, "records were resent")
        header = measured.wire_bytes - before_wire - written
        self.assertLess(header, 200, "the protocol header should stay small and fixed")
        self.assertEqual(self.chain.mirror_path().stat().st_size, written)
        self.assertLess(elapsed, 30, "one node-minute must fit inside the SSH timeout")

        # An idle minute after it costs one request and no records at all.
        before_wire = measured.wire_bytes
        self.assertEqual(self.collect(), 0)
        self.assertLess(measured.wire_bytes - before_wire, 200)
        self.assertClean()

    def test_the_mirror_is_never_larger_than_what_the_node_sent(self) -> None:
        written = 0
        for day in range(3):
            written += len(self.chain.node.append(self.chain.today - timedelta(days=day), 100))
        self.settle()
        self.assertEqual(self.chain.mirror_path().stat().st_size, written)
        self.assertEqual(self.chain.measured.payload_bytes, written)

    def test_the_interface_reads_a_bounded_amount_however_large_the_mirror(self) -> None:
        self.chain.node.append(self.chain.today, 1200)
        self.assertEqual(self.collect(), 0)
        reading = self.chain.ui(limit=500)
        self.assertEqual(len(reading.entries), 500)
        self.assertEqual(reading.malformed, 0)
        newest = json.loads(self.chain.mirrored()[-1])["request"]
        self.assertEqual(reading.entries[0].request, newest, "the newest record is not first")


if __name__ == "__main__":  # pragma: no cover - convenience
    unittest.main()
