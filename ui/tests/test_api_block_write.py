"""Placing a block and lifting it through the API (B416): the same call, and the same job as the page's.

The helper behind the socket is answered by a function here; its own checks
are `tests/test_block_api_helper.py` (the engine's).
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock
from uuid import UUID

from haprion import block_api_socket

from haprion_ui import blocked, db
from haprion_ui.api import caller, writing
from tests.test_api import ApiTestCase
from tests.test_api_blocks import BLOCKING, SHOP, held, status, stored
from tests.test_api_writing import IDEMPOTENT, a_job
from tests.test_login import configuration

PATH = "/api/v1/clusters/alpha/objects/shop/blocks"
ACTOR = f"token{':'}fail2ban"


def node(name: str, addresses: list[str], outcome: str = "done") -> dict[str, Any]:
    return {
        "node": name,
        "outcome": outcome,
        "message": None if outcome == "done" else "ssh: connection refused",
        "addresses": [
            {"address": address, "outcome": "done" if outcome == "done" else "failed"}
            for address in addresses
        ],
    }


def helper_answer(
    nodes: list[dict[str, Any]],
    *,
    outcome: str = "done",
    warnings: list[dict[str, Any]] | None = None,
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "ok": outcome == "done",
        "outcome": outcome,
        "operation": "dynamic_block",
        "cluster": "alpha",
        "request_id": "5a1c2b64-6f3f-4f3a-9c6e-1d2b3c4d5e6f",
        "result": {"object": "shop", "nodes": nodes},
        "warnings": warnings or [],
        "error": error,
    }


def refused_answer(code: str, message: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "ok": False,
        "outcome": "blocked",
        "operation": "dynamic_block",
        "cluster": "alpha",
        "request_id": "5a1c2b64-6f3f-4f3a-9c6e-1d2b3c4d5e6f",
        "result": None,
        "warnings": [],
        "error": {"code": code, "message": message, "node": None, "details": None},
    }


class BlockingTestCase(ApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.asked: list[tuple[Any, ...]] = []
        self.events: list[dict[str, Any]] = []
        self.queued: list[dict[str, Any]] = []
        self.answer: Any = lambda addresses: helper_answer(
            [node("node-a", addresses), node("node-b", addresses)]
        )
        self.raising: BaseException | None = None
        self.refusal: BaseException | None = None
        self.objects = stored(("shop", BLOCKING), ("intranet", SHOP))
        for patch in (
            mock.patch("haprion_ui.db.cluster_objects", side_effect=lambda *_a, **_k: self.objects),
            mock.patch("haprion_ui.db.cluster_statuses", return_value=[]),
            mock.patch("haprion.block_api_socket.ask", side_effect=self._ask),
            mock.patch("haprion_ui.db.record_audit_event", side_effect=self._event),
            mock.patch("haprion_ui.db.queue_job", side_effect=self._queue),
            mock.patch("haprion_ui.operations.prepare"),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def _ask(self, cluster: str, name: str, addresses: list[str], **keywords: Any) -> Any:
        self.asked.append((cluster, name, addresses, keywords["actor"], keywords["request_id"]))
        if self.raising is not None:
            raise self.raising
        return self.answer(addresses)

    def _event(self, _c: object, **values: Any) -> None:
        if self.refusal is not None:
            raise self.refusal
        self.events.append(values)

    def _queue(self, _c: object, **values: Any) -> db.Job:
        self.queued.append(values)
        return a_job(operation=values["operation"], cluster=values["cluster"])

    def client_with(self, *, writes: bool = True) -> Any:
        return self.client(
            replace(configuration(), clusters=("alpha", "beta"), management_writes=writes)
        )

    def place(
        self,
        secret: str,
        body: Any = None,
        *,
        path: str = PATH,
        writes: bool = True,
        method: str = "POST",
    ) -> Any:
        return self.client_with(writes=writes).request(
            method,
            path,
            json={"addresses": ["203.0.113.7"]} if body is None else body,
            headers={
                "Authorization": f"Bearer {secret}",
                writing.IDEMPOTENCY_HEADER: IDEMPOTENT,
            },
        )

    def blocker(self, **changes: Any) -> str:
        return self.issue(
            level="block", name="fail2ban", clusters=["alpha"], objects=["shop"], **changes
        )


class PlacingABlock(BlockingTestCase):
    def test_the_addresses_are_blocked_in_the_call_and_the_answer_says_how_long(self) -> None:
        response = self.place(self.blocker())

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(
            (body["ok"], body["outcome"], body["operation"], body["cluster"]),
            (True, "done", "object_block", "alpha"),
        )
        self.assertEqual(body["warnings"], [])
        self.assertEqual(
            body["result"],
            {
                "object": "shop",
                "block_for": "2h",
                "blocked": ["203.0.113.7"],
                "refused": [],
                "nodes": [
                    {
                        "node": name,
                        "outcome": "done",
                        "message": None,
                        "addresses": [{"address": "203.0.113.7", "outcome": "done"}],
                    }
                    for name in ("node-a", "node-b")
                ],
            },
        )
        (asked,) = self.asked
        self.assertEqual(asked[:4], ("alpha", "shop", ["203.0.113.7"], ACTOR))
        # One id for the call, the helper's request and the audit row.
        self.assertEqual(body["request_id"], asked[4])
        (event,) = self.events
        self.assertEqual(
            (event["actor"], event["action"], event["cluster"], str(event["request_id"])),
            (ACTOR, "api_block", "alpha", asked[4]),
        )
        self.assertEqual(
            event["detail"],
            {"via": "api", "object": "shop", "addresses": ["203.0.113.7"], "outcome": "done"},
        )
        self.assertEqual(self.queued, [])

    def test_no_job_and_no_key_are_needed(self) -> None:
        response = self.client_with().post(
            PATH,
            json={"addresses": ["203.0.113.7"]},
            headers={"Authorization": f"Bearer {self.blocker()}"},
        )
        self.assertEqual(response.status_code, 200, response.text)

    def test_an_address_is_written_as_the_nodes_write_it_and_once(self) -> None:
        response = self.place(
            self.blocker(), {"addresses": ["::ffff:203.0.113.7", "203.0.113.7", "2001:db8::7"]}
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.asked[0][2], ["203.0.113.7", "2001:db8::7"])

    def test_a_write_token_blocks_on_any_object_and_a_block_token_only_on_its_own(self) -> None:
        other = "/api/v1/clusters/alpha/objects/intranet/blocks"
        self.assertEqual(self.place(self.blocker(), path=other).status_code, 404)
        self.assertEqual(self.place(self.issue(level="write"), path=other).status_code, 200)
        self.assertEqual(len(self.asked), 1)

    def test_an_address_that_is_not_one_is_left_out_and_said(self) -> None:
        response = self.place(self.blocker(), {"addresses": ["203.0.113.7", "not-an-address"]})

        body = response.json()
        self.assertEqual(
            (response.status_code, body["outcome"], body["ok"]), (200, "partial", False)
        )
        self.assertEqual(self.asked[0][2], ["203.0.113.7"])
        self.assertEqual(
            body["result"]["refused"],
            [
                {
                    "address": "not-an-address",
                    "code": "address_invalid",
                    "reason": "not-an-address is not an IP address.",
                }
            ],
        )
        self.assertEqual([w["code"] for w in body["warnings"]], ["address_invalid"])
        self.assertEqual(self.events[0]["detail"]["refused"], ["not-an-address"])

    def test_an_address_with_a_zone_is_left_out_and_the_others_are_blocked(self) -> None:
        """Review 26-11-01, b-P2-1: the nodes refuse a zone, and it would stop every address."""

        zoned = "fe80::1%x\nblock shop in alpha: 198.51.100.1 for token:x"
        response = self.place(self.blocker(), {"addresses": ["203.0.113.7", zoned, "fe80::1%eth0"]})

        body = response.json()
        self.assertEqual((response.status_code, body["outcome"]), (200, "partial"))
        self.assertEqual(self.asked[0][2], ["203.0.113.7"])
        self.assertEqual(
            [(r["address"], r["code"]) for r in body["result"]["refused"]],
            [(zoned, "address_invalid"), ("fe80::1%eth0", "address_invalid")],
        )
        self.assertEqual(body["result"]["blocked"], ["203.0.113.7"])

    def test_a_token_name_that_fills_the_name_field_still_blocks(self) -> None:
        """Review 26-11-01, b-P3-3: `token:` and sixty-four characters are over what the helper takes."""

        name = "a" * 64
        secret = self.issue(level="block", name=name, clusters=["alpha"], objects=["shop"])
        self.assertEqual(self.place(secret).status_code, 200)
        self.assertEqual(self.asked[0][3], f"token{':'}{name}"[:64])
        self.assertEqual(self.events[0]["actor"], f"token{':'}{name}")

    def test_a_token_revoked_while_the_request_ran_places_no_block(self) -> None:
        """Review 26-11-01, b-P3-5: judged again right before the helper is asked."""

        secret = self.blocker()
        (digest,) = self.tokens
        live = self.tokens[digest]
        revoked = replace(live, revoked_at=datetime.now(UTC), revoked_by="admin")
        reads = iter([live, revoked])
        with (
            mock.patch("haprion_ui.db.api_token_by_hash", side_effect=lambda _c, _d: next(reads)),
            self.assertLogs("haprion_ui.api", "WARNING"),
        ):
            response = self.place(secret)
        self.assertEqual(response.status_code, 401)
        self.assertEqual((self.asked, self.events), ([], []))

    def test_a_block_whose_place_never_comes_back_is_still_recorded_and_answered(self) -> None:
        """Review 26-11-01, P3-4: the wait for a place is bounded, and the nodes already hold the block."""

        client = self.client_with()
        state = next(
            route.app.state
            for route in client.app.routes
            if getattr(route, "path", "") == "/api/v1"
        )
        taken: list[bool] = []

        def answered(addresses: list[str]) -> dict[str, Any]:
            # Other calls fill every place while the nodes are asked.
            while state.slots.acquire(blocking=False):
                taken.append(True)
            return helper_answer([node("node-a", addresses)])

        self.answer = answered
        headers = {"Authorization": f"Bearer {self.blocker()}"}
        with (
            mock.patch.object(caller, "PLACE_WAIT", 0.05),
            self.assertLogs("haprion_ui.api", "WARNING"),
        ):
            response = client.post(PATH, json={"addresses": ["203.0.113.7"]}, headers=headers)
        for _ in taken:
            state.slots.release()
        self.assertEqual((response.status_code, response.json()["outcome"]), (200, "done"))
        self.assertEqual([event["action"] for event in self.events], ["api_block"])
        self.assertEqual(state.slots._value, 3)

    def test_a_block_gives_its_place_back_while_the_nodes_are_asked(self) -> None:
        """Review 26-11-01, b-P3-4: ten to forty-five seconds with no connection held."""

        client = self.client_with()
        state = next(
            route.app.state
            for route in client.app.routes
            if getattr(route, "path", "") == "/api/v1"
        )
        free: list[int] = []

        def answered(addresses: list[str]) -> dict[str, Any]:
            free.append(state.slots._value)
            return helper_answer([node("node-a", addresses)])

        self.answer = answered
        headers = {"Authorization": f"Bearer {self.blocker()}"}
        body = {"addresses": ["203.0.113.7"]}
        self.assertEqual(client.post(PATH, json=body, headers=headers).status_code, 200)
        self.assertEqual(free, [state.slots._value], "all places free while the helper is asked")
        self.assertEqual(state.slots._value, 3, "the place is given back at the end")

        self.raising = block_api_socket.HelperSilent("The block service did not answer in time.")
        self.assertEqual(client.post(PATH, json=body, headers=headers).status_code, 504)
        self.assertEqual(state.slots._value, 3)

        taken = 0
        while state.helper_calls.acquire(blocking=False):
            taken += 1
        self.raising = None
        asked = len(self.asked)
        with self.assertLogs("haprion_ui.api", "WARNING"):
            busy = client.post(PATH, json=body, headers=headers)
        self.assertEqual((busy.status_code, busy.json()["error"]["code"]), (429, "busy"))
        self.assertEqual((len(self.asked), state.slots._value), (asked, 3))
        for _ in range(taken):
            state.helper_calls.release()

    def test_nothing_that_is_an_address_asks_no_node(self) -> None:
        response = self.place(self.blocker(), {"addresses": ["x", "y"]})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "bad_input")
        self.assertEqual((self.asked, self.events), ([], []))

    def test_an_exempt_address_is_refused_by_the_helper_and_the_rest_is_blocked(self) -> None:
        self.answer = lambda addresses: helper_answer(
            [node("node-a", addresses[1:]), node("node-b", addresses[1:])],
            outcome="partial",
            warnings=[
                {
                    "code": "address_exempt",
                    "message": "192.0.2.7: shop never blocks it, the object exempts it",
                    "node": None,
                    "details": {"address": "192.0.2.7"},
                }
            ],
        )

        response = self.place(self.blocker(), {"addresses": ["192.0.2.7", "203.0.113.7"]})

        body = response.json()
        self.assertEqual((response.status_code, body["outcome"]), (200, "partial"))
        self.assertEqual(body["result"]["blocked"], ["203.0.113.7"])
        self.assertEqual(
            body["result"]["refused"],
            [
                {
                    "address": "192.0.2.7",
                    "code": "address_exempt",
                    "reason": "192.0.2.7: shop never blocks it, the object exempts it",
                }
            ],
        )
        self.assertEqual(body["warnings"][0]["code"], "address_exempt")

    def test_a_node_that_did_not_take_it_is_partial_and_its_reason_is_a_write_token_s(self) -> None:
        self.answer = lambda addresses: helper_answer(
            [node("node-a", addresses), node("node-b", addresses, "failed")],
            outcome="partial",
            warnings=[
                {
                    "code": "node_block_failed",
                    "message": "ssh: connection refused",
                    "node": "node-b",
                    "details": None,
                }
            ],
        )

        blocking = self.place(self.blocker()).json()
        writing_token = self.place(self.issue(level="write", name="admin-key")).json()

        for body, said in (
            (blocking, "The node did not take the block."),
            (writing_token, "ssh: connection refused"),
        ):
            self.assertEqual(body["outcome"], "partial")
            self.assertEqual(body["result"]["blocked"], ["203.0.113.7"])
            self.assertEqual(body["warnings"][0]["node"], "node-b")
            self.assertEqual(body["warnings"][0]["message"], said)
            self.assertEqual(body["result"]["nodes"][1]["message"], said)
        self.assertEqual(self.events[0]["detail"]["outcome"], "partial")

    def test_no_node_taking_it_is_a_502_with_no_result(self) -> None:
        self.answer = lambda addresses: helper_answer(
            [node("node-a", addresses, "failed")],
            outcome="failed",
            warnings=[
                {"code": "node_block_failed", "message": "gone", "node": "node-a", "details": None}
            ],
            error={"code": "node_block_failed", "message": "no node placed the block"},
        )

        response = self.place(self.blocker())

        body = response.json()
        self.assertEqual(response.status_code, 502)
        self.assertEqual((body["ok"], body["outcome"], body["result"]), (False, "failed", None))
        self.assertEqual(body["error"]["code"], "blocking_failed")
        self.assertEqual(body["warnings"][0]["node"], "node-a")
        self.assertEqual(self.events[0]["detail"]["outcome"], "failed")

    def test_what_the_helper_refused_is_the_callers_or_the_installation_s(self) -> None:
        for code, said, status_code, api_code in (
            ("bad_input", "shop has no dynamic blocking in its newest version", 400, "bad_input"),
            ("server_not_found", "there is no object shop", 404, "not_found"),
            ("dependency_unavailable", "cannot read /srv/configs/alpha", 503, "unavailable"),
        ):
            with self.subTest(code=code):
                self.answer = lambda _a, code=code, said=said: refused_answer(code, said)
                response = self.place(self.blocker())
                self.assertEqual(response.status_code, status_code)
                self.assertEqual(response.json()["error"]["code"], api_code)
                self.assertNotIn("/srv", response.text)
        self.assertEqual(self.events, [])
        written = self.place(self.issue(level="write"))
        self.assertIn("/srv/configs/alpha", written.json()["error"]["message"])

    def test_a_service_that_cannot_be_asked_is_a_503_and_one_that_went_quiet_is_unknown(
        self,
    ) -> None:
        secret = self.blocker()
        self.raising = block_api_socket.HelperUnavailable("The block service is not running here.")
        with self.assertLogs("haprion_ui.api", "WARNING"):
            response = self.place(secret)
        self.assertEqual(
            (response.status_code, response.json()["error"]["code"]), (503, "unavailable")
        )
        self.assertEqual(self.events, [])

        self.raising = block_api_socket.HelperSilent("The block service did not answer in time.")
        response = self.place(secret)
        self.assertEqual(
            (response.status_code, response.json()["error"]["code"]), (504, "outcome_unknown")
        )
        self.assertEqual(self.events[0]["detail"]["outcome"], "unknown")

        self.raising = block_api_socket.HelperBusy("dropped")
        with self.assertLogs("haprion_ui.api", "WARNING") as logged:
            response = self.place(secret)
        self.assertIn("dropped the connection before answering", logged.output[0])
        self.assertIn("ended before it read", logged.output[0])
        self.assertEqual((response.status_code, response.json()["error"]["code"]), (429, "busy"))
        self.assertEqual(response.headers["retry-after"], "1")
        self.assertEqual(len(self.events), 1)

    def test_an_audit_row_that_cannot_be_written_does_not_hide_a_block_that_was_placed(
        self,
    ) -> None:
        self.refusal = RuntimeError("the database went away")
        with self.assertLogs("haprion_ui.api", "ERROR"):
            response = self.place(self.blocker())
        self.assertEqual((response.status_code, response.json()["outcome"]), (200, "done"))

    def test_the_default_time_is_the_engine_s_for_an_object_that_sets_none(self) -> None:
        self.objects = stored(("shop", SHOP))
        self.assertEqual(self.place(self.blocker()).json()["result"]["block_for"], "30m")


class TheRequestIsChecked(BlockingTestCase):
    def test_a_token_below_block_is_forbidden_and_one_outside_its_scope_gets_a_404(self) -> None:
        self.assertEqual(self.place(self.issue(level="read")).status_code, 403)
        for scope in ({"clusters": ["beta"]}, {"objects": ["intranet"]}):
            with self.subTest(scope=scope):
                response = self.place(self.issue(level="block", **{"objects": ["shop"], **scope}))
                self.assertEqual(
                    (response.status_code, response.json()["error"]["code"]), (404, "not_found")
                )
        self.assertEqual(self.asked, [])

    def test_a_cluster_that_is_not_there_is_a_404_before_anything_is_asked(self) -> None:
        response = self.place(
            self.issue(level="write"), path="/api/v1/clusters/gamma/objects/shop/blocks"
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.asked, [])

    def test_a_body_that_is_not_a_list_of_one_to_the_limit_is_a_400(self) -> None:
        secret = self.blocker()
        bodies: list[dict[str, Any]] = [
            {},
            {"addresses": []},
            {"addresses": "203.0.113.7"},
            {"addresses": [7]},
            {"addresses": ["203.0.113.7"] * 65},
            {"addresses": ["x" * 65]},
            {"addresses": ["203.0.113.7"], "all": True},
        ]
        for body in bodies:
            with self.subTest(body=str(body)[:40]):
                response = self.place(secret, body)
                self.assertEqual(
                    (response.status_code, response.json()["error"]["code"]), (400, "bad_input")
                )
        self.assertEqual(self.place(secret, {"addresses": ["203.0.113.7"] * 64}).status_code, 200)
        self.assertEqual(self.asked[-1][2], ["203.0.113.7"])

    def test_a_block_is_placed_with_writes_off(self) -> None:
        """B419: a block publishes nothing; only lifting it waits for writes."""

        response = self.place(self.blocker(), writes=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.asked[-1][2], ["203.0.113.7"])


class ReadingOwnBlocks(BlockingTestCase):
    def setUp(self) -> None:
        super().setUp()
        patch = mock.patch(
            "haprion_ui.db.cluster_statuses",
            return_value=status(
                datetime.now(UTC), ("node-a", {"shop": held(1, ("192.0.2.7", 600_000))})
            ),
        )
        patch.start()
        self.addCleanup(patch.stop)

    def read(self, secret: str, name: str = "shop") -> Any:
        return self.client_with().get(
            f"/api/v1/clusters/alpha/objects/{name}/blocks",
            headers={"Authorization": f"Bearer {secret}"},
        )

    def test_a_block_token_reads_the_blocks_of_its_own_object_as_a_read_token_does(self) -> None:
        mine = self.read(self.blocker())
        theirs = self.read(self.issue(level="read"))
        self.assertEqual(mine.status_code, 200, mine.text)
        self.assertEqual(mine.json()["result"]["addresses"][0]["address"], "192.0.2.7")

        # `seconds_left` counts down between the two calls; the rest is the same answer.
        def steady(response: Any) -> list[dict[str, Any]]:
            return [
                {key: value for key, value in entry.items() if key != "seconds_left"}
                for entry in response.json()["result"]["addresses"]
            ]

        self.assertEqual(steady(mine), steady(theirs))

    def test_a_block_token_does_not_read_an_object_that_is_not_its_own(self) -> None:
        response = self.read(self.blocker(), "intranet")
        self.assertEqual(
            (response.status_code, response.json()["error"]["code"]), (404, "not_found")
        )
        self.assertEqual(self.read(self.issue(level="write"), "intranet").status_code, 200)


class LiftingABlock(BlockingTestCase):
    def lift(self, secret: str, body: Any = None, **keywords: Any) -> Any:
        return self.place(secret, body, method="DELETE", **keywords)

    def test_it_is_the_job_the_page_queues_for_unblock_answered_202(self) -> None:
        response = self.lift(
            self.issue(level="write", name="fail2ban"),
            {"addresses": ["203.0.113.7", "2001:db8::7"]},
        )

        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(response.headers["location"], "/api/v1/jobs/41")
        body = response.json()
        self.assertEqual((body["operation"], body["cluster"]), ("object_unblock", "alpha"))
        self.assertEqual(body["result"]["follow"], "/api/v1/jobs/41")
        (queued,) = self.queued
        # What the Unblock button queues for the same ticks, from the same builder.
        payload = blocked.unblock_payload("shop", ["203.0.113.7", "2001:db8::7"])
        self.assertEqual(
            (queued["operation"], queued["cluster"], queued["payload"], queued["idempotency_key"]),
            ("dynamic_unblock", "alpha", payload, UUID(IDEMPOTENT)),
        )
        self.assertEqual(payload, {"object": "shop", "addresses": ["203.0.113.7", "2001:db8::7"]})
        (event,) = self.events
        self.assertEqual((event["actor"], event["action"]), (ACTOR, "queue_job"))
        self.assertEqual(
            event["detail"],
            {
                "operation": "dynamic_unblock",
                "job": 41,
                "via": "api",
                "object": "shop",
                "addresses": ["203.0.113.7", "2001:db8::7"],
            },
        )

    def test_below_write_and_outside_the_scope_nothing_is_queued(self) -> None:
        for level in ("read", "block"):
            self.assertEqual(self.lift(self.issue(level=level)).status_code, 403)
        for scope in ({"clusters": ["beta"]}, {"objects": ["intranet"]}):
            response = self.lift(self.issue(level="write", **scope))
            self.assertEqual(response.status_code, 404)
        response = self.lift(
            self.issue(level="write"), path="/api/v1/clusters/gamma/objects/shop/blocks"
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.queued, [])

    def test_a_bad_body_a_missing_key_and_writes_off_are_refused(self) -> None:
        secret = self.issue(level="write")
        bad: list[dict[str, Any]] = [{}, {"addresses": []}, {"addresses": ["203.0.113.7"] * 65}]
        for body in bad:
            self.assertEqual(self.lift(secret, body).status_code, 400)
        response = self.client_with().request(
            "DELETE",
            PATH,
            json={"addresses": ["203.0.113.7"]},
            headers={"Authorization": f"Bearer {secret}"},
        )
        self.assertEqual(response.status_code, 400)
        off = self.lift(secret, writes=False)
        self.assertEqual((off.status_code, off.json()["error"]["code"]), (403, "writes_off"))
        self.assertEqual(self.queued, [])
