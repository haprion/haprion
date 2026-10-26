from __future__ import annotations

import unittest
from uuid import UUID

from haprion_ui.views import _publish_key

DRAWN = UUID("00000000-0000-4000-8000-000000000001")


class TheKeyIsTheRequest(unittest.TestCase):
    """One key, one request. The queue depends on it and could not enforce it.

    A repeated key is treated as a retry only when the payload hashes the same,
    so a key derived from less than the payload can be handed two different
    requests - and the second is refused with "already asked for with different
    content", permanently, for a publish somebody is looking at.
    """

    def payload(self, **overrides: object) -> dict[str, object]:
        body: dict[str, object] = {
            "objects": {"shop": "schema: 1\n"},
            "expected_head": "a" * 40,
            "comment": "Publish shop",
            "drafts": [{"id": "11111111-2222-3333-4444-555555555555", "revision": 1}],
        }
        body.update(overrides)
        return body

    def key(self, **overrides: object) -> object:
        return _publish_key("alpha", "changes_publish", self.payload(**overrides), drawn=DRAWN)

    def test_the_same_request_asked_twice_is_one_key(self) -> None:
        self.assertEqual(self.key(), self.key())

    def test_a_moved_head_is_a_different_request(self) -> None:
        #
        # This is the one that blocked a publish for good. The document was
        # unchanged, so the key was unchanged, while `expected_head` in the
        # payload was not - one key with two contents, and the queue refused
        # the second every time it was tried.
        #
        self.assertNotEqual(self.key(), self.key(expected_head="b" * 40))

    def test_every_field_of_the_payload_moves_the_key(self) -> None:
        for field, value in (
            ("objects", {"shop": "schema: 1\nname: changed\n"}),
            ("comment", "Publish shop again"),
            ("draft", {"id": "11111111-2222-3333-4444-555555555555", "revision": 2}),
            ("allow_certificate_mismatch", True),
        ):
            with self.subTest(field=field):
                self.assertNotEqual(self.key(), self.key(**{field: value}))

    def test_the_cluster_and_the_operation_are_part_of_it(self) -> None:
        body = self.payload()

        self.assertNotEqual(
            _publish_key("alpha", "changes_publish", body, drawn=DRAWN),
            _publish_key("beta", "changes_publish", body, drawn=DRAWN),
        )
        self.assertNotEqual(
            _publish_key("alpha", "changes_publish", body, drawn=DRAWN),
            _publish_key("alpha", "revert", body, drawn=DRAWN),
        )

    def test_a_form_drawn_again_is_a_new_request(self) -> None:
        """Review 26-10-22, 1B-1: a publish that failed kept its job and so its key, and
        the same list sent again from a fresh page was answered with the old job."""

        body = self.payload()
        again = UUID("00000000-0000-4000-8000-000000000002")

        self.assertNotEqual(
            _publish_key("alpha", "changes_publish", body, drawn=DRAWN),
            _publish_key("alpha", "changes_publish", body, drawn=again),
        )

    def test_the_order_a_payload_was_built_in_is_not_part_of_the_request(self) -> None:
        forwards = dict(self.payload())
        backwards = {key: forwards[key] for key in reversed(list(forwards))}

        self.assertEqual(
            _publish_key("alpha", "changes_publish", forwards, drawn=DRAWN),
            _publish_key("alpha", "changes_publish", backwards, drawn=DRAWN),
        )


if __name__ == "__main__":
    unittest.main()
