"""The object form's folded groups: every field somewhere, and a line saying what each holds."""

from __future__ import annotations

import unittest

from haprion_ui.form_groups import ALWAYS_SHOWN, CARRIED, GROUPS, form_groups
from haprion_ui.preview import DEFAULTS


def form(**overrides: object) -> dict[str, object]:
    return dict(DEFAULTS) | overrides


class EveryFieldHasExactlyOnePlace(unittest.TestCase):
    """A field added to the form and to neither list would be drawn nowhere."""

    def test_the_groups_and_the_short_list_cover_the_form_once(self) -> None:
        placed = [
            *ALWAYS_SHOWN,
            *CARRIED,
            *(field for group in GROUPS.values() for field in group.fields),
        ]

        self.assertEqual(sorted(placed), sorted(set(placed)), "a field sits in two places")
        self.assertEqual(set(placed), set(DEFAULTS))


class TheClosedLineSaysWhatTheGroupHolds(unittest.TestCase):
    def test_the_rate_limit_is_read_with_its_default_window(self) -> None:
        self.assertEqual(
            form_groups(form(rate_limit="5"))["access"].summary,
            "From everywhere · at most 5 per 10s",
        )

    def test_a_redirect_names_where_it_goes(self) -> None:
        summary = form_groups(
            form(redirect_path="/old", redirect_location="https://example.net/new")
        )["redirect"].summary

        self.assertEqual(summary, "/old → https://example.net/new (301)")

    def test_a_server_timeout_is_named_on_the_closed_line(self) -> None:
        summary = form_groups(form(server_timeout="5m"))["connections"].summary

        self.assertIn("server timeout 5m", summary)

    def test_empty_groups_say_so(self) -> None:
        states = form_groups(form())

        self.assertEqual(states["headers"].summary, "None")
        self.assertEqual(states["timing"].summary, "Defaults")


class TheAccessGroupSaysWhatItsRulesDo(unittest.TestCase):
    """Fas 21: yellow for what only looks, red for what refuses."""

    def test_rules_and_the_deny_list_are_counted_by_mode(self) -> None:
        state = form_groups(
            {
                "rule_mode": ["deny", "log"],
                "deny_ranges": "203.0.113.0/24",
                "deny_mode": "log",
            }
        )["access"]

        self.assertEqual(
            [(badge.text, badge.kind) for badge in state.badges],
            [("2 logging", "warning"), ("1 denying", "critical")],
        )

    def test_an_object_without_rules_shows_no_badge(self) -> None:
        self.assertEqual(form_groups({})["access"].badges, ())
