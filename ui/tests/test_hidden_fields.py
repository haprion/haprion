"""What the form hides for a protocol is what `build_document` leaves out (26-10-06).

Two lists kept by hand: the template's `data-show-when` on the page, and
`preview.HIDDEN_FOR`, which empties the same fields before the document is
built. A field hidden on the page but not in the list is sent anyway, and the
engine refuses the object for text the person can no longer see (the hostnames
of 26-10-06). A field in the list but shown on the page drops what somebody
typed without a word. Neither can be told apart by reading one side, so the page
is rendered and the two are compared.
"""

from __future__ import annotations

from html.parser import HTMLParser
from unittest import mock

from haproxy_ui.preview import HIDDEN_FOR
from tests.test_dns_form import node, status
from tests.test_editor_page import EditorTestCase

#
# Fields hidden with their protocol that need no entry of their own: each is
# written only beside the field named, which is in `HIDDEN_FOR`, or - the access
# rules - only for http and https (`build_document`).
#
DEPENDENT = {
    "hsts_max_age": "hsts",
    "hsts_subdomains": "hsts",
    "redirect_match": "redirect_path",
    "redirect_status": "redirect_path",
    "deny_mode": "deny_from",
    "rule_header": "access rules",
    "rule_header_match": "access rules",
    "rule_header_value": "access rules",
    "rule_match": "access rules",
    "rule_methods": "access rules",
    "rule_mode": "access rules",
    "rule_name": "access rules",
    "rule_negate": "access rules",
    "rule_path": "access rules",
    "rule_source": "access rules",
}

VOID = {"input", "br", "img", "hr", "meta", "link", "source", "wbr", "area", "base", "col"}


class _Fields(HTMLParser):
    """Each named control, and whether the page hides it, and whether for the protocol."""

    def __init__(self, protocol: str) -> None:
        super().__init__()
        self.protocol = protocol
        self.stack: list[tuple[str, bool, bool]] = []
        self.hidden: dict[str, bool] = {}
        self.by_protocol: dict[str, bool] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        found = dict(attrs)
        condition = found.get("data-show-when") or ""
        here_protocol = (
            condition.startswith("protocol:")
            and self.protocol not in condition.split(":", 1)[1].split()
        )
        here = "hidden" in found
        above, above_protocol = (
            (self.stack[-1][1], self.stack[-1][2]) if self.stack else (False, False)
        )
        hidden, protocol = above or here, above_protocol or here_protocol
        name = found.get("name")
        if tag in ("input", "select", "textarea") and name and found.get("type") != "hidden":
            self.hidden[name] = self.hidden.get(name, True) and hidden
            self.by_protocol[name] = self.by_protocol.get(name, True) and protocol
        if tag not in VOID:
            self.stack.append((tag, hidden, protocol))

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                return


class TheFormHidesWhatTheDocumentLeavesOut(EditorTestCase):
    def fields(self, protocol: str) -> _Fields:
        client = self.editor()
        with mock.patch("haproxy_ui.db.cluster_statuses", return_value=[status(node("node-a"))]):
            text = str(
                self.submit(
                    client,
                    "/proxies/alpha/shop/edit",
                    action="check",
                    protocol=protocol,
                    hostnames="",
                ).text
            )
        parsed = _Fields(protocol)
        parsed.feed(text)
        return parsed

    def test_every_field_hidden_for_a_protocol_is_left_out(self) -> None:
        for protocol in HIDDEN_FOR:
            with self.subTest(protocol=protocol):
                parsed = self.fields(protocol)
                hidden = {name for name, flag in parsed.by_protocol.items() if flag}
                self.assertEqual(hidden - set(HIDDEN_FOR[protocol]) - set(DEPENDENT), set())

    def test_nothing_left_out_is_shown(self) -> None:
        for protocol, names in HIDDEN_FOR.items():
            with self.subTest(protocol=protocol):
                parsed = self.fields(protocol)
                shown = {name for name in names if parsed.hidden.get(name) is False}
                self.assertEqual(shown, set())
