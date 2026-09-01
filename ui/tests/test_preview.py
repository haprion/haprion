"""The configuration preview: a form in, an object and a configuration out.

The page exists so that the shape of an object can be judged before any of it
is published, which is how this project decides what belongs in the model at
all. Nothing here writes: the value of the tests below is that the page's
answer is the engine's answer, not a second opinion the interface formed on its
own.
"""

from __future__ import annotations

import re
import unittest

from haproxy_ui.preview import (
    DEFAULTS,
    PREVIEW_CLUSTER,
    build_document,
    preview,
    suggested_cookie,
)
from tests.test_login import LoginTestCase


def form(**overrides: object) -> dict[str, object]:
    return dict(DEFAULTS) | {"certificate": "wildcard-example-com"} | overrides


class TheFormBecomesTheObjectTheEngineReads(unittest.TestCase):
    def test_the_document_is_what_would_be_stored(self) -> None:
        result = preview(form(), PREVIEW_CLUSTER)

        self.assertIsNone(result.problem)
        self.assertIn("schema: 1", result.document)
        self.assertIn("certificate: wildcard-example-com", result.document)
        self.assertEqual(sorted(result.files), ["1000-frontends.cfg", "1001-app.cfg"])

    def test_the_generated_configuration_is_the_engine_s(self) -> None:
        result = preview(form(hsts=True, hsts_subdomains=True), PREVIEW_CLUSTER)

        frontends = result.files["1000-frontends.cfg"]
        self.assertIn("bind 192.0.2.20:443 ssl crt", frontends)
        self.assertIn("alpn h2,http/1.1", frontends)
        self.assertIn("redirect scheme https code 301", frontends)
        self.assertIn(
            'Strict-Transport-Security "max-age=31536000; includeSubDomains"',
            result.files["1001-app.cfg"],
        )

    def test_a_refusal_is_the_engine_s_words_not_ours(self) -> None:
        """The page must not have its own opinion about what is valid.

        If it did, somebody would be told their object is fine here and find
        out otherwise during a publish - which is the failure this preview is
        supposed to prevent.
        """

        result = preview(form(certificate="not-issued"), PREVIEW_CLUSTER)

        self.assertIsNotNone(result.problem)
        self.assertIn("not-issued", str(result.problem))
        self.assertIn("schema: 1", result.document)

    def test_a_server_line_that_is_not_a_host_and_port_says_so(self) -> None:
        result = preview(form(servers="not a server"), PREVIEW_CLUSTER)

        self.assertIn("host and port", str(result.problem))

    def test_a_hostname_is_never_pasted_into_yaml_as_text(self) -> None:
        """The document is dumped from data, so a typed value cannot be syntax.

        A form field is not trusted to be safe YAML, and hand-quoting it is how
        an input ends up changing the structure of the document rather than a
        value in it.
        """

        document = build_document(form(name="app", hostnames="a.example.com\\nb: evil"))

        self.assertNotIn("\\nb: evil\\n", document.replace("  ", ""))
        self.assertIn("schema: 1", document)


class ThePageIsReachableAndWritesNothing(LoginTestCase):
    def test_the_form_is_rendered_for_a_signed_in_user(self) -> None:
        client = self.client()
        self.sign_in(client)

        page = client.get("/proxies/preview")

        self.assertEqual(page.status_code, 200)
        self.assertIn('action="/proxies/preview"', page.text)
        self.assertIn("Example cluster", page.text)

    def test_signing_in_is_required(self) -> None:
        page = self.client().get("/proxies/preview", follow_redirects=False)

        self.assertEqual(page.status_code, 303)
        self.assertEqual(page.headers["location"], "/login")

    def test_a_post_without_a_token_is_refused(self) -> None:
        client = self.client()
        self.sign_in(client)

        refused = client.post("/proxies/preview", data={"name": "app"})

        self.assertEqual(refused.status_code, 403)

    def test_a_submitted_form_renders_the_configuration(self) -> None:
        client = self.client()
        self.sign_in(client)
        page = client.get("/proxies/preview")
        token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page.text)
        if token is None:
            self.fail("the form did not render a CSRF token")

        submitted = client.post(
            "/proxies/preview",
            data={
                "csrf_token": token.group(1),
                "name": "app",
                "hostnames": "app.example.com",
                "protocol": "https",
                "certificate": "wildcard-example-com",
                "balance": "roundrobin",
                "servers": "198.51.100.10:8080",
                "health_type": "disabled",
            },
        )

        self.assertEqual(submitted.status_code, 200)
        self.assertIn("frontend mgd-internal-https", submitted.text)
        self.assertIn("backend mgd-app-web", submitted.text)


if __name__ == "__main__":
    unittest.main()


class TheFieldsAddedAfterTheFirstLook(unittest.TestCase):
    """What the maintainer asked for once the page existed.

    Each of these is a field somebody wanted the moment they saw the form,
    which is the whole reason the page was built before the rest of the model.
    """

    def test_addresses_may_be_written_straight_into_the_object(self) -> None:
        """A range belonging to one site has no business being named cluster-wide."""

        result = preview(form(allow_ranges="198.51.100.0/24\n203.0.113.10"), PREVIEW_CLUSTER)

        self.assertIsNone(result.problem)
        self.assertIn("198.51.100.0/24", result.document)
        self.assertIn(
            "acl mgd-app-allow src 198.51.100.0/24 203.0.113.10/32",
            result.files["1000-frontends.cfg"],
        )

    def test_a_group_and_an_address_may_be_used_together(self) -> None:
        result = preview(form(allow_from=("office",), allow_ranges="203.0.113.10"), PREVIEW_CLUSTER)

        self.assertIn(
            "acl mgd-app-allow src 198.51.100.0/24 203.0.113.10/32",
            result.files["1000-frontends.cfg"],
        )

    def test_the_health_check_may_answer_on_its_own_port(self) -> None:
        result = preview(form(health_port="8413"), PREVIEW_CLUSTER)

        self.assertIn("check port 8413", result.files["1001-app.cfg"])

    def test_no_port_means_the_server_s_own(self) -> None:
        result = preview(form(), PREVIEW_CLUSTER)

        self.assertNotIn("check port", result.files["1001-app.cfg"])
        self.assertIn("check inter", result.files["1001-app.cfg"])

    def test_a_port_that_is_not_a_number_says_so(self) -> None:
        result = preview(form(health_port="eight"), PREVIEW_CLUSTER)

        self.assertIn("port must be a number", str(result.problem))

    def test_the_suggested_cookie_name_carries_the_object_s_name(self) -> None:
        self.assertEqual(suggested_cookie("shop"), "hap_shop")
        self.assertEqual(suggested_cookie(""), "hap_site")


class TheSourceAddressMayBeChosen(unittest.TestCase):
    """A VIP carries a default source; it is not a rule.

    HAProxy takes the source address per backend, so an object may leave on a
    different address than the one it arrived on. Most never do, which is why
    the VIP still carries a default and this is the exception that has to be
    named.
    """

    def test_the_vip_s_own_source_is_used_when_nothing_is_chosen(self) -> None:
        result = preview(form(vip="internal"), PREVIEW_CLUSTER)

        self.assertIn("source 192.0.2.25", result.files["1001-app.cfg"])

    def test_a_named_source_overrides_it(self) -> None:
        result = preview(form(vip="internal", source="outbound"), PREVIEW_CLUSTER)

        self.assertIn("source 192.0.2.35", result.files["1001-app.cfg"])
        self.assertIn("source: outbound", result.document)

    def test_everywhere_is_not_a_group_name(self) -> None:
        """The `Everywhere` option submits an empty value, which must not be a group."""

        result = preview(form(allow_from=("",)), PREVIEW_CLUSTER)

        self.assertIsNone(result.problem)
        self.assertNotIn("allow_from", result.document)
        self.assertNotIn("http-request deny", result.files["1000-frontends.cfg"])


class ARefusalNamesTheFieldItIsAbout(unittest.TestCase):
    def test_the_field_is_separated_from_the_sentence(self) -> None:
        result = preview(form(certificate=""), PREVIEW_CLUSTER)

        self.assertEqual(result.problem_field, "app.listen.certificate")
        self.assertEqual(result.problem_text, "is required for https")

    def test_a_refusal_without_a_field_is_shown_whole(self) -> None:
        result = preview(form(servers="not a server"), PREVIEW_CLUSTER)

        self.assertEqual(result.problem_field, "")
        self.assertEqual(result.problem_text, str(result.problem))
