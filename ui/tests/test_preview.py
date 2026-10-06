"""The form's whole path: fields in, an object and a configuration out.

There was a preview page once, and it is gone (B73) - the editor does the same
thing against the cluster's real addresses. What the page left behind is the
example cluster, and these tests, which are the reason to keep it: they run the
form's entire path without standing up a cluster, and every one of them says
that the answer is the engine's answer rather than a second opinion the
interface formed on its own.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

import yaml

from haproxy_ui.preview import (
    DEFAULTS,
    PREVIEW_CLUSTER,
    Unexpressible,
    build_document,
    form_from_document,
    preview,
    suggested_cookie,
)


def form(**overrides: object) -> dict[str, object]:
    #
    # A hostname is supplied here rather than taken from `DEFAULTS`. The form
    # deliberately opens with that field empty so the placeholder can show what
    # several names look like, and a prefilled value is one that can be saved
    # by not being looked at - but every object below has to have one.
    #
    return (
        dict(DEFAULTS)
        | {"hostnames": "app.example.com", "certificate": "wildcard-example-com"}
        | overrides
    )


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


class ThePageIsGone(unittest.TestCase):
    """The preview page was removed once the editor did the same job better.

    Kept as one case rather than deleted outright: the route answered without
    `management_writes`, which made it the one form a read-only installation
    could show. Somebody will reasonably wonder where it went, and a test that
    names the removal is a better answer than a 404.
    """

    def test_the_route_no_longer_exists(self) -> None:
        from haproxy_ui import views

        self.assertFalse(
            [name for name in dir(views) if "preview_page" in name or "preview_form" in name]
        )


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
        result = preview(form(health_type="http", health_port="8413"), PREVIEW_CLUSTER)

        self.assertIn("check port 8413", result.files["1001-app.cfg"])

    def test_no_port_means_the_server_s_own(self) -> None:
        result = preview(form(health_type="http"), PREVIEW_CLUSTER)

        self.assertNotIn("check port", result.files["1001-app.cfg"])
        self.assertIn("check inter", result.files["1001-app.cfg"])

    def test_a_port_that_is_not_a_number_says_so(self) -> None:
        result = preview(form(health_type="http", health_port="eight"), PREVIEW_CLUSTER)

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
        #
        # Named for the object's own allowlist rather than any deny: the
        # cluster's abuse brake writes denies of its own, and they are not what
        # this is about.
        #
        self.assertNotIn("mgd-app-allow", result.files["1000-frontends.cfg"])


class ARefusalNamesTheFieldItIsAbout(unittest.TestCase):
    def test_the_field_is_separated_from_the_sentence(self) -> None:
        result = preview(form(certificate=""), PREVIEW_CLUSTER)

        self.assertEqual(result.problem_field, "app.listen.certificate")
        self.assertEqual(result.problem_text, "is required for https")

    def test_a_refusal_without_a_field_is_shown_whole(self) -> None:
        result = preview(form(servers="not a server"), PREVIEW_CLUSTER)

        self.assertEqual(result.problem_field, "")
        self.assertEqual(result.problem_text, str(result.problem))


class MaintenanceIsAStateOfTheObject(unittest.TestCase):
    """The checkbox produces a `maintenance` block, and nothing else moves."""

    def test_the_message_reaches_both_the_object_and_the_configuration(self) -> None:
        result = preview(
            form(maintenance=True, maintenance_message="Back at 18:00."), PREVIEW_CLUSTER
        )

        self.assertIsNone(result.problem)
        self.assertIn("message: Back at 18:00.", result.document)
        self.assertIn('string "Back at 18:00."', result.files["1000-frontends.cfg"])

    def test_an_unticked_box_writes_no_block_at_all(self) -> None:
        result = preview(form(maintenance_message="Back at 18:00."), PREVIEW_CLUSTER)

        self.assertNotIn("maintenance", result.document)

    def test_a_ticked_box_without_a_message_is_refused_by_the_engine(self) -> None:
        """Not defaulted by the form: what a visitor is told is not this page's to decide."""

        result = preview(form(maintenance=True), PREVIEW_CLUSTER)

        self.assertEqual(result.problem_field, "app.maintenance.message")


class TheAnswerWhenNoServerAnswers(unittest.TestCase):
    """A message rather than a checkbox: writing one is what turns it on."""

    def test_the_message_reaches_the_backend(self) -> None:
        result = preview(form(unavailable_message="The shop is not answering."), PREVIEW_CLUSTER)

        self.assertIsNone(result.problem)
        self.assertIn(
            'http-error status 503 content-type text/plain string "The shop is not answering."',
            result.files["1001-app.cfg"],
        )

    def test_an_empty_field_leaves_haproxy_s_own_text(self) -> None:
        result = preview(form(), PREVIEW_CLUSTER)

        self.assertNotIn("http-error", result.files["1001-app.cfg"])


class TheSiteNameCanBeAskedForRatherThanTyped(unittest.TestCase):
    def test_the_token_reaches_the_configuration_as_the_site_s_name(self) -> None:
        result = preview(
            form(unavailable_message="The site %URL% is not answering."), PREVIEW_CLUSTER
        )

        self.assertIsNone(result.problem)
        self.assertIn("message: The site %URL% is not answering.", result.document)
        self.assertIn(
            'string "The site app.example.com is not answering."', result.files["1001-app.cfg"]
        )

    def test_a_message_that_starts_with_the_token_is_written_so_it_can_be_read_back(self) -> None:
        """YAML gives `%` a meaning at the start of a scalar, and only there.

        The dumper quotes it and the parser accepts it again, which is what
        keeps the document the interface writes and the document somebody
        writes by hand the same document.
        """

        result = preview(form(unavailable_message="%URL% is not answering."), PREVIEW_CLUSTER)

        self.assertIsNone(result.problem)
        self.assertIn("'%URL% is not answering.'", result.document)
        self.assertIn('string "app.example.com is not answering."', result.files["1001-app.cfg"])

    def test_a_token_nobody_fills_in_is_refused_before_it_reaches_a_visitor(self) -> None:
        result = preview(form(unavailable_message="The site %SITE% is down."), PREVIEW_CLUSTER)

        self.assertEqual(result.problem_field, "app.unavailable.message")


class BoundingWhatOneServerIsHanded(unittest.TestCase):
    def test_a_limit_reaches_the_server_line_and_bounds_the_queue(self) -> None:
        result = preview(form(max_connections="50"), PREVIEW_CLUSTER)

        self.assertIsNone(result.problem)
        self.assertIn(" maxconn 50", result.files["1001-app.cfg"])
        self.assertIn("timeout queue 5s", result.files["1001-app.cfg"])

    def test_a_ramp_reaches_the_server_line(self) -> None:
        result = preview(form(health_type="http", slow_start="30s"), PREVIEW_CLUSTER)

        self.assertIsNone(result.problem)
        self.assertIn(" slowstart 30s", result.files["1001-app.cfg"])

    def test_a_limit_that_is_not_a_number_is_named_before_the_engine_sees_it(self) -> None:
        result = preview(form(max_connections="fifty"), PREVIEW_CLUSTER)

        self.assertIsNotNone(result.problem)


class TheClusterWideRulesAreVisibleInThePreview(unittest.TestCase):
    """The page shows the whole frontend, not only the object's part of it."""

    def test_the_forwarded_headers_are_written_before_any_routing(self) -> None:
        frontends = preview(form(), PREVIEW_CLUSTER).files["1000-frontends.cfg"]

        self.assertIn("http-request del-header X-Forwarded-For", frontends)
        self.assertIn("set-header X-Forwarded-Proto https", frontends)

    def test_the_abuse_brake_is_written_with_its_thresholds(self) -> None:
        frontends = preview(form(), PREVIEW_CLUSTER).files["1000-frontends.cfg"]

        self.assertIn("stick-table type ip", frontends)
        self.assertIn("sc_http_req_rate(0) gt 100", frontends)


class HeaderEditsAreWrittenAsLines(unittest.TestCase):
    """One line per edit, in the three shapes the note describes."""

    def test_the_three_shapes_become_the_three_actions(self) -> None:
        result = preview(
            form(request_headers="X-Tenant: acme\n+X-Trace: 1\n-X-Debug"), PREVIEW_CLUSTER
        )

        self.assertIsNone(result.problem)
        backend = result.files["1001-app.cfg"]
        self.assertIn("http-request set-header X-Tenant 'acme'", backend)
        self.assertIn("http-request add-header X-Trace '1'", backend)
        self.assertIn("http-request del-header X-Debug", backend)

    def test_the_response_direction_is_separate(self) -> None:
        result = preview(response_headers_form(), PREVIEW_CLUSTER)

        self.assertIn("http-response del-header Server", result.files["1001-app.cfg"])

    def test_a_line_that_is_not_an_edit_is_named_before_the_engine_sees_it(self) -> None:
        result = preview(form(request_headers="X-Tenant acme"), PREVIEW_CLUSTER)

        self.assertIsNotNone(result.problem)

    def test_a_forwarded_header_is_refused_by_the_engine(self) -> None:
        result = preview(form(request_headers="X-Forwarded-For: 203.0.113.1"), PREVIEW_CLUSTER)

        self.assertEqual(result.problem_field, "app.headers.request.set")


def response_headers_form() -> dict[str, object]:
    return form(response_headers="X-Frame-Options: DENY\n-Server")


class ARouteMayRedirect(unittest.TestCase):
    def test_the_redirect_becomes_a_backend_of_its_own(self) -> None:
        result = preview(
            form(
                redirect_path="/old",
                redirect_location="https://example.net/new",
                redirect_status="308",
            ),
            PREVIEW_CLUSTER,
        )

        self.assertIsNone(result.problem)
        self.assertIn(
            "http-request redirect location 'https://example.net/new' code 308",
            result.files["1001-app.cfg"],
        )

    def test_a_path_without_a_location_is_named_before_the_engine_sees_it(self) -> None:
        result = preview(form(redirect_path="/old"), PREVIEW_CLUSTER)

        self.assertIsNotNone(result.problem)

    def test_a_site_root_may_redirect_while_the_rest_of_the_site_proxies(self) -> None:
        """The shape the redirect field was not first written for.

        An application whose front page is somewhere other than `/` - the entry
        point is `/web/admin/login`, and `/` answers with a redirect to it -
        while every other address still reaches the backend. It only works as an
        exact match: as a prefix, the redirect on `/` would cover the address
        it points at and the browser would follow it forever.
        """

        result = preview(
            form(
                redirect_path="/",
                redirect_match="exact",
                redirect_location="https://app.example.com/web/admin/login",
                redirect_status="301",
            ),
            PREVIEW_CLUSTER,
        )

        self.assertIsNone(result.problem)
        generated = result.files["1001-app.cfg"]
        self.assertIn(
            "http-request redirect location 'https://app.example.com/web/admin/login' code 301",
            generated,
        )

    def test_a_prefix_redirect_on_the_root_is_refused_in_the_form_s_words(self) -> None:
        """The same form without the exact match, which is the same route twice.

        Refused rather than quietly turned into an exact match: the person may
        have meant the whole site to redirect, and that is an object with
        nowhere to send anything - which is worth saying out loud.

        Said by the form, not by the engine. "routes matches the same path
        twice" is true and describes a document the person never saw; it does
        not name the field that fixes it, and this is the shape people reach
        for often enough that meeting it with a puzzle is the wrong answer.
        """

        result = preview(
            form(
                redirect_path="/",
                redirect_location="https://app.example.com/web/admin/login",
            ),
            PREVIEW_CLUSTER,
        )

        self.assertIsNotNone(result.problem)
        self.assertIn("set the redirect's match to exact", str(result.problem))

    def test_a_prefix_redirect_is_written_as_it_always_was(self) -> None:
        """The default carries no `match` key, so older objects round-trip.

        A stored object written before the field existed has no `match` on its
        redirect route, and one written now with the default must be the same
        document - otherwise every such object would show a difference it did
        not ask for the first time somebody opened it.
        """

        result = preview(
            form(redirect_path="/old", redirect_location="https://example.net/new"),
            PREVIEW_CLUSTER,
        )

        self.assertIsNone(result.problem)
        self.assertNotIn("match:", result.document)

    def test_no_redirect_leaves_the_object_with_one_route(self) -> None:
        result = preview(form(), PREVIEW_CLUSTER)

        self.assertNotIn("redirect", result.files["1001-app.cfg"])


class ARawPortIsPreviewedToo(unittest.TestCase):
    """One form, two shapes: the fields that mean nothing are left out."""

    def test_a_tcp_object_becomes_a_port_and_one_backend(self) -> None:
        result = preview(form(protocol="tcp", tcp_port="5432", hostnames=""), PREVIEW_CLUSTER)

        self.assertIsNone(result.problem)
        self.assertIn("frontend mgd-internal-tcp-5432", result.files["1000-frontends.cfg"])
        self.assertIn("mode tcp", result.files["1001-app.cfg"])
        self.assertNotIn("hostnames", result.document)

    def test_a_hostname_left_in_the_form_is_refused_rather_than_dropped(self) -> None:
        """The same treatment the header box already gets.

        Two identical mistakes - a field filled in for a shape that has no use
        for it - must be answered the same way. Dropping the name would show a
        preview of an object the person did not describe, and they would find
        out at publish time that it was never there.
        """

        result = preview(
            form(protocol="tcp", tcp_port="5432", hostnames="db.example.com"), PREVIEW_CLUSTER
        )

        self.assertIsNotNone(result.problem)
        self.assertIn("hostnames", str(result.problem))

    def test_a_redirect_left_in_the_form_is_refused_rather_than_dropped(self) -> None:
        result = preview(
            form(
                protocol="tcp",
                tcp_port="5432",
                hostnames="",
                redirect_path="/old",
                redirect_location="https://example.com/new",
            ),
            PREVIEW_CLUSTER,
        )

        self.assertIsNotNone(result.problem)
        self.assertIn("routes", str(result.problem))

    def test_a_tcp_object_without_a_port_is_named_before_the_engine_sees_it(self) -> None:
        result = preview(form(protocol="tcp"), PREVIEW_CLUSTER)

        self.assertIsNotNone(result.problem)

    def test_session_persistence_on_a_raw_port_is_refused_by_the_engine(self) -> None:
        """HAProxy would ignore it with a warning and balance without it."""

        result = preview(
            form(protocol="tcp", tcp_port="5432", hostnames="", cookie="SRV"), PREVIEW_CLUSTER
        )

        self.assertEqual(result.problem_field, "app.backends.web.cookie")


class TheRateLimitTheObjectAsksFor(unittest.TestCase):
    """One number, which the object's shape turns into requests or connections."""

    def test_an_empty_box_writes_no_limit(self) -> None:
        self.assertNotIn("rate_limit:", build_document(form()))

    def test_a_site_counts_requests_in_its_own_backend(self) -> None:
        result = preview(form(rate_limit="100", rate_window="1m"), PREVIEW_CLUSTER)

        self.assertIsNone(result.problem)
        self.assertIn(
            "http-request deny deny_status 429 if { sc_http_req_rate(1) gt 100 }",
            result.files["1001-app.cfg"],
        )

    def test_a_raw_port_counts_new_connections(self) -> None:
        written = form(protocol="tcp", tcp_port="5432", hostnames="", rate_limit="20")

        self.assertIn("max_new_connections: 20", build_document(written))
        self.assertIsNone(preview(written, PREVIEW_CLUSTER).problem)

    def test_a_window_without_a_limit_is_named_before_the_engine_sees_it(self) -> None:
        with self.assertRaises(ValueError) as raised:
            build_document(form(rate_window="1m"))

        self.assertIn("needs a limit", str(raised.exception))

    def test_a_limit_that_is_not_a_number_is_named(self) -> None:
        with self.assertRaises(ValueError) as raised:
            build_document(form(rate_limit="many"))

        self.assertIn("must be a number", str(raised.exception))

    def test_the_limit_survives_a_round_trip_for_both_shapes(self) -> None:
        for written in (
            form(rate_limit="100"),
            form(rate_limit="100", rate_window="1m"),
            form(protocol="tcp", tcp_port="5432", hostnames="", rate_limit="20", rate_window="30s"),
        ):
            with self.subTest(written["protocol"], window=written["rate_window"]):
                reopened = form_from_document(build_document(written), networks=())

                self.assertEqual(reopened["rate_limit"], written["rate_limit"])
                self.assertEqual(reopened["rate_window"], written["rate_window"])


class TheCheckTimingTheObjectAsksFor(unittest.TestCase):
    """Interval, rise and fall, which the form had no field for until now.

    Every object written here carried HAProxy's own values because nothing
    could say otherwise - which was invisible, since the generated file states
    them either way. The three are optional, and left empty they must stay out
    of the document rather than be written into it as though somebody chose
    them.
    """

    def test_nothing_written_leaves_the_defaults_to_the_engine(self) -> None:
        document = build_document(form(health_type="http"))

        self.assertNotIn("interval:", document)
        self.assertNotIn("rise:", document)
        self.assertNotIn("fast_interval:", document)
        self.assertNotIn("down_interval:", document)
        self.assertNotIn("fall:", document)

    def test_what_is_written_reaches_the_server_line(self) -> None:
        result = preview(
            form(health_type="http", health_interval="5s", health_rise="3", health_fall="2"),
            PREVIEW_CLUSTER,
        )

        self.assertIsNone(result.problem)
        # Fast and down are ours when not written (proxy_model.DEFAULT_FAST_INTERVAL).
        self.assertIn(
            "check inter 5s fastinter 1s downinter 1s rise 3 fall 2", result.files["1001-app.cfg"]
        )

    def test_a_written_fast_and_down_interval_win_over_the_default(self) -> None:
        result = preview(
            form(health_type="http", health_fast_interval="1s", health_down_interval="3s"),
            PREVIEW_CLUSTER,
        )

        self.assertIsNone(result.problem)
        self.assertIn(
            "check inter 2s fastinter 1s downinter 3s rise 2 fall 3", result.files["1001-app.cfg"]
        )

    def test_a_count_that_is_not_a_count_is_named_before_the_engine_sees_it(self) -> None:
        result = preview(form(health_type="http", health_rise="twice"), PREVIEW_CLUSTER)

        self.assertIn("rise must be a number", str(result.problem))

    def test_the_timing_survives_a_round_trip_through_the_document(self) -> None:
        """Opened, saved and opened again must not change what it says."""

        written = form(
            health_type="http",
            health_interval="5s",
            health_fast_interval="1s",
            health_down_interval="3s",
            health_rise="3",
            health_fall="2",
        )
        reopened = form_from_document(build_document(written), networks=())

        self.assertEqual(reopened["health_interval"], "5s")
        self.assertEqual(reopened["health_fast_interval"], "1s")
        self.assertEqual(reopened["health_down_interval"], "3s")
        self.assertEqual(reopened["health_rise"], "3")
        self.assertEqual(reopened["health_fall"], "2")

    def test_a_disabled_check_carries_no_timing_at_all(self) -> None:
        document = build_document(form(health_type="disabled", health_interval="5s"))

        self.assertNotIn("interval", document)


class EverythingTheModelAllowsInOneRouteAndOnePool(unittest.TestCase):
    """The form expresses every field of a health check and of a server.

    It expressed most of them, and an object using one of the rest was refused
    outright - honestly, with the field named, but with nothing to do about it
    except edit the file by hand. The round trip is what proves the boundary is
    where it is claimed to be: one route and one backend, and inside those,
    everything.
    """

    def document(self, **fields: object) -> dict[str, Any]:
        form = dict(DEFAULTS)
        form.update(
            {
                "name": "shop",
                "hostnames": "shop.example.com",
                "protocol": "http",
                "backend": "web",
                "servers": "198.51.100.10:8080",
            }
        )
        form.update(fields)
        document: dict[str, Any] = yaml.safe_load(build_document(form))
        return document

    def test_a_check_may_speak_tls_where_the_backend_does_not(self) -> None:
        document = self.document(health_type="https", health_port="9443")
        health = document["backends"]["web"]["health"]

        self.assertEqual(health["type"], "http")
        self.assertEqual(health["tls"], True)
        self.assertEqual(health["port"], 9443)

    def test_a_check_may_be_plaintext_on_a_backend_that_is_not(self) -> None:
        """The combination that could not be written before. `no-check-ssl`."""

        document = self.document(
            health_type="http",
            health_port="9443",
            backend_tls="none",
            servers="app.example.com:8443",
        )

        self.assertEqual(document["backends"]["web"]["health"]["tls"], False)

    def test_a_check_that_says_what_the_backend_says_writes_nothing(self) -> None:
        """The backend already decides it, and a repeated word is a line in every diff."""

        plain = self.document(health_type="http", health_port="9443")
        self.assertNotIn("tls", plain["backends"]["web"]["health"])

        secure = self.document(
            health_type="https", backend_tls="none", servers="app.example.com:8443"
        )
        self.assertNotIn("tls", secure["backends"]["web"]["health"])

    def test_a_tcp_check_may_ask_for_the_handshake_itself(self) -> None:
        """`option ssl-hello-chk` is a check the backend's own TLS does not imply."""

        document = self.document(health_type="tcp-tls")
        health = document["backends"]["web"]["health"]

        self.assertEqual((health["type"], health["tls"]), ("tcp", True))

    def test_an_http_check_may_name_what_a_good_answer_is(self) -> None:
        """Text, not a number, because the model reads it as text.

        Written as a YAML integer until 2026-09-06, which the engine refuses:
        the value is matched against a pattern that must also accept `200-299`.
        Any status typed into the form therefore produced a document that could
        not be published, and the refusal named a rule the form gave no way to
        satisfy. A range is now accepted here too, for the same reason.
        """

        document = self.document(
            health_type="http", health_expect_status="204", health_expect_body="ok"
        )
        health = document["backends"]["web"]["health"]

        self.assertEqual((health["expect_status"], health["expect_body"]), ("204", "ok"))

    def test_a_range_is_as_good_an_answer_as_a_status(self) -> None:
        document = self.document(health_type="http", health_expect_status="200-299")

        self.assertEqual(document["backends"]["web"]["health"]["expect_status"], "200-299")

    def test_something_that_is_neither_is_refused_with_both_shapes_named(self) -> None:
        with self.assertRaises(ValueError) as refused:
            self.document(health_type="http", health_expect_status="twohundred")

        self.assertIn("200-299", str(refused.exception))

    def test_a_tcp_check_may_hold_a_conversation(self) -> None:
        document = self.document(health_type="tcp", health_send="PING", health_expect="PONG")
        health = document["backends"]["web"]["health"]

        self.assertEqual((health["send"], health["expect"]), ("PING", "PONG"))

    def test_the_expectations_belong_to_the_kind_of_check_that_has_them(self) -> None:
        #
        # The model refuses an http field on a tcp check and the other way
        # round, so the form must not write one there - it would build a
        # document nothing can read.
        #
        tcp = self.document(health_type="tcp", health_expect_status="204", health_expect_body="ok")
        http = self.document(health_type="http", health_send="PING", health_expect="PONG")

        self.assertNotIn("expect_status", tcp["backends"]["web"]["health"])
        self.assertNotIn("send", http["backends"]["web"]["health"])

    def test_a_disabled_check_writes_none_of_them(self) -> None:
        document = self.document(health_type="disabled", health_send="PING")

        self.assertEqual(document["backends"]["web"]["health"], {"type": "disabled"})

    def test_a_server_may_be_a_standby(self) -> None:
        document = self.document(servers="198.51.100.10:8080\n198.51.100.11:8080 backup")
        servers = document["backends"]["web"]["servers"]

        self.assertEqual(servers[0], {"host": "198.51.100.10", "port": 8080})
        self.assertEqual(servers[1], {"host": "198.51.100.11", "port": 8080, "backup": True})

    def test_a_backend_of_nothing_but_standbys_is_refused(self) -> None:
        #
        # HAProxy would take it. The person writing it meant something else.
        #
        with self.assertRaises(ValueError):
            self.document(servers="198.51.100.10:8080 backup")

    def test_a_standby_survives_the_round_trip(self) -> None:
        written = build_document(
            {
                **DEFAULTS,
                "name": "shop",
                "hostnames": "shop.example.com",
                "protocol": "http",
                "backend": "web",
                "servers": "198.51.100.10:8080\n198.51.100.11:8080 backup",
            }
        )

        back = form_from_document(written)

        self.assertEqual(back["servers"], "198.51.100.10:8080\n198.51.100.11:8080 backup")


class WhereTheFormStops(unittest.TestCase):
    """One route and one backend, and the boundary is deliberate.

    Everything inside it the form can now say. Beyond it - a second path going
    somewhere else, a second backend - is a repeating group, which is a different
    form rather than more fields on this one, and it is refused with the field
    named rather than opened with the extra routes silently dropped.

    The golden objects are the proof: they are the shapes the engine is tested
    against, so an object refused here is one somebody could plausibly write.
    """

    def golden(self) -> list[tuple[str, str]]:
        root = Path(__file__).resolve().parents[2] / "tests" / "golden"
        refused = []
        for path in sorted(root.rglob("*.yaml")):
            #
            # Network documents describe a cluster's addresses, and `_cluster.yaml`
            # its log targets and exporter. Neither is an object and the editor
            # never opens one.
            #
            if path.name in ("vips.yaml", "_cluster.yaml"):
                continue
            try:
                form_from_document(path.read_text(encoding="utf-8"))
            except Unexpressible as refusal:
                refused.append((f"{path.parent.name}/{path.name}", str(refusal)))
        return refused

    def test_only_a_second_route_is_still_out_of_reach(self) -> None:
        refused = self.golden()

        self.assertEqual(
            refused,
            [
                #
                # A dns object (B249) is served by dnsdist, and the form learns
                # it in the build's fifth step; until then it stops at the port.
                #
                ("dns/iot.yaml", "listen.port"),
                ("dns/resolver.yaml", "listen.port"),
                ("monitors/probes.yaml", "routes"),
                ("routes/shop.yaml", "routes"),
            ],
        )


class TheAdvancedConfigIsCarriedThrough(unittest.TestCase):
    """The form opens an object with advanced config and writes the text back unchanged.

    The text is edited in its own dialog (Fas 17, B223); the form has no field
    for it and must not be where it is lost. Nor a pool the text writes (B224):
    the form shows no pool fields for one, and saves it as it found it.
    """

    GOLDEN = Path(__file__).resolve().parents[2] / "tests" / "golden" / "advanced"

    def round_trip(self, name: str) -> tuple[dict[str, object], dict[str, object]]:
        stored = (self.GOLDEN / f"{name}.yaml").read_text(encoding="utf-8")
        return yaml.safe_load(stored), yaml.safe_load(build_document(form_from_document(stored)))

    def test_the_text_comes_back_byte_for_byte(self) -> None:
        for name in ("db", "shop"):
            with self.subTest(name):
                stored, written = self.round_trip(name)
                self.assertEqual(written["advanced"], stored["advanced"])

    def test_a_pool_the_text_writes_stays_empty_and_alone(self) -> None:
        stored, written = self.round_trip("shop")

        self.assertEqual(written["backends"], {"web": {"servers": []}})
        self.assertEqual(written["backends"], stored["backends"])

    def test_pool_fields_left_on_the_form_do_not_reach_a_written_pool(self) -> None:
        document = yaml.safe_load(
            build_document(
                form(
                    protocol="http",
                    servers="",
                    balance="leastconn",
                    cookie="SRV",
                    max_connections="50",
                    handwritten_pool=True,
                    advanced="server app1 198.51.100.20:8080\n",
                )
            )
        )

        self.assertEqual(document["backends"], {"web": {"servers": []}})

    def test_the_line_ends_a_browser_sends_change_nothing(self) -> None:
        document = build_document(form(advanced="timeout server 2m   \r\nretries 5\r\n\r\n"))

        self.assertEqual(yaml.safe_load(document)["advanced"], "timeout server 2m\nretries 5\n")
        self.assertIn("advanced: |", document)

    def test_an_empty_text_is_no_advanced_config(self) -> None:
        document = yaml.safe_load(build_document(form(advanced=" \r\n\n")))

        self.assertNotIn("advanced", document)

    def test_a_text_the_engine_would_store_differently_still_opens(self) -> None:
        stored = (self.GOLDEN / "db.yaml").read_text(encoding="utf-8")
        loose = stored.replace("retries 5\n", "retries 5   \n")
        self.assertNotEqual(yaml.safe_load(loose)["advanced"], yaml.safe_load(stored)["advanced"])

        written = yaml.safe_load(build_document(form_from_document(loose)))

        self.assertEqual(written["advanced"], yaml.safe_load(stored)["advanced"])

    def test_advanced_config_that_is_not_text_is_refused_rather_than_dropped(self) -> None:
        stored = yaml.safe_load((self.GOLDEN / "db.yaml").read_text(encoding="utf-8"))
        stored["advanced"] = ["retries 5"]

        with self.assertRaises(Unexpressible) as refusal:
            form_from_document(yaml.safe_dump(stored))

        self.assertIn("advanced", str(refusal.exception))
