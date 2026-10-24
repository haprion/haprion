"""The generator's output, held to the byte.

A golden file is the phase's form of proof: the same objects must always
produce the same configuration, and any change to what the generator emits has
to show up as a diff somebody reads. Regenerate with `tools/update_golden.py`
after a deliberate change - the diff it produces is the review.

The cases are directories under `tests/golden/`, each holding its objects as
`.yaml` and the expected configuration as `.cfg`. There is no list of cases to
keep in step: adding a directory adds a case.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from haprion import advanced
from haprion import generate as generate_module
from haprion.candidate_validation import peer_arguments
from haprion.config import TLS_POLICY_NAMES, AbuseProtection, Vip
from haprion.generate import (
    HTTP_TRAFFIC_LOG_FORMAT,
    NODE_CERTIFICATE_DIR,
    TRAFFIC_LOG_PROFILE,
    GeneratorError,
    generate,
)
from haprion.golden import (
    CERTIFICATES,
    DEFAULT_VIPS,
    GOLDEN,
    arguments,
    cases,
    expected,
    expected_dns,
    expected_ipvs,
    expected_rsyslog,
    objects,
    produced,
    produced_dns,
    produced_ipvs,
    produced_lists,
    produced_rsyslog,
)
from haprion.proxy_model import ModelError, Proxy, load_proxy
from haprion.reservations import Reservations
from haprion.tls_policy import TLS_POLICIES

#
# Enough of a configuration for `haproxy -c` to have something to attach the
# generated fragments to. It stands in for what `core/` provides on a node: the
# generated files are fragments of a directory, and a fragment cannot be
# validated entirely on its own.
#
CORE = """
global
    daemon
    default-path config
    tune.stick-counters 5
resolvers cluster-dns
    nameserver ns1 192.0.2.53:53
    resolve_retries 3
    timeout resolve 1s
    timeout retry 1s
    hold valid 10s
defaults
    mode http
    timeout connect 5s
    timeout client 50s
    timeout server 50s
"""


def _backend_guids(text: str) -> list[str]:
    """The `guid` lines inside `backend` sections of one configuration file."""

    found: list[str] = []
    section = ""
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = line.split()[0]
        elif section == "backend" and line.split()[:1] == ["guid"]:
            found.append(line.strip())
    return found


class NoBackendCarriesAGuid(unittest.TestCase):
    """HAProxy 3.4.6 cannot carry a backend's counters across a reload (guid.py).

    With a GUID the `BACKEND` row alternates between two slots and shows the
    figures of the process before last; without one it starts from zero, which
    the metrics read as a restart. Frontends and servers keep theirs.
    """

    def test_no_golden_case_writes_one(self) -> None:
        for case in cases():
            for name, text in produced(case).items():
                with self.subTest(case=case.name, file=name):
                    self.assertEqual(_backend_guids(text), [])

    def test_the_waf_engine_backend_has_none(self) -> None:
        text = generate_module._waf_backend_file()

        self.assertIn("backend ", text)
        self.assertEqual(_backend_guids(text), [])

    def test_servers_and_frontends_still_have_theirs(self) -> None:
        text = "\n".join(produced(GOLDEN / "minimal").values())

        self.assertIn(" guid srv:", text)
        self.assertIn("    guid fe:", text)


class AVipHoldsOnlyItsObjectsPorts(unittest.TestCase):
    """26-10-15: nothing generated listens on every address, so a VIP starts empty.

    A listener without an address holds its port on every VIP too, and an
    object there then fails every deploy. The exporter did, and dnsdist's
    statistics did; both now name the nodes' own addresses.
    """

    WILDCARD_BIND = re.compile(r"^\s*bind\s+(:|\*:|\[::\]:|0\.0\.0\.0:)", re.MULTILINE)
    WILDCARD_WEBSERVER = re.compile(r'webserver\("(0\.0\.0\.0|\[::\]|\*):')

    def test_no_case_binds_every_address(self) -> None:
        for case in cases():
            with self.subTest(case.name):
                for name, text in produced(case).items():
                    self.assertIsNone(self.WILDCARD_BIND.search(text), name)
                for name, text in produced_dns(case).items():
                    self.assertIsNone(self.WILDCARD_WEBSERVER.search(text), name)


class EveryCaseMatchesItsGoldenFiles(unittest.TestCase):
    def test_traffic_log_stream_is_opt_in_and_does_not_replace_httplog(self) -> None:
        case = GOLDEN / "minimal"
        baseline = produced(case)["1000-frontends.cfg"]
        enabled = generate(objects(case), **arguments(case), traffic_logging=True).configuration[
            "1000-frontends.cfg"
        ]

        self.assertNotIn("log-profile", baseline)
        self.assertNotIn("haproxy-traffic", baseline)
        self.assertIn(f"log-profile {TRAFFIC_LOG_PROFILE}", enabled)
        self.assertIn(f"on close format {HTTP_TRAFFIC_LOG_FORMAT}", enabled)
        self.assertIn("option httplog", enabled)
        self.assertIn("%(path)HPO ", enabled)
        self.assertNotIn("%(path)HP ", enabled)
        self.assertNotIn("capture request header", enabled)

    def test_the_extra_log_target_speaks_the_format_rsyslog_can_tag(self) -> None:
        """`format rfc3164` makes HAProxy write a hostname before the tag.

        rsyslog's local-socket reader takes the first word after the timestamp
        as the tag, so that record was filed under `localhost` and reached no
        rule. `local` is the same format without the hostname - what the
        ordinary httplog stream already uses. Measured against a real rsyslogd.
        """

        case = GOLDEN / "minimal"
        enabled = generate(objects(case), **arguments(case), traffic_logging=True).configuration[
            "1000-frontends.cfg"
        ]

        self.assertIn(f"format local profile {TRAFFIC_LOG_PROFILE} local2", enabled)
        self.assertNotIn("format rfc3164", enabled)

    def test_the_profile_drops_the_error_step(self) -> None:
        """An SSL handshake failure is logged at the error step, in plain text.

        Every log target of the frontend receives it, so without this line it
        lands in the structured file as a record nothing can parse. The
        classic log still carries it through the global target.
        """

        case = GOLDEN / "minimal"
        enabled = generate(objects(case), **arguments(case), traffic_logging=True).configuration[
            "1000-frontends.cfg"
        ]

        profile = enabled[enabled.index("log-profile ") :].split("\n\n", 1)[0]
        self.assertIn("    on error drop", profile)
        self.assertLess(profile.index("on error drop"), profile.index("on close format"))

    def test_every_traffic_record_carries_a_field_that_differs_per_request(self) -> None:
        """rsyslog collapses consecutive identical lines, so records must differ.

        Ubuntu ships `$RepeatedMsgReduction on`. Two identical requests in the
        same second with identical timings and byte counts would otherwise be
        written once, with nothing reporting the loss.
        """

        self.assertIn("%(request)rt", HTTP_TRAFFIC_LOG_FORMAT)

    def test_a_server_named_by_hostname_is_kept_resolved(self) -> None:
        """The trap this repository would otherwise walk into.

        A hostname without a resolvers section is looked up once at startup and
        never again. The site then dies whenever that address changes, and it
        dies looking like a broken backend rather than like stale DNS.
        """

        files = produced(GOLDEN / "https")

        self.assertIn("resolvers cluster-dns init-addr last,libc,none", files["1001-admin.cfg"])
        self.assertNotIn("resolvers", files["1001-app.cfg"])

    def test_the_cases_exist_at_all(self) -> None:
        """A test that silently checks nothing is worse than no test.

        If the directory is ever empty or moved, everything below passes
        without comparing anything, and the generator would be unprotected
        while the suite stayed green.
        """

        self.assertGreaterEqual(len(cases()), 3)

    def test_the_output_is_byte_identical_to_what_is_committed(self) -> None:
        for case in cases():
            with self.subTest(case.name):
                self.assertEqual(produced(case), expected(case))
                self.assertEqual(produced_dns(case), expected_dns(case))
                self.assertEqual(produced_ipvs(case), expected_ipvs(case))
                self.assertEqual(produced_rsyslog(case), expected_rsyslog(case))

    def test_generating_twice_produces_the_same_bytes(self) -> None:
        for case in cases():
            with self.subTest(case.name):
                self.assertEqual(produced(case), produced(case))

    def test_the_order_the_objects_are_read_in_does_not_matter(self) -> None:
        for case in cases():
            with self.subTest(case.name):
                loaded = objects(case)
                cluster = arguments(case)
                self.assertEqual(
                    generate(list(reversed(loaded)), **cluster).configuration,
                    generate(loaded, **cluster).configuration,
                )


@unittest.skipUnless(
    shutil.which("haproxy") and shutil.which("openssl"),
    "haproxy or openssl is not installed here",
)
class HaproxyAcceptsWhatWeGenerate(unittest.TestCase):
    """The check that the golden files are configuration and not just text.

    Skipped where HAProxy is absent, which is honest about what ran: a machine
    without HAProxy cannot answer this question, and pretending otherwise would
    make the gate green for the wrong reason.
    """

    def test_every_case_validates(self) -> None:
        for case in cases():
            with self.subTest(case.name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                #
                # The layout a release has: `conf.d` is what the node loads with
                # `-f`, and the certificate lists sit beside it because `-f` on a
                # directory reads every file in it. The bind lines reach them by
                # a path relative to `conf.d`, which `default-path config` in the
                # core file is what makes resolve.
                #
                (root / "conf.d").mkdir()
                (root / "haproxy.cfg").write_text(CORE)
                certificates = _certificate_directory(root)

                def local(content: str, certificates: Path = certificates) -> str:
                    #
                    # The same substitution `candidate_validation` makes when it
                    # validates a candidate in a sandbox that has no /etc: the
                    # node's certificate directory becomes one that exists here.
                    # HAProxy refuses to start on a certificate it cannot stat,
                    # so without this an https case could not be validated at all.
                    #
                    return content.replace(NODE_CERTIFICATE_DIR, str(certificates))

                for name, content in produced(case).items():
                    (root / "conf.d" / name).write_text(local(content))
                listings = produced_lists(case)
                if listings:
                    (root / "crt-lists").mkdir()
                    for name, content in listings.items():
                        (root / "crt-lists" / name).write_text(local(content))

                arguments = [
                    *peer_arguments(root / "conf.d"),
                    "-f",
                    str(root / "haproxy.cfg"),
                    "-f",
                    str(root / "conf.d"),
                ]
                binary = shutil.which("haproxy")
                assert binary is not None
                result = subprocess.run(
                    [binary, "-c", *arguments],
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                #
                # A warning on a line of an object's advanced config is HAProxy
                # saying it will ignore the line, which `-c` lets through. The
                # publish refuses on it, so a frozen case may not carry one.
                #
                _, warnings = advanced.annotate(result.stdout + result.stderr, produced(case))
                self.assertEqual(warnings, [])

    def test_opt_in_traffic_profile_validates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "conf.d").mkdir()
            (root / "haproxy.cfg").write_text(CORE)
            layer = generate(
                objects(GOLDEN / "minimal"),
                **arguments(GOLDEN / "minimal"),
                traffic_logging=True,
            )
            for name, content in layer.configuration.items():
                (root / "conf.d" / name).write_text(content)

            binary = shutil.which("haproxy")
            assert binary is not None
            result = subprocess.run(
                [binary, "-c", "-f", str(root / "haproxy.cfg"), "-f", str(root / "conf.d")],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


def _generate(proxies: list[Proxy], **cluster: Any) -> dict[str, str]:
    """The generator on a cluster with one plain address, which most are.

    The configuration half only. The certificate lists are covered where they
    have to be - against a real HAProxy, which is the only thing that can say
    whether a bind line finds the file it names.
    """

    return generate(
        proxies,
        vips=dict(DEFAULT_VIPS),
        default_vip="main",
        certificates=CERTIFICATES,
        **cluster,
    ).configuration


def _certificate_directory(root: Path) -> Path:
    """Throwaway certificates for the ones the cases name.

    Generated per run rather than committed: a certificate and its private key
    have no business in this repository even when both are worthless, and a
    key block in the tree is exactly what the secret scanner is there to stop.
    """

    directory = root / "certs"
    directory.mkdir()
    openssl = shutil.which("openssl")
    assert openssl is not None
    for name in CERTIFICATES:
        subprocess.run(
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(directory / "key.pem"),
                "-out",
                str(directory / "cert.pem"),
                "-days",
                "1",
                "-nodes",
                "-subj",
                f"/CN={name}",
            ],
            capture_output=True,
            check=True,
        )
        (directory / f"{name}.pem").write_bytes(
            (directory / "cert.pem").read_bytes() + (directory / "key.pem").read_bytes()
        )
    return directory


class ThingsAWholeLayerRefuses(unittest.TestCase):
    """Refusals that only exist once more than one object is in view.

    The model reads one object at a time and cannot see these; the generator is
    the first place the question can be asked.
    """

    def test_two_objects_cannot_claim_the_same_hostname(self) -> None:
        first = load_proxy("shop", MINIMAL)
        second = load_proxy("store", MINIMAL.replace(b"name: shop", b"name: store"))

        with self.assertRaises(GeneratorError) as raised:
            _generate([first, second])

        self.assertIn("shop.example.com", str(raised.exception))
        self.assertIn("store", str(raised.exception))

    def test_an_object_this_version_cannot_generate_is_refused_not_skipped(self) -> None:
        """Skipping it would take a site down and report success.

        Reached through a cluster that serves no https rather than through an
        unknown protocol: every protocol the model accepts can now be
        generated, and the branch that refuses is the one where a cluster does
        not offer the port an object asks for.
        """

        with self.assertRaises(GeneratorError) as raised:
            generate(
                [load_proxy("app", HTTPS)],
                vips=dict(DEFAULT_VIPS),
                default_vip="main",
                certificates=CERTIFICATES,
                ports={"http": 80},
            )

        self.assertIn("app", str(raised.exception))

    def test_two_routes_to_one_backend_must_rewrite_the_path_the_same_way(self) -> None:
        """The rewrite lives in the backend, so the backend can only have one.

        Refused rather than resolved by whichever route came first: the fix is
        one line in the object - a second backend name - and it makes the
        intent readable.
        """

        conflicting = MINIMAL.replace(
            b"  - path: /\n    backend: web\n",
            b"  - path: /\n    backend: web\n"
            b"  - path: /api\n    backend: web\n    strip_prefix: /api\n",
        )

        with self.assertRaises(GeneratorError) as raised:
            _generate([load_proxy("shop", conflicting)])

        self.assertIn("separate backends", str(raised.exception))


MINIMAL = (Path(__file__).parent / "golden" / "minimal" / "shop.yaml").read_bytes()

VERIFIED = b"""\
schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: pool
backends:
  pool:
    balance: roundrobin
    tls:
      verify: system
    health:
      type: http
      path: /
    servers:
      - host: pool-a.example.net
        port: 8443
"""


class HttpsIsRefusedWhereItCannotBeHonoured(unittest.TestCase):
    """What the layer refuses once TLS is in the picture."""

    def test_a_certificate_the_cluster_does_not_distribute_is_refused(self) -> None:
        """Otherwise it reaches the node as a path to a file that is not there.

        HAProxy refuses to start on a certificate it cannot read, so the
        failure would land on the node during a deploy rather than in the
        editor while somebody is still typing.
        """

        document = HTTPS.replace(b"certificate: wildcard-example-com", b"certificate: not-issued")

        with self.assertRaises(GeneratorError) as raised:
            _generate([load_proxy("app", document)])

        self.assertIn("not-issued", str(raised.exception))
        self.assertIn("example.net", str(raised.exception))

    def test_a_certificate_that_does_not_answer_for_the_name_is_refused(self) -> None:
        """HAProxy serves it; the visitor's browser is what refuses.

        A certificate is a file HAProxy loads, not a claim it checks against
        the objects using it - so the site looks broken to visitors while every
        layer here reports success.
        """

        with self.assertRaises(GeneratorError) as raised:
            _generate(
                [load_proxy("app", HTTPS)],
                certificate_sans={"wildcard-example-com": ("*.example.net",)},
            )

        self.assertIn("wildcard-example-com", str(raised.exception))
        self.assertIn("*.example.net", str(raised.exception))

    def test_a_wildcard_answers_for_one_label_and_not_two(self) -> None:
        """`*.example.com` is not a certificate for `a.b.example.com`.

        The mistake this rule exists for: it reads as covered, it passes every
        check the node makes, and it fails in the visitor's browser.
        """

        deeper = HTTPS.replace(b"app.example.com", b"api.internal.example.com")

        with self.assertRaises(GeneratorError) as raised:
            _generate(
                [load_proxy("app", deeper)],
                certificate_sans={"wildcard-example-com": ("*.example.com",)},
            )

        self.assertIn("api.internal.example.com", str(raised.exception))

    def test_the_wildcard_answers_for_a_single_label(self) -> None:
        files = _generate(
            [load_proxy("app", HTTPS)],
            certificate_sans={"wildcard-example-com": ("*.example.com",)},
        )

        self.assertIn("1000-frontends.cfg", files)

    def test_the_override_is_what_makes_a_deliberate_mismatch_possible(self) -> None:
        """Picking the "wrong" certificate on purpose is a real thing to do.

        It is temporary, which is why the override is asked for per publish
        rather than written into the object, where the next reader would take
        it for a decision (B66).
        """

        files = _generate(
            [load_proxy("app", HTTPS)],
            certificate_sans={"wildcard-example-com": ("*.example.net",)},
            allow_certificate_mismatch=True,
        )

        self.assertIn("1000-frontends.cfg", files)

    def test_a_certificate_that_could_not_be_read_is_not_a_refusal(self) -> None:
        """An absent entry means "not measured", never "covers nothing".

        Refusing a publish because a file was briefly unreadable would block a
        change for a reason that has nothing to do with the object.
        """

        files = _generate([load_proxy("app", HTTPS)], certificate_sans={})

        self.assertIn("1000-frontends.cfg", files)

    def test_a_redirect_puts_the_object_on_port_80_as_well(self) -> None:
        """An https object that redirects needs a listener on 80 to redirect from."""

        files = _generate([load_proxy("app", HTTPS)])
        frontends = files["1000-frontends.cfg"]

        self.assertIn("bind 192.0.2.20:80", frontends)
        self.assertIn("redirect scheme https code 301", frontends)
        self.assertIn("bind 192.0.2.20:443 ssl crt", frontends)

    def test_the_strict_transport_header_is_set_on_every_answer_for_the_names(self) -> None:
        """Not on the server's answer only (review 2026-10-24).

        A refusal, a redirect or the maintenance page is made by HAProxy and
        never passes the backend's `http-response` rules. At response time a
        frontend cannot read the Host header, so the request phase records the
        value and one `http-after-response` rule writes it - before the
        listener's own refusals, so those carry it too.
        """

        files = _generate([load_proxy("app", HTTPS)])
        frontends = files["1000-frontends.cfg"]

        self.assertNotIn("Strict-Transport-Security", files["1001-app.cfg"])
        recorded = frontends.index(
            'http-request set-var(txn.hsts) str("max-age=31536000; includeSubDomains") '
            "if mgd-app-hsts"
        )
        self.assertIn(
            "http-after-response set-header Strict-Transport-Security %[var(txn.hsts)] "
            "if { var(txn.hsts) -m found }",
            frontends,
        )
        self.assertLess(recorded, frontends.rindex("    # app\n"))


HTTPS = (Path(__file__).parent / "golden" / "https" / "app.yaml").read_bytes()


class WhoGetsAnAnswerAndWhoDoesNot(unittest.TestCase):
    """The two questions a cluster answers rather than an object."""

    def test_a_name_no_object_claims_gets_the_configured_answer(self) -> None:
        """Reached through default_backend, which only fires when nothing matched.

        A rule in the frontend could not do this: `http-request` runs before
        `use_backend`, so an unconditional one would answer every request,
        claimed name or not.
        """

        frontends = produced(GOLDEN / "https")["1000-frontends.cfg"]

        self.assertIn("default_backend mgd-main-https-unknown", frontends)
        self.assertIn("http-request return status 404", frontends)

    def test_an_allowlist_denies_before_anything_is_routed(self) -> None:
        frontends = produced(GOLDEN / "https")["1000-frontends.cfg"]

        #
        # The case has a trusted proxy, so the visitor is the forwarded address
        # rather than the connection (B227, question 1).
        #
        self.assertIn(
            "acl mgd-admin-allow var(txn.client) -m ip 198.51.100.0/24 203.0.113.128/25", frontends
        )
        self.assertIn(
            "http-request deny deny_status 403 if mgd-admin-host !mgd-admin-allow", frontends
        )

    def test_a_network_the_cluster_does_not_define_is_refused(self) -> None:
        """Ignoring it would admit everybody; matching nothing would deny everybody."""

        document = HTTPS.replace(b"routes:", b"allow_from: [nowhere]\nroutes:")

        with self.assertRaises(GeneratorError) as raised:
            _generate([load_proxy("app", document)])

        self.assertIn("nowhere", str(raised.exception))


class AnObjectDeliberatelyOutOfService(unittest.TestCase):
    """`maintenance` answers for the object's names and routes nothing."""

    def frontends(self, message: str = "Back at 18:00.") -> str:
        document = MINIMAL.replace(
            b"routes:", f"maintenance:\n  message: {message}\nroutes:".encode()
        )
        return _generate([load_proxy("shop", document)])["1000-frontends.cfg"]

    def test_a_dollar_sign_is_escaped_where_the_line_is_written(self) -> None:
        """HAProxy expands `$HOME` inside double quotes; `\\$` is a literal dollar.

        The model lets a sentence carry a dollar - a price is the ordinary
        reason to write one - so the escaping has to happen here, in the one
        place that knows the line is double-quoted.
        """

        self.assertIn(
            r'string "Refunds cost \$0, see \$HOME"',
            self.frontends("Refunds cost $0, see $HOME"),
        )

    def test_the_message_is_returned_for_this_object_s_names_only(self) -> None:
        self.assertIn(
            'http-request return status 503 content-type text/plain string "Back at 18:00." '
            'hdr cache-control "no-store" if mgd-shop-host',
            self.frontends(),
        )

    def test_the_routes_are_still_written_below_it(self) -> None:
        """`return` ends the transaction, so they are unreachable while it stands.

        Kept rather than dropped so that turning maintenance off changes one
        rule instead of regenerating the object's whole contribution, and so
        the pools stay routed to and therefore stay checked.
        """

        frontends = self.frontends()
        rule = frontends.index("http-request return status 503")
        route = frontends.index("use_backend web")

        self.assertLess(rule, route)

    def test_a_serving_object_carries_no_such_rule(self) -> None:
        frontends = _generate([load_proxy("shop", MINIMAL)])["1000-frontends.cfg"]

        self.assertNotIn("http-request return status 503", frontends)


class ThePoolsOwnAnswerWhenItCannotServe(unittest.TestCase):
    def backend(self) -> str:
        document = MINIMAL.replace(
            b"routes:", b"unavailable:\n  message: The shop is not answering.\nroutes:"
        )
        return _generate([load_proxy("shop", document)])["1001-shop.cfg"]

    def test_all_three_failure_answers_carry_the_same_message(self) -> None:
        """502, 503 and 504 are one grey page to a visitor, whichever way it failed."""

        backend = self.backend()

        for status in (502, 503, 504):
            with self.subTest(status):
                self.assertIn(
                    f"http-error status {status} content-type text/plain "
                    'string "The shop is not answering."',
                    backend,
                )

    def test_a_site_that_says_nothing_gets_haproxy_s_own_text(self) -> None:
        backend = _generate([load_proxy("shop", MINIMAL)])["1001-shop.cfg"]

        self.assertNotIn("http-error", backend)


class TheSiteNameIsFilledInWhereItIsAskedFor(unittest.TestCase):
    def test_the_token_becomes_the_object_s_first_hostname(self) -> None:
        document = MINIMAL.replace(
            b"routes:", b"unavailable:\n  message: The site %URL% is not answering.\nroutes:"
        )

        backend = _generate([load_proxy("shop", document)])["1001-shop.cfg"]

        self.assertIn('string "The site shop.example.com is not answering."', backend)
        self.assertNotIn("%URL%", backend)

    def test_it_is_filled_in_for_a_maintenance_message_too(self) -> None:
        """Quoted, because YAML gives `%` a meaning at the start of a scalar.

        Nothing the interface writes hits this - `dump_document` quotes what
        needs quoting - but somebody editing an object by hand does, and the
        answer is the ordinary YAML one.
        """

        document = MINIMAL.replace(
            b"routes:", b'maintenance:\n  message: "%URL% is back at 18:00."\nroutes:'
        )

        frontends = _generate([load_proxy("shop", document)])["1000-frontends.cfg"]

        self.assertIn('string "shop.example.com is back at 18:00."', frontends)


class TheLimitAndTheRampAreWrittenPerServer(unittest.TestCase):
    def test_a_limit_puts_a_bound_on_the_server_and_on_the_queue(self) -> None:
        document = MINIMAL.replace(
            b"    balance: roundrobin", b"    balance: roundrobin\n    max_connections: 50"
        )

        backend = _generate([load_proxy("shop", document)])["1001-shop.cfg"]

        self.assertIn(" maxconn 50", backend)
        self.assertIn("timeout queue 5s", backend)

    def test_a_ramp_is_written_on_every_server_line(self) -> None:
        document = MINIMAL.replace(b"      type: disabled", b"      type: tcp").replace(
            b"    balance: roundrobin", b"    balance: roundrobin\n    slow_start: 30s"
        )

        backend = _generate([load_proxy("shop", document)])["1001-shop.cfg"]

        self.assertIn(" slowstart 30s", backend)

    def test_a_server_timeout_replaces_the_default_in_the_objects_backend(self) -> None:
        document = MINIMAL.replace(
            b"    balance: roundrobin", b"    balance: roundrobin\n    server_timeout: 5m"
        )

        backend = _generate([load_proxy("shop", document)])["1001-shop.cfg"]

        self.assertIn("    timeout server 5m\n", backend)
        self.assertNotIn("timeout server 50s", backend)

    def test_without_one_the_server_waits_the_default(self) -> None:
        backend = _generate([load_proxy("shop", MINIMAL)])["1001-shop.cfg"]

        self.assertIn("    timeout server 50s\n", backend)

    def test_neither_appears_where_the_object_asked_for_neither(self) -> None:
        backend = _generate([load_proxy("shop", MINIMAL)])["1001-shop.cfg"]

        self.assertNotIn("maxconn", backend)
        self.assertNotIn("slowstart", backend)
        self.assertNotIn("timeout queue", backend)


class TheListenerAcceptsWhatTheClusterSaysItAccepts(unittest.TestCase):
    """A VIP may name a TLS policy; without one it inherits from `core/`."""

    def frontends(self, policy: str | None) -> str:
        vip = Vip(name="main", address="192.0.2.20", tls_policy=policy)
        return generate(
            [load_proxy("app", HTTPS)],
            vips={"main": vip},
            default_vip="main",
            certificates=CERTIFICATES,
        ).configuration["1000-frontends.cfg"]

    def test_every_name_the_configuration_accepts_can_be_written(self) -> None:
        """Otherwise a cluster is refused on the node after a publish said it worked."""

        self.assertEqual(sorted(TLS_POLICIES), sorted(TLS_POLICY_NAMES))

    def test_modern_binds_to_tls_1_3_alone(self) -> None:
        """Measured on 3.4.4: a client held to TLS 1.2 gets no handshake at all."""

        self.assertIn("ssl-min-ver TLSv1.3", self.frontends("modern"))

    def test_intermediate_keeps_tls_1_2_with_a_named_cipher_set(self) -> None:
        frontends = self.frontends("intermediate")

        self.assertIn("ssl-min-ver TLSv1.2", frontends)
        self.assertIn("ECDHE-ECDSA-AES128-GCM-SHA256", frontends)

    def test_tls12only_closes_the_top_as_well_as_the_floor(self) -> None:
        """Measured on 3.4.4: a TLS 1.3 client is answered with alert 70.

        The only policy that names a ceiling. Without `ssl-max-ver` the name
        would be a claim the configuration does not make - a 1.3 client would
        be served 1.3 by a listener whose field said 1.2 only.
        """

        frontends = self.frontends("tls12only")

        self.assertIn("ssl-min-ver TLSv1.2 ssl-max-ver TLSv1.2", frontends)
        self.assertIn("ECDHE-ECDSA-AES128-GCM-SHA256", frontends)
        self.assertNotIn("ciphersuites", frontends)

    def test_a_vip_that_says_nothing_writes_nothing(self) -> None:
        """`core/` keeps deciding, which is what every cluster does today.

        A bind line overrides `core/` in both directions, so a policy defaulted
        here would quietly loosen a cluster whose own defaults are stricter.
        """

        frontends = self.frontends(None)

        self.assertNotIn("ssl-min-ver", frontends)
        self.assertNotIn("ciphers", frontends)


class WhoTheBrakeHoldsResponsible(unittest.TestCase):
    """Which address is counted, which is the whole question behind a proxy."""

    def frontends(self, trusted: tuple[str, ...]) -> str:
        return generate(
            [load_proxy("shop", MINIMAL)],
            vips=dict(DEFAULT_VIPS),
            default_vip="main",
            trusted_proxies=trusted,
            abuse_protection=AbuseProtection(window="10s", max_requests=100),
        ).configuration["1000-frontends.cfg"]

    def test_without_a_trusted_proxy_the_connecting_address_is_counted(self) -> None:
        frontends = self.frontends(())

        self.assertIn("http-request track-sc0 src\n", frontends)
        self.assertNotIn("X-Forwarded-For,-1", frontends)

    def test_behind_one_the_forwarded_address_is_counted_instead(self) -> None:
        """Counting the proxy would refuse everybody within one window."""

        frontends = self.frontends(("198.51.100.0/24",))

        self.assertIn(
            "http-request track-sc0 req.hdr_ip(X-Forwarded-For,-1) if mgd-trusted-proxy",
            frontends,
        )
        self.assertIn("http-request track-sc0 src unless mgd-trusted-proxy", frontends)

    def test_the_last_element_is_taken_and_not_the_first(self) -> None:
        """A visitor may put anything in front of what the proxy wrote."""

        self.assertIn("X-Forwarded-For,-1", self.frontends(("198.51.100.0/24",)))


class WhatTheBackendIsToldAboutTheVisitor(unittest.TestCase):
    """The forwarded headers, and who is allowed to have written them already."""

    def frontends(self, trusted: tuple[str, ...]) -> str:
        return generate(
            [load_proxy("shop", MINIMAL)],
            vips=dict(DEFAULT_VIPS),
            default_vip="main",
            trusted_proxies=trusted,
        ).configuration["1000-frontends.cfg"]

    def test_the_headers_are_deleted_before_they_are_written(self) -> None:
        """A visitor may send any of them, so what arrives cannot be trusted."""

        frontends = self.frontends(())

        for header in ("X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host"):
            with self.subTest(header):
                deleted = frontends.index(f"del-header {header}")
                self.assertLess(deleted, frontends.index("use_backend"))

        self.assertIn("set-header X-Forwarded-Proto http", frontends)

    def test_without_a_trusted_network_no_request_is_an_exception(self) -> None:
        frontends = self.frontends(())

        self.assertNotIn("mgd-trusted-proxy", frontends)
        self.assertNotIn("unless", frontends.split("# shop")[0])

    def test_a_trusted_proxy_keeps_the_chain_it_arrived_with(self) -> None:
        frontends = self.frontends(("198.51.100.0/24",))

        self.assertIn("acl mgd-trusted-proxy src 198.51.100.0/24", frontends)
        self.assertIn("del-header X-Forwarded-For unless mgd-trusted-proxy", frontends)

    def test_the_address_is_appended_in_the_backend(self) -> None:
        """`option forwardfor` is only taken there, and it appends rather than replaces."""

        backend = _generate([load_proxy("shop", MINIMAL)])["1001-shop.cfg"]

        self.assertIn("option forwardfor", backend)


class WhatTheHandwrittenHalfHasAlreadyClaimed(unittest.TestCase):
    """Both failures are ones HAProxy does not report as failures."""

    def test_a_reserved_hostname_stops_the_publish(self) -> None:
        """Otherwise whichever frontend comes first in the directory answers."""

        with self.assertRaises(GeneratorError) as raised:
            generate(
                [load_proxy("shop", MINIMAL)],
                vips=dict(DEFAULT_VIPS),
                default_vip="main",
                reservations=Reservations(hostnames=frozenset({"shop.example.com"})),
            )

        self.assertIn("shop.example.com", str(raised.exception))
        self.assertIn("manual/reservations.yaml", str(raised.exception))

    def test_a_reserved_port_stops_the_publish(self) -> None:
        """Two frontends on one port both bind it and split the traffic at random."""

        with self.assertRaises(GeneratorError) as raised:
            generate(
                [load_proxy("shop", MINIMAL)],
                vips=dict(DEFAULT_VIPS),
                default_vip="main",
                reservations=Reservations(tcp_ports=frozenset({80})),
            )

        self.assertIn("port 80", str(raised.exception))

    def test_a_port_no_object_causes_to_be_bound_is_not_a_conflict(self) -> None:
        """Writing down what the handwritten side uses is the file's whole purpose."""

        files = generate(
            [load_proxy("shop", MINIMAL)],
            vips=dict(DEFAULT_VIPS),
            default_vip="main",
            reservations=Reservations(tcp_ports=frozenset({8443})),
        ).configuration

        self.assertIn("1000-frontends.cfg", files)


class AVerifiedPoolSendsItsName(unittest.TestCase):
    """Measured on 3.4.4, 2026-09-04, after a site 503'd with a green health card.

    `ssl verify required ca-file @system-ca` without `sni` failed the handshake
    on every request - `SC--`, nothing established, three retries inside a
    millisecond - against a pool whose certificate `openssl s_client` accepts
    with `Verify return code: 0`. Adding `sni` fixed it and `verifyhost` alone
    did not, isolated across five configurations.

    The check deliberately does not carry it. `check-sni` looks like the
    matching half and makes every server fail with `L6RSP` instead, measured
    the same day against the same pool.
    """

    def rendered(self, document: bytes) -> str:
        files = generate(
            [load_proxy("shop", document)],
            vips=dict(DEFAULT_VIPS),
            default_vip="main",
        ).configuration
        return files["1001-shop.cfg"]

    def test_a_verified_pool_sends_the_server_name(self) -> None:
        text = self.rendered(VERIFIED)

        self.assertIn("sni str(pool-a.example.net)", text)

    def test_the_check_does_not_send_it(self) -> None:
        """Measured both ways: `check-sni` marks every server down with `L6RSP`.

        The argument for adding it is good - a check that speaks a different
        handshake than the traffic reports on something nobody asked about -
        and the behaviour on 3.4.4 contradicts it. The measurement wins.
        """

        self.assertNotIn("check-sni", self.rendered(VERIFIED))

    def test_an_unverified_pool_sends_nothing(self) -> None:
        """Nothing to check the name against, so there is no name to send."""

        text = self.rendered(VERIFIED.replace(b"verify: system", b"verify: none"))

        self.assertNotIn("sni ", text)

    def test_a_verified_pool_named_by_address_is_refused(self) -> None:
        """There is no honest default: an address is not the name on a certificate."""

        with self.assertRaises(ModelError) as raised:
            load_proxy("shop", VERIFIED.replace(b"pool-a.example.net", b"192.0.2.10"))

        self.assertIn("192.0.2.10", str(raised.exception))
        self.assertIn("hostname", str(raised.exception))


class AReservationNamesAnAddress(unittest.TestCase):
    """B86: a port claimed cluster-wide is unusable once there are two VIPs.

    The arrangement this file exists for is something complex written by hand
    beside the generated objects, and that needs more than one address. A
    reservation that could not say which one would block every managed object
    everywhere, so making one would cost more than the collision it prevents.
    """

    #
    # Two addresses, because one cannot show the difference between "here" and
    # "everywhere" - which is the whole question.
    #
    TWO_VIPS = {
        "main": Vip(name="main", address="192.0.2.20"),
        "other": Vip(name="other", address="198.51.100.20"),
    }

    def publish(self, reservations: Reservations) -> dict[str, str]:
        return generate(
            [load_proxy("shop", MINIMAL)],
            vips=dict(self.TWO_VIPS),
            default_vip="main",
            reservations=reservations,
        ).configuration

    def test_a_port_reserved_on_another_address_does_not_stop_the_publish(self) -> None:
        """The failure that made the mechanism unusable before it was addressed."""

        files = self.publish(Reservations(tcp_listeners=frozenset({("198.51.100.20", 80)})))

        self.assertIn("1000-frontends.cfg", files)

    def test_a_port_reserved_on_the_objects_own_address_stops_it(self) -> None:
        with self.assertRaises(GeneratorError) as raised:
            self.publish(Reservations(tcp_listeners=frozenset({("192.0.2.20", 80)})))

        self.assertIn("main port 80", str(raised.exception))
        self.assertIn("manual/reservations.yaml", str(raised.exception))

    def test_a_port_reserved_without_an_address_still_stops_it(self) -> None:
        """A `bind` line without an address takes the port on every one of them."""

        with self.assertRaises(GeneratorError) as raised:
            self.publish(Reservations(tcp_ports=frozenset({80})))

        self.assertIn("port 80", str(raised.exception))


class OneAddressAndPortIsBoundOnce(unittest.TestCase):
    """`haproxy -c` says yes, and then both listeners quietly share the port."""

    def tcp(self, name: str, port: int) -> Proxy:
        document = f"""
schema: 1
name: {name}
listen:
  protocol: tcp
  port: {port}
backend: {name}-pool
backends:
  {name}-pool:
    balance: leastconn
    health:
      type: disabled
    servers:
      - host: 198.51.100.10
        port: 5432
"""
        return load_proxy(name, document.encode())

    def test_two_tcp_objects_on_one_port_are_refused(self) -> None:
        with self.assertRaises(GeneratorError) as raised:
            _generate([self.tcp("db", 5432), self.tcp("cache", 5432)])

        self.assertIn("5432", str(raised.exception))

    def test_a_tcp_object_may_not_take_a_port_the_cluster_serves_http_on(self) -> None:
        with self.assertRaises(GeneratorError) as raised:
            _generate([self.tcp("db", 80), load_proxy("shop", MINIMAL)])

        self.assertIn("http", str(raised.exception))

    def test_a_tcp_object_may_not_take_the_port_a_redirect_listens_on(self) -> None:
        """The redirect frontend is not named in any object's listen.protocol.

        A https object with redirect_http puts a frontend on port 80 all the
        same, and asking each object what protocol it named would miss it - so
        the tcp object would be accepted and the two would split port 80
        between them.
        """

        with self.assertRaises(GeneratorError) as raised:
            _generate([self.tcp("db", 80), load_proxy("app", HTTPS)])

        self.assertIn("port 80", str(raised.exception))

    def test_two_ports_on_one_address_are_two_frontends(self) -> None:
        frontends = _generate([self.tcp("db", 5432), self.tcp("cache", 6379)])["1000-frontends.cfg"]

        self.assertIn("frontend mgd-main-tcp-5432", frontends)
        self.assertIn("frontend mgd-main-tcp-6379", frontends)


class OneCertificateMayCarrySeveralNamedPolicies(unittest.TestCase):
    def document(self, name: str, policy: str) -> Proxy:
        return load_proxy(
            name,
            (
                f"schema: 1\nname: {name}\nhostnames: [{name}.example.com]\n"
                f"listen:\n  protocol: https\n  certificate: shared\n{policy}"
                f"routes:\n  - path: /\n    backend: {name}-web\n"
                f"backends:\n  {name}-web:\n    balance: roundrobin\n"
                "    health:\n      type: disabled\n"
                "    servers:\n      - host: 198.51.100.10\n        port: 8080\n"
            ).encode(),
        )

    def test_two_sites_asking_differently_get_sni_filtered_lines(self) -> None:
        files = generate(
            [self.document("one", "  tls: modern\n"), self.document("two", "")],
            vips=dict(DEFAULT_VIPS),
            default_vip="main",
            certificates=("shared",),
            certificate_sans={"shared": ("one.example.com", "two.example.com")},
        )

        listing = next(iter(files.certificate_lists.values()))
        self.assertEqual(listing.count("shared.pem"), 3)
        self.assertTrue(listing.startswith(f"{NODE_CERTIFICATE_DIR}/shared.pem\n"))
        self.assertIn("shared.pem [ssl-min-ver TLSv1.3", listing)
        self.assertIn("one.example.com", listing)
        self.assertIn("shared.pem two.example.com", listing)
        frontend = files.configuration["1000-frontends.cfg"]
        self.assertIn("ssl_fc_sni,lower -m str one.example.com", frontend)
        self.assertIn("deny_status 421", frontend)

    def test_the_same_certificate_may_differ_between_two_vips(self) -> None:
        """The unit is the certificate on one listener, not everywhere.

        Each listener writes a certificate list of its own, so a certificate
        that serves sites on two addresses has a line in each file and can be
        held to different terms in each. Only the two sites sharing one line -
        one certificate on one listener - have to agree.

        Worth a test of its own because the refusal above reads as though it
        were about the certificate globally, and somebody reading only that one
        would reasonably give two VIPs two certificates they do not need.
        """

        vips = {
            "main": Vip(name="main", address="192.0.2.20"),
            "other": Vip(name="other", address="192.0.2.21"),
        }
        files = generate(
            [
                self.document("one", "  tls: modern\n"),
                self.document("two", "  vip: other\n"),
            ],
            vips=vips,
            default_vip="main",
            certificates=("shared",),
            certificate_sans={"shared": ("one.example.com", "two.example.com")},
        )

        listings = files.certificate_lists
        self.assertEqual(len(listings), 2)
        held = sorted(body.strip() for body in listings.values())
        self.assertTrue(all("shared.pem" in body for body in held))
        self.assertTrue(any("shared.pem [" in body for body in held))

    def test_two_sites_asking_the_same_are_fine(self) -> None:
        """The refusal is about disagreement, not about sharing."""

        files = generate(
            [
                self.document("one", "  tls: modern\n"),
                self.document("two", "  tls: modern\n"),
            ],
            vips=dict(DEFAULT_VIPS),
            default_vip="main",
            certificates=("shared",),
            certificate_sans={"shared": ("one.example.com", "two.example.com")},
        ).configuration

        self.assertIn("1000-frontends.cfg", files)
        self.assertNotIn("deny_status 421", files["1000-frontends.cfg"])


@unittest.skipUnless(shutil.which("haproxy"), "haproxy is not installed here")
class SharedTablesAreCheckedAsANode(unittest.TestCase):
    """`haproxy -c` on the manager drops a peers section it is not in (B270)."""

    def check(self, *extra: str) -> str:
        case = next(case for case in cases() if case.name == "peers")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "conf.d").mkdir()
            (root / "haproxy.cfg").write_text(CORE)
            for name, content in produced(case).items():
                (root / "conf.d" / name).write_text(content)
            binary = shutil.which("haproxy")
            assert binary is not None
            result = subprocess.run(  # the local haproxy, a generated case
                [
                    binary,
                    "-c",
                    *extra,
                    *(peer_arguments(root / "conf.d") if not extra else ()),
                    "-f",
                    str(root / "haproxy.cfg"),
                    "-f",
                    str(root / "conf.d"),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout + result.stderr

    def test_as_the_first_node_the_section_is_kept(self) -> None:
        self.assertNotIn("Removing incomplete section", self.check())

    def test_as_nobody_it_is_dropped_with_a_warning(self) -> None:
        self.assertIn("Removing incomplete section", self.check("-L", "mgr"))


class DynamicBlockingInTheGeneratedText(unittest.TestCase):
    """What the golden case does not show: no trusted proxy, and refusals (B271)."""

    SHOP = """schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
rate_limit:
  max_requests: 100
dynamic_block:
  max_requests: 300
  block_for: 30m
  status: 429
  exempt: [{exempt}]
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    servers:
      - host: 198.51.100.10
        port: 8080
"""

    def files(self, exempt: str = "192.0.2.10", **options: Any) -> dict[str, str]:
        proxy = load_proxy("shop", self.SHOP.format(exempt=exempt).encode())
        return generate(
            [proxy], vips=dict(DEFAULT_VIPS), default_vip="main", **options
        ).configuration

    def test_without_a_trusted_proxy_the_source_is_counted_and_blocked(self) -> None:
        text = self.files()["1001-shop.cfg"]
        rules = [line.strip() for line in text.splitlines() if "dynblock" in line]
        self.assertEqual(
            rules,
            [
                "acl mgd-shop-dynblock-exempt src 192.0.2.10/32",
                "acl mgd-shop-dynblock-over sc_http_req_rate(3) gt 300",
                "http-request track-sc3 src table mgd-shop-dynblock-rate "
                "if !mgd-shop-dynblock-exempt",
                "http-request track-sc4 src table mgd-shop-dynblock "
                "if !mgd-shop-dynblock-exempt mgd-shop-dynblock-over",
                "http-request set-var(txn.rule) str(dynamic-block:deny) "
                "if !mgd-shop-dynblock-exempt { src,in_table(mgd-shop-dynblock) }",
                "backend mgd-shop-dynblock-rate",
                "backend mgd-shop-dynblock",
            ],
        )
        self.assertNotIn("mgd-trusted-proxy", text)
        self.assertIn("deny_status 429 if { var(txn.rule) -m str dynamic-block:deny }", text)

    def test_the_block_is_counted_before_the_rate_limit_refuses(self) -> None:
        """A flood refused with 429 first would never be counted, and never blocked."""

        text = self.files()["1001-shop.cfg"]
        self.assertLess(text.index("track-sc3"), text.index("track-sc1"))

    def test_an_exempt_group_the_cluster_does_not_define_is_refused(self) -> None:
        with self.assertRaises(GeneratorError) as raised:
            self.files(exempt="monitoring")
        self.assertIn("names the group monitoring", str(raised.exception))
        text = self.files(exempt="monitoring", networks={"monitoring": ("203.0.113.0/24",)})
        self.assertIn("acl mgd-shop-dynblock-exempt src 203.0.113.0/24", text["1001-shop.cfg"])


class APoolVerifiesAgainstTheClustersOwnCa(unittest.TestCase):
    """B276: `verify: ca` names one of the cluster's authorities, from its own directory."""

    def rendered(self, document: bytes, authorities: tuple[str, ...]) -> str:
        files = generate(
            [load_proxy("shop", document)],
            vips=dict(DEFAULT_VIPS),
            default_vip="main",
            authorities=authorities,
        ).configuration
        return files["1001-shop.cfg"]

    def document(self) -> bytes:
        return VERIFIED.replace(b"verify: system", b"verify: ca\n      ca: corp-root")

    def test_the_server_line_reads_the_ca_file_and_still_sends_the_name(self) -> None:
        text = self.rendered(self.document(), ("corp-root",))

        self.assertIn(
            "ssl verify required ca-file /etc/haproxy/certs/ca/corp-root.pem "
            "sni str(pool-a.example.net)",
            text,
        )
        self.assertNotIn("@system-ca", text)

    def test_a_ca_the_cluster_does_not_carry_is_refused_by_name(self) -> None:
        with self.assertRaises(GeneratorError) as raised:
            self.rendered(self.document(), ("other-ca",))

        self.assertIn("corp-root", str(raised.exception))
        self.assertIn("does not carry", str(raised.exception))

    def test_verify_ca_needs_a_ca_and_nothing_else_takes_one(self) -> None:
        with self.assertRaises(ModelError):
            load_proxy("shop", VERIFIED.replace(b"verify: system", b"verify: ca"))
        with self.assertRaises(ModelError):
            load_proxy(
                "shop", VERIFIED.replace(b"verify: system", b"verify: system\n      ca: corp-root")
            )

    def test_a_ca_pool_named_by_address_is_refused_like_a_system_one(self) -> None:
        with self.assertRaises(ModelError):
            load_proxy("shop", self.document().replace(b"pool-a.example.net", b"192.0.2.10"))


TCP_PROXIED = b"""\
schema: 1
name: mail
listen:
  protocol: tcp
  port: 2525
backend: pool
backends:
  pool:
    balance: roundrobin
    proxy_protocol: v2
    health:
      type: tcp
    servers:
      - host: 192.0.2.25
        port: 25
"""


class ATcpPoolMayBeToldTheClientsAddress(unittest.TestCase):
    """B279: `send-proxy-v2` on every server, and the check sends a header too."""

    def server_line(self, document: bytes) -> str:
        text = generate(
            [load_proxy("mail", document)], vips=dict(DEFAULT_VIPS), default_vip="main"
        ).configuration["1001-mail.cfg"]
        return next(line for line in text.splitlines() if line.strip().startswith("server "))

    def test_the_server_and_its_check_send_the_header(self) -> None:
        self.assertIn(" send-proxy-v2 check-send-proxy", self.server_line(TCP_PROXIED))

    def test_without_a_check_there_is_no_check_to_send_it(self) -> None:
        line = self.server_line(TCP_PROXIED.replace(b"type: tcp", b"type: disabled"))

        self.assertIn(" send-proxy-v2", line)
        self.assertNotIn("check-send-proxy", line)

    def test_a_pool_that_does_not_ask_gets_nothing(self) -> None:
        line = self.server_line(TCP_PROXIED.replace(b"    proxy_protocol: v2\n", b""))

        self.assertNotIn("send-proxy", line)

    def test_only_version_2_and_only_on_a_tcp_object(self) -> None:
        with self.assertRaises(ModelError):
            load_proxy("mail", TCP_PROXIED.replace(b"proxy_protocol: v2", b"proxy_protocol: v1"))
        with self.assertRaises(ModelError) as raised:
            load_proxy(
                "shop",
                VERIFIED.replace(
                    b"    balance: roundrobin", b"    balance: roundrobin\n    proxy_protocol: v2"
                ),
            )
        self.assertIn("X-Forwarded-For", str(raised.exception))


def subdomain(name: str, hostnames: str, protocol: str = "http", extra: str = "") -> bytes:
    return f"""\
schema: 1
name: {name}
hostnames: {hostnames}
listen:
  protocol: {protocol}
{extra}routes:
  - path: /
    backend: {name}-pool
backends:
  {name}-pool:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 192.0.2.10
        port: 8080
""".encode()


class ASubdomainIsOneObject(unittest.TestCase):
    """B278: `*.apps.example.com` - one label, one wildcard per object, exact names win."""

    def frontend(self, *documents: tuple[str, bytes], **arguments: Any) -> str:
        return generate(
            [load_proxy(name, document) for name, document in documents],
            vips=dict(DEFAULT_VIPS),
            default_vip="main",
            **arguments,
        ).configuration["1000-frontends.cfg"]

    def test_the_name_is_a_one_label_expression(self) -> None:
        text = self.frontend(("apps", subdomain("apps", '["*.apps.example.com"]')))

        self.assertIn(r"lower -m reg ^[^.]+\.apps\.example\.com$", text)
        self.assertNotIn("host-taken", text)

    def test_an_exact_name_under_it_is_taken_out_of_every_rule(self) -> None:
        text = self.frontend(
            ("apps", subdomain("apps", '["*.apps.example.com"]')),
            ("grafana", subdomain("grafana", "[grafana.apps.example.com]")),
            ("shop", subdomain("shop", "[shop.example.com]")),
        )

        taken = [line for line in text.splitlines() if "host-taken" in line and " acl " in line]
        self.assertEqual(len(taken), 1)
        self.assertIn("-m str grafana.apps.example.com", taken[0])
        routed = next(line for line in text.splitlines() if "use_backend apps-pool" in line)
        self.assertRegex(routed, r"if \S+host !\S+host-taken$")

    def test_what_the_model_refuses(self) -> None:
        for hostnames in (
            '["*.com"]',
            '["a.*.example.com"]',
            '["*.a.example.com", "*.b.example.com"]',
        ):
            with self.subTest(hostnames=hostnames), self.assertRaises(ModelError):
                load_proxy("apps", subdomain("apps", hostnames))

    def test_two_objects_with_the_same_subdomain_are_refused(self) -> None:
        with self.assertRaises(GeneratorError):
            self.frontend(
                ("apps", subdomain("apps", '["*.apps.example.com"]')),
                ("more", subdomain("more", '["*.apps.example.com"]')),
            )

    def test_a_reserved_name_under_it_is_refused(self) -> None:
        with self.assertRaises(GeneratorError) as raised:
            self.frontend(
                ("apps", subdomain("apps", '["*.apps.example.com"]')),
                reservations=Reservations(hostnames=frozenset({"legacy.apps.example.com"})),
            )

        self.assertIn("legacy.apps.example.com", str(raised.exception))

    def test_its_certificate_must_name_the_subdomain(self) -> None:
        https = subdomain(
            "apps", '["*.apps.example.com"]', "https", "  certificate: apps-cert\n"
        ).replace(
            b"listen:\n  protocol: https\n  certificate",
            b"listen:\n  protocol: https\n  certificate",
        )
        with self.assertRaises(GeneratorError):
            self.frontend(
                ("apps", https),
                certificates=("apps-cert",),
                certificate_sans={"apps-cert": ("shop.apps.example.com",)},
            )
        self.frontend(
            ("apps", https),
            certificates=("apps-cert",),
            certificate_sans={"apps-cert": ("*.apps.example.com",)},
        )


class AVipMayServeHttp3(unittest.TestCase):
    """B280: a QUIC bind beside the TCP one, `alt-svc` on every answer, UDP held to itself."""

    def frontend(self, *documents: tuple[str, bytes], vip: Vip) -> str:
        return generate(
            [load_proxy(name, document) for name, document in documents],
            vips={"main": vip},
            default_vip="main",
            certificates=("site",),
        ).configuration["1000-frontends.cfg"]

    def https(self) -> bytes:
        return subdomain("shop", "[shop.example.com]", "https", "  certificate: site\n")

    def test_the_quic_bind_shares_the_certificates_and_the_policy(self) -> None:
        text = self.frontend(
            ("shop", self.https()),
            vip=Vip(name="main", address="192.0.2.20", tls_policy="modern", http3=True),
        )
        tcp = next(line for line in text.splitlines() if "bind 192.0.2.20:443" in line)
        quic = next(line for line in text.splitlines() if "bind quic4@192.0.2.20:443" in line)

        self.assertIn("alpn h3 ", quic)
        self.assertEqual(
            quic.split(" ssl ")[1].replace("alpn h3", "")[: len("crt-list")],
            tcp.split(" ssl ")[1][: len("crt-list")],
        )
        self.assertIn("ssl-min-ver TLSv1.3", quic)
        self.assertIn('http-after-response set-header alt-svc "h3=\\":443\\"; ma=86400"', text)

    def test_an_ipv6_vip_is_quic6(self) -> None:
        text = self.frontend(
            ("shop", self.https()), vip=Vip(name="main", address="2001:db8::20", http3=True)
        )

        self.assertIn("bind quic6@2001:db8::20:443", text)

    def test_a_vip_without_it_has_neither(self) -> None:
        text = self.frontend(("shop", self.https()), vip=Vip(name="main", address="192.0.2.20"))

        self.assertNotIn("quic", text)
        self.assertNotIn("alt-svc", text)

    def test_a_dns_object_on_udp_443_of_the_same_address_is_refused(self) -> None:
        dns = b"""\
schema: 1
name: resolver
listen:
  protocol: dns
  port: 443
backend: pool
backends:
  pool:
    balance: firstAvailable
    health:
      type: disabled
    servers:
      - host: 192.0.2.53
        port: 53
"""
        with self.assertRaises(GeneratorError) as raised:
            self.frontend(
                ("shop", self.https()),
                ("resolver", dns),
                vip=Vip(name="main", address="192.0.2.20", http3=True),
            )
        self.assertIn("UDP port 443", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
