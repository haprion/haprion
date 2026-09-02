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

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from haproxy_mgmt.config import TLS_POLICY_NAMES, AbuseProtection, Vip
from haproxy_mgmt.generate import (
    NODE_CERTIFICATE_DIR,
    TLS_POLICIES,
    GeneratorError,
    generate,
)
from haproxy_mgmt.golden import (
    CERTIFICATES,
    DEFAULT_VIPS,
    GOLDEN,
    arguments,
    cases,
    expected,
    objects,
    produced,
)
from haproxy_mgmt.proxy_model import Proxy, load_proxy
from haproxy_mgmt.reservations import Reservations

#
# Enough of a configuration for `haproxy -c` to have something to attach the
# generated fragments to. It stands in for what `core/` provides on a node: the
# generated files are fragments of a directory, and a fragment cannot be
# validated entirely on its own.
#
CORE = """
global
    daemon
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


class EveryCaseMatchesItsGoldenFiles(unittest.TestCase):
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
                    generate(list(reversed(loaded)), **cluster),  # type: ignore[arg-type]
                    generate(loaded, **cluster),  # type: ignore[arg-type]
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
                (root / "0000-core.cfg").write_text(CORE)
                certificates = _certificate_directory(root)
                for name, content in produced(case).items():
                    #
                    # The same substitution `candidate_validation` makes when it
                    # validates a candidate in a sandbox that has no /etc: the
                    # node's certificate directory becomes one that exists here.
                    # HAProxy refuses to start on a certificate it cannot stat,
                    # so without this an https case could not be validated at
                    # all.
                    #
                    content = content.replace(NODE_CERTIFICATE_DIR, str(certificates))
                    (root / name).write_text(content)

                arguments: list[str] = []
                for path in sorted(root.iterdir()):
                    arguments += ["-f", str(path)]
                binary = shutil.which("haproxy")
                assert binary is not None
                result = subprocess.run(
                    [binary, "-c", *arguments],
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


def _generate(proxies: list[Proxy]) -> dict[str, str]:
    """The generator on a cluster with one plain address, which most are."""

    return generate(proxies, vips=dict(DEFAULT_VIPS), default_vip="main", certificates=CERTIFICATES)


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


if __name__ == "__main__":
    unittest.main()


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

    def test_a_redirect_puts_the_object_on_port_80_as_well(self) -> None:
        """An https object that redirects needs a listener on 80 to redirect from."""

        files = _generate([load_proxy("app", HTTPS)])
        frontends = files["1000-frontends.cfg"]

        self.assertIn("bind 192.0.2.20:80", frontends)
        self.assertIn("redirect scheme https code 301", frontends)
        self.assertIn("bind 192.0.2.20:443 ssl crt", frontends)

    def test_the_strict_transport_header_is_written_in_the_backend(self) -> None:
        """HAProxy refuses to make it conditional anywhere else.

        An `http-response` rule in a frontend cannot read the request's Host
        header - HAProxy warns that such an ACL "will never match" - so the
        header goes in the backend, which belongs to one object and needs no
        condition at all.
        """

        files = _generate([load_proxy("app", HTTPS)])

        self.assertNotIn("Strict-Transport-Security", files["1000-frontends.cfg"])
        self.assertIn(
            'http-response set-header Strict-Transport-Security "max-age=31536000; '
            'includeSubDomains"',
            files["1001-app.cfg"],
        )


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

        self.assertIn("acl mgd-admin-allow src 198.51.100.0/24 203.0.113.128/25", frontends)
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
        route = frontends.index("use_backend mgd-shop-web")

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
        )["1000-frontends.cfg"]

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
        )["1000-frontends.cfg"]

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
        )["1000-frontends.cfg"]

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
        )

        self.assertIn("1000-frontends.cfg", files)


class OneAddressAndPortIsBoundOnce(unittest.TestCase):
    """`haproxy -c` says yes, and then both listeners quietly share the port."""

    def tcp(self, name: str, port: int) -> Proxy:
        document = f"""
schema: 1
name: {name}
listen:
  protocol: tcp
  port: {port}
backend: pool
backends:
  pool:
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
