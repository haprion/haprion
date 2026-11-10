"""A blocklist as an object's *Denied* group: one `-f` line, nowhere else (B500)."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from haprion.candidate_validation import materialize_candidate, parse_candidate
from haprion.generate import BLOCKLISTS_DIRECTORY, GeneratorError, generate
from haprion.golden import CERTIFICATES, DEFAULT_VIPS
from haprion.proxy_model import ModelError, Proxy, load_proxy
from tests.test_golden import _haproxy_check, _https

NETWORKS = {"office": ("198.51.100.0/24",)}


def _tcp(extra: str) -> Proxy:
    return load_proxy(
        "db",
        f"""schema: 1
name: db
listen:
  protocol: tcp
  port: 5432
{extra}backend: pool
backends:
  pool:
    balance: leastconn
    health:
      type: tcp
    servers:
      - host: 198.51.100.10
        port: 5432
""".encode(),
    )


def _layer(proxies: list[Proxy], blocklists: tuple[str, ...] = ("crowdsec",)) -> dict[str, str]:
    return dict(
        generate(
            proxies,
            vips=dict(DEFAULT_VIPS),
            default_vip="main",
            certificates=CERTIFICATES,
            networks=NETWORKS,
            blocklists=blocklists,
        ).configuration
    )


def _lines(files: dict[str, str], start: str) -> list[str]:
    return [line for line in files["1000-frontends.cfg"].split("\n") if line.startswith(start)]


class AListIsReadFromItsFile(unittest.TestCase):
    def test_denied_names_the_file_beside_its_groups_and_ranges(self) -> None:
        files = _layer(
            [_https("shop", "deny_from:\n  mode: deny\n  sources: [crowdsec, office, 192.0.2.7]\n")]
        )

        self.assertEqual(
            _lines(files, "    acl mgd-shop-deny-from "),
            [
                "    acl mgd-shop-deny-from src 192.0.2.7/32 198.51.100.0/24",
                f"    acl mgd-shop-deny-from src -f {BLOCKLISTS_DIRECTORY}/crowdsec.lst",
            ],
        )
        self.assertTrue(_lines(files, "    http-request deny deny_status 403 if mgd-shop-host"))

    def test_a_list_alone_is_one_condition(self) -> None:
        files = _layer([_https("shop", "deny_from:\n  sources: [crowdsec]\n")])

        self.assertEqual(
            _lines(files, "    acl mgd-shop-deny-from "),
            [f"    acl mgd-shop-deny-from src -f {BLOCKLISTS_DIRECTORY}/crowdsec.lst"],
        )

    def test_a_tcp_object_rejects_the_connection(self) -> None:
        files = _layer([_tcp("deny_from:\n  mode: deny\n  sources: [crowdsec]\n")])

        self.assertIn(
            f"    acl mgd-db-deny-from src -f {BLOCKLISTS_DIRECTORY}/crowdsec.lst",
            files["1000-frontends.cfg"],
        )
        self.assertIn(
            "tcp-request connection reject if mgd-db-deny-from", files["1000-frontends.cfg"]
        )


class AListOnlyDenies(unittest.TestCase):
    def test_anywhere_else_it_is_refused(self) -> None:
        reached = 0
        for extra in (
            "allow_from: [crowdsec]\n",
            "deny_rules:\n  - name: lists\n    source: crowdsec\n",
            "dynamic_block:\n  max_requests: 100\n  window: 10s\n  block_for: 5m\n"
            "  exempt: [crowdsec]\n",
        ):
            with self.subTest(extra=extra.split(":")[0]):
                try:
                    proxy = _https("shop", extra)
                except ModelError:
                    continue
                reached += 1
                with self.assertRaisesRegex(GeneratorError, "outside Denied"):
                    _layer([proxy])
        self.assertGreaterEqual(reached, 2, "the model refused the cases before the generator")

    def test_a_group_with_a_lists_name_is_refused(self) -> None:
        with self.assertRaisesRegex(GeneratorError, "share a name"):
            _layer([_https("shop")], blocklists=("office",))

    def test_a_name_that_is_neither_is_the_unknown_group_it_was(self) -> None:
        with self.assertRaisesRegex(GeneratorError, "does not define"):
            _layer([_https("shop", "deny_from:\n  sources: [crowdsec]\n")], blocklists=())


@unittest.skipUnless(shutil.which("haproxy") and shutil.which("openssl"), "no haproxy here")
class HaproxyTakesIt(unittest.TestCase):
    def test_the_layer_validates_against_a_list_file(self) -> None:
        layer = generate(
            [_https("shop", "deny_from:\n  mode: deny\n  sources: [crowdsec]\n")],
            vips=dict(DEFAULT_VIPS),
            default_vip="main",
            certificates=CERTIFICATES,
            blocklists=("crowdsec",),
        )
        with tempfile.TemporaryDirectory() as directory:
            lists = Path(directory)
            (lists / "crowdsec.lst").write_text("192.0.2.0/24\n2001:db8::1\n")
            configuration = {
                name: content.replace(BLOCKLISTS_DIRECTORY, str(lists))
                for name, content in layer.configuration.items()
            }
            result = _haproxy_check(configuration, layer.certificate_lists)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


class TheCandidateGetsAStandIn(unittest.TestCase):
    def test_each_named_list_is_an_empty_file_in_the_sandbox(self) -> None:
        candidate = parse_candidate(
            {
                "files": {
                    "haproxy.cfg": "global\n",
                    "conf.d/1000-frontends.cfg": (
                        f"    acl a src -f {BLOCKLISTS_DIRECTORY}/crowdsec.lst\n"
                        f"    acl b src -f {BLOCKLISTS_DIRECTORY}/spamhaus-drop.lst\n"
                    ),
                }
            }
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "candidate"
            materialize_candidate(
                candidate, root, certificate_ids=(), validation_certificate=b"dummy PEM\n"
            )
            self.assertIn(
                b"-f /candidate/blocklists/crowdsec.lst",
                (root / "conf.d/1000-frontends.cfg").read_bytes(),
            )
            self.assertEqual(
                sorted(p.name for p in (root / "blocklists").iterdir()),
                ["crowdsec.lst", "spamhaus-drop.lst"],
            )
            self.assertEqual((root / "blocklists" / "crowdsec.lst").read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
