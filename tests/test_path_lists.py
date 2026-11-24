"""Path lists and *Denied paths*: the model, the file root keeps, the version's copy, the generator (B527, B532)."""

from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any

from haprion import path_lists, regeneration
from haprion.candidate_validation import DERIVED_LIMITS
from haprion.config import ConfigError
from haprion.generate import (
    BLOCK_REASON_BY_NAME,
    GeneratedLayer,
    GeneratorError,
    generate,
    rule_block_table,
)
from haprion.golden import CERTIFICATES, DEFAULT_VIPS
from haprion.managed_publish import managed_files
from haprion.proxy_model import ModelError, Proxy, load_proxy
from tests.test_golden import _haproxy_check, _https
from tests.test_managed_publish import NETWORK, cluster
from tests.test_regeneration import COMMIT, KEY

SCANNERS = {"scanners": ("/.env", "/wp-login.php")}


def denied(body: str) -> Proxy:
    return _https("shop", f"deny_paths:\n{body}")


def layer(proxy: Proxy, lists: Mapping[str, tuple[str, ...]] = SCANNERS) -> GeneratedLayer:
    return generate(
        [proxy],
        vips=dict(DEFAULT_VIPS),
        default_vip="main",
        certificates=CERTIFICATES,
        path_lists=lists,
    )


def frontend(proxy: Proxy, lists: Mapping[str, tuple[str, ...]] = SCANNERS) -> list[str]:
    return layer(proxy, lists).configuration["1000-frontends.cfg"].split("\n")


class TheModel(unittest.TestCase):
    def test_lists_paths_mode_and_time_are_read(self) -> None:
        proxy = denied(
            "  mode: block\n  lists: [scanners]\n  paths: [/server-info, /server-info]\n"
            "  block_for: 1h\n"
        )
        assert proxy.deny_paths is not None
        self.assertEqual(proxy.deny_paths.lists, ("scanners",))
        self.assertEqual(proxy.deny_paths.paths, ("/server-info",))
        self.assertEqual((proxy.deny_paths.mode, proxy.deny_paths.block_for), ("block", "1h"))
        self.assertTrue(proxy.blocks_on_match)

    def test_log_only_is_what_an_absent_mode_means_and_blocks_nothing(self) -> None:
        proxy = denied("  lists: [scanners]\n")
        assert proxy.deny_paths is not None
        self.assertEqual((proxy.deny_paths.mode, proxy.deny_paths.block_for), ("log", None))
        self.assertFalse(proxy.blocks_on_match)

    def test_block_without_a_time_takes_the_rule_default(self) -> None:
        proxy = denied("  mode: block\n  paths: [/.git]\n")
        assert proxy.deny_paths is not None
        self.assertEqual(proxy.deny_paths.block_for, "30m")

    def test_block_without_a_time_takes_the_time_a_rule_would(self) -> None:
        # Review 26-11-24, PW06: the object's dynamic blocking, else the default.
        proxy = _https(
            "shop",
            "dynamic_block:\n  max_requests: 100\n  block_for: 2h\n"
            "deny_paths:\n  mode: block\n  paths: [/x]\n",
        )
        assert proxy.deny_paths is not None
        self.assertEqual(proxy.deny_paths.block_for, "2h")
        own = denied("  mode: block\n  paths: [/x]\n  block_for: 5m\n")
        assert own.deny_paths is not None
        self.assertEqual(own.deny_paths.block_for, "5m")

    def test_what_cannot_be_a_denied_path_is_refused(self) -> None:
        for body, said in (
            ("  mode: deny\n", "at least one path list or path"),
            ("  paths: [/]\n", "every path"),
            ("  paths: [relative]\n", "absolute path"),
            ("  paths: ['/a%2e']\n", "as it reads decoded"),
            ("  lists: [Scanners]\n", "a path list's name"),
            ("  lists: [a, a]\n", "the same list twice"),
            ("  mode: deny\n  paths: [/x]\n  block_for: 1h\n", "deny mode"),
            ("  mode: other\n  paths: [/x]\n", "mode must be one of"),
            ("  paths: [/x]\n  extra: 1\n", "extra"),
            (f"  paths: [/{'a' * 300}]\n", "longer than"),
        ):
            with self.subTest(body=body), self.assertRaisesRegex(ModelError, said):
                denied(body)

    def test_a_tcp_object_has_no_path_to_deny(self) -> None:
        with self.assertRaisesRegex(ModelError, "no path to refuse on"):
            load_proxy(
                "db",
                b"schema: 1\nname: db\nlisten:\n  protocol: tcp\n  port: 5432\n"
                b"deny_paths:\n  mode: deny\n  paths: [/x]\nbackend: pool\nbackends:\n  pool:\n"
                b"    balance: leastconn\n    health:\n      type: tcp\n    servers:\n"
                b"      - host: 198.51.100.10\n        port: 5432\n",
            )

    def test_a_rule_may_not_take_the_name_the_generator_writes(self) -> None:
        with self.assertRaisesRegex(ModelError, "written by the generator"):
            _https("shop", "deny_rules:\n  - name: deny-paths\n    mode: log\n    path: /x\n")


class TheGenerator(unittest.TestCase):
    def test_each_path_matches_itself_and_what_is_under_it_a_list_is_a_file(self) -> None:
        made = layer(denied("  mode: deny\n  lists: [scanners]\n  paths: [/Server-Info]\n"))
        acl = [
            line.strip()
            for line in made.configuration["1000-frontends.cfg"].split("\n")
            if "acl mgd-shop-deny-paths " in line
        ]
        self.assertEqual(
            acl,
            [
                "acl mgd-shop-deny-paths var(txn.access_path) -m str /server-info",
                "acl mgd-shop-deny-paths var(txn.access_path) -m beg /server-info/",
                "acl mgd-shop-deny-paths var(txn.access_path),concat(/) -m beg "
                "-f /etc/haproxy/maps/paths-scanners.lst",
            ],
        )
        self.assertEqual(
            made.map_files, {"paths-scanners.lst": "# Path list scanners\n/.env/\n/wp-login.php/\n"}
        )
        lines = made.configuration["1000-frontends.cfg"].split("\n")
        self.assertTrue(any("set-var(txn.access_path)" in line for line in lines))
        self.assertTrue(any("str(deny-paths:deny)" in line for line in lines))
        self.assertFalse(any("ruleblock" in line for line in lines))

    def test_a_path_that_cannot_be_decoded_is_refused_in_every_mode_that_reads_it(self) -> None:
        # Review 26-11-24, PW01: the variable is unset for such a path.
        for mode, verdict in (("deny", "deny"), ("block", "deny"), ("log", "log")):
            lines = frontend(denied(f"  mode: {mode}\n  lists: [scanners]\n"))
            with self.subTest(mode=mode):
                self.assertTrue(
                    any(
                        "acl mgd-shop-path-read var(txn.access_path) -m found" in line
                        for line in lines
                    )
                )
                refused = [line for line in lines if "mgd-shop-host !mgd-shop-path-read" in line]
                self.assertTrue(any(f"str(path-chars:{verdict})" in line for line in refused))
                self.assertEqual(
                    any("deny deny_status 400" in line for line in refused), mode != "log"
                )

    def test_a_list_named_by_a_thousand_objects_is_written_once(self) -> None:
        # Review 26-11-24, PW13: the frontend file grew with objects times paths.
        paths = tuple(f"/scanner-probe/path-number-{number:04d}.php" for number in range(500))
        proxies = [
            _https(f"shop{number}", "deny_paths:\n  mode: deny\n  lists: [scanners]\n")
            for number in range(1000)
        ]
        made = generate(
            proxies,
            vips=dict(DEFAULT_VIPS),
            default_vip="main",
            certificates=CERTIFICATES,
            path_lists={"scanners": paths},
        )
        frontend_bytes = len(made.configuration["1000-frontends.cfg"].encode())
        self.assertLess(frontend_bytes, DERIVED_LIMITS.file_bytes // 10)
        self.assertEqual(list(made.map_files), ["paths-scanners.lst"])
        self.assertNotIn("path-number", made.configuration["1000-frontends.cfg"])
        self.assertEqual(made.map_files["paths-scanners.lst"].count("\n"), 501)

    def test_log_only_records_and_refuses_nothing(self) -> None:
        lines = frontend(denied("  lists: [scanners]\n"))
        verdict = [
            line for line in lines if "mgd-shop-deny-paths" in line and "http-request" in line
        ]
        self.assertEqual(len(verdict), 1)
        self.assertIn("str(deny-paths:log)", verdict[0])

    def test_block_places_the_address_in_the_rule_table_for_its_time_as_paths(self) -> None:
        proxy = denied("  mode: block\n  lists: [scanners]\n  block_for: 1h\n")
        lines = frontend(proxy)
        table = rule_block_table("shop", "1h")
        self.assertTrue(any(f"table {table}" in line and "track-sc" in line for line in lines))
        code = BLOCK_REASON_BY_NAME["paths"]
        self.assertTrue(any(f"sc-set-gpt(0,4) {code} " in line for line in lines))

    def test_never_blocked_is_spared_the_block(self) -> None:
        proxy = _https(
            "shop",
            "deny_paths:\n  mode: block\n  paths: [/.env]\nnever_blocked: [198.51.100.0/24]\n",
        )
        tracked = [line for line in frontend(proxy) if "track-sc4" in line]
        self.assertEqual(len(tracked), 1)
        self.assertIn("!mgd-shop-dynblock-exempt", tracked[0])

    def test_a_list_nobody_defined_is_refused(self) -> None:
        with self.assertRaisesRegex(GeneratorError, "path list missing, which does not exist"):
            frontend(denied("  mode: deny\n  lists: [missing]\n"), {})

    def test_an_object_without_denied_paths_is_generated_as_before(self) -> None:
        plain = frontend(_https("shop"), {})
        self.assertEqual(plain, frontend(_https("shop"), SCANNERS))
        self.assertFalse(any("deny-paths" in line for line in plain))

    def test_haproxy_takes_every_mode(self) -> None:
        for mode in ("log", "deny", "block"):
            proxy = denied(f"  mode: {mode}\n  lists: [scanners]\n  paths: [/server-info]\n")
            layer = generate(
                [proxy],
                vips=dict(DEFAULT_VIPS),
                default_vip="main",
                certificates=CERTIFICATES,
                path_lists=SCANNERS,
            )
            with self.subTest(mode=mode):
                result = _haproxy_check(
                    layer.configuration, layer.certificate_lists, layer.map_files
                )
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


class TheFileRootKeeps(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def write(self, item: path_lists.PathList) -> Path:
        return path_lists.write(item, directory=self.directory, require_secure=False)

    def test_a_list_is_written_read_and_removed(self) -> None:
        item = path_lists.path_list("scanners", ["/.env", "/.env", "/wp-login.php"], "Scanners", 2)
        path = self.write(item)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path_lists.read_all(directory=self.directory), {"scanners": item})
        self.assertEqual(item.paths, ("/.env", "/wp-login.php"))
        self.assertTrue(
            path_lists.remove("scanners", directory=self.directory, require_secure=False)
        )
        self.assertFalse(
            path_lists.remove("scanners", directory=self.directory, require_secure=False)
        )
        self.assertEqual(path_lists.read_all(directory=self.directory), {})

    def test_an_older_revision_does_not_replace_a_newer_one(self) -> None:
        self.write(path_lists.path_list("scanners", ["/.env"], revision=3))
        with self.assertRaisesRegex(path_lists.PathListError, "revision 2 is older"):
            self.write(path_lists.path_list("scanners", ["/.git"], revision=2))

    def test_the_directory_must_be_roots_alone(self) -> None:
        with self.assertRaisesRegex(path_lists.PathListError, "owned by root, mode 0700"):
            path_lists.write(path_lists.path_list("a", ["/x"]), directory=self.directory)

    def test_a_damaged_or_misplaced_file_is_refused(self) -> None:
        (self.directory / "other.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "revision": 1,
                    "name": "scanners",
                    "description": "",
                    "paths": ["/.env"],
                }
            )
        )
        with self.assertRaisesRegex(path_lists.PathListError, "holds the path list scanners"):
            path_lists.read_all(directory=self.directory)
        (self.directory / "other.json").write_text("{}")
        with self.assertRaisesRegex(path_lists.PathListError, "shape"):
            path_lists.read_all(directory=self.directory)

    def test_what_cannot_be_a_list_is_refused(self) -> None:
        for args, said in (
            (("Bad", ["/x"]), "name"),
            (("a", []), "at least one path"),
            (("a", ["/"]), "every path"),
            (("a", ["/x"], "line\nbreak"), "one line"),
            (("a", ["/x"], "", 0), "revision"),
        ):
            with self.subTest(args=args), self.assertRaisesRegex(path_lists.PathListError, said):
                path_lists.path_list(*args)

    def test_the_store_reader_gives_the_lists_named_and_refuses_a_missing_one(self) -> None:
        self.write(path_lists.path_list("scanners", ["/.env"]))
        reader = path_lists.store_reader(self.directory)
        self.assertEqual(reader({"scanners"}), {"scanners": ("/.env",)})
        with self.assertRaisesRegex(ConfigError, "path list other does not exist"):
            reader({"other"})

    def test_another_lists_damaged_file_stops_nothing(self) -> None:
        # Review 26-11-24, PW04: only the files of the lists named are read.
        self.write(path_lists.path_list("scanners", ["/.env"]))
        (self.directory / "other.json").write_text("{")
        reader = path_lists.store_reader(self.directory)
        self.assertEqual(reader({"scanners"}), {"scanners": ("/.env",)})
        with self.assertRaisesRegex(ConfigError, "other.json could not be read"):
            reader({"other"})
        with self.assertRaisesRegex(ConfigError, "a path list's name"):
            reader({"Bad Name"})

    def test_a_list_can_be_saved_over_its_damaged_file_and_says_so(self) -> None:
        (self.directory / "scanners.json").write_text("{")
        notes: list[str] = []
        path_lists.write(
            path_lists.path_list("scanners", ["/.env"], revision=1),
            directory=self.directory,
            require_secure=False,
            warnings=notes,
        )
        self.assertEqual(len(notes), 1)
        self.assertIn("could not be read", notes[0])
        self.assertEqual(
            path_lists.read_all(directory=self.directory)["scanners"].paths, ("/.env",)
        )

    def test_a_directory_that_cannot_be_read_is_an_error_not_a_crash(self) -> None:
        blocked = self.directory / "path-lists"
        blocked.write_text("a file where a directory belongs")
        with self.assertRaisesRegex(path_lists.PathListError, "could not be read"):
            path_lists.read_all(directory=blocked)
        self.assertEqual(path_lists.digest(directory=blocked), "unreadable")

    def test_a_damaged_file_no_object_names_changes_the_digest_by_its_name_only(self) -> None:
        self.write(path_lists.path_list("scanners", ["/.env"]))
        before = path_lists.digest(directory=self.directory)
        self.assertNotEqual(before, "unreadable")
        (self.directory / "other.json").write_text("{")
        after = path_lists.digest(directory=self.directory)
        self.assertNotIn(after, (before, "unreadable"))
        (self.directory / "other.json").write_text("{ ")
        self.assertEqual(after, path_lists.digest(directory=self.directory))

    def test_the_digest_moves_with_the_paths(self) -> None:
        self.write(path_lists.path_list("scanners", ["/.env"]))
        before = path_lists.digest(directory=self.directory)
        self.write(path_lists.path_list("scanners", ["/.env", "/.git"], revision=2))
        self.assertNotEqual(before, path_lists.digest(directory=self.directory))


def object_document(extra: str) -> bytes:
    return (
        "schema: 1\nname: shop\nhostnames: [shop.example.com]\nlisten:\n  protocol: http\n"
        f"{extra}routes:\n- path: /\n  backend: web\nbackends:\n  web:\n    balance: roundrobin\n"
        "    health:\n      type: disabled\n    servers:\n    - host: 198.51.100.10\n"
        "      port: 8080\n"
    ).encode()


def reader(lists: Mapping[str, tuple[str, ...]]) -> path_lists.Reader:
    def read(names: Collection[str]) -> Mapping[str, tuple[str, ...]]:
        missing = sorted(set(names) - set(lists))
        if missing:
            raise ConfigError(f"the path list {missing[0]} does not exist")
        return {name: lists[name] for name in names}

    return read


class TheVersionCarriesACopy(unittest.TestCase):
    def publish(
        self, base: dict[str, bytes], lists: Mapping[str, tuple[str, ...]] | None
    ) -> dict[str, bytes]:
        return managed_files(
            {"managed/network.yaml": NETWORK, **base},
            network_document=NETWORK,
            cluster=cluster(),
            path_list_reader=reader(lists) if lists is not None else None,
        )

    def test_a_publish_copies_only_the_lists_named(self) -> None:
        document = object_document("deny_paths:\n  mode: deny\n  lists: [scanners]\n")
        files = self.publish(
            {"managed/proxies/shop.yaml": document}, {**SCANNERS, "other": ("/x",)}
        )
        self.assertEqual(
            path_lists.load_snapshot(files[path_lists.SNAPSHOT]), {"scanners": SCANNERS["scanners"]}
        )
        self.assertEqual(
            files["managed/maps/paths-scanners.lst"],
            b"# Path list scanners\n/.env/\n/wp-login.php/\n",
        )
        self.assertNotIn("managed/maps/paths-other.lst", files)

    def test_without_a_reader_the_versions_own_copy_is_taken(self) -> None:
        document = object_document("deny_paths:\n  mode: deny\n  lists: [scanners]\n")
        first = self.publish({"managed/proxies/shop.yaml": document}, {"scanners": ("/old",)})
        again = self.publish({**first, "managed/proxies/shop.yaml": document}, None)
        self.assertEqual(again[path_lists.SNAPSHOT], first[path_lists.SNAPSHOT])
        self.assertIn(b"/old/", again["managed/maps/paths-scanners.lst"])

    def test_no_list_named_leaves_no_copy(self) -> None:
        named = object_document("deny_paths:\n  mode: deny\n  lists: [scanners]\n")
        first = self.publish({"managed/proxies/shop.yaml": named}, SCANNERS)
        files = self.publish({**first, "managed/proxies/shop.yaml": object_document("")}, SCANNERS)
        self.assertNotIn(path_lists.SNAPSHOT, files)
        self.assertNotIn("managed/maps/paths-scanners.lst", files)

    def test_a_list_that_is_gone_refuses_the_publish(self) -> None:
        document = object_document("deny_paths:\n  mode: deny\n  lists: [scanners]\n")
        with self.assertRaisesRegex(ConfigError, "path list scanners does not exist"):
            self.publish({"managed/proxies/shop.yaml": document}, {})

    def test_a_damaged_copy_is_refused(self) -> None:
        for content, said in (
            (b"schema: 2\nlists: {}\n", "must hold schema"),
            (b"schema: 1\nlists:\n  scanners: [/]\n", "every path"),
            (b"[", "not valid YAML"),
        ):
            with self.subTest(content=content), self.assertRaisesRegex(ConfigError, said):
                path_lists.load_snapshot(content)


class ARegenerationSaysAListChanged(unittest.TestCase):
    def tree(self, lists: Mapping[str, tuple[str, ...]]) -> dict[str, bytes]:
        base = {
            "managed/network.yaml": NETWORK,
            "managed/proxies/shop.yaml": object_document(
                "deny_paths:\n  mode: deny\n  lists: [scanners]\n"
            ),
        }
        generated = managed_files(
            base, network_document=NETWORK, cluster=cluster(), path_list_reader=reader(lists)
        )
        return {
            **base,
            **generated,
            "core/haproxy.cfg": b"global\n",
            "manual/reservations.yaml": b"{}\n",
        }

    def regenerate(self, files: dict[str, bytes], lists: Mapping[str, tuple[str, ...]]) -> Any:
        from tests.test_regeneration import core_is_current

        with core_is_current():
            return regeneration.regenerate(
                files,
                cluster(),
                commit=COMMIT,
                version=3,
                key=KEY,
                addresses=(),
                installed_crs=None,
                rule_set=lambda: None,
                path_list_reader=reader(lists),
            )

    def test_a_changed_list_is_a_required_cause_naming_it(self) -> None:
        files = self.tree({"scanners": ("/.env",)})
        result = self.regenerate(files, {"scanners": ("/.env", "/.git")})
        self.assertEqual(result["outcome"], "changed")
        self.assertTrue(result["required"])
        self.assertIn({"kind": "path_lists", "lists": ["scanners"]}, result["causes"])

    def test_the_same_list_changes_nothing(self) -> None:
        files = self.tree({"scanners": ("/.env",)})
        self.assertEqual(self.regenerate(files, {"scanners": ("/.env",)})["outcome"], "unchanged")

    def test_the_fingerprint_moves_with_the_lists(self) -> None:
        def key(digest: str | None) -> str:
            return regeneration.fingerprint(COMMIT, cluster(), (), None, path_lists_digest=digest)

        self.assertNotEqual(key("a"), key("b"))


if __name__ == "__main__":
    unittest.main()
