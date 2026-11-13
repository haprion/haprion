"""Would publishing again change what runs: the published version made again and compared."""

from __future__ import annotations

import dataclasses
import io
import json
import tempfile
import unittest
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from unittest import mock

import yaml

from haprion import crs, exit_codes, generate, geo, objects, regeneration, tls_policy
from haprion.cli import readings_helper, regeneration_helper
from haprion.config import Cluster, ConfigError, load_policy, load_runtime_config
from haprion.deploy_plan import ReleaseTarget
from haprion.managed_publish import managed_files
from haprion.release_layout import LayoutError
from haprion.version_diff import MAX_FILES
from tests.contract_schema import assert_contract
from tests.test_managed_publish import NETWORK, cluster

BASE = Path(__file__).resolve().parents[1]
COMMIT = "c" * 40
KEY = "b" * 64
PUBLISHED = ReleaseTarget(version=3, hash=COMMIT)
REQUEST_ID = "55555555-5555-4555-8555-555555555555"


def rule_set(version: str = "9.9.9", rules: bytes = b"# rules\n") -> crs.RuleSet:
    return crs.RuleSet(
        version=version,
        files={
            "VERSION": f"{version}\n".encode(),
            "crs-setup.conf": b"# setup\n",
            "rules/REQUEST-901-INITIALIZATION.conf": rules,
        },
    )


def site(number: int, extra: str = "") -> bytes:
    name = f"site{number:02d}"
    return (
        f"schema: 1\nname: {name}\nhostnames: [{name}.example.com]\nlisten:\n  protocol: http\n"
        f"{extra}routes:\n- path: /\n  backend: web{number:02d}\nbackends:\n  web{number:02d}:\n    balance: roundrobin\n"
        f"    health:\n      type: disabled\n    servers:\n    - host: 198.51.100.{10 + number}\n"
        "      port: 8080\n"
    ).encode()


def published_tree(
    *,
    on: Cluster | None = None,
    rules: crs.RuleSet | None = None,
    countries: geo.CountryReader | None = None,
    count: int = 4,
    addresses: tuple[tuple[str, str], ...] = (),
) -> dict[str, bytes]:
    """A version as a publish writes it: several objects, the first two with the WAF."""

    base = {"managed/network.yaml": NETWORK}
    for number in range(count):
        waf = "waf: {mode: block}\n" if number < 2 else ""
        if number == 2:
            waf = "allow_from: [country:SE]\n"
        base[f"managed/proxies/site{number:02d}.yaml"] = site(number, waf)
    rules = rules or rule_set()
    generated = managed_files(
        base,
        network_document=NETWORK,
        cluster=on or cluster(),
        rule_set=lambda: rules,
        country_reader=countries or sweden("2026-10-01", "192.0.2.0/25"),
        node_addresses=lambda: addresses,
    )
    return {
        **base,
        **generated,
        "core/haproxy.cfg": b"global\n",
        "manual/reservations.yaml": b"{}\n",
    }


def sweden(stamp: str, *networks: str) -> geo.CountryReader:
    return lambda _countries: geo.Countries(stamp, {"SE": tuple(networks)})


def regenerated(files: Mapping[str, bytes], **options: Any) -> dict[str, Any]:
    rules = options.pop("rules", None) or rule_set()
    return regeneration.regenerate(
        files,
        options.pop("on", None) or cluster(),
        commit=COMMIT,
        version=3,
        key=KEY,
        addresses=options.pop("addresses", ()),
        installed_crs=rules.version,
        rule_set=lambda: rules,
        location_database=options.pop("database", sweden("2026-10-01", "192.0.2.0/25")),
        **options,
    )


def core_is_current() -> Any:
    """The fixtures' core is bare; the check of its TLS defaults has its own tests below."""

    return mock.patch.object(tls_policy, "core_defaults_problem", return_value=None)


class TheComparison(unittest.TestCase):
    def setUp(self) -> None:
        patch = core_is_current()
        patch.start()
        self.addCleanup(patch.stop)

    def test_an_unchanged_engine_compares_equal_over_several_waf_objects(self) -> None:
        files = published_tree()
        self.assertIn("managed/waf/coraza.yaml", files)

        result = regenerated(files)

        self.assertEqual(result["outcome"], "unchanged")
        self.assertIsNone(result["diff"])
        self.assertEqual(
            (result["objects"], result["files_changed"], result["causes"]), ([], 0, [])
        )
        self.assertEqual((result["published_commit"], result["published_version"]), (COMMIT, 3))

    def test_a_changed_generator_is_found_naming_the_file_and_the_object(self) -> None:
        original = generate._backend

        def backend(proxy: Any, *args: Any, **kwargs: Any) -> list[str]:
            lines = original(proxy, *args, **kwargs)
            return (
                [*lines, "    # a directive the new generator adds"]
                if proxy.name == "site01"
                else lines
            )

        files = published_tree()
        with mock.patch.object(generate, "_backend", backend):
            result = regenerated(files)

        self.assertEqual(result["outcome"], "changed")
        self.assertEqual(
            result["objects"], [{"name": "site01", "change": "changed", "parts": ["backends"]}]
        )
        self.assertEqual(result["files_changed"], 1)
        (change,) = result["diff"]["files"]
        self.assertTrue(change["path"].endswith("-site01.cfg"), change["path"])
        self.assertEqual((change["status"], change["added"], change["removed"]), ("modified", 1, 0))
        self.assertIn("+    # a directive the new generator adds", change["lines"])
        self.assertTrue(change["lines"][0].startswith("@@"))
        self.assertEqual(result["diff"]["commit"], COMMIT)
        self.assertEqual(result["causes"], [])

    def test_a_newer_location_database_does_not_change_the_result(self) -> None:
        files = published_tree()

        result = regenerated(files, database=sweden("2026-11-01", "203.0.113.0/24"))

        self.assertEqual(result["outcome"], "unchanged")

    def test_a_rule_set_that_cannot_be_read_is_a_failed_reading_not_an_answer(self) -> None:
        files = published_tree()

        def unreadable() -> crs.RuleSet:
            raise crs.RuleSetError("rules/x.conf.dpkg-new is not a rule file")

        with self.assertRaisesRegex(regeneration.RegenerationError, "not a rule file"):
            regeneration.regenerate(
                files,
                cluster(),
                commit=COMMIT,
                version=3,
                key=KEY,
                addresses=(),
                installed_crs=None,
                rule_set=unreadable,
            )

    def test_the_checks_a_publish_makes_on_what_it_writes_are_made_on_the_candidate(self) -> None:
        files = published_tree()
        newer = rule_set("9.9.10", b"# rules, newer\n")

        with mock.patch.object(tls_policy, "core_defaults_problem", return_value="core is stale"):
            result = regenerated(files, rules=newer)
            quiet = regenerated(files)

        self.assertEqual((result["outcome"], result["message"]), ("refused", "core is stale"))
        self.assertEqual(quiet["outcome"], "unchanged")

    def test_a_hostname_the_certificate_does_not_cover_is_refused_as_a_publish_would(self) -> None:
        on = dataclasses.replace(cluster(), certificate_ids=("example.com",))
        files = published_tree(on=on)
        files["managed/proxies/site00.yaml"] = files["managed/proxies/site00.yaml"].replace(
            b"protocol: http\n", b"protocol: https\n  certificate: example.com\n"
        )

        result = regenerated(
            files,
            on=on,
            rules=rule_set("9.9.10", b"# n\n"),
            certificate_sans={"example.com": ("other.example.org",)},
        )

        self.assertEqual(result["outcome"], "refused")
        self.assertIn("does not answer for", result["message"])

    def test_a_version_published_past_the_coverage_check_is_unchanged_not_refused(self) -> None:
        """26-11-01: `--allow-certificate-mismatch` published it; nothing would change now."""

        on = dataclasses.replace(cluster(), certificate_ids=("example.com",))
        base = {"managed/network.yaml": NETWORK}
        for number in range(2):
            base[f"managed/proxies/site{number:02d}.yaml"] = site(number, "")
        base["managed/proxies/site00.yaml"] = base["managed/proxies/site00.yaml"].replace(
            b"protocol: http\n", b"protocol: https\n  certificate: example.com\n"
        )
        rules = rule_set()
        generated = managed_files(
            base,
            network_document=NETWORK,
            cluster=on,
            rule_set=lambda: rules,
            country_reader=sweden("2026-10-01", "192.0.2.0/25"),
        )
        files = {
            **base,
            **generated,
            "core/haproxy.cfg": b"global\n",
            "manual/reservations.yaml": b"{}\n",
        }

        result = regenerated(
            files, on=on, rules=rules, certificate_sans={"example.com": ("other.example.org",)}
        )

        self.assertEqual((result["outcome"], result["message"]), ("unchanged", None))

    def test_a_newer_rule_set_does_change_it_and_says_which(self) -> None:
        files = published_tree()
        newer = rule_set("9.9.10", b"# rules, newer\n")

        result = regenerated(files, rules=newer)

        self.assertEqual(result["outcome"], "changed")
        self.assertEqual(
            result["causes"], [{"kind": "rule_set", "published": "9.9.9", "installed": "9.9.10"}]
        )
        paths = [change["path"] for change in result["diff"]["files"]]
        self.assertIn("waf/crs/VERSION", paths)
        self.assertIn("waf/crs/rules/REQUEST-901-INITIALIZATION.conf", paths)

    def test_a_generator_that_refuses_the_published_configuration_is_a_refusal(self) -> None:
        files = published_tree()

        result = regeneration.regenerate(
            files,
            cluster(),
            commit=COMMIT,
            version=3,
            key=KEY,
            addresses=(),
            installed_crs=None,
            rule_set=lambda: None,
        )

        self.assertEqual(result["outcome"], "refused")
        self.assertIn("haprion-crs", result["message"])
        self.assertIsNone(result["diff"])

    def test_addresses_that_are_needed_and_cannot_be_looked_up_stop_the_comparison(self) -> None:
        files = published_tree()
        files["managed/cluster.yaml"] = b"metrics: {port: 8405, sources: [192.0.2.0/24]}\n"

        with self.assertRaisesRegex(regeneration.RegenerationError, "lookup failed"):
            regenerated(files, addresses=ConfigError("lookup failed"))

    def test_a_cluster_written_by_hand_has_nothing_to_make_again(self) -> None:
        result = regenerated({"core/haproxy.cfg": b"global\n", "manual/reservations.yaml": b"{}\n"})

        self.assertEqual((result["outcome"], result["managed"]), ("unchanged", False))

    def test_the_diff_keeps_a_version_diff_s_bounds(self) -> None:
        published = {f"conf.d/{n:04d}.cfg": b"a\n" for n in range(MAX_FILES + 5)}
        candidate = {path: b"b\n" for path in published}

        diff = regeneration.artifact_diff(published, candidate, COMMIT)

        self.assertEqual(len(diff.files), MAX_FILES)
        self.assertTrue(diff.truncated)
        big = regeneration.artifact_diff({"x": b"a\n"}, {"x": b"b\n" * 200000}, COMMIT)
        self.assertEqual(
            (big.files[0].lines, big.files[0].added, big.truncated), ((), 200000, True)
        )
        self.assertEqual(
            regeneration.artifact_diff({"x": b"\0"}, {"x": b"\1"}, COMMIT).files[0].binary, True
        )


class AnUpdateIsRequiredOnlyWhenTheLevelSaysSo(unittest.TestCase):
    """B493: a difference asks for a deploy only when the generator level rose
    above the published version's, or the rule set is another."""

    def setUp(self) -> None:
        patch = core_is_current()
        patch.start()
        self.addCleanup(patch.stop)

    @staticmethod
    def another_generator() -> Any:
        original = generate._backend

        def backend(proxy: Any, *args: Any, **kwargs: Any) -> list[str]:
            return [*original(proxy, *args, **kwargs), "    # written another way"]

        return mock.patch.object(generate, "_backend", backend)

    def test_a_difference_at_the_same_level_is_not_required(self) -> None:
        files = published_tree()
        with self.another_generator():
            result = regenerated(files)

        self.assertEqual(
            (result["outcome"], result["required"], result["causes"]), ("changed", False, [])
        )

    def test_a_higher_level_is_required_and_says_so(self) -> None:
        files = published_tree()
        with self.another_generator(), mock.patch.object(regeneration, "GENERATOR_LEVEL", 2):
            result = regenerated(files)

        self.assertEqual((result["outcome"], result["required"]), ("changed", True))
        self.assertEqual(
            result["causes"], [{"kind": "generator", "published": "1", "installed": "2"}]
        )

    def test_a_higher_level_with_nothing_different_is_unchanged(self) -> None:
        files = published_tree()
        with mock.patch.object(regeneration, "GENERATOR_LEVEL", 2):
            result = regenerated(files)

        self.assertEqual((result["outcome"], result["required"]), ("unchanged", False))

    def test_a_version_published_before_the_level_was_recorded_is_at_the_baseline(self) -> None:
        files = published_tree()
        document = json.loads(files["managed/manifest.json"])
        self.assertEqual(document.pop("generator_level"), generate.GENERATOR_LEVEL)
        files["managed/manifest.json"] = json.dumps(document).encode()
        with self.another_generator():
            same = regenerated(files)
        with self.another_generator(), mock.patch.object(regeneration, "GENERATOR_LEVEL", 2):
            higher = regenerated(files)

        self.assertEqual((same["required"], higher["required"]), (False, True))
        self.assertEqual(higher["causes"][0]["published"], "1")

    def test_a_revised_rule_file_under_the_same_version_is_required(self) -> None:
        files = published_tree()

        result = regenerated(files, rules=rule_set(rules=b"# rules, revised\n"))

        self.assertEqual((result["outcome"], result["required"]), ("changed", True))
        self.assertEqual(
            result["causes"], [{"kind": "rule_set", "published": "9.9.9", "installed": "9.9.9"}]
        )

    def test_a_node_that_has_another_address_is_required(self) -> None:
        on = dataclasses.replace(cluster(), vrrp_router_id=51)
        published = (("node-a", "192.0.2.31"), ("node-b", "192.0.2.32"))
        files = published_tree(on=on, addresses=published)

        same = regenerated(files, on=on, addresses=published)
        moved = regenerated(
            files, on=on, addresses=(("node-a", "192.0.2.31"), ("node-b", "192.0.2.99"))
        )

        self.assertEqual((same["outcome"], same["required"]), ("unchanged", False))
        self.assertEqual((moved["outcome"], moved["required"]), ("changed", True))
        self.assertEqual(moved["causes"][0]["kind"], "addresses")
        self.assertEqual(
            moved["causes"][0]["files"],
            ["keepalived/node-node-a.conf", "keepalived/node-node-b.conf"],
        )

    def test_a_generator_difference_in_a_file_the_addresses_do_not_steer_is_not_an_address(
        self,
    ) -> None:
        on = dataclasses.replace(cluster(), vrrp_router_id=51)
        addresses = (("node-a", "192.0.2.31"), ("node-b", "192.0.2.32"))
        files = published_tree(on=on, addresses=addresses)
        with self.another_generator():
            result = regenerated(files, on=on, addresses=addresses)

        self.assertEqual(
            (result["outcome"], result["required"], result["causes"]), ("changed", False, [])
        )

    def test_a_placeholder_build_that_fails_counts_the_changed_files_as_address_steered(
        self,
    ) -> None:
        published = {"keepalived/node-a.conf": b"old\n", "core/a.cfg": b"same\n"}
        candidate = {"keepalived/node-a.conf": b"new\n", "core/a.cfg": b"same\n", "new.cfg": b"x\n"}

        for failure in (ConfigError("no"), LayoutError("no")):

            def failing(_commit: Any, _lookup: Any, failure: Exception = failure) -> Any:
                raise failure

            steered = regeneration._steered_by_addresses(
                failing, published, candidate, (("node-a", "192.0.2.31"),)
            )
            self.assertEqual(steered, ["keepalived/node-a.conf", "new.cfg"])

    def test_a_version_written_by_a_newer_generator_is_required_after_a_rollback(self) -> None:
        files = published_tree()
        document = json.loads(files["managed/manifest.json"])
        document["generator_level"] = generate.GENERATOR_LEVEL + 1
        files["managed/manifest.json"] = json.dumps(document).encode()
        with self.another_generator():
            result = regenerated(files)

        self.assertEqual((result["outcome"], result["required"]), ("changed", True))
        self.assertEqual(
            result["causes"],
            [
                {
                    "kind": "generator",
                    "published": str(generate.GENERATOR_LEVEL + 1),
                    "installed": str(generate.GENERATOR_LEVEL),
                }
            ],
        )

    def test_another_rule_set_is_required(self) -> None:
        result = regenerated(published_tree(), rules=rule_set("9.9.10", b"# rules, newer\n"))

        self.assertEqual((result["outcome"], result["required"]), ("changed", True))


class TheHelper(unittest.TestCase):
    def setUp(self) -> None:
        patch = core_is_current()
        patch.start()
        self.addCleanup(patch.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.policy = self.runtime()
        runtime = load_runtime_config(
            load_policy(self.policy, require_secure=False), require_secure=False
        )
        self.cluster = runtime.cluster("alpha")
        self.files = published_tree(on=self.cluster)
        self.reads: list[str] = []

    def runtime(self) -> Path:
        roots = {name: self.root / name for name in ("config", "published", "certs")}
        for directory in roots.values():
            directory.mkdir()
        (roots["certs"] / "validation.pem").write_text("dummy PEM\n", encoding="utf-8")
        clusters = yaml.safe_load((BASE / "examples/clusters.yaml").read_text())
        entry = clusters["clusters"]["alpha"]
        entry["config_path"] = str(roots["config"] / "alpha")
        entry["publish_path"] = str(roots["published"] / "alpha")
        entry["validation_certs"] = str(roots["certs"])
        (self.root / "clusters.yaml").write_text(yaml.safe_dump(clusters), encoding="utf-8")
        policy = {
            "schema_version": 1,
            "cluster_file": str(self.root / "clusters.yaml"),
            "config_root": str(roots["config"]),
            "publish_root": str(roots["published"]),
            "validation_certs_root": str(roots["certs"]),
        }
        path = self.root / "runtime-policy.yaml"
        path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        return path

    def ask(
        self,
        parameters: dict[str, object] | None = None,
        *,
        target: ReleaseTarget | None = PUBLISHED,
        rules: crs.RuleSet | None = None,
        crs_version: str = "9.9.9",
        addresses: regeneration.Lookup = lambda _cluster: (),
        installed: Callable[[], crs.RuleSet | None] | None = None,
    ) -> tuple[int, str, str]:
        request = {
            "schema_version": 1,
            "operation": "regeneration",
            "cluster": "alpha",
            "request_id": REQUEST_ID,
            "parameters": parameters or {},
        }
        out, err = io.StringIO(), io.StringIO()

        def tree(_repo: Path, commit: str, paths: Sequence[str] = ()) -> Mapping[str, bytes]:
            if paths:
                return {path: self.files[path] for path in paths if path in self.files}
            self.reads.append(commit)
            return self.files

        code = regeneration_helper.main(
            [],
            policy_path=self.policy,
            input_stream=io.BytesIO(json.dumps(request).encode()),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            tree_reader=tree,
            target_reader=lambda _publish, _node: target,
            addresses=addresses,
            rule_set=installed or (lambda: rules or rule_set(crs_version)),
        )
        return code, out.getvalue(), err.getvalue()

    def test_the_answer_is_the_frozen_contract(self) -> None:
        with mock.patch.object(
            geo, "location_database", lambda: sweden("2026-10-01", "192.0.2.0/25")
        ):
            code, out, _ = self.ask()

        self.assertEqual(code, 0)
        result = assert_contract("haprion-regeneration", out)["result"]
        self.assertEqual(result["outcome"], "unchanged")
        self.assertEqual(self.reads, [COMMIT])

    def test_a_changed_result_validates_with_its_diff(self) -> None:
        with mock.patch.object(
            geo, "location_database", lambda: sweden("2026-10-01", "192.0.2.0/25")
        ):
            code, out, _ = self.ask(rules=rule_set("9.9.10", b"# newer\n"), crs_version="9.9.10")

        self.assertEqual(code, 0)
        result = assert_contract("haprion-regeneration", out)["result"]
        self.assertEqual(result["outcome"], "changed")
        self.assertEqual(result["causes"][0]["installed"], "9.9.10")

    def test_a_matching_fingerprint_skips_the_regeneration(self) -> None:
        with mock.patch.object(
            geo, "location_database", lambda: sweden("2026-10-01", "192.0.2.0/25")
        ):
            _, first, _ = self.ask()
            known = json.loads(first)["result"]["fingerprint"]
            self.reads.clear()
            with mock.patch.object(regeneration, "regenerate") as regenerate:
                code, out, _ = self.ask({"unchanged_since": known})

        self.assertEqual(code, 0)
        result = assert_contract("haprion-regeneration", out)["result"]
        self.assertEqual(
            result, {"published_commit": COMMIT, "fingerprint": known, "unchanged": True}
        )
        self.assertEqual(self.reads, [])
        regenerate.assert_not_called()

    def test_each_input_of_the_result_is_part_of_the_fingerprint(self) -> None:
        def fingerprint(**changes: Any) -> str:
            found: dict[str, Any] = {
                "commit": COMMIT,
                "cluster": self.cluster,
                "addresses": (("node-a", "192.0.2.31"),),
                "crs_version": "9.9.9",
                "rules": regeneration.rules_digest(rule_set()),
                "certificates": "state",
            } | changes
            return regeneration.fingerprint(
                found["commit"],
                found["cluster"],
                found["addresses"],
                found["crs_version"],
                rules=found["rules"],
                certificates=found["certificates"],
            )

        base = fingerprint()
        self.assertEqual(base, fingerprint())
        for changes in (
            {"commit": "d" * 40},
            {"crs_version": "9.9.10"},
            #
            # A package revision that changes a rule file and keeps the version.
            #
            {"rules": regeneration.rules_digest(rule_set(rules=b"# revised\n"))},
            {"certificates": "other"},
            {"addresses": (("node-a", "192.0.2.32"),)},
            {"addresses": ConfigError("no")},
            {"cluster": cluster()},
        ):
            with self.subTest(changes=changes):
                self.assertNotEqual(base, fingerprint(**changes))
        with mock.patch.object(objects, "_engine_digest", return_value="other"):
            self.assertNotEqual(base, fingerprint())

    def test_a_rule_set_that_cannot_be_read_fails_only_where_the_objects_use_it(self) -> None:
        def unreadable() -> crs.RuleSet:
            raise crs.RuleSetError("rules/x.conf.dpkg-new is not a rule file")

        with mock.patch.object(
            geo, "location_database", lambda: sweden("2026-10-01", "192.0.2.0/25")
        ):
            code, out, _ = self.ask(installed=unreadable)
            self.files = {
                k: (
                    v.replace(b"waf: {mode: block}\n", b"")
                    if k.startswith("managed/proxies")
                    else v
                )
                for k, v in self.files.items()
            }
            without, _, _ = self.ask(installed=unreadable)

        self.assertEqual(code, exit_codes.UNAVAILABLE)
        self.assertEqual(
            assert_contract("haprion-regeneration", out)["error"]["code"],
            "regeneration_unavailable",
        )
        self.assertEqual(without, 0)

    def test_the_nodes_are_looked_up_only_where_the_generated_layer_asks_for_them(self) -> None:
        asked: list[str] = []

        def lookup(_cluster: Cluster) -> tuple[tuple[str, str], ...]:
            asked.append("asked")
            raise ConfigError("resolver is slow")

        with mock.patch.object(
            geo, "location_database", lambda: sweden("2026-10-01", "192.0.2.0/25")
        ):
            _, plain, _ = self.ask(addresses=lookup)
            self.files["managed/cluster.yaml"] = b"metrics: {port: 8405, sources: [192.0.2.0/24]}\n"
            code, _, _ = self.ask(addresses=lookup)

        self.assertEqual(json.loads(plain)["result"]["outcome"], "unchanged")
        self.assertEqual(asked, ["asked"])
        self.assertEqual(code, exit_codes.UNAVAILABLE)

    def test_nothing_published_is_an_answer_and_reads_nothing(self) -> None:
        code, out, _ = self.ask(target=None)

        self.assertEqual(code, 0)
        result = assert_contract("haprion-regeneration", out)["result"]
        self.assertEqual((result["outcome"], result["published_commit"]), ("unpublished", None))
        self.assertEqual(self.reads, [])

    def test_a_published_version_that_is_not_a_release_is_a_failed_reading(self) -> None:
        self.files = {k: v for k, v in self.files.items() if k != "core/haproxy.cfg"}

        code, out, _ = self.ask()

        self.assertEqual(code, exit_codes.UNAVAILABLE)
        self.assertEqual(
            assert_contract("haprion-regeneration", out)["error"]["code"],
            "regeneration_unavailable",
        )

    def test_a_fingerprint_that_is_not_one_is_refused(self) -> None:
        code, out, err = self.ask({"unchanged_since": "../../etc"})

        self.assertEqual(code, 64)
        self.assertEqual(assert_contract("haprion-regeneration", out)["error"]["code"], "bad_input")
        self.assertIn("unchanged_since", err)

    def test_the_poller_can_ask_for_it_among_the_readings(self) -> None:
        self.assertIs(readings_helper.READINGS["regeneration"], regeneration_helper.main)


if __name__ == "__main__":
    unittest.main()
