"""Every node's fetch keys bound to its own cluster and its own address (B358)."""

from __future__ import annotations

import copy
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import yaml

from haprion import pull_keys
from haprion.cli import node as node_command
from haprion.config import load_policy, load_runtime_config
from haprion.node_enrollment import Locations
from tests.test_node_enrollment import key, resolving

BASE = Path(__file__).resolve().parents[1]
RRSYNC = "/usr/bin/rrsync"
NODES = {
    "alpha": ("node-a", "node-b"),
    "beta": ("node-c", "unresolved"),
}


def no_owner(_path: Path, _uid: int, _gid: int) -> None:
    """Ownership is root's to give; the run is about which paths and lines."""


class Site:
    """A manager in a directory: two clusters, a registry, both pull accounts as they were."""

    def __init__(self, root: Path, *, registry: bool = True) -> None:
        self.root = root
        self.publish_root = root / "published"
        self.certificates = root / "certdist"
        config_root = root / "config"
        validation = root / "validation"
        for directory in (validation, self.certificates / "ca"):
            directory.mkdir(parents=True)
        (validation / "validation.pem").write_text("dummy PEM\n", encoding="utf-8")

        raw = yaml.safe_load((BASE / "examples" / "clusters.yaml").read_text())
        template = raw["clusters"]["alpha"]
        raw["clusters"] = {}
        for index, (cluster_id, names) in enumerate(NODES.items()):
            entry = copy.deepcopy(template)
            entry["config_path"] = str(config_root / cluster_id)
            entry["publish_path"] = str(self.publish_root / cluster_id)
            entry["validation_certs"] = str(validation)
            entry["node_path"] = cluster_id
            entry["vrrp_router_id"] = index + 1
            entry["nodes"] = [{"name": name, "mgmt_host": f"{name}.example.com"} for name in names]
            (config_root / cluster_id).mkdir(parents=True)
            (self.publish_root / cluster_id / "current").mkdir(parents=True)
            raw["clusters"][cluster_id] = entry
        policy: dict[str, object] = {
            "schema_version": 1,
            "cluster_file": str(root / "clusters.yaml"),
            "config_root": str(config_root),
            "publish_root": str(self.publish_root),
            "validation_certs_root": str(validation),
            "certificate_root": str(self.certificates),
        }
        if registry:
            for entry in raw["clusters"].values():
                entry.pop("certificate_ids")
                entry["default_certificate"] = "example.com"
            certificates = {
                "example.com": {"source": {"kind": "acme"}, "clusters": ["alpha", "beta"]},
                "example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
                "corp-root": {"source": {"kind": "authority"}, "clusters": ["beta"]},
            }
            (root / "certificates.yaml").write_text(
                yaml.safe_dump({"schema_version": 1, "certificates": certificates})
            )
            policy["certificate_registry"] = str(root / "certificates.yaml")
        (root / "clusters.yaml").write_text(yaml.safe_dump(raw, sort_keys=False))
        self.policy_file = root / "runtime-policy.yaml"
        self.policy_file.write_text(yaml.safe_dump(policy))

        #
        # The shared copies every cluster read before (B358), and the lines
        # every node had: the whole of both roots, from anywhere.
        #
        for name in ("example.com", "example.net", "stray.example"):
            (self.certificates / f"{name}.pem").write_text(f"{name}\n", encoding="ascii")
        (self.certificates / "ca" / "corp-root.pem").write_text("corp-root\n", encoding="ascii")
        self.keys = {
            name: (key(10 + index), key(20 + index))
            for index, name in enumerate(["node-a", "node-b", "node-c", "unresolved", "gone"])
        }
        for account, root_path, purpose, which in (
            ("_haprion-pull", self.publish_root, "config pull", 0),
            ("_haprion-cert-pull", self.certificates, "certificate pull", 1),
        ):
            (root / account / ".ssh").mkdir(parents=True)
            self.authorized_keys(account).write_text(
                "# kept as written\n"
                + "".join(
                    f'restrict,command="{RRSYNC} -ro {root_path}" {pair[which]} {name} {purpose}\n'
                    for name, pair in self.keys.items()
                )
                + f"{key(99)} admin@laptop\n"
            )
        (root / ".journal").mkdir()
        self.locations = Locations(
            journal=root / ".journal" / "change-journal.json",
            home=lambda account: root / account,
            forward=resolving_but("unresolved.example.com"),
        )

    def authorized_keys(self, account: str) -> Path:
        return self.root / account / ".ssh" / "authorized_keys"

    def line(self, account: str, name: str) -> str:
        return next(
            line
            for line in self.authorized_keys(account).read_text().splitlines()
            if f" {name} " in line
        )

    def run(self) -> pull_keys.Report:
        policy = load_policy(self.policy_file, require_secure=False)
        return pull_keys.run(
            policy,
            load_runtime_config(policy, require_secure=False),
            locations=self.locations,
            lock_root=self.root / "locks",
            certificate_lock=self.root / "cert.lock",
            change_owner=no_owner,
        )

    def snapshot(self) -> dict[str, bytes | str]:
        return {
            str(path.relative_to(self.root)): (
                f"-> {os.readlink(path)}" if path.is_symlink() else path.read_bytes()
            )
            for path in sorted(self.root.rglob("*"))
            if (path.is_file() or path.is_symlink())
            and "locks" not in path.parts
            and path.name != "cert.lock"
        }


def resolving_but(unresolved: str) -> Callable[[str], tuple[str, ...]]:
    def forward(name: str) -> tuple[str, ...]:
        return () if name == unresolved else resolving(name)

    return forward


class Fixture(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        patcher = mock.patch.object(pull_keys, "ROOT_UID", os.getuid())
        patcher.start()
        self.addCleanup(patcher.stop)


class TheLines(Fixture):
    def test_each_node_reads_its_own_cluster_from_its_own_address(self) -> None:
        site = Site(self.root)

        site.run()

        for name, cluster in (("node-a", "alpha"), ("node-b", "alpha"), ("node-c", "beta")):
            source = f'from="{name}.example.com,{resolving(f"{name}.example.com")[0]}",restrict,'
            config, certificate = site.keys[name]
            self.assertEqual(
                site.line("_haprion-pull", name),
                f'{source}command="{RRSYNC} -ro {site.publish_root / cluster}" '
                f"{config} {name} config pull",
            )
            self.assertEqual(
                site.line("_haprion-cert-pull", name),
                f'{source}command="{RRSYNC} -ro {site.certificates / cluster}" '
                f"{certificate} {name} certificate pull",
            )

    def test_a_node_whose_host_does_not_resolve_is_narrowed_without_from_and_said(self) -> None:
        site = Site(self.root)

        report = site.run()

        self.assertEqual(
            site.line("_haprion-cert-pull", "unresolved"),
            f'restrict,command="{RRSYNC} -ro {site.certificates / "beta"}" '
            f"{site.keys['unresolved'][1]} unresolved certificate pull",
        )
        self.assertTrue(
            any("unresolved.example.com does not resolve" in line for line in report.left)
        )

    def test_a_line_for_a_node_no_cluster_has_is_removed_and_said(self) -> None:
        site = Site(self.root)

        report = site.run()

        for account in ("_haprion-pull", "_haprion-cert-pull"):
            self.assertNotIn(" gone ", site.authorized_keys(account).read_text())
        self.assertIn("removed gone's config pull key: gone is not a node", report.done)
        self.assertIn("removed gone's certificate pull key: gone is not a node", report.done)

    def test_a_line_of_another_shape_and_a_comment_stay_as_written(self) -> None:
        site = Site(self.root)

        report = site.run()

        for account in ("_haprion-pull", "_haprion-cert-pull"):
            text = site.authorized_keys(account).read_text()
            self.assertTrue(text.startswith("# kept as written\n"))
            self.assertIn(f"{key(99)} admin@laptop\n", text)
        self.assertEqual(
            sum("a line that names no node" in line for line in report.left), 2, report.left
        )

    def test_a_node_name_in_two_clusters_is_left_as_written(self) -> None:
        site = Site(self.root)
        clusters = yaml.safe_load((self.root / "clusters.yaml").read_text())
        clusters["clusters"]["beta"]["nodes"][0] = {
            "name": "node-a",
            "mgmt_host": "node-a2.example.com",
        }
        (self.root / "clusters.yaml").write_text(yaml.safe_dump(clusters, sort_keys=False))
        before = site.line("_haprion-pull", "node-a")

        report = site.run()

        self.assertEqual(site.line("_haprion-pull", "node-a"), before)
        self.assertIn(
            "node-a's config pull key is left as written: node-a is a node of alpha and beta",
            report.left,
        )

    def test_a_second_run_changes_nothing(self) -> None:
        site = Site(self.root)
        site.run()
        before = site.snapshot()

        report = site.run()

        self.assertEqual(site.snapshot(), before)
        self.assertEqual(report.done, [])

    def test_the_change_is_recorded_and_finished(self) -> None:
        site = Site(self.root)

        site.run()

        self.assertFalse(site.locations.journal.exists())


class TheCertificates(Fixture):
    def test_each_cluster_gets_its_own_copies_and_the_shared_ones_go(self) -> None:
        site = Site(self.root)

        report = site.run()

        held = {
            str(path.relative_to(site.certificates)): path.read_text()
            for path in sorted(site.certificates.rglob("*.pem"))
        }
        self.assertEqual(
            held,
            {
                "alpha/example.com.pem": "example.com\n",
                "alpha/example.net.pem": "example.net\n",
                "beta/ca/corp-root.pem": "corp-root\n",
                "beta/example.com.pem": "example.com\n",
            },
        )
        self.assertFalse((site.certificates / "ca").exists())
        self.assertFalse((site.certificates / "alpha" / "ca").exists())
        self.assertIn(
            f"removed the 4 shared certificate files from {site.certificates}", report.done
        )
        for path in site.certificates.rglob("*.pem"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o640, path)

    def test_a_cluster_s_own_copy_is_not_overwritten_by_the_shared_one(self) -> None:
        """A publish after the layout moved is newer than the root's copy."""

        site = Site(self.root)
        (site.certificates / "alpha").mkdir()
        (site.certificates / "alpha" / "example.com.pem").write_text("renewed\n")

        site.run()

        self.assertEqual((site.certificates / "alpha" / "example.com.pem").read_text(), "renewed\n")
        self.assertEqual(
            (site.certificates / "beta" / "example.com.pem").read_text(), "example.com\n"
        )

    def test_the_shared_copies_stay_while_a_line_still_reads_the_whole_root(self) -> None:
        site = Site(self.root)
        clusters = yaml.safe_load((self.root / "clusters.yaml").read_text())
        clusters["clusters"]["beta"]["nodes"][0] = {
            "name": "node-a",
            "mgmt_host": "node-a2.example.com",
        }
        (self.root / "clusters.yaml").write_text(yaml.safe_dump(clusters, sort_keys=False))

        report = site.run()

        self.assertTrue((site.certificates / "example.com.pem").exists())
        self.assertTrue((site.certificates / "ca" / "corp-root.pem").exists())
        self.assertIn(
            f"the shared copies in {site.certificates} stay: a line still reads all of it",
            report.left,
        )
        #
        # Put right, the next run finishes it.
        #
        clusters["clusters"]["beta"]["nodes"][0] = {
            "name": "node-c",
            "mgmt_host": "node-c.example.com",
        }
        (self.root / "clusters.yaml").write_text(yaml.safe_dump(clusters, sort_keys=False))
        site.run()
        self.assertEqual(sorted(site.certificates.glob("*.pem")), [])

    def test_a_cluster_named_like_the_shared_authorities_is_refused_before_anything(self) -> None:
        site = Site(self.root)
        text = (self.root / "clusters.yaml").read_text()
        text = text.replace("beta", "ca")
        (self.root / "clusters.yaml").write_text(text)
        (self.root / "published" / "beta").rename(self.root / "published" / "ca")
        (self.root / "config" / "beta").rename(self.root / "config" / "ca")
        registry = (self.root / "certificates.yaml").read_text().replace("beta", "ca")
        (self.root / "certificates.yaml").write_text(registry)
        before = site.snapshot()

        with self.assertRaisesRegex(pull_keys.PullKeysError, "rename the cluster"):
            site.run()

        self.assertEqual(site.snapshot(), before)

    def test_without_a_registry_the_one_shared_root_stays(self) -> None:
        site = Site(self.root, registry=False)

        site.run()

        self.assertIn(
            f'command="{RRSYNC} -ro {site.certificates}" ',
            site.line("_haprion-cert-pull", "node-a"),
        )
        self.assertTrue((site.certificates / "example.com.pem").exists())
        self.assertFalse((site.certificates / "alpha").exists())


class ThePublishedTrees(Fixture):
    def test_each_tree_links_to_itself_so_a_node_s_path_holds(self) -> None:
        site = Site(self.root)

        report = site.run()

        for cluster in NODES:
            link = site.publish_root / cluster / cluster
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.readlink(link), ".")
            self.assertEqual(
                (link / "current").resolve(), (site.publish_root / cluster / "current").resolve()
            )
            self.assertIn(f"{cluster}: {link} -> .", report.done)

    def test_something_else_where_the_link_goes_is_refused(self) -> None:
        site = Site(self.root)
        (site.publish_root / "alpha" / "alpha").mkdir()

        out, err = io.StringIO(), io.StringIO()
        code = node_command.pull_keys_main(
            out,
            err,
            policy_path=site.policy_file,
            require_root=False,
            require_secure=False,
            locations=site.locations,
            lock_root=self.root / "locks",
            certificate_lock=self.root / "cert.lock",
            change_owner=no_owner,
        )

        self.assertNotEqual(code, 0)
        self.assertIn("is not the cluster's link to itself", err.getvalue())


@unittest.skipUnless(
    shutil.which("rsync") and Path(RRSYNC).exists(), "rsync and rrsync are not installed here"
)
class WhatANarrowRootServes(Fixture):
    """The forced command as a node meets it: rsync over a pretend ssh into rrsync."""

    def fetch(self, root: Path, path: str) -> tuple[int, list[str]]:
        ssh = self.root / "ssh"
        ssh.write_text(
            '#!/bin/sh\nshift\nSSH_ORIGINAL_COMMAND="$*" exec ' + RRSYNC + ' -ro "$PULL_ROOT"\n'
        )
        ssh.chmod(0o700)
        out = self.root / "out"
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir()
        completed = subprocess.run(  # fixed programs, paths of the test's own
            [shutil.which("rsync") or "rsync", "-r", "-e", str(ssh), f"node:{path}", f"{out}/"],
            env={**os.environ, "PULL_ROOT": str(root)},
            capture_output=True,
            check=False,
        )
        return completed.returncode, sorted(
            str(found.relative_to(out)) for found in out.rglob("*") if found.is_file()
        )

    def test_a_node_s_path_reads_its_own_cluster_and_nothing_else(self) -> None:
        site = Site(self.root)
        for cluster in NODES:
            (site.publish_root / cluster / "current" / cluster).mkdir()
            (site.publish_root / cluster / "current" / cluster / "haproxy.cfg").write_text(cluster)
        site.run()
        alpha = site.publish_root / "alpha"

        for path, files in (
            ("alpha/current/alpha/", ["haproxy.cfg"]),  # what the nodes ask for
            ("current/alpha/", ["haproxy.cfg"]),
        ):
            with self.subTest(path):
                code, fetched = self.fetch(alpha, path)
                self.assertEqual((code, fetched), (0, files))
        for path in ("beta/current/beta/", "../beta/current/beta/", "alpha/../beta/", "/etc/"):
            with self.subTest(path):
                code, fetched = self.fetch(alpha, path)
                self.assertNotEqual(code, 0)
                self.assertEqual(fetched, [])

    def test_a_node_s_certificate_paths_read_its_own_cluster_s_copies(self) -> None:
        site = Site(self.root)
        site.run()
        beta = site.certificates / "beta"

        self.assertEqual(self.fetch(beta, "example.com.pem"), (0, ["example.com.pem"]))
        self.assertEqual(self.fetch(beta, "ca/corp-root.pem"), (0, ["corp-root.pem"]))
        for path in ("example.net.pem", "../alpha/example.net.pem", "alpha/example.net.pem"):
            with self.subTest(path):
                self.assertEqual(self.fetch(beta, path)[1], [])


class TheCommand(Fixture):
    def run_command(self, site: Site, *, require_root: bool = False) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = node_command.pull_keys_main(
            out,
            err,
            policy_path=site.policy_file,
            require_root=require_root,
            require_secure=False,
            locations=site.locations,
            lock_root=self.root / "locks",
            certificate_lock=self.root / "cert.lock",
            change_owner=no_owner,
        )
        return code, out.getvalue(), err.getvalue()

    def test_it_says_each_step_then_nothing_to_do(self) -> None:
        site = Site(self.root)

        code, out, _ = self.run_command(site)

        self.assertEqual(code, 0)
        self.assertIn("node-a's config pull key reads", out)
        self.assertIn("WARNING: unresolved's", out)
        code, out, _ = self.run_command(site)
        self.assertEqual(code, 0)
        self.assertNotIn("reads", out)

    def test_it_runs_as_root_only(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("runs as root")
        site = Site(self.root)
        before = site.snapshot()

        code, _, err = self.run_command(site, require_root=True)

        self.assertNotEqual(code, 0)
        self.assertIn("sudo haprion-node pull-keys", err)
        self.assertEqual(site.snapshot(), before)

    def test_the_argument_reaches_it(self) -> None:
        with mock.patch.object(node_command, "pull_keys_main", return_value=0) as called:
            self.assertEqual(node_command.main(["pull-keys"]), 0)
        called.assert_called_once()


if __name__ == "__main__":
    unittest.main()
