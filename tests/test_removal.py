"""The removal commands (B372): what they find, what they take, and what they leave.

`haprion-setup --remove` and `haprion-node-prepare --remove` run on a machine of
the test's own here - files under a temporary root, accounts and commands
answered by the test - and the installation test runs them for real after an
installation. The static half holds them to the steps: a path a step writes
that the removal neither takes nor accounts for is a test that fails, not a
file left on somebody's machine.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import pwd
import re
import subprocess
import tempfile
import unittest
from pathlib import Path, PurePath
from types import ModuleType
from typing import Any

from haprion import accounts, node_package

BASE = Path(__file__).resolve().parents[1]
INSTALL = BASE / "install"


def load(name: str) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(name.replace("-", "_"), str(INSTALL / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


MANAGER = load("remove-manager")
NODE = load("node-remove")


class Machine(MANAGER.Host):  # type: ignore[misc, name-defined]
    """Files under a temporary root; accounts and commands as the test says."""

    def __init__(self, root: str) -> None:
        super().__init__(root)
        self.ran: list[list[str]] = []
        self.accounts: list[pwd.struct_passwd] = []
        self.groups: set[str] = set()
        self.mounts: set[Path] = set()
        self.answers: dict[str, str] = {}

    def run(self, argv: list[str], *, input_text: str | None = None) -> Any:
        self.ran.append(argv)
        joined = " ".join(argv)
        for asked, answer in self.answers.items():
            if asked in joined:
                return subprocess.CompletedProcess(argv, 0, answer, "")
        #
        # A question nobody answered is a no; anything else the machine did.
        #
        questions = ("is-active", "is-enabled", "dpkg-query", "psql", "git config", "sshd -t")
        return subprocess.CompletedProcess(argv, int(any(q in joined for q in questions)), "", "")

    def users(self) -> list[pwd.struct_passwd]:
        return list(self.accounts)

    def group_exists(self, name: str) -> bool:
        return name in self.groups

    def is_mount(self, path: Path) -> bool:
        return path in self.mounts

    def account(self, name: str, home: str) -> None:
        self.accounts.append(pwd.struct_passwd((name, "x", 990, 990, "", home, "/bin/sh")))
        self.groups.add(name)

    def write(self, name: str, text: str = "x\n") -> Path:
        path: Path = self.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path


#
# What 02-platform-database adds to PostgreSQL's two files, as it adds it.
#
IDENT = "# MAPNAME SYSTEM-USERNAME PG-USERNAME\nmine   someone   somebody\n"
HBA = "local   all   postgres   peer\nlocal   all   all   peer\n"


RULES: dict[str, str] = MANAGER.PG_RULES


def patched_ident(text: str) -> str:
    return text + "\n# haprion platform\n" + RULES["ident_file"] + "\n"


def patched_hba(text: str) -> str:
    return "# haprion platform\n" + RULES["hba_file"] + "\n\n" + text


class AManager(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        machine = Machine(self.directory.name)
        self.machine = machine
        machine.write(
            "/etc/haprion/runtime-policy.yaml",
            "schema_version: 1\n"
            "cluster_file: /etc/haprion/registry/clusters.yaml\n"
            "config_root: /configs/haproxy\n"
            "publish_root: /configs/haproxy-published\n"
            "backup_root: /haproxy-backups\n"
            "certificate_root: /srv/certdist/haproxy\n"
            "receiver_root: /srv/certdist/receivers\n"
            "certificate_registry: /etc/haprion/registry/certificates.yaml\n"
            'deploy_identity:\n  key: "/root/.ssh/id_ed25519_deploy"\n'
            'status_identity:\n  key: "/root/.ssh/id_ed25519_status"\n'
            "acme:\n  certbot: /opt/haprion-certbot/current/venv/bin/certbot\n"
            "  dns_cloudflare_credentials: /etc/letsencrypt/cloudflare/example.ini\n",
        )
        machine.write(
            "/etc/haprion/registry/clusters.yaml",
            "schema_version: 1\nclusters:\n  alpha:\n    config_path: /configs/haproxy/alpha\n    nodes:\n"
            "    - name: node-a\n      mgmt_host: node-a.example.com\n",
        )
        machine.write(
            "/etc/haprion/registry/certificates.yaml",
            "schema_version: 1\nreceivers:\n  lb-01.example.com:\n"
            "    owner: crx-lb-01-example-com\n    transport: rsync\n"
            "certificates:\n  shop.example.com:\n    source:\n      kind: acme\n"
            "  imported.example.com:\n    source:\n      kind: import\n",
        )
        for name in (
            "/configs/haproxy/alpha/objects/shop.yaml",
            "/configs/haproxy-published/alpha/releases/x",
            "/haproxy-backups/alpha/node-a/1.tar",
            "/srv/certdist/haproxy/alpha/shop.pem",
            "/srv/certdist/manager-ui.pem",
            "/root/.ssh/id_ed25519_deploy",
            "/root/.ssh/id_ed25519_deploy.pub",
            "/root/.ssh/id_ed25519_status",
            "/root/.ssh/known_hosts",
            "/etc/systemd/system/haprion-web.service",
            "/etc/systemd/system/haprion-web.service.replaced-20261001-101010",
            "/etc/systemd/system/sockets.target.wants/haprion-web.socket",
            "/etc/sudoers.d/haprion-worker",
            "/etc/nginx/sites-available/haprion",
            "/etc/nginx/sites-available/default",
            "/etc/tmpfiles.d/haprion.conf",
            "/var/lib/haprion-ui/dumps/haprion-20261026.dump",
            "/etc/letsencrypt/renewal/shop.example.com.conf",
            "/opt/haprion-certbot/current/venv/bin/certbot",
            # The operator's own, beside Haprion's.
            "/configs/haproxy-apt/notes.txt",
            "/srv/certdist/own.pem",
            "/etc/sudoers.d/svc-other",
            "/root/.ssh/id_ed25519",
            "/etc/letsencrypt/cloudflare/example.ini",
        ):
            machine.write(name)
        machine.path("/etc/nginx/sites-enabled").mkdir(parents=True)
        machine.path("/etc/nginx/sites-enabled/haprion").symlink_to(
            "/etc/nginx/sites-available/haprion"
        )
        machine.write(
            "/etc/sysusers.d/haprion.conf",
            "g haprion -\nu _haprion-pull - - /home/_haprion-pull /bin/bash\n"
            "u _haprion-web - - - /usr/sbin/nologin\nm _haprion-web haprion\n",
        )
        machine.account("_haprion-pull", "/home/_haprion-pull")
        machine.account("_haprion-web", "/")
        machine.account("crx-lb-01-example-com", "/srv/certdist/receivers/lb-01.example.com")
        machine.accounts.append(
            pwd.struct_passwd(("operator", "x", 1000, 1000, "", "/home/operator", "/bin/bash"))
        )
        machine.groups |= {"haprion"}
        machine.write("/home/_haprion-pull/.ssh/authorized_keys", "")
        machine.write(
            "/srv/certdist/receivers/lb-01.example.com/.ssh/authorized_keys",
            'restrict,command="rrsync -ro /x" ssh-ed25519 AAAAkey receiver@lb-01\n',
        )
        machine.mounts.add(machine.path("/var/lib/haprion-ui"))
        ident = machine.write("/etc/postgresql/18/main/pg_ident.conf", patched_ident(IDENT))
        hba = machine.write("/etc/postgresql/18/main/pg_hba.conf", patched_hba(HBA))
        machine.write("/etc/postgresql/18/main/pg_hba.conf.pre-haprion-20261010", HBA)
        machine.answers = {
            "select datname from pg_database": "postgres\nhaprion\ntemplate1\n",
            "select rolname from pg_roles": "postgres\n_haprion-migrate\napp_web\nsomeone\n",
            "show ident_file": str(ident.relative_to(machine.root)).join(["/", ""]),
            "show hba_file": str(hba.relative_to(machine.root)).join(["/", ""]),
            "list-units": "haprion-web.socket loaded active listening x\n"
            "haprion-web.service loaded active running x\n",
            "dpkg-query -W": "install ok installed",
            "drop database": "",
            "drop role": "",
        }

    def main(self, *argv: str) -> tuple[int, str]:
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = MANAGER.main(list(argv), host=self.machine)
        return code, out.getvalue()

    def test_without_yes_it_lists_and_changes_nothing(self) -> None:
        before = sorted(str(p) for p in self.machine.root.rglob("*"))

        code, said = self.main()

        self.assertEqual(code, 0)
        self.assertEqual(sorted(str(p) for p in self.machine.root.rglob("*")), before)
        for named in (
            "/configs/haproxy",
            "/haproxy-backups",
            "id_ed25519_deploy",
            "haprion-web.service",
            "database haprion",
            "role _haprion-migrate",
            "user crx-lb-01-example-com",
            "lb-01.example.com: the public key",
            "shop.example.com",
            "Nothing was changed",
            "kept: named by the runtime policy",
            "/etc/letsencrypt/cloudflare/example.ini",
            "sudo apt purge haprion-ui",
        ):
            with self.subTest(named=named):
                self.assertIn(named, said)
        self.assertNotIn("imported.example.com", said)
        # A cluster's directory goes with its root, and is said once.
        self.assertNotIn("/configs/haproxy/alpha", said)
        # Kept is only what stays: not a key the removal takes, nor a package's tree.
        kept = said.split("== kept: named by the runtime policy", 1)[1].split("\n\n", 1)[0]
        self.assertIn("/etc/letsencrypt/cloudflare/example.ini", kept)
        self.assertNotIn("id_ed25519_deploy", kept)
        self.assertNotIn("/opt/haprion-certbot", kept)
        self.assertNotIn("role someone", said)
        changing = [argv for argv in self.machine.ran if argv[1:2] in (["stop"], ["disable"])]
        self.assertEqual(changing, [])

    def test_with_yes_haprion_s_parts_go_and_the_operator_s_stay(self) -> None:
        code, said = self.main("--yes")

        self.assertEqual(code, 0, said)
        for gone in (
            "/configs/haproxy",
            "/configs/haproxy-published",
            "/haproxy-backups",
            "/srv/certdist/haproxy",
            "/srv/certdist/receivers",
            "/srv/certdist/manager-ui.pem",
            "/etc/haprion",
            "/etc/systemd/system/haprion-web.service",
            "/etc/systemd/system/haprion-web.service.replaced-20261001-101010",
            "/etc/systemd/system/sockets.target.wants/haprion-web.socket",
            "/etc/sudoers.d/haprion-worker",
            "/etc/nginx/sites-available/haprion",
            "/etc/nginx/sites-enabled/haprion",
            "/etc/tmpfiles.d/haprion.conf",
            "/etc/sysusers.d/haprion.conf",
            "/root/.ssh/id_ed25519_deploy",
            "/root/.ssh/id_ed25519_deploy.pub",
            "/root/.ssh/id_ed25519_status",
            "/home/_haprion-pull",
            "/var/lib/haprion-ui/dumps",
            "/etc/postgresql/18/main/pg_hba.conf.pre-haprion-20261010",
        ):
            with self.subTest(gone=gone):
                path = self.machine.path(gone)
                self.assertFalse(path.exists() or path.is_symlink())
        for kept in (
            "/configs/haproxy-apt/notes.txt",
            "/srv/certdist/own.pem",
            "/etc/sudoers.d/svc-other",
            "/root/.ssh/id_ed25519",
            "/etc/nginx/sites-available/default",
        ):
            with self.subTest(kept=kept):
                self.assertTrue(self.machine.path(kept).exists())
        # A mount point is the machine's: emptied, kept.
        self.assertTrue(self.machine.path("/var/lib/haprion-ui").is_dir())
        # The site the steps took away is back.
        default = self.machine.path("/etc/nginx/sites-enabled/default")
        self.assertEqual(os.readlink(default), "/etc/nginx/sites-available/default")
        # PostgreSQL's two files are as they were before step 2.
        self.assertEqual(
            self.machine.path("/etc/postgresql/18/main/pg_ident.conf").read_text(), IDENT
        )
        self.assertEqual(self.machine.path("/etc/postgresql/18/main/pg_hba.conf").read_text(), HBA)
        ran = [" ".join(argv) for argv in self.machine.ran]
        for command in (
            "systemctl stop haprion-web.socket",
            "systemctl stop haprion-web.service",
            'drop database if exists "haprion" with (force)',
            'drop role if exists "_haprion-migrate"',
            'drop role if exists "app_web"',
            "userdel crx-lb-01-example-com",
            "userdel _haprion-pull",
            "userdel _haprion-web",
            "groupdel haprion",
            "delete --non-interactive --cert-name shop.example.com",
            "ssh-keygen -R node-a.example.com",
        ):
            with self.subTest(command=command):
                self.assertTrue(any(command in line for line in ran), ran)
        self.assertFalse(any("someone" in line for line in ran))
        self.assertNotIn("imported.example.com", [word for line in ran for word in line.split()])
        self.assertFalse(any("userdel operator" in line for line in ran))
        # Timers and sockets stop before the services they start.
        stops = [line for line in ran if " stop " in line]
        self.assertLess(
            stops.index(next(s for s in stops if "socket" in s)),
            stops.index(next(s for s in stops if "service" in s)),
        )

    def test_the_default_site_comes_back_whatever_the_link_points_at(self) -> None:
        # A link is asked about itself: its target is on the machine, not under this root.
        enabled = self.machine.path("/etc/nginx/sites-enabled/haprion")
        enabled.unlink()
        enabled.symlink_to("/nonexistent/sites-available/haprion")
        code, said = self.main("--yes")

        self.assertEqual(code, 0, said)
        default = self.machine.path("/etc/nginx/sites-enabled/default")
        self.assertEqual(os.readlink(default), "/etc/nginx/sites-available/default")

    def test_a_receiver_s_key_and_the_registry_are_kept_for_registering_it_again(self) -> None:
        self.main("--yes")

        saved = next(self.machine.path("/root").glob("haprion-removed-*"))
        self.assertEqual(
            (saved / "receivers" / "lb-01.example.com.pub").read_text(), "ssh-ed25519 AAAAkey\n"
        )
        self.assertTrue((saved / "registry" / "certificates.yaml").is_file())

    def test_an_empty_parent_goes_and_one_with_the_operator_s_files_stays(self) -> None:
        self.machine.path("/srv/certdist/own.pem").unlink()
        self.main("--yes")
        self.assertFalse(self.machine.path("/srv/certdist").exists())

    def test_a_second_run_finds_nothing_to_do(self) -> None:
        self.main("--yes")
        self.machine.accounts = [a for a in self.machine.accounts if a.pw_name == "operator"]
        self.machine.groups.clear()
        self.machine.answers.pop("select datname from pg_database")
        self.machine.answers.pop("select rolname from pg_roles")
        self.machine.answers.pop("list-units")

        steps = MANAGER.plan(self.machine, "later")

        self.assertEqual([(s.title, s.found) for s in steps if s.found], [])

    def test_only_with_yes_or_nothing(self) -> None:
        self.assertEqual(self.main("--force")[0], 64)

    def test_without_the_engine_it_reads_nothing_and_removes_nothing(self) -> None:
        """The policy names the roots; a guess at them could miss one or take another."""

        from unittest import mock

        before = sorted(str(p) for p in self.machine.root.rglob("*"))
        with mock.patch.dict("sys.modules", {"haprion.safe_yaml": None}):
            code, said = self.main("--yes")
        self.assertEqual(code, 1)
        self.assertIn("install haprion-cli again", said)
        self.assertEqual(sorted(str(p) for p in self.machine.root.rglob("*")), before)

    def test_a_policy_with_a_key_given_twice_is_refused(self) -> None:
        policy = self.machine.path("/etc/haprion/runtime-policy.yaml")
        policy.write_text(policy.read_text() + "config_root: /elsewhere\n")
        code, said = self.main()
        self.assertEqual(code, 1)
        self.assertIn("cannot be read", said)


class PostgresqlFilesAsTheyWere(unittest.TestCase):
    def test_both_rules_come_out_exactly(self) -> None:
        for rule, patch, text in (
            (MANAGER.PG_RULES["ident_file"], patched_ident, IDENT),
            (MANAGER.PG_RULES["hba_file"], patched_hba, HBA),
        ):
            with self.subTest(rule=rule[:8], text=text[:8]):
                self.assertEqual(MANAGER.without_rule(patch(text), rule), text)

    def test_a_line_that_only_looks_like_it_stays(self) -> None:
        text = "# haprion platform\nlocal   all   all   peer\n"
        self.assertEqual(MANAGER.without_rule(text, MANAGER.PG_RULES["hba_file"]), text)


class ANode(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        machine = Machine(self.directory.name)
        self.machine = machine
        for name in (
            "/etc/haprion/node.conf",
            "/etc/sudoers.d/haprion-node",
            "/etc/sudoers.d/haprion-node-join",
            "/etc/sudoers.d/someone-else",
            "/etc/ssh/sshd_config.d/05-haprion-listen.conf",
            "/etc/sysctl.d/60-haproxy.conf",
            "/etc/rsyslog.d/47-haprion-forward.conf",
            "/etc/rsyslog.d/haprion/forward.conf",
            "/etc/rsyslog.d/49-haproxy.conf",
            "/etc/systemd/system/haprion-haproxy-log.socket",
            "/etc/systemd/system/sockets.target.wants/haprion-haproxy-log.socket",
            "/etc/systemd/system/haproxy.service.d/haprion-server-state.conf",
            "/etc/systemd/system/dnsdist.service.d/haprion.conf",
            "/etc/systemd/system/dnsdist.service.d/operator.conf",
            "/etc/haproxy/releases/20261026-101010/haproxy.cfg",
            "/etc/haproxy/certs/shop.pem",
            "/etc/haproxy/haproxy.cfg.packaged",
            "/etc/keepalived/addresses.conf",
            "/var/lib/haprion-node/prepared",
            "/var/log/haprion/traffic-2026-10-26T10.jsonl",
            "/var/log/journal/0123456789abcdef.haprion-waf/system.journal",
            "/var/spool/rsyslog/haprion-graylog.00000001",
            "/var/spool/rsyslog/other.queue",
            "/root/.ssh/id_ed25519_config_pull",
            "/root/.ssh/id_ed25519_config_pull.pub",
            "/root/.ssh/known_hosts",
            "/root/.ssh/authorized_keys",
            "/home/_haprion-trigger/.ssh/authorized_keys",
        ):
            machine.write(name)
        machine.write(
            "/etc/haprion/node.conf",
            'CLUSTER="alpha"\nMANAGER="mgr.example.com"\n'
            'CONFIG_PULL_KEY="/root/.ssh/id_ed25519_older_pull"\n',
        )
        machine.write("/root/.ssh/id_ed25519_older_pull")
        machine.write("/root/.ssh/id_ed25519_older_pull.pub")
        machine.write(
            "/etc/keepalived/keepalived.conf", NODE.KEEPALIVED_MARK + "\nglobal_defs {}\n"
        )
        machine.path("/etc/haproxy/current").symlink_to("releases/20261026-101010")
        for name in NODE.RELEASE_LINKS:
            machine.path(f"/etc/haproxy/{name}").symlink_to(f"current/{name}")
        machine.path("/etc/systemd/system/ipvsadm.service").symlink_to("/dev/null")
        machine.write(
            "/etc/sysusers.d/haprion-node.conf",
            "u _haprion-trigger - - /home/_haprion-trigger /bin/bash\ng _haprion-logs -\n",
        )
        machine.account("_haprion-trigger", "/home/_haprion-trigger")
        machine.groups.add("_haprion-logs")
        machine.answers = {
            "is-enabled --quiet keepalived.service": "",
            "is-active --quiet haproxy.service": "",
            "dpkg-query -W": "install ok installed",
        }

    def main(self, *argv: str) -> tuple[int, str]:
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = NODE.main(list(argv), host=self.machine)
        return code, out.getvalue()

    def test_without_yes_nothing_changes(self) -> None:
        before = sorted(str(p) for p in self.machine.root.rglob("*"))
        code, said = self.main()
        self.assertEqual(code, 0)
        self.assertEqual(sorted(str(p) for p in self.machine.root.rglob("*")), before)
        self.assertIn("keepalived.service: stopped and disabled", said)
        self.assertIn("ipvsadm.service: the mask Haprion set, undone", said)
        self.assertIn("sudo apt purge haprion-node", said)

    def test_with_yes_the_node_is_as_before_step_4(self) -> None:
        code, said = self.main("--yes")

        self.assertEqual(code, 0, said)
        for gone in (
            "/etc/haprion",
            "/etc/sudoers.d/haprion-node",
            "/etc/sudoers.d/haprion-node-join",
            "/etc/ssh/sshd_config.d/05-haprion-listen.conf",
            "/etc/sysctl.d/60-haproxy.conf",
            "/etc/rsyslog.d/47-haprion-forward.conf",
            "/etc/rsyslog.d/haprion",
            "/etc/systemd/system/haprion-haproxy-log.socket",
            "/etc/systemd/system/sockets.target.wants/haprion-haproxy-log.socket",
            "/etc/systemd/system/haproxy.service.d",
            "/etc/systemd/system/dnsdist.service.d/haprion.conf",
            "/etc/haproxy/releases",
            "/etc/haproxy/certs",
            "/etc/haproxy/current",
            "/etc/haproxy/conf.d",
            "/etc/keepalived/keepalived.conf",
            "/etc/keepalived/addresses.conf",
            "/var/lib/haprion-node",
            "/var/log/haprion",
            "/var/log/journal/0123456789abcdef.haprion-waf",
            "/var/spool/rsyslog/haprion-graylog.00000001",
            "/root/.ssh/id_ed25519_config_pull",
            "/root/.ssh/id_ed25519_older_pull",
            "/root/.ssh/id_ed25519_older_pull.pub",
            "/home/_haprion-trigger",
            "/etc/sysusers.d/haprion-node.conf",
        ):
            with self.subTest(gone=gone):
                path = self.machine.path(gone)
                self.assertFalse(path.exists() or path.is_symlink())
        for kept in (
            "/etc/sudoers.d/someone-else",
            "/etc/rsyslog.d/49-haproxy.conf",
            "/etc/systemd/system/dnsdist.service.d/operator.conf",
            "/var/spool/rsyslog/other.queue",
            "/root/.ssh/known_hosts",
            "/root/.ssh/authorized_keys",
        ):
            with self.subTest(kept=kept):
                self.assertTrue(self.machine.path(kept).exists())
        self.assertEqual(self.machine.path("/etc/haproxy/haproxy.cfg").read_text(), "x\n")
        ran = [" ".join(argv) for argv in self.machine.ran]
        for command in (
            "systemctl disable --now keepalived.service",
            "systemctl disable --now haproxy.service",
            "systemctl unmask ipvsadm.service",
            "userdel _haprion-trigger",
            "groupdel _haprion-logs",
            "ssh-keygen -R mgr.example.com",
        ):
            with self.subTest(command=command):
                self.assertTrue(any(command in line for line in ran), ran)

    def test_a_keepalived_conf_written_by_hand_stays_and_is_said(self) -> None:
        self.machine.write("/etc/keepalived/keepalived.conf", "global_defs {}\n")
        _, said = self.main()
        self.assertIn("keepalived.conf: its first line is not Haprion's", said)
        self.main("--yes")
        self.assertTrue(self.machine.path("/etc/keepalived/keepalived.conf").is_file())


#
# Paths the steps name that the removal does not take as files - each with why.
# A new path in a step lands here or in the removal's lists; nowhere else.
#
NODE_ACCOUNTED = {
    "/etc/apt/keyrings": "apt's directory",
    "/etc/apt/keyrings/dnsdist-21-pub.asc": "dnsdist's source: kept with the package (B372)",
    "/etc/apt/preferences.d": "apt's directory",
    "/etc/apt/preferences.d/dnsdist-21": "dnsdist's source: kept with the package (B372)",
    "/etc/apt/preferences.d/haproxy-": "HAProxy's source: kept with the package (B372)",
    "/etc/apt/sources.list.d": "apt's directory",
    "/etc/apt/sources.list.d/haproxy-": "HAProxy's source: kept with the package (B372)",
    "/etc/apt/sources.list.d/pdns.list": "dnsdist's source: kept with the package (B372)",
    "/etc/cloud/cloud-init.disabled": "read by the state export",
    "/etc/default/haproxy": "read by the state export",
    "/etc/default/keepalived": "read by the state export",
    "/etc/haproxy": "HAProxy's directory; Haprion's parts in it are listed",
    "/etc/haproxy/conf.d": "a link into the release (RELEASE_LINKS); the package's own is put back",
    "/etc/haproxy/dns/dnsdist.conf": "inside the release, through the dns link",
    "/etc/haproxy/haproxy.cfg": "a link into the release (RELEASE_LINKS); the package's put back",
    "/etc/haproxy/maps": "a link into the release (RELEASE_LINKS)",
    "/etc/haproxy/waf": "a link into the release (RELEASE_LINKS)",
    "/etc/hostname": "read by the state export",
    "/etc/hosts": "read by the state export",
    "/etc/keepalived/keepalived.conf": "removed when its first line is Haprion's (KEEPALIVED_MARK)",
    "/etc/machine-id": "read",
    "/etc/systemd/resolved.conf.d": "named in advice to the operator, never written (F23)",
    "/etc/netplan": "read by the state export",
    "/etc/os-release": "read",
    "/etc/rsyslog.conf": "read",
    "/etc/rsyslog.d": "rsyslog's directory; Haprion's files in it are listed",
    "/etc/rsyslog.d/49-haproxy.conf": "the haproxy package's",
    "/etc/ssh/ssh_host_": "read by the state export",
    "/etc/ssh/ssh_host_ed25519_key": "read by the state export",
    "/etc/ssh/ssh_host_ed25519_key.pub": "read",
    "/etc/ssh/sshd_config": "read by the state export",
    "/etc/ssh/sshd_config.d": "sshd's directory; Haprion's file in it is listed",
    "/etc/sudoers.d": "sudo's directory; Haprion's files in it are listed",
    "/etc/sysctl.d": "read by the state export",
    "/etc/systemd/system": "systemd's directory; haprion-* and the drop-ins are listed",
    "/etc/systemd/system/haproxy.service.d": "removed when empty (DROPIN_DIRS)",
    "/etc/systemd/system/ipvsadm.service": "the mask, undone (MASKS)",
    "/etc/sysusers.d": "systemd's directory; Haprion's fragment is listed",
    "/root/.ssh": "root's; Haprion's keys in it are listed",
    "/root/.ssh/known_hosts": "the manager's line, removed with ssh-keygen -R",
    "/var/lib/cmk-agent/cmk-agent-ctl.toml": "named in advice to the operator, never written (F23)",
    "/var/lib/haproxy/dev/log": "rsyslog's socket, taken back when rsyslog restarts",
    "/var/log/journal": "journald's directory; the haprion-waf namespace is listed (PATTERNS)",
}
MANAGER_ACCOUNTED = {
    "/etc/apt/keyrings": "apt's directory",
    "/etc/apt/keyrings/dnsdist-21-pub.asc": "dnsdist's source: kept with the package (B372)",
    "/etc/apt/preferences.d/dnsdist-21": "dnsdist's source: kept with the package (B372)",
    "/etc/apt/preferences.d/haproxy-": "HAProxy's source: kept with the package (B372)",
    "/etc/apt/sources.list.d/haproxy-": "HAProxy's source: kept with the package (B372)",
    "/etc/apt/sources.list.d/pdns.list": "dnsdist's source: kept with the package (B372)",
    "/etc/haproxy/current": "read: a node's layout, never made on the manager",
    "/etc/letsencrypt": "certbot's; Haprion's lineages and hook are removed",
    "/etc/letsencrypt/renewal": "certbot's; Haprion's lineages are deleted with certbot",
    "/etc/letsencrypt/renewal-hooks": "certbot's directory; the hook 50-haprion is listed",
    "/etc/letsencrypt/renewal-hooks/deploy": "certbot's directory; the hook 50-haprion is listed",
    "/etc/nginx/nginx.conf": "read",
    "/etc/nginx/sites-enabled/default": "put back when the steps took it away",
    "/etc/nginx/snippets": "nginx's directory; Haprion's snippets are listed",
    "/etc/os-release": "read",
    "/etc/ssh/ssh_host_ed25519_key.pub": "read",
    "/etc/sudoers.d": "sudo's directory; Haprion's files in it are listed",
    "/etc/systemd/system": "systemd's directory; haprion-* are listed",
    "/etc/sysusers.d": "systemd's directory; Haprion's fragment is listed",
    "/etc/tmpfiles.d": "systemd's directory; Haprion's fragment is listed",
    "/opt/haprion": "the CLI package's; its purge removes it",
    "/opt/haprion-certbot": "the certbot package's; its purge removes it",
    "/root/.ssh/known_hosts": "the nodes' lines, removed with ssh-keygen -R",
    "/var/lib/letsencrypt": "certbot's, shared with any other certbot",
    "/var/log/letsencrypt": "certbot's, shared with any other certbot",
    "/var/run/postgresql": "PostgreSQL's socket directory",
}
PATH = re.compile(r"(?<![\w$])(/(?:etc|var|srv|opt|root|home)/[A-Za-z0-9_.@/-]+)")


def named_paths(files: list[Path]) -> dict[str, str]:
    """Every absolute path a script names outside its comments, and the first script."""

    found: dict[str, str] = {}
    for file in files:
        for line in file.read_text(encoding="utf-8").splitlines():
            if not line.lstrip().startswith("#"):
                for match in PATH.finditer(line):
                    found.setdefault(match.group(1).rstrip("/."), file.name)
    return found


def unaccounted(found: dict[str, str], listed: list[str], accounted: dict[str, str]) -> list[str]:
    return sorted(
        f"{path} (in {where})"
        for path, where in found.items()
        if path not in accounted
        and not any(path == entry or path.startswith(entry.rstrip("/") + "/") for entry in listed)
        and not PurePath(path).match("/etc/systemd/system/haprion-*")
        and not any(
            path.startswith(entry + "/") for entry in accounted if entry.startswith("/opt/")
        )
    )


class TheRemovalNamesWhatTheStepsWrite(unittest.TestCase):
    def test_on_a_node(self) -> None:
        files = [INSTALL / "04-node-prepare", INSTALL / "node-lib.sh"] + sorted(
            p for p in (INSTALL / "node").iterdir() if p.is_file() and p.suffix != ".py"
        )
        listed = [*NODE.FIXED_PATHS, *NODE.PATTERNS]
        self.assertEqual(unaccounted(named_paths(files), listed, NODE_ACCOUNTED), [])

    def test_on_the_manager(self) -> None:
        files = [
            INSTALL / "01-manager-prepare",
            INSTALL / "02-manager-config",
            INSTALL / "03-manager-keys",
            INSTALL / "lib.sh",
            INSTALL / "node-lib.sh",
            *sorted((INSTALL / "platform").glob("[0-9]*")),
        ]
        listed = [*MANAGER.FIXED_PATHS, *MANAGER.DEFAULT_ROOTS, MANAGER.DATA]
        self.assertEqual(unaccounted(named_paths(files), listed, MANAGER_ACCOUNTED), [])

    def test_every_accounted_path_is_still_named_by_a_step(self) -> None:
        """An entry nothing names any more is a reason kept for a path that went."""

        node = named_paths(
            [INSTALL / "04-node-prepare", INSTALL / "node-lib.sh"]
            + sorted(p for p in (INSTALL / "node").iterdir() if p.is_file())
        )
        manager = named_paths(
            [
                INSTALL / n
                for n in (
                    "01-manager-prepare",
                    "02-manager-config",
                    "03-manager-keys",
                    "lib.sh",
                    "node-lib.sh",
                )
            ]
            + sorted((INSTALL / "platform").glob("[0-9]*"))
        )
        for accounted, named in ((NODE_ACCOUNTED, node), (MANAGER_ACCOUNTED, manager)):
            stale = [
                entry for entry in accounted
                if not any(path == entry or path.startswith(entry + "/") for path in named)
            ]  # fmt: skip
            self.assertEqual(stale, [])


class TheNamesAreTheInstallation_s(unittest.TestCase):
    def test_the_database_roles_are_the_fixed_ones(self) -> None:
        logins = (accounts.MIGRATION_ROLE, accounts.WEB, accounts.WORKER, accounts.POLLER)
        groups = ("app_web", "app_worker", "app_poller", "app_collector")
        self.assertEqual(set(MANAGER.DB_ROLES), {*logins, accounts.COLLECTOR, *groups})
        self.assertEqual(MANAGER.DB_NAME, accounts.DATABASE)

    def test_the_rules_are_the_ones_step_2_writes(self) -> None:
        step = (INSTALL / "platform/02-platform-database").read_text()
        self.assertIn('ident_line="haprion_migration   root   ${DB_MIGRATION_ROLE}"', step)
        self.assertIn(
            'hba_line="local   ${DB_NAME}   ${DB_MIGRATION_ROLE}   peer   map=haprion_migration"',
            step,
        )
        self.assertEqual(
            MANAGER.PG_RULES["ident_file"],
            f"haprion_migration   root   {accounts.MIGRATION_ROLE}",
        )

    def test_keepalived_s_mark_is_the_writer_s(self) -> None:
        from haprion import keepalived_conf

        self.assertIn(NODE.KEEPALIVED_MARK, keepalived_conf.__dict__.values())

    def test_both_packages_carry_the_removal(self) -> None:
        shipped = {source for source, _ in node_package.CONTENTS.values()}
        self.assertLessEqual({"install/node-remove", "install/removal.py"}, shipped)
        self.assertFalse(
            any(
                path.startswith(node_package.INSTALL_DIR[1:] + "/node-remove")
                for path in node_package.CONTENTS
            )
        )
        ui = (BASE / "tools/build-ui-package.py").read_text()
        for name in ("install/remove-manager", "install/removal.py"):
            self.assertIn(f'"{name}"', ui)


if __name__ == "__main__":
    unittest.main()
