"""An update installs the platform files again, and puts them back when it fails (review 2026-10-22, 6-5).

Only the web unit followed `apt upgrade`. A release that needed one more
helper rule stopped its own update at the check ("expected 15 ... found 14"),
and a changed nginx site waited for step 05 to be run again by hand. These run
`refresh-platform-files` as written, under a temporary root, with systemctl,
visudo and nginx standing in; its `../lib.sh` is the real one with the root
check left out, as in `test_platform_release`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / "install/platform"

STUB_SYSTEMCTL = """#!/bin/bash
echo "systemctl $*" >> "$RECORD"
"""
STUB_NGINX = """#!/bin/bash
echo "nginx $*" >> "$RECORD"
[[ -z "${NGINX_REFUSES:-}" ]]
"""
STUB_VISUDO = """#!/bin/bash
! grep -q "does not parse" "${@: -1}"
"""
STUB_CHOWN = """#!/bin/bash
exit 0
"""
#
# install(1) as the script calls it, without the owner it may not give here.
#
STUB_INSTALL = """#!/bin/bash
arguments=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|-g) shift 2 ;;
        *) arguments+=("$1"); shift ;;
    esac
done
exec /usr/bin/install "${arguments[@]}"
"""
#
# The release's Python, asked for the worker's sandbox roots.
#
STUB_PYTHON = """#!/bin/bash
echo /srv/example/config /srv/example/registry
"""


class ThePlatformFilesFollowAnUpdate(unittest.TestCase):
    def setUp(self) -> None:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        shutil.copytree(PLATFORM / "examples", work / "platform/examples")
        shutil.copy2(PLATFORM / "refresh-platform-files", work / "platform")
        shutil.copy2(ROOT / "install/certbot-deploy-hook", work / "certbot-deploy-hook")
        (work / "lib.sh").write_text((ROOT / "install/lib.sh").read_text() + "need_root() { :; }\n")
        shutil.copy2(ROOT / "install/node-lib.sh", work / "node-lib.sh")
        shutil.copy2(ROOT / "install/defaults.sh", work / "defaults.sh")
        (work / "accounts.sh").write_text(
            (ROOT / "install/accounts.sh")
            .read_text()
            .replace("readonly UI_ROOT=/opt/haprion-ui", f"readonly UI_ROOT={work / 'ui'}")
        )
        python = work / "ui/releases/r2/venv/bin/python"
        python.parent.mkdir(parents=True)
        self.executable(python, STUB_PYTHON)
        stubs = work / "bin"
        stubs.mkdir()
        for name, text in (
            ("systemctl", STUB_SYSTEMCTL),
            ("nginx", STUB_NGINX),
            ("visudo", STUB_VISUDO),
            ("chown", STUB_CHOWN),
            ("install", STUB_INSTALL),
        ):
            self.executable(stubs / name, text)
        self.systemd = work / "etc/systemd/system"
        self.sudoers = work / "etc/sudoers.d"
        self.site = work / "etc/nginx/sites-available/haprion"
        self.tls = work / "etc/haprion/ui-tls.conf"
        self.hooks = work / "etc/letsencrypt/renewal-hooks/deploy"
        for directory in (
            self.systemd,
            self.sudoers,
            self.site.parent,
            self.tls.parent,
            self.hooks,
            self.site.parent.parent / "snippets",
        ):
            directory.mkdir(parents=True)
        self.tls.write_text(
            "TLS_CERT=/etc/haprion/tls/ui.crt\nTLS_KEY=/etc/haprion/tls/ui.key\n"
            "SERVER_NAME=mgr.example.com\n"
        )
        self.keep = work / "keep"
        self.keep.mkdir()
        self.record = work / "record"
        self.script = work / "platform/refresh-platform-files"
        self.environment = {
            **os.environ,
            "PATH": f"{stubs}:{os.environ['PATH']}",
            "RECORD": str(self.record),
            "SYSTEMD_DIR": str(self.systemd),
            "SUDOERS_DIR": str(self.sudoers),
            "NGINX_SITE": str(self.site),
            "TLS_CONF": str(self.tls),
            "CERTBOT_HOOK_DIR": str(self.hooks),
            "HSTS_SNIPPET": str(self.site.parent.parent / "snippets/haprion-hsts.conf"),
        }
        #
        # A first installation's files, as an older package wrote them: every
        # one step 07 always installs, the probe's socket, the retention timer
        # and the site - and not the OIDC helper's socket or the collector's.
        #
        self.old = {
            self.sudoers / "haprion-worker": "old worker rule",
            self.sudoers / "haprion-poller": "old poller rule",
            self.systemd / "haprion-worker.service": "old",
            self.systemd / "haprion-poller.service": "old",
            self.systemd / "haprion-web.service": "old",
            self.systemd / "haprion-retention.service": "old",
            self.systemd / "haprion-retention.timer": "old",
            self.site: "old site",
        }
        for name in (
            "resolve",
            "cert-export",
            "cert-receiver",
            "node",
            "tls",
            "backup-job",
            "probe",
        ):
            self.old[self.systemd / f"haprion-{name}-helper@.service"] = "old"
            self.old[self.systemd / f"haprion-{name}-helper.socket"] = "old"
        for path, text in self.old.items():
            path.write_text(text + "\n")

    @staticmethod
    def executable(path: Path, text: str) -> None:
        path.write_text(text)
        path.chmod(0o755)

    def run_script(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - the copied script, fixed arguments
            ["/bin/bash", str(self.script), *arguments],
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def refresh(self) -> subprocess.CompletedProcess[str]:
        return self.run_script("r2", str(self.keep))

    def recorded(self) -> list[str]:
        return self.record.read_text().splitlines() if self.record.exists() else []

    def test_every_file_its_step_installed_is_this_package_s(self) -> None:
        done = self.refresh()
        self.assertEqual(done.returncode, 0, done.stderr)

        worker = (self.sudoers / "haprion-worker").read_text()
        self.assertEqual(worker, (PLATFORM / "examples/haprion-worker.sudoers.example").read_text())
        unit = (self.systemd / "haprion-worker.service").read_text()
        self.assertIn("/srv/example/config /srv/example/registry", unit)
        self.assertNotIn("@POLICY_PATHS@", unit)
        socket = (self.systemd / "haprion-node-helper.socket").read_text()
        self.assertIn("SocketGroup=_haprion-worker", socket)
        self.assertIn("haprion-probe", (self.systemd / "haprion-probe-helper.socket").read_text())
        site = self.site.read_text()
        self.assertIn("mgr.example.com", site)
        self.assertNotIn("SERVER_NAME", site)

    def test_a_socket_step_07_always_installs_is_installed_when_missing(self) -> None:
        done = self.refresh()
        self.assertEqual(done.returncode, 0, done.stderr)

        self.assertTrue((self.systemd / "haprion-node-restore-helper.socket").is_file())
        enabled = [line for line in self.recorded() if line.startswith("systemctl enable")]
        self.assertTrue(any("haprion-node-restore-helper.socket" in line for line in enabled))

    def test_a_timer_a_later_release_added_to_a_step_comes_with_the_step_s_first(self) -> None:
        """The traffic partitions' hourly budget (B356) belongs to step 11, which ran before it existed."""

        done = self.refresh()
        self.assertEqual(done.returncode, 0, done.stderr)

        for kind in ("service", "timer"):
            self.assertEqual(
                (self.systemd / f"haprion-retention-budget.{kind}").read_text(),
                (PLATFORM / f"examples/haprion-retention-budget.{kind}.example").read_text(),
            )
        enabled = [line for line in self.recorded() if line.startswith("systemctl enable")]
        self.assertTrue(any("haprion-retention-budget.timer" in line for line in enabled))

    def test_the_web_s_socket_is_installed_and_left_to_the_activation(self) -> None:
        """5-8: the running web holds the listener it started with until it is restarted."""

        done = self.refresh()
        self.assertEqual(done.returncode, 0, done.stderr)

        self.assertEqual(
            (self.systemd / "haprion-web.socket").read_text(),
            (PLATFORM / "examples/haprion-web.socket.example").read_text(),
        )
        started = [
            line
            for line in self.recorded()
            if line.startswith(("systemctl enable", "systemctl restart", "systemctl start"))
        ]
        self.assertFalse(any("haprion-web" in line for line in started), started)

    def test_what_its_step_did_not_install_stays_out(self) -> None:
        done = self.refresh()
        self.assertEqual(done.returncode, 0, done.stderr)

        self.assertFalse((self.systemd / "haprion-oidc-helper.socket").exists())
        self.assertFalse((self.systemd / "haprion-traffic-collector.timer").exists())
        self.assertFalse((self.systemd / "haprion-certbot-renew.timer").exists())

    def test_what_changed_is_read_again_restarted_and_proved(self) -> None:
        done = self.refresh()
        self.assertEqual(done.returncode, 0, done.stderr)

        recorded = self.recorded()
        self.assertIn("systemctl daemon-reload", recorded)
        self.assertTrue(
            any(
                line.startswith("systemctl restart haprion-")
                and "haprion-node-helper.socket" in line
                for line in recorded
            )
        )
        self.assertTrue(
            any(
                line.startswith("systemctl restart ") and "haprion-retention.timer" in line.split()
                for line in recorded
            )
        )
        # Proved here, taken by nginx when the release is activated (5-8): the
        # running web still listens where the old site says.
        self.assertIn("nginx -t", recorded)
        self.assertNotIn("systemctl reload nginx", recorded)

    def test_a_second_run_changes_nothing(self) -> None:
        self.assertEqual(self.refresh().returncode, 0)
        self.record.unlink()
        again = self.run_script("r2", str(self.keep))

        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(self.recorded(), [])
        self.assertIn("every platform file is this package's already", again.stdout)

    def test_a_restore_puts_back_what_the_previous_release_ran_with(self) -> None:
        self.assertEqual(self.refresh().returncode, 0)
        self.record.unlink()
        done = self.run_script("--restore", str(self.keep))

        self.assertEqual(done.returncode, 0, done.stderr)
        for path, text in self.old.items():
            with self.subTest(path=path.name):
                self.assertEqual(path.read_text(), text + "\n")
        self.assertFalse((self.systemd / "haprion-node-restore-helper.socket").exists())
        recorded = self.recorded()
        self.assertIn(
            "systemctl disable --quiet --now haprion-node-restore-helper.socket", recorded
        )
        self.assertFalse((self.systemd / "haprion-retention-budget.timer").exists())
        self.assertFalse((self.systemd / "haprion-web.socket").exists())
        self.assertIn("systemctl disable --quiet --now haprion-web.socket", recorded)
        self.assertIn("systemctl disable --quiet --now haprion-retention-budget.timer", recorded)
        self.assertIn("systemctl daemon-reload", recorded)
        self.assertIn("systemctl reload nginx", recorded)
        self.assertEqual((self.keep / "manifest").read_text(), "")

    def test_certbot_s_hook_follows_where_step_14_installed_it(self) -> None:
        """Review 26-10-24, 14-01: only step 14 wrote it, and an update ran that
        step only when certbot's own release changed."""

        hook = self.hooks / "50-haprion"
        hook.write_text("old hook\n")
        (self.systemd / "haprion-certbot-renew.timer").write_text("old\n")
        done = self.refresh()

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(hook.read_text(), (ROOT / "install/certbot-deploy-hook").read_text())
        self.assertEqual(hook.stat().st_mode & 0o777, 0o755)
        restored = self.run_script("--restore", str(self.keep))

        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(hook.read_text(), "old hook\n")
        # certbot runs every file in the directory: no copy is ever left beside it.
        self.assertEqual([path.name for path in self.hooks.iterdir()], ["50-haprion"])

    def test_hsts_is_written_as_the_operator_chose_it_and_kept(self) -> None:
        """Review 26-10-24, 09-03: a line added to the site by hand went at every update."""

        snippet = Path(self.environment["HSTS_SNIPPET"])
        self.tls.write_text(self.tls.read_text() + "HSTS=yes\n")
        self.assertEqual(self.refresh().returncode, 0)
        self.assertIn("Strict-Transport-Security", snippet.read_text())
        self.assertIn("include /etc/nginx/snippets/haprion-hsts.conf;", self.site.read_text())
        self.record.unlink()
        again = self.run_script("r2", str(self.keep))
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("Strict-Transport-Security", snippet.read_text())
        self.assertEqual(self.recorded(), [])

    def test_hsts_is_off_unless_chosen(self) -> None:
        snippet = Path(self.environment["HSTS_SNIPPET"])
        self.assertEqual(self.refresh().returncode, 0)
        self.assertNotIn("Strict-Transport-Security", snippet.read_text())

    def test_without_step_14_there_is_no_hook(self) -> None:
        self.assertEqual(self.refresh().returncode, 0)
        self.assertEqual(list(self.hooks.iterdir()), [])

    def test_a_sudo_rule_that_does_not_parse_is_not_installed(self) -> None:
        rule = self.script.parent / "examples/haprion-worker.sudoers.example"
        rule.write_text("this rule does not parse\n")
        done = self.refresh()

        self.assertNotEqual(done.returncode, 0)
        self.assertIn("does not parse", done.stderr)
        self.assertEqual((self.sudoers / "haprion-worker").read_text(), "old worker rule\n")
        self.assertNotIn("haprion-worker\t", (self.keep / "manifest").read_text())

    def test_a_site_nginx_refuses_stops_the_update(self) -> None:
        self.environment["NGINX_REFUSES"] = "1"
        done = self.refresh()

        self.assertNotEqual(done.returncode, 0)
        self.assertIn("nginx refuses the new site", done.stderr)
        self.assertNotIn("systemctl reload nginx", self.recorded())


class TheListsAreTheSteps(unittest.TestCase):
    """The lists the update installs from, held to the steps that install them first."""

    @staticmethod
    def array(name: str) -> list[str]:
        text = (PLATFORM / "refresh-platform-files").read_text()
        found = re.search(rf"^{name}=\(([^)]*)\)", text, re.MULTILINE)
        if found is None:
            raise AssertionError(f"{name} is not in refresh-platform-files")
        return found.group(1).split()

    @staticmethod
    def examples(suffix: str) -> set[str]:
        return {
            path.name.removesuffix(suffix) for path in (PLATFORM / "examples").glob(f"*{suffix}")
        }

    #
    # Each file a platform step installs, as the step names it: what the update
    # installs it from (a word refresh-platform-files must hold), or why the
    # step alone writes it. Review 26-10-24, 14-01: certbot's hook was neither,
    # and a changed hook never reached an installation.
    #
    REFRESHED = {
        ("04-platform-service", '"/etc/systemd/system/${unit_name}.socket"'): (
            "examples/haprion-web.socket.example"
        ),
        ("04-platform-service", '"$unit"'): "examples/haprion-web.service.example",
        ("05-platform-nginx", "/etc/nginx/sites-available/haprion"): (
            "examples/haprion.nginx.example"
        ),
        ("05-platform-nginx", "/etc/nginx/snippets/haprion-hsts.conf"): "HSTS_SNIPPET",
        ("06-platform-backup", '"/etc/systemd/system/${unit}.${kind}"'): (
            "haprion-backup haprion-restore-check"
        ),
        ("07-platform-services", '"/etc/sudoers.d/${POLLER_SUDOERS}"'): (
            "examples/haprion-poller.sudoers.example"
        ),
        ("07-platform-services", '"/etc/sudoers.d/${WORKER_SUDOERS}"'): (
            "examples/haprion-worker.sudoers.example"
        ),
        ("07-platform-services", '"/etc/systemd/system/${WORKER_UNIT}"'): (
            "examples/haprion-worker.service.example"
        ),
        ("07-platform-services", '"/etc/systemd/system/${POLLER_UNIT}"'): (
            "examples/haprion-poller.service.example"
        ),
        ("11-platform-retention", '"/etc/systemd/system/${timer}.${kind}"'): ("haprion-retention"),
        ("13-platform-traffic-collector", '"/etc/systemd/system/${UNIT}.${kind}"'): (
            "haprion-traffic-collector"
        ),
        ("14-platform-certbot", '"$HOOK"'): "../certbot-deploy-hook",
        ("14-platform-certbot", '"/etc/systemd/system/${UNIT}.service"'): ("haprion-certbot-renew"),
        ("14-platform-certbot", '"/etc/systemd/system/${UNIT}.timer"'): "haprion-certbot-renew",
        ("17-platform-oidc", "/etc/systemd/system/haprion-oidc-helper@.service"): (
            "OPTIONAL_SOCKETS=(probe oidc)"
        ),
        ("17-platform-oidc", "/etc/systemd/system/haprion-oidc-helper.socket"): (
            "OPTIONAL_SOCKETS=(probe oidc)"
        ),
    }
    REFRESHED |= {
        ("07-platform-services", f'"/etc/systemd/system/haprion-{name}-helper{suffix}"'): name
        for name in (
            "probe",
            "resolve",
            "cert-export",
            "cert-receiver",
            "node",
            "tls",
            "backup-job",
            "node-restore",
            "ndes-server",
        )
        for suffix in ("@.service", ".socket")
    }
    LEFT_TO_THE_STEP = {
        ("01-platform-prepare", '"$config"'): "ui.toml, the operator's; made empty once",
        ("02-platform-database", '"$hba"'): "PostgreSQL's file, for the database the step makes",
        ("02-platform-database", "/etc/haprion/ui-admin.conf"): "from the answers",
        ("05-platform-nginx", "/etc/haprion/ui-tls.conf"): "from the answers",
        ("05-platform-nginx", "/etc/nginx/snippets/haprion-receivers.conf"): (
            "made empty once; haprion-cert-receiver writes it"
        ),
        ("05-platform-nginx", "/etc/nginx/snippets/haprion-real-ip.conf"): "from the answers",
        ("13-platform-traffic-collector", '"$COLLECTOR_KNOWN_HOSTS"'): (
            "the nodes' host keys, as the operator confirmed them"
        ),
        ("13-platform-traffic-collector", '"$COLLECTOR_CONFIG"'): (
            "the nodes, kept by adding and removing them (node_enrollment)"
        ),
    }

    def test_every_file_a_step_installs_is_refreshed_or_said_why_not(self) -> None:
        refresh = (PLATFORM / "refresh-platform-files").read_text()
        written = re.compile(
            r"^\s*(?:install_file (\S+)|install -o \S+ -g \S+ -m \d+ \S+ (\S+)$)", re.MULTILINE
        )
        found: set[tuple[str, str]] = set()
        for step in sorted(PLATFORM.glob("[01][0-9]-platform-*")):
            for match in written.finditer(step.read_text()):
                found.add((step.name, match.group(1) or match.group(2)))
        self.assertEqual(sorted(found - set(self.REFRESHED) - set(self.LEFT_TO_THE_STEP)), [])
        self.assertEqual(sorted((set(self.REFRESHED) | set(self.LEFT_TO_THE_STEP)) - found), [])
        for (name, target), word in self.REFRESHED.items():
            with self.subTest(step=name, target=target):
                self.assertIn(word, refresh)

    #
    # Each directory a platform step makes, with the owner and mode it gives it:
    # made again by every update (the line lib.sh's functions hold for it), or
    # why only the step makes it. Review 26-10-24, 14-02: steps 13 and 17 made
    # their identity directories root's, and no installation made before then
    # was given that.
    #
    AS_FIRST_MADE = "unchanged since the first installation; a change must reach the update too"
    MADE_BY_THE_UPDATE = {
        ("13-platform-traffic-collector", '"$IDENTITY_DIR" "root:${COLLECTOR_USER}" 550'): (
            'ensure_dir /etc/haprion/traffic-collector "root:${COLLECTOR_USER}" 550'
        ),
        ("15-platform-dns-keys", '"$PROFILE_DIR" root:root 700'): (
            "ensure_dir /etc/haprion/dns-profiles root:root 700"
        ),
        ("16-platform-scep", "/etc/haprion/ndes-profiles root:root 700"): (
            "ensure_dir /etc/haprion/ndes-profiles root:root 700"
        ),
        ("16-platform-scep", "/etc/haprion/ndes-requests root:root 700"): (
            "ensure_dir /etc/haprion/ndes-requests root:root 700"
        ),
    }
    MADE_ONCE = {
        ("01-platform-prepare", '"$UI_ROOT" root:root 755'): AS_FIRST_MADE,
        ("01-platform-prepare", '"${UI_ROOT}/releases" root:root 755'): AS_FIRST_MADE,
        ("01-platform-prepare", '"$(dirname "$UI_CONFIG")" root:root 755'): AS_FIRST_MADE,
        ("01-platform-prepare", '"$UI_SECRETS" root:root 700'): AS_FIRST_MADE,
        ("01-platform-prepare", '"$UI_DATA" root:root 755'): AS_FIRST_MADE,
        ("01-platform-prepare", '"${UI_DATA}/dumps" root:root 700'): AS_FIRST_MADE,
        ("02-platform-database", "/etc/haprion root:root 755"): AS_FIRST_MADE,
        ("05-platform-nginx", "/etc/haprion root:root 755"): AS_FIRST_MADE,
        ("05-platform-nginx", '"$(dirname "$TLS_CERT")" root:root 700'): "from the answers",
        ("05-platform-nginx", '"$(dirname "$TLS_KEY")" root:root 700'): "from the answers",
        ("05-platform-nginx", "/etc/nginx/snippets root:root 755"): AS_FIRST_MADE,
        ("06-platform-backup", '"$DUMP_DIR" root:root 700'): AS_FIRST_MADE,
        ("13-platform-traffic-collector", '"$LOG_ROOT" root:root 755'): AS_FIRST_MADE,
        ("13-platform-traffic-collector", '"$MIRROR" "${COLLECTOR_USER}:${WEB_USER}" 2750'): (
            AS_FIRST_MADE
        ),
        ("13-platform-traffic-collector", '"$STAGING" "${COLLECTOR_USER}:${COLLECTOR_USER}" 700'): (
            AS_FIRST_MADE
        ),
        ("14-platform-certbot", "/etc/letsencrypt/renewal-hooks root:root 755"): AS_FIRST_MADE,
        ("14-platform-certbot", '"$HOOK_DIR" root:root 755'): AS_FIRST_MADE,
        ("15-platform-dns-keys", '"$PRIVATE_DIR" root:root 700'): AS_FIRST_MADE,
        ("15-platform-dns-keys", '"$PUBLIC_DIR" "root:${PLATFORM_GROUP}" 750'): AS_FIRST_MADE,
        ("17-platform-oidc", '"$PUBLIC_DIR" "root:${PLATFORM_GROUP}" 750'): AS_FIRST_MADE,
        ("17-platform-oidc", '-o root -g root -m 700 "$KEY_DIR"'): (
            "closed while the key pair is written; the update gives it the step's final owner"
        ),
    }

    def test_every_directory_a_step_makes_is_made_by_the_update_or_said_why_not(self) -> None:
        lib = (ROOT / "install/lib.sh").read_text()
        made = re.compile(r"^\s*(?:ensure_dir|install -d) (.*)$", re.MULTILINE)
        found: set[tuple[str, str]] = set()
        for step in sorted(PLATFORM.glob("[01][0-9]-platform-*")):
            for match in made.finditer(step.read_text()):
                found.add((step.name, " ".join(match.group(1).split())))
        listed = set(self.MADE_BY_THE_UPDATE) | set(self.MADE_ONCE)
        self.assertEqual(sorted(found - listed), [])
        self.assertEqual(sorted(listed - found), [])
        for (name, line), made_by in self.MADE_BY_THE_UPDATE.items():
            with self.subTest(step=name, line=line):
                self.assertRegex(lib, rf"(?m)^\s+{re.escape(made_by)}$")

    def test_the_update_gives_the_identity_directories_what_their_steps_do(self) -> None:
        lib = (ROOT / "install/lib.sh").read_text()
        collector = (PLATFORM / "13-platform-traffic-collector").read_text()
        self.assertIn('\nIDENTITY_DIR="/etc/haprion/traffic-collector"\n', collector)
        oidc = (PLATFORM / "17-platform-oidc").read_text()
        self.assertIn('\nKEY_DIR="/etc/haprion/oidc"\n', oidc)
        self.assertIn('\nchown "root:${OIDC_USER}" "$KEY_DIR"\nchmod 550 "$KEY_DIR"\n', oidc)
        self.assertIn('\n        ensure_dir /etc/haprion/oidc "root:${OIDC_USER}" 550\n', lib)

    def test_every_sudo_boundary_check_asks_the_rules_and_runs_nothing(self) -> None:
        """Review 26-10-24, 08-01: without -l a check could never fail."""

        step = (PLATFORM / "07-platform-services").read_text()
        asked = re.findall(r"sudo -n(?! -l)\S*\s+/", step)
        self.assertEqual(asked, [], "a boundary check runs the helper instead of asking sudo")

    def test_each_granted_helper_is_asked_for_by_every_other_account(self) -> None:
        step = (PLATFORM / "07-platform-services").read_text()
        start = step.index("refuse_granted_elsewhere() {")
        body = step[start : step.index("\n}\n", start) + 3]
        rules = (
            '_haprion-worker ALL=(root) NOPASSWD: /opt/haprion/current/bin/a-helper ""\n'
            '_haprion-worker ALL=(root) NOPASSWD: /opt/haprion/current/bin/b-helper ""\n'
        )
        with tempfile.TemporaryDirectory() as raw:
            sudoers = Path(raw) / "haprion-worker"
            sudoers.write_text(rules)
            empty = Path(raw) / "empty"
            empty.write_text("# nothing\n")
            done = subprocess.run(  # noqa: S603 - fixed interpreter, the step's own function
                [
                    "/bin/bash",
                    "-c",
                    "WEB_USER=_haprion-ui; WORKER_USER=_haprion-worker; "
                    "POLLER_USER=_haprion-poller; failed=0; "
                    'warn() { echo "$*"; }; refuse() { echo "asked $1 ${*:3}"; }; '
                    f'{body}refuse_granted_elsewhere "{sudoers}" _haprion-worker; '
                    f'refuse_granted_elsewhere "{empty}" _haprion-poller; echo "failed=$failed"',
                ],
                capture_output=True,
                text=True,
                check=True,
            )
        asked = [line for line in done.stdout.splitlines() if line.startswith("asked")]
        self.assertEqual(
            asked,
            [
                "asked _haprion-ui sudo -n -l /opt/haprion/current/bin/a-helper",
                "asked _haprion-poller sudo -n -l /opt/haprion/current/bin/a-helper",
                "asked _haprion-ui sudo -n -l /opt/haprion/current/bin/b-helper",
                "asked _haprion-poller sudo -n -l /opt/haprion/current/bin/b-helper",
            ],
        )
        self.assertIn("FAIL     no _haprion-poller rule could be read", done.stdout)
        self.assertIn("failed=1", done.stdout)

    def test_the_sockets_are_those_step_07_always_installs(self) -> None:
        step = (PLATFORM / "07-platform-services").read_text()
        always = set(
            re.findall(
                r'^install_file "/etc/systemd/system/haprion-([a-z-]+)-helper\.socket"',
                step,
                re.MULTILINE,
            )
        )
        self.assertEqual(set(self.array("SOCKETS")), always)

    def test_every_socket_and_timer_example_is_one_of_them(self) -> None:
        # The web's own socket is installed with the web's unit (5-8), not as a helper's.
        sockets = {
            name.removeprefix("haprion-").removesuffix("-helper")
            for name in self.examples(".socket.example")
            if name != "haprion-web"
        }
        self.assertEqual(set(self.array("SOCKETS")) | set(self.array("OPTIONAL_SOCKETS")), sockets)
        self.assertEqual(set(self.array("TIMERS")), self.examples(".timer.example"))

    def test_each_step_renders_an_example_as_render_example_does(self) -> None:
        lib = (ROOT / "install/lib.sh").read_text()
        body = lib[
            lib.index("render_example() {") : lib.index("\n}\n", lib.index("render_example() {"))
        ]
        rendered = set(re.findall(r"s\|([A-Z_]+)\|\$\{([A-Z_]+)\}\|g", body))
        self.assertTrue(rendered)
        self.assertTrue(all(token == variable for token, variable in rendered))
        found = 0
        for step in sorted(PLATFORM.glob("[01][0-9]-platform-*")):
            text = step.read_text()
            for token, variable in re.findall(
                r's\|([A-Z_]+)\|\$\{([A-Z_]+)\}\|g"? [\'"]?examples/', text
            ):
                found += 1
                with self.subTest(step=step.name, token=token):
                    self.assertEqual(token, variable)
                    self.assertIn((token, variable), rendered)
        self.assertGreater(found, 5)


if __name__ == "__main__":
    unittest.main()
