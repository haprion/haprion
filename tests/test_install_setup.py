"""A manager installed with one command and no answers file (B302).

The installation steps run as root and are proved on a machine; what is held
here is what they are made of: the defaults, what step 2 writes read back by
the engine's own readers, the editing policy in the shape the cluster flows
edit, and the errors - each one provoked and read the way haprion-setup shows
it, in words rather than an exit code.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

from haprion import traffic_collector
from haprion.cli.cluster_config import main as cluster_config_main
from haprion.cluster_definition import sudoers_with
from haprion.config import load_policy, load_registry, load_runtime_config

INSTALL = Path(__file__).resolve().parents[1] / "install"
LIB = INSTALL / "lib.sh"
SETUP = INSTALL / "setup.sh"
DRIVER = INSTALL / "haprion-setup"
# What haprion-setup does before its checks; "$1" is setup.sh.
STRICT = f'set -Eeuo pipefail; source "{LIB}"; source "$1"; '


def bash(
    script: str, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter, the repository's own scripts
        ["/bin/bash", "-c", script, "bash", *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def answers_value(names: list[str], answers: str = "") -> dict[str, str]:
    printed = bash(
        'set -Eeuo pipefail; source "$1"; load_answers "$2"; shift 2; '
        'for name in "$@"; do printf "%s=%s\\n" "$name" "${!name}"; done',
        str(LIB),
        answers,
        *names,
    )
    assert printed.returncode == 0, printed.stderr
    return dict(line.split("=", 1) for line in printed.stdout.splitlines())


class TheAnswersFileIsOptional(unittest.TestCase):
    def test_without_one_the_defaults_are_the_answers(self) -> None:
        values = answers_value(["CONFIG_ROOT", "CLUSTERS", "CERTIFICATE_REGISTRY", "SERVER_NAME"])
        self.assertEqual(values["CONFIG_ROOT"], "/srv/haprion/config")
        self.assertEqual(values["CLUSTERS"], "")
        self.assertEqual(values["CERTIFICATE_REGISTRY"], "/etc/haprion/registry/certificates.yaml")
        self.assertEqual(values["SERVER_NAME"], socket.getfqdn() or values["SERVER_NAME"])

    def test_a_dash_is_no_file(self) -> None:
        self.assertEqual(answers_value(["CONFIG_ROOT"], "-"), answers_value(["CONFIG_ROOT"]))

    def test_a_file_sets_what_it_names_and_keeps_an_empty_value_empty(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            answers = Path(raw) / "answers.env"
            answers.write_text("CONFIG_ROOT=/srv/other\nBACKUP_ROOT=\n")
            values = answers_value(["CONFIG_ROOT", "BACKUP_ROOT", "PUBLISH_ROOT"], str(answers))
        self.assertEqual(values["CONFIG_ROOT"], "/srv/other")
        self.assertEqual(values["BACKUP_ROOT"], "")
        self.assertEqual(values["PUBLISH_ROOT"], "/srv/haprion/published")


class RelativePathsAreTheCallers(unittest.TestCase):
    """Every step changes to its own directory first; a path the operator gives
    relative to where they stood must still name the same file (Fas 18, finding 21)."""

    LIB_SOURCE = re.compile(r'^(source|\.) .*lib\.sh"?$', re.MULTILINE)

    def test_an_answers_file_beside_the_caller_is_found(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            (Path(raw) / "answers.env").write_text("CONFIG_ROOT=/srv/other\n")
            done = subprocess.run(  # noqa: S603 - fixed interpreter, the repository's lib.sh
                [
                    "/bin/bash",
                    "-c",
                    'set -Eeuo pipefail; cd "$1"; source ./lib.sh; load_answers answers.env; '
                    'printf %s "$CONFIG_ROOT"',
                    "bash",
                    str(INSTALL),
                ],
                capture_output=True,
                text=True,
                check=False,
                cwd=raw,
            )
        self.assertEqual((done.returncode, done.stdout), (0, "/srv/other"), done.stderr)

    def test_every_script_changes_to_its_own_directory_just_before_lib_sh(self) -> None:
        texts = {
            path: path.read_bytes().decode(errors="replace")  # apt-keys/ holds binary keys
            for path in sorted(INSTALL.rglob("*"))
            if path.is_file() and path.name != "lib.sh"
        }
        scripts = {
            path: found for path, text in texts.items() if (found := self.LIB_SOURCE.search(text))
        }
        self.assertGreater(len(scripts), 15)
        for path, found in scripts.items():
            with self.subTest(path.relative_to(INSTALL)):
                head = texts[path][: found.start()]
                changes = re.findall(r"^cd .*$", head, re.MULTILINE)
                self.assertEqual(len(changes), 1, changes)
                self.assertRegex(changes[0], r'^cd "(\$\(dirname "\$0"\)|\$here)"$')


class Step3MakesTheFileANodeChangeEdits(unittest.TestCase):
    """Create cluster refused on a new manager: no root known_hosts (Fas 18, finding 28)."""

    BLOCK = re.compile(r"^ROOT_KNOWN_HOSTS=.*?^fi\n", re.MULTILINE | re.DOTALL)

    def test_it_is_the_file_the_change_reads(self) -> None:
        from haprion import node_enrollment  # noqa: PLC0415

        found = self.BLOCK.search((INSTALL / "03-manager-keys").read_text())
        assert found, "03-manager-keys no longer makes root's known_hosts"
        self.assertIn(f'ROOT_KNOWN_HOSTS="{node_enrollment.ROOT_KNOWN_HOSTS}"', found.group(0))

    def test_it_is_made_empty_once_and_then_left_alone(self) -> None:
        found = self.BLOCK.search((INSTALL / "03-manager-keys").read_text())
        assert found
        with tempfile.TemporaryDirectory() as raw:
            known = Path(raw) / "ssh" / "known_hosts"
            block = (
                found.group(0)
                .replace("/root/.ssh/known_hosts", str(known))
                .replace("install -o root -g root -m 644", "install -m 644")
            )
            script = f'set -Eeuo pipefail; source "{LIB}"; chown() {{ :; }}\n{block}'
            first = bash(script)
            known.write_text("node-a ssh-ed25519 AAAAexample\n")
            again = bash(script)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertIn("created", first.stdout)
            self.assertIn("ok", again.stdout)
            self.assertEqual(known.read_text(), "node-a ssh-ed25519 AAAAexample\n")


class Step1GivesARepositoryItsIdentity(unittest.TestCase):
    def test_the_same_identity_create_cluster_keeps(self) -> None:
        from haprion.cluster_definition import REPOSITORY_IDENTITY  # noqa: PLC0415

        text = (INSTALL / "01-manager-prepare").read_text()
        for setting, value in REPOSITORY_IDENTITY:
            self.assertIn(f'git -C "$bare" config {setting} {value}', text)


class TheExampleShowsTheDefaults(unittest.TestCase):
    """answers.example.env says its values are the defaults; this keeps it true."""

    # Read on a node by 04-node-prepare, which has no defaults (defaults.sh).
    NODE_SIDE = {"NODE_CONFIG_PULL_KEY", "NODE_CERT_PULL_KEY"}

    def test_every_value_it_sets_is_the_default(self) -> None:
        example = {
            name: value.strip('"')
            for name, value in re.findall(
                r"^([A-Z_]+)=(.*)$", (INSTALL / "answers.example.env").read_text(), re.MULTILINE
            )
        }
        manager = sorted(set(example) - self.NODE_SIDE)
        self.assertEqual(answers_value(manager), {name: example[name] for name in manager})

    def test_every_default_is_in_the_example(self) -> None:
        defaults = set(re.findall(r"\$\{([A-Z_]+)=", (INSTALL / "defaults.sh").read_text()))
        text = (INSTALL / "answers.example.env").read_text()
        missing = {name for name in defaults if not re.search(rf"^#?{name}=", text, re.MULTILINE)}
        self.assertEqual(missing, set())


class WhatStep2WritesTheEngineReads(unittest.TestCase):
    """The text step 2 renders, loaded by the readers the commands use."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.keys = self.root / "dns-profile-keys"
        self.keys.mkdir()
        self.answers = self.root / "answers.env"
        self.answers.write_text(
            "\n".join(
                f"{name}={self.root}/{path}"
                for name, path in (
                    ("CONFIG_ROOT", "config"),
                    ("PUBLISH_ROOT", "published"),
                    ("VALIDATION_ROOT", "validation"),
                    ("CLUSTER_FILE", "registry/clusters.yaml"),
                    ("CERTIFICATE_REGISTRY", "registry/certificates.yaml"),
                    ("BACKUP_ROOT", "backups"),
                    ("CERTIFICATE_ROOT", "certdist/haproxy"),
                    ("RECEIVER_ROOT", "certdist/receivers"),
                )
            )
            + "\n"
        )
        (self.root / "registry").mkdir()

    def render(self, extra: str = "") -> Path:
        if extra:
            with self.answers.open("a") as handle:
                handle.write(extra)
        env = dict(os.environ, DNS_PROFILE_KEYS=str(self.keys))
        for function, target in (
            ("render_policy", self.root / "runtime-policy.yaml"),
            ("render_cluster_file", self.root / "registry/clusters.yaml"),
            ("render_certificate_registry", self.root / "registry/certificates.yaml"),
        ):
            done = bash(
                f'set -Eeuo pipefail; source "$1"; load_answers "$2"; {function}',
                str(LIB),
                str(self.answers),
                env=env,
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            target.write_text(done.stdout)
        return self.root / "runtime-policy.yaml"

    def test_a_new_installation_has_no_cluster_and_names_the_registry(self) -> None:
        policy = load_policy(self.render(), require_secure=False)
        self.assertEqual(policy.certificate_registry, self.root / "registry/certificates.yaml")
        self.assertEqual(policy.receiver_root, self.root / "certdist/receivers")
        assert policy.acme is not None
        # Resolved by the reader, as every root is: on a machine with certbot installed
        # `current` is a link to the release.
        self.assertEqual(
            policy.acme.certbot, Path("/opt/haprion-certbot/current/venv/bin/certbot").resolve()
        )
        self.assertIsNone(policy.acme.dns_profiles)
        self.assertEqual(load_runtime_config(policy, require_secure=False).clusters, {})
        assert policy.certificate_registry is not None
        registry = load_registry(policy.certificate_registry, require_secure=False)
        self.assertEqual((registry.receivers, registry.certificates), ({}, {}))

    def test_the_keys_step_15_made_are_named_for_the_dns_profiles(self) -> None:
        for name in ("b2.key", "a1.key"):
            (self.keys / name).write_text("key\n")
        policy = load_policy(self.render(), require_secure=False)
        assert policy.acme is not None and policy.acme.dns_profiles is not None
        self.assertEqual(
            policy.acme.dns_profiles.private_keys, (self.keys / "a1.key", self.keys / "b2.key")
        )

    def test_clusters_named_in_an_answers_file_still_load(self) -> None:
        policy = load_policy(
            self.render(
                'CLUSTERS="alpha"\nNODES_alpha="node-a:node-a.example.com"\nNODE_PATH_alpha=a\n'
                "VIP_alpha=192.0.2.10\n"
            ),
            require_secure=False,
        )
        runtime = load_runtime_config(policy, require_secure=False)
        self.assertEqual(list(runtime.clusters), ["alpha"])
        self.assertEqual([node.name for node in runtime.cluster("alpha").nodes], ["node-a"])

    def listed(self, policy: Path) -> tuple[int, str]:
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            code = cluster_config_main(["--list"], policy_path=policy, require_secure=False)
        return code, printed.getvalue()

    def test_the_cluster_list_command_names_none_on_a_new_installation(self) -> None:
        self.assertEqual(self.listed(self.render()), (0, ""))

    def test_the_cluster_list_command_names_the_clusters_there_are(self) -> None:
        policy = self.render(
            'CLUSTERS="alpha beta"\nNODES_alpha="node-a:node-a.example.com"\nNODE_PATH_alpha=a\n'
            'NODES_beta="node-b:node-b.example.com"\nNODE_PATH_beta=b\n'
            "VIP_alpha=192.0.2.10\nVIP_beta=198.51.100.10\n"
        )
        self.assertEqual(self.listed(policy), (0, "alpha\nbeta\n"))

    def test_the_cluster_list_command_takes_no_field(self) -> None:
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            cluster_config_main(["--list", "--field", "nodes"], policy_path=self.render())


class TheEditingPolicyWithNoCluster(unittest.TestCase):
    def render(self, *paths: str) -> str:
        done = bash('source "$1"; shift; render_edit_policy "$@"', str(LIB), "admin", *paths)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def visudo(self, text: str) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile("w", suffix=".sudoers") as handle:
            handle.write(text)
            handle.flush()
            return subprocess.run(  # noqa: S603 - the system's visudo, a fixed check
                ["/usr/sbin/visudo", "-cqf", handle.name],
                capture_output=True,
                text=True,
                check=False,
            )

    @unittest.skipUnless(Path("/usr/sbin/visudo").exists(), "visudo is not installed")
    def test_names_the_editors_only_and_parses(self) -> None:
        text = self.render()
        self.assertNotIn("Cmnd_Alias", text)
        self.assertEqual(self.visudo(text).returncode, 0)

    @unittest.skipUnless(Path("/usr/sbin/visudo").exists(), "visudo is not installed")
    def test_the_first_cluster_adds_the_rule_the_way_step_2_would_write_it(self) -> None:
        paths = ("/srv/c/alpha/core/haproxy.cfg", "/srv/c/alpha/manual/reservations.yaml")
        added = sudoers_with(self.render(), add=paths)
        self.assertEqual(added, self.render(*paths))
        self.assertEqual(self.visudo(added).returncode, 0)


class ErrorsInWords(unittest.TestCase):
    """Provoked, and read as the operator reads them (B302)."""

    def test_a_cluster_without_its_vip_is_refused_in_words(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            answers = Path(raw) / "answers.env"
            answers.write_text(
                'CLUSTERS="alpha"\nNODES_alpha="node-a:node-a.example.com"\nNODE_PATH_alpha=a\n'
            )
            done = bash(
                'set -Eeuo pipefail; source "$1"; load_answers "$2"; clusters="$(render_cluster_file)"',
                str(LIB),
                str(answers),
            )
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(
            "ERROR: VIP_alpha is not set; every cluster needs its virtual address", done.stderr
        )

    def test_fail_says_what_why_and_what_to_do(self) -> None:
        done = bash(
            'source "$1"; fail "the thing broke" "it needs a part" "add the part"', str(LIB)
        )
        self.assertEqual(done.returncode, 1)
        self.assertEqual(
            done.stderr.splitlines(),
            ["ERROR: the thing broke", "WHY: it needs a part", "TODO: add the part"],
        )

    def test_a_command_without_words_of_its_own_is_named_with_its_step(self) -> None:
        done = bash(
            'set -Eeuo pipefail; source "$1"; step "Copying"; ls /nonexistent-haprion', str(LIB)
        )
        self.assertNotEqual(done.returncode, 0)
        lines = [line for line in done.stderr.splitlines() if line.startswith("ERROR: ")]
        self.assertEqual(
            lines,
            [
                "ERROR: the command 'ls /nonexistent-haprion' stopped with exit code 2 "
                "while doing: Copying"
            ],
        )

    def test_a_failure_inside_a_substitution_is_reported_once_by_the_script(self) -> None:
        done = bash('set -Eeuo pipefail; source "$1"; value="$(ls /nonexistent-haprion)"', str(LIB))
        self.assertEqual(done.stderr.count("ERROR: "), 1, done.stderr)

    def test_a_condition_that_is_false_is_no_error(self) -> None:
        done = bash(
            'set -Eeuo pipefail; source "$1"; if false; then :; fi; false || true', str(LIB)
        )
        self.assertEqual((done.returncode, done.stderr), (0, ""))


class TheSetupReport(unittest.TestCase):
    def report(self, output: str, advice: str = "read the log") -> str:
        with tempfile.NamedTemporaryFile("w") as handle:
            handle.write(output)
            handle.flush()
            done = bash(
                'source "$1"; setup_report_failure 3 9 "the database" "$2" "$3" /var/log/haprion/setup.log',
                str(SETUP),
                advice,
                handle.name,
            )
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def test_a_die_is_what_went_wrong_and_the_steps_advice_what_to_do(self) -> None:
        shown = self.report(
            "== Database\n[10:00:00]   ok       role\n"
            "ERROR: haprion_web cannot connect\n  peer authentication refused it\n",
            advice="check that PostgreSQL is running: systemctl status postgresql",
        )
        self.assertIn("haprion-setup stopped at step 3 of 9: the database.", shown)
        self.assertIn("What went wrong: haprion_web cannot connect\n", shown)
        self.assertIn("peer authentication refused it", shown)
        self.assertIn("What to do:      check that PostgreSQL is running", shown)
        self.assertIn("Everything the step said is in /var/log/haprion/setup.log", shown)
        self.assertNotIn("exit code", shown)

    def test_a_fail_brings_its_own_why_and_what_to_do(self) -> None:
        shown = self.report("ERROR: no name\nWHY: nginx needs it\nTODO: set SERVER_NAME\n")
        self.assertIn("Why:             nginx needs it", shown)
        self.assertIn("What to do:      set SERVER_NAME", shown)
        self.assertNotIn("read the log", shown)

    def test_a_die_in_a_substitution_is_shown_not_the_trap_after_it(self) -> None:
        shown = self.report(
            "ERROR: NODES_alpha is not set\n"
            "ERROR: the command 'clusters_yaml=\"$(render_cluster_file)\"' stopped with exit code 1\n"
            "TODO: the lines above it in this output are that command's own words\n"
        )
        self.assertIn("What went wrong: NODES_alpha is not set", shown)
        self.assertNotIn("render_cluster_file", shown)

    def test_a_bare_command_failure_shows_what_it_printed_as_why(self) -> None:
        shown = self.report(
            "nginx: [emerg] bind() to 0.0.0.0:443 failed (98: Address already in use)\n"
            "ERROR: the command 'nginx -t' stopped with exit code 1 while doing: Starting\n"
            "TODO: the lines above it in this output are that command's own words\n",
            advice="see why nginx stopped: nginx -t",
        )
        self.assertIn("Why:             nginx: [emerg] bind() to 0.0.0.0:443 failed", shown)
        self.assertIn("What to do:      see why nginx stopped: nginx -t", shown)

    def test_a_check_in_its_own_form_shows_its_verdict_and_its_failures(self) -> None:
        shown = self.report(
            "== Releases\n  PASS  UI release        r1\n"
            "  FAIL  worker sudoers    cannot read /etc/sudoers.d/haprion-worker\n"
            "  FAIL  node socket       /run/haprion/cluster-node.sock: No such file\n\n"
            "INCOMPATIBLE: 2 check(s) failed\n"
        )
        self.assertIn("What went wrong: INCOMPATIBLE: 2 check(s) failed", shown)
        self.assertIn("Why:             FAIL  worker sudoers    cannot read", shown)
        self.assertIn("FAIL  node socket", shown)
        self.assertNotIn("PASS", shown)

    def test_a_step_that_said_nothing_says_so(self) -> None:
        self.assertIn("What went wrong: the step stopped without saying why", self.report("\n"))


class TheChecksBeforeAnythingChanges(unittest.TestCase):
    """Each check run the way haprion-setup runs it: strict mode, after lib.sh.

    Run without it at first, the port check passed here and stopped the setup on
    the first real machine (26-10-13): nothing listening made grep fail under
    pipefail.
    """

    def ports(self, listening: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as raw:
            ss = Path(raw) / "ss"
            ss.write_text(f"#!/bin/sh\nprintf '%s' '{listening}'\n")
            ss.chmod(0o755)
            return bash(
                STRICT + 'PATH="$2:$PATH"; setup_check_ports; setup_report_problems',
                str(SETUP),
                raw,
            )

    def test_free_ports_pass(self) -> None:
        done = self.ports("")
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "", ""))

    def test_nginx_on_the_ports_passes(self) -> None:
        done = self.ports('LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=7,fd=6))\n')
        self.assertEqual((done.returncode, done.stdout), (0, ""))

    def test_another_listener_is_named(self) -> None:
        done = self.ports('LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("apache2",pid=7,fd=4))\n')
        self.assertEqual(done.returncode, 1)
        self.assertIn("port 80 is already in use by apache2", done.stdout)

    def test_an_unsynchronised_clock_is_a_note_not_a_problem(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stub = Path(raw) / "timedatectl"
            stub.write_text("#!/bin/sh\necho no\n")
            stub.chmod(0o755)
            done = bash(
                STRICT + 'PATH="$2:$PATH"; setup_check_clock; setup_report_problems; '
                'printf "%s\\n" "${SETUP_NOTES[@]}"',
                str(SETUP),
                raw,
            )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("the clock is not synchronised", done.stdout)

    def test_every_missing_command_is_named_with_its_package(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            done = bash(
                STRICT + 'PATH="$2"; setup_check_commands; setup_report_problems',
                str(SETUP),
                raw,
            )
        self.assertEqual(done.returncode, 1)
        self.assertIn("things need fixing first", done.stdout)
        self.assertIn("What is wrong:  the command nginx is not installed", done.stdout)
        self.assertIn("What to do:     install it: apt install rsync", done.stdout)
        self.assertIn("apt install postgresql-client", done.stdout)

    def test_another_distribution_is_refused_by_name(self) -> None:
        with tempfile.NamedTemporaryFile("w") as release:
            release.write("ID=fedora\nVERSION_CODENAME=\n")
            release.flush()
            done = bash(
                STRICT + 'setup_check_distribution "$2"; setup_report_problems',
                str(SETUP),
                release.name,
            )
        self.assertIn("one thing needs fixing first", done.stdout)
        self.assertIn("this machine runs fedora", done.stdout)

    def test_the_supported_ones_pass(self) -> None:
        for content in (
            "ID=debian\nVERSION_CODENAME=trixie\n",
            "ID=ubuntu\nVERSION_CODENAME=resolute\n",
        ):
            with tempfile.NamedTemporaryFile("w") as release:
                release.write(content)
                release.flush()
                done = bash(
                    STRICT + 'setup_check_distribution "$2"; setup_report_problems',
                    str(SETUP),
                    release.name,
                )
            self.assertEqual((done.returncode, done.stdout), (0, ""), content)

    def test_a_name_that_does_not_resolve_is_named(self) -> None:
        done = bash(
            STRICT + "setup_check_server_name mgr.invalid; setup_report_problems", str(SETUP)
        )
        self.assertIn("the name mgr.invalid does not resolve", done.stdout)
        self.assertIn("SERVER_NAME=<name>", done.stdout)

    def test_not_root_changes_nothing_and_says_how(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the check is for an account that is not root")
        done = subprocess.run(  # noqa: S603 - the repository's own command, as an operator runs it
            [str(DRIVER)], capture_output=True, text=True, check=False
        )
        self.assertEqual(done.returncode, 1)
        self.assertIn("haprion-setup changed nothing", done.stdout)
        self.assertIn("run it with sudo: sudo haprion-setup", done.stdout)


class TheFirstAccountComesLast(unittest.TestCase):
    """The password was asked for in the middle of the run and the closing
    words asked for the account again (26-10-14): setup asks once, last."""

    def closing_words(self, accounts: str) -> str:
        done = bash(
            STRICT + 'setup_closing_words "$2" "$3"', str(SETUP), "mgr.example.com", accounts
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def test_with_an_account_the_closing_words_only_say_sign_in(self) -> None:
        shown = self.closing_words("1")
        self.assertIn("https://mgr.example.com/", shown)
        self.assertIn("Sign in, and create the first cluster", shown)
        self.assertNotIn("init-admin", shown)

    def test_without_an_account_or_a_count_they_say_how_to_make_one(self) -> None:
        for accounts in ("0", ""):
            with self.subTest(accounts=accounts):
                self.assertIn("sudo haprion-user init-admin", self.closing_words(accounts))

    def test_setup_activates_without_asking_and_asks_after_the_last_step(self) -> None:
        driver = DRIVER.read_text()
        self.assertIn("./platform/install-ui-release --no-first-account ${release_id}", driver)
        self.assertGreater(driver.index("haprion-user init-admin"), driver.index("for entry in"))
        installer = (INSTALL / "platform" / "install-ui-release").read_text()
        self.assertIn("--no-first-account) first_account=0 ;;", installer)
        self.assertIn(
            "if (( first_account )); then\n    /usr/sbin/haprion-user init-admin", installer
        )


class TheKeyStepsNameTheirKeyForTheWeb(unittest.TestCase):
    """Step 17 left `[oidc] public_key` for the operator to add by hand and the
    web to be restarted (26-10-14); step 15 adds its own. Both add theirs."""

    def test_each_adds_its_table_when_ui_toml_names_none(self) -> None:
        for step, table in (("15-platform-dns-keys", "dns_profiles"), ("17-platform-oidc", "oidc")):
            with self.subTest(step=step):
                text = (INSTALL / "platform" / step).read_text()
                self.assertIn('install_file "$UI_CONFIG" "root:${PLATFORM_GROUP}" 640', text)
                self.assertIn(f"\n[{table}]\npublic_key = ", text)
                self.assertIn('systemctl restart "$WEB_UNIT"', text)
                self.assertNotIn("give the web interface the public key", text)


class TheSetupRunsEveryStep(unittest.TestCase):
    """A numbered step added later is in haprion-setup, or named here with why it is not."""

    LEFT_OUT = {
        "04-node-prepare": "runs on a node, not the manager",
        "05-verify": "runs as an operator, not root; check-compatibility is the setup's own check",
        "platform/16-platform-scep": "needs the operator's SCEP bundle and its digest",
    }

    def steps(self) -> list[str]:
        return re.findall(r'^\s+"\./([\w/.-]+)', DRIVER.read_text(), re.MULTILINE)

    def test_each_numbered_step_is_run_or_named_here(self) -> None:
        numbered = {path.name for path in INSTALL.glob("[0-9][0-9]-*")} | {
            f"platform/{path.name}" for path in (INSTALL / "platform").glob("[0-9][0-9]-*")
        }
        run = set(self.steps())
        self.assertEqual(numbered - run, set(self.LEFT_OUT))
        self.assertEqual(
            run - numbered,
            {"platform/migrate", "platform/install-ui-release", "platform/check-compatibility"},
        )

    def test_the_order_puts_what_a_step_reads_before_it(self) -> None:
        order = self.steps()
        for before, after in (
            ("01-manager-prepare", "platform/01-platform-prepare"),
            # step 2 names the DNS keys in the policy it writes
            ("platform/15-platform-dns-keys", "02-manager-config"),
            ("02-manager-config", "platform/02-platform-database"),
            ("platform/migrate", "platform/install-ui-release"),
            ("platform/07-platform-services", "platform/14-platform-certbot"),
        ):
            with self.subTest(before=before, after=after):
                self.assertLess(order.index(before), order.index(after))
        self.assertEqual(order[-1], "platform/check-compatibility")

    def test_the_check_before_the_first_activation_leaves_step_07_to_the_last(self) -> None:
        text = DRIVER.read_text()
        self.assertIn(
            '"./platform/check-compatibility --release ${release_id}${first_install}"', text
        )
        self.assertIn('[[ "$activation" == first ]] && first_install=" --first-install"', text)


class ARerunAfterActivationSkipsTheCheckBeforeIt(unittest.TestCase):
    """A run that stopped after the activation and before step 07 was rerun
    and failed the check before activation on the parts step 07 installs
    (26-10-15, the install test): once current is the release, that check is
    left to the one after the last step."""

    def activation(self, root: Path) -> str:
        done = bash(STRICT + 'setup_activation "$2" "$3"', str(SETUP), str(root), "0.8.0-abc")
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.strip()

    def test_each_state_of_current(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "releases" / "0.8.0-abc").mkdir(parents=True)
            (root / "releases" / "0.8.0-old").mkdir()
            self.assertEqual(self.activation(root), "first")
            (root / "current").symlink_to("releases/0.8.0-old")
            self.assertEqual(self.activation(root), "other")
            (root / "current").unlink()
            (root / "current").symlink_to("releases/0.8.0-abc")
            self.assertEqual(self.activation(root), "done")

    def test_the_driver_adds_the_check_and_the_activation_only_before_it(self) -> None:
        text = DRIVER.read_text()
        block = text[text.index('if [[ "$activation" != "done" ]]; then') :]
        block = block[: block.index("\nfi\n")]
        self.assertIn("./platform/check-compatibility --release", block)
        self.assertIn("./platform/install-ui-release --no-first-account", block)


class WhatLibShReadsShipsWithIt(unittest.TestCase):
    """Every file lib.sh sources is in each package that carries lib.sh.

    defaults.sh was not, at first (B302): every platform step and the node's
    04-node-prepare would have stopped on a missing file.
    """

    def sourced(self) -> set[str]:
        return set(
            re.findall(
                r'^source "\$\(dirname "\$\{BASH_SOURCE\[0\]\}"\)/([\w.]+)"',
                LIB.read_text(),
                re.MULTILINE,
            )
        )

    def test_lib_sh_reads_the_accounts_and_the_defaults(self) -> None:
        self.assertEqual(self.sourced(), {"accounts.sh", "defaults.sh"})

    def test_the_node_package_carries_them(self) -> None:
        from haprion import node_package

        shipped = {source for source, _ in node_package.CONTENTS.values()}
        self.assertEqual({f"install/{name}" for name in self.sourced()} - shipped, set())

    def test_the_ui_package_carries_them(self) -> None:
        tool = (INSTALL.parent / "tools" / "build-ui-package.py").read_text()
        shared = re.search(r"^SHARED = \((.*)\)$", tool, re.MULTILINE)
        assert shared is not None
        listed = set(re.findall(r'"([^"]+)"', shared.group(1)))
        self.assertEqual({f"install/{name}" for name in self.sourced()} - listed, set())


class TheWorkersSandboxOpensWhatExists(unittest.TestCase):
    """Every fixed path the worker unit opens is made by step 07, before the unit.

    systemd refuses to start a unit whose ReadWritePaths names a missing path;
    the first new machine stopped on /etc/letsencrypt (26-10-13).
    """

    # Made elsewhere, before step 07 can run.
    ELSEWHERE = {"/run/haprion": "install/tmpfiles/haprion.conf, applied by step 1"}

    def test_each_one_is_created_by_step_07(self) -> None:
        unit = (INSTALL / "platform/examples/haprion-worker.service.example").read_text()
        line = re.search(r"^ReadWritePaths=(.*)$", unit, re.MULTILINE)
        assert line is not None
        fixed = [path for path in line.group(1).split() if not path.startswith("@")]
        step = (INSTALL / "platform/07-platform-services").read_text()
        made = set(re.findall(r"^ensure_dir (\S+) ", step, re.MULTILINE))
        loop = re.search(r"^for path in ((?:/[^\s:]+:\d+ ?)+); do", step, re.MULTILINE)
        assert loop is not None
        made |= {entry.split(":")[0] for entry in loop.group(1).split()}
        self.assertEqual(set(fixed) - made, set(self.ELSEWHERE))


class AUnitThatDoesNotStart(unittest.TestCase):
    """Reported with the journal's reason, not systemctl's 'control process exited'."""

    JOURNAL = (
        "Starting haprion-worker.service - Haprion job worker...\n"
        "haprion-worker.service: Failed to set up mount namespacing: /etc/letsencrypt: No such file or directory\n"
        "haprion-worker.service: Failed at step NAMESPACE spawning /opt/x/haprion-worker: No such file or directory\n"
        "haprion-worker.service: Main process exited, code=exited, status=226/NAMESPACE\n"
        "haprion-worker.service: Failed with result 'exit-code'.\n"
        "Failed to start haprion-worker.service - Haprion job worker.\n"
        "haprion-worker.service: Scheduled restart job, restart counter is at 6.\n"
    )

    def test_the_lines_keep_the_order_they_were_last_said_in(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            stub = Path(raw) / "journalctl"
            stub.write_text("#!/bin/sh\nprintf 'one\\ntwo\\nthree\\none\\nfour\\n'\n")
            stub.chmod(0o755)
            done = bash('source "$1"; PATH="$2:$PATH"; unit_failure x.service', str(LIB), raw)
        self.assertEqual(done.stdout.splitlines(), ["three", "one", "four"])

    def test_the_reason_is_the_units_own_words(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            for name, body in (
                ("systemctl", "#!/bin/sh\nexit 1\n"),
                ("journalctl", '#!/bin/sh\ncat "$JOURNAL"\n'),
            ):
                stub = Path(raw) / name
                stub.write_text(body)
                stub.chmod(0o755)
            journal = Path(raw) / "journal"
            journal.write_text(self.JOURNAL * 2)
            done = bash(
                'set -Eeuo pipefail; source "$1"; PATH="$2:$PATH"; restart_units haprion-worker.service',
                str(LIB),
                raw,
                env=dict(os.environ, JOURNAL=str(journal)),
            )
        self.assertEqual(done.returncode, 1)
        self.assertEqual(
            done.stderr.splitlines(),
            [
                "ERROR: haprion-worker.service did not start",
                "WHY: haprion-worker.service: Failed to set up mount namespacing: "
                "/etc/letsencrypt: No such file or directory",
                "WHY: haprion-worker.service: Failed at step NAMESPACE spawning "
                "/opt/x/haprion-worker: No such file or directory",
                "TODO: correct what the lines above name, then run this step again",
                "TODO: the unit's whole journal: journalctl -u haprion-worker.service -n 50",
            ],
        )


class NoClusterYetForTheCollector(unittest.TestCase):
    def test_a_collector_with_no_node_loads(self) -> None:
        document = {
            "schema_version": 2,
            "user": "_haprion-logread",
            "key": "/etc/haprion/traffic-collector/id_ed25519",
            "known_hosts": "/etc/haprion/traffic-collector/known_hosts",
            "mirror": "/var/lib/haprion-ui/logs/mirror",
            "staging": "/var/lib/haprion-ui/logs/staging",
            "database": "haprion",
            "database_socket": "/var/run/postgresql",
            "nodes": [],
        }
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "collector.json"
            path.write_text(json.dumps(document))
            config = traffic_collector.load_config(path, require_secure=False)
        self.assertEqual(config.nodes, ())


if __name__ == "__main__":
    unittest.main()
