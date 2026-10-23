"""The node's keepalived step, exercised as the shell it actually is.

The function is extracted from `install/node/haprion-pull-deploy` verbatim and
run with `keepalived` and `systemctl` replaced by recording stubs. That proves
the branches - when it does nothing, when it reloads, and what it leaves behind
when the configuration test fails - without a node.

It deliberately does not prove the wiring: that keepalived reads an included
file, and that the reload does not move the address, are facts about a real
node measured on one (2026-09-01, and again per cluster during rollout). This
is about the decisions the script makes around them, which is the half that can
silently take a wrong branch.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-pull-deploy"
#
# From the include tests through `sync_keepalived`: the shared step and both
# files' wrappers (B256), as one piece of the script.
#
FUNCTION = re.compile(
    r"^keepalived_includes_anywhere\(\) \{.*?^sync_keepalived\(\) \{.*?^\}$",
    re.DOTALL | re.MULTILINE,
)

STUB = """#!/bin/sh
echo "$(basename "$0") $*" >> "$RECORD"
exit "${%s:-0}"
"""

#
# `install -o root -g root` is right on a node, where this runs as root, and
# impossible in a test that does not. Ownership is not what these cases are
# about - they are about which branch is taken - so the flags are dropped and
# the copy is real.
#
INSTALL_STUB = """#!/bin/sh
set -eu
kept=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o|-g) shift 2 ;;
        *) kept="${kept} \"$1\""; shift ;;
    esac
done
eval exec /usr/bin/install ${kept}
"""


class Step(unittest.TestCase):
    """The extracted step in a scratch root, with recording stubs. No tests of its own."""

    def setUp(self) -> None:
        found = FUNCTION.search(SCRIPT.read_text())
        assert found, "the function is no longer where the test extracts it from"
        self.function = found.group(0)
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / "bin").mkdir()
        for name, variable in (("keepalived", "TEST_EXIT"), ("systemctl", "RELOAD_EXIT")):
            stub = self.root / "bin" / name
            stub.write_text(STUB % variable)
            stub.chmod(0o755)
        #
        # `is-active` answers on its own: whether keepalived runs is a separate
        # fact from whether its reload works.
        #
        (self.root / "bin" / "systemctl").write_text(
            '#!/bin/sh\necho "systemctl $*" >> "$RECORD"\n'
            '[ "$1" = is-active ] && exit "${ACTIVE_EXIT:-0}"\n'
            'exit "${RELOAD_EXIT:-0}"\n'
        )
        installer = self.root / "bin" / "install"
        installer.write_text(INSTALL_STUB)
        installer.chmod(0o755)
        (self.root / "release" / "keepalived").mkdir(parents=True)
        (self.root / "etc").mkdir()
        self.published = self.root / "release" / "keepalived" / "addresses.conf"
        self.conf = self.root / "etc" / "keepalived.conf"
        self.installed = self.root / "etc" / "addresses.conf"
        self.record = self.root / "record"

    def run_step(
        self, step: str = "sync_keepalived_addresses", **environment: str
    ) -> tuple[int, str]:
        script = self.root / "step.sh"
        script.write_text(
            "set -Eeuo pipefail\n"
            'log() { echo "$*"; }\n'
            f'CURRENT="{self.root / "release"}"\n'
            f'KEEPALIVED_CONF="{self.conf}"\n'
            f'KEEPALIVED_ADDRESSES="{self.root / "etc" / "addresses.conf"}"\n'
            f'KEEPALIVED_IPVS="{self.root / "etc" / "ipvs.conf"}"\n'
            f"{self.function}\n"
            f"{step}\n"
        )
        finished = subprocess.run(
            ["/bin/bash", str(script)],
            capture_output=True,
            text=True,
            env={
                "PATH": f"{self.root / 'bin'}:/usr/bin:/bin",
                "RECORD": str(self.record),
                **environment,
            },
            check=False,
        )
        return finished.returncode, finished.stdout

    def calls(self) -> str:
        return self.record.read_text() if self.record.exists() else ""


class TheKeepalivedStep(Step):
    def test_a_release_without_an_address_list_is_not_an_error(self) -> None:
        # Every cluster is in this state until its repository has been through
        # a publish that writes one.
        code, _ = self.run_step()

        self.assertEqual(code, 0)
        self.assertFalse(self.installed.exists())
        self.assertEqual(self.calls(), "")

    def test_a_node_without_the_include_line_gets_the_file_and_no_reload(self) -> None:
        #
        # The rollout order rests on this. The include cannot be added before
        # the file exists - keepalived would be pointed at something absent -
        # and the file cannot arrive if installing it required the include. So
        # the deploy delivers it inert, and a person adds the include after.
        #
        self.published.write_text("    192.0.2.20\n")
        self.conf.write_text("vrrp_instance alpha {\n}\n")

        code, output = self.run_step()

        self.assertEqual(code, 0)
        self.assertEqual(self.installed.read_text(), "    192.0.2.20\n")
        self.assertEqual(self.calls(), "")
        self.assertIn("NOT in use on this node", output)

    def include(self) -> None:
        self.conf.write_text(f"virtual_ipaddress {{\n    include {self.installed}\n}}\n")

    def test_a_changed_list_is_installed_and_keepalived_reloaded(self) -> None:
        self.published.write_text("    192.0.2.20\n")
        self.include()

        code, _ = self.run_step()

        self.assertEqual(code, 0)
        self.assertEqual(self.installed.read_text(), "    192.0.2.20\n")
        self.assertIn("--config-test", self.calls())
        self.assertIn("systemctl reload keepalived", self.calls())

    def test_an_unchanged_list_reloads_nothing(self) -> None:
        # Most deploys change only HAProxy configuration, and a reload of
        # keepalived on every one of them would be a risk taken for nothing.
        self.published.write_text("    192.0.2.20\n")
        self.installed.write_text("    192.0.2.20\n")
        self.include()

        code, _ = self.run_step()

        self.assertEqual(code, 0)
        self.assertEqual(self.calls(), "")

    def test_a_rejected_list_is_restored_and_never_reloaded(self) -> None:
        #
        # The single most important branch. keepalived skips an address it
        # cannot parse at runtime and carries on, so a reload after a failed
        # test would turn a mistyped address into a VIP that never appears and
        # says nothing about why.
        #
        self.published.write_text("    not-an-address\n")
        self.installed.write_text("    192.0.2.20\n")
        self.include()

        code, output = self.run_step(TEST_EXIT="5")

        self.assertEqual(code, 1)
        self.assertEqual(self.installed.read_text(), "    192.0.2.20\n")
        self.assertNotIn("reload", self.calls())
        self.assertIn("previous address list restored", output)

    def test_a_first_list_that_is_rejected_leaves_nothing_behind(self) -> None:
        # There is no previous file to restore, and leaving the rejected one in
        # place would mean the next unrelated deploy found them equal and
        # skipped the step that would have refused it again.
        self.published.write_text("    not-an-address\n")
        self.include()

        code, _ = self.run_step(TEST_EXIT="5")

        self.assertEqual(code, 1)
        self.assertFalse(self.installed.exists())

    def test_a_failed_reload_is_reported_rather_than_assumed(self) -> None:
        self.published.write_text("    192.0.2.20\n")
        self.installed.write_text("    192.0.2.21\n")
        self.include()

        code, output = self.run_step(RELOAD_EXIT="1")

        self.assertEqual(code, 1)
        self.assertEqual(self.installed.read_text(), "    192.0.2.21\n")
        self.assertIn("keepalived reload failed", output)


class KeepalivedNotRunning(Step):
    """B298: masked on a node restored in test mode, not yet started on a new one."""

    def test_the_list_is_tested_and_installed_and_nothing_is_reloaded(self) -> None:
        published = self.root / "release" / "keepalived" / "addresses.conf"
        published.write_text("    192.0.2.20\n")
        self.installed.write_text("    192.0.2.21\n")
        self.conf.write_text(f"virtual_ipaddress {{\n    include {self.installed}\n}}\n")

        code, output = self.run_step(ACTIVE_EXIT="3")

        self.assertEqual(code, 0, output)
        self.assertEqual(self.installed.read_text(), "    192.0.2.20\n")
        self.assertIn("--config-test", self.calls())
        self.assertNotIn("systemctl reload", self.calls())
        self.assertIn("read when it starts", output)
        self.assertFalse((self.root / "etc" / "addresses.conf.rollback").exists())

    def test_a_rejected_list_is_still_refused(self) -> None:
        published = self.root / "release" / "keepalived" / "addresses.conf"
        published.write_text("    not-an-address\n")
        self.installed.write_text("    192.0.2.21\n")
        self.conf.write_text(f"virtual_ipaddress {{\n    include {self.installed}\n}}\n")

        code, _ = self.run_step(ACTIVE_EXIT="3", TEST_EXIT="5")

        self.assertEqual(code, 1)
        self.assertEqual(self.installed.read_text(), "    192.0.2.21\n")


class TheIpvsFile(Step):
    """The syslog objects' virtual servers (B256): the same step, included at the top level."""

    SERVER = "virtual_server 192.0.2.20 514 {\n}\n"

    def setUp(self) -> None:
        super().setUp()
        self.published = self.root / "release" / "keepalived" / "ipvs.conf"
        self.installed = self.root / "etc" / "ipvs.conf"

    def ipvs(self, **environment: str) -> tuple[int, str]:
        return self.run_step("sync_keepalived_ipvs", **environment)

    def test_a_release_without_the_file_leaves_the_node_alone(self) -> None:
        """A release from before B256: absent means not managed from here."""

        self.installed.write_text(self.SERVER)

        code, _ = self.ipvs()

        self.assertEqual(code, 0)
        self.assertEqual(self.installed.read_text(), self.SERVER)
        self.assertEqual(self.calls(), "")

    def test_included_at_the_top_level_it_is_tested_and_reloaded(self) -> None:
        self.published.write_text(self.SERVER)
        self.conf.write_text(
            "vrrp_instance alpha {\n    virtual_ipaddress {\n    }\n}\n"
            f"include {self.installed}  # syslog objects\n"
        )

        code, output = self.ipvs()

        self.assertEqual(code, 0, output)
        self.assertEqual(self.installed.read_text(), self.SERVER)
        self.assertIn("--config-test", self.calls())
        self.assertIn("systemctl reload keepalived", self.calls())
        self.assertIn("IPVS file active", output)

    EMPTY = "#\n# Generated by Haprion.\n#\n"

    def test_a_file_without_virtual_servers_arrives_inert(self) -> None:
        """How the file reaches a node before a person adds the include."""

        self.published.write_text(self.EMPTY)
        self.conf.write_text("vrrp_instance alpha {\n}\n")

        code, output = self.ipvs()

        self.assertEqual(code, 0, output)
        self.assertEqual(self.installed.read_text(), self.EMPTY)
        self.assertEqual(self.calls(), "")
        self.assertIn("NOT in use on this node", output)

    def test_virtual_servers_keepalived_does_not_read_refuse_the_deploy(self) -> None:
        """Review 26-10-08 F1: forwarded nowhere while the deploy said it succeeded."""

        for conf in (
            "vrrp_instance alpha {\n}\n",
            f"vrrp_instance alpha {{\n    include {self.installed}\n}}\n",
            f"# include {self.installed}\n",
            f"! include {self.installed}\n",
        ):
            with self.subTest(conf=conf):
                self.installed.write_text(self.EMPTY)
                self.published.write_text(self.SERVER)
                self.conf.write_text(conf)

                code, output = self.ipvs()

                self.assertEqual(code, 1)
                self.assertIn("does not include", output)
                self.assertEqual(self.installed.read_text(), self.EMPTY)
        self.assertEqual(self.calls(), "")

    def test_the_deploy_asks_before_it_activates(self) -> None:
        text = SCRIPT.read_text()

        self.assertLess(
            text.index('validate_ipvs_candidate "$VALIDATE" || exit 1'),
            text.index('mv -Tf "$NEW_LINK" "$CURRENT"'),
        )

    def test_a_candidate_with_virtual_servers_is_refused_before_it_is_activated(self) -> None:
        candidate = self.root / "candidate" / "keepalived"
        candidate.mkdir(parents=True)
        (candidate / "ipvs.conf").write_text(self.SERVER)
        self.conf.write_text("vrrp_instance alpha {\n}\n")

        code, output = self.run_step(f'validate_ipvs_candidate "{self.root / "candidate"}"')
        self.assertEqual(code, 1)
        self.assertIn("carries syslog objects", output)

        self.conf.write_text(f"include {self.installed}\n")
        self.assertEqual(
            self.run_step(f'validate_ipvs_candidate "{self.root / "candidate"}"')[0], 0
        )
        (candidate / "ipvs.conf").write_text(self.EMPTY)
        self.conf.write_text("vrrp_instance alpha {\n}\n")
        self.assertEqual(
            self.run_step(f'validate_ipvs_candidate "{self.root / "candidate"}"')[0], 0
        )

    def test_a_rejected_file_is_restored_and_never_reloaded(self) -> None:
        self.published.write_text("virtual_server broken\n")
        self.installed.write_text(self.SERVER)
        self.conf.write_text(f"include {self.installed}\n")

        code, output = self.ipvs(TEST_EXIT="5")

        self.assertEqual(code, 1)
        self.assertEqual(self.installed.read_text(), self.SERVER)
        self.assertNotIn("reload", self.calls())
        self.assertIn("previous IPVS file restored", output)

    def both(self, address: str) -> Path:
        addresses = self.root / "release" / "keepalived" / "addresses.conf"
        addresses.write_text(address)
        self.published.write_text(self.SERVER)
        installed_addresses = self.root / "etc" / "addresses.conf"
        installed_addresses.write_text("    192.0.2.19\n")
        self.installed.write_text("")
        self.conf.write_text(
            "vrrp_instance alpha {\n    virtual_ipaddress {\n"
            f"        include {installed_addresses}\n    }}\n}}\n"
            f"include {self.installed}\n"
        )
        return installed_addresses

    def test_both_files_changed_are_one_test_and_one_reload(self) -> None:
        """R3 (26-10-08): a VIP and the syslog object on it go live together."""

        installed_addresses = self.both("    192.0.2.20\n")

        code, output = self.run_step("sync_keepalived")

        self.assertEqual(code, 0, output)
        self.assertEqual(self.calls().count("--config-test"), 1)
        self.assertEqual(self.calls().count("systemctl reload keepalived"), 1)
        self.assertEqual(installed_addresses.read_text(), "    192.0.2.20\n")
        self.assertEqual(self.installed.read_text(), self.SERVER)
        self.assertIn("address list and IPVS file active", output)

    def test_a_refusal_puts_both_files_back_and_reloads_nothing(self) -> None:
        installed_addresses = self.both("    not-an-address\n")

        code, output = self.run_step("sync_keepalived", TEST_EXIT="5")

        self.assertEqual(code, 1)
        self.assertNotIn("reload", self.calls())
        self.assertEqual(installed_addresses.read_text(), "    192.0.2.19\n")
        self.assertEqual(self.installed.read_text(), "")
        self.assertIn("previous address list restored", output)
        self.assertIn("previous IPVS file restored", output)


class TheProductsKeepalivedConf(Step):
    """B313: the node installs its own `keepalived/node-<name>.conf` from the release."""

    PRODUCT = (
        "# Written by Haprion - a deploy replaces this file.\n"
        "include IPVS\n"
        "vrrp_instance alpha {\n"
        "    interface @INTERFACE@\n"
        "    unicast_src_ip 192.0.2.11\n"
        "    virtual_ipaddress {\n"
        "        include ADDRESSES\n"
        "    }\n"
        "}\n"
    )

    def setUp(self) -> None:
        super().setUp()
        bin_dir = self.root / "bin"
        (bin_dir / "hostname").write_text("#!/bin/sh\necho node-a\n")
        (bin_dir / "hostname").chmod(0o755)
        (bin_dir / "ip").write_text(
            "#!/bin/sh\n"
            "echo '1: lo    inet 127.0.0.1/8 scope host lo'\n"
            "echo '2: ens18    inet 192.0.2.11/24 brd 192.0.2.255 scope global ens18'\n"
        )
        (bin_dir / "ip").chmod(0o755)
        (bin_dir / "systemctl").write_text(
            '#!/bin/sh\necho "systemctl $*" >> "$RECORD"\n'
            '[ "$1" = is-active ] && exit "${ACTIVE_EXIT:-0}"\n'
            '[ "$1" = is-enabled ] && { echo "${ENABLED:-enabled}"; exit 0; }\n'
            'exit "${RELOAD_EXIT:-0}"\n'
        )
        self.node_file = self.root / "release" / "keepalived" / "node-node-a.conf"
        self.node_file.write_text(
            self.PRODUCT.replace("IPVS", str(self.root / "etc" / "ipvs.conf")).replace(
                "ADDRESSES", str(self.installed)
            )
        )
        self.published.write_text("    192.0.2.20\n")

    def test_a_new_node_gets_the_file_its_addresses_and_a_started_keepalived(self) -> None:
        code, output = self.run_step("sync_keepalived", ACTIVE_EXIT="3")

        self.assertEqual(code, 0, output)
        written = self.conf.read_text()
        self.assertTrue(written.startswith("# Written by Haprion - a deploy replaces this file.\n"))
        self.assertIn("interface ens18\n", written)
        self.assertNotIn("@INTERFACE@", written)
        # The list is staged because the file just written includes it.
        self.assertEqual(self.installed.read_text(), "    192.0.2.20\n")
        self.assertEqual(self.calls().count("--config-test"), 1)
        self.assertIn("systemctl start keepalived", self.calls())
        self.assertNotIn("reload", self.calls())

    def test_a_running_keepalived_is_reloaded_when_its_file_changes(self) -> None:
        self.conf.write_text("# Written by Haprion - a deploy replaces this file.\nold\n")

        code, output = self.run_step("sync_keepalived")

        self.assertEqual(code, 0, output)
        self.assertIn("interface ens18", self.conf.read_text())
        self.assertIn("systemctl reload keepalived", self.calls())
        self.assertNotIn("systemctl start", self.calls())

    def test_a_file_a_person_wrote_is_left_alone(self) -> None:
        mine = "vrrp_instance alpha {\n    include ADDRESSES\n}\n".replace(
            "ADDRESSES", str(self.installed)
        )
        self.conf.write_text(mine)

        code, output = self.run_step("sync_keepalived")

        self.assertEqual(code, 0, output)
        self.assertEqual(self.conf.read_text(), mine)
        self.assertIn("written by a person; left as it is", output)

    def test_a_refused_file_is_removed_again_and_nothing_starts(self) -> None:
        code, output = self.run_step("sync_keepalived", ACTIVE_EXIT="3", TEST_EXIT="5")

        self.assertEqual(code, 1)
        self.assertFalse(self.conf.exists())
        self.assertNotIn("systemctl start", self.calls())
        self.assertIn("the published configuration was removed again", output)

    def test_a_masked_keepalived_is_not_started(self) -> None:
        # A node restored in test mode: someone took it out on purpose.
        code, output = self.run_step("sync_keepalived", ACTIVE_EXIT="3", ENABLED="masked")

        self.assertEqual(code, 0, output)
        self.assertTrue(self.conf.exists())
        self.assertNotIn("systemctl start", self.calls())

    def test_no_interface_with_the_node_s_address_is_refused(self) -> None:
        self.node_file.write_text(self.node_file.read_text().replace("192.0.2.11", "192.0.2.99"))

        code, output = self.run_step("sync_keepalived", ACTIVE_EXIT="3")

        self.assertEqual(code, 1)
        self.assertFalse(self.conf.exists())
        self.assertIn("no interface carries this node's address 192.0.2.99", output)

    def test_the_mark_is_the_generator_s(self) -> None:
        from haprion import keepalived_conf

        text = SCRIPT.read_text()
        self.assertIn(f'KEEPALIVED_MARK="{keepalived_conf.MARK}"', text)
        self.assertIn(
            f'KEEPALIVED_INTERFACE_FROM_NODE="{keepalived_conf.INTERFACE_FROM_NODE}"', text
        )
        self.assertIn('keepalived/node-$(hostname).conf"', text)
        self.assertEqual(keepalived_conf.file_name("x"), "node-x.conf")


class OneReadingOfTheTopLevelInclude(unittest.TestCase):
    """`04-node-prepare` warns with the deploy's own awk program, not a second reading of it."""

    PROGRAM = re.compile(r"awk -v wanted=\"\$\w+\" '(.*?)'", re.DOTALL)

    def program(self, path: Path) -> str:
        found = self.PROGRAM.findall(path.read_text())
        self.assertEqual(len(found), 1, path)
        return " ".join(found[0].split())

    def test_the_two_are_the_same(self) -> None:
        prepare = SCRIPT.parents[1] / "04-node-prepare"

        self.assertEqual(self.program(prepare), self.program(SCRIPT))
