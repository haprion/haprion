from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, ClassVar
from unittest import mock

from haproxy_mgmt import restore_agent
from haproxy_mgmt.restore_agent import Failed, Host

RUN = "run-0123456789"
BUNDLE_ROOT = "haproxy-manager-node-0123456789ab"


def bundle_bytes() -> bytes:
    """A node bundle's shape: one root, install/04-node-prepare inside it."""

    raw = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as packed,
        tarfile.open(fileobj=packed, mode="w") as archive,
    ):
        for name, text in (
            (f"{BUNDLE_ROOT}/install/04-node-prepare", "#!/bin/bash\n"),
            (f"{BUNDLE_ROOT}/install/lib.sh", "# library\n"),
        ):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(text), 0o755
            archive.addfile(info, io.BytesIO(text.encode()))
    return raw.getvalue()


BUNDLE = bundle_bytes()


class FakeHost(Host):
    """A directory standing in for the target, and a record of every command."""

    def __init__(self, root: Path) -> None:
        super().__init__(str(root))
        self.commands: list[list[str]] = []
        self.owners: dict[str, tuple[int, int]] = {}
        self.active: dict[str, str] = {}
        self.fail: set[str] = set()
        self.preinstalled: set[str] = set()
        # What the bundle's 04-node-prepare prints, and node.conf as it renders it.
        self.prepare_stderr = ""
        # Whether starting keepalived writes its state file, as the notify script does.
        self.notifies = True
        self.rendered_node_conf: str | None = None
        for name, text in {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"
            "syslog:x:104:110::/nonexistent:/usr/sbin/nologin\n"
            "operator:x:1000:1000:Operator:/home/operator:/bin/bash\n",
            "/etc/group": "root:x:0:\nsudo:x:27:\nsyslog:x:110:\noperator:x:1000:\n",
            "/etc/shadow": "root:*:1::::::\noperator:$y$existing:1::::::\n",
            "/etc/os-release": 'ID=ubuntu\nVERSION_ID="26.04"\n',
            "/etc/hostname": "temp\n",
            # Ubuntu's rsyslog drops to `syslog`, as the node's does.
            "/etc/rsyslog.conf": "$PrivDropToUser syslog\n$PrivDropToGroup syslog\n",
        }.items():
            path = self.path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        for directory in (
            "/etc/netplan",
            "/etc/sudoers.d",
            "/etc/apt/sources.list.d",
            "/root/.ssh",
        ):
            self.path(directory).mkdir(parents=True, exist_ok=True)
        self.path("/etc/netplan/50-cloud-init.yaml").write_text("dhcp\n")
        self.path("/etc/sudoers.d/90-cloud-init-users").write_text(
            "ubuntu ALL=(ALL) NOPASSWD:ALL\n"
        )
        self.path("/etc/apt/sources.list.d/ubuntu.sources").write_text("image\n")
        self.path("/root/.ssh/authorized_keys").write_text("one-time key\n")
        self.path("/usr/sbin").mkdir(parents=True)
        self.path("/etc/ssh").mkdir(parents=True)
        self.path("/etc/ssh/ssh_host_ed25519_key.pub").write_text("ssh-ed25519 AAAA temp\n")
        self.path("/etc/haproxy").mkdir(parents=True)
        self.path("/etc/haproxy/haproxy.cfg").write_text("package default\n")

    def chown(self, path: Path, uid: int, gid: int) -> None:
        self.owners["/" + str(path.relative_to(self.root))] = (uid, gid)

    def _free(self, name: str, *, system: bool) -> str:
        """As useradd/groupadd choose: system IDs from 999 down, others from 1000 up."""

        taken = {int(line.split(":")[2]) for line in self.path(name).read_text().splitlines()}
        candidates = range(999, 99, -1) if system else range(1000, 60000)
        return str(next(number for number in candidates if number not in taken))

    def _append(self, name: str, line: str) -> None:
        with self.path(name).open("a") as stream:
            stream.write(line + "\n")

    def run(
        self, argv: list[str], *, stdin: str | None = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(argv)
        out, code = "", 0
        if argv[0] in self.fail:
            code = 1
        elif argv[:2] == ["ip", "-j"]:
            if argv[2:4] == ["route", "show"]:
                out = json.dumps([{"dst": "default", "dev": "eth0"}])
            elif argv[2] == "link":
                out = json.dumps([{"ifname": "eth0", "address": "02:00:00:00:00:99"}])
            else:
                out = json.dumps([{"addr_info": [{"local": "192.0.2.120", "prefixlen": 24}]}])
        elif argv[0] == "dpkg-query" and "${db:Status-Status}" in argv[3]:
            out = "".join(f"{name}\tinstalled\n" for name in argv[4:] if name in self.preinstalled)
            out += "".join(
                f"{name}\tnot-installed\n" for name in argv[4:] if name not in self.preinstalled
            )
        elif argv[0] == "ssh-keygen":
            out = "256 SHA256:fixturefingerprint root@temp (ED25519)\n"
        elif argv[0] == "groupadd":
            gid = argv[2] if argv[1] == "-g" else self._free("/etc/group", system="-r" in argv)
            self._append("/etc/group", f"{argv[-1]}:x:{gid}:")
        elif argv[0] == "useradd":
            flags = [a for a in argv[1:-1] if a in {"-r", "-M", "-m"}]
            rest = [a for a in argv[1:-1] if a not in flags]
            options = dict(zip(rest[::2], rest[1::2], strict=False))
            uid = options.get("-u") or self._free("/etc/passwd", system="-r" in flags)
            self._append(
                "/etc/passwd",
                f"{argv[-1]}:x:{uid}:{options['-g']}:{options['-c']}:"
                f"{options['-d']}:{options['-s']}",
            )
            self._append("/etc/shadow", f"{argv[-1]}:!:1::::::")
        elif argv[0] == "chpasswd":
            name, hashed = (stdin or "").strip().split(":", 1)
            lines = self.path("/etc/shadow").read_text().splitlines()
            lines = [
                f"{name}:{hashed}:1::::::" if ln.startswith(f"{name}:") else ln for ln in lines
            ]
            self.path("/etc/shadow").write_text("\n".join(lines) + "\n")
        elif argv[:2] == ["systemctl", "is-active"]:
            out = self.active.get(argv[2], "inactive") + "\n"
        elif argv == ["systemctl", "start", "keepalived"] and self.notifies:
            # keepalived's notify script, as it runs on the state it enters.
            state = self.path("/run/haproxy/keepalived.state")
            state.parent.mkdir(parents=True, exist_ok=True)
            state.write_text("BACKUP\n")
        errors = ""
        if argv[0] == "bash" and argv[1].endswith("/install/04-node-prepare"):
            errors = self.prepare_stderr
            if self.rendered_node_conf is not None:
                self.path("/etc/haproxy-manager/node.conf").write_text(self.rendered_node_conf)
        if check and code != 0:
            raise Failed(f"{argv[0]} failed")
        return subprocess.CompletedProcess(argv, code, out, errors)


# One archive member: path, kind, mode, uid, gid and its content.
type Member = tuple[str, str, int, int, int, bytes | str]


def payload(items: list[Member]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:") as archive:
        for path, kind, mode, uid, gid, data in items:
            info = tarfile.TarInfo(path.lstrip("/"))
            info.mode, info.uid, info.gid = mode, uid, gid
            if kind == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = str(data)
                archive.addfile(info)
            else:
                raw = data if isinstance(data, bytes) else data.encode()
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
    return buffer.getvalue()


def request(header: dict[str, Any], body: bytes = b"") -> io.BytesIO:
    return io.BytesIO(json.dumps(header).encode() + b"\n" + body)


APPLY_FILES: list[Member] = [
    ("/etc/apt/sources.list.d", "directory", 0o755, 0, 0, b""),
    ("/etc/apt/sources.list.d/ubuntu.sources", "file", 0o644, 0, 0, "archive\n"),
    ("/etc/apt/sources.list.d/haproxy.sources", "file", 0o644, 0, 0, "haproxy\n"),
    ("/etc/sudoers.d", "directory", 0o750, 0, 0, b""),
    ("/etc/sudoers.d/haproxy-node", "file", 0o440, 0, 0, "# rules\n"),
    ("/etc/haproxy-manager/node.conf", "file", 0o600, 0, 0, "CLUSTER=alpha\n"),
    ("/root/.ssh", "directory", 0o700, 0, 0, b""),
    ("/root/.ssh/known_hosts", "file", 0o644, 0, 0, "mgr key\n"),
    ("/var/lib/svc-backup/.ssh/authorized_keys", "file", 0o644, 0, 0, "restrict\n"),
    ("/etc/systemd/system/ipvsadm.service", "symlink", 0o777, 0, 0, "/dev/null"),
    ("/etc/default/grub.d/99-local.cfg", "file", 0o644, 0, 0, "local\n"),
    (f"/var/lib/haproxy-restore/{RUN}/node-bundle.tar.gz", "file", 0o600, 0, 0, BUNDLE),
]

APPLY_HEADER: dict[str, Any] = {
    "op": "apply",
    "run": RUN,
    "hostname": "node-test",
    "keepalived": "mask",
    "packages": ["haproxy", "keepalived"],
    "equal_directories": ["/etc/apt/sources.list.d", "/etc/sudoers.d", "/root/.ssh"],
    "cluster": "alpha",
    "node_bundle": {"root": BUNDLE_ROOT, "sha256": hashlib.sha256(BUNDLE).hexdigest()},
    "answers": 'TRIGGER_USER="svc-trigger"\n',
    "traffic_log": False,
    "groups": [
        {"name": "operator", "gid": 1000},
        {"name": "svc-backup", "gid": 990},
        {"name": "svc-logread-group", "gid": 985},
    ],
    "accounts": [
        {
            "name": "svc-backup",
            "uid": 990,
            "gid": 990,
            "gecos": "",
            "home": "/var/lib/svc-backup",
            "shell": "/bin/bash",
            "groups": ["svc-backup", "svc-logread-group"],
            "service": True,
            "password_hash": "!",
        },
        {
            "name": "operator",
            "uid": 1000,
            "gid": 1000,
            "gecos": "Operator",
            "home": "/home/operator",
            "shell": "/bin/bash",
            "groups": ["operator", "sudo", "adm"],
            "service": False,
            "password_hash": "$y$archived",
        },
    ],
}


class AgentTest(unittest.TestCase):
    def setUp(self) -> None:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        self.host = FakeHost(work)

    def serve(self, header: dict[str, Any], body: bytes = b"") -> dict[str, Any]:
        return restore_agent.serve(self.host, request(header, body))

    def commands(self, program: str) -> list[list[str]]:
        return [argv for argv in self.host.commands if argv[0] == program]


class Inspect(AgentTest):
    def test_reads_without_writing(self) -> None:
        before = sorted(p for p in self.host.root.rglob("*"))
        result = self.serve({"op": "inspect", "names": ["operator"], "ids": [990]})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["interface"]["mac"], "02:00:00:00:00:99")
        self.assertEqual(result["host_keys"], {"ed25519": "SHA256:fixturefingerprint"})
        self.assertEqual(result["accounts"], {"operator": [1000, 1000]})
        self.assertEqual(result["os_release"]["VERSION_ID"], "26.04")
        self.assertEqual(sorted(p for p in self.host.root.rglob("*")), before)
        self.assertEqual(result["installed"], [])

    def test_says_what_configures_the_network(self) -> None:
        result = self.serve({"op": "inspect", "names": [], "ids": []})
        self.assertEqual(result["network"], {"netplan": ["50-cloud-init.yaml"], "ifupdown": []})
        self.host.path("/etc/network/interfaces.d").mkdir(parents=True)
        self.host.path("/etc/network/interfaces").write_text(
            "auto lo\niface lo inet loopback\n# iface eth9 inet dhcp\nsource interfaces.d/*\n"
        )
        self.host.path("/etc/network/interfaces.d/eth0").write_text("iface eth0 inet dhcp\n")
        result = self.serve({"op": "inspect", "names": [], "ids": []})
        self.assertEqual(result["network"]["ifupdown"], ["eth0"])

    def test_names_the_product_packages_already_installed(self) -> None:
        self.host.preinstalled = {"haproxy", "rsyslog"}
        result = self.serve({"op": "inspect", "names": [], "ids": []})
        self.assertEqual(result["installed"], ["haproxy"])


class Apply(AgentTest):
    def apply(self, header: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.serve(header or APPLY_HEADER, payload(APPLY_FILES))

    def test_files_land_with_their_metadata_and_parents_are_created_plain(self) -> None:
        result = self.apply()
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.host.path("/etc/sudoers.d/haproxy-node").read_text(), "# rules\n")
        self.assertEqual(
            self.host.path("/etc/sudoers.d/haproxy-node").stat().st_mode & 0o7777, 0o440
        )
        self.assertEqual(self.host.path("/etc/sudoers.d").stat().st_mode & 0o7777, 0o750)
        # A parent the export only created with mkdir -p is plain 0755 root here.
        self.assertEqual(self.host.path("/etc/default/grub.d").stat().st_mode & 0o7777, 0o755)
        self.assertEqual(self.host.owners["/etc/default/grub.d"], (0, 0))
        self.assertTrue(self.host.path("/etc/systemd/system/ipvsadm.service").is_symlink())

    def test_what_the_image_had_in_a_carried_directory_goes_to_quarantine(self) -> None:
        self.apply()
        self.assertFalse(self.host.path("/etc/sudoers.d/90-cloud-init-users").exists())
        moved = self.host.path(
            f"/var/lib/haproxy-restore/{RUN}/quarantine/etc/sudoers.d/90-cloud-init-users"
        )
        self.assertTrue(moved.exists())
        self.assertEqual(
            self.host.path("/etc/apt/sources.list.d/ubuntu.sources").read_text(), "archive\n"
        )

    def test_runs_older_than_thirty_days_are_removed_when_a_run_begins_writing(self) -> None:
        state = self.host.path("/var/lib/haproxy-restore")
        today = time.strftime("%y%m%d")
        old = time.strftime("%y%m%d", time.localtime(time.time() - 40 * 86400))
        recent = time.strftime("%y%m%d", time.localtime(time.time() - 20 * 86400))
        for name in (f"r{old}-0000aaaa", f"r{recent}-0000bbbb", f"r{today}-0000cccc",
                     "undated-old-run", "undated-new-run", "not a run"):  # fmt: skip
            (state / name / "before").mkdir(parents=True)
        month_ago = time.time() - 40 * 86400
        os.utime(state / "undated-old-run", (month_ago, month_ago))
        result = self.apply()
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            sorted(p.name for p in state.iterdir()),
            sorted([f"r{recent}-0000bbbb", f"r{today}-0000cccc", "undated-new-run",
                    "not a run", RUN]),
        )  # fmt: skip
        step = next(s for s in result["steps"] if s["step"] == "old-runs")
        self.assertEqual(sorted(step["removed"]), [f"r{old}-0000aaaa", "undated-old-run"])

    def test_the_one_time_key_survives_apply(self) -> None:
        self.apply()
        self.assertEqual(self.host.path("/root/.ssh/authorized_keys").read_text(), "one-time key\n")
        self.assertTrue(self.host.path("/root/.ssh/known_hosts").exists())

    def test_nothing_starts_during_package_installation(self) -> None:
        seen: list[bool] = []
        original = self.host.run

        def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if argv[:2] == ["apt-get", "install"]:
                seen.append(self.host.path("/usr/sbin/policy-rc.d").exists())
            return original(argv, **kwargs)

        self.host.run = run  # type: ignore[method-assign]
        self.apply()
        self.assertEqual(seen, [True])
        self.assertFalse(self.host.path("/usr/sbin/policy-rc.d").exists())

    def test_apt_sources_are_in_place_before_apt_runs(self) -> None:
        order: list[str] = []
        original = self.host.run

        def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if argv[0] == "apt-get" and argv[-1] == "update":
                order.append(self.host.path("/etc/apt/sources.list.d/haproxy.sources").read_text())
            return original(argv, **kwargs)

        self.host.run = run  # type: ignore[method-assign]
        self.apply()
        self.assertEqual(order, ["haproxy\n"])

    def test_the_archives_ids_are_taken_before_packages_can_take_them(self) -> None:
        self.apply()
        programs = [argv[0] for argv in self.host.commands]
        self.assertLess(programs.index("groupadd"), programs.index("apt-get"))
        self.assertLess(programs.index("useradd"), programs.index("apt-get"))

    def test_accounts_groups_and_passwords(self) -> None:
        self.apply()
        useradd = self.commands("useradd")
        self.assertEqual(len(useradd), 1)
        self.assertIn("-M", useradd[0])
        self.assertEqual(useradd[0][-1], "svc-backup")
        self.assertEqual(self.host.owners["/var/lib/svc-backup"], (0, 0))
        self.assertIn(["usermod", "-a", "-G", "sudo", "operator"], self.host.commands)
        self.assertIn(
            ["usermod", "-a", "-G", "svc-logread-group", "svc-backup"], self.host.commands
        )
        # The operator already has a password on the target (B173).
        self.assertEqual(self.commands("chpasswd"), [])

    def test_an_archived_hash_is_set_where_the_account_has_none(self) -> None:
        self.host.path("/etc/shadow").write_text("root:*:1::::::\noperator:!:1::::::\n")
        self.apply()
        self.assertEqual(self.commands("chpasswd"), [["chpasswd", "-e"]])
        self.assertIn("operator:$y$archived:", self.host.path("/etc/shadow").read_text())

    def test_a_number_the_target_uses_gives_the_account_another_and_files_follow(
        self,
    ) -> None:
        """B181: Debian's systemd-timesync holds 997, which the archived node's account had."""

        self.host._append("/etc/passwd", "systemd-timesync:x:990:990::/:/usr/sbin/nologin")
        self.host._append("/etc/group", "tcpdump:x:985:")
        result = self.apply()
        self.assertTrue(result["ok"], result)
        useradd = self.commands("useradd")[0]
        self.assertNotIn("-u", useradd)
        self.assertIn("-r", useradd)
        groupadd = next(
            argv for argv in self.commands("groupadd") if argv[-1] == "svc-logread-group"
        )
        self.assertEqual(groupadd, ["groupadd", "-r", "svc-logread-group"])
        renumbered = next(step for step in result["steps"] if step["step"] == "accounts")[
            "renumbered"
        ]
        self.assertIn("group svc-logread-group 985 -> 999", renumbered)
        self.assertIn("account svc-backup 990 -> 999", renumbered)

    def test_an_archived_owner_is_translated_by_name(self) -> None:
        self.host._append("/etc/passwd", "systemd-timesync:x:990:990::/:/usr/sbin/nologin")
        owned: Member = ("/var/lib/svc-backup/.ssh/known_hosts", "file", 0o600, 990, 990, "k\n")
        result = self.serve(APPLY_HEADER, payload([*APPLY_FILES, owned]))
        self.assertTrue(result["ok"], result)
        # Staged beside its name and renamed onto it; the owner is set on the staged file.
        staged = [
            owner
            for path, owner in self.host.owners.items()
            if path.startswith("/var/lib/svc-backup/.ssh/.restore-")
        ]
        self.assertIn((999, 990), staged)

    def test_an_account_whose_group_the_archive_lacks_stops_before_anything_is_written(
        self,
    ) -> None:
        header = json.loads(json.dumps(APPLY_HEADER))
        header["accounts"][1]["gid"] = 1234
        result = self.apply(header)
        self.assertFalse(result["ok"])
        self.assertTrue(result["refused"])
        self.assertIn("operator", result["error"])
        self.assertEqual(self.host.commands, [])
        self.assertTrue(self.host.path("/etc/sudoers.d/90-cloud-init-users").exists())

    def test_the_haproxy_layout_boots_on_a_listener_nothing_can_reach(self) -> None:
        self.apply()
        current = self.host.path("/etc/haproxy/current")
        self.assertTrue(current.is_symlink())
        config = self.host.path("/etc/haproxy/releases/00000000-000000/haproxy.cfg").read_text()
        self.assertIn("bind unix@/run/haproxy-restore-bootstrap.sock mode 600", config)
        self.assertEqual(
            str(self.host.path("/etc/haproxy/haproxy.cfg").readlink()), "current/haproxy.cfg"
        )
        moved = self.host.path(f"/var/lib/haproxy-restore/{RUN}/quarantine/etc/haproxy/haproxy.cfg")
        self.assertEqual(moved.read_text(), "package default\n")

    def test_keepalived_is_masked_in_test_mode(self) -> None:
        self.apply()
        self.assertIn(["systemctl", "mask", "keepalived"], self.host.commands)
        self.assertNotIn(["systemctl", "enable", "keepalived"], self.host.commands)

    def test_sysctl_hostname_and_sshd(self) -> None:
        self.apply()
        self.assertIn(["sysctl", "--system"], self.host.commands)
        self.assertIn(["hostnamectl", "set-hostname", "node-test"], self.host.commands)
        sshd = self.host.commands.index(["sshd", "-t"])
        self.assertEqual(
            self.host.commands[sshd + 1], ["systemctl", "reload-or-restart", "ssh.service"]
        )

    def prepared(self) -> list[str]:
        return next(argv for argv in self.host.commands if argv[0] == "bash")

    def test_the_release_s_node_bundle_prepares_the_node_last(self) -> None:
        """B180: 04-node-prepare with answers from the archive, after files and services."""

        result = self.apply()
        self.assertTrue(result["ok"], result)
        argv = self.prepared()
        work = self.host.path(f"/var/lib/haproxy-restore/{RUN}/node-bundle")
        self.assertEqual(
            argv,
            [
                "bash",
                str(work / BUNDLE_ROOT / "install/04-node-prepare"),
                str(work / "answers.env"),
                "alpha",
            ],
        )
        self.assertEqual((work / "answers.env").read_text(), APPLY_HEADER["answers"])
        self.assertEqual((work / "answers.env").stat().st_mode & 0o777, 0o600)
        self.assertLess(
            self.host.commands.index(["systemctl", "enable", "haproxy"]),
            self.host.commands.index(argv),
        )
        # The bundle is extracted beside the run, never placed as a node file.
        self.assertFalse(self.host.path("/etc/node-bundle.tar.gz").exists())
        self.assertNotIn(["/usr/local/sbin/haproxy-traffic-log-enable"], self.host.commands)

    def test_the_traffic_log_is_turned_on_by_the_bundle_when_it_was_on(self) -> None:
        header = dict(APPLY_HEADER, traffic_log=True)
        result = self.apply(header)
        self.assertTrue(result["ok"], result)
        enable = self.host.commands.index(["/usr/local/sbin/haproxy-traffic-log-enable"])
        self.assertLess(self.host.commands.index(self.prepared()), enable)

    def test_the_node_preparation_s_warnings_are_reported_but_the_state_file_s(self) -> None:
        """The state file is asked about in `finish`, once keepalived runs.

        In `apply` keepalived has not been started yet, so the preparation's
        warning that its state file is missing was true on every new VM and
        said nothing (2026-09-25).
        """

        self.host.prepare_stderr = (
            "WARNING: /run/haproxy/keepalived.state does not exist yet. A config reload\n"
            "WARNING:   does not always produce a state transition - force one by\n"
            "noise\n"
            "WARNING:   restarting keepalived on this node once.\n"
            "WARNING: nopreempt is not set.\n"
        )
        result = self.apply()
        self.assertEqual(
            [w for w in result["warnings"] if w.startswith("node preparation")],
            ["node preparation: nopreempt is not set."],
        )

    def test_a_node_conf_rendered_differently_is_reported(self) -> None:
        self.host.rendered_node_conf = "CLUSTER=alpha\n"
        self.assertFalse(any("node.conf" in w for w in self.apply()["warnings"]))
        self.setUp()
        self.host.rendered_node_conf = "CLUSTER=beta\n"
        self.assertTrue(any("rendered differently" in w for w in self.apply()["warnings"]))

    def test_a_bundle_that_does_not_match_its_digest_stops_before_anything_is_written(
        self,
    ) -> None:
        header = dict(APPLY_HEADER, node_bundle={"root": BUNDLE_ROOT, "sha256": "0" * 64})
        result = self.apply(header)
        self.assertFalse(result["ok"])
        self.assertTrue(result["refused"])
        self.assertIn("does not match", result["error"])
        self.assertEqual(self.host.commands, [])

    def test_apply_without_a_bundle_is_refused(self) -> None:
        files = [item for item in APPLY_FILES if not item[0].endswith("node-bundle.tar.gz")]
        result = self.serve(APPLY_HEADER, payload(files))
        self.assertFalse(result["ok"])
        self.assertIn("no node bundle", result["error"])
        self.assertEqual(self.host.commands, [])

    def test_nothing_else_may_be_placed_in_the_restore_s_own_directory(self) -> None:
        stray: Member = (f"/var/lib/haproxy-restore/{RUN}/answers.env", "file", 0o600, 0, 0, "x")
        result = self.serve(APPLY_HEADER, payload([*APPLY_FILES, stray]))
        self.assertFalse(result["ok"])
        self.assertIn("own directory", result["error"])

    def test_netplan_and_roots_keys_are_refused_in_apply(self) -> None:
        for path in ("/etc/netplan/50-x.yaml", "/root/.ssh/authorized_keys"):
            result = self.serve(APPLY_HEADER, payload([(path, "file", 0o600, 0, 0, "x")]))
            self.assertFalse(result["ok"])
            self.assertIn("later session", result["error"])

    def test_an_unsafe_payload_path_is_refused(self) -> None:
        result = self.serve(APPLY_HEADER, payload([("etc/../../x", "file", 0o600, 0, 0, "x")]))
        self.assertFalse(result["ok"])
        self.assertIn("unsafe", result["error"])


class Network(AgentTest):
    NETPLAN: ClassVar[list[Member]] = [
        ("/etc/netplan/50-cloud-init.yaml", "file", 0o600, 0, 0, "network: {}\n")
    ]

    def header(self, seconds: int = 180) -> dict[str, Any]:
        return {"op": "network", "run": RUN, "rollback_seconds": seconds}

    def test_netplan_is_replaced_and_a_rollback_is_scheduled_before_it_applies(self) -> None:
        result = self.serve(self.header(), payload(self.NETPLAN))
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            self.host.path("/etc/netplan/50-cloud-init.yaml").read_text(), "network: {}\n"
        )
        before = self.host.path(f"/var/lib/haproxy-restore/{RUN}/netplan-before/50-cloud-init.yaml")
        self.assertEqual(before.read_text(), "dhcp\n")
        runs = self.commands("systemd-run")
        self.assertEqual(
            runs[0][1:3], [f"--unit=haproxy-restore-rollback-{RUN}", "--on-active=180"]
        )
        self.assertEqual(runs[1][1:3], [f"--unit=haproxy-restore-apply-{RUN}", "--on-active=3"])
        self.assertEqual(result["rollback_unit"], f"haproxy-restore-rollback-{RUN}")

    def test_a_rejected_netplan_is_put_back_at_once(self) -> None:
        self.host.fail.add("netplan")
        result = self.serve(self.header(), payload(self.NETPLAN))
        self.assertFalse(result["ok"])
        self.assertEqual(self.host.path("/etc/netplan/50-cloud-init.yaml").read_text(), "dhcp\n")
        self.assertEqual(self.commands("systemd-run"), [])

    def test_only_netplan_travels_and_the_delay_is_bounded(self) -> None:
        wrong = payload([("/etc/hosts", "file", 0o644, 0, 0, "x")])
        self.assertFalse(self.serve(self.header(), wrong)["ok"])
        self.assertFalse(self.serve(self.header(seconds=10), payload(self.NETPLAN))["ok"])

    def test_a_second_network_change_in_one_run_is_refused(self) -> None:
        self.assertTrue(self.serve(self.header(), payload(self.NETPLAN))["ok"])
        again = self.serve(self.header(), payload(self.NETPLAN))
        self.assertFalse(again["ok"])
        self.assertIn("already", again["error"])


class Finish(AgentTest):
    KEYS: ClassVar[list[Member]] = [
        ("/root/.ssh/authorized_keys", "file", 0o600, 0, 0, "operator key\n")
    ]

    def header(self, keepalived: str = "mask") -> dict[str, Any]:
        return {
            "op": "finish",
            "run": RUN,
            "certificates": ["cert-a", "cert-b"],
            "keepalived": keepalived,
        }

    def test_the_order_is_timer_haproxy_certificates_config_services_keys(self) -> None:
        self.host.active.update(
            {f"haproxy-restore-rollback-{RUN}.timer": "active", "haproxy": "active"}
        )
        result = self.serve(self.header(), payload(self.KEYS))
        self.assertTrue(result["ok"], result)
        sequence = [argv for argv in self.host.commands if argv[:2] != ["systemctl", "is-active"]]
        self.assertEqual(
            sequence,
            [
                ["systemctl", "stop", f"haproxy-restore-rollback-{RUN}.timer"],
                ["systemctl", "start", "haproxy"],
                ["/usr/local/sbin/haproxy-cert-pull", "cert-a", "cert-b"],
                ["/usr/local/sbin/haproxy-pull-deploy"],
            ],
        )
        self.assertEqual(self.host.path("/root/.ssh/authorized_keys").read_text(), "operator key\n")

    def test_a_fired_rollback_timer_stops_finish(self) -> None:
        result = self.serve(self.header(), payload(self.KEYS))
        self.assertFalse(result["ok"])
        self.assertIn("rollback timer", result["error"])
        self.assertEqual(self.host.path("/root/.ssh/authorized_keys").read_text(), "one-time key\n")

    def test_failing_services_keep_the_one_time_key(self) -> None:
        self.host.active.update({f"haproxy-restore-rollback-{RUN}.timer": "active"})
        result = self.serve(self.header(), payload(self.KEYS))
        self.assertFalse(result["ok"])
        self.assertEqual(self.host.path("/root/.ssh/authorized_keys").read_text(), "one-time key\n")

    def test_keepalived_is_started_for_a_real_restore(self) -> None:
        self.host.active.update(
            {
                f"haproxy-restore-rollback-{RUN}.timer": "active",
                "haproxy": "active",
                "keepalived": "active",
            }
        )
        result = self.serve(self.header("start"), payload(self.KEYS))
        self.assertTrue(result["ok"], result)
        self.assertIn(["systemctl", "start", "keepalived"], self.host.commands)

    def test_finish_carries_roots_keys_and_nothing_else(self) -> None:
        extra = payload([*self.KEYS, ("/etc/hosts", "file", 0o644, 0, 0, "x")])
        self.assertFalse(self.serve(self.header(), extra)["ok"])


OVERWRITE_FILES = [item for item in APPLY_FILES if not item[0].startswith("/etc/apt/")]
OVERWRITE_HEADER: dict[str, Any] = {
    **APPLY_HEADER,
    "keepalived": "start",
    "overwrite": True,
    "packages": ["rsync"],
    "equal_directories": ["/etc/haproxy-manager"],
    "keep": ["/etc/haproxy-manager/node-installation.json"],
}


class Overwrite(AgentTest):
    """B172/B183: the archive over a running node, with a copy to go back to."""

    def setUp(self) -> None:
        super().setUp()
        # A running node: its product files, its release, a stray file of its own.
        for name, text in {
            "/etc/sudoers.d/haproxy-node": "# node's rules\n",
            "/etc/haproxy-manager/node.conf": "CLUSTER=drifted\n",
            "/etc/haproxy-manager/node-installation.json": '{"node_api": 1}\n',
            "/etc/haproxy-manager/stray": "left by hand\n",
            "/etc/haproxy-manager/node.conf.replaced-20260101-000000": "old\n",
            "/usr/local/sbin/haproxy-pull-deploy": "#!/bin/sh\nold\n",
        }.items():
            path = self.host.path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.host.path("/etc/haproxy/haproxy.cfg").unlink()
        self.host.path("/etc/haproxy/releases/r1").mkdir(parents=True)
        self.host.path("/etc/haproxy/current").symlink_to("/etc/haproxy/releases/r1")
        self.host.path("/etc/haproxy/haproxy.cfg").symlink_to("current/haproxy.cfg")

    def apply(self, header: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.serve(header or OVERWRITE_HEADER, payload(OVERWRITE_FILES))

    def test_inspect_says_what_the_node_holds(self) -> None:
        self.host.preinstalled = {"haproxy", "rsync"}
        result = self.serve(
            {
                "op": "inspect",
                "names": [],
                "ids": [],
                "hash": ["/etc/sudoers.d/haproxy-node", "/etc/missing"],
                "list": ["/etc/haproxy-manager", "/etc/systemd/system/haproxy.service.d"],
                "packages": ["haproxy", "keepalived", "rsync"],
            }
        )
        self.assertTrue(result["ok"], result)
        self.assertIsNone(result["hashes"]["/etc/missing"])
        self.assertEqual(
            result["hashes"]["/etc/sudoers.d/haproxy-node"],
            hashlib.sha256(b"# node's rules\n").hexdigest(),
        )
        self.assertIn("/etc/haproxy-manager/stray", result["hashes"])
        self.assertEqual(result["listing"]["/etc/systemd/system/haproxy.service.d"], [])
        self.assertIn("/etc/haproxy-manager/stray", result["listing"]["/etc/haproxy-manager"])
        self.assertEqual(result["product_installed"], ["haproxy", "rsync"])

    def test_root_s_keys_are_compared_without_this_run_s_one_time_key(self) -> None:
        """The paste appends the one-time key; the restore takes it away again.

        Counted as a difference, every overwrite said "1 of 34 files differ"
        on a node nobody had touched (2026-09-25). Only this run's key is left
        out - an older run's line, or any other, still counts.
        """

        archived = b"ssh-ed25519 AAAAoperator operator@desk\n"
        keys = self.host.path("/root/.ssh/authorized_keys")
        keys.parent.mkdir(parents=True, exist_ok=True)
        keys.write_bytes(
            archived
            + b'from="192.0.2.7",restrict ssh-ed25519 AAAAone haproxy-restore-r260925-5cbabcd3\n'
        )
        header = {"op": "inspect", "names": [], "ids": [], "hash": ["/root/.ssh/authorized_keys"]}
        this_run = self.serve({**header, "run": "r260925-5cbabcd3"})
        other_run = self.serve({**header, "run": "r260925-00000000"})
        self.assertEqual(
            this_run["hashes"]["/root/.ssh/authorized_keys"], hashlib.sha256(archived).hexdigest()
        )
        self.assertNotEqual(
            other_run["hashes"]["/root/.ssh/authorized_keys"], hashlib.sha256(archived).hexdigest()
        )

    def test_the_copy_comes_first_and_keepalived_stops_before_any_write(self) -> None:
        result = self.apply()
        self.assertTrue(result["ok"], result)
        steps = [step["step"] for step in result["steps"]]
        self.assertEqual(steps[:2], ["copy", "keepalived"])
        self.assertEqual(self.host.commands[0], ["systemctl", "stop", "keepalived"])
        self.assertTrue(
            self.host.path(f"/var/lib/haproxy-restore/{RUN}/before/files.tar").is_file()
        )

    def test_the_nodes_software_and_release_are_left_alone(self) -> None:
        self.apply()
        installs = [argv for argv in self.commands("apt-get") if "install" in argv]
        self.assertEqual(len(installs), 1)
        self.assertIn("--no-upgrade", installs[0])
        self.assertEqual(installs[0][-1], "rsync")
        self.assertFalse(self.host.path("/etc/apt/sources.list.d/haproxy.sources").exists())
        self.assertEqual(
            os.readlink(self.host.path("/etc/haproxy/current")), "/etc/haproxy/releases/r1"
        )
        self.assertFalse(self.host.path("/etc/haproxy/releases/00000000-000000").exists())

    def test_nothing_missing_means_no_apt_at_all(self) -> None:
        self.apply({**OVERWRITE_HEADER, "packages": []})
        self.assertEqual(self.commands("apt-get"), [])

    def test_the_products_directory_is_made_the_archives(self) -> None:
        self.apply()
        self.assertFalse(self.host.path("/etc/haproxy-manager/stray").exists())
        self.assertTrue(
            self.host.path(
                f"/var/lib/haproxy-restore/{RUN}/quarantine/etc/haproxy-manager/stray"
            ).exists()
        )
        self.assertTrue(self.host.path("/etc/haproxy-manager/node-installation.json").exists())
        self.assertTrue(
            self.host.path("/etc/haproxy-manager/node.conf.replaced-20260101-000000").exists()
        )
        self.assertEqual(
            self.host.path("/etc/haproxy-manager/node.conf").read_text(), "CLUSTER=alpha\n"
        )
        # The directories the product shares with the image keep the image's files.
        self.assertTrue(self.host.path("/etc/sudoers.d/90-cloud-init-users").exists())

    def test_a_failure_puts_the_node_back_as_it_was(self) -> None:
        self.host.fail = {"bash"}  # the node bundle's 04-node-prepare
        result = self.apply()
        self.assertFalse(result["ok"])
        self.assertTrue(result["rolled_back"], result)
        self.assertEqual(
            self.host.path("/etc/haproxy-manager/node.conf").read_text(), "CLUSTER=drifted\n"
        )
        self.assertEqual(self.host.path("/etc/haproxy-manager/stray").read_text(), "left by hand\n")
        self.assertEqual(
            self.host.path("/etc/sudoers.d/haproxy-node").read_text(), "# node's rules\n"
        )
        # What the overwrite added is set aside, not left behind.
        self.assertFalse(self.host.path("/etc/default/grub.d/99-local.cfg").exists())
        self.assertIn(["systemctl", "start", "keepalived"], self.host.commands)

    def test_a_link_the_node_had_comes_back_as_a_link(self) -> None:
        link = self.host.path("/etc/systemd/system/ipvsadm.service")
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to("/dev/null")
        self.host.fail = {"bash"}
        result = self.apply()
        self.assertTrue(result["rolled_back"], result)
        self.assertEqual(os.readlink(link), "/dev/null")

    def test_a_copy_naming_a_path_outside_the_node_is_not_put_back(self) -> None:
        self.apply()
        copy = self.host.path(f"/var/lib/haproxy-restore/{RUN}/before/files.tar")
        with tarfile.open(copy, "a") as archive:
            info = tarfile.TarInfo("../escaped")
            archive.addfile(info, io.BytesIO(b""))
        result = self.serve({"op": "rollback", "run": RUN})
        self.assertFalse(result["ok"])
        self.assertIn("unsafe path", result["error"])
        self.assertFalse((self.host.root.parent / "escaped").exists())

    def test_a_failed_rollback_says_go_to_the_console(self) -> None:
        self.host.fail = {"bash"}
        self.host.path("/var/lib/haproxy-restore").mkdir(parents=True)
        original = restore_agent.rollback_files

        def broken(*_args: object) -> None:
            raise Failed("disk full")

        restore_agent.rollback_files = broken  # type: ignore[assignment]
        self.addCleanup(setattr, restore_agent, "rollback_files", original)
        result = self.apply()
        self.assertFalse(result["ok"])
        self.assertNotIn("rolled_back", result)
        self.assertIn("go to the console", result["error"])

    def test_a_second_copy_in_one_run_is_refused(self) -> None:
        self.apply()
        result = self.apply()
        self.assertFalse(result["ok"])
        self.assertIn("already taken", result["error"])

    def test_an_overwrite_writes_no_repository_file(self) -> None:
        result = self.serve(OVERWRITE_HEADER, payload(APPLY_FILES))
        self.assertTrue(result["refused"], result)

    def test_rollback_after_a_network_failure_puts_the_files_back(self) -> None:
        self.apply()
        result = self.serve({"op": "rollback", "run": RUN})
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            self.host.path("/etc/haproxy-manager/node.conf").read_text(), "CLUSTER=drifted\n"
        )

    def finish(self) -> dict[str, Any]:
        header = {
            "op": "finish",
            "run": RUN,
            "certificates": [],
            "keepalived": "start",
            "overwrite": True,
            "network": False,
        }
        return self.serve(header, payload(Finish.KEYS))

    def test_finish_without_a_network_change_has_no_timer_to_stop(self) -> None:
        self.apply()
        self.host.active.update({"haproxy": "active", "keepalived": "active"})
        result = self.finish()
        self.assertTrue(result["ok"], result)
        self.assertNotIn("rollback-cancelled", [step["step"] for step in result["steps"]])

    def test_a_keepalived_that_reports_its_state_is_not_warned_about(self) -> None:
        self.apply()
        self.host.active.update({"haproxy": "active", "keepalived": "active"})
        result = self.finish()
        self.assertTrue(result["ok"], result)
        self.assertFalse(any("keepalived.state" in w for w in result["warnings"]), result)

    def test_a_keepalived_that_reports_no_state_is_warned_about_after_it_starts(self) -> None:
        self.apply()
        self.host.active.update({"haproxy": "active", "keepalived": "active"})
        self.host.notifies = False
        with mock.patch.object(restore_agent, "KEEPALIVED_STATE_WAIT", 0.0):
            result = self.finish()
        self.assertTrue(result["ok"], result)
        self.assertTrue(
            any(
                w.startswith("/run/haproxy/keepalived.state does not exist yet.")
                for w in result["warnings"]
            ),
            result,
        )

    def test_a_node_that_does_not_come_up_is_put_back_and_keeps_the_one_time_key(self) -> None:
        self.apply()
        self.host.active.update({"haproxy": "active"})  # keepalived does not come up
        result = self.finish()
        self.assertFalse(result["ok"])
        self.assertTrue(result["rolled_back"], result)
        self.assertEqual(
            self.host.path("/etc/haproxy-manager/node.conf").read_text(), "CLUSTER=drifted\n"
        )
        self.assertEqual(self.host.path("/root/.ssh/authorized_keys").read_text(), "one-time key\n")


class Protocol(AgentTest):
    def test_unknown_operations_and_run_ids_are_refused(self) -> None:
        self.assertFalse(self.serve({"op": "shell"})["ok"])
        self.assertFalse(self.serve({"op": "apply", "run": "../x"})["ok"])

    def test_a_missing_header_is_refused(self) -> None:
        self.assertFalse(restore_agent.serve(self.host, io.BytesIO(b"{}"))["ok"])

    def test_the_agent_imports_only_the_standard_library(self) -> None:
        source = Path(restore_agent.__file__).read_text()
        self.assertNotIn("haproxy_mgmt", source.split('"""', 2)[2])
        self.assertNotIn("import yaml", source)


if __name__ == "__main__":
    unittest.main()


class AptUpdate(unittest.TestCase):
    """A distribution mirror mid-sync does not stop a restore; the HAProxy repository does."""

    SOURCE = "https://ppa.launchpadcontent.net/example/haproxy-3.4/ubuntu"

    def attempt(self, *answers: tuple[int, str]) -> tuple[list[str], list[float]]:
        replies = iter(answers)
        calls: list[list[str]] = []

        class Host:
            def run(self, argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
                calls.append(argv)
                code, err = next(replies)
                return subprocess.CompletedProcess(argv, code, "", err)

        report = restore_agent.Report()
        slept: list[float] = []
        restore_agent._update(
            Host(),  # type: ignore[arg-type]
            (self.SOURCE,),
            report,
            sleep=slept.append,
        )
        self.assertTrue(all(argv[-1] == "update" for argv in calls))
        return report.warnings, slept

    MIRROR = (
        "E: Failed to fetch http://security.ubuntu.example/ubuntu/dists/x-security/universe/"
        "dep11/Components-amd64.yml.xz  Hash Sum mismatch\n"
        "E: Some index files failed to download."
    )

    def test_a_passing_try_after_a_failing_one_is_enough(self) -> None:
        warnings, slept = self.attempt((100, self.MIRROR), (0, ""))
        self.assertEqual((warnings, slept), ([], [restore_agent.APT_UPDATE_PAUSE]))

    def test_another_mirror_failing_every_try_is_a_warning(self) -> None:
        warnings, slept = self.attempt(*[(100, self.MIRROR)] * 3)
        self.assertEqual(len(slept), 2)
        self.assertIn("outside the HAProxy repository", warnings[0])
        self.assertIn("Components-amd64.yml.xz", warnings[0])

    def test_the_haproxy_repository_failing_stops_the_restore(self) -> None:
        failing = (
            f"Err:7 {self.SOURCE} x InRelease\nE: Failed to fetch {self.SOURCE}/dists/x/InRelease"
        )
        with self.assertRaisesRegex(restore_agent.Failed, "apt-get update exited 100"):
            self.attempt(*[(100, failing)] * 3)

    def test_a_failure_it_cannot_read_stops_the_restore(self) -> None:
        with self.assertRaises(restore_agent.Failed):
            self.attempt(*[(100, "E: something else entirely")] * 3)

    def test_the_required_uris_are_read_from_the_placed_sources(self) -> None:
        items = [
            restore_agent.Item(
                path="/etc/apt/sources.list.d/haproxy-3.4.sources",
                kind="file",
                mode=0o644,
                uid=0,
                gid=0,
                data=f"Types: deb\nURIs: {self.SOURCE}/\nSuites: x\n".encode(),
            ),
            restore_agent.Item(
                path="/etc/apt/keyrings/haproxy.asc", kind="file", mode=0o644, uid=0, gid=0
            ),
        ]
        self.assertEqual(restore_agent._required_uris(items), (self.SOURCE,))
