"""Where HAProxy logs the traffic stream, and the cores a publish refuses for it.

Review 2026-10-30-igen, R2: the stream's socket is in HAProxy's chroot, and a
core may have no chroot, another one, or another account. The generated line
names the socket by its host path; step 4 links the same path inside the
chroot to it; a core that would still miss the socket refuses the publish.
"""

from __future__ import annotations

import posixpath
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from haprion import traffic_stream
from haprion.cluster_definition import seed_files
from haprion.generate import TRAFFIC_LOG_PROFILE

ROOT = Path(__file__).resolve().parents[1]
NODE_PREPARE = ROOT / "install" / "04-node-prepare"
PULL_DEPLOY = ROOT / "install" / "node" / "haprion-pull-deploy"
GENERATED = "managed/generated/1040-frontends.cfg"
LOGGED = (
    b"frontend mgd-http\n"
    b"    log /var/lib/haproxy/dev/haprion-traffic len 2048 format local profile mgd-traffic-json"
    b" local2\n"
)
UBUNTU_GLOBAL = (
    b"global\n"
    b"    log /dev/log local0\n"
    b"    chroot /var/lib/haproxy\n"
    b"    user haproxy\n"
    b"    group haproxy\n"
    b"    daemon\n"
)


def tree(core: bytes, generated: bytes = LOGGED, **more: bytes) -> dict[str, bytes]:
    return {"core/haproxy.cfg": core, GENERATED: generated, **more}


def problem(files: dict[str, bytes]) -> str | None:
    return traffic_stream.problem(files, cluster="alpha", config_path="/srv/config/alpha")


class TheLineReachesTheSocket(unittest.TestCase):
    def test_the_profile_is_the_generators(self) -> None:
        self.assertEqual(traffic_stream.TRAFFIC_LOG_PROFILE, TRAFFIC_LOG_PROFILE)

    def test_without_a_chroot_the_host_path_is_the_socket(self) -> None:
        self.assertEqual(
            traffic_stream.reached(traffic_stream.TRAFFIC_LOG_SOCKET, None),
            traffic_stream.TRAFFIC_LOG_SOCKET,
        )

    def test_in_ubuntus_chroot_the_same_path_is_step_4s_link_to_the_socket(self) -> None:
        inside = traffic_stream.reached(traffic_stream.TRAFFIC_LOG_SOCKET, "/var/lib/haproxy/")
        self.assertEqual(inside, traffic_stream.TRAFFIC_LOG_LINK)
        text = NODE_PREPARE.read_text(encoding="utf-8")
        link = re.search(r'^TRAFFIC_SOCKET_LINK="([^"]+)"$', text, re.MULTILINE)
        target = re.search(r'^TRAFFIC_SOCKET_LINK_TARGET="([^"]+)"$', text, re.MULTILINE)
        socket = re.search(r'^TRAFFIC_SOCKET_PATH="([^"]+)"$', text, re.MULTILINE)
        assert link is not None and target is not None and socket is not None
        self.assertEqual(link[1], traffic_stream.TRAFFIC_LOG_LINK)
        self.assertEqual(socket[1], traffic_stream.TRAFFIC_LOG_SOCKET)
        #
        # From the host, and from inside the chroot, where /var/lib/haproxy is /.
        #
        self.assertEqual(
            posixpath.normpath(posixpath.join(posixpath.dirname(link[1]), target[1])), socket[1]
        )
        self.assertEqual(
            posixpath.normpath(
                posixpath.join(posixpath.dirname(traffic_stream.TRAFFIC_LOG_SOCKET), target[1])
            ),
            "/dev/haprion-traffic",
        )


class ACoreThatMissesTheSocketIsRefused(unittest.TestCase):
    def test_a_release_that_logs_no_stream_is_not_held_to_it(self) -> None:
        self.assertIsNone(problem(tree(b"global\n    chroot /srv/x\n", b"frontend x\n")))

    def test_ubuntus_packaged_global_and_the_seeded_core_pass(self) -> None:
        self.assertIsNone(problem(tree(UBUNTU_GLOBAL)))
        seeded = seed_files(None)["core/haproxy.cfg"]
        self.assertIsNone(problem(tree(seeded)))
        self.assertIsNone(problem(tree(UBUNTU_GLOBAL.replace(b"haproxy\n", b"haproxy/\n", 1))))

    def test_a_chroot_elsewhere_is_refused_with_the_line_to_write(self) -> None:
        said = problem(tree(UBUNTU_GLOBAL.replace(b"/var/lib/haproxy", b"/srv/haproxy")))
        assert said is not None
        self.assertIn("chroot /var/lib/haproxy", said)
        self.assertIn("sudoedit /srv/config/alpha/core/haproxy.cfg", said)

    def test_an_anonymous_chroot_is_named_as_one(self) -> None:
        said = problem(tree(UBUNTU_GLOBAL.replace(b"/var/lib/haproxy", b"auto")))
        assert said is not None
        self.assertIn("an anonymous chroot (`auto`)", said)
        self.assertNotIn("in auto", said)

    def test_an_explicit_root_may_write_the_socket(self) -> None:
        self.assertIsNone(problem(tree(b"global\n    user root\n")))

    def test_a_chroot_in_a_core_fragment_counts_when_the_core_has_none(self) -> None:
        files = tree(
            b"global\n    daemon\n", **{"core/conf.d/0100-g.cfg": b"global\n  chroot /srv/x\n"}
        )
        self.assertIsNotNone(problem(files))

    def test_the_first_chroot_wins_as_haproxy_reads_it(self) -> None:
        later = b"global\n  chroot /srv/x\n"
        self.assertIsNone(problem(tree(UBUNTU_GLOBAL, **{"manual/conf.d/9000-x.cfg": later})))
        first = b"global\n    chroot /srv/jail\n"
        self.assertIsNotNone(
            problem(
                tree(first, **{"manual/conf.d/9000-x.cfg": b"global\n  chroot /var/lib/haproxy\n"})
            )
        )

    def test_the_first_account_wins_and_user_and_uid_are_one_setting(self) -> None:
        late = b"global\n    user haproxy\n    group haproxy\n"
        files = tree(
            b"global\n    user nobody\n    group nogroup\n", **{"manual/conf.d/9000-x.cfg": late}
        )
        self.assertIsNotNone(problem(files))
        self.assertIsNone(
            problem(tree(late, **{"manual/conf.d/9000-x.cfg": b"global\n    user nobody\n"}))
        )
        uid_first = b"global\n    uid 65534\n    user haproxy\n    group haproxy\n"
        user_late = {"manual/conf.d/9000-x.cfg": b"global\n    user haproxy\n"}
        self.assertIsNotNone(problem(tree(b"global\n    uid 65534\n", **user_late)))
        self.assertIsNotNone(problem(tree(uid_first.replace(b"    group haproxy\n", b""))))
        gid_first = b"global\n    user www-data\n    gid 33\n    group haproxy\n"
        self.assertIsNotNone(problem(tree(gid_first)))

    def test_another_account_is_refused_unless_its_group_is_haproxys(self) -> None:
        other = UBUNTU_GLOBAL.replace(b"user haproxy", b"user www-data")
        self.assertIsNone(problem(tree(other)))
        said = problem(tree(other.replace(b"group haproxy", b"group www-data")))
        assert said is not None
        self.assertIn("runs HAProxy as www-data", said)
        self.assertIn("user haproxy", said)
        self.assertIsNotNone(problem(tree(b"global\n    uid 33\n")))
        self.assertIsNone(problem(tree(b"global\n    uid 0\n")))

    def test_a_userlist_is_not_the_account_haproxy_runs_as(self) -> None:
        files = tree(
            UBUNTU_GLOBAL,
            **{"manual/conf.d/3000-users.cfg": b"userlist admins\n    user admin password x\n"},
        )
        self.assertIsNone(problem(files))


class PullDeployReadsTheCoreToo(unittest.TestCase):
    """Review 2026-10-30-igen3, T2: a log line in the core's haproxy.cfg counts as one in conf.d."""

    def refused(self, where: str) -> bool:
        """Whether `validate_traffic_stream_candidate` refuses a candidate with the line at `where`."""

        text = PULL_DEPLOY.read_text(encoding="utf-8")
        function = re.search(
            r"^validate_traffic_stream_candidate\(\) \{\n.*?^\}\n", text, re.DOTALL | re.MULTILINE
        )
        assert function is not None
        with tempfile.TemporaryDirectory() as raw:
            candidate = Path(raw)
            (candidate / "conf.d").mkdir()
            line = "    log /var/lib/haproxy/dev/haprion-traffic len 2048 local2\n"
            (candidate / where).write_text("defaults\n" + line, encoding="utf-8")
            script = (
                "log() { :; }\ntraffic_socket_ready() { return 1; }\n"
                'TRAFFIC_SOCKET="/var/lib/haproxy/dev/haprion-traffic"\n'
                f'{function.group(0)}\nvalidate_traffic_stream_candidate "{candidate}"\n'
            )
            done = subprocess.run(["/bin/bash", "-c", script], capture_output=True, check=False)
        return done.returncode != 0

    def test_a_line_in_conf_d_is_refused_on_an_unprepared_node(self) -> None:
        self.assertTrue(self.refused("conf.d/10-x.cfg"))

    def test_a_line_in_the_core_haproxy_cfg_is_refused_too(self) -> None:
        self.assertTrue(self.refused("haproxy.cfg"))


if __name__ == "__main__":
    unittest.main()
