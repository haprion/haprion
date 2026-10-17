"""The certbot environment installer, run against a stand-in uv.

Real uv needs the network and 375 MB; what the installer adds on top of it is
what is tested here - the release layout, the plugin proof, the relocation of
the scripts uv wrote for the staging path, the freeze, and the refusals.
"""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from unittest import mock

INSTALLER_PATH = Path(__file__).resolve().parents[1] / "tools" / "install-certbot-env.py"
SPEC = spec_from_file_location("install_certbot_env", INSTALLER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load certbot environment installer")
installer = module_from_spec(SPEC)
SPEC.loader.exec_module(installer)

PYTHON_TAG = f"python{sys.version_info[0]}.{sys.version_info[1]}"
# The interpreter a real installation names is a base one, never a venv's;
# a venv built on a venv's python finds no standard library.
BASE_PYTHON = Path(sys._base_executable).resolve()  # type: ignore[attr-defined]  # noqa: SLF001 - the one honest source

#
# A uv that builds a venv the way uv does - interpreter link, lib64 link,
# site-packages, scripts carrying the staging path - and populates it with
# whatever plugin distributions the test listed in a file beside it. A file,
# not an environment variable: the installer runs uv in an environment of its
# own choosing, and that is part of what is under test.
#
FAKE_UV = textwrap.dedent(
    f"""\
    #!{BASE_PYTHON}
    import os, sys
    from pathlib import Path
    assert sys.argv[1] == "sync" and "--locked" in sys.argv, sys.argv
    venv = Path(os.environ["UV_PROJECT_ENVIRONMENT"])
    python = Path(sys.argv[sys.argv.index("--python") + 1])
    site = venv / "lib" / "{PYTHON_TAG}" / "site-packages"
    site.mkdir(parents=True)
    (venv / "bin").mkdir()
    (venv / "bin" / "python").symlink_to(python)
    (venv / "bin" / "python3").symlink_to("python")
    (venv / "lib64").symlink_to("lib")
    (venv / "pyvenv.cfg").write_text(
        f"home = {{python.parent}}\\nversion = 0\\ninclude-system-site-packages = false\\n"
    )
    script = venv / "bin" / "certbot"
    script.write_text(f"#!{{venv / 'bin' / 'python'}}\\nprint('certbot')\\n")
    script.chmod(0o755)
    for spec in Path(sys.argv[0]).with_suffix(".plugins").read_text().split():
        name, _, kind = spec.partition(":")
        module = name.replace("-", "_")
        info = site / f"{{module}}-1.0.dist-info"
        info.mkdir()
        (info / "METADATA").write_text(f"Metadata-Version: 2.4\\nName: {{name}}\\nVersion: 1.0\\n")
        if kind == "silent":
            continue
        body = "raise ImportError('broken')" if kind == "broken" else "class Authenticator: pass"
        (site / f"{{module}}.py").write_text(body + "\\n")
        (info / "entry_points.txt").write_text(
            f"[certbot.plugins]\\n{{name.removeprefix('certbot-')}} = {{module}}:Authenticator\\n"
        )
    """
)

LOCK = 'version = 1\n\n[[package]]\nname = "certbot"\nversion = "5.8.0"\n'


class InstallCertbotEnvTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = tempfile.TemporaryDirectory()
        self.work = Path(self.raw.name).resolve()
        self.uv = self.work / "uv"
        self.uv.write_text(FAKE_UV)
        self.uv.chmod(0o755)
        self.project = self.work / "certbot"
        self.project.mkdir()
        (self.project / "pyproject.toml").write_text(
            '[project]\nname = "haprion-certbot-env"\nversion = "0"\n'
        )
        (self.project / "uv.lock").write_text(LOCK)
        (self.project / "verify-integrations.py").write_text(
            "import json, sys\n"
            "json.dump({'passed': ['fake-integration'], 'failed': []}, open(sys.argv[2], 'w'))\n"
        )
        (self.work / "src").mkdir()
        self.target = self.work / "target"

    def tearDown(self) -> None:
        for path in sorted(self.work.rglob("*"), reverse=True):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)
        self.raw.cleanup()

    def install(self, plugins: str) -> str:
        self.uv.with_suffix(".plugins").write_text(plugins)
        release_id: str = installer.install_environment(
            project=self.project,
            uv=self.uv,
            target=self.target,
            python=BASE_PYTHON,
            require_root=False,
        )
        return release_id

    def test_builds_a_frozen_release_whose_scripts_run_from_their_final_path(self) -> None:
        release_id = self.install("certbot-dns-alpha certbot-dns-beta")

        lock_hash = hashlib.sha256(LOCK.encode()).hexdigest()[:12]
        self.assertEqual(release_id, f"5.8.0-{lock_hash}")
        release = self.target / "releases" / release_id
        self.assertEqual((self.target / "current").readlink(), Path("releases") / release_id)
        metadata = json.loads((release / "INSTALLATION.json").read_text())
        self.assertEqual(metadata["certbot"], "5.8.0")
        self.assertEqual(metadata["plugins"], ["dns-alpha", "dns-beta"])
        self.assertEqual(metadata["integrations"], ["fake-integration"])
        self.assertEqual((release / "uv.lock").read_text(), LOCK)

        script = release / "venv" / "bin" / "certbot"
        self.assertTrue(script.read_text().startswith(f"#!{release / 'venv' / 'bin' / 'python'}\n"))
        self.assertNotIn(".5.8.0-", script.read_text())
        completed = subprocess.run(  # noqa: S603 - the release's own script
            [str(script)], check=True, capture_output=True, text=True
        )
        self.assertEqual(completed.stdout, "certbot\n")

        self.assertEqual(stat.S_IMODE(release.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((release / "venv" / "pyvenv.cfg").stat().st_mode), 0o444)
        self.assertEqual((release / "venv" / "lib64").readlink(), Path("lib"))
        self.assertEqual([p.name for p in (self.target / "releases").iterdir()], [release_id])

    def test_the_same_lock_is_not_rebuilt_and_a_changed_lock_is_a_new_release(self) -> None:
        first = self.install("certbot-dns-alpha")
        (self.target / "current").unlink()
        self.assertEqual(self.install("certbot-dns-alpha"), first)
        self.assertEqual((self.target / "current").readlink(), Path("releases") / first)

        (self.project / "uv.lock").write_text(LOCK.replace("5.8.0", "5.9.0"))
        second = self.install("certbot-dns-alpha")
        self.assertNotEqual(first, second)
        self.assertTrue(second.startswith("5.9.0-"))
        self.assertEqual((self.target / "current").readlink(), Path("releases") / second)
        self.assertTrue((self.target / "releases" / first).is_dir())

    def test_a_plugin_that_does_not_load_or_registers_nothing_refuses_the_release(self) -> None:
        for plugins, expected in (
            ("certbot-dns-alpha certbot-dns-broken:broken", "plugins that do not load"),
            ("certbot-dns-alpha certbot-dns-quiet:silent", "register no plugin"),
            ("", "no certbot plugins at all"),
        ):
            with self.subTest(plugins=plugins):
                with self.assertRaises(installer.InstallError) as caught:
                    self.install(plugins)
                self.assertIn(expected, str(caught.exception))
                self.assertFalse((self.target / "current").exists())
                self.assertEqual(list((self.target / "releases").iterdir()), [])

    def test_a_project_that_is_not_ours_or_pins_no_certbot_is_refused(self) -> None:
        (self.project / "uv.lock").write_text("version = 1\n")
        with self.assertRaises(installer.InstallError) as caught:
            self.install("certbot-dns-alpha")
        self.assertIn("does not pin certbot", str(caught.exception))

        (self.project / "uv.lock").write_text(LOCK)
        (self.project / "pyproject.toml").write_text('[project]\nname = "something-else"\n')
        with self.assertRaises(installer.InstallError) as caught:
            self.install("certbot-dns-alpha")
        self.assertIn("is not the haprion-certbot-env project", str(caught.exception))

    def test_a_failed_or_missing_integration_verifier_refuses_the_release(self) -> None:
        verifier = self.project / "verify-integrations.py"
        verifier.write_text(
            "import json, sys\n"
            "json.dump({'passed': [], 'failed': ['mock failed']}, open(sys.argv[2], 'w'))\n"
            "raise SystemExit(1)\n"
        )
        with self.assertRaisesRegex(installer.InstallError, "integration checks failed"):
            self.install("certbot-dns-alpha")
        self.assertFalse((self.target / "current").exists())

        verifier.unlink()
        with self.assertRaisesRegex(installer.InstallError, "regular non-symlink file"):
            self.install("certbot-dns-alpha")

    def test_without_a_source_tree_the_installed_engine_answers_the_catalogue(self) -> None:
        """From the haprion-ui package there is no src/ beside certbot/ (26-10-09)."""

        (self.work / "src").rmdir()
        engine = self.work / "installed-engine"
        engine.mkdir()
        with mock.patch.object(installer, "INSTALLED_ENGINE", engine):
            self.assertEqual(installer.engine_root(self.project), engine)
        with (
            mock.patch.object(installer, "INSTALLED_ENGINE", self.work / "absent"),
            self.assertRaisesRegex(installer.InstallError, "no engine"),
        ):
            installer.engine_root(self.project)


VERIFIER_PATH = INSTALLER_PATH.parents[1] / "certbot" / "verify-integrations.py"


class OfflineVerifierTests(unittest.TestCase):
    def test_the_network_block_leaves_socket_a_class_that_refuses(self) -> None:
        """dnspython annotates `socket.socket | ssl.SSLSocket`; before Python 3.14
        that is evaluated at import, and a function in its place failed every
        lexicon plugin on a Debian 13 manager (26-10-14). Run apart: the block
        patches the socket module for the whole process."""

        probe = textwrap.dedent(
            f"""\
            import runpy, socket, ssl
            runpy.run_path({str(VERIFIER_PATH)!r}, run_name="verifier")["forbid_network"]()
            assert isinstance(socket.socket | ssl.SSLSocket, object)
            try:
                socket.socket()
            except RuntimeError as exc:
                assert "network access" in str(exc), exc
            else:
                raise AssertionError("a socket was created")
            """
        )
        completed = subprocess.run(  # noqa: S603 - this interpreter and a fixed probe
            [sys.executable, "-I", "-c", probe],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()


class TheSameLockGivesTheSameTree(unittest.TestCase):
    """Two builds of one lock differed (26-10-17): bytecode carried the staging
    path and the source's time, the scripts' RECORD lines the staging path's
    digest, and two plugins' stray `tests/conftest.py` the install order."""

    def venv(self, root: Path) -> Path:
        venv = root / "venv"
        site = venv / "lib" / PYTHON_TAG / "site-packages"
        (site / "pkg").mkdir(parents=True)
        (site / "pkg" / "__init__.py").write_text("VALUE = 1\n")
        (site / "tests").mkdir()
        (site / "tests" / "conftest.py").write_text("x = 1\n")
        (site / "pkg-1.0.dist-info").mkdir()
        (venv / "bin").mkdir()
        (venv / "bin" / "python").symlink_to(BASE_PYTHON)
        (venv / "bin" / "tool").write_text(f"#!{venv}/bin/python\nimport pkg\n")
        (site / "pkg-1.0.dist-info" / "RECORD").write_text(
            "pkg/__init__.py,sha256=x,10\n"
            "tests/conftest.py,sha256=y,6\n"
            "../../../bin/tool,sha256=stale,40\n"
            "pkg-1.0.dist-info/RECORD,,\n"
        )
        return venv

    def test_the_stray_tests_go_with_their_record_lines(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            venv = self.venv(Path(directory))
            installer._drop_stray_tests(venv)
            site = venv / "lib" / PYTHON_TAG / "site-packages"
            self.assertFalse((site / "tests").exists())
            self.assertNotIn("tests/", (site / "pkg-1.0.dist-info" / "RECORD").read_text())

    def test_a_relocated_script_has_its_true_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            venv = self.venv(Path(directory))
            final = Path("/opt/haprion-certbot/releases/x/venv")
            installer._relocate_scripts(venv, final)
            script = (venv / "bin" / "tool").read_bytes()
            self.assertTrue(script.startswith(f"#!{final}/bin/python\n".encode()))
            record = (
                venv / "lib" / PYTHON_TAG / "site-packages/pkg-1.0.dist-info/RECORD"
            ).read_text()
            self.assertIn(
                f"../../../bin/tool,{installer._record_digest(script)},{len(script)}\n", record
            )

    def test_bytecode_is_the_same_from_two_staging_paths(self) -> None:
        final = Path("/opt/haprion-certbot/releases/x/venv")
        compiled = []
        for name in ("one", "two"):
            with tempfile.TemporaryDirectory(prefix=name) as directory:
                venv = self.venv(Path(directory))
                stale = venv / "lib" / PYTHON_TAG / "site-packages/pkg/__pycache__"
                stale.mkdir()
                (stale / "junk.pyc").write_bytes(b"old")
                installer._compile(venv, final)
                caches = sorted((venv / "lib").rglob("*.pyc"))
                self.assertNotIn("junk.pyc", [path.name for path in caches])
                pyc = next(path for path in caches if path.name.startswith("__init__."))
                compiled.append(pyc.read_bytes())
        self.assertEqual(compiled[0], compiled[1])
        self.assertIn(str(final).encode(), compiled[0])
