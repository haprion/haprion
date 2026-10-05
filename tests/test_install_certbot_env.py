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
            '[project]\nname = "haproxy-manager-certbot-env"\nversion = "0"\n'
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
        self.assertIn("is not the haproxy-manager-certbot-env project", str(caught.exception))

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


if __name__ == "__main__":
    unittest.main()
