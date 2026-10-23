"""The watch over the WAF packages' upstream sources (B323, B337), offline."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

import yaml

BASE = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
LATER_COMMIT = "b" * 40
OUTSIDE_COMMIT = "c" * 40


def load(name: str, relative: Path) -> Any:
    loader = importlib.machinery.SourceFileLoader(name, str(relative))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


WATCH = load("upstream_watch", BASE / "tools" / "upstream-watch")


def archive(top: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo(f"{top}/README")
        info.size = 2
        tar.addfile(info, io.BytesIO(b"x\n"))
    return buffer.getvalue()


class Upstream:
    """Upstream as the tests set it: releases, tags, files, signatures."""

    def __init__(self, signer: Signer) -> None:
        self.signer = signer
        self.coraza: list[dict[str, Any]] = []
        self.crs: list[dict[str, Any]] = []
        self.go: list[dict[str, Any]] = []
        self.vuln: list[str] = []
        self.tag_commits: dict[str, str] = {}
        self.containing: set[str] = set()
        self.files: dict[str, bytes] = {}

    def releases(self, repository: str) -> list[dict[str, Any]]:
        return {WATCH.CORAZA_REPOSITORY: self.coraza, WATCH.CRS_REPOSITORY: self.crs}[repository]

    def contains(self, repository: str, tag: str, commit: str) -> bool:
        return tag in self.containing

    def tag_commit(self, repository: str, tag: str) -> str:
        return self.tag_commits.get(tag, LATER_COMMIT)

    def commit_date(self, repository: str, commit: str) -> str:
        return "2026-10-01T00:00:00Z"

    def tags(self, repository: str) -> list[str]:
        return self.vuln

    def go_releases(self) -> list[dict[str, Any]]:
        return self.go

    def download(self, url: str) -> bytes:
        return self.files[url]

    # Setting it up

    def coraza_release(
        self, tag: str, *, contains: bool = True, commit: str = LATER_COMMIT
    ) -> None:
        self.coraza.append({"tag_name": tag, "published_at": "2026-10-01T00:00:00Z"})
        self.tag_commits[tag] = commit
        if contains:
            self.containing.add(tag)
        url = f"https://github.com/{WATCH.CORAZA_REPOSITORY}/archive/{commit}.tar.gz"
        self.files[url] = archive(f"coraza-spoa-{commit}")

    def crs_release(self, text: str, *, lts: bool = True, signed: bool = True) -> None:
        tag = f"v{text}"
        self.crs.append(
            {
                "tag_name": tag,
                "name": f"{tag} (LTS)" if lts else tag,
                "published_at": "2026-10-01T00:00:00Z",
            }
        )
        file = f"coreruleset-{text}-minimal.tar.gz"
        url = f"https://github.com/{WATCH.CRS_REPOSITORY}/releases/download/{tag}/{file}"
        data = archive(f"coreruleset-{text}")
        self.files[url] = data
        self.files[url + ".asc"] = self.signer.sign(data if signed else data + b"tampered")

    def go_release(self, name: str) -> None:
        self.go.append(
            {
                "version": name,
                "stable": True,
                "files": [
                    {"os": "linux", "arch": "amd64", "kind": "archive", "sha256": "d" * 64},
                    {"os": "darwin", "arch": "arm64", "kind": "archive", "sha256": "e" * 64},
                ],
            }
        )


class Signer:
    """A throwaway key standing in for the rule set's release key."""

    def __init__(self, work: Path) -> None:
        self.home = work / "gnupg"
        self.home.mkdir(mode=0o700)
        self.env = {"PATH": "/usr/bin:/bin", "GNUPGHOME": str(self.home)}
        self.gpg = ["/usr/bin/gpg", "--batch", "--quiet", "--pinentry-mode", "loopback"]
        subprocess.run(
            [*self.gpg, "--passphrase", "", "--quick-gen-key", "test", "ed25519", "sign", "1d"],
            check=True,
            env=self.env,
        )
        self.public = subprocess.run(
            [*self.gpg, "--armor", "--export"], check=True, env=self.env, capture_output=True
        ).stdout

    def sign(self, data: bytes) -> bytes:
        return subprocess.run(
            [*self.gpg, "--passphrase", "", "--armor", "--detach-sign"],
            input=data,
            check=True,
            env=self.env,
            capture_output=True,
        ).stdout

    def close(self) -> None:
        subprocess.run(["/usr/bin/gpgconf", "--kill", "all"], check=False, env=self.env)


@unittest.skipUnless(shutil.which("gpg") and shutil.which("gpgv"), "needs gpg")
class TheWatch(unittest.TestCase):
    work: ClassVar[Path]
    signer: ClassVar[Signer]

    @classmethod
    def setUpClass(cls) -> None:
        cls.work = Path(tempfile.mkdtemp(prefix="upstream-watch-test-"))
        cls.signer = Signer(cls.work)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.signer.close()
        shutil.rmtree(cls.work)

    def setUp(self) -> None:
        self.tree = Path(tempfile.mkdtemp(prefix="tree-", dir=self.work))
        (self.tree / "tools").mkdir()
        for name in ("build-coraza-package.py", "build-release-packages"):
            shutil.copy(BASE / "tools" / name, self.tree / "tools" / name)
        shutil.copytree(BASE / "src", self.tree / "src")
        (self.tree / "keys" / "upstream").mkdir(parents=True)
        (self.tree / "keys" / "upstream" / "coreruleset.asc").write_bytes(self.signer.public)
        # The pins as a known starting point, whatever the tree pins today.
        engine = self.tree / "tools" / "build-coraza-package.py"
        WATCH.replace_source(
            engine,
            "CORAZA",
            revision=("CORAZA_REVISION", "8"),
            comment="The pin the tests start from.",
            file=f"coraza-spoa-{COMMIT}.tar.gz",
            sha256="f" * 64,
            top=f"coraza-spoa-{COMMIT}",
            version="0.9.0",
            url=f"https://github.com/{WATCH.CORAZA_REPOSITORY}/archive/{COMMIT}.tar.gz",
        )
        WATCH.replace_source(
            engine,
            "CRS",
            revision=("CRS_REVISION", "1"),
            file="coreruleset-4.25.2-minimal.tar.gz",
            sha256="f" * 64,
            top="coreruleset-4.25.2",
            version="4.25.2",
            url="https://example.com/coreruleset-4.25.2-minimal.tar.gz",
        )
        WATCH.replace_constant(engine, "GO_VERSION", "go1.26.9")
        WATCH.replace_constant(engine, "GOVULNCHECK_VERSION", "v1.8.0")
        WATCH.replace_go_archives(
            self.tree / "tools" / "build-release-packages", "go1.26.9", "f" * 64
        )
        self.upstream = Upstream(self.signer)

    def engine(self) -> Any:
        return WATCH.load(self.tree / "tools" / "build-coraza-package.py", "test_engine")

    def release(self) -> Any:
        return WATCH.load(self.tree / "tools" / "build-release-packages", "test_release")

    def check(self, **kwargs: bool) -> dict[str, list[dict[str, str]]]:
        options = {"apply": True, "security_only": False, **kwargs}
        result: dict[str, list[dict[str, str]]] = WATCH.check(self.tree, self.upstream, **options)
        return result

    def test_nothing_newer_proposes_nothing(self) -> None:
        self.upstream.coraza_release("v0.9.0")
        self.upstream.crs_release("4.25.2")
        self.upstream.go_release("go1.26.9")
        self.upstream.vuln.append("v1.8.0")
        self.assertEqual(self.check(), {"proposed": [], "held": []})

    def test_an_engine_release_with_the_pinned_commit_is_pinned_by_its_commit(self) -> None:
        self.upstream.coraza_release("v0.9.1")
        result = self.check()
        self.assertEqual(
            [(c["component"], c["proposed"], c["kind"]) for c in result["proposed"]],
            [("coraza", "0.9.1", "patch")],
        )
        engine = self.engine()
        self.assertEqual(engine.CORAZA.version, "0.9.1")
        self.assertEqual(engine.CORAZA.top, f"coraza-spoa-{LATER_COMMIT}")
        self.assertIn(LATER_COMMIT, engine.CORAZA.url)
        self.assertEqual(engine.CORAZA_REVISION, "1")
        # The comment that explained the old pin does not stay with the new one.
        text = (self.tree / "tools" / "build-coraza-package.py").read_text()
        self.assertNotIn("The pin the tests start from.", text)
        self.assertIn("Release v0.9.1", text)

    def test_a_release_without_the_pinned_commit_is_not_a_candidate(self) -> None:
        # The engine is on a commit for a security fix (S04); a release that
        # leaves it out would take the fix away again.
        self.upstream.coraza_release("v0.9.1", contains=False)
        self.assertEqual(self.check()["proposed"], [])

    def test_an_engine_minor_step_below_one_waits_for_a_person(self) -> None:
        self.upstream.coraza_release("v0.10.0")
        result = self.check()
        self.assertEqual(result["proposed"], [])
        self.assertEqual([c["proposed"] for c in result["held"]], ["0.10.0"])
        self.assertEqual(self.engine().CORAZA.version, "0.9.0")

    def test_the_rule_set_follows_its_lts_line(self) -> None:
        self.upstream.crs_release("4.30.0", lts=False)
        self.upstream.crs_release("4.25.3")
        self.upstream.crs_release("4.31.0")  # a new LTS line
        result = self.check()
        self.assertEqual(
            [(c["proposed"], c["kind"]) for c in result["proposed"]], [("4.25.3", "patch")]
        )
        self.assertEqual([c["proposed"] for c in result["held"]], ["4.31.0"])
        engine = self.engine()
        self.assertEqual(engine.CRS.version, "4.25.3")
        self.assertEqual(engine.CRS_REVISION, "1")

    def test_a_rule_set_its_key_did_not_sign_is_refused(self) -> None:
        self.upstream.crs_release("4.25.3", signed=False)
        before = (self.tree / "tools" / "build-coraza-package.py").read_bytes()
        with self.assertRaisesRegex(WATCH.WatchError, "signature does not verify"):
            self.check()
        self.assertEqual((self.tree / "tools" / "build-coraza-package.py").read_bytes(), before)

    def test_a_go_patch_moves_the_digest_and_the_engine_revision(self) -> None:
        self.upstream.go_release("go1.26.10")
        self.upstream.go_release("go1.27.0")
        result = self.check()
        self.assertEqual([c["proposed"] for c in result["proposed"]], ["go1.26.10"])
        self.assertEqual([c["proposed"] for c in result["held"]], ["go1.27.0"])
        engine, release = self.engine(), self.release()
        self.assertEqual(engine.GO_VERSION, "go1.26.10")
        self.assertEqual(release.GO_ARCHIVES, {"go1.26.10": "d" * 64})
        # Another Go is another binary: apt takes it only under a new version.
        self.assertEqual(engine.CORAZA_REVISION, "9")

    def test_a_new_engine_release_with_a_new_go_starts_its_revision_over(self) -> None:
        self.upstream.go_release("go1.26.10")
        self.upstream.coraza_release("v0.9.1")
        self.check()
        self.assertEqual(self.engine().CORAZA_REVISION, "1")

    def test_a_new_scanner_changes_no_package(self) -> None:
        self.upstream.vuln.extend(["v1.9.0", "v1.8.0", "v2.0.0", "v1.9.0-rc1"])
        result = self.check()
        self.assertEqual([c["proposed"] for c in result["proposed"]], ["v1.9.0"])
        self.assertEqual([c["proposed"] for c in result["held"]], ["v2.0.0"])
        engine = self.engine()
        self.assertEqual(engine.GOVULNCHECK_VERSION, "v1.9.0")
        self.assertEqual(engine.CORAZA_REVISION, "8")

    def test_a_security_proposal_leaves_the_rules_out(self) -> None:
        self.upstream.go_release("go1.26.10")
        self.upstream.crs_release("4.25.3")
        result = self.check(security_only=True)
        self.assertEqual([c["component"] for c in result["proposed"]], ["go"])
        self.assertEqual(self.engine().CRS.version, "4.25.2")

    def test_without_apply_the_tree_is_left_alone(self) -> None:
        self.upstream.go_release("go1.26.10")
        before = (self.tree / "tools" / "build-coraza-package.py").read_bytes()
        self.assertEqual(len(self.check(apply=False)["proposed"]), 1)
        self.assertEqual((self.tree / "tools" / "build-coraza-package.py").read_bytes(), before)

    def test_the_change_between_trees_is_read_again_from_upstream(self) -> None:
        base = self.tree
        self.upstream.go_release("go1.26.10")
        self.upstream.coraza_release("v0.9.1")
        head = Path(tempfile.mkdtemp(prefix="head-", dir=self.work))
        shutil.copytree(base, head, dirs_exist_ok=True)
        WATCH.check(head, self.upstream, apply=True, security_only=False)
        changes = WATCH.changes_between(base, head, self.upstream)
        self.assertEqual(sorted(c.component for c in changes), ["coraza", "go"])
        # A head pinned at a commit the tag does not name is not merged.
        self.upstream.tag_commits["v0.9.1"] = OUTSIDE_COMMIT
        with self.assertRaisesRegex(WATCH.WatchError, "does not name"):
            WATCH.changes_between(base, head, self.upstream)


class WhenItIsDue(unittest.TestCase):
    RELEASED = datetime(2026, 10, 1, tzinfo=UTC)

    def change(self, component: str, kind: str = "patch") -> Any:
        return WATCH.Change(component, "1", "2", kind, self.RELEASED.isoformat())

    def test_seven_days_after_the_upstream_release(self) -> None:
        changes = [self.change("crs")]
        at = self.RELEASED + timedelta(days=7)
        self.assertFalse(WATCH.due(changes, vulnerable=False, now=at - timedelta(minutes=1))[0])
        self.assertTrue(WATCH.due(changes, vulnerable=False, now=at)[0])

    def test_two_days_when_the_pinned_engine_is_vulnerable(self) -> None:
        changes = [self.change("go"), self.change("coraza")]
        self.assertTrue(
            WATCH.due(changes, vulnerable=True, now=self.RELEASED + timedelta(days=2))[0]
        )

    def test_the_rules_never_ride_on_a_security_wait(self) -> None:
        changes = [self.change("go"), self.change("crs")]
        at = self.RELEASED + timedelta(days=2)
        self.assertFalse(WATCH.due(changes, vulnerable=True, now=at)[0])

    def test_a_major_change_is_never_due(self) -> None:
        changes = [self.change("go", "major")]
        ready, reason = WATCH.due(changes, vulnerable=True, now=self.RELEASED + timedelta(days=99))
        self.assertFalse(ready)
        self.assertIn("person", reason)

    def test_a_person_can_lift_the_cooldown_but_not_the_major_rule(self) -> None:
        self.assertTrue(
            WATCH.due([self.change("crs")], vulnerable=False, now=self.RELEASED, cooldown=False)[0]
        )
        major = [self.change("go", "major")]
        self.assertFalse(WATCH.due(major, vulnerable=False, now=self.RELEASED, cooldown=False)[0])

    def test_nothing_is_not_due(self) -> None:
        self.assertFalse(WATCH.due([], vulnerable=False, now=self.RELEASED)[0])


class WhetherTheWatchStillRuns(unittest.TestCase):
    REGISTERED = datetime(2026, 10, 19, 19, 1, 3, tzinfo=UTC)
    WORKFLOW: ClassVar[dict[str, Any]] = {
        "state": "active",
        "created_at": "2026-10-19T21:01:03.000+02:00",
    }

    def run_at(self, at: datetime) -> dict[str, Any]:
        return {"created_at": at.strftime("%Y-%m-%dT%H:%M:%SZ"), "event": "schedule"}

    def test_a_scheduled_run_inside_the_window(self) -> None:
        last = self.REGISTERED + timedelta(days=3)
        self.assertTrue(WATCH.ran(self.WORKFLOW, self.run_at(last), last + timedelta(hours=47))[0])

    def test_two_nights_without_a_run_is_a_watch_that_stopped(self) -> None:
        last = self.REGISTERED + timedelta(days=3)
        ok, reason = WATCH.ran(self.WORKFLOW, self.run_at(last), last + timedelta(hours=49))
        self.assertFalse(ok)
        self.assertIn("48 hours", reason)

    def test_before_the_first_run_the_window_counts_from_the_registration(self) -> None:
        self.assertTrue(WATCH.ran(self.WORKFLOW, None, self.REGISTERED + timedelta(hours=47))[0])
        ok, reason = WATCH.ran(self.WORKFLOW, None, self.REGISTERED + timedelta(hours=49))
        self.assertFalse(ok)
        self.assertIn("no scheduled run", reason)

    def test_a_disabled_watch_has_stopped_whatever_ran_last(self) -> None:
        # GitHub turns a public repository's schedules off after 60 quiet days.
        workflow = {**self.WORKFLOW, "state": "disabled_inactivity"}
        ok, reason = WATCH.ran(workflow, self.run_at(self.REGISTERED), self.REGISTERED)
        self.assertFalse(ok)
        self.assertIn("disabled_inactivity", reason)

    def test_the_window_allows_one_dropped_night_and_no_more(self) -> None:
        # The window is two of the schedule's intervals: a daily cron.
        watch = yaml.safe_load((BASE / ".github" / "workflows" / "upstream-watch.yml").read_text())
        (schedule,) = watch[True]["schedule"]
        minute, hour, *rest = schedule["cron"].split()
        self.assertTrue(minute.isdigit() and hour.isdigit())
        self.assertEqual(rest, ["*", "*", "*"])
        self.assertEqual(WATCH.SCHEDULE_WINDOW, timedelta(days=2))

    def test_ci_asks_about_the_workflow_the_tool_names(self) -> None:
        workflows = BASE / ".github" / "workflows"
        self.assertTrue((workflows / WATCH.WORKFLOW).is_file())
        ci = yaml.safe_load((workflows / "ci.yml").read_text())
        (step,) = [
            s
            for s in ci["jobs"]["upstream-watch-ran"]["steps"]
            if "upstream-watch ran" in s.get("run", "")
        ]
        self.assertIn("--repository", step["run"])


class ThePinsInTheTree(unittest.TestCase):
    def test_the_tree_is_pinned_the_way_the_watch_reads_it(self) -> None:
        # A hand edit that left the form the watch rewrites fails here, not in
        # the scheduled job.
        pins = WATCH.read_pins(BASE)
        self.assertRegex(pins.coraza_commit, r"^[0-9a-f]{40}$")
        text = (BASE / "tools" / "build-coraza-package.py").read_text()
        for name in ("GO_VERSION", "GOVULNCHECK_VERSION", "CORAZA_REVISION", "CRS_REVISION"):
            self.assertRegex(text, rf'(?m)^{name} = "[^"]+"$')
        for name in ("CORAZA", "CRS"):
            self.assertRegex(text, rf"(?ms)^{name} = Source\(\n.*?^\)$")
        release = (BASE / "tools" / "build-release-packages").read_text()
        self.assertRegex(release, r"(?ms)^GO_ARCHIVES = \{\n.*?^\}$")

    def test_a_proposal_passes_the_package_tests(self) -> None:
        # A test that pins the tree's revision fails every proposal that moves
        # it, and the merge waits forever (PR #3, 2026-10-20).
        with tempfile.TemporaryDirectory(prefix="proposal-") as work:
            tree = Path(work)
            (tree / "tests").mkdir()
            shutil.copytree(BASE / "tools", tree / "tools")
            shutil.copy(BASE / "tests" / "test_coraza_package.py", tree / "tests")
            shutil.copytree(BASE / "src", tree / "src")
            engine = tree / "tools" / "build-coraza-package.py"
            WATCH.next_revision(engine, "CORAZA_REVISION")
            WATCH.next_revision(engine, "CRS_REVISION")
            done = subprocess.run(
                [sys.executable, "-m", "unittest", "test_coraza_package"],
                cwd=tree / "tests",
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])

    def test_the_rule_set_key_is_the_one_the_comment_names(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gnupg-") as home:
            listing = subprocess.run(
                [
                    "/usr/bin/gpg",
                    "--homedir",
                    home,
                    "--show-keys",
                    "--with-colons",
                    str(BASE / WATCH.CRS_KEY),
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        fingerprints = [
            line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
        ]
        self.assertEqual(fingerprints[0], "36006F0E0BA167832158821138EEACA1AB8A6E72")


class TheScratchDirectory(unittest.TestCase):
    def test_a_read_only_module_cache_is_removed_before_and_after(self) -> None:
        # Go leaves its module cache read-only; ignored, it outlived the run and
        # the next one stopped on "File exists" (26-10-21).
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)

            def go_was_here(work: Path) -> None:
                module = work / "gomodcache" / "example.com" / "m@v1.0.0"
                module.mkdir(parents=True)
                (module / "go.mod").write_text("module example.com/m\n")
                (module / "go.mod").chmod(0o444)
                for directory in (module, module.parent, work / "gomodcache"):
                    directory.chmod(0o555)

            go_was_here(cache / "upstream-watch")
            with WATCH.scratch(cache) as work:
                self.assertEqual(list(work.iterdir()), [])
                go_was_here(work)
            self.assertFalse((cache / "upstream-watch").exists())


class TheWorkflow(unittest.TestCase):
    def test_every_check_the_merge_waits_for_is_a_job_that_exists(self) -> None:
        # A renamed job would leave the merge waiting for a check that never
        # comes - every proposal held, and nothing saying why.
        workflows = BASE / ".github" / "workflows"
        watch = yaml.safe_load((workflows / "upstream-watch.yml").read_text())
        (step,) = [s for s in watch["jobs"]["merge"]["steps"] if "REQUIRED" in s.get("env", {})]
        required = [line for line in step["env"]["REQUIRED"].splitlines() if line.strip()]
        self.assertIn("Source, quality, and security gates", required)
        names = {
            job.get("name")
            for path in workflows.glob("*.yml")
            for job in yaml.safe_load(path.read_text())["jobs"].values()
        }
        for name in required:
            self.assertIn(name, names)

    def test_a_finding_is_reported_rather_than_ending_the_scan(self) -> None:
        """The scan step as GitHub runs a `shell: bash` step: `bash -eo pipefail` (26-10-21).

        Under `-e` the step ended on the scanner's 3 before it wrote
        `vulnerable=true`: the night's finding failed the run, no issue was
        opened, and the proposal job never ran.
        """

        watch = yaml.safe_load((BASE / ".github/workflows/upstream-watch.yml").read_text())
        (step,) = [s for s in watch["jobs"]["vulnerabilities"]["steps"] if s.get("id") == "scan"]
        self.assertEqual(step["shell"], "bash")
        for code, outcome, output in (
            (0, 0, "vulnerable=false"),
            (3, 0, "vulnerable=true"),
            (2, 2, ""),
        ):
            with self.subTest(scanner=code), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "bin").mkdir()
                stub = root / "bin" / "python3"
                stub.write_text(f"#!/bin/sh\necho report\nexit {code}\n")
                stub.chmod(0o755)
                (root / "step.sh").write_text(step["run"])
                (root / "output").write_text("")
                result = subprocess.run(
                    [
                        "/bin/bash",
                        "--noprofile",
                        "--norc",
                        "-eo",
                        "pipefail",
                        str(root / "step.sh"),
                    ],
                    env={
                        "PATH": f"{root / 'bin'}:/usr/bin:/bin",
                        "RUNNER_TEMP": str(root),
                        "GITHUB_OUTPUT": str(root / "output"),
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, outcome, result.stderr)
                self.assertEqual((root / "output").read_text().strip(), output)
                self.assertEqual((root / "vulnerabilities.txt").read_text(), "report\n")

    def test_an_unchanged_proposal_s_failed_checks_run_again(self) -> None:
        """A failure from outside no longer holds the proposal for good (26-10-21)."""

        watch = yaml.safe_load((BASE / ".github/workflows/upstream-watch.yml").read_text())
        job = watch["jobs"]["propose"]
        self.assertEqual(job["permissions"], {"contents": "read", "actions": "write"})
        (keep,) = [s for s in job["steps"] if s.get("id") == "proposal"]
        self.assertIn('echo "unchanged=true" >> "${GITHUB_OUTPUT}"', keep["run"])
        (step,) = [
            s for s in job["steps"] if s.get("name") == "Run the proposal's failed checks again"
        ]
        self.assertEqual(step["if"], "steps.proposal.outputs.unchanged == 'true'")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            stub = root / "bin" / "gh"
            stub.write_text(
                "#!/bin/sh\n"
                f'echo "$*" >> {root / "calls"}\n'
                'case "$*" in\n'
                "  *branches/upstream-watch*) echo 0123abcd ;;\n"
                '  *"head_sha=0123abcd&status=failure"*) printf "11\\n12\\n" ;;\n'
                "esac\n"
            )
            stub.chmod(0o755)
            (root / "step.sh").write_text(step["run"])
            result = subprocess.run(
                ["/bin/bash", "--noprofile", "--norc", "-eo", "pipefail", str(root / "step.sh")],
                env={
                    "PATH": f"{root / 'bin'}:/usr/bin:/bin",
                    "REPOSITORY": "example/repo",
                    "BRANCH": "upstream-watch",
                },
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            posts = [line for line in (root / "calls").read_text().splitlines() if "POST" in line]
        self.assertEqual(
            posts,
            [
                "api --method POST repos/example/repo/actions/runs/11/rerun-failed-jobs",
                "api --method POST repos/example/repo/actions/runs/12/rerun-failed-jobs",
            ],
        )

    def test_no_step_reads_a_status_the_shell_never_reaches(self) -> None:
        """A status read on its own line runs only after success under GitHub's `bash -e`."""

        alone = re.compile(r"^\s*\w+=(\$\?|\$\{PIPESTATUS)", re.MULTILINE)
        for path in sorted((BASE / ".github" / "workflows").glob("*.yml")):
            for name, job in yaml.safe_load(path.read_text())["jobs"].items():
                for step in job.get("steps", []):
                    script = step.get("run", "")
                    with self.subTest(workflow=path.name, job=name, step=step.get("name")):
                        if "set +e" not in script:
                            self.assertIsNone(alone.search(script))


def audit_answer(*found: tuple[str, str, str, list[str]]) -> str:
    """`uv audit --output-format json` as uv 0.12.5 writes it (measured 26-10-23)."""

    return json.dumps(
        {
            "schema": {"version": "preview"},
            "summary": {
                "audited_packages": 10,
                "vulnerabilities": len(found),
                "adverse_statuses": 0,
            },
            "vulnerabilities": [
                {
                    "dependency": {"name": name, "version": version},
                    "id": advisory,
                    "fix_versions": fixed,
                }
                for name, version, advisory, fixed in found
            ],
            "adverse_statuses": [],
        }
    )


class FakeUv:
    """Audits answer from a script per project; `uv lock` writes the upgraded version."""

    def __init__(self, tree: Path, audits: dict[str, list[str]], upgrade: dict[str, str]) -> None:
        self.tree = tree
        self.audits = {project: list(answers) for project, answers in audits.items()}
        self.upgrade = upgrade
        self.locked: list[tuple[str, list[str]]] = []

    def __call__(self, argv: list[str], *, cwd: Path, **_: Any) -> subprocess.CompletedProcess[str]:
        project = str(Path(cwd).relative_to(self.tree)) or "."
        if argv[:2] == ["uv", "audit"]:
            answer = self.audits[project].pop(0)
            return subprocess.CompletedProcess(argv, 1 if '"id"' in answer else 0, answer, "")
        self.locked.append((project, argv[2:]))
        lock = Path(cwd) / "uv.lock"
        for package, version in self.upgrade.items():
            lock.write_text(
                lock.read_text().replace(
                    f'name = "{package}"\nversion = "1.0"',
                    f'name = "{package}"\nversion = "{version}"',
                )
            )
        return subprocess.CompletedProcess(argv, 0, "", "")


class TheLocks(unittest.TestCase):
    """B353: an advisory in a Python lock is fixed by the watch, not by whoever notices."""

    def tree(self) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        for project in WATCH.LOCKED_PROJECTS:
            (root / project).mkdir(exist_ok=True)
            (root / project / "uv.lock").write_text(
                'version = 1\n\n[[package]]\nname = "otel-api"\nversion = "1.0"\n'
            )
        return root

    def test_a_fixed_advisory_is_upgraded_and_said(self) -> None:
        root = self.tree()
        clean = audit_answer()
        found = audit_answer(("otel-api", "1.0", "GHSA-xxxx", ["1.1"]))
        uv = FakeUv(
            root,
            {".": [clean, clean], "ui": [clean, clean], "certbot": [found, clean]},
            {"otel-api": "1.1"},
        )

        result = WATCH.locks(root, apply=True, run=uv)

        self.assertEqual(uv.locked, [("certbot", ["--upgrade-package", "otel-api"])])
        self.assertEqual(result["held"], [])
        (updated,) = result["updated"]
        self.assertEqual(
            (updated["project"], updated["package"], updated["version"], updated["locked"]),
            ("certbot", "otel-api", "1.0", ["1.1"]),
        )

    def test_one_with_no_fix_or_one_the_upgrade_does_not_clear_is_held(self) -> None:
        root = self.tree()
        clean = audit_answer()
        unfixed = audit_answer(("otel-api", "1.0", "GHSA-none", []))
        kept = audit_answer(("otel-api", "1.0", "GHSA-kept", ["2.0"]))
        uv = FakeUv(
            root, {".": [unfixed, unfixed], "ui": [kept, kept], "certbot": [clean, clean]}, {}
        )

        result = WATCH.locks(root, apply=True, run=uv)

        self.assertEqual(uv.locked, [("ui", ["--upgrade-package", "otel-api"])])
        self.assertEqual(result["updated"], [])
        self.assertEqual(
            [entry["advisory"] for entry in result["held"]], ["GHSA-none", "GHSA-kept"]
        )

    def test_without_apply_nothing_is_written(self) -> None:
        root = self.tree()
        found = audit_answer(("otel-api", "1.0", "GHSA-xxxx", ["1.1"]))
        uv = FakeUv(root, {".": [found], "ui": [audit_answer()], "certbot": [audit_answer()]}, {})

        result = WATCH.locks(root, apply=False, run=uv)

        self.assertEqual(uv.locked, [])
        self.assertEqual([entry["advisory"] for entry in result["held"]], ["GHSA-xxxx"])

    def test_an_audit_that_failed_is_not_a_clean_lock(self) -> None:
        root = self.tree()
        for code, answer in ((2, "error: no network"), (1, "not json")):
            with self.subTest(code=code):

                def run(
                    argv: list[str], *, code: int = code, answer: str = answer, **_: Any
                ) -> subprocess.CompletedProcess[str]:
                    return subprocess.CompletedProcess(argv, code, answer, "boom")

                with self.assertRaises(WATCH.WatchError):
                    WATCH.locks(root, apply=True, run=run)

    def test_the_watch_audits_every_lock_the_gate_audits(self) -> None:
        gate = (BASE / "run-tests").read_text()
        audited = {"."} | set(re.findall(r'cd "\$base/(\w+)" && uv audit --locked', gate))
        self.assertEqual(audited, set(WATCH.LOCKED_PROJECTS))
        for project in WATCH.LOCKED_PROJECTS:
            self.assertTrue((BASE / project / "uv.lock").is_file(), project)

    def test_the_locks_proposal_waits_for_jobs_that_run_on_its_branch(self) -> None:
        workflows = BASE / ".github" / "workflows"
        watch = yaml.safe_load((workflows / "upstream-watch.yml").read_text())
        branch = watch["env"]["LOCKS_BRANCH"]
        (step,) = [
            s for s in watch["jobs"]["merge-locks"]["steps"] if "REQUIRED" in s.get("env", {})
        ]
        required = [line for line in step["env"]["REQUIRED"].splitlines() if line.strip()]
        ci = yaml.safe_load((workflows / "ci.yml").read_text())
        for job in ci["jobs"].values():
            if job.get("name") in required and "head_ref" in str(job.get("if", "")):
                with self.subTest(job=job["name"]):
                    self.assertIn(f"'{branch}'", job["if"])
        names = {job.get("name") for job in ci["jobs"].values()}
        for name in required:
            self.assertIn(name, names)
        uv = [
            step["with"]["version"]
            for path in (workflows / "ci.yml", workflows / "upstream-watch.yml")
            for job in yaml.safe_load(path.read_text())["jobs"].values()
            for step in job.get("steps", [])
            if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
        ]
        self.assertEqual(len(set(uv)), 1, uv)


if __name__ == "__main__":
    unittest.main()
