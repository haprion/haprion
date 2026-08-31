"""Where the golden cases live and how one is loaded.

A golden case is a directory: the proxy objects that go in, as `.yaml`, and the
configuration that must come out, as `.cfg`. Adding a case is dropping a
directory in - there is no list to remember to update, which is the only kind of
list that stays correct.

Shared between the test that checks the cases and the tool that rewrites them,
so that the two cannot disagree about what a case is. A tool that regenerated
something slightly different from what the test compares would make the test
pass by writing its own expectations.
"""

from __future__ import annotations

from pathlib import Path

from haproxy_mgmt.generate import generate
from haproxy_mgmt.proxy_model import Proxy, load_proxy

GOLDEN = Path(__file__).resolve().parents[2] / "tests" / "golden"


def cases(root: Path = GOLDEN) -> list[Path]:
    return sorted(path for path in root.iterdir() if path.is_dir())


def objects(case: Path) -> list[Proxy]:
    """The case's input, read as bytes exactly as the generator will read it."""

    return [load_proxy(path.stem, path.read_bytes()) for path in sorted(case.glob("*.yaml"))]


def expected(case: Path) -> dict[str, str]:
    return {path.name: path.read_text() for path in sorted(case.glob("*.cfg"))}


def produced(case: Path) -> dict[str, str]:
    return generate(objects(case))
