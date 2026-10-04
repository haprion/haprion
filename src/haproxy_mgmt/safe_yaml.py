"""One safe YAML reader for every document the engine reads (review 2026-10-03, K7).

`yaml.safe_load` always uses PyYAML's pure-Python `SafeLoader`, even where the
installed PyYAML carries LibYAML. `CSafeLoader` builds the same safe types from
the same documents about six times faster (measured 26-10-04 on two CPUs: 1 000
object loads, 1.05 s against 0.17 s, the same models), and is still the safe loader: no Python
objects, no arbitrary tags. Where LibYAML is missing the Python loader is used,
so the result never depends on which one is installed - only the speed does.

Never `yaml.CLoader`, `yaml.Loader` or `unsafe_load`: every document here is
one a person or a node could have written.
"""

from __future__ import annotations

from typing import Any

import yaml

SafeLoader: type[yaml.SafeLoader] = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def load(text: str | bytes) -> Any:
    """`yaml.safe_load`, with LibYAML's safe loader when it is installed."""

    return yaml.load(text, Loader=SafeLoader)  # noqa: S506 - a safe loader, never yaml.Loader
