"""One safe YAML reader for every document the engine reads (review 2026-10-03, K7).

`yaml.safe_load` always uses PyYAML's pure-Python `SafeLoader`, even where the
installed PyYAML carries LibYAML. `CSafeLoader` builds the same safe types from
the same documents about six times faster (measured 26-10-04 on two CPUs: 1 000
object loads, 1.05 s against 0.17 s, the same models), and is still the safe loader: no Python
objects, no arbitrary tags. Where LibYAML is missing the Python loader is used,
so the result never depends on which one is installed - only the speed does.

Never `yaml.CLoader`, `yaml.Loader` or `unsafe_load`: every document here is
one a person or a node could have written.

And a key given twice in one mapping is refused, with the line it is on
(review 26-10-24, 15-02). Both loaders keep the last one without a word, so a
copied VIP block not yet renamed changed the first VIP's address, and with
`--prune` the first section's entries were removed.
"""

from __future__ import annotations

from typing import Any

import yaml

SafeLoader: type[yaml.SafeLoader] = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

MERGE = "tag:yaml.org,2002:merge"


class _UniqueKeys(SafeLoader):  # type: ignore[misc, valid-type]
    """The safe loader, refusing a mapping that names one key twice.

    The parser may be LibYAML's; the constructor is Python's either way, so this
    one method serves both. A merge key (`<<`) is not a key of the mapping, and
    a key given beside a merge is how YAML overrides what the merge brought.
    """

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _value in node.value:
            if key_node.tag == MERGE:
                continue
            key = self.construct_object(key_node, deep=True)
            try:
                repeated = key in seen
            except TypeError:
                continue  # an unhashable key; the base refuses it below
            if repeated:
                raise yaml.constructor.ConstructorError(
                    "while reading a mapping",
                    node.start_mark,
                    f"found the key {key!r} a second time; each key may be given once",
                    key_node.start_mark,
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)  # type: ignore[no-any-return]


def load(text: str | bytes) -> Any:
    """`yaml.safe_load`, with LibYAML's safe loader when it is installed, and each key once."""

    return yaml.load(text, Loader=_UniqueKeys)  # noqa: S506 - a safe loader, never yaml.Loader
