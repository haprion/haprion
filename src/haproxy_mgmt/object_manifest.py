"""What each object in a release actually amounts to, so releases can be compared.

A release is named by the commit it was built from, and that name answers one
question: are the nodes running the release they were told to run. It cannot
answer the question an operator asks about one site - has *this* object reached
the nodes - because a release carries every object, and the file its routing
lives in is shared with every other object on the same address.

So each release writes down a fingerprint per object, and the comparison is
between two releases rather than between a release and a memory of who
published what. That difference is the point:

- **The entrance stops mattering.** A change made from the command line and one
  made from the web produce the same bytes and therefore the same answer.
- **There is no window.** A job list is a recent history, and an object that
  fell off the end of it looked unchanged; a fingerprint is a fact about the
  release itself and does not age.
- **A change nobody made to the object still counts.** Moving the VIP, changing
  the abuse rules or the trusted proxies alters what the node serves for a site
  whose own document is untouched. It lands in `listener`, and the comparison
  sees it.

**Where it is written.** In the release directory, beside the level the nodes
pull rather than inside it. Everything under that level reaches the node, and
`conf.d` is read with `-f` - a stray file there is configuration HAProxy tries
to parse. This is the manager's index of what it published, not part of the
contract with the node.

**What it does not answer.** Whether the file on the node still holds what the
release put there. A fingerprint compares two releases; somebody editing a file
in place on a node is the question the golden and checksum paths ask.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

SCHEMA = 1

MANIFEST_FILE = "MANIFEST.json"

#
# The four pieces an object's behaviour is spread across, in the order a reader
# would want them: what it serves with, how requests reach it, what listener it
# sits on, and under which certificate. `generate` produces them; the names are
# shared with it through this tuple rather than through two spellings.
#
PARTS: tuple[str, ...] = ("backends", "routing", "listener", "certificate")

CURRENT = "current"
CHANGED = "changed"
ABSENT = "absent"


@dataclass(frozen=True, slots=True)
class ObjectFingerprint:
    """One object's release, hashed by part and as a whole."""

    fingerprint: str
    parts: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class Manifest:
    """Every object one release carries, and which release it is."""

    cluster: str
    version: int
    commit: str
    objects: Mapping[str, ObjectFingerprint]


@dataclass(frozen=True, slots=True)
class Difference:
    """What one object's two releases say about each other."""

    state: str
    """`current`, `changed`, or `absent` - the object is not in the observed release."""

    parts: tuple[str, ...]
    """Which parts differ, empty unless the state is `changed`."""


def _digest(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode()).hexdigest()}"


def fingerprint(parts: Mapping[str, str]) -> ObjectFingerprint:
    """One object's parts, hashed individually and then together.

    Individually because "changed" on its own sends somebody to read a whole
    configuration; "the listener changed" says where to look. Together because
    the comparison itself should be one equality and not four.

    A part the generator did not produce hashes as the empty string rather than
    being left out. An object that stops serving TLS must not compare equal to
    one that never did - absence is a value here, and it has to be hashed like
    one.
    """

    hashed = {name: _digest(parts.get(name, "")) for name in PARTS}
    summary = "".join(f"{name}\n{hashed[name]}\n" for name in PARTS)
    return ObjectFingerprint(fingerprint=_digest(summary), parts=hashed)


def build(
    *,
    cluster: str,
    version: int,
    commit: str,
    object_parts: Mapping[str, Mapping[str, str]],
) -> Manifest:
    """The manifest for one generated release."""

    return Manifest(
        cluster=cluster,
        version=version,
        commit=commit,
        objects={name: fingerprint(parts) for name, parts in object_parts.items()},
    )


def render(manifest: Manifest) -> bytes:
    """The manifest as it is written into the release.

    Sorted and indented, because it is read by people during an incident as
    often as by code, and a diff between two releases should be legible.
    """

    document = {
        "schema": SCHEMA,
        "cluster": manifest.cluster,
        "version": manifest.version,
        "commit": manifest.commit,
        "objects": {
            name: {
                "fingerprint": entry.fingerprint,
                "parts": dict(entry.parts),
            }
            for name, entry in sorted(manifest.objects.items())
        },
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def parse(text: str) -> Manifest | None:
    """A manifest read back, or nothing at all.

    Deliberately strict, and the opposite stance to `parse_release_file`. A
    release stamp that cannot be read still identifies a release the nodes are
    running, so tolerance there keeps a status command answering. A manifest
    that cannot be read answers a question about *difference*, and half of one
    would report objects as unchanged because their entries failed to load.
    Nothing is the honest return: the caller reports unknown.
    """

    try:
        document = json.loads(text)
    except ValueError:
        return None
    if not isinstance(document, Mapping) or document.get("schema") != SCHEMA:
        return None
    cluster, version, commit = (
        document.get("cluster"),
        document.get("version"),
        document.get("commit"),
    )
    entries = document.get("objects")
    if not isinstance(cluster, str) or not isinstance(commit, str):
        return None
    if not isinstance(version, int) or isinstance(version, bool):
        return None
    if not isinstance(entries, Mapping):
        return None
    objects: dict[str, ObjectFingerprint] = {}
    for name, entry in entries.items():
        parsed = _entry(entry)
        if not isinstance(name, str) or parsed is None:
            return None
        objects[name] = parsed
    return Manifest(cluster=cluster, version=version, commit=commit, objects=objects)


def _entry(entry: Any) -> ObjectFingerprint | None:
    if not isinstance(entry, Mapping):
        return None
    summary = entry.get("fingerprint")
    parts = entry.get("parts")
    if not isinstance(summary, str) or not isinstance(parts, Mapping):
        return None
    if any(not isinstance(value, str) for value in parts.values()):
        return None
    return ObjectFingerprint(fingerprint=summary, parts={str(k): v for k, v in parts.items()})


def compare(published: Manifest, observed: Manifest) -> dict[str, Difference]:
    """What each published object's state is on a node running `observed`.

    Keyed by the published manifest's objects, because those are the ones an
    operator can open a page for. An object only the observed release carries
    is one that was removed, and removal is reported by the listing rather than
    by a row that no longer exists.
    """

    return {
        name: _difference(entry, observed.objects.get(name))
        for name, entry in published.objects.items()
    }


def _difference(published: ObjectFingerprint, observed: ObjectFingerprint | None) -> Difference:
    if observed is None:
        return Difference(state=ABSENT, parts=())
    if published.fingerprint == observed.fingerprint:
        return Difference(state=CURRENT, parts=())
    differing = tuple(
        name for name in PARTS if published.parts.get(name) != observed.parts.get(name)
    )
    return Difference(state=CHANGED, parts=differing)


def worst(states: Sequence[Difference]) -> Difference | None:
    """One answer for an object read on several nodes.

    A node that is behind decides the answer, in the same way a release is only
    converged when every node has it: an object served correctly by three nodes
    out of four is not an object that has reached the cluster.

    Nothing at all when nothing could be read. Returning `current` for an empty
    sequence would be the same mistake this module exists to remove - silence
    reported as agreement - so the absence is handed back and the caller says
    unknown.
    """

    if not states:
        return None
    for state in states:
        if state.state == ABSENT:
            return state
    changed = [state for state in states if state.state == CHANGED]
    if changed:
        merged: list[str] = []
        for state in changed:
            merged.extend(part for part in state.parts if part not in merged)
        return Difference(state=CHANGED, parts=tuple(p for p in PARTS if p in merged))
    return Difference(state=CURRENT, parts=())
