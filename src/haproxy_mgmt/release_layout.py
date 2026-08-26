"""Turn a repository tree into the artifact a node actually runs.

The repository keeps configuration in three layers - `core/`, `managed/` and
`manual/` - while a node runs a single flat directory: one `haproxy.cfg`, one
`conf.d/` and one `maps/`. Collapsing the former into the latter is the step
between "saved" and "published".

Why this lives here rather than in the publishing command
---------------------------------------------------------
The privilege boundary needs the same answer on both sides. The unprivileged
caller builds this artifact to validate it, and the root helper builds it again
to install it - and the guarantee that what was validated is what gets installed
holds only if both derive it from the same bytes with the same code. Root
therefore never accepts a caller-built artifact; it accepts the repository bytes
and derives the artifact itself.

The rules are ported from `haproxy-publish-core` case by case and are frozen:
the layer order is core, managed, manual; a collision is an error rather than an
implicit overwrite; `conf.d` layers contribute only `.cfg` files; map layers
contribute every file except `.gitkeep`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

#
# Frozen order. Not alphabetical and not configurable: it is the order the
# published contract names, and a collision between two layers is reported
# rather than resolved, so the order decides only which layer is named first in
# the error.
#
CFG_LAYERS: tuple[tuple[str, str], ...] = (
    ("core/conf.d", "core"),
    ("managed/generated", "managed"),
    ("manual/conf.d", "manual"),
)
MAP_LAYERS: tuple[tuple[str, str], ...] = (
    ("core/maps", "core"),
    ("manual/maps", "manual"),
)

REQUIRED_FILES: tuple[str, ...] = ("core/haproxy.cfg", "manual/reservations.yaml")

#
# Directories the node layout always has, even when nothing lands in them.
# `haproxy-publish-core` creates both with `mkdir -p` before it merges anything,
# so a cluster with no map files still ships an empty `maps/`.
#
# Measured 2026-08-26: external is exactly that cluster. The step 1 parity check
# compared FILES against a real release and could not see this - a directory is
# not a file - so it took the end-to-end parity run to surface it.
#
NODE_DIRECTORIES: tuple[str, ...] = ("conf.d", "maps")

#
# managed/ is written by the application, not by a human, so it is held to a
# stricter rule than the layers a person edits: nothing but generated .cfg files
# and the directory placeholder may appear there.
#
MANAGED_GENERATED = "managed/generated"
MANAGED_ALLOWED_SUFFIX = ".cfg"
PLACEHOLDER = ".gitkeep"


class LayoutError(Exception):
    """The repository tree cannot be turned into a node artifact.

    Carries the exit code the publishing path uses for "the input is wrong"
    (65), so the caller and the helper report the same thing for the same tree.
    """

    def __init__(self, message: str, *, exit_code: int = 65):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class ReleaseMetadata:
    cluster: str
    version: int
    commit: str
    timestamp: str


def _children(files: Mapping[str, bytes], prefix: str) -> Iterable[tuple[str, bytes]]:
    """Yield (path relative to `prefix`, content) for everything under it."""

    start = f"{prefix}/"
    for path in sorted(files):
        if path.startswith(start):
            relative = path[len(start) :]
            if relative:
                yield relative, files[path]


def build_node_artifact(files: Mapping[str, bytes]) -> dict[str, bytes]:
    """Collapse a repository tree into the flat artifact a node runs.

    `files` maps repository-relative paths to contents - exactly what
    `git archive <commit>` contains. The result maps node-relative paths
    (`haproxy.cfg`, `conf.d/...`, `maps/...`) to the same bytes.

    RELEASE is deliberately NOT included. It carries a timestamp, so including
    it would make two derivations of the same commit differ in bytes for a
    reason that has nothing to do with the configuration. It is added when the
    release is installed; HAProxy never reads it.
    """

    for required in REQUIRED_FILES:
        if required not in files:
            raise LayoutError(f"{required} is missing.")

    for relative, _ in _children(files, MANAGED_GENERATED):
        name = relative.rsplit("/", 1)[-1]
        if name != PLACEHOLDER and not name.endswith(MANAGED_ALLOWED_SUFFIX):
            raise LayoutError(f"file not allowed in {MANAGED_GENERATED}: {relative}")

    artifact: dict[str, bytes] = {"haproxy.cfg": files["core/haproxy.cfg"]}
    #
    # Remembered per target so a collision can name the layer that got there
    # first as well as the one that arrived second. "Something already exists"
    # is not a useful thing to tell an operator holding three layers.
    #
    origin: dict[str, str] = {}

    for prefix, layer in CFG_LAYERS:
        for relative, content in _children(files, prefix):
            if not relative.endswith(".cfg"):
                continue
            target = f"conf.d/{relative}"
            if target in artifact:
                raise LayoutError(
                    f"configuration collision '{relative}': "
                    f"layer '{layer}' and layer '{origin[target]}' both provide it."
                )
            artifact[target] = content
            origin[target] = layer

    for prefix, layer in MAP_LAYERS:
        for relative, content in _children(files, prefix):
            if relative.rsplit("/", 1)[-1] == PLACEHOLDER:
                continue
            target = f"maps/{relative}"
            if target in artifact:
                raise LayoutError(
                    f"map collision '{relative}': "
                    f"layer '{layer}' and layer '{origin[target]}' both provide it."
                )
            artifact[target] = content
            origin[target] = layer

    return artifact


def render_release_file(metadata: ReleaseMetadata) -> bytes:
    """The RELEASE stamp, written at the level a node pulls.

    Kept byte identical to what `haproxy-publish-core` writes, including field
    order: the nodes read it, and a reordering would be a contract change
    dressed up as a refactor.
    """

    return (
        "schema=1\n"
        f"cluster={metadata.cluster}\n"
        f"version={metadata.version}\n"
        f"hash={metadata.commit}\n"
        f"timestamp={metadata.timestamp}\n"
    ).encode()
