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

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from haproxy_mgmt.object_manifest import MANIFEST_FILE, REPOSITORY_PATH

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
    ("managed/maps", "managed"),
    ("manual/maps", "manual"),
)
#
# The generated map layer (B228): one network list per country, written whole
# on every publish. Held to the managed rule - one shape, one level - since it
# is application output a person never edits.
#
MANAGED_MAPS = "managed/maps"
MANAGED_MAP_NAME = re.compile(r"^geo-[a-z]{2}\.lst$")

REQUIRED_FILES: tuple[str, ...] = ("core/haproxy.cfg", "manual/reservations.yaml")

#
# The manager's index of what each object in this version amounts to. Its two
# names - in the tree and in the release - are imported rather than repeated:
# a layout that spelled either of them its own way would quietly stop carrying
# the file, and the comparison would report unknown for a release that has one.
#

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

#
# The keepalived address list, which travels in the same release and is read by
# nothing HAProxy runs. It is a layer of its own rather than a fourth `conf.d`
# contributor: `conf.d` is what the engine loads, and a file in it that the
# engine must never load would be one careless glob away from being loaded.
#
# One writer, so no collision rule and no ordering rule: the application
# generates this directory whole on every publish, the way it does
# `managed/generated`. A cluster whose repository predates B57 simply has no
# such directory, and the release then carries none - which is exactly what a
# node that has not been given the `include` line expects.
#
KEEPALIVED_LAYER = "managed/keepalived"
KEEPALIVED_TARGET = "keepalived"
KEEPALIVED_ALLOWED_SUFFIX = ".conf"

#
# The certificate lists a TLS listener binds, for the same reason keepalived has
# a layer of its own: `conf.d` is what the engine loads with `-f`, and `-f` on a
# directory reads every file in it. A certificate list parsed as configuration
# is a failed deploy, so it must live where nothing globs for it.
#
# One writer, generated whole on every publish. A cluster with no https listener
# carries no such directory, and the release then has none - which is what a
# node that has never seen one expects. Nothing on the node side changes: the
# release is fetched with `rsync -a --delete`, so a new directory arrives on its
# own, and the bind line reaches it by a path relative to `conf.d`.
#
#
# The WAF engine's layer (B229, B233), for the same reason again: nothing in it
# is HAProxy configuration `-f` may load - the SPOE file is named by the
# frontends' filter line, the rest is the engine's. One writer, generated whole
# on every publish; held to its shapes like every managed layer.
#
WAF_LAYER = "managed/waf"
WAF_TARGET = "waf"
WAF_NAME = re.compile(
    r"^(coraza\.yaml|spoe\.conf|crs/crs-setup\.conf|crs/VERSION"
    r"|crs/rules/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.(conf|data))$"
)

CRT_LIST_LAYER = "managed/crt-lists"
CRT_LIST_TARGET = "crt-lists"
CRT_LIST_ALLOWED_SUFFIX = ".list"

#
# The three layers flatten into one `conf.d`, and HAProxy reads that directory
# in ALPHABETICAL order - measured on 2026-08-27, where `100-a.cfg` sorted
# before `20-b.cfg`. Fixed width with leading zeroes is the only thing that
# makes alphabetical order and numeric order the same order, so every file that
# HAProxy will load carries exactly four digits and a dash. Decision B18.
#
NUMBERED = re.compile(r"^[0-9]{4}-")

#
# The band the generator owns, and the reason this check exists at all. Once an
# application writes into the same flat directory a person edits, the two will
# eventually reach for the same name - and a convention that lives only in a
# document holds until somebody is in a hurry.
#
# Enforced in both directions on purpose. A handwritten file inside the band
# would be silently replaced the next time the generator runs; a generated file
# outside it would survive a regeneration that was supposed to remove it. The
# first loses work, the second leaves configuration nobody meant to keep.
#
# `2000`-`2999` is reserved for a second generated layer and is deliberately NOT
# enforced here: nothing writes there yet, and a rule with no writer behind it
# is a rule nobody can test against reality.
#
GENERATED_BAND = range(1000, 2000)
GENERATED_LAYER = "managed"


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


def _check_number(relative: str, layer: str) -> None:
    """Hold one `conf.d` file to the numbering its layer is allowed.

    Checked here rather than at candidate validation because this is the last
    point that still knows which layer a file came from: by the time a candidate
    exists the three layers have been flattened into one directory and the
    provenance is gone.

    Only files HAProxy will actually load are held to the rule. A `.txt` or a
    `.cfg.bak` left in `conf.d` is ignored by HAProxy - measured the same day as
    the ordering - so refusing to publish because of one would be a rule about
    tidiness enforced as though it were a rule about correctness. The caller has
    already filtered to `.cfg` before this is asked.
    """

    name = relative.rsplit("/", 1)[-1]
    if not NUMBERED.match(name):
        raise LayoutError(
            f"'{relative}' in layer '{layer}' must start with four digits and a dash, "
            f"because conf.d is read in alphabetical order."
        )

    number = int(name[:4])
    generated = layer == GENERATED_LAYER
    if generated and number not in GENERATED_BAND:
        raise LayoutError(
            f"generated file '{relative}' is numbered {number:04d}, outside the "
            f"{GENERATED_BAND.start:04d}-{GENERATED_BAND.stop - 1:04d} band the generator owns."
        )
    if not generated and number in GENERATED_BAND:
        raise LayoutError(
            f"'{relative}' in layer '{layer}' is numbered {number:04d}, inside the "
            f"{GENERATED_BAND.start:04d}-{GENERATED_BAND.stop - 1:04d} band reserved for "
            f"generated files, which are rewritten without warning."
        )


def build_release_index(files: Mapping[str, bytes]) -> dict[str, bytes]:
    """What travels with a release without travelling to the nodes.

    The object manifest, and so far only that. It is written beside the level a
    node pulls rather than inside it, because a node fetches that level whole
    and `conf.d` is loaded with `-f`: the manager's own index has no business
    being parsed as configuration, or being deleted by an rsync that syncs the
    node's view of the release.

    Empty for a tree published before the manifest existed. That release then
    has none, and a comparison against it answers unknown - which is the honest
    answer and the reason nothing here invents a default.
    """

    manifest = files.get(REPOSITORY_PATH)
    return {} if manifest is None else {MANIFEST_FILE: manifest}


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
            _check_number(relative, layer)
            target = f"conf.d/{relative}"
            if target in artifact:
                raise LayoutError(
                    f"configuration collision '{relative}': "
                    f"layer '{layer}' and layer '{origin[target]}' both provide it."
                )
            artifact[target] = content
            origin[target] = layer

    for relative, content in _children(files, KEEPALIVED_LAYER):
        if relative.rsplit("/", 1)[-1] == PLACEHOLDER:
            continue
        if "/" in relative or not relative.endswith(KEEPALIVED_ALLOWED_SUFFIX):
            raise LayoutError(f"file not allowed in {KEEPALIVED_LAYER}: {relative}")
        artifact[f"{KEEPALIVED_TARGET}/{relative}"] = content
        origin[f"{KEEPALIVED_TARGET}/{relative}"] = GENERATED_LAYER

    for relative, content in _children(files, CRT_LIST_LAYER):
        if relative.rsplit("/", 1)[-1] == PLACEHOLDER:
            continue
        if "/" in relative or not relative.endswith(CRT_LIST_ALLOWED_SUFFIX):
            raise LayoutError(f"file not allowed in {CRT_LIST_LAYER}: {relative}")
        artifact[f"{CRT_LIST_TARGET}/{relative}"] = content
        origin[f"{CRT_LIST_TARGET}/{relative}"] = GENERATED_LAYER

    for relative, content in _children(files, WAF_LAYER):
        if relative.rsplit("/", 1)[-1] == PLACEHOLDER:
            continue
        if not WAF_NAME.match(relative):
            raise LayoutError(f"file not allowed in {WAF_LAYER}: {relative}")
        artifact[f"{WAF_TARGET}/{relative}"] = content
        origin[f"{WAF_TARGET}/{relative}"] = GENERATED_LAYER

    for prefix, layer in MAP_LAYERS:
        for relative, content in _children(files, prefix):
            if relative.rsplit("/", 1)[-1] == PLACEHOLDER:
                continue
            if prefix == MANAGED_MAPS and not MANAGED_MAP_NAME.match(relative):
                raise LayoutError(f"file not allowed in {MANAGED_MAPS}: {relative}")
            target = f"maps/{relative}"
            if target in artifact:
                raise LayoutError(
                    f"map collision '{relative}': "
                    f"layer '{layer}' and layer '{origin[target]}' both provide it."
                )
            artifact[target] = content
            origin[target] = layer

    return artifact


def parse_release_file(text: str) -> dict[str, str]:
    """The RELEASE stamp read back, beside the code that writes it.

    One file, one schema. The published stamp has two readers - the node that
    pulls it and the status command that reports it - and a second, private
    idea of its shape here is the drift that makes them disagree about what is
    published while both look correct.

    Deliberately tolerant, in the same way the shell command's `sed` was:
    unknown keys are kept, lines without `=` are ignored, and a missing key is
    the caller's problem rather than an error. A stamp written by a newer
    version must not make an older status command refuse to answer.
    """

    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key.strip()] = value.strip()
    return fields


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
