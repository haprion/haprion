"""The proxy objects as they are written, not as HAProxy ended up expressing them.

`inventory` answers "what is this cluster serving" by parsing published HAProxy
configuration. That is the right answer to that question and the wrong one to
this: the generated file is derived, and the object that produced it carries
things the configuration no longer distinguishes - which route the author wrote
first, what a backend is called, whether a redirect was meant as a redirect.
Editing needs the source.

Read from a commit and never from a working tree, the same rule the rest of the
chain follows. A file somebody is halfway through saving must not be able to
look like a stored object.

**An object that does not parse is still listed.** It is the one somebody needs
to open, and dropping it would leave the editor blind to exactly the file that
needs fixing. Every entry therefore carries the document as written, and says
separately whether this version can read it.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import PurePosixPath

from haproxy_mgmt.config import ConfigError
from haproxy_mgmt.proxy_model import MAX_MODEL_BYTES, ModelError, load_proxy

PROXY_PREFIX = "managed/proxies/"
PLACEHOLDER = ".gitkeep"


class ObjectsError(ValueError):
    """A committed tree cannot be represented faithfully as a list of objects."""


def _document(raw: bytes, path: str) -> str:
    #
    # Refused rather than replaced, and the size is checked first: a file this
    # large is not an object anybody wrote, and decoding it to find out would
    # be the cost the limit exists to avoid.
    #
    if len(raw) > MAX_MODEL_BYTES:
        raise ObjectsError(f"{path} is larger than a proxy object may be")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ObjectsError(f"{path} is not UTF-8: {exc}") from exc


def _entry(name: str, document: str) -> dict[str, object]:
    entry: dict[str, object] = {
        "name": name,
        "document": document,
        "readable": True,
        "problem": None,
        "protocol": None,
        "hostnames": [],
    }
    try:
        proxy = load_proxy(name, document.encode("utf-8"))
    except (ModelError, ConfigError) as exc:
        #
        # The refusal is the useful part, not a reason to hide the file. It is
        # the same sentence the editor will show beside the field, and the same
        # one a publish would have given.
        #
        entry["readable"] = False
        entry["problem"] = str(exc)
        return entry

    entry["protocol"] = proxy.listen.protocol
    entry["hostnames"] = sorted(proxy.hostnames)
    return entry


def objects_result(
    files: Mapping[str, bytes],
    commit: str | None,
    *,
    generated_at: datetime | None = None,
) -> dict[str, object]:
    """Every stored proxy object at one commit, keyed by the name it is filed under.

    `commit` is what the objects were read at, and it is returned so that a
    draft can record the base it was derived from. None means the repository has
    no commit yet, which is a new cluster rather than a broken one - the answer
    is an empty list, never a guess from somewhere else.
    """

    timestamp = generated_at or datetime.now(UTC)
    result: dict[str, object] = {
        "commit": commit,
        "generated_at": timestamp.isoformat().replace("+00:00", "Z"),
        "objects": [],
    }
    if commit is None:
        return result

    entries: list[dict[str, object]] = []
    for path in sorted(files):
        if not path.startswith(PROXY_PREFIX):
            continue
        relative = path.removeprefix(PROXY_PREFIX)
        if relative == PLACEHOLDER:
            continue
        pure = PurePosixPath(relative)
        #
        # The same shape the publishing path requires. A nested directory or a
        # second suffix is refused here too rather than skipped: the two must
        # agree about what a proxy object file is, or the editor would list a
        # file the publish then rejects.
        #
        if len(pure.parts) != 1 or pure.suffix != ".yaml" or not pure.stem:
            raise ObjectsError(f"{path} is not a proxy object file")
        entries.append(_entry(pure.stem, _document(files[path], path)))

    result["objects"] = entries
    return result
