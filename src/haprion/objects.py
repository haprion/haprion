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

import dataclasses
import functools
import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from haprion import geo
from haprion.config import ConfigError, Network
from haprion.generate import GeneratorError, runtime_backends, source_of, vip_of
from haprion.proxy_model import (
    MAX_MODEL_BYTES,
    SENDERS_ADDRESS,
    ModelError,
    Proxy,
    load_proxy,
)

PROXY_PREFIX = "managed/proxies/"
PLACEHOLDER = ".gitkeep"


class ObjectsError(ValueError):
    """A committed tree cannot be represented faithfully as a list of objects."""


@functools.cache
def _engine_digest() -> str:
    """This engine's own source, as one digest.

    Part of the fingerprint below because the answer depends on the code that
    produced it as much as on the commit: a release that reads objects
    differently must not be told its predecessor's answer still stands.
    """

    digest = hashlib.sha256()
    package = Path(__file__).resolve().parent
    for path in sorted(package.rglob("*.py")):
        digest.update(path.relative_to(package).as_posix().encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def fingerprint(
    commit: str | None,
    network: Network | None,
    geo_stamp: str | None = None,
    waf: Mapping[str, str | None] | None = None,
) -> str:
    """What an objects listing depends on: the commit, the network and this engine (B222).

    The poller sends back the fingerprint of the listing it holds, and an
    unchanged one is answered without reading the tree or parsing a document -
    which at ten thousand objects was twelve seconds of every pass.
    """

    described = (
        None
        if network is None
        else {
            "vips": {name: dataclasses.asdict(vip) for name, vip in sorted(network.vips.items())},
            "default_vip": network.default_vip,
            "sources": dict(sorted(network.sources.items())),
        }
    )
    #
    # The location database's date (B228): a new database changes nothing in
    # the tree, and a listing answered `unchanged` would keep saying the old one.
    #
    document: dict[str, object] = {
        "commit": commit,
        "network": described,
        "engine": _engine_digest(),
        "geo": geo_stamp,
    }
    #
    # And the WAF engine and rule set on the manager (B231), for the same
    # reason. Only when known, so a listing from before them keeps its value.
    #
    if waf is not None:
        document["waf"] = dict(waf)
    return hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()


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


def _addresses(
    proxy: Proxy, network: Network | None
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    """The VIP this object is served on and the source it leaves from (B222).

    Worked out by the generator's own `vip_of` and `source_of`, against the same
    network description the generator reads, so a listing cannot say one
    address while the configuration binds another. A name the network does not
    have is reported with no address rather than refused: the listing is where
    somebody finds out, and a publish refuses it anyway.
    """

    if network is None:
        return None, None
    name = proxy.listen.vip or network.default_vip
    default = name == network.default_vip
    try:
        vip = vip_of(proxy, network.vips, network.default_vip)
    except GeneratorError:
        return {"name": name, "address": None, "default": default}, None
    #
    # A syslog object leaves from no address of the cluster's: IPVS forwards
    # each message with its sender's (B256), which is the point of it. Naming
    # the VIP's source here would also have the interface hold the receivers'
    # verdict to the node carrying that address, while every node checks them.
    #
    if proxy.listen.protocol in SENDERS_ADDRESS:
        return {"name": name, "address": vip.address, "default": default}, None
    try:
        address = source_of(proxy, vip, network.sources)
    except GeneratorError:
        address = None
    source: dict[str, object] | None = (
        {"name": proxy.listen.source, "address": address}
        if proxy.listen.source is not None or address is not None
        else None
    )
    return {"name": name, "address": vip.address, "default": default}, source


def _entry(name: str, document: str, network: Network | None = None) -> dict[str, object]:
    entry: dict[str, object] = {
        "name": name,
        "document": document,
        "readable": True,
        "problem": None,
        "protocol": None,
        "hostnames": [],
        #
        # Added 2026-09-03, additively: an entry from an older release carries
        # neither, and a reader must treat that as "did not say" rather than as
        # "none" - the difference between a pool with no backends and a helper
        # that was not asked.
        #
        # They are here rather than derived by the interface because the
        # interface must not become a second reader of this document. One file
        # with two interpretations is the hardest kind of divergence to find:
        # both look correct on their own.
        #
        "backend_count": None,
        "redirect_http": None,
        #
        # Added 2026-10-01 (B222), on the same terms: absent from an older
        # release, null where they could not be worked out. `source.name` is
        # null when the address is the VIP's own.
        #
        "vip": None,
        "source": None,
        "servers": [],
        "health_checked": None,
        #
        # Added 2026-10-06 (B250), on the same terms: the names HAProxy knows
        # this object's backends by. A pool is named by itself, so the
        # interface cannot tell whose a backend is from its name any more.
        #
        "runtime_backends": None,
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
    entry["backend_count"] = len(proxy.backends)
    entry["runtime_backends"] = runtime_backends(proxy)
    #
    # A property of this object, not a second object. An https listener that
    # redirects plain HTTP produces routing in two generated frontends - the
    # one on 443 that serves it and the one on 80 that redirects it - but the
    # person wrote one thing and the interface has to say one thing.
    #
    entry["redirect_http"] = bool(proxy.listen.redirect_http)
    entry["vip"], entry["source"] = _addresses(proxy, network)
    servers = [
        f"{server.host}:{server.port}"
        for backend in proxy.backends.values()
        for server in backend.servers
    ]
    #
    # A pool written in the advanced config (B224) has its servers in the
    # text, and the search and the server list would otherwise not know the
    # object reaches them at all - a wrong answer rather than no answer.
    #
    if proxy.advanced is not None:
        servers += [address for _, address in proxy.advanced.placement.servers]
    entry["servers"] = servers
    #
    # `disabled` is a written-down decision not to check, so it counts as no
    # check: the question is whether something is checking.
    #
    entry["health_checked"] = any(
        backend.health.type != "disabled" for backend in proxy.backends.values()
    )
    return entry


def objects_result(
    files: Mapping[str, bytes],
    commit: str | None,
    *,
    network: Network | None = None,
    generated_at: datetime | None = None,
    geo_stamp: str | None = None,
    waf: Mapping[str, str | None] | None = None,
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
        "fingerprint": fingerprint(commit, network, geo_stamp, waf),
        "objects": [],
        #
        # How fresh the cluster's country files are against the database
        # (B228): new data reaches a cluster at its next publish, and this is
        # what tells somebody one is due.
        #
        "geo": {"database": geo_stamp, "published": geo.published_stamp(files)},
        #
        # Whether the manager can publish an object with WAF (B231): the engine
        # compiles the rules here, from the rule set installed here.
        #
        "waf": dict(waf) if waf is not None else {"engine": None, "crs": None},
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
        entries.append(_entry(pure.stem, _document(files[path], path), network))

    result["objects"] = entries
    return result


def unchanged_result(
    commit: str | None,
    network: Network | None,
    *,
    generated_at: datetime | None = None,
    geo_stamp: str | None = None,
    waf: Mapping[str, str | None] | None = None,
) -> dict[str, object]:
    """The answer to a caller whose listing is still the right one.

    `objects` is empty and `unchanged` says why: the caller keeps what it has.
    A reader that ignored `unchanged` would see no objects, which is why only
    a caller that sent `unchanged_since` can ever receive this.
    """

    timestamp = generated_at or datetime.now(UTC)
    return {
        "commit": commit,
        "generated_at": timestamp.isoformat().replace("+00:00", "Z"),
        "fingerprint": fingerprint(commit, network, geo_stamp, waf),
        "unchanged": True,
        "objects": [],
    }
