"""The advanced config dialog on an object's page (Fas 17, B223-B225).

The dialog edits one thing, the object's `advanced` text, and one choice beside
it: whether the text writes the object's pool. Everything else in the object is
the form's and is carried over as the draft or stored document has it. Where
each line goes is the engine's decision (`proxy_model.advanced_placement`), so
the dialog's *Check* and `haprion-objects --advanced` cannot disagree.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from haprion import advanced as advanced_config
from haprion.proxy_model import (
    ModelError,
    advanced_placement,
    dump_document,
    load_written,
    pool_written_by_hand,
    read_document,
)

#
# What a pool gets when it is handed back to the form: the form's own defaults,
# so the editor opens on what it would have offered for a new object.
#
RETURNED_BALANCE = "roundrobin"

#
# How long a text may be, well inside the draft's own limit. Checked by the
# dialog's route rather than by the form parser, so the answer is a sentence in
# the dialog and not a 422 the dialog can only call "no answer" (review F1).
#
MAX_TEXT = 65536


@dataclass(frozen=True, slots=True)
class Opened:
    """What the dialog opens with."""

    text: str
    handwritten: bool
    #
    # Only an object with one pool may have it written by hand (B224).
    #
    one_pool: bool


@dataclass(frozen=True, slots=True)
class Answer:
    """What *Check* or a refused *Save* draws in the dialog."""

    document: str = ""
    lines: tuple[advanced_config.Line, ...] = ()
    problem: str = ""


def opened(document: str) -> Opened:
    """The text and the pool choice as the draft or stored document has them."""

    try:
        data = read_document("object", document.encode())
    except ModelError:
        return Opened(text="", handwritten=False, one_pool=False)
    backends = data.get("backends")
    pools = list(backends.values()) if isinstance(backends, Mapping) else []
    text = data.get("advanced")
    return Opened(
        text=text if isinstance(text, str) else "",
        handwritten=any(pool_written_by_hand(pool) for pool in pools),
        one_pool=len(pools) == 1,
    )


def apply(name: str, document: str, text: str, *, handwritten: bool) -> str:
    """The object's document with this text and this pool choice, as it would be saved.

    Raises `ValueError` with the sentence the dialog shows when the choice cannot
    be made: a pool written by hand needs an object with one pool, and a pool
    handed back to the form needs servers the form can show.
    """

    data: dict[str, Any] = dict(read_document(name, document.encode()))
    written = advanced_config.normalise(text)
    if written:
        data["advanced"] = written
    else:
        data.pop("advanced", None)

    backends = data.get("backends")
    if not isinstance(backends, Mapping):
        raise ValueError("this proxy has no pool the dialog can read")
    pools = dict(backends)
    now = any(pool_written_by_hand(pool) for pool in pools.values())
    if handwritten and not now:
        if len(pools) != 1:
            raise ValueError("only a proxy with one pool can have it written here")
        data["backends"] = {next(iter(pools)): {"servers": []}}
    elif now and not handwritten:
        data["backends"] = {pool_name: _returned_pool(name, data, written) for pool_name in pools}
    return dump_document(data)


def _returned_pool(name: str, data: Mapping[str, Any], text: str) -> dict[str, Any]:
    """The pool the form takes back: the text's servers, the form's other defaults.

    Read from the same `server` lines the engine reads for the object listing
    (B224), and refused when one of them is not a plain `name host:port` - a
    server the form cannot show would be dropped by the first save.
    """

    listen = data.get("listen")
    protocol = str(listen.get("protocol", "") if isinstance(listen, Mapping) else "")
    placement = advanced_config.place(
        text,
        name=name,
        protocol=protocol,
        rate_limit=data.get("rate_limit") is not None,
        dynamic_block=data.get("dynamic_block") is not None,
        handwritten=True,
    )
    lines = [
        line
        for line in placement.backend
        if advanced_config.words(line.text)[:1] in (["server"], ["server-template"])
    ]
    if not placement.servers:
        raise ValueError(
            "the text has no server line for the form to take over; "
            "write one before giving the pool back"
        )
    if len(lines) != len(placement.servers):
        raise ValueError(
            "every server line must be a name and a host:port for the form to take the pool back"
        )
    servers = []
    for _, address in placement.servers:
        host, _, port = address.rpartition(":")
        servers.append({"host": host, "port": int(port)})
    return {"balance": RETURNED_BALANCE, "health": {"type": "disabled"}, "servers": servers}


def check(name: str, document: str) -> Answer:
    """Each line's fate, and the engine's refusal of the whole object if it has one.

    The lines are shown even when the object is refused, because a refused line
    is exactly what somebody needs to see in place.
    """

    try:
        placement = advanced_placement(name, document.encode())
    except (ModelError, advanced_config.TextError) as exc:
        return Answer(document=document, problem=str(exc))
    lines = tuple(line for line in placement.lines if line.text) if placement else ()
    try:
        load_written(name, document.encode())
    except ModelError as exc:
        return Answer(document=document, lines=lines, problem=str(exc))
    return Answer(document=document, lines=lines)
