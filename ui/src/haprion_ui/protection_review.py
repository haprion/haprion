"""Protection review: the states an object was given that protect it less (B517, 12; B521).

A list to read, not an alarm: each state is one somebody chose, and may be right
- an internal admin page without a WAF can be. *Needs attention* leaves them out
for that reason, and this page is where they are seen together, one row per
object with a mark per state, each mark a link into the form at its field.

What counts is decided in B517 and B521: the WAF off (where the engine is
offered) or only logging, no rate limit, no HSTS on https, a pool whose TLS
certificate is not verified, advanced config, and a proxy written by hand,
which is not assessed. Where an object is reachable from is shown beside them
and is not one of them: a VLAN and a firewall usually stand in front.

An admin accepts a row with the marks it has. It stays accepted while it has no
mark the acceptance does not hold; a new one makes it a row to review again,
with the new mark said and the accepted ones dimmed.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import quote

from haprion.proxy_model import ModelError, Proxy, load_proxy

from haprion_ui.db import ReviewAck, ReviewView
from haprion_ui.objects import ObjectView
from haprion_ui.proxies import ProxyView


@dataclass(frozen=True, slots=True)
class Weakness:
    """One state that protects an object less: its key, its words and where it is set."""

    key: str
    label: str
    group: str
    """The form's group that holds the field, or "" for a link to the object's page."""

    field: str
    """The field to focus, or "advanced" for the object's advanced config dialog."""


#
# In the order a row shows them. The keys are stored with an acceptance, so a
# key is never renamed.
#
WEAKNESSES: tuple[Weakness, ...] = (
    Weakness("manual", "Not assessed · written by hand", "", ""),
    Weakness("waf-off", "WAF off", "waf", "waf_mode"),
    Weakness("waf-log", "WAF log only", "waf", "waf_mode"),
    Weakness("no-rate-limit", "No rate limit", "limits", "rate_limit"),
    Weakness("no-hsts", "No HSTS", "tls", "hsts"),
    Weakness("backend-tls-unverified", "Backend TLS not verified", "connections", "backend_tls"),
    Weakness("advanced", "Advanced config", "", "advanced"),
)
BY_KEY = {weakness.key: weakness for weakness in WEAKNESSES}
SITES = ("http", "https")


def weaknesses(proxy: Proxy, *, waf_offered: bool) -> tuple[str, ...]:
    """The keys of the states that protect this object less, in `WEAKNESSES` order.

    Only the states its kind has: a dns or syslog object has none of them.
    """

    protocol = proxy.listen.protocol
    found: set[str] = set()
    if protocol in SITES:
        mode = proxy.waf.mode if proxy.waf is not None else "off"
        if mode == "log":
            found.add("waf-log")
        elif mode == "off" and waf_offered:
            found.add("waf-off")
    if protocol in (*SITES, "tcp"):
        #
        # Path limits protect their paths only (B521): the rest of the object
        # is still unlimited.
        #
        if proxy.rate_limit is None:
            found.add("no-rate-limit")
        if any(
            backend.tls is not None and backend.tls.verify == "none"
            for backend in proxy.backends.values()
        ):
            found.add("backend-tls-unverified")
        if proxy.advanced is not None:
            found.add("advanced")
    if protocol == "https" and proxy.listen.hsts is None:
        found.add("no-hsts")
    return tuple(weakness.key for weakness in WEAKNESSES if weakness.key in found)


@lru_cache(maxsize=32768)
def _read(name: str, document: str, waf_offered: bool) -> tuple[tuple[str, ...], str] | None:
    """The marks and the reach of one stored document, or None where it cannot be read.

    Kept by the document itself: the page reads every object of every cluster,
    and a document changes far less often than the page is opened.
    """

    try:
        proxy = load_proxy(name, document.encode())
    except ModelError:
        return None
    reach = ", ".join(proxy.allow_from) if proxy.allow_from else "Everywhere"
    return weaknesses(proxy, waf_offered=waf_offered), reach


@dataclass(frozen=True, slots=True)
class Mark:
    label: str
    href: str
    state: str = ""
    """"" as found, "new" where the row was accepted without it, "accepted" where it was."""


@dataclass(frozen=True, slots=True)
class ReviewRow:
    name: str
    href: str
    reach: str
    marks: tuple[Mark, ...]
    keys: tuple[str, ...]
    state: str
    """"clean" with no marks, "accepted", or "open"."""

    accepted_by: str = ""
    accepted_at: object = None


@dataclass(frozen=True, slots=True)
class ReviewCluster:
    cluster: str
    accent: int | None
    rows: tuple[ReviewRow, ...]
    shown: bool
    tone: str = "unknown"
    """The cluster's lamp, as the proxy list draws it."""

    @property
    def open(self) -> int:
        return sum(row.state == "open" for row in self.rows)

    @property
    def detail(self) -> str:
        counts = (
            (self.open, "to review"),
            (sum(row.state == "accepted" for row in self.rows), "accepted"),
            (sum(row.state == "clean" for row in self.rows), "with nothing to review"),
        )
        said = [f"{count} {words}" for count, words in counts if count]
        return " · ".join(said) or "No proxies"


@dataclass(frozen=True, slots=True)
class Review:
    clusters: tuple[ReviewCluster, ...]
    view: ReviewView

    @property
    def count(self) -> int:
        """The rows still to review in the clusters shown: the number on the view's tab."""

        return sum(cluster.open for cluster in self.clusters if cluster.shown)


def _href(cluster: str, name: str, weakness: Weakness, *, editable: bool) -> str:
    page = f"/proxies/{quote(cluster, safe='')}/{quote(name, safe='')}"
    if weakness.field == "advanced":
        return f"{page}?open=advanced"
    if not weakness.group or not editable:
        return page
    return f"{page}/edit?open={weakness.group}&focus={weakness.field}"


def _row(
    cluster: str,
    name: str,
    keys: Sequence[str],
    reach: str,
    ack: ReviewAck | None,
    *,
    editable: bool,
) -> ReviewRow:
    href = f"/proxies/{quote(cluster, safe='')}/{quote(name, safe='')}"
    accepted = ack is not None and set(keys) <= ack.weaknesses
    state = "clean" if not keys else "accepted" if accepted else "open"
    marks = tuple(
        Mark(
            label=BY_KEY[key].label,
            href=_href(cluster, name, BY_KEY[key], editable=editable),
            state=""
            if ack is None or state == "accepted"
            else "accepted"
            if key in ack.weaknesses
            else "new",
        )
        for key in keys
    )
    return ReviewRow(
        name=name,
        href=href,
        reach=reach,
        marks=marks,
        keys=tuple(keys),
        state=state,
        accepted_by=ack.accepted_by if ack is not None and accepted else "",
        accepted_at=ack.accepted_at if ack is not None and accepted else None,
    )


def review(
    clusters: Sequence[tuple[str, int | None, str]],
    stored: Mapping[str, Sequence[ObjectView]],
    unmanaged: Mapping[str, Sequence[ProxyView]],
    acks: Mapping[tuple[str, str], ReviewAck],
    view: ReviewView,
    *,
    waf_offered: bool,
    editable: bool,
) -> Review:
    """Every cluster's rows, alphabetical, each against its acceptance."""

    built: list[ReviewCluster] = []
    for cluster, accent, tone in clusters:
        rows: list[ReviewRow] = []
        for obj in stored.get(cluster, ()):
            read = _read(obj.name, obj.document, waf_offered) if obj.readable else None
            if read is None:
                continue
            keys, reach = read
            rows.append(
                _row(
                    cluster, obj.name, keys, reach, acks.get((cluster, obj.name)), editable=editable
                )
            )
        for proxy in unmanaged.get(cluster, ()):
            rows.append(
                _row(
                    cluster,
                    proxy.name,
                    ("manual",),
                    "—",
                    acks.get((cluster, proxy.name)),
                    editable=editable,
                )
            )
        built.append(
            ReviewCluster(
                cluster=cluster,
                accent=accent,
                rows=tuple(sorted(rows, key=lambda row: row.name)),
                shown=cluster not in view.hidden_clusters,
                tone=tone,
            )
        )
    return Review(clusters=tuple(built), view=view)


def gone(
    acks: Collection[tuple[str, str]], present: Mapping[str, Collection[str]]
) -> set[tuple[str, str]]:
    """Acceptances whose object is no longer there, in a cluster whose objects were read.

    `present` holds every name a read cluster has, a document this version
    cannot read included; a cluster nobody could read is not in it, and says
    nothing about what is gone from it.
    """

    return {key for key in acks if key[0] in present and key[1] not in present[key[0]]}


def row_keys(review: Review, cluster: str, name: str) -> tuple[str, ...] | None:
    """The marks one row has now, or None where the page shows no such row."""

    for listed in review.clusters:
        if listed.cluster != cluster:
            continue
        for row in listed.rows:
            if row.name == name:
                return row.keys
    return None
