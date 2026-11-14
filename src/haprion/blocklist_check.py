"""What *Test* and *Check address* on Settings -> Blocklists answer (B496 nr 13, B500).

*Test* fetches a list as the form holds it, saving nothing and keeping
nothing: how many addresses it holds, how many lines were not addresses, and
what the exceptions take out of it in each cluster - a group an exception
names is each cluster's own, so the count can differ between them.

*Check address* answers from the lists the timer keeps, the last good fetch
of each: which lists hold the address, when that list was fetched, and in
which clusters an exception keeps it off the nodes. It never fetches.

Both run as root in `haprion-blocklist-check-helper`, since the saved secret
and the kept lists are root's; the command `haprion-blocklist-check` is the
same code from a terminal.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from haprion import address_ranges, blocklists, exit_codes
from haprion.blocklist_store import ListState
from haprion.labels import noun

Fetch = Callable[[blocklists.Definition, str], bytes]
Groups = Mapping[str, Mapping[str, Sequence[str]]]
"""Each cluster's network groups, by cluster: what an exception's group names mean there."""

Kept = Callable[[str], "tuple[blocklists.Network, ...] | None"]


class CheckError(Exception):
    """A question that could not be asked, as a stable code and a sentence."""

    def __init__(self, code: str, message: str, *, exit_code: int = exit_codes.REFUSED) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


def _figure(count: int) -> str:
    return f"{count:,}".replace(",", " ")


def _moment(stamp: str | None) -> str:
    """A kept time in the app's format, on this machine's clock."""

    if stamp is None:
        return "never"
    return dt.datetime.fromisoformat(stamp).astimezone().strftime("%y-%m-%d %H:%M:%S")


def _entry(entry: str) -> str:
    """An exception as written back: a single address bare, as the list files write it."""

    for single in ("/32", "/128"):
        if entry.endswith(single):
            return entry.removesuffix(single)
    return entry


def _names(names: Sequence[str]) -> str:
    return ", ".join(names[:-1]) + f" and {names[-1]}" if len(names) > 1 else names[0]


# - Test --------------------------------------------------------------------


@dataclass(frozen=True)
class ClusterExcept:
    """What one list's exceptions take out in one cluster."""

    cluster: str
    excepted: int
    unknown_groups: tuple[str, ...]


@dataclass(frozen=True)
class Tested:
    """A list fetched once to see it, or why it could not be."""

    name: str
    answer: Literal["fetched", "failed"]
    entries: int
    skipped: int
    excepts: tuple[str, ...]
    clusters: tuple[ClusterExcept, ...]
    problem: str | None
    """Why the list could not be fetched or read (`failed` only)."""
    unread: tuple[str, ...] = ()
    """Clusters whose network description could not be read, so their exceptions are not counted."""

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": "list",
            "name": self.name,
            "answer": self.answer,
            "entries": self.entries,
            "skipped": self.skipped,
            "excepts": list(self.excepts),
            "clusters": [
                {
                    "cluster": item.cluster,
                    "excepted": item.excepted,
                    "unknown_groups": list(item.unknown_groups),
                }
                for item in self.clusters
            ],
            "problem": self.problem,
            **({"unread": list(self.unread)} if self.unread else {}),
        }

    @classmethod
    def from_dict(cls, result: Mapping[str, Any]) -> Tested:
        """The helper's `list` result read back; KeyError or TypeError when it is not one."""

        if result.get("kind") != "list" or result["answer"] not in ("fetched", "failed"):
            raise TypeError("not a test's answer")
        return cls(
            name=str(result["name"]),
            answer=result["answer"],
            entries=int(result["entries"]),
            skipped=int(result["skipped"]),
            excepts=tuple(str(entry) for entry in result["excepts"]),
            clusters=tuple(
                ClusterExcept(
                    cluster=str(item["cluster"]),
                    excepted=int(item["excepted"]),
                    unknown_groups=tuple(str(group) for group in item["unknown_groups"]),
                )
                for item in result["clusters"]
            ),
            problem=None if result["problem"] is None else str(result["problem"]),
            unread=tuple(str(cluster) for cluster in result.get("unread", ())),
        )

    def sentence(self) -> str:
        """The answer in plain words, the way the terminal and the form say it."""

        if self.answer == "failed":
            return f"Not fetched: {self.problem}."
        said = [f"{_figure(self.entries)} addresses"]
        if self.skipped:
            said.append(f"{_figure(self.skipped)} {noun(self.skipped, 'line')} skipped or cut back")
        if self.excepts and self.clusters:
            counts = {item.excepted for item in self.clusters}
            if len(counts) == 1:
                taken = f"{_figure(counts.pop())} excepted"
            else:
                taken = "excepted " + ", ".join(
                    f"{_figure(item.excepted)} on {item.cluster}" for item in self.clusters
                )
            said.append(f"{taken} ({', '.join(_entry(e) for e in self.excepts)})")
        missing: dict[str, list[str]] = {}
        for item in self.clusters:
            for group in item.unknown_groups:
                missing.setdefault(group, []).append(item.cluster)
        for group, clusters in missing.items():
            said.append(f"{group} is not a group on {_names(clusters)}")
        if self.unread:
            said.append(f"the network of {_names(self.unread)} could not be read")
        return " · ".join(said)


def test(
    item: blocklists.Definition,
    secret: str,
    groups: Groups,
    *,
    fetch: Fetch = blocklists.fetch,
    unread: Sequence[str] = (),
) -> Tested:
    """Fetch `item` once and read it as the timer would; nothing is kept."""

    try:
        parsed = blocklists.parse(fetch(item, secret))
    except (blocklists.BlocklistError, ValueError) as exc:
        return Tested(
            name=item.name,
            answer="failed",
            entries=0,
            skipped=0,
            excepts=item.excepts,
            clusters=(),
            problem=str(exc),
        )
    clusters: list[ClusterExcept] = []
    if item.excepts:
        for cluster in sorted(groups):
            count, unknown = blocklists.excepted(parsed.networks, item.excepts, groups[cluster])
            clusters.append(ClusterExcept(cluster, count, unknown))
    return Tested(
        name=item.name,
        answer="fetched",
        entries=len(parsed.networks),
        skipped=parsed.skipped,
        excepts=item.excepts,
        clusters=tuple(clusters),
        problem=None,
        unread=tuple(unread) if item.excepts else (),
    )


# - Check address -----------------------------------------------------------


@dataclass(frozen=True)
class Listed:
    """One kept list that holds the address."""

    name: str
    network: str
    """The list's entry the address is in: the address itself, or a network."""
    fetched_at: str | None
    excepted_on: tuple[str, ...]
    """The clusters whose exceptions keep the address off this list's file."""
    clusters: tuple[str, ...]
    """Every cluster the list goes to, so 'excepted everywhere' can be told from 'on some'."""

    def sentence(self, address: str) -> str:
        """Where the address is listed, and what the proxies do with it (said plainly 26-11-14).

        "It is not excepted" left the reader to work out the consequence. A
        proxy only acts on the list where it names it under Denied, and there
        its Denied mode decides: refused, or logged and served.
        """

        where = "" if self.network == address else f" ({self.network})"
        said = f"{address} is on {self.name}{where}, fetched {_moment(self.fetched_at)}."
        acting = f"proxies that use {self.name} refuse it, or log it where Denied is log only."
        if not self.excepted_on:
            return f"{said} {acting[0].upper()}{acting[1:]}"
        if set(self.excepted_on) == set(self.clusters):
            return f"{said} Every cluster excepts it, so no proxy refuses it for {self.name}."
        return f"{said} {_names(self.excepted_on)} {'excepts' if len(self.excepted_on) == 1 else 'except'} it; elsewhere {acting}"


@dataclass(frozen=True)
class AddressCheck:
    address: str
    lists: tuple[Listed, ...]
    unfetched: tuple[str, ...]
    """Lists with no good fetch kept yet: they hold nothing to look in."""
    unread: tuple[str, ...] = ()
    """Clusters whose network description could not be read, so their exceptions are not applied."""

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": "address",
            "address": self.address,
            "lists": [
                {
                    "name": item.name,
                    "network": item.network,
                    "fetched_at": item.fetched_at,
                    "excepted_on": list(item.excepted_on),
                    "clusters": list(item.clusters),
                }
                for item in self.lists
            ],
            "unfetched": list(self.unfetched),
            **({"unread": list(self.unread)} if self.unread else {}),
        }

    @classmethod
    def from_dict(cls, result: Mapping[str, Any]) -> AddressCheck:
        """The helper's `address` result read back; KeyError or TypeError when it is not one."""

        if result.get("kind") != "address":
            raise TypeError("not an address check's answer")
        return cls(
            address=str(result["address"]),
            lists=tuple(
                Listed(
                    name=str(item["name"]),
                    network=str(item["network"]),
                    fetched_at=None if item["fetched_at"] is None else str(item["fetched_at"]),
                    excepted_on=tuple(str(cluster) for cluster in item["excepted_on"]),
                    clusters=tuple(str(cluster) for cluster in item["clusters"]),
                )
                for item in result["lists"]
            ),
            unfetched=tuple(str(name) for name in result["unfetched"]),
            unread=tuple(str(cluster) for cluster in result.get("unread", ())),
        )

    def sentence(self) -> str:
        said = [item.sentence(self.address) for item in self.lists]
        if not said:
            said.append(f"{self.address} is on no blocklist.")
        if self.unfetched:
            verb = "has" if len(self.unfetched) == 1 else "have"
            said.append(f"{_names(self.unfetched)} {verb} not been fetched yet.")
        if self.unread:
            said.append(
                f"The network of {_names(self.unread)} could not be read, "
                "so its exceptions are not shown."
            )
        return " ".join(said)


def checked_address(value: object) -> str:
    """One address as written back, or `CheckError`: a network is a list's business, not a question."""

    if not isinstance(value, str) or len(value) > 45:
        raise CheckError("bad_input", "the address is one IPv4 or IPv6 address")
    try:
        found = address_ranges.plain_address(value)
    except ValueError:
        raise CheckError("bad_input", f"{value} is not an IPv4 or IPv6 address") from None
    mapped = getattr(found, "ipv4_mapped", None)
    return str(mapped if mapped is not None else found)


def check_address(
    address: str,
    definitions: Sequence[blocklists.Definition],
    states: Mapping[str, ListState],
    groups: Groups,
    *,
    kept: Kept,
    unread: Sequence[str] = (),
) -> AddressCheck:
    """Which kept lists hold `address`, and where an exception keeps it off the nodes."""

    wanted = checked_address(address)
    listed: list[Listed] = []
    unfetched: list[str] = []
    for item in sorted(definitions, key=lambda entry: entry.name):
        networks = kept(item.name)
        if networks is None:
            unfetched.append(item.name)
            continue
        found = blocklists.contains(networks, wanted)
        if found is None:
            continue
        excepted_on = []
        for cluster in sorted(groups):
            taken, _unknown = blocklists.except_networks(item.excepts, groups[cluster])
            if blocklists.contains(taken, wanted) is not None:
                excepted_on.append(cluster)
        state = states.get(item.name)
        listed.append(
            Listed(
                name=item.name,
                network=wanted if found.num_addresses == 1 else str(found),
                fetched_at=state.fetched_at if state else None,
                excepted_on=tuple(excepted_on),
                clusters=tuple(sorted(groups)),
            )
        )
    return AddressCheck(
        address=wanted, lists=tuple(listed), unfetched=tuple(unfetched), unread=tuple(unread)
    )
