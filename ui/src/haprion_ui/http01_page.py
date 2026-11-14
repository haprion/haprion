"""Certificates -> HTTP-01: where each cluster sends Let's Encrypt's challenge (PL17).

A cluster's setting is the `acme_challenge` section of its `managed/cluster.yaml`,
the file *Logs & metrics* edits, and is saved the same way: a draft that goes out
with the next publish. This module reads the poller's `cluster_settings` rows,
says one line per cluster, and turns the form into the one field it owns - the
rest of the settings are kept as they are.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import quote

from haprion import cluster_settings
from haprion.config import ConfigError

from haprion_ui.cluster_settings_page import FormProblem, sentence

NOT_SENT = "Not sent — HTTP-01 cannot be used"


@dataclass(frozen=True, slots=True)
class ClusterRow:
    cluster: str
    href: str
    readable: bool
    sent_to: str


@dataclass(frozen=True, slots=True)
class Http01Form:
    on: bool = False
    address: str = ""
    port: str = ""


def href(cluster: str) -> str:
    return "/http01/" + quote(cluster, safe="")


def challenge_of(result: Mapping[str, Any]) -> cluster_settings.AcmeChallenge | None:
    """The challenge a reading carries, or None when it names none."""

    raw = result.get("acme_challenge")
    if not isinstance(raw, Mapping):
        return None
    address, port = raw.get("address"), raw.get("port")
    if not isinstance(address, str) or type(port) is not int:
        return None
    return cluster_settings.AcmeChallenge(address, port)


def target(challenge: cluster_settings.AcmeChallenge | None) -> str:
    """`address:port`, an IPv6 address in brackets; the words for none."""

    if challenge is None:
        return NOT_SENT
    shown = f"[{challenge.address}]" if ":" in challenge.address else challenge.address
    return f"{shown}:{challenge.port}"


def rows(clusters: Sequence[str], readings: Iterable[Any]) -> list[ClusterRow]:
    """One row per listed cluster, in the order the installation lists them."""

    by_cluster = {row.cluster: row for row in readings}
    result: list[ClusterRow] = []
    for cluster in clusters:
        row = by_cluster.get(cluster)
        reading = row.result if row is not None and row.outcome == "done" else None
        readable = isinstance(reading, Mapping)
        result.append(
            ClusterRow(
                cluster=cluster,
                href=href(cluster),
                readable=readable,
                sent_to=target(challenge_of(reading)) if isinstance(reading, Mapping) else "",
            )
        )
    return result


def form_from(challenge: cluster_settings.AcmeChallenge | None) -> Http01Form:
    if challenge is None:
        return Http01Form(port=str(cluster_settings.DEFAULT_ACME_PORT))
    return Http01Form(on=True, address=challenge.address, port=str(challenge.port))


def challenge_from(form: Http01Form) -> cluster_settings.AcmeChallenge | None:
    """The setting the form describes, checked by the engine's own parser."""

    if not form.on:
        return None
    address = form.address.strip()
    if not address:
        raise FormProblem("The manager address is needed.")
    entry: dict[str, Any] = {"address": address}
    port = form.port.strip()
    if port:
        if not port.isascii() or not port.isdigit():
            raise FormProblem("The port must be a number.")
        entry["port"] = int(port)
    try:
        return cluster_settings.load_mapping({"acme_challenge": entry}).acme_challenge
    except ConfigError as exc:
        raise FormProblem(sentence(str(exc))) from exc


def with_challenge(
    settings: cluster_settings.ClusterSettings, challenge: cluster_settings.AcmeChallenge | None
) -> cluster_settings.ClusterSettings:
    """The settings as they were, with only this field changed."""

    return replace(settings, acme_challenge=challenge)
