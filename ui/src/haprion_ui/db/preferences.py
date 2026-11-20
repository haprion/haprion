"""The installation's own switches and answers: features, attention, updates, status access."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import class_row
from psycopg.types.json import Jsonb


@dataclass(frozen=True, slots=True)
class FeatureSwitch:
    """One of the capabilities an installation may turn off (0040, B193)."""

    name: str
    enabled: bool
    remembered: dict[str, Any]
    updated_at: datetime
    updated_by: str | None


def feature_switches(connection: Connection[Any]) -> dict[str, FeatureSwitch]:
    """Every switch by name. Before 0040 there are none, and everything is on."""

    with connection.cursor(row_factory=class_row(FeatureSwitch)) as cursor:
        cursor.execute(
            "select name, enabled, remembered, updated_at, updated_by from feature_switch"
        )
        return {row.name: row for row in cursor.fetchall()}


def set_feature_switch(
    connection: Connection[Any],
    *,
    name: str,
    enabled: bool,
    remembered: Mapping[str, Any],
    actor: str,
) -> bool:
    """Flip one switch, if it is not already where it is asked to go.

    The condition is in the statement, so two admins pressing the same button
    at once flip it once: the second finds it already flipped and is told so.
    """

    with connection.cursor() as cursor:
        cursor.execute(
            "update feature_switch "
            "   set enabled = %(enabled)s, remembered = %(remembered)s, updated_by = %(actor)s "
            " where name = %(name)s and enabled is distinct from %(enabled)s",
            {
                "name": name,
                "enabled": enabled,
                "remembered": Jsonb(dict(remembered)),
                "actor": actor,
            },
        )
        return cursor.rowcount == 1


@dataclass(frozen=True, slots=True)
class StatusAccess:
    """One network allowed to ask `/status/` what needs doing (B274)."""

    network: str
    added_by: str
    added_at: datetime


#
# A row of *Needs attention* by kind, cluster ('' for none), subject, the
# severity it was acknowledged as and its variant ('' for none) (B299, B406).
#
type AttentionKey = tuple[str, str, str, str, str]


def attention_acks(connection: Connection[Any]) -> set[AttentionKey]:
    """The rows an admin has acknowledged (0073)."""

    with connection.cursor() as cursor:
        cursor.execute("select kind, cluster, subject, severity, variant from attention_ack")
        return {
            (str(kind), str(cluster), str(subject), str(severity), str(variant))
            for kind, cluster, subject, severity, variant in cursor
        }


def acknowledge_attention(connection: Connection[Any], key: AttentionKey, *, actor: str) -> bool:
    """Acknowledge one row; False when it already was."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into attention_ack (kind, cluster, subject, severity, variant, acknowledged_by) "
            "values (%s, %s, %s, %s, %s, %s) on conflict do nothing",
            (*key, actor),
        )
        return cursor.rowcount == 1


def forget_attention_acks(connection: Connection[Any], gone: set[AttentionKey]) -> None:
    """Remove acknowledgements whose row has gone, so the row is new if it comes back."""

    with connection.cursor() as cursor:
        for key in sorted(gone):
            cursor.execute(
                "delete from attention_ack where kind = %s and cluster = %s and subject = %s"
                " and severity = %s and variant = %s",
                key,
            )


def getting_started_hidden_at(connection: Connection[Any]) -> datetime | None:
    """When an admin hid the getting started list (0075); None while it shows."""

    with connection.cursor() as cursor:
        cursor.execute("select hidden_at from getting_started")
        row = cursor.fetchone()
        if row is None:
            return None
        hidden_at: datetime = row[0]
        return hidden_at


def hide_getting_started(connection: Connection[Any], *, actor: str) -> bool:
    """Hide the list for the whole installation; False when it already was."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into getting_started (hidden_by) values (%s) on conflict do nothing", (actor,)
        )
        return cursor.rowcount == 1


@dataclass(frozen=True, slots=True)
class UpdateCheck:
    """What the poller last heard from GitHub about the newest release (0081, B342).

    `latest_tag`/`latest_url`/`checked_at` are the last answer and outlive a
    failure after it; `failing_since` is the first failure since that answer.
    """

    latest_tag: str | None
    latest_url: str | None
    checked_at: datetime | None
    attempted_at: datetime
    failing_since: datetime | None


def update_check(connection: Connection[Any]) -> UpdateCheck | None:
    """The one row, or None before the first ask."""

    with connection.cursor(row_factory=class_row(UpdateCheck)) as cursor:
        cursor.execute(
            "select latest_tag, latest_url, checked_at, attempted_at, failing_since "
            "  from update_check"
        )
        return cursor.fetchone()


def switch_enabled(connection: Connection[Any], name: str) -> bool:
    """Whether one feature switch is on, as the poller asks it (0081)."""

    with connection.cursor() as cursor:
        cursor.execute("select enabled from feature_switch where name = %s", (name,))
        row = cursor.fetchone()
        return bool(row and row[0])


def record_update_answer(connection: Connection[Any], *, tag: str, url: str, at: datetime) -> None:
    """GitHub answered: the release it named, and no failure since."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into update_check "
            "       (latest_tag, latest_url, checked_at, attempted_at, failing_since, error) "
            "values (%(tag)s, %(url)s, %(at)s, %(at)s, null, null) "
            "on conflict (only_row) do update "
            "   set latest_tag = excluded.latest_tag, latest_url = excluded.latest_url, "
            "       checked_at = excluded.checked_at, attempted_at = excluded.attempted_at, "
            "       failing_since = null, error = null",
            {"tag": tag, "url": url, "at": at},
        )


def record_update_failure(connection: Connection[Any], *, error: str, at: datetime) -> None:
    """GitHub did not answer: the last answer stays, and the failure keeps its first time."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into update_check (attempted_at, failing_since, error) "
            "values (%(at)s, %(at)s, %(error)s) "
            "on conflict (only_row) do update "
            "   set attempted_at = excluded.attempted_at, "
            "       failing_since = coalesce(update_check.failing_since, excluded.failing_since), "
            "       error = excluded.error",
            {"at": at, "error": error[:300]},
        )


@dataclass(frozen=True, slots=True)
class PackageWaiting:
    """One of the manager's packages with a newer version in the repository (0088, B357)."""

    name: str
    installed: str
    available: str
    read_at: datetime


def package_waiting(connection: Connection[Any]) -> list[PackageWaiting]:
    """Every package with a newer version waiting, by name; none when all are current."""

    with connection.cursor(row_factory=class_row(PackageWaiting)) as cursor:
        cursor.execute(
            "select name, installed, available, read_at from package_waiting order by name"
        )
        return cursor.fetchall()


def replace_package_waiting(
    connection: Connection[Any], rows: Sequence[tuple[str, str, str]], *, at: datetime
) -> None:
    """The packages behind as the poller found them, `(name, installed, available)` each."""

    with connection.cursor() as cursor:
        cursor.execute("delete from package_waiting")
        for name, installed, available in rows:
            cursor.execute(
                "insert into package_waiting (name, installed, available, read_at) "
                "values (%s, %s, %s, %s)",
                (name, installed, available, at),
            )


def show_getting_started(connection: Connection[Any]) -> bool:
    """Show the list again (0076); False when it was not hidden."""

    with connection.cursor() as cursor:
        cursor.execute("delete from getting_started")
        return cursor.rowcount == 1


def status_access(connection: Connection[Any]) -> list[StatusAccess]:
    with connection.cursor(row_factory=class_row(StatusAccess)) as cursor:
        cursor.execute(
            "select network::text as network, added_by, added_at "
            "  from status_access order by network"
        )
        return cursor.fetchall()


def set_status_access(connection: Connection[Any], *, networks: Sequence[str], actor: str) -> None:
    """The list as given, in the caller's transaction (B274).

    Only what changed is written: an address that stays keeps who added it and
    when. Replacing the whole list gave every address the last saver's name
    and time (26-10-12), which the edit page shows beside each one.
    """

    wanted = list(networks)
    with connection.cursor() as cursor:
        cursor.execute(
            "delete from status_access where network <> all(%(wanted)s::cidr[])",
            {"wanted": wanted},
        )
        #
        # `on conflict`, not `where not exists`: two saves at once both saw the
        # address missing, and the second met the unique index and answered 500
        # (review 2026-10-22, 3-9).
        #
        for network in wanted:
            cursor.execute(
                "insert into status_access (network, added_by) "
                "values (%(network)s::cidr, %(actor)s) "
                "on conflict (network) do nothing",
                {"network": network, "actor": actor},
            )


@dataclass(frozen=True, slots=True)
class ReviewAck:
    """An object an admin accepted on *Protection review* (0122): the weaknesses it had then."""

    weaknesses: frozenset[str]
    accepted_by: str
    accepted_at: datetime


@dataclass(frozen=True, slots=True)
class ReviewView:
    """The view's shared choices (0122). Before anybody chose, everything shows."""

    show_clean: bool = True
    hidden_clusters: frozenset[str] = frozenset()


def review_state(
    connection: Connection[Any],
) -> tuple[dict[tuple[str, str], ReviewAck], ReviewView]:
    """Every acceptance by (cluster, object), and the view's choices, in one read."""

    with connection.cursor() as cursor:
        cursor.execute(
            "select cluster, subject, weaknesses, accepted_by, accepted_at"
            "  from protection_review_ack"
        )
        acks = {
            (str(cluster), str(subject)): ReviewAck(
                weaknesses=frozenset(str(item) for item in weaknesses),
                accepted_by=str(accepted_by),
                accepted_at=accepted_at,
            )
            for cluster, subject, weaknesses, accepted_by, accepted_at in cursor
        }
        cursor.execute("select show_clean, hidden_clusters from protection_review_view")
        row = cursor.fetchone()
    view = (
        ReviewView()
        if row is None
        else ReviewView(show_clean=bool(row[0]), hidden_clusters=frozenset(row[1]))
    )
    return acks, view


def accept_review(
    connection: Connection[Any],
    *,
    cluster: str,
    subject: str,
    weaknesses: Sequence[str],
    actor: str,
) -> None:
    """Accept one object with the weaknesses it has now, replacing an earlier acceptance."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into protection_review_ack (cluster, subject, weaknesses, accepted_by)"
            " values (%(cluster)s, %(subject)s, %(weaknesses)s, %(actor)s)"
            " on conflict (cluster, subject) do update"
            "   set weaknesses = excluded.weaknesses, accepted_by = excluded.accepted_by,"
            "       accepted_at = statement_timestamp()",
            {
                "cluster": cluster,
                "subject": subject,
                "weaknesses": sorted(weaknesses),
                "actor": actor,
            },
        )


def undo_review(connection: Connection[Any], *, cluster: str, subject: str) -> bool:
    """Take an acceptance back; False when there was none."""

    with connection.cursor() as cursor:
        cursor.execute(
            "delete from protection_review_ack where cluster = %s and subject = %s",
            (cluster, subject),
        )
        return cursor.rowcount == 1


def forget_review_acks(connection: Connection[Any], gone: set[tuple[str, str]]) -> None:
    """Remove the acceptances of objects that are gone, so one made again starts afresh."""

    with connection.cursor() as cursor:
        for cluster, subject in sorted(gone):
            cursor.execute(
                "delete from protection_review_ack where cluster = %s and subject = %s",
                (cluster, subject),
            )


def set_review_view(connection: Connection[Any], view: ReviewView, *, actor: str) -> None:
    """Store the view's shared choices."""

    with connection.cursor() as cursor:
        cursor.execute(
            "insert into protection_review_view (id, show_clean, hidden_clusters, updated_by)"
            " values (true, %(show_clean)s, %(hidden)s, %(actor)s)"
            " on conflict (id) do update"
            "   set show_clean = excluded.show_clean, hidden_clusters = excluded.hidden_clusters,"
            "       updated_by = excluded.updated_by, updated_at = statement_timestamp()",
            {
                "show_clean": view.show_clean,
                "hidden": sorted(view.hidden_clusters),
                "actor": actor,
            },
        )
