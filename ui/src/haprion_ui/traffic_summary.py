"""What a cluster's VIPs carry, for its header on the dashboard: requests and bytes, now and over a day.

Read from the same stored readings and the same differencing as the metrics
page's cards (`db.read_traffic_summary`), so the dashboard and a card cannot
disagree about what a counter did. Two windows: the last day for the totals,
and the last few minutes for the rates, because a rate averaged over a day says
nothing about whether traffic is flowing now.

A window nothing could be counted in is shown as a dash, never as nought: no
readings is not no traffic.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from haprion_ui.metrics import BackendMeasurement, Total

DAY = timedelta(hours=24)
#
# Long enough to hold a dozen or so readings at the default 20-second poll,
# short enough to still mean "now". A slower poll is given three readings.
#
RECENT = timedelta(minutes=5)
DASH = "—"
#
# Response times come from the traffic log, one record per request, so they
# need more than a few minutes to say anything at a quiet installation.
#
RESPONSE_WINDOW = timedelta(hours=1)


def recent_window(poll_seconds: int) -> timedelta:
    return max(RECENT, timedelta(seconds=poll_seconds * 3))


def _figure(value: float) -> str:
    """Three significant figures at most: 3.2, 38, 247."""

    if value == 0:
        return "0"
    return f"{value:.1f}" if value < 10 else f"{value:.0f}"


def _scaled(value: float, units: tuple[str, ...], step: float) -> str:
    for unit in units[:-1]:
        if value < step:
            return f"{_figure(value)} {unit}"
        value /= step
    return f"{_figure(value)} {units[-1]}"


def count(value: int) -> str:
    """A request count short enough for a line: 950, 12k, 4.6M, 80M, 1.2B."""

    if value < 1000:
        return str(value)
    return _scaled(float(value), ("", "k", "M", "B", "T", "Q"), 1000.0).replace(" ", "")


def size(octets: int) -> str:
    """Bytes in decimal units, as an interface's counters are read: 3.4 GB."""

    return _scaled(float(octets), ("B", "kB", "MB", "GB", "TB", "PB", "EB"), 1000.0)


def bitrate(octets: int, seconds: float) -> str:
    """Bytes over a span as bits per second, the unit a link is sized in."""

    return _scaled(
        octets * 8 / seconds, ("bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s", "Pbit/s"), 1000.0
    )


@dataclass(frozen=True, slots=True)
class TrafficRow:
    requests: str
    request_rate: str
    inbound: str
    outbound: str
    inbound_day: str
    outbound_day: str
    response_median: str = DASH
    response_p95: str = ""


def milliseconds(value: int) -> str:
    """A response time in the unit it is read in: 38 ms, 1.5 s, 3.0 min, 2.0 h."""

    if value < 1000:
        return f"{value} ms"
    for unit, size_ in (("s", 1000), ("min", 60_000), ("h", 3_600_000)):
        scaled = value / size_
        if unit == "h" or scaled < {"s": 60, "min": 60}[unit]:
            return f"{_figure(scaled)} {unit}"
    raise AssertionError("unreachable")


def _total(measurement: BackendMeasurement, label: str) -> Total | None:
    found = next((total for total in measurement.totals if total.label == label), None)
    if found is None or not found.known or measurement.intervals == 0:
        return None
    return found


def _seconds(measurement: BackendMeasurement) -> float:
    if measurement.started_at is None or measurement.ended_at is None:
        return 0.0
    return (measurement.ended_at - measurement.started_at).total_seconds()


def row(
    day: BackendMeasurement,
    recent: BackendMeasurement,
    responses: tuple[int, int | None, int | None] | None = None,
) -> TrafficRow:
    """`responses` is `db.read_response_times`, or None where the traffic log is off."""

    requests = _total(day, "Requests")
    inbound_day = _total(day, "Bytes in")
    outbound_day = _total(day, "Bytes out")
    seconds = _seconds(recent)
    rate_requests = _total(recent, "Requests") if seconds > 0 else None
    rate_in = _total(recent, "Bytes in") if seconds > 0 else None
    rate_out = _total(recent, "Bytes out") if seconds > 0 else None
    return TrafficRow(
        requests=DASH if requests is None else count(requests.value),
        request_rate="" if rate_requests is None else f"{_figure(rate_requests.value / seconds)}/s",
        inbound=DASH if rate_in is None else bitrate(rate_in.value, seconds),
        outbound=DASH if rate_out is None else bitrate(rate_out.value, seconds),
        inbound_day="" if inbound_day is None else size(inbound_day.value),
        outbound_day="" if outbound_day is None else size(outbound_day.value),
        response_median=(
            DASH if responses is None or responses[1] is None else milliseconds(responses[1])
        ),
        response_p95=(
            "" if responses is None or responses[2] is None else milliseconds(responses[2])
        ),
    )
