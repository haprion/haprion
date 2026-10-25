"""Countries as networks, from the IPFire Location database (Fas 21, B228).

An object names a country as `country:SE` wherever it names an address group;
publishing turns each country some object names into a file of networks the
nodes load with `-f`. The networks are read here, from the database the
`location` package keeps current on the management host, and nowhere else.

Why a reader and not data: which countries are needed is known only once the
objects being published have been read, and that happens inside the publishing
module, which opens nothing itself (B66). The caller hands it this reader; the
module asks it for exactly the countries it found.

Why the import is inside the function: `python3-location` is a system package
for the system interpreter the CLI runs on. An installation that names no
country never needs it, and should not fail to publish for want of it.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from haprion.config import ConfigError

DEFAULT_DATABASE = Path("/var/lib/location/database.db")
COUNTRY = re.compile(r"^[A-Z]{2}$")
PREFIX = "country:"


class GeoUnavailable(ConfigError):
    """The countries an object names cannot be turned into networks."""


@dataclass(frozen=True, slots=True)
class Countries:
    """Networks per country, and the day the database was built."""

    stamp: str
    networks: Mapping[str, tuple[str, ...]] = field(default_factory=dict)


CountryReader = Callable[[Collection[str]], Countries]


def is_country(entry: str) -> bool:
    return entry.startswith(PREFIX)


def code(entry: str) -> str:
    """`country:SE` -> `SE`."""

    return entry[len(PREFIX) :]


def file_name(country: str) -> str:
    """The node's file for one country, as the generator names it."""

    return f"geo-{country.lower()}.lst"


def location_database(path: Path = DEFAULT_DATABASE) -> CountryReader:
    """A reader over the installed database, opened only when a country is asked for."""

    def read(countries: Collection[str]) -> Countries:
        try:
            import location  # type: ignore[import-not-found]
        except ImportError as exc:
            raise GeoUnavailable(
                "an object names a country, and the IPFire Location library is not installed "
                "on the management host (apt install location python3-location)"
            ) from exc
        if not path.is_file():
            raise GeoUnavailable(
                f"an object names a country, and there is no location database at {path} "
                f"(run 'location update' once, and enable location-update.timer)"
            )
        database = location.Database(str(path))
        stamp = time.strftime("%Y-%m-%d", time.gmtime(database.created_at))
        networks: dict[str, tuple[str, ...]] = {}
        for country in sorted(countries):
            found = tuple(
                sorted(
                    str(network)
                    for network in database.search_networks(country_codes=[country], flatten=True)
                )
            )
            if not found:
                raise GeoUnavailable(
                    f"the location database knows no networks for the country {country}"
                )
            networks[country] = found
        return Countries(stamp=stamp, networks=networks)

    return read


def database_stamp(path: Path = DEFAULT_DATABASE) -> str | None:
    """The day the installed database was built, or None if there is none to read.

    None rather than an error: a listing that cannot say how fresh the data
    is still lists the objects, and an installation that names no country has
    no reason to have the library at all.
    """

    try:
        import location
    except ImportError:
        return None
    if not path.is_file():
        return None
    try:
        created = location.Database(str(path)).created_at
    except (OSError, ValueError):
        return None
    return time.strftime("%Y-%m-%d", time.gmtime(created))


STAMP = re.compile(r"^# IPFire Location (\d{4}-\d{2}-\d{2}) ")


def published_stamp(files: Mapping[str, bytes], prefix: str = "managed/maps/") -> str | None:
    """The oldest database date among a tree's country files; None if it has none."""

    stamps = []
    for path, content in files.items():
        if not path.startswith(f"{prefix}geo-"):
            continue
        found = STAMP.match(content.split(b"\n", 1)[0].decode("utf-8", "replace"))
        if found:
            stamps.append(found.group(1))
    return min(stamps) if stamps else None


def tree_reader(
    files: Mapping[str, bytes], fallback: CountryReader, prefix: str = "managed/maps/"
) -> CountryReader:
    """A reader over the country files a version carries, `fallback` for the rest.

    A revert gives back the networks the version ran, not today's database
    (B366). A country the version has no file for - it named none, or the
    file is damaged - is read from `fallback`, all of them at once, so one
    answer has one stamp.
    """

    def read(countries: Collection[str]) -> Countries:
        stamps: set[str] = set()
        networks: dict[str, tuple[str, ...]] = {}
        for country in sorted(countries):
            content = files.get(f"{prefix}{file_name(country)}")
            if content is None:
                return fallback(countries)
            header, _, body = content.decode("utf-8", "replace").partition("\n")
            found = STAMP.match(header)
            if found is None or not header.endswith(f" {country}"):
                return fallback(countries)
            stamps.add(found.group(1))
            networks[country] = tuple(line for line in body.split("\n") if line)
        if len(stamps) > 1:
            return fallback(countries)
        return Countries(stamp=stamps.pop() if stamps else "", networks=networks)

    return read
