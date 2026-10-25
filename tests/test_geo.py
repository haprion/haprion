"""The location database reader (B228), against a stand-in for the library.

The library is a system package for Python 3.14 and the development
environment is 3.13, so the module is stood in for here; the real reading is
proved against the installed package on the management host.
"""

from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from haprion import geo, objects


def fake_library(networks: dict[str, list[str]]) -> types.ModuleType:
    module = types.ModuleType("location")

    class Database:
        created_at = 1_790_000_000

        def __init__(self, path: str) -> None:
            self.path = path

        def search_networks(self, *, country_codes: list[str], flatten: bool) -> list[str]:
            assert flatten
            return networks.get(country_codes[0], [])

    module.Database = Database  # type: ignore[attr-defined]
    return module


class ReadingCountries(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / "database.db"
        self.database.write_bytes(b"")

    def read(self, countries: set[str], networks: dict[str, list[str]]) -> geo.Countries:
        with mock.patch.dict(sys.modules, {"location": fake_library(networks)}):
            return geo.location_database(self.database)(countries)

    def test_networks_are_sorted_and_dated_by_the_database(self) -> None:
        countries = self.read({"SE"}, {"SE": ["198.51.100.0/24", "192.0.2.0/24"]})

        self.assertEqual(countries.networks, {"SE": ("192.0.2.0/24", "198.51.100.0/24")})
        self.assertEqual(countries.stamp, "2026-09-21")

    def test_a_country_the_database_does_not_know_is_refused(self) -> None:
        with self.assertRaises(geo.GeoUnavailable) as raised:
            self.read({"QQ"}, {})

        self.assertIn("QQ", str(raised.exception))

    def test_a_missing_database_says_how_to_get_one(self) -> None:
        self.database.unlink()

        with self.assertRaises(geo.GeoUnavailable) as raised:
            self.read({"SE"}, {"SE": ["192.0.2.0/24"]})

        self.assertIn("location update", str(raised.exception))

    def test_a_missing_library_says_which_packages(self) -> None:
        with (
            mock.patch.dict(sys.modules, {"location": None}),
            self.assertRaises(geo.GeoUnavailable) as raised,
        ):
            geo.location_database(self.database)({"SE"})

        self.assertIn("python3-location", str(raised.exception))


class HowFreshACluster_sCountriesAre(unittest.TestCase):
    def test_the_oldest_file_date_is_the_cluster_s(self) -> None:
        files = {
            "managed/maps/geo-se.lst": b"# IPFire Location 2026-09-14 (CC BY-SA 4.0) SE\n192.0.2.0/24\n",
            "managed/maps/geo-no.lst": b"# IPFire Location 2026-09-20 (CC BY-SA 4.0) NO\n",
            "core/maps/other.map": b"# IPFire Location 2020-01-01 (CC BY-SA 4.0) XX\n",
        }

        self.assertEqual(geo.published_stamp(files), "2026-09-14")
        self.assertIsNone(geo.published_stamp({}))

    def test_a_new_database_is_a_new_listing(self) -> None:
        """Otherwise the poller's `unchanged` would keep the old date for ever."""

        self.assertNotEqual(
            objects.fingerprint("a" * 40, None, "2026-09-14"),
            objects.fingerprint("a" * 40, None, "2026-10-01"),
        )

    def test_the_listing_carries_both_dates(self) -> None:
        result = objects.objects_result(
            {"managed/maps/geo-se.lst": b"# IPFire Location 2026-09-14 (CC BY-SA 4.0) SE\n"},
            "a" * 40,
            geo_stamp="2026-10-01",
        )

        self.assertEqual(result["geo"], {"database": "2026-10-01", "published": "2026-09-14"})


class AVersion_sOwnCountries(unittest.TestCase):
    """A revert reads the networks the version ran, not today's database (B366)."""

    FILES = {
        "managed/maps/geo-se.lst": b"# IPFire Location 2026-01-02 (CC BY-SA 4.0) SE\n192.0.2.0/24\n",
        "managed/maps/geo-no.lst": b"# IPFire Location 2026-01-02 (CC BY-SA 4.0) NO\n198.51.100.0/24\n",
    }

    def today(self, countries: object) -> geo.Countries:
        self.asked = countries
        return geo.Countries(stamp="2026-10-25", networks={"SE": ("203.0.113.0/24",)})

    def test_the_version_s_files_are_read_back_as_written(self) -> None:
        read = geo.tree_reader(self.FILES, self.today)

        countries = read({"SE", "NO"})

        self.assertEqual(countries.stamp, "2026-01-02")
        self.assertEqual(
            dict(countries.networks), {"NO": ("198.51.100.0/24",), "SE": ("192.0.2.0/24",)}
        )
        self.assertFalse(hasattr(self, "asked"))

    def test_a_country_the_version_has_no_file_for_reads_all_of_them_today(self) -> None:
        read = geo.tree_reader(self.FILES, self.today)

        countries = read({"SE", "DK"})

        self.assertEqual(countries.stamp, "2026-10-25")
        self.assertEqual(self.asked, {"SE", "DK"})

    def test_a_file_for_another_country_is_not_taken(self) -> None:
        files = {"managed/maps/geo-se.lst": self.FILES["managed/maps/geo-no.lst"]}

        self.assertEqual(geo.tree_reader(files, self.today)({"SE"}).stamp, "2026-10-25")
