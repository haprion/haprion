"""The HAProxy repository a restored node gets for its own distribution (B178, B179)."""

from __future__ import annotations

import unittest
from importlib.resources import files
from unittest import mock

from haprion import haproxy_repository as repository

UBUNTU = {"ID": "ubuntu", "VERSION_ID": "26.04", "VERSION_CODENAME": "resolute"}
DEBIAN = {"ID": "debian", "VERSION_ID": "13", "VERSION_CODENAME": "trixie"}


class TheShippedKeys(unittest.TestCase):
    def test_each_key_is_the_one_its_fingerprint_names(self) -> None:
        """The gate holds the files to the fingerprints, not a person remembering to."""

        for distribution, pinned in repository.REPOSITORIES.items():
            with self.subTest(distribution=distribution):
                self.assertEqual(
                    repository.fingerprint(repository.key(distribution)), pinned.fingerprint
                )

    def test_a_key_that_is_not_the_pinned_one_is_refused(self) -> None:
        other = files("haprion").joinpath("apt-keys", "haproxy-ubuntu-ppa.asc").read_bytes()
        with (
            mock.patch.object(repository, "fingerprint", return_value="0" * 40),
            self.assertRaisesRegex(repository.RepositoryError, "changed without its fingerprint"),
        ):
            repository.key("ubuntu")
        self.assertTrue(other.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"))

    def test_what_is_not_an_armored_v4_key_is_refused(self) -> None:
        for text in (
            b"not a key",
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n",
        ):
            with self.subTest(text=text[:20]), self.assertRaises(repository.RepositoryError):
                repository.fingerprint(text)


class TheFilesForATarget(unittest.TestCase):
    def paths(self, os_release: dict[str, str]) -> dict[str, bytes]:
        return {item.path: item.data for item in repository.repository_files(os_release, "3.4")}

    def test_ubuntu_gets_the_ppa_for_its_codename_and_no_pin(self) -> None:
        written = self.paths(UBUNTU)
        source = written["/etc/apt/sources.list.d/haproxy-3.4.sources"].decode()
        self.assertIn("URIs: https://ppa.launchpadcontent.net/vbernat/haproxy-3.4/ubuntu\n", source)
        self.assertIn("Suites: resolute\n", source)
        self.assertIn("Signed-By: /etc/apt/keyrings/haproxy-ubuntu-ppa.asc\n", source)
        self.assertNotIn("/etc/apt/preferences.d/haproxy-3.4.pref", written)

    def test_debian_gets_the_backports_suite_and_a_pin_over_notautomatic(self) -> None:
        written = self.paths(DEBIAN)
        source = written["/etc/apt/sources.list.d/haproxy-3.4.sources"].decode()
        self.assertIn("URIs: https://haproxy.debian.net\n", source)
        self.assertIn("Suites: trixie-backports-3.4\n", source)
        pin = written["/etc/apt/preferences.d/haproxy-3.4.pref"].decode()
        self.assertIn("Pin: release o=PPA-haproxy,n=trixie-backports-3.4\n", pin)
        self.assertIn("Pin-Priority: 600\n", pin)

    def test_an_unsupported_target_is_refused(self) -> None:
        for os_release in (
            {"ID": "ubuntu", "VERSION_ID": "26.10", "VERSION_CODENAME": "later"},
            {"ID": "rocky", "VERSION_ID": "10"},
            {"ID": "debian", "VERSION_ID": "13"},
        ):
            with self.subTest(os_release=os_release), self.assertRaises(repository.RepositoryError):
                repository.repository_files(os_release, "3.4")

    def test_the_branch_is_read_from_the_installed_version(self) -> None:
        self.assertEqual(repository.branch_of("3.4.4-1ppa1~resolute"), "3.4")
        self.assertEqual(repository.branch_of("3.4.4-1~bpo13+1"), "3.4")
        self.assertEqual(repository.branch_of("1:3.2.10-1"), "3.2")
        with self.assertRaises(repository.RepositoryError):
            repository.branch_of("")
