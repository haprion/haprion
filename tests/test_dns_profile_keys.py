"""The key pair that seals DNS provider credentials, and its two files."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from haprion.dns_profile_keys import (
    PRIVATE_TAG,
    PUBLIC_TAG,
    KeyFileError,
    generate,
    key_id_of,
    open_sealed,
    parse_private_key,
    parse_public_key,
    read_private_key,
    read_public_key,
    render_private_key,
    render_public_key,
    seal,
    write_key_pair,
)


class KeyFileTests(unittest.TestCase):
    def test_a_rendered_key_reads_back_with_the_same_identifier(self) -> None:
        private_key, public_key = generate()
        self.assertEqual(private_key.key_id, public_key.key_id)
        self.assertEqual(len(public_key.key_id), 16)
        self.assertEqual(parse_public_key(render_public_key(public_key)).key_id, public_key.key_id)
        self.assertEqual(
            parse_private_key(render_private_key(private_key)).key_id, private_key.key_id
        )
        self.assertEqual(key_id_of(private_key.key.public_key), public_key.key_id)

    def test_the_tag_keeps_a_private_key_out_of_the_public_slot(self) -> None:
        private_key, public_key = generate()
        with self.assertRaisesRegex(KeyFileError, f"holds a {PRIVATE_TAG}"):
            parse_public_key(render_private_key(private_key))
        with self.assertRaisesRegex(KeyFileError, f"holds a {PUBLIC_TAG}"):
            parse_private_key(render_public_key(public_key))
        for bad in ("", "x\ny\n", f"{PUBLIC_TAG}:abc\n", f"{PUBLIC_TAG}:{'0' * 64}extra\n"):
            with self.subTest(bad=bad), self.assertRaises(KeyFileError):
                parse_public_key(bad)

    def test_sealing_is_one_way_and_bound_to_the_pair(self) -> None:
        private_key, public_key = generate()
        other_private, _ = generate()
        ciphertext = seal(public_key, b"fields-example")
        self.assertNotIn(b"fields-example", ciphertext)
        self.assertEqual(open_sealed(private_key, ciphertext), b"fields-example")
        with self.assertRaisesRegex(KeyFileError, "not sealed against this key"):
            open_sealed(other_private, ciphertext)
        with self.assertRaises(KeyFileError):
            open_sealed(private_key, ciphertext[:-1])

    def test_a_pair_is_written_once_with_the_modes_the_split_needs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            private_path = Path(raw) / "secrets" / "key.key"
            public_path = Path(raw) / "config" / "key.pub"
            private_path.parent.mkdir()
            public_path.parent.mkdir()
            written = write_key_pair(private_path, public_path)

            self.assertEqual(private_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(public_path.stat().st_mode & 0o777, 0o640)
            self.assertEqual(read_public_key(public_path).key_id, written.key_id)
            self.assertEqual(
                read_private_key(private_path, require_secure=False).key_id, written.key_id
            )
            self.assertEqual(sorted(os.listdir(private_path.parent)), ["key.key"])

            with self.assertRaisesRegex(KeyFileError, "never overwritten"):
                write_key_pair(private_path, public_path)
            self.assertEqual(read_public_key(public_path).key_id, written.key_id)

    def test_the_private_key_is_refused_unless_it_is_root_s_alone(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            private_path = Path(raw) / "key.key"
            public_path = Path(raw) / "key.pub"
            write_key_pair(private_path, public_path)
            if os.geteuid() != 0:
                with self.assertRaisesRegex(KeyFileError, "owned by root, mode 0600"):
                    read_private_key(private_path)
            private_path.chmod(0o640)
            with self.assertRaisesRegex(KeyFileError, "owned by root, mode 0600"):
                read_private_key(private_path)
            with self.assertRaisesRegex(KeyFileError, "cannot read"):
                read_private_key(Path(raw) / "missing.key")


if __name__ == "__main__":
    unittest.main()
