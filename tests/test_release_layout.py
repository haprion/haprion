"""The layering rules that turn a repository tree into a node artifact.

Each case corresponds to a rule read out of `haproxy-publish-core`. The rules
are frozen, so a failure here is a contract change rather than a detail.
"""

from __future__ import annotations

import unittest

from haproxy_mgmt.release_layout import (
    LayoutError,
    ReleaseMetadata,
    build_node_artifact,
    render_release_file,
)

HAPROXY_CFG = b"global\n  daemon\ndefaults\n  mode http\n"
RESERVATIONS = b"reservations: []\n"


def tree(**overrides: bytes) -> dict[str, bytes]:
    """A minimal repository tree that passes, plus whatever a case adds."""

    files = {
        "core/haproxy.cfg": HAPROXY_CFG,
        "manual/reservations.yaml": RESERVATIONS,
    }
    files.update(overrides)
    return files


class RequiredFileTests(unittest.TestCase):
    def test_a_missing_required_file_is_refused(self) -> None:
        for missing in ("core/haproxy.cfg", "manual/reservations.yaml"):
            with self.subTest(missing=missing):
                files = tree()
                del files[missing]
                with self.assertRaises(LayoutError) as caught:
                    build_node_artifact(files)
                self.assertIn(missing, str(caught.exception))
                self.assertEqual(caught.exception.exit_code, 65)

    def test_core_haproxy_cfg_becomes_the_node_entry_point(self) -> None:
        self.assertEqual(build_node_artifact(tree())["haproxy.cfg"], HAPROXY_CFG)


class ConfigurationLayerTests(unittest.TestCase):
    def test_all_three_layers_contribute(self) -> None:
        artifact = build_node_artifact(
            tree(
                **{
                    "core/conf.d/0010-stats.cfg": b"frontend stats\n  bind 192.0.2.10:8404\n",
                    "managed/generated/1040-managed.cfg": b"frontend managed\n  bind 192.0.2.20:80\n",
                    "manual/conf.d/0050-extra.cfg": b"backend extra\n  mode http\n",
                }
            )
        )
        self.assertEqual(
            set(artifact),
            {
                "haproxy.cfg",
                "conf.d/0010-stats.cfg",
                "conf.d/1040-managed.cfg",
                "conf.d/0050-extra.cfg",
            },
        )

    def test_nested_paths_keep_their_shape(self) -> None:
        artifact = build_node_artifact(tree(**{"core/conf.d/sub/dir/0011-deep.cfg": b"# deep\n"}))
        self.assertIn("conf.d/sub/dir/0011-deep.cfg", artifact)

    def test_non_cfg_files_are_ignored_in_conf_d(self) -> None:
        artifact = build_node_artifact(tree(**{"core/conf.d/notes.txt": b"not configuration\n"}))
        self.assertEqual(artifact, {"haproxy.cfg": HAPROXY_CFG})

    def test_a_collision_names_both_layers(self) -> None:
        with self.assertRaises(LayoutError) as caught:
            build_node_artifact(
                tree(
                    **{
                        "core/conf.d/0020-shared.cfg": b"# from core\n",
                        "manual/conf.d/0020-shared.cfg": b"# from manual\n",
                    }
                )
            )
        message = str(caught.exception)
        self.assertIn("20-shared.cfg", message)
        self.assertIn("core", message)
        self.assertIn("manual", message)

    def test_a_generated_file_cannot_reach_for_a_handwritten_name(self) -> None:
        """The frozen rule, now enforced a step earlier.

        A generated file and a handwritten one could once collide on a name and
        were caught by the collision check. With the numbering bands they can no
        longer share a name at all - one lives in 1000-1999 and the other cannot
        - so the refusal happens at the band and says something more useful than
        "two layers provide this". The protection is the same; it arrives sooner
        and names the actual rule.
        """

        with self.assertRaises(LayoutError) as caught:
            build_node_artifact(
                tree(
                    **{
                        "core/conf.d/0030-x.cfg": b"# core\n",
                        "managed/generated/0030-x.cfg": b"# managed\n",
                    }
                )
            )
        self.assertIn("0030", str(caught.exception))
        self.assertIn("1000-1999", str(caught.exception))


class ManagedLayerTests(unittest.TestCase):
    def test_the_placeholder_is_allowed(self) -> None:
        build_node_artifact(tree(**{"managed/generated/.gitkeep": b""}))

    def test_anything_but_generated_cfg_is_refused(self) -> None:
        with self.assertRaises(LayoutError) as caught:
            build_node_artifact(tree(**{"managed/generated/leftover.bak": b"x\n"}))
        self.assertIn("managed/generated", str(caught.exception))
        self.assertEqual(caught.exception.exit_code, 65)


class MapLayerTests(unittest.TestCase):
    def test_maps_come_from_core_and_manual(self) -> None:
        artifact = build_node_artifact(
            tree(
                **{
                    "core/maps/hosts.map": b"host.example.com backend_a\n",
                    "manual/maps/extra.map": b"other.example.net backend_b\n",
                }
            )
        )
        self.assertEqual(artifact["maps/hosts.map"], b"host.example.com backend_a\n")
        self.assertEqual(artifact["maps/extra.map"], b"other.example.net backend_b\n")

    def test_the_placeholder_never_reaches_a_node(self) -> None:
        artifact = build_node_artifact(tree(**{"core/maps/.gitkeep": b""}))
        self.assertEqual([path for path in artifact if path.startswith("maps/")], [])

    def test_a_map_present_in_both_layers_is_a_collision(self) -> None:
        with self.assertRaises(LayoutError) as caught:
            build_node_artifact(
                tree(**{"core/maps/hosts.map": b"a\n", "manual/maps/hosts.map": b"b\n"})
            )
        self.assertIn("hosts.map", str(caught.exception))

    def test_maps_are_taken_whatever_the_extension(self) -> None:
        """Unlike conf.d, a map layer is not filtered by suffix."""
        self.assertIn("maps/hosts", build_node_artifact(tree(**{"core/maps/hosts": b"a\n"})))


class DeterminismTests(unittest.TestCase):
    def test_the_same_tree_always_yields_the_same_artifact(self) -> None:
        """The whole privilege split rests on this being true."""
        files = tree(
            **{
                "core/conf.d/0010-a.cfg": b"# a\n",
                "manual/conf.d/0020-b.cfg": b"# b\n",
                "core/maps/hosts.map": b"host.example.com backend_a\n",
            }
        )
        reversed_files = dict(reversed(list(files.items())))
        self.assertEqual(build_node_artifact(files), build_node_artifact(reversed_files))

    def test_release_is_not_part_of_the_validated_artifact(self) -> None:
        """It carries a timestamp; including it would make two derivations differ."""
        self.assertNotIn("RELEASE", build_node_artifact(tree()))


class ReleaseStampTests(unittest.TestCase):
    def test_field_order_is_the_published_contract(self) -> None:
        rendered = render_release_file(
            ReleaseMetadata(
                cluster="alpha",
                version=7,
                commit="0" * 40,
                timestamp="2026-08-25T20:00:00Z",
            )
        )
        self.assertEqual(
            rendered,
            b"schema=1\ncluster=alpha\nversion=7\nhash=" + b"0" * 40 + b"\n"
            b"timestamp=2026-08-25T20:00:00Z\n",
        )


if __name__ == "__main__":
    unittest.main()


class TheNumberingBandsAreEnforced(unittest.TestCase):
    """B18, checked where the layer a file came from is still known.

    Three layers flatten into one `conf.d`, and HAProxy reads it in alphabetical
    order - `100-a.cfg` before `20-b.cfg`, measured on 2026-08-27. Four fixed
    digits are what make alphabetical and numeric order the same order, and the
    band is what keeps an application and a person out of each other's names in
    a directory they now share.

    Enforced here rather than at candidate validation because by then the layers
    have been flattened and nothing knows whether a file was written by a person
    or by the generator.
    """

    def test_a_handwritten_file_without_four_digits_is_refused(self) -> None:
        for name in ("stats.cfg", "10-stats.cfg", "010-stats.cfg", "10000-stats.cfg"):
            with self.subTest(name=name), self.assertRaises(LayoutError) as caught:
                build_node_artifact(tree(**{f"core/conf.d/{name}": b"# x\n"}))

            self.assertIn("four digits", str(caught.exception))

    def test_four_digits_without_a_dash_is_refused(self) -> None:
        """`0010stats.cfg` sorts fine and is still refused.

        The dash is not decoration: without a separator `0010stats` and `00101`
        are both "four digits and then something", and the band a file belongs
        to stops being readable at a glance.
        """

        with self.assertRaises(LayoutError):
            build_node_artifact(tree(**{"core/conf.d/0010stats.cfg": b"# x\n"}))

    def test_a_handwritten_file_inside_the_generated_band_is_refused(self) -> None:
        """The case that loses somebody's work if it is allowed."""

        for layer in ("core", "manual"):
            with self.subTest(layer=layer), self.assertRaises(LayoutError) as caught:
                build_node_artifact(tree(**{f"{layer}/conf.d/1500-mine.cfg": b"# x\n"}))

            self.assertIn("1500", str(caught.exception))
            self.assertIn("rewritten without warning", str(caught.exception))

    def test_a_generated_file_outside_its_band_is_refused(self) -> None:
        """The case that leaves configuration nobody meant to keep."""

        with self.assertRaises(LayoutError) as caught:
            build_node_artifact(tree(**{"managed/generated/0099-sneaky.cfg": b"# x\n"}))

        self.assertIn("0099", str(caught.exception))

    def test_the_edges_of_the_band_are_inside_it(self) -> None:
        artifact = build_node_artifact(
            tree(
                **{
                    "managed/generated/1000-first.cfg": b"# x\n",
                    "managed/generated/1999-last.cfg": b"# y\n",
                }
            )
        )

        self.assertIn("conf.d/1000-first.cfg", artifact)
        self.assertIn("conf.d/1999-last.cfg", artifact)

    def test_the_bands_next_to_it_belong_to_the_person(self) -> None:
        """0999 and 2000 are handwritten, and one of them is load-bearing.

        `2000`-`2999` is reserved for a second generated layer that does not
        exist. Reserving it in a document is not the same as refusing to publish
        into it, and a rule with no writer behind it cannot be tested against
        anything real - so a person may still write there today.
        """

        artifact = build_node_artifact(
            tree(
                **{
                    "core/conf.d/0999-last-handwritten.cfg": b"# x\n",
                    "manual/conf.d/2000-reserved.cfg": b"# y\n",
                }
            )
        )

        self.assertIn("conf.d/0999-last-handwritten.cfg", artifact)
        self.assertIn("conf.d/2000-reserved.cfg", artifact)

    def test_a_file_haproxy_never_loads_is_left_alone(self) -> None:
        """A saved copy in conf.d is untidy, not a publishing error.

        `notes.txt` and `50-z.cfg.bak` were both measured as ignored by HAProxy
        on 2026-08-27. Refusing to publish because of one would enforce
        tidiness as though it were correctness.
        """

        artifact = build_node_artifact(
            tree(
                **{
                    "core/conf.d/notes.txt": b"not configuration\n",
                    "core/conf.d/50-z.cfg.bak": b"an old copy\n",
                }
            )
        )

        self.assertEqual(artifact, {"haproxy.cfg": HAPROXY_CFG})
