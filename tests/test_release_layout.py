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
                    "core/conf.d/10-stats.cfg": b"frontend stats\n  bind 192.0.2.10:8404\n",
                    "managed/generated/40-managed.cfg": b"frontend managed\n  bind 192.0.2.20:80\n",
                    "manual/conf.d/50-extra.cfg": b"backend extra\n  mode http\n",
                }
            )
        )
        self.assertEqual(
            set(artifact),
            {
                "haproxy.cfg",
                "conf.d/10-stats.cfg",
                "conf.d/40-managed.cfg",
                "conf.d/50-extra.cfg",
            },
        )

    def test_nested_paths_keep_their_shape(self) -> None:
        artifact = build_node_artifact(tree(**{"core/conf.d/sub/dir/11-deep.cfg": b"# deep\n"}))
        self.assertIn("conf.d/sub/dir/11-deep.cfg", artifact)

    def test_non_cfg_files_are_ignored_in_conf_d(self) -> None:
        artifact = build_node_artifact(tree(**{"core/conf.d/notes.txt": b"not configuration\n"}))
        self.assertEqual(artifact, {"haproxy.cfg": HAPROXY_CFG})

    def test_a_collision_names_both_layers(self) -> None:
        with self.assertRaises(LayoutError) as caught:
            build_node_artifact(
                tree(
                    **{
                        "core/conf.d/20-shared.cfg": b"# from core\n",
                        "manual/conf.d/20-shared.cfg": b"# from manual\n",
                    }
                )
            )
        message = str(caught.exception)
        self.assertIn("20-shared.cfg", message)
        self.assertIn("core", message)
        self.assertIn("manual", message)

    def test_a_collision_is_never_an_overwrite(self) -> None:
        """The frozen rule: publishing must not silently pick a winner."""
        with self.assertRaises(LayoutError):
            build_node_artifact(
                tree(
                    **{
                        "core/conf.d/30-x.cfg": b"# core\n",
                        "managed/generated/30-x.cfg": b"# managed\n",
                    }
                )
            )


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
                "core/conf.d/10-a.cfg": b"# a\n",
                "manual/conf.d/20-b.cfg": b"# b\n",
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
