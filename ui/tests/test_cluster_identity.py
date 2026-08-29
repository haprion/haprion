from __future__ import annotations

import unittest

from haproxy_ui.cluster_identity import accent_index


class ClusterIdentityTests(unittest.TestCase):
    def test_accent_is_stable_and_separates_generic_cluster_names(self) -> None:
        self.assertEqual(accent_index("alpha"), accent_index("alpha"))
        self.assertNotEqual(accent_index("alpha"), accent_index("bravo"))
