#!/usr/bin/env python3
"""Build and verify a node bundle from a checkout: `haproxy_mgmt.node_bundle`."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haproxy_mgmt.node_bundle import main  # noqa: E402 - the path above comes first

if __name__ == "__main__":
    raise SystemExit(main())
