from __future__ import annotations

import argparse
import sys
from pathlib import Path

from haproxy_mgmt.config import ConfigError
from haproxy_mgmt.identity_policy import load_identity_policy, render_sysusers


def main(argv: list[str] | None = None, *, require_secure: bool = True) -> int:
    parser = argparse.ArgumentParser(prog="haprion-render-sysusers")
    parser.add_argument("--policy", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        policy = load_identity_policy(args.policy, require_secure=require_secure)
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return exc.exit_code

    sys.stdout.write(render_sysusers(policy))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
