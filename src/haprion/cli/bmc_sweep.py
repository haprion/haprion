"""`haprion-bmc-sweep` - the timer's pass over the BMCs (B526, B536).

Asks every BMC the registry names what it serves, and installs the current
certificate where one answers with anything else (`bmc_targets.sweep`). A BMC
that does not answer is no fault: the pass notes when it asked and exits 0.
What each BMC did is in the state file the poller reads; one line per BMC goes
to the journal. Non-zero only when the pass could not run at all.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TextIO

from haprion import bmc_targets, exit_codes
from haprion.bmc_targets import TargetError
from haprion.cert_registry import RegistryError
from haprion.cli.bmc_helper import root_side
from haprion.config import DEFAULT_POLICY_PATH, ConfigError


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    if argv:
        errors.write("usage: haprion-bmc-sweep (no arguments)\n")
        return exit_codes.USAGE
    try:
        said = bmc_targets.sweep(root_side(policy_path))
    except (TargetError, ConfigError, RegistryError) as exc:
        errors.write(f"ERROR: {exc}\n")
        return getattr(exc, "exit_code", exit_codes.CONFIG)
    for certificate_id, status in said.items():
        out.write(f"{certificate_id}: {status}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
