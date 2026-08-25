"""`haproxy-history-reset` - start a cluster's version history over.

The name is the contract. This resets the HISTORY; the configuration is kept
exactly as it is and becomes version 1. A command called "factory reset" would
imply the opposite, and an operator reading it under pressure would be right to
assume their configuration was about to be thrown away.

Two confirmations, for two different mistakes
---------------------------------------------
The yes/no question guards against running the command at all. The typed phrase
guards against running it while distracted - it cannot be answered by reflex, and
it cannot be answered by a key held down.

What it does and does not do
----------------------------
It publishes version 1 on the way out, because without that the manager describes
itself incorrectly: the published release is named after a commit that no longer
exists. Publishing is local, validated, and touches no node.

It does NOT deploy. Sending a reload to production nodes is not something a
command named "history-reset" should do quietly, and it is not urgent: the nodes
are already running this exact configuration, since the configuration is what was
kept. Only the release metadata differs. The deploy is printed as the next step,
and `haproxy-config-status` keeps showing the difference until it is run.
"""

from __future__ import annotations

import grp
import os
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.history_reset import (
    OWNER_GROUP,
    ChangeOwner,
    ResetError,
    preview,
    reset_history,
)
from haproxy_mgmt.history_reset import (
    chown as default_chown,
)

CONFIRMATION = "please reset me"
BASELINE_MESSAGE = "Baseline after the build phase"
PUBLISH = "/usr/local/bin/haproxy-publish"
USAGE = "Usage:\n  haproxy-history-reset -c <cluster>"

#
# Publishing is a separate program today - the shell command that owns the
# published tree. Injected rather than called directly so the confirmation
# behaviour can be exercised without publishing anything.
#
type PublishCall = Callable[[str], int]


def _publish(cluster_id: str) -> int:
    return subprocess.run(  # noqa: S603 - fixed path, fixed arguments
        [PUBLISH, "-c", cluster_id, BASELINE_MESSAGE],
        check=False,
    ).returncode


def _parse(argv: list[str]) -> str:
    if len(argv) != 2 or argv[0] not in ("-c", "--cluster"):
        raise SystemExit(f"{USAGE}\n")
    return argv[1]


def _ask(reader: TextIO, writer: TextIO, question: str) -> str:
    writer.write(question)
    writer.flush()
    answer = reader.readline()
    if not answer:
        #
        # End of input rather than an answer. Treated as "no": a reset must never
        # be the default outcome of a closed pipe.
        #
        return ""
    return str(answer).strip()


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    stream_in: TextIO | None = None,
    stream_out: TextIO | None = None,
    require_root: bool = True,
    publish: PublishCall = _publish,
    change_owner: ChangeOwner = default_chown,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    reader: TextIO = stream_in or sys.stdin
    writer: TextIO = stream_out or sys.stdout
    cluster_id = _parse(argv)

    if require_root and os.geteuid() != 0:
        writer.write("ERROR: this command rewrites root-owned directories. Run it with sudo.\n")
        return 77

    try:
        #
        # The secure-permission checks and the root check answer the same
        # question - is this really running as root against the real files - so
        # they are relaxed together, never separately.
        #
        policy = load_policy(policy_path, require_secure=require_root)
        cluster = load_runtime_config(policy, require_secure=require_root).cluster(cluster_id)
        plan = preview(cluster_id, cluster.config_path)
    except (ConfigError, ResetError) as exc:
        writer.write(f"ERROR: {exc}\n")
        return getattr(exc, "exit_code", 65)

    writer.write(
        f"\nThis discards the version history for cluster '{cluster_id}'.\n\n"
        f"  Configuration:      kept exactly as it is, and becomes version 1\n"
        f"  Version history:    {plan.versions} versions discarded\n"
        f"  Draft area:         {plan.draft}\n"
        f"  History:            {plan.history}\n\n"
        "The previous history is kept beside the new one and can be moved back.\n"
        "Nothing is deleted by this command.\n\n"
    )

    if _ask(reader, writer, "Continue? [y/N] ").lower() not in ("y", "yes"):
        writer.write("Nothing was changed.\n")
        return 0

    typed = _ask(reader, writer, f"Type '{CONFIRMATION}' to confirm: ")
    if typed != CONFIRMATION:
        writer.write("The phrase did not match. Nothing was changed.\n")
        return 0

    try:
        group_id = grp.getgrnam(OWNER_GROUP).gr_gid
    except KeyError:
        writer.write(
            f"ERROR: the group '{OWNER_GROUP}' does not exist. The new history would be "
            "unreadable to the management identity.\n"
        )
        return 78

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    try:
        result = reset_history(
            plan,
            stamp=stamp,
            message=BASELINE_MESSAGE,
            group_id=group_id,
            change_owner=change_owner,
        )
    except ResetError as exc:
        writer.write(f"ERROR: {exc}\n")
        return exc.exit_code

    writer.write(
        f"\nCluster '{cluster_id}' now starts at version 1.\n\n"
        f"  Discarded:  {result.versions_discarded} versions\n"
        f"  Kept:       {result.archived_history}\n"
        f"              {result.archived_draft}\n\n"
    )

    #
    # Publish immediately. Until this runs the published release is named after a
    # commit that no longer exists, and every status view is misleading.
    #
    writer.write("Publishing version 1...\n")
    published = publish(cluster_id)
    if published != 0:
        writer.write(
            "\nERROR: the reset succeeded but publishing version 1 did not.\n"
            f"Until it does, this cluster's published release refers to a version that\n"
            f"no longer exists. Fix the cause and run:\n\n"
            f'  haproxy-publish -c {cluster_id} "Baseline after the build phase"\n'
        )
        return published

    writer.write(
        "\nThe nodes are already running this configuration - only the release metadata\n"
        "differs. Bring them into step with:\n\n"
        f"  haproxy-deploy -c {cluster_id}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
