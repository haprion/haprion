"""Turning a queued job into the exact command that performs it.

The interface never builds a request envelope of its own. Each write operation's
envelope is built by the engine module that owns it - the same function the
command line calls - because the helper validates the envelope strictly and two
constructions of one request drift apart in ways that look correct on both
sides. This module is the lookup and the payload check, and nothing else.

The payload check is an allowlist. A job's payload arrives from a form and has
been sitting in a table since; by the time a worker reads it, the only honest
assumption is that it may say anything. A key nobody expected is refused rather
than ignored, because ignoring it silently performs a different operation from
the one that was asked for.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from haproxy_mgmt.cli import cert_deploy, deploy, revert

#
# How long an operation may run before the worker stops it. Deliberately
# generous: a deploy reaches every node in the cluster over SSH, and a timeout
# that fires during normal work would turn a slow day into an `unknown` job.
#
TIMEOUT_SECONDS = 900.0

#
# `-n` because a worker has no terminal to answer a password prompt with, and
# `--` so a helper path could never be read as an option. The paths themselves
# come from the engine modules rather than being written again here.
#
SUDO_FLAGS = ("-n", "--")


class UnknownOperation(Exception):
    """The job asks for something this worker does not know how to run."""


class BadPayload(Exception):
    """The payload is not what this operation accepts.

    Refused before anything runs. A payload that cannot be understood is not a
    reason to run the operation with defaults - the defaults are not what was
    asked for.
    """


@dataclass(frozen=True, slots=True)
class Prepared:
    """One command, ready to run: its argv and the envelope for its stdin."""

    argv: tuple[str, ...]
    request: str


def _flag(payload: Mapping[str, Any], name: str, *, default: bool) -> bool:
    value = payload.get(name, default)
    if not isinstance(value, bool):
        raise BadPayload(f"{name} must be true or false")
    return value


def _only(payload: Mapping[str, Any], *allowed: str) -> None:
    unexpected = sorted(set(payload) - set(allowed))
    if unexpected:
        raise BadPayload(f"unexpected parameters: {', '.join(unexpected)}")


def prepare(
    *, operation: str, cluster: str, request_id: UUID, payload: Mapping[str, Any]
) -> Prepared:
    """Build the command for one job, or refuse it.

    `json_mode` is always true here. The command line renders progress for a
    person; the worker has to store a result, and a machine-readable envelope is
    the only form it can honestly parse into one.
    """

    if operation == "deploy":
        _only(payload, "allow_vip_unknown")
        return Prepared(
            argv=(deploy.SUDO, *SUDO_FLAGS, deploy.HELPER),
            request=deploy.build_request(
                cluster,
                str(request_id),
                allow_vip_unknown=_flag(payload, "allow_vip_unknown", default=False),
                json_mode=True,
            ),
        )

    if operation == "cert_deploy":
        _only(payload, "allow_vip_unknown")
        return Prepared(
            argv=(cert_deploy.SUDO, *SUDO_FLAGS, cert_deploy.HELPER),
            request=cert_deploy.build_request(
                cluster,
                str(request_id),
                allow_vip_unknown=_flag(payload, "allow_vip_unknown", default=False),
                json_mode=True,
            ),
        )

    if operation == "revert":
        _only(payload, "version", "expected_commit")
        version = payload.get("version")
        commit = payload.get("expected_commit")
        #
        # A bool is an int in Python, and `version: true` would otherwise revert
        # to version 1. Checked here rather than trusted to the helper, because
        # the helper's refusal would arrive after the cluster's lock was taken.
        #
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise BadPayload("version must be a positive integer")
        if not isinstance(commit, str) or not commit:
            raise BadPayload("expected_commit must be a commit id")
        return Prepared(
            argv=(revert.SUDO, *SUDO_FLAGS, revert.HELPER),
            request=revert.build_request(
                cluster, str(request_id), version=version, expected_commit=commit
            ),
        )

    raise UnknownOperation(operation)
