"""Every write the interface makes has its terminal counterpart (Fas 23, B269, B293).

The interface is the first way in and the terminal is how the same installation
is automated, so what one can set the other must. Each POST route - and each
operation the shared `/operations` route queues - is listed here once, as the
command that does the same, as a gap with the Fas 23 step that closes it, or
as something that is not a setting. A route added without an entry fails, and
so does a command named here that does not exist.

The gaps are the list Fas 23 empties.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import ctypes
import importlib
import io
import multiprocessing
import os
import socket
import subprocess
import sys
import tempfile
import tomllib
import unittest
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any, NoReturn
from unittest import mock

import psycopg
import psycopg_pool
from haprion import config as config_module
from haprion import exit_codes, http01_check
from haprion.config import ConfigError
from starlette.applications import Starlette
from starlette.endpoints import HTTPEndpoint
from starlette.routing import Route

from haprion_ui import api, certificate_form
from haprion_ui import config as ui_config
from haprion_ui.app import create_app
from tests.contract_schema import assert_contract
from tests.product_filesystem import PRODUCT_ROOTS, product_directories, write_installation
from tests.test_login import configuration

REAL_SECURE_YAML = config_module._secure_yaml
ROOT = Path(__file__).resolve().parents[2]
VIEWS = ROOT / "ui" / "src" / "haprion_ui" / "pages" / "dashboard.py"
SCHEMAS = ROOT / "schemas" / "v1"
#
# The contracts that only read. A command whose answer is one of these shows a
# setting; it does not say whether it changed one.
#
WRITES = frozenset({"POST", "PUT", "PATCH", "DELETE"})
READS = frozenset(
    {
        "haprion-cluster-settings",
        "haprion-network",
        "haprion-objects",
        "haprion-list",
        "haprion-status",
        "haprion-cert-list",
        "haprion-inventory",
        "haprion-list-backups",
        "haprion-readings",
        "haprion-cluster-list",
    }
)


#
# The reading commands answer in a contract too; their usage is held to the same rule.
#
READ_PROGRAMS = (
    "haprion-blocklist-check",
    "haprion-cert-list",
    "haprion-inventory",
    "haprion-list",
    "haprion-list-backups",
    "haprion-status",
)


USER_VERBS = (
    "add",
    "init-admin",
    "delete",
    "break-glass",
    "reset",
    "disable",
    "enable",
    "unlock",
    "revoke",
    "list",
    "role",
    "apply",
)


#
# A call each command refuses: well formed, so the command reads it, with a
# value it cannot use. The gate runs it with `--json` and holds stdout to the
# command's schema (K01, K07 and K12 passed every older check). A command added
# to the tables needs its line here.
#
BAD_CLUSTER = ["-c", "Bad Cluster!"]
REFUSED_CALLS: dict[str, list[str]] = {
    "haprion-api-token add": ["add", "Bad Name!", "--level", "read"],
    "haprion-api-token extend": ["extend", "no-such-token"],
    "haprion-api-token remove": ["remove", "no-such-token"],
    "haprion-api-token revoke": ["revoke", "no-such-token"],
    "haprion-blocklists apply": ["apply", "/nonexistent.yaml"],
    "haprion-blocklists remove": ["remove", "Bad Name!"],
    "haprion-backup-schedule": [*BAD_CLUSTER, "--time", "03:00"],
    "haprion-cert-delete": ["Bad ID!"],
    "haprion-cert-deploy": [*BAD_CLUSTER],
    "haprion-cert-renew": ["--ndes-now", "no-such-certificate"],
    "haprion-cert-request": ["--id", "Bad ID!", "--domain", "Bad Name!"],
    "haprion-cert-import": ["--id", "Bad ID!", "--certificate", "/nonexistent.pem"],
    "haprion-cert-issue": ["--domain", "Bad Name!", "--method", "dns-01"],
    "haprion-cert-issue --renew": ["--domain", "Bad Name!", "--renew"],
    "haprion-cert-publish --certificate": ["--certificate", "Bad ID!"],
    "haprion-cert-receiver add": [
        "add",
        "Bad Name!",
        "--transport",
        "rsync",
        "--public-key",
        "/nonexistent.pub",
    ],
    "haprion-cert-receiver key": ["key", "Bad Name!", "--public-key", "/nonexistent.pub"],
    "haprion-cert-receiver remove": ["remove", "Bad Name!"],
    "haprion-cert-receiver secret": ["secret", "Bad Name!", "--show-password"],
    "haprion-cert-scep --abandon": ["--id", "Bad ID!", "--abandon"],
    "haprion-cert-scep --resume": ["--id", "Bad ID!", "--resume"],
    "haprion-cert-target": ["add", "Bad ID!", "--cluster", "alpha"],
    "haprion-cluster add": [
        "add",
        *BAD_CLUSTER,
        "--vip",
        "192.0.2.10",
        "--node-path",
        "/x",
        "--host",
        "node-a",
    ],
    "haprion-cluster remove": ["remove", *BAD_CLUSTER],
    "haprion-cluster-settings apply": ["apply", *BAD_CLUSTER, "/nonexistent.yaml"],
    "haprion-config-status": [*BAD_CLUSTER],
    "haprion-deploy": [*BAD_CLUSTER],
    "haprion-export": [*BAD_CLUSTER, "/srv/export"],
    "haprion-history-reset": [*BAD_CLUSTER, "--confirm", "please reset me"],
    "haprion-http01-check": ["not a name", "--json"],
    "haprion-ndes-server add": ["add", "not an address"],
    "haprion-ndes-server remove": ["remove", "not an address"],
    "haprion-network apply": ["apply", *BAD_CLUSTER, "/nonexistent.yaml"],
    "haprion-node add": ["add", *BAD_CLUSTER, "--host", "node-a"],
    "haprion-node host": ["host", *BAD_CLUSTER, "node-a", "--host", "node-b"],
    "haprion-node remove": ["remove", *BAD_CLUSTER, "node-a"],
    "haprion-node-restore discard": ["discard", "--run", "bad run"],
    "haprion-node-restore prepare": [
        "prepare",
        *BAD_CLUSTER,
        "--node",
        "node-a",
        "--archive",
        "2026-01-01_00-00-00",
        "--target",
        "192.0.2.10",
    ],
    "haprion-node-restore preview": ["preview", "--run", "bad run"],
    "haprion-node-restore run": ["run", "--run", "bad run", "--confirm", "node-a"],
    "haprion-node-restore status": ["status", "--run", "bad run"],
    "haprion-objects apply": ["apply", *BAD_CLUSTER, "/nonexistent"],
    "haprion-objects remove": ["remove", *BAD_CLUSTER, "shop"],
    "haprion-probe": [*BAD_CLUSTER, "-t", "192.0.2.10:80"],
    "haprion-profiles apply": ["apply", "/nonexistent.yaml"],
    "haprion-profiles remove": ["remove", "dns", "Bad Id!"],
    "haprion-publish --regenerate": [*BAD_CLUSTER, "--regenerate"],
    "haprion-revert": [*BAD_CLUSTER],
    "haprion-server-state": [*BAD_CLUSTER, "-o", "shop", "drain", "192.0.2.10:80"],
    "haprion-server-state unblock": [*BAD_CLUSTER, "-o", "shop", "unblock", "192.0.2.10"],
    "haprion-settings apply": ["apply", "/nonexistent.yaml"],
    "haprion-state-backup": [*BAD_CLUSTER],
    "haprion-user apply": ["apply", "/nonexistent.yaml"],
}


@dataclass(frozen=True)
class Command:
    """The terminal's way to the same thing; the first word is the program.

    `schema` is the contract its `--json` answer is held to: a command a
    configuration tool cannot read `changed` or the outcome from is not the
    terminal's way to a setting, however well it works at a prompt.
    """

    line: str
    schema: str


@dataclass(frozen=True)
class Gap:
    """Not there yet: the Fas 23 step that adds it, and what it will be."""

    step: str
    planned: str


@dataclass(frozen=True)
class NotASetting:
    why: str


@dataclass(frozen=True)
class NoCounterpart:
    """A write the engine has no command for, and none is planned: said, not hidden."""

    why: str


PARITY: dict[str, Command | Gap | NotASetting] = {
    "/proxies/{cluster}/new": Command("haprion-objects apply", "haprion-objects-apply"),
    "/proxies/{cluster}/{name}/edit": Command("haprion-objects apply", "haprion-objects-apply"),
    "/proxies/{cluster}/{name}/advanced": Command("haprion-objects apply", "haprion-objects-apply"),
    "/proxies/{cluster}/{name}/remove": Command("haprion-objects remove", "haprion-objects-apply"),
    "/waf/allow": Command("haprion-objects apply", "haprion-objects-apply"),
    "/waf/exceptions/remove": Command("haprion-objects apply", "haprion-objects-apply"),
    "/proxies/{cluster}/{name}/lookup": NotASetting("looks a name up for the form"),
    "/proxies/{cluster}/{name}/servers": Command("haprion-server-state", "haprion-server-state"),
    "/proxies/{cluster}/{name}/unblock": Command(
        "haprion-server-state unblock", "haprion-server-state"
    ),
    "/certificates/new": Command("haprion-cert-issue", "haprion-cert-issue"),
    "/certificates/import": Command("haprion-cert-import", "haprion-cert-import"),
    "/certificates/{certificate_id}/upload": Command("haprion-cert-import", "haprion-cert-import"),
    "/certificates/{certificate_id}/resume": Command(
        "haprion-cert-scep --resume", "haprion-cert-scep"
    ),
    "/certificates/abandon": Command("haprion-cert-scep --abandon", "haprion-cert-scep"),
    "/certificates/abandon/confirm": Command("haprion-cert-scep --abandon", "haprion-cert-scep"),
    "/certificates/{certificate_id}/publish": Command(
        "haprion-cert-publish --certificate", "haprion-cert-publish"
    ),
    "/certificates/renew": Command("haprion-cert-issue --renew", "haprion-cert-issue"),
    "/certificates/renew/confirm": Command("haprion-cert-issue --renew", "haprion-cert-issue"),
    "/certificates/{certificate_id}/download": NotASetting("hands the certificate to the browser"),
    "/certificates/export": NotASetting("hands key material to the browser"),
    "/certificates/{certificate_id}/export": NotASetting("hands key material to the browser"),
    "/certificates/targets/{action}": Command("haprion-cert-target", "haprion-cert-target"),
    "/certificates/targets/{action}/confirm": Command("haprion-cert-target", "haprion-cert-target"),
    "/certificates/delete": Command("haprion-cert-delete", "haprion-cert-delete"),
    "/certificates/delete/confirm": Command("haprion-cert-delete", "haprion-cert-delete"),
    "/certificates/receivers/new": Command("haprion-cert-receiver add", "haprion-cert-receiver"),
    "/certificates/receivers/remove": Command(
        "haprion-cert-receiver remove", "haprion-cert-receiver"
    ),
    "/certificates/receivers/secret": Command(
        "haprion-cert-receiver secret", "haprion-cert-receiver"
    ),
    "/certificates/receivers/key": Command("haprion-cert-receiver key", "haprion-cert-receiver"),
    "/settings/blocklists/new": Command("haprion-blocklists apply", "haprion-blocklists-apply"),
    "/settings/blocklists/{name}/edit": Command(
        "haprion-blocklists apply", "haprion-blocklists-apply"
    ),
    "/settings/blocklists/{name}/remove": Command(
        "haprion-blocklists remove", "haprion-blocklists-apply"
    ),
    "/settings/blocklists/{name}/add-to-proxies": Command(
        "haprion-objects apply", "haprion-objects-apply"
    ),
    "/dns-profiles/new": Command("haprion-profiles apply", "haprion-profiles-apply"),
    "/dns-profiles/{profile_id}/replace": Command(
        "haprion-profiles apply", "haprion-profiles-apply"
    ),
    "/dns-profiles/{profile_id}/remove": Command(
        "haprion-profiles remove", "haprion-profiles-apply"
    ),
    "/ndes-profiles/new": Command("haprion-profiles apply", "haprion-profiles-apply"),
    "/ndes-profiles/{profile_id}/replace": Command(
        "haprion-profiles apply", "haprion-profiles-apply"
    ),
    "/ndes-profiles/{profile_id}/remove": Command(
        "haprion-profiles remove", "haprion-profiles-apply"
    ),
    "/certificates/new/check-http01": Command("haprion-http01-check", "haprion-http01-check"),
    "/ndes-profiles/servers/new": Command("haprion-ndes-server add", "haprion-ndes-server"),
    "/ndes-profiles/servers/confirm": Command("haprion-ndes-server add", "haprion-ndes-server"),
    "/ndes-profiles/servers/remove": Command("haprion-ndes-server remove", "haprion-ndes-server"),
    "/settings/clusters/{cluster}": Command(
        "haprion-cluster-settings apply", "haprion-cluster-settings-apply"
    ),
    "/settings/nodes/{cluster}/add": Command("haprion-node add", "haprion-cluster-node"),
    "/settings/nodes/{cluster}/remove": Command("haprion-node remove", "haprion-cluster-node"),
    "/settings/nodes/{cluster}/host": Command("haprion-node host", "haprion-cluster-node"),
    "/settings/nodes/{cluster}/remove-cluster": Command(
        "haprion-cluster remove", "haprion-cluster-define"
    ),
    "/settings/new-cluster": Command("haprion-cluster add", "haprion-cluster-define"),
    #
    # The first cluster's guide (B315): the same two operations, one node at a
    # time; its first step only reads the form.
    #
    "/first-cluster/name": NotASetting("checks the guide's first step; nothing is written"),
    "/first-cluster/first-node": Command("haprion-cluster add", "haprion-cluster-define"),
    "/first-cluster/second-node": Command("haprion-node add", "haprion-cluster-node"),
    "/settings/new-user": Command("haprion-user apply", "haprion-user-apply"),
    "/settings/users/{name}": Command("haprion-user apply", "haprion-user-apply"),
    "/settings/oidc": Command("haprion-settings apply", "haprion-settings-apply"),
    "/settings/features/{name}": Command("haprion-settings apply", "haprion-settings-apply"),
    "/attention/acknowledge": NotASetting(
        "a judgement on a row of Needs attention, not something the installation is"
    ),
    "/jobs/{job_id}/held": NotASetting(
        "an answer about a job in the interface's own queue (0082); the terminal runs an"
        " operation at once and has no queue to hold it in"
    ),
    "/getting-started/hide": NotASetting(
        "what the dashboard shows an admin, not something the installation is"
    ),
    "/getting-started/show": NotASetting(
        "what the dashboard shows an admin, not something the installation is"
    ),
    "/settings/status-access": Command("haprion-settings apply", "haprion-settings-apply"),
    "/settings/api-tokens/new": Command("haprion-api-token add", "haprion-api-token"),
    "/settings/api-tokens/{name}/extend": Command("haprion-api-token extend", "haprion-api-token"),
    "/settings/api-tokens/{name}/revoke": Command("haprion-api-token revoke", "haprion-api-token"),
    "/settings/api-tokens/{name}/remove": Command("haprion-api-token remove", "haprion-api-token"),
    "/backups/restore/new": Command("haprion-node-restore prepare", "haprion-node-restore-prepare"),
    "/backups/restore/{run}/preview": Command(
        "haprion-node-restore preview", "haprion-node-restore-preview"
    ),
    "/backups/restore/{run}/run": Command("haprion-node-restore run", "haprion-node-restore"),
    "/backups/restore/{run}/discard": Command(
        "haprion-node-restore discard", "haprion-node-restore-discard"
    ),
    "/backups/restore/{run}/status": Command(
        "haprion-node-restore status", "haprion-node-restore-status"
    ),
    "/history/{cluster}/publish": NotASetting(
        "publishes what was saved in the interface; the terminal's apply publishes at once (B293)"
    ),
    "/history/{cluster}/regenerated": Command(
        "haprion-publish --regenerate", "haprion-changes-publish"
    ),
    "/login": NotASetting("signs in"),
    "/logout": NotASetting("signs out"),
    "/account/password": NotASetting("the signed-in person's own password; haprion-user reset"),
}

#
# What `/operations` queues, by its `operation` field.
#
OPERATIONS: dict[str, Command | Gap | NotASetting] = {
    "deploy": Command("haprion-deploy", "haprion-deploy"),
    "revert": Command("haprion-revert", "haprion-revert"),
    "network_save": Command("haprion-network apply", "haprion-network-apply"),
    "backup_run": Command("haprion-state-backup", "haprion-backup-run"),
    "backup_schedule": Command("haprion-backup-schedule", "haprion-backup-schedule"),
}


#
# What the API's write routes do in the terminal (B416, K03 26-11-05). The API
# is the other way in beside the pages, so a write added there without its
# command fails here like a page's. Object writes save a change in the
# interface; the terminal's `apply` is the same document published at once.
#
API_PARITY: dict[str, Command | Gap | NotASetting | NoCounterpart] = {
    "POST /clusters/{cluster}/objects": Command("haprion-objects apply", "haprion-objects-apply"),
    "PUT /clusters/{cluster}/objects/{name}": Command(
        "haprion-objects apply", "haprion-objects-apply"
    ),
    "DELETE /clusters/{cluster}/objects/{name}": Command(
        "haprion-objects remove", "haprion-objects-apply"
    ),
    "POST /clusters/{cluster}/publish": NotASetting(
        "publishes what was saved in the interface; the terminal's apply publishes at once (B293)"
    ),
    "POST /clusters/{cluster}/revert": Command("haprion-revert", "haprion-revert"),
    "POST /clusters/{cluster}/deploy": Command("haprion-deploy", "haprion-deploy"),
    "POST /certificates": Command("haprion-cert-issue", "haprion-cert-issue"),
    "POST /certificates/{certificate_id}/renew": Command(
        "haprion-cert-issue --renew", "haprion-cert-issue"
    ),
    "PUT /certificates/{certificate_id}/targets": Command(
        "haprion-cert-target", "haprion-cert-target"
    ),
    "DELETE /certificates/{certificate_id}": Command("haprion-cert-delete", "haprion-cert-delete"),
    "POST /clusters/{cluster}/objects/{name}/servers": Command(
        "haprion-server-state", "haprion-server-state"
    ),
    "POST /clusters/{cluster}/objects/{name}/health-check": Command(
        "haprion-probe", "haprion-probe"
    ),
    "DELETE /clusters/{cluster}/objects/{name}/blocks": Command(
        "haprion-server-state unblock", "haprion-server-state"
    ),
    "POST /clusters/{cluster}/objects/{name}/blocks": NoCounterpart(
        "the API exists for blocking tools (fail2ban, a firewall); the engine has no command that"
        " places a block, only one that lifts it"
    ),
}


#
# Commands the terminal has and the interface has no button for: what the timers
# and the playbooks run. They answer in a contract as the others do, so they are
# held to the same rule (W02, 26-11-05).
#
TERMINAL_ONLY: dict[str, Command] = {
    "haprion-cert-deploy": Command("haprion-cert-deploy", "haprion-cert-deploy"),
    "haprion-cert-renew": Command("haprion-cert-renew", "haprion-cert-renew"),
    "haprion-cert-request": Command("haprion-cert-request", "haprion-cert-request"),
    "haprion-config-status": Command("haprion-config-status", "haprion-config-status"),
    "haprion-export": Command("haprion-export", "haprion-export"),
    "haprion-history-reset": Command("haprion-history-reset", "haprion-history-reset"),
}

#
# Scripts that are not commands an operator or a playbook runs for an answer. A
# `*-helper` or `*-ask` is the socket protocol's end of a command listed above
# and is held by the helper tests; each is named in HELPER_ENDS, so one added
# without a decision here fails (Z04); the rest are named here with why.
#
HELPER_SUFFIXES = ("-helper", "-ask")
HELPER_ENDS = frozenset(
    {
        "haprion-backup-job-ask",
        "haprion-backup-job-helper",
        "haprion-block-api-helper",
        "haprion-blocklist-apply-helper",
        "haprion-blocklist-check-helper",
        "haprion-cert-delete-helper",
        "haprion-cert-deploy-helper",
        "haprion-cert-export-helper",
        "haprion-cert-import-helper",
        "haprion-cert-issue-helper",
        "haprion-cert-list-helper",
        "haprion-cert-publish-helper",
        "haprion-cert-receiver-ask",
        "haprion-cert-receiver-helper",
        "haprion-cert-request-helper",
        "haprion-cert-scep-helper",
        "haprion-cert-target-helper",
        "haprion-changes-publish-helper",
        "haprion-cluster-list-helper",
        "haprion-cluster-settings-helper",
        "haprion-deploy-helper",
        "haprion-dns-profile-apply-helper",
        "haprion-history-reset-helper",
        "haprion-http01-check-helper",
        "haprion-inventory-helper",
        "haprion-list-backups-helper",
        "haprion-list-helper",
        "haprion-ndes-profile-apply-helper",
        "haprion-ndes-server-helper",
        "haprion-network-helper",
        "haprion-node-ask",
        "haprion-node-helper",
        "haprion-node-restore-ask",
        "haprion-node-restore-helper",
        "haprion-objects-helper",
        "haprion-oidc-helper",
        "haprion-probe-helper",
        "haprion-publish-helper",
        "haprion-published-release-helper",
        "haprion-readings-helper",
        "haprion-regeneration-helper",
        "haprion-resolve-helper",
        "haprion-revert-helper",
        "haprion-server-state-helper",
        "haprion-status-helper",
        "haprion-tls-helper",
        "haprion-validate-candidate-helper",
    }
)
NOT_COMMANDS: dict[str, str] = {
    "haprion-cluster-config": "prints one value or the list for a shell script; it has no JSON form",
    "haprion-poller": "a service the unit runs",
    "haprion-worker": "a service the unit runs",
    "haprion-traffic-collector": "a service the timer runs on the nodes",
    "haprion-blocklist-refresh": (
        "a pass the timer runs (B500); Settings shows its state, which the poller reads"
    ),
}

#
# The refusals that stop before the command has judged anything it was asked: the
# caller is not root, or the thing it depends on is not there.
#
EARLY_STOPS = frozenset({"not_root", "dependency_unavailable"})

#
# Commands whose own judgement of the call lies behind something the gate does not
# run, so their refusal here is still an early stop. A command that starts
# reaching its own validation must leave this list.
#
BEHIND_THE_DATABASE = "the database is asked before the call is judged; there is none here"
BEHIND_A_HELPER = "the helper behind the socket judges the call; it is tested with the helper"
BEHIND_THE_WEBROOT = (
    "the runtime policy's webroot is read before the name is judged; there is none here"
)
BEHIND_SOMETHING: dict[str, str] = {
    **{
        f"haprion-api-token {verb}": BEHIND_THE_DATABASE
        for verb in ("add", "extend", "remove", "revoke")
    },
    "haprion-cert-delete": BEHIND_A_HELPER,
    "haprion-export": BEHIND_THE_DATABASE,
    "haprion-http01-check": BEHIND_THE_WEBROOT,
    "haprion-cert-target": BEHIND_A_HELPER,
    "haprion-cluster add": BEHIND_A_HELPER,
    "haprion-cluster remove": BEHIND_A_HELPER,
    "haprion-node add": BEHIND_A_HELPER,
    "haprion-node host": BEHIND_A_HELPER,
    "haprion-node remove": BEHIND_A_HELPER,
    "haprion-objects remove": BEHIND_A_HELPER,
    "haprion-probe": BEHIND_A_HELPER,
    "haprion-server-state": BEHIND_A_HELPER,
    "haprion-server-state unblock": BEHIND_A_HELPER,
}

#
# What a call the installation can answer must answer, though nothing is wrong
# with it: a step that asks about a run that is gone (W01, 26-11-05).
#
GONE = "r260101-0000aaaa"


@dataclass(frozen=True)
class Answer:
    argv: list[str]
    code: int
    outcome: str
    error: str | None
    result: dict[str, Any] | None = None


ANSWERS: dict[str, Answer] = {
    "haprion-node-restore status": Answer(
        ["status", "--run", GONE], 75, "blocked", "restore_refused"
    ),
    "haprion-node-restore discard": Answer(
        ["discard", "--run", GONE], 0, "done", None, {"run": GONE, "removed": False}
    ),
    "haprion-node-restore preview": Answer(
        ["preview", "--run", GONE, "--fingerprint", "SHA256:" + "A" * 43],
        75,
        "blocked",
        "restore_refused",
    ),
    "haprion-node-restore run": Answer(
        ["run", "--run", GONE, "--confirm", "node-a"], 75, "blocked", "restore_refused"
    ),
}


def _write_routes(routes: Any, prefix: str = "") -> set[tuple[str, str, str]]:
    """Every route that writes, as (mount prefix, method, path) - in routers, and in mounted apps.

    The pages are routers among routers; the API, and anything else mounted
    beside them, is an application a walk of `app.routes` stops at (K03, W03,
    26-11-05). The prefix is where it is mounted, the path is within it.
    """

    found: set[tuple[str, str, str]] = set()
    for route in routes:
        router = getattr(route, "original_router", None)
        if router is not None:
            found |= _write_routes(router.routes, prefix)
            continue
        inner = getattr(route, "app", None)
        if inner is not None and hasattr(inner, "routes") and not hasattr(route, "methods"):
            found |= _write_routes(inner.routes, prefix + str(getattr(route, "path", "")))
            continue
        for method in sorted((getattr(route, "methods", None) or set()) & WRITES):
            found.add((prefix, method, str(getattr(route, "path", ""))))
    return found


#
# The applications mounted without routes of their own, which a walk cannot look
# into, and why none of them takes a write (Z07, 26-11-05).
#
NOT_WRITES: dict[str, str] = {"/static": "files served for GET and HEAD only"}


def _unwalked(routes: Any, prefix: str = "") -> set[str]:
    """Where a write would go unseen: a mount with no `routes` to walk, and a route with no `methods`.

    A route given no `methods` (a class endpoint, a raw ASGI application) answers
    whichever the endpoint defines, so the walk cannot say it takes none (N04).
    """

    found: set[str] = set()
    for route in routes:
        router = getattr(route, "original_router", None)
        if router is not None:
            found |= _unwalked(router.routes, prefix)
            continue
        path = prefix + str(getattr(route, "path", ""))
        if hasattr(route, "methods") and route.methods is None:
            found.add(path)
            continue
        inner = getattr(route, "app", None)
        if inner is None or hasattr(route, "methods"):
            continue
        if hasattr(inner, "routes"):
            found |= _unwalked(inner.routes, path)
        else:
            found.add(path)
    return found


def _app() -> Any:
    return create_app(replace(configuration(), management_writes=True))


def _api_writes(app: Any = None) -> set[str]:
    """The API's write routes as `METHOD /path` under its prefix."""

    walked = _write_routes((app or _app()).routes)
    return {f"{method} {path}" for prefix, method, path in walked if prefix == api.PREFIX}


def _posted_routes(app: Any = None) -> set[str]:
    """Every other write: the pages' paths, and the full path of anything mounted elsewhere."""

    walked = _write_routes((app or _app()).routes)
    return {f"{prefix}{path}" for prefix, _, path in walked if prefix != api.PREFIX}


def _queued_operations() -> set[str]:
    """The `operation == "..."` branches of the `/operations` route, read from the source."""

    tree = ast.parse(VIEWS.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "queue_operation":
            return {
                compare.comparators[0].value
                for compare in ast.walk(node)
                if isinstance(compare, ast.Compare)
                and isinstance(compare.left, ast.Name)
                and compare.left.id == "operation"
                and isinstance(compare.ops[0], ast.Eq)
                and isinstance(compare.comparators[0], ast.Constant)
                and isinstance(compare.comparators[0].value, str)
            }
    raise AssertionError("queue_operation is no longer where this test reads it")


def _entry_points() -> dict[str, str]:
    points: dict[str, str] = {}
    for pyproject in (ROOT / "pyproject.toml", ROOT / "ui" / "pyproject.toml"):
        points.update(tomllib.loads(pyproject.read_text())["project"].get("scripts", {}))
    return points


def _help(line: str) -> str:
    """What the command says when asked for `--help`: run, not read from its source.

    Nothing is called but the parser, so the command is not run against the
    machine, and a command that does not know `--json` does not say it.
    """

    words = line.split()
    module, _, _ = _entry_points()[words[0]].partition(":")
    shown = io.StringIO()
    with (
        contextlib.redirect_stdout(shown),
        contextlib.redirect_stderr(shown),
        mock.patch("subprocess.run", side_effect=AssertionError("a command was run")),
        mock.patch("sys.stdin", io.StringIO()),
        contextlib.suppress(SystemExit),
    ):
        importlib.import_module(module).main([*words[1:], "--help"])
    return shown.getvalue()


def _no_database(seen: list[str]) -> Any:
    def connect(*_args: Any, **_kwargs: Any) -> Any:
        seen.append("database")
        raise psycopg.OperationalError("no database here")

    return connect


def _no_async_database(seen: list[str]) -> Any:
    async def connect(*_args: Any, **_kwargs: Any) -> Any:
        seen.append("database")
        raise psycopg.OperationalError("no database here")

    return connect


#
# What the audit hook refuses, by the name of the event (N02, 26-11-05). Python
# raises one event for each family: `os.exec` for every `execv*`, `os.spawn` for
# every `spawn*`.
#
REFUSED_EVENTS = frozenset(
    {
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.spawn",
        "os.posix_spawn",
        "os.fork",
        "os.forkpty",
        "ctypes.dlopen",
        "socket.connect",
        "socket.sendto",
        "socket.getaddrinfo",
    }
)
#
# The one foreign library a command loads on purpose: libcrypt, which hashes a
# password and reaches nothing. `dlopen(None)` is the process itself, whose
# libc can do anything, and every other name is refused.
#
ALLOWED_LIBRARIES = ("libcrypt.so",)
WRITING = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
TEMPORARY_ROOT = os.path.realpath(tempfile.gettempdir())


@dataclass
class Watch:
    """The command the hook is watching, where it may write, and what it caught."""

    program: str
    scratch: Path | None
    escapes: list[str]


WATCHING: Watch | None = None
HOOKED = False


def _opens_outside(watch: Watch, path: Any, mode: Any, flags: Any) -> bool:
    """Whether an `open` is one the command may not make.

    The rule, since Python itself opens files while it imports: a read is free,
    except of a path under a product directory, which the fixture would have
    moved below the scratch directory, so one that arrives here unmoved is the
    machine's own. A write is refused unless it is below the scratch directory
    or the temporary one, `/dev/null`, or a byte-code cache (an import may write
    one beside its source).
    """

    if isinstance(path, int) or path is None:
        return False
    try:
        text = os.path.abspath(os.fsdecode(path))
    except (TypeError, ValueError):
        return False
    if any(text == root or text.startswith(root + "/") for root in PRODUCT_ROOTS):
        return True
    writes = (
        bool(flags & WRITING)
        if isinstance(flags, int) and flags >= 0
        else any(letter in str(mode) for letter in "wax+")
    )
    if not writes:
        return False
    allowed = [TEMPORARY_ROOT]
    if watch.scratch is not None:
        allowed.append(os.path.realpath(watch.scratch))
    return not (
        text == os.devnull
        or "/__pycache__/" in text
        or any(text == root or text.startswith(root + "/") for root in allowed)
    )


def _audit(event: str, args: tuple[Any, ...]) -> None:
    watch = WATCHING
    if watch is None:
        return
    if event == "open":
        refused = _opens_outside(watch, *args)
    elif event == "ctypes.dlopen":
        refused = not (isinstance(args[0], str) and args[0].startswith(ALLOWED_LIBRARIES))
    else:
        refused = event in REFUSED_EVENTS
    if refused:
        message = f"{watch.program} reached {event}"
        watch.escapes.append(message)
        raise OSError(message)


@contextlib.contextmanager
def _watching(watch: Watch) -> Iterator[None]:
    """Run the block with the audit hook refusing what it must not do.

    A hook cannot be removed, so it is installed once and does nothing while
    `WATCHING` is empty; the flag is what turns it on for the length of one
    command.
    """

    global WATCHING, HOOKED
    if not HOOKED:
        sys.addaudithook(_audit)
        HOOKED = True
    WATCHING = watch

    def fork_exec(*_args: Any, **_kwargs: Any) -> Any:
        message = f"{watch.program} reached _posixsubprocess.fork_exec"
        watch.escapes.append(message)
        raise OSError(message)

    try:
        #
        # The one route to a new process Python raises no event for:
        # `multiprocessing` starts its children straight through this function.
        #
        with mock.patch("_posixsubprocess.fork_exec", fork_exec):
            yield
    finally:
        WATCHING = None


def _guards(program: str, seen: list[str], escapes: list[str], scratch: Path | None) -> list[Any]:
    """What a command run in the gate must not reach: a database, a socket, another process (Z01, N02).

    The database is asked through libpq, which no audit hook sees, so
    `psycopg.connect`, the connection classes' `connect` (which every pool calls)
    are replaced by ones that record the attempt and fail as a host without a
    database does. Everything else is the audit hook's: a socket, a name lookup,
    a new process by any route, a foreign library and a file outside the
    scratch directory fail the test with the command's name and the event.
    """

    return [
        mock.patch("psycopg.connect", _no_database(seen)),
        mock.patch.object(psycopg.Connection, "connect", _no_database(seen)),
        mock.patch.object(psycopg.AsyncConnection, "connect", _no_async_database(seen)),
        _watching(Watch(program, scratch, escapes)),
    ]


def _invoke(
    program: str, argv: list[str], scratch: Path | None = None, seen: list[str] | None = None
) -> tuple[int, str, str]:
    """The command's `main` in this process: its exit code, stdout and stderr.

    Without `scratch`, as an ordinary user with no helper to reach and no
    configuration: what is measured is what the command itself writes before it
    has read anything. With it, as root on an installation with one cluster
    (`write_installation`), the product's directories below `scratch`, so the
    command gets as far as judging the call (W02, 26-11-05). Either way it
    cannot leave the process: a database, a socket or a new process fails the
    test with the command's name, and a database attempt is added to `seen`
    (Z01, 26-11-05; N03, 26-11-05).
    """

    module, _, _ = _entry_points()[program].partition(":")
    out, err = io.StringIO(), io.StringIO()
    code: int
    escapes: list[str] = []
    with contextlib.ExitStack() as stack:
        stack.enter_context(contextlib.redirect_stdout(out))
        stack.enter_context(contextlib.redirect_stderr(err))
        stack.enter_context(
            mock.patch("subprocess.run", return_value=CompletedProcess([], 1, "", ""))
        )
        stack.enter_context(mock.patch("sys.stdin", io.StringIO()))
        if scratch is None:
            stack.enter_context(mock.patch("os.geteuid", return_value=1000))
            #
            # Not this machine's configuration: a call that gets as far as the runtime
            # policy finds it unreadable, as it is on a host with none.
            #
            stack.enter_context(
                mock.patch(
                    "haprion.config._secure_yaml",
                    side_effect=ConfigError(
                        "no runtime policy here", exit_code=exit_codes.UNAVAILABLE
                    ),
                )
            )
        else:
            stack.enter_context(mock.patch("os.geteuid", return_value=0))
            stack.enter_context(product_directories(scratch))
            stack.enter_context(
                mock.patch(
                    "haprion.config._secure_yaml",
                    side_effect=lambda path, *, require_secure: _read_yaml(path),
                )
            )
            real_load = ui_config.load
            stack.enter_context(
                mock.patch(
                    "haprion_ui.config.load",
                    side_effect=lambda path=ui_config.DEFAULT_CONFIG_PATH, *, require_secure=True: (
                        real_load(path, require_secure=False)
                    ),
                )
            )
        for guard in _guards(program, seen if seen is not None else [], escapes, scratch):
            stack.enter_context(guard)
        try:
            returned = importlib.import_module(module).main(argv)
            code = returned if isinstance(returned, int) else 0
        except SystemExit as stopped:
            code = stopped.code if isinstance(stopped.code, int) else 0
        except Exception as error:
            if escapes:
                raise AssertionError("; ".join(escapes)) from error
            raise
    if escapes:
        raise AssertionError("; ".join(escapes))
    return code, out.getvalue(), err.getvalue()


def _read_yaml(path: Path) -> dict[str, Any]:
    """The file as `_secure_yaml` reads it, without asking that root owns it."""

    return REAL_SECURE_YAML(path, require_secure=False)


def _commands() -> list[Command]:
    """Every command the tables name, once per line."""

    seen: dict[str, Command] = {}
    for entry in (
        *PARITY.values(),
        *OPERATIONS.values(),
        *API_PARITY.values(),
        *TERMINAL_ONLY.values(),
    ):
        if isinstance(entry, Command):
            seen.setdefault(entry.line, entry)
    return [seen[line] for line in sorted(seen)]


def _reaches_a_socket(_argv: list[str]) -> int:
    with socket.socket(socket.AF_UNIX) as sock:
        sock.connect("/run/haprion/none.sock")
    return 0


def _reaches_a_network(_argv: list[str]) -> int:
    with socket.socket(socket.AF_INET) as sock:
        sock.connect(("192.0.2.1", 5432))
    return 0


def _reaches_a_process(_argv: list[str]) -> int:
    subprocess.Popen(["true"])  # noqa: S607
    return 0


def _reaches_exec(_argv: list[str]) -> NoReturn:
    os.execv("/bin/true", ["true"])  # noqa: S606


def _reaches_a_database(_argv: list[str]) -> int:
    psycopg.connect("dbname=x")
    return 0


def _reaches_a_connection_class(_argv: list[str]) -> int:
    psycopg.Connection.connect("dbname=x")
    return 0


def _reaches_an_async_connection_class(_argv: list[str]) -> int:
    asyncio.run(psycopg.AsyncConnection.connect("dbname=x"))
    return 0


def _reaches_a_pool(_argv: list[str]) -> int:
    pool = psycopg_pool.ConnectionPool("dbname=x", open=False, timeout=2)
    try:
        pool.open(wait=True, timeout=2)
    finally:
        pool.close()
    return 0


def _reaches_spawn(_argv: list[str]) -> int:
    os.spawnl(os.P_WAIT, "/bin/true", "true")  # noqa: S606
    return 0


def _reaches_fork(_argv: list[str]) -> int:
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
    return 0


def _reaches_ctypes(_argv: list[str]) -> int:
    ctypes.CDLL(None)
    return 0


def _reaches_udp(_argv: list[str]) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"x", ("192.0.2.1", 9))
    return 0


def _reaches_a_name_lookup(_argv: list[str]) -> int:
    socket.getaddrinfo("name.invalid", 80)
    return 0


def _reaches_multiprocessing(_argv: list[str]) -> int:
    multiprocessing.get_context("spawn").Process(target=int).start()
    return 0


def _writes_beside_the_scratch_directory(_argv: list[str]) -> int:
    Path("/var/tmp/haprion-parity-gate-probe").write_text("x", encoding="utf-8")  # noqa: S108
    return 0


def _reads_the_machines_state(_argv: list[str]) -> int:
    # Not /etc/haprion: the test runner refuses that root on its own, before
    # this hook is asked.
    io.FileIO("/var/lib/haprion/state.json")
    return 0


def _stand_in(argv: list[str]) -> int:
    raise AssertionError("replaced by each test")


def main(argv: list[str]) -> int:
    """The `main` a stand-in command is run through."""

    return _stand_in(argv)


def _unclassified(points: dict[str, str]) -> list[str]:
    """The scripts that are neither a command in the tables, a reading program, a helper end nor named."""

    classified = {command.line.split()[0] for command in _commands()}
    classified |= set(READ_PROGRAMS) | set(NOT_COMMANDS)
    return sorted(
        program for program in points if program not in classified and program not in HELPER_ENDS
    )


def _programs() -> set[str]:
    programs: set[str] = set()
    for pyproject in (ROOT / "pyproject.toml", ROOT / "ui" / "pyproject.toml"):
        scripts = tomllib.loads(pyproject.read_text())["project"].get("scripts", {})
        programs.update(scripts)
    programs.update(path.name for path in (ROOT / "install" / "platform" / "bin").iterdir())
    return programs


class EveryWriteHasItsCommand(unittest.TestCase):
    def test_every_route_that_writes_is_listed_once(self) -> None:
        routes = _posted_routes()
        listed = set(PARITY) | {"/operations"}

        self.assertEqual(sorted(routes - listed), [], "a write with no terminal counterpart named")
        self.assertEqual(sorted(listed - routes), [], "listed here, but no such route")

    def test_every_api_write_is_listed_once(self) -> None:
        writes = _api_writes()

        self.assertEqual(len(writes), len(API_PARITY), "the walk no longer reaches the mounted API")
        self.assertEqual(sorted(writes - set(API_PARITY)), [], "an API write with no counterpart")
        self.assertEqual(sorted(set(API_PARITY) - writes), [], "listed here, but no such route")

    def test_every_mount_a_walk_cannot_enter_is_said_to_take_no_write(self) -> None:
        self.assertEqual(sorted(_unwalked(_app().routes)), sorted(NOT_WRITES))

    def test_a_mounted_application_without_routes_would_be_found(self) -> None:
        """Z07: `app.mount("/hook", raw_asgi)` takes a POST nothing here would otherwise hear of."""

        async def raw(scope: Any, receive: Any, send: Any) -> None:
            return None

        app = _app()
        app.mount("/hook", raw)

        self.assertEqual(sorted(_unwalked(app.routes)), ["/hook", *sorted(NOT_WRITES)])

    def test_a_route_without_methods_would_be_found(self) -> None:
        """N04: a class endpoint answers every method it defines, and a raw ASGI route all of them."""

        class Endpoint(HTTPEndpoint):
            async def post(self, request: Any) -> Any:
                return None

        class Raw:
            async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
                return None

        app = _app()
        app.router.routes.append(Route("/ep", Endpoint))
        app.router.routes.append(Route("/rawroute", Raw()))
        app.mount("/sub", Starlette(routes=[Route("/p", Endpoint)]))

        self.assertEqual(
            sorted(_unwalked(app.routes)),
            sorted(["/ep", "/rawroute", "/sub/p", *NOT_WRITES]),
        )

    def test_the_writes_with_no_command_are_the_ones_said(self) -> None:
        said = sorted(
            route for route, entry in API_PARITY.items() if isinstance(entry, NoCounterpart)
        )

        self.assertEqual(said, ["POST /clusters/{cluster}/objects/{name}/blocks"])

    def test_every_queued_operation_is_listed_once(self) -> None:
        self.assertEqual(sorted(_queued_operations()), sorted(OPERATIONS))

    def test_every_command_named_exists(self) -> None:
        programs = _programs()
        named = {
            entry.line.split()[0]
            for entry in (*PARITY.values(), *OPERATIONS.values(), *API_PARITY.values())
            if isinstance(entry, Command)
        }

        self.assertEqual(sorted(named - programs), [])

    def test_every_command_answers_in_a_contract(self) -> None:
        """A schema for each, and `--json` where the command is written (Fas 23 review).

        `haprion-cluster-settings --set` was listed here for a day while it had
        neither `--json` nor `--check`; the program existed, so the list was
        satisfied, and a playbook could not tell a change from none.
        """

        entries = [
            entry
            for entry in (
                *PARITY.values(),
                *OPERATIONS.values(),
                *API_PARITY.values(),
                *TERMINAL_ONLY.values(),
            )
            if isinstance(entry, Command)
        ]
        missing = sorted(
            {entry.schema for entry in entries}
            - {path.name.removesuffix(".schema.json") for path in SCHEMAS.iterdir()}
        )
        self.assertEqual(missing, [])
        self.assertEqual(sorted({entry.line for entry in entries if entry.schema in READS}), [])
        silent = sorted({entry.line for entry in entries if "--json" not in _help(entry.line)})
        self.assertEqual(silent, [])

    def test_every_command_has_a_call_it_refuses(self) -> None:
        self.assertEqual(sorted({command.line for command in _commands()} ^ set(REFUSED_CALLS)), [])

    def test_a_refusal_is_the_one_document_the_contract_holds(self) -> None:
        """K01, K07: bad input with `--json` gives stdout that validates against the command's schema.

        As an ordinary user: what a command writes before it has read anything.
        The exit code is the outcome's: a document that says `blocked` exits 75,
        and one that says `failed` exits with something else but 0.
        """

        for command in _commands():
            with self.subTest(command.line):
                code, out, _ = _invoke(
                    command.line.split()[0], [*REFUSED_CALLS[command.line], "--json"]
                )
                document = assert_contract(command.schema, out)
                self.assertNotEqual(code, 0)
                self.assertFalse(document["ok"])
                self.assertEqual(document["outcome"], exit_codes.outcome(code), document["error"])

    def test_a_refusal_comes_from_the_commands_own_judgement(self) -> None:
        """W02: as root on an installation that has a cluster, the call is judged by the command.

        K01 had every step answer `not_root` here while its own code for a run
        that is gone was wrong. A command that still stops early must say why.
        """

        with tempfile.TemporaryDirectory() as raw:
            scratch = Path(raw)
            write_installation(scratch)
            for command in _commands():
                with self.subTest(command.line):
                    seen: list[str] = []
                    code, out, _ = _invoke(
                        command.line.split()[0],
                        [*REFUSED_CALLS[command.line], "--json"],
                        scratch,
                        seen,
                    )
                    document = assert_contract(command.schema, out)
                    stopped = document["error"]["code"]
                    #
                    # The reason given is the one measured (Z02): the database was asked
                    # by the commands that say so, and by no other.
                    #
                    self.assertEqual(
                        "database" in seen,
                        BEHIND_SOMETHING.get(command.line) == BEHIND_THE_DATABASE,
                        (command.line, document["error"]),
                    )
                    self.assertNotEqual(code, 0)
                    self.assertEqual(document["outcome"], exit_codes.outcome(code), stopped)
                    if command.line in BEHIND_SOMETHING:
                        self.assertIn(
                            stopped, EARLY_STOPS, "it judges the call now: take it off the list"
                        )
                    else:
                        self.assertNotIn(stopped, EARLY_STOPS, document["error"])
                    if stopped == "dependency_unavailable":
                        self.assertNotEqual(code, exit_codes.USAGE, "a mistake is bad_input")

    def test_a_call_that_has_an_answer_gets_it(self) -> None:
        """W01: a run that is gone is `blocked`, and discarding it twice is not an error."""

        schemas = {command.line: command.schema for command in _commands()}
        with tempfile.TemporaryDirectory() as raw:
            scratch = Path(raw)
            write_installation(scratch)
            for line, answer in ANSWERS.items():
                with self.subTest(line):
                    code, out, _ = _invoke(line.split()[0], [*answer.argv, "--json"], scratch)
                    document = assert_contract(schemas[line], out)
                    self.assertEqual(
                        (code, document["outcome"], (document["error"] or {}).get("code")),
                        (answer.code, answer.outcome, answer.error),
                    )
                    if answer.result is not None:
                        self.assertEqual(document["result"], answer.result)

    def test_a_command_that_leaves_the_scratch_directory_fails_with_its_name(self) -> None:
        """Z01: a socket, a process or an exec fails the test; a database is refused and recorded."""

        points = {"haprion-fake": f"{__name__}:main"}
        with (
            tempfile.TemporaryDirectory() as raw,
            mock.patch(f"{__name__}._entry_points", return_value=points),
        ):
            scratch = Path(raw)
            write_installation(scratch)
            for stand_in in (
                _reaches_a_socket,
                _reaches_a_network,
                _reaches_a_process,
                _reaches_exec,
            ):
                with (
                    self.subTest(stand_in.__name__),
                    mock.patch(f"{__name__}._stand_in", stand_in),
                    self.assertRaisesRegex(AssertionError, "haprion-fake reached"),
                ):
                    _invoke("haprion-fake", [], scratch)
            seen: list[str] = []
            with (
                mock.patch(f"{__name__}._stand_in", _reaches_a_database),
                self.assertRaises(psycopg.OperationalError),
            ):
                _invoke("haprion-fake", [], scratch, seen)
            self.assertEqual(seen, ["database"])

    def test_the_audit_hook_names_the_command_and_the_event(self) -> None:
        """N02: one hook sees what the patches by name missed; it says which event and whose."""

        points = {"haprion-fake": f"{__name__}:main"}
        planted = (
            (_reaches_spawn, "os.fork"),
            (_reaches_fork, "os.fork"),
            (_reaches_ctypes, "ctypes.dlopen"),
            (_reaches_udp, "socket.sendto"),
            (_reaches_a_name_lookup, "socket.getaddrinfo"),
            (_reaches_multiprocessing, "_posixsubprocess.fork_exec"),
            (_writes_beside_the_scratch_directory, "open"),
            (_reads_the_machines_state, "open"),
        )
        with (
            tempfile.TemporaryDirectory() as raw,
            mock.patch(f"{__name__}._entry_points", return_value=points),
        ):
            scratch = Path(raw)
            write_installation(scratch)
            for stand_in, event in planted:
                with (
                    self.subTest(stand_in.__name__),
                    mock.patch(f"{__name__}._stand_in", stand_in),
                    self.assertRaisesRegex(AssertionError, f"haprion-fake reached {event}"),
                ):
                    _invoke("haprion-fake", [], scratch)

    def test_the_audit_hook_is_silent_outside_a_command(self) -> None:
        """N02: a hook cannot be removed, so it must do nothing when no command is running."""

        points = {"haprion-fake": f"{__name__}:main"}
        with (
            mock.patch(f"{__name__}._entry_points", return_value=points),
            mock.patch(f"{__name__}._stand_in", lambda _argv: 0),
        ):
            _invoke("haprion-fake", [])
        self.assertEqual(subprocess.run(["true"], check=False).returncode, 0)  # noqa: S607

    def test_a_command_may_write_in_the_scratch_directory_and_read_python(self) -> None:
        """N02: the rule lets the fixture's own paths and Python's imports through."""

        def writes_in_scratch(_argv: list[str]) -> int:
            Path("/etc/haprion/probe.txt").write_text("x", encoding="utf-8")
            importlib.import_module("csv")
            return 0

        points = {"haprion-fake": f"{__name__}:main"}
        with (
            tempfile.TemporaryDirectory() as raw,
            mock.patch(f"{__name__}._entry_points", return_value=points),
            mock.patch(f"{__name__}._stand_in", writes_in_scratch),
        ):
            scratch = Path(raw)
            write_installation(scratch)
            self.assertEqual(_invoke("haprion-fake", [], scratch)[0], 0)
            self.assertTrue((scratch / "etc/haprion/probe.txt").is_file())

    def test_the_guards_hold_for_an_ordinary_user_too(self) -> None:
        """N03: the branch without a scratch directory is guarded as the root one is."""

        points = {"haprion-fake": f"{__name__}:main"}
        with mock.patch(f"{__name__}._entry_points", return_value=points):
            for stand_in in (_reaches_a_network, _reaches_a_process, _reaches_exec):
                with (
                    self.subTest(stand_in.__name__),
                    mock.patch(f"{__name__}._stand_in", stand_in),
                    self.assertRaisesRegex(AssertionError, "haprion-fake reached"),
                ):
                    _invoke("haprion-fake", [])
            seen: list[str] = []
            with (
                mock.patch(f"{__name__}._stand_in", _reaches_a_database),
                self.assertRaises(psycopg.OperationalError),
            ):
                _invoke("haprion-fake", [], None, seen)
            self.assertEqual(seen, ["database"])

    def test_every_way_to_a_database_is_refused_and_recorded(self) -> None:
        """N01: the connection classes and the pool reach libpq as `psycopg.connect` does."""

        points = {"haprion-fake": f"{__name__}:main"}
        with (
            tempfile.TemporaryDirectory() as raw,
            mock.patch(f"{__name__}._entry_points", return_value=points),
        ):
            scratch = Path(raw)
            write_installation(scratch)
            for stand_in in (
                _reaches_a_connection_class,
                _reaches_an_async_connection_class,
                _reaches_a_pool,
            ):
                seen: list[str] = []
                with (
                    self.subTest(stand_in.__name__),
                    mock.patch(f"{__name__}._stand_in", stand_in),
                    contextlib.suppress(Exception),
                ):
                    _invoke("haprion-fake", [], scratch, seen)
                self.assertIn("database", seen, stand_in.__name__)

    def test_every_script_is_classified(self) -> None:
        """W02: a command added to pyproject.toml without a class fails here."""

        self.assertEqual(_unclassified(_entry_points()), [])
        self.assertEqual(sorted(set(NOT_COMMANDS) - set(_entry_points())), [])
        self.assertEqual(sorted(set(BEHIND_SOMETHING) - {c.line for c in _commands()}), [])

    def test_the_helper_ends_are_the_scripts_named_so(self) -> None:
        """Z04: the exemption is a list a person extends, not a suffix a new script gets free."""

        suffixed = {name for name in _entry_points() if name.endswith(HELPER_SUFFIXES)}

        self.assertEqual(sorted(suffixed ^ HELPER_ENDS), [])

    def test_a_new_helper_end_would_not_pass_unclassified(self) -> None:
        points = {**_entry_points(), "haprion-cert-foo-helper": "haprion.cli.cert_foo_helper:main"}

        self.assertEqual(_unclassified(points), ["haprion-cert-foo-helper"])

    def test_a_new_script_would_not_pass_unclassified(self) -> None:
        """A check that cannot fail is not a check."""

        points = {**_entry_points(), "haprion-cert-foo": "haprion.cli.cert_foo:main"}

        self.assertEqual(_unclassified(points), ["haprion-cert-foo"])

    def test_the_other_commands_a_script_runs_answer_json_too(self) -> None:
        """K12: the contract says every command can; a script needs `unlock` and `revoke` as much as `apply`."""

        lines = [
            *(f"haprion-user {verb}" for verb in USER_VERBS),
            "haprion-cert-renew",
            "haprion-config-status",
        ]

        self.assertEqual(sorted(line for line in lines if "--json" not in _help(line)), [])

    def test_a_mistyped_call_leaves_stdout_empty(self) -> None:
        """K08: with `--json`, stdout holds a document or nothing - never the usage text.

        Asked for with `--help` the text goes to stdout; a mistake is said on
        stderr, as the parser-based commands always said it.
        """

        programs = sorted(
            {command.line.split()[0] for command in _commands()} | (set(READ_PROGRAMS))
        )
        said = {
            program: _invoke(program, ["--no-such-flag", "--json"])
            for program in programs
            if program in _entry_points()
        }

        self.assertEqual(
            sorted(program for program, (code, out, _) in said.items() if out.strip()), []
        )
        self.assertEqual(
            sorted(program for program, (code, _, _) in said.items() if code != 64), []
        )

    def test_a_write_on_another_mount_is_seen(self) -> None:
        """W03: a second application mounted beside the pages is not exempt."""

        from fastapi import FastAPI

        other = FastAPI()
        other.add_api_route("/danger", lambda: None, methods=["POST"])
        app = _app()
        app.mount("/v2", other)

        self.assertIn("/v2/danger", _posted_routes(app) - set(PARITY))
        self.assertEqual(_api_writes(app), _api_writes())

    def test_the_check_would_notice_a_new_route(self) -> None:
        """A check that cannot fail is not a check."""

        routes = _posted_routes() | {"/settings/something-new"}

        self.assertIn("/settings/something-new", routes - set(PARITY))

    def test_the_http01_check_judges_the_name_as_the_form_does(self) -> None:
        """The form's name and the command's argument are read alike."""

        for text in (" App.Example.COM ", "app.example.com.", "app.example.com", "127.1", "."):
            with self.subTest(text=text):
                form = certificate_form.normalise(replace(certificate_form.EMPTY_FORM, domain=text))
                try:
                    from_command: str | None = http01_check.parse_name(text)
                except http01_check.CheckError:
                    from_command = None
                try:
                    from_form: str | None = http01_check.parse_name(form.domain)
                except http01_check.CheckError:
                    from_form = None
                self.assertEqual(from_form, from_command)

    def test_fas_23_left_no_gap(self) -> None:
        """Every write the interface makes now has its command; a new one must name its own."""

        gaps = sorted(
            (entry.step, path)
            for path, entry in (*PARITY.items(), *OPERATIONS.items(), *API_PARITY.items())
            if isinstance(entry, Gap)
        )

        self.assertEqual(gaps, [])


if __name__ == "__main__":
    unittest.main()
