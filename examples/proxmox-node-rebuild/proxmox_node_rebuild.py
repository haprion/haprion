#!/usr/bin/env python3
"""Rebuild a lost node on a new Proxmox VM with one command: an example.

This is not part of the product. It is one installation's way of putting
`haprion-node-restore` behind Proxmox, kept here for anyone with the same
hypervisor to read, adapt, or leave alone. It uses the installed command's
`--json` answers and nothing else of the product.

What it does, in order (README.md says why):

1. reads its settings and the API token, and checks them against Proxmox;
2. clones the template into the pool, gives the clone the cluster's bridge and
   a temporary address with cloud-init (no package upgrade), and starts it;
3. waits for the guest agent and for cloud-init to finish;
4. `haprion-node-restore prepare`, then runs the line it prints inside the VM
   through the guest agent, and reads the host key fingerprint from its output
   - the console's job, done over the hypervisor's channel, not the network;
5. `preview`, shown as it is; `run` once it passes;
6. switches cloud-init off in the VM, stops it, removes the cloud-init drive,
   and starts it again on the node's own address.

Usage:
    proxmox_node_rebuild.py [--settings FILE] check <node> [--test]
    proxmox_node_rebuild.py [--settings FILE] run <node> [--archive VERSION] [--vmid ID] [--test]

Run as root: `haprion-node-restore` needs it, and so does the token file.
"""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

DEFAULT_SETTINGS = Path("/etc/proxmox-node-rebuild/settings.env")
RESTORE = "haprion-node-restore"
LIST_BACKUPS = "haprion-list-backups"
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
#
# What the token needs on the pool, the template and the storage.
# Read back from Proxmox by `check`, so a missing one is named before a clone.
# `VM.GuestAgent.Unrestricted` is what `agent/exec` and `exec-status` take
# since Proxmox VE 9.
#
POOL_PRIVILEGES = (
    "VM.Allocate",
    "VM.Audit",
    "VM.Config.Cloudinit",
    "VM.Config.CPU",
    "VM.Config.Disk",
    "VM.Config.Memory",
    "VM.Config.Network",
    "VM.PowerMgmt",
    "VM.GuestAgent.Unrestricted",
)
TEMPLATE_PRIVILEGES = ("VM.Clone",)
STORAGE_PRIVILEGES = ("Datastore.AllocateSpace",)
AGENT_WAIT = 300.0
CLOUD_INIT_WAIT = 900.0
TASK_WAIT = 900.0
ADDRESS_WAIT = 300.0


class Stop(Exception):
    """Something refused or failed, said in a sentence for the operator."""


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------


def read_env(path: Path) -> dict[str, str]:
    """KEY=value lines, as an answers file has them. Read, never sourced."""

    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise Stop(f"{path} could not be read: {exc.strerror}") from None
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not KEY.fullmatch(key):
            raise Stop(f"{path}:{number} is not KEY=value")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def env_name(name: str) -> str:
    """A node or cluster name as it stands in a key: lb-01 -> LB_01."""

    return re.sub(r"[^A-Z0-9]", "_", name.upper())


@dataclass(frozen=True)
class Target:
    """Where one rebuild goes, from the settings."""

    node: str
    cluster: str
    vmid: int
    name: str
    bridge: str
    gateway: str
    temporary: ipaddress.IPv4Interface
    test: ipaddress.IPv4Interface | None
    test_vip: str | None


@dataclass(frozen=True)
class Settings:
    hosts: tuple[str, ...]
    port: int
    ca_file: str | None
    token_id: str
    token_secret: str
    template: str
    storage: str
    pool: str
    target_node: str | None
    cores: int | None
    memory_mb: int | None
    nameserver: str | None
    searchdomain: str | None
    values: Mapping[str, str]

    @classmethod
    def load(cls, path: Path) -> Settings:
        values = read_env(path)

        def need(key: str) -> str:
            if not values.get(key):
                raise Stop(f"{path} has no {key}")
            return values[key]

        token = read_env(Path(need("PVE_TOKEN_FILE")))
        for key in ("PVE_API_TOKEN_ID", "PVE_API_TOKEN_SECRET"):
            if not token.get(key):
                raise Stop(f"{values['PVE_TOKEN_FILE']} has no {key}")
        return cls(
            hosts=tuple(need("PVE_API_HOSTS").split()),
            port=_integer(values.get("PVE_API_PORT") or "8006", "PVE_API_PORT"),
            ca_file=values.get("PVE_CA_FILE") or None,
            token_id=token["PVE_API_TOKEN_ID"],
            token_secret=token["PVE_API_TOKEN_SECRET"],
            template=need("PVE_TEMPLATE_NAME"),
            storage=need("PVE_STORAGE"),
            pool=need("PVE_POOL"),
            target_node=values.get("PVE_TARGET_NODE") or None,
            cores=_integer(values["VM_CORES"], "VM_CORES") if values.get("VM_CORES") else None,
            memory_mb=(
                _integer(values["VM_MEMORY_MB"], "VM_MEMORY_MB")
                if values.get("VM_MEMORY_MB")
                else None
            ),
            nameserver=values.get("NAMESERVER") or None,
            searchdomain=values.get("SEARCHDOMAIN") or None,
            values=values,
        )

    def resolve(self, given: str) -> tuple[str, str]:
        """A node as typed - its whole name or a short one that fits only it - to its key and cluster.

        `01` finds NODE_LB_01_CLUSTER when no other node ends in 01, as haprion-list-backups --node takes a
        short name that can only mean one node.
        """

        wanted = env_name(given)
        keys = [
            key[len("NODE_") : -len("_CLUSTER")]
            for key, value in self.values.items()
            if key.startswith("NODE_") and key.endswith("_CLUSTER") and value
        ]
        found = [key for key in keys if key == wanted or key.endswith("_" + wanted)]
        if len(found) != 1:
            known = ", ".join(sorted(keys)) or "none"
            what = "fits no node" if not found else f"fits {', '.join(sorted(found))}"
            raise Stop(f"{given} {what} in the settings (NODE_<name>_CLUSTER: {known})")
        return found[0], self.values[f"NODE_{found[0]}_CLUSTER"]

    def target(self, node: str, *, test: bool, vmid: int | None) -> Target:
        def need(key: str) -> str:
            if not self.values.get(key):
                raise Stop(f"the settings have no {key}")
            return self.values[key]

        prefix = f"NODE_{env_name(node)}"
        cluster = need(f"{prefix}_CLUSTER")
        cprefix = f"CLUSTER_{env_name(cluster)}"
        temporary = _interface(need(f"{cprefix}_TEMPORARY_ADDRESS"), f"{cprefix}_TEMPORARY_ADDRESS")
        test_address = None
        test_vip = None
        if test:
            test_address = _interface(need(f"{cprefix}_TEST_ADDRESS"), f"{cprefix}_TEST_ADDRESS")
            test_vip = str(_interface(need("TEST_VIP"), "TEST_VIP"))
            chosen = vmid if vmid is not None else _integer(need("TEST_VMID"), "TEST_VMID")
            name = f"restoretest-{node}"[:63]
        else:
            chosen = (
                vmid if vmid is not None else _integer(need(f"{prefix}_VMID"), f"{prefix}_VMID")
            )
            name = node
        return Target(
            node=node,
            cluster=cluster,
            vmid=chosen,
            name=name,
            bridge=need(f"{cprefix}_BRIDGE"),
            gateway=str(ipaddress.IPv4Address(need(f"{cprefix}_GATEWAY"))),
            temporary=temporary,
            test=test_address,
            test_vip=test_vip,
        )


def _integer(value: str, key: str) -> int:
    if not value.isdigit():
        raise Stop(f"{key} is not a number: {value}")
    return int(value)


def _interface(value: str, key: str) -> ipaddress.IPv4Interface:
    try:
        interface = ipaddress.IPv4Interface(value)
    except ValueError:
        raise Stop(f"{key} is not an address/prefix: {value}") from None
    if "/" not in value:
        raise Stop(f"{key} needs its prefix: {value}/24, for example")
    return interface


# --------------------------------------------------------------------------
# Proxmox
# --------------------------------------------------------------------------

Call = Callable[[str, str, Mapping[str, Any] | None], Any]


class Proxmox:
    """The API calls this needs, through one function: real, or a test's."""

    def __init__(self, call: Call, *, sleep: Callable[[float], None] = time.sleep) -> None:
        self.call = call
        self.sleep = sleep

    def wait_task(self, node: str, upid: str, what: str, *, limit: float = TASK_WAIT) -> None:
        waited = 0.0
        path = f"/nodes/{node}/tasks/{urllib.parse.quote(upid, safe='')}/status"
        while True:
            status = self.call("GET", path, None)
            if status.get("status") == "stopped":
                if status.get("exitstatus") != "OK":
                    raise Stop(f"{what} failed in Proxmox: {status.get('exitstatus')}")
                return
            if waited >= limit:
                raise Stop(f"{what} did not finish in {int(limit)} s; see the task in Proxmox")
            self.sleep(2.0)
            waited += 2.0

    def vms(self) -> list[dict[str, Any]]:
        return [vm for vm in self.call("GET", "/cluster/resources", {"type": "vm"}) or []]

    def host_state(self, host: str) -> str | None:
        """online or offline, as the cluster has it; None when the token cannot see the host."""

        hosts = self.call("GET", "/cluster/resources", {"type": "node"}) or []
        state = next((h.get("status") for h in hosts if h.get("node") == host), None)
        return str(state) if state else None

    def config(self, node: str, vmid: int) -> dict[str, Any]:
        return dict(self.call("GET", f"/nodes/{node}/qemu/{vmid}/config", None) or {})

    def agent_up(self, node: str, vmid: int, *, limit: float = AGENT_WAIT) -> None:
        waited = 0.0
        while True:
            try:
                self.call("POST", f"/nodes/{node}/qemu/{vmid}/agent/ping", None)
                return
            except Stop:
                if waited >= limit:
                    raise Stop(
                        f"the guest agent in VM {vmid} did not answer in {int(limit)} s; "
                        "is qemu-guest-agent installed in the template, and the agent "
                        "option on?"
                    ) from None
            self.sleep(5.0)
            waited += 5.0

    def execute(
        self, node: str, vmid: int, script: str, *, limit: float = 120.0
    ) -> tuple[int, str, str]:
        """`sh` in the guest with the script on stdin: the exit code, stdout and stderr."""

        started = self.call(
            "POST",
            f"/nodes/{node}/qemu/{vmid}/agent/exec",
            {"command": ["/bin/sh"], "input-data": script},
        )
        pid = started.get("pid") if isinstance(started, Mapping) else None
        if not isinstance(pid, int):
            raise Stop(f"the guest agent started no command: {started!r}")
        waited = 0.0
        last = "still running"
        while True:
            #
            # An agent busy with a first boot misses an answer now and then:
            # "got timeout" (26-11-03). Asked again until the limit, which
            # then says the last thing it heard.
            #
            try:
                status = self.call(
                    "GET", f"/nodes/{node}/qemu/{vmid}/agent/exec-status", {"pid": pid}
                )
            except Stop as exc:
                status, last = {}, str(exc)
            if status.get("exited"):
                return (
                    int(status.get("exitcode", -1)),
                    str(status.get("out-data", "")),
                    str(status.get("err-data", "")),
                )
            if waited >= limit:
                raise Stop(f"the command in VM {vmid} did not finish in {int(limit)} s: {last}")
            self.sleep(2.0)
            waited += 2.0

    def cloud_init_done(self, node: str, vmid: int, *, limit: float = CLOUD_INIT_WAIT) -> None:
        """Short questions in a loop, not one long `--wait`: an agent restarted on a first boot
        forgets the commands it started, and a new question still works."""

        waited = 0.0
        last = ""
        while True:
            try:
                code, out, _ = self.execute(
                    node,
                    vmid,
                    "command -v cloud-init >/dev/null || { echo 'status: absent'; exit 0; }\n"
                    "cloud-init status\n",
                    limit=30.0,
                )
                found = re.search(r"^status:\s*(\S+)", out, re.MULTILINE)
                state = found.group(1) if found else f"exit {code}"
            except Stop as exc:
                state, last = "", str(exc)
            if state in ("done", "absent", "disabled"):
                return
            if state == "error":
                raise Stop(f"cloud-init in VM {vmid} reports an error; see its console")
            last = f"status {state}" if state else last
            if waited >= limit:
                raise Stop(f"cloud-init in VM {vmid} did not finish in {int(limit)} s ({last})")
            self.sleep(5.0)
            waited += 5.0


def api_call(settings: Settings, *, timeout: float = 30.0) -> Call:
    """A function that calls the first API host that answers."""

    context = ssl.create_default_context(cafile=settings.ca_file)
    header = f"PVEAPIToken={settings.token_id}={settings.token_secret}"

    def call(method: str, path: str, data: Mapping[str, Any] | None) -> Any:
        last = ""
        for host in settings.hosts:
            url = f"https://{host}:{settings.port}/api2/json{path}"
            body = None
            headers = {"Authorization": header}
            if data is not None and method == "GET":
                url += "?" + urllib.parse.urlencode(data, doseq=True)
            elif data is not None:
                body = json.dumps(data).encode("utf-8")
                headers["Content-Type"] = "application/json"
            # https://, to the configured hosts only: no other scheme can be built here.
            request = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310
            try:
                with urllib.request.urlopen(request, timeout=timeout, context=context) as answer:  # noqa: S310
                    return json.loads(answer.read().decode("utf-8")).get("data")
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")[:300]
                raise Stop(f"Proxmox {method} {path}: {exc.code} {exc.reason} {detail}") from None
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last = f"{host}: {getattr(exc, 'reason', exc)}"
        raise Stop(f"no Proxmox API host answered ({last})")

    return call


def _missing(granted: Mapping[str, Any], wanted: Sequence[str]) -> list[str]:
    """What is not granted. A privilege's value is its propagate flag, not whether it is held.

    26-11-04: a right through a pool answers VM.Clone 0, and read as a truth
    value it looked missing.
    """

    return [name for name in wanted if name not in granted]


# --------------------------------------------------------------------------
# haprion-node-restore and the backups
# --------------------------------------------------------------------------

Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def run_command(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), check=False, capture_output=True, text=True)  # noqa: S603 - fixed commands


def latest_archive(runner: Runner, cluster: str, node: str) -> str:
    done = runner([LIST_BACKUPS, "-c", cluster, "--node", node, "--json"])
    try:
        nodes = json.loads(done.stdout)["result"]["nodes"]
    except (ValueError, KeyError, TypeError):
        raise Stop(f"{LIST_BACKUPS} gave no answer: {done.stderr.strip()[-300:]}") from None
    for entry in nodes:
        if entry.get("name") == node and entry.get("latest_version"):
            return str(entry["latest_version"])
    raise Stop(f"there is no backup of {node} in {cluster}")


def node_standing(runner: Runner, cluster: str, key: str) -> tuple[str, str]:
    """The node's name and management host, as the cluster's definition has them."""

    done = runner(["haprion-status", "-c", cluster, "--json"])
    try:
        nodes = json.loads(done.stdout)["result"]["nodes"]
    except (ValueError, KeyError, TypeError):
        raise Stop(f"haprion-status gave no answer: {done.stderr.strip()[-300:]}") from None
    for node in nodes:
        if env_name(str(node.get("name", ""))) == key and node.get("mgmt_host"):
            return str(node["name"]), str(node["mgmt_host"])
    raise Stop(f"cluster {cluster} has no node that NODE_{key}_CLUSTER names")


def resolve(host: str) -> str:
    try:
        return str(socket.getaddrinfo(host, 22, socket.AF_INET, socket.SOCK_STREAM)[0][4][0])
    except (OSError, IndexError):
        raise Stop(f"{host} does not resolve; the node's address cannot be checked") from None


def answers(address: str, port: int = 22, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# The steps
# --------------------------------------------------------------------------


@dataclass
class Context:
    settings: Settings
    api: Proxmox
    runner: Runner
    out: TextIO
    answering: Callable[[str], bool]
    resolving: Callable[[str], str] = resolve

    def alive(self, address: str) -> bool:
        """ssh on port 22, or an answer to ping: anything that says a machine holds it."""

        if self.answering(address):
            return True
        return self.runner(["ping", "-c", "1", "-W", "1", address]).returncode == 0


def same_host(vm_name: str, node: str) -> bool:
    """A VM name that is the node: case aside, and its first label (LB-01.example.net is lb-01).

    26-11-04: Proxmox held a node with a capital first letter, and an exact
    comparison let the rebuild past it.
    """

    return vm_name.split(".", 1)[0].casefold() == node.split(".", 1)[0].casefold()


def find_template(resources: Sequence[Mapping[str, Any]], pattern: str) -> Mapping[str, Any]:
    """The one template whose name fits the pattern, case aside (TemplateUbuntu*).

    26-11-04: found by name, so a new template needs no new setting. Two that
    fit stop it: which one is the right one is not the example's to guess.
    """

    wanted = pattern.casefold()
    found = [
        vm
        for vm in resources
        if vm.get("template") and fnmatch.fnmatchcase(str(vm.get("name") or "").casefold(), wanted)
    ]
    if not found:
        raise Stop(f"no template the token can see is named {pattern}")
    if len(found) > 1:
        listed = ", ".join(f"{vm.get('vmid')} {vm.get('name')} on {vm.get('node')}" for vm in found)
        raise Stop(f"{len(found)} templates are named {pattern} ({listed}); keep one")
    return found[0]


def check(context: Context, target: Target, mgmt_host: str) -> str:
    """Read-only: nothing of the node may exist, and Proxmox must be ready. The template's node.

    A rebuild goes ahead only where the node is gone: no VM by its name
    anywhere in Proxmox, nothing at its address, and its VMID free. A test
    rebuild leaves the node running and asks the same of the test VM.
    """

    api, settings, out = context.api, context.settings, context.out
    version = api.call("GET", "/version", None)
    out.write(f"  Proxmox VE {version.get('version')} answers; token {settings.token_id}\n")
    resources = api.vms()
    template = find_template(resources, settings.template)
    host = str(template.get("node"))
    #
    # The clone runs on the template's host, whichever host answers the API
    # (26-11-04). A host the token cannot see is said, not taken as up.
    #
    state = api.host_state(host)
    if state is not None and state != "online":
        raise Stop(
            f"the template's host {host} is {state}; move the template to a running host "
            "(README: If the template's host is down)"
        )
    seen = "" if state else " (the token cannot see that host's state)"
    out.write(f"  template {template.get('vmid')} {template.get('name')} on {host}{seen}\n")
    named = [vm for vm in resources if same_host(str(vm.get("name") or ""), target.name)]
    if named:
        found = named[0].get("name")
        where = ", ".join(f"{vm.get('vmid')} on {vm.get('node')}" for vm in named)
        raise Stop(f"a VM named {found} exists ({where}); remove it in Proxmox first")
    if any(vm.get("vmid") == target.vmid for vm in resources):
        raise Stop(f"VMID {target.vmid} is taken; remove that VM in Proxmox first, or give --vmid")
    out.write(f"  no VM named {target.name}, and VMID {target.vmid} is free\n")
    if target.test is None:
        address = context.resolving(mgmt_host)
        if context.alive(address):
            raise Stop(f"{target.node} answers at {address}: the node is running")
        out.write(f"  {target.node} ({address}) does not answer\n")
    temporary = str(target.temporary.ip)
    if context.alive(temporary):
        raise Stop(f"the temporary address {temporary} answers; another machine holds it")
    out.write(f"  the temporary address {temporary} is free\n")
    for path, wanted in (
        (f"/pool/{settings.pool}", POOL_PRIVILEGES),
        (f"/vms/{template.get('vmid')}", TEMPLATE_PRIVILEGES),
        (f"/storage/{settings.storage}", STORAGE_PRIVILEGES),
    ):
        granted = api.call("GET", "/access/permissions", {"path": path}) or {}
        missing = _missing(granted.get(path, {}), wanted)
        if missing:
            raise Stop(f"the token lacks {', '.join(missing)} on {path}")
    out.write(
        f"  the token's privileges on the pool, the template and {settings.storage} suffice\n"
    )
    return str(settings.target_node or template["node"])


def clone(context: Context, target: Target, node: str) -> None:
    api, settings, out = context.api, context.settings, context.out
    template = find_template(api.vms(), settings.template)
    source = str(template["node"])
    out.write(f"cloning template {template.get('vmid')} to VM {target.vmid} ({target.name})\n")
    parameters: dict[str, Any] = {
        "newid": target.vmid,
        "name": target.name,
        "pool": settings.pool,
        "full": 1,
        "storage": settings.storage,
    }
    if node != source:
        parameters["target"] = node
    upid = api.call("POST", f"/nodes/{source}/qemu/{template.get('vmid')}/clone", parameters)
    api.wait_task(source, str(upid), "the clone")
    config = api.config(node, target.vmid)
    net0 = str(config.get("net0", ""))
    if not net0:
        raise Stop(f"VM {target.vmid} has no net0")
    parts = [part for part in net0.split(",") if not part.startswith("bridge=")]
    change: dict[str, Any] = {
        "net0": ",".join([*parts, f"bridge={target.bridge}"]),
        "ipconfig0": f"ip={target.temporary},gw={target.gateway}",
        # Proxmox's default upgrades every package on the first boot: some
        # 90 s before the restore, and apt busy when the VM is shut down.
        # The node is updated as the others are, after it runs.
        "ciupgrade": 0,
    }
    for key, value in (
        ("nameserver", settings.nameserver),
        ("searchdomain", settings.searchdomain),
        ("cores", settings.cores),
        ("memory", settings.memory_mb),
    ):
        if value is not None:
            change[key] = value
    api.call("PUT", f"/nodes/{node}/qemu/{target.vmid}/config", change)
    out.write(f"  bridge {target.bridge}, temporary address {target.temporary}\n")
    upid = api.call("POST", f"/nodes/{node}/qemu/{target.vmid}/status/start", {})
    api.wait_task(node, str(upid), "the start")
    out.write("  started; waiting for the guest agent\n")
    api.agent_up(node, target.vmid)
    api.cloud_init_done(node, target.vmid)
    out.write("  cloud-init finished\n")


def restore(context: Context, target: Target, node: str, archive: str) -> str:
    """The restore, through the installed command. The node's own address, as its result has it."""

    out = context.out
    name = target.name if target.test is not None else target.node
    prepare = [
        RESTORE,
        "prepare",
        "-c",
        target.cluster,
        "--node",
        target.node,
        "--archive",
        archive,
        "--target",
        str(target.temporary.ip),
    ]
    if target.test is not None and target.test_vip is not None:
        prepare += [
            "--test",
            "--test-hostname",
            target.name,
            "--test-address",
            str(target.test),
            "--test-vip",
            target.test_vip,
        ]
    done = context.runner([*prepare, "--json"])
    if done.returncode != 0:
        raise Stop(f"{RESTORE} prepare: {done.stderr.strip()[-500:]}")
    prepared = json.loads(done.stdout)["result"]
    run = str(prepared["run"])
    out.write(f"run {run}: the one-time key goes in through the guest agent\n")
    try:
        code, stdout, stderr = context.api.execute(node, target.vmid, prepared["paste"] + "\n")
        found = FINGERPRINT.findall(stdout)
        if code != 0 or len(found) != 1:
            raise Stop(
                f"the line did not run in VM {target.vmid} ({code}): {stderr.strip()[-300:]}"
            )
        fingerprint = found[0]
        out.write(f"  host key {fingerprint}, read through the guest agent\n\n")
        out.flush()
        shown = context.runner([RESTORE, "preview", "--run", run, "--fingerprint", fingerprint])
        out.write(shown.stderr)
        out.write(shown.stdout)
        if shown.returncode != 0:
            raise Stop(f"the preview refused: {shown.stderr.strip()[-500:]}")
    except Stop:
        context.runner([RESTORE, "discard", "--run", run])
        out.write(f"run {run} discarded\n")
        raise
    out.write("\n")
    out.flush()
    ran = context.runner([RESTORE, "run", "--run", run, "--confirm", name])
    out.write(ran.stderr)
    out.write(ran.stdout)
    if ran.returncode != 0:
        raise Stop(f"the restore did not finish; {RESTORE} status --run {run} says how it stands")
    answer = json.loads(context.runner([RESTORE, "status", "--run", run, "--json"]).stdout)
    standing = answer.get("result") or {}
    address = (standing.get("result") or {}).get("address")
    if standing.get("outcome") != "done" or not isinstance(address, str):
        raise Stop(f"the run's result has no address: {standing!r}")
    return address


def cloud_init_off(context: Context, target: Target, node: str, address: str) -> None:
    """The template's cloud-init would write its own network again: off, and its drive gone."""

    api, out = context.api, context.out
    code, _, err = api.execute(
        node,
        target.vmid,
        "if [ -d /etc/cloud ]; then touch /etc/cloud/cloud-init.disabled; fi\nsync\n",
    )
    if code != 0:
        raise Stop(f"cloud-init could not be switched off in VM {target.vmid}: {err.strip()}")
    #
    # A clean shutdown, and a stop if it has not happened in two minutes: on a
    # first boot the request through the agent was lost while unattended
    # upgrades held their inhibitor (26-11-03), and nothing was queued after it.
    # The restore is done and synced; a stop loses nothing.
    #
    upid = api.call(
        "POST",
        f"/nodes/{node}/qemu/{target.vmid}/status/shutdown",
        {"timeout": 120, "forceStop": 1},
    )
    api.wait_task(node, str(upid), "the shutdown")
    config = api.config(node, target.vmid)
    drives = [key for key, value in config.items() if "cloudinit" in str(value)]
    deleted = [
        *drives,
        *[key for key in ("ipconfig0", "nameserver", "searchdomain") if key in config],
    ]
    if deleted:
        api.call("PUT", f"/nodes/{node}/qemu/{target.vmid}/config", {"delete": ",".join(deleted)})
    upid = api.call("POST", f"/nodes/{node}/qemu/{target.vmid}/status/start", {})
    api.wait_task(node, str(upid), "the start")
    out.write(f"cloud-init off, {', '.join(deleted) or 'nothing'} removed, VM started again\n")
    _wait_for(context, address)


def _wait_for(context: Context, address: str) -> None:
    waited = 0.0
    while not context.answering(address):
        if waited >= ADDRESS_WAIT:
            raise Stop(f"{address} did not answer on port 22 after the restart")
        context.api.sleep(5.0)
        waited += 5.0
    context.out.write(f"{address} answers on port 22\n")


def main(
    argv: Sequence[str] | None = None,
    *,
    out: TextIO | None = None,
    call: Call | None = None,
    runner: Runner = run_command,
    answering: Callable[[str], bool] = answers,
    resolving: Callable[[str], str] = resolve,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    parser = argparse.ArgumentParser(
        prog="proxmox-node-rebuild",
        description="Rebuild a node on a new Proxmox VM with haprion-node-restore (an example).",
    )
    parser.add_argument("--settings", type=Path, default=DEFAULT_SETTINGS)
    steps = parser.add_subparsers(dest="step", required=True)
    for step in ("check", "run"):
        one = steps.add_parser(step)
        one.add_argument(
            "node",
            help="the node to rebuild: its name, or a short one that fits only it (01 for lb-01)",
        )
        one.add_argument("--test", action="store_true", help="the test VM, address and VIP")
        one.add_argument("--vmid", type=int, help="instead of the settings' VMID")
        if step == "run":
            one.add_argument("--archive", help="instead of the node's latest backup")
    arguments = parser.parse_args(argv)
    stream = out or sys.stdout
    try:
        settings = Settings.load(arguments.settings)
        key, cluster = settings.resolve(arguments.node)
        name, mgmt_host = node_standing(runner, cluster, key)
        target = settings.target(name, test=arguments.test, vmid=arguments.vmid)
        context = Context(
            settings=settings,
            api=Proxmox(call or api_call(settings), sleep=sleep),
            runner=runner,
            out=stream,
            answering=answering,
            resolving=resolving,
        )
        stream.write(f"{target.node} ({target.cluster}) to VM {target.vmid}\n")
        node = check(context, target, mgmt_host)
        archive = getattr(arguments, "archive", None) or latest_archive(
            runner, target.cluster, target.node
        )
        stream.write(f"  backup {archive}\n")
        if arguments.step == "check":
            stream.write("check: OK, nothing was changed\n")
            return 0
        clone(context, target, node)
        address = restore(context, target, node, archive)
        cloud_init_off(context, target, node, address)
        stream.write(f"done: VM {target.vmid} is {target.name}\n")
        return 0
    except Stop as exc:
        stream.write(f"ERROR: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
