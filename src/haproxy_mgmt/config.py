from __future__ import annotations

import ipaddress
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

DEFAULT_POLICY_PATH = Path("/etc/haproxy-manager/runtime-policy.yaml")
MAX_CONFIG_BYTES = 1024 * 1024
CLUSTER_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
NODE_PATH = re.compile(r"^[a-z][a-z0-9_-]{0,62}$")
NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
CERTIFICATE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,254}$")


class ConfigError(ValueError):
    def __init__(self, message: str, *, exit_code: int = 65):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class PathPolicy:
    cluster_file: Path
    config_root: Path
    publish_root: Path
    validation_certs_root: Path
    deploy_identity: DeployIdentity | None = None
    #
    # The shared directory published certificates are distributed from, and the
    # identity that triggers a certificate pull. Both optional for the same
    # reason deploy_identity is: every other command works without them, and a
    # policy file that every command rejected until certificate deployment was
    # configured would be worse than one that says what is missing when it is
    # needed.
    #
    certificate_root: Path | None = None
    cert_deploy_identity: DeployIdentity | None = None
    #
    # The identity that reads node status. Optional for the same reason as the
    # other two, and separate from them on purpose: it is the only one of the
    # three that never changes a node, so it is the one identity a deployment
    # can hand out without handing out the ability to act.
    #
    status_identity: DeployIdentity | None = None
    #
    # Where the backup engine writes each node's state archives, one directory
    # per node. Optional like the others: it is read by one command, and a
    # policy every other command rejected until backups were configured would
    # be worse than one that says what is missing when it is needed.
    #
    backup_root: Path | None = None

    #
    # The systemd timer that takes those backups, so a listing can say whether
    # anything is still producing it. Optional and separate from `backup_root`:
    # an installation can hold archives without this project knowing what puts
    # them there, and that is reported as "no schedule declared" rather than as
    # a missing configuration error.
    #
    backup_timer: str | None = None


@dataclass(frozen=True, slots=True)
class DeployIdentity:
    """Who the manager becomes to reach a node, and with which key.

    Environment-specific, so it lives in configuration and never in code: the
    account name and the key path identify a real installation, and a repository
    that is going to be public must not carry either.

    Optional in the policy. Every other command works without it, and a
    deployment that needs it says exactly what is missing rather than failing on
    a name that was compiled in.
    """

    user: str
    key: Path


@dataclass(frozen=True, slots=True)
class Node:
    name: str
    mgmt_host: str


@dataclass(frozen=True, slots=True)
class Cluster:
    cluster_id: str
    display_name: str
    vip: str
    config_path: Path
    publish_path: Path
    node_path: str
    validation_certs: Path
    default_certificate: str
    certificate_ids: tuple[str, ...]
    trusted_proxy_cidrs: tuple[str, ...]
    nodes: tuple[Node, ...]


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    schema_version: int
    clusters: Mapping[str, Cluster]

    def cluster(self, cluster_id: str) -> Cluster:
        if not CLUSTER_ID.fullmatch(cluster_id):
            raise ConfigError("invalid cluster ID", exit_code=64)
        try:
            return self.clusters[cluster_id]
        except KeyError as exc:
            valid = ", ".join(sorted(self.clusters))
            raise ConfigError(
                f"unknown cluster '{cluster_id}'. Valid clusters: {valid}",
                exit_code=64,
            ) from exc


def _mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ConfigError(f"{location} must be a mapping")
    return value


def _only_keys(value: Mapping[str, Any], allowed: set[str], location: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConfigError(f"{location} contains unknown field(s): {', '.join(unknown)}")


def _required_string(value: Mapping[str, Any], key: str, location: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise ConfigError(f"{location}.{key} must be a non-empty string")
    return result


def _secure_yaml(path: Path, *, require_secure: bool) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ConfigError(f"cannot stat configuration file: {exc}", exit_code=68) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ConfigError("configuration file must be a regular non-symlink", exit_code=68)
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise ConfigError("configuration file exceeds 1 MiB", exit_code=68)
    if require_secure and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022):
        raise ConfigError(
            "configuration file must be root-owned and not group/other-writable",
            exit_code=68,
        )
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read configuration file: {exc}", exit_code=68) from exc
    return _mapping(loaded, str(path))


def _absolute_path(raw: str, location: str) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        raise ConfigError(f"{location} must be absolute")
    return path.resolve(strict=False)


def _under_root(raw: str, root: Path, location: str) -> Path:
    path = _absolute_path(raw, location)
    resolved_root = root.resolve(strict=False)
    if path != resolved_root and resolved_root not in path.parents:
        raise ConfigError(f"{location} escapes its allowed root")
    return path


def _host(value: str, location: str) -> str:
    if len(value) > 253 or any(character.isspace() for character in value):
        raise ConfigError(f"{location} is not a valid management host")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        labels = value.rstrip(".").split(".")
        if not labels or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise ConfigError(f"{location} is not a valid management host") from None
        return value


USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
#
# Deliberately narrower than systemd's own rules: this is the set of names an
# installation of this project can reasonably use, and everything outside it -
# path separators, spaces, template instances - is refused rather than escaped.
# Defined here, where the policy is read, and imported by the code that puts the
# name in an argv, so there is one answer to what a timer name may be.
#
TIMER_UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.timer$")


def _optional_timer(data: Mapping[str, Any], key: str) -> str | None:
    """A systemd timer unit the installation may or may not have declared.

    Checked here as well as where it is used. The name reaches an argv, and a
    policy file being root-owned makes it trusted, not well-formed.
    """

    raw = data.get(key)
    if raw is None:
        return None
    name = _required_string(data, key, "runtime policy")
    if not TIMER_UNIT.fullmatch(name):
        raise ConfigError(f"runtime policy {key} is not a systemd timer name")
    return name


def _optional_root(data: Mapping[str, Any], key: str) -> Path | None:
    """An absolute root the installation may or may not have declared."""

    raw = data.get(key)
    if raw is None:
        return None
    return _absolute_path(_required_string(data, key, "runtime policy"), key)


def _deploy_identity(data: Mapping[str, Any], key: str) -> DeployIdentity | None:
    """One trigger identity, when the installation has declared it.

    Absent is a valid policy: only the path that uses it needs it, and requiring
    it everywhere would mean a policy file that every other command rejects
    until it is updated.

    Config deployment and certificate deployment have separate identities on
    purpose - that is how the installation is built, and it is what lets a key
    that can push configuration be unable to push certificates.
    """

    raw = data.get(key)
    if raw is None:
        return None

    location = f"runtime policy.{key}"
    entry = _mapping(raw, location)
    _only_keys(entry, {"user", "key"}, location)
    user = _required_string(entry, "user", location)
    if not USERNAME.fullmatch(user):
        raise ConfigError(f"{location}.user is not a valid account name")
    return DeployIdentity(
        user=user,
        key=_absolute_path(_required_string(entry, "key", location), f"{location}.key"),
    )


def load_policy(path: Path = DEFAULT_POLICY_PATH, *, require_secure: bool = True) -> PathPolicy:
    data = _secure_yaml(path, require_secure=require_secure)
    _only_keys(
        data,
        {
            "schema_version",
            "cluster_file",
            "config_root",
            "publish_root",
            "validation_certs_root",
            "deploy_identity",
            "certificate_root",
            "cert_deploy_identity",
            "status_identity",
            "backup_root",
            "backup_timer",
        },
        "runtime policy",
    )
    schema_version = data.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise ConfigError("runtime policy schema_version must be 1")
    return PathPolicy(
        cluster_file=_absolute_path(
            _required_string(data, "cluster_file", "runtime policy"), "cluster_file"
        ),
        config_root=_absolute_path(
            _required_string(data, "config_root", "runtime policy"), "config_root"
        ),
        publish_root=_absolute_path(
            _required_string(data, "publish_root", "runtime policy"), "publish_root"
        ),
        validation_certs_root=_absolute_path(
            _required_string(data, "validation_certs_root", "runtime policy"),
            "validation_certs_root",
        ),
        deploy_identity=_deploy_identity(data, "deploy_identity"),
        certificate_root=_optional_root(data, "certificate_root"),
        cert_deploy_identity=_deploy_identity(data, "cert_deploy_identity"),
        status_identity=_deploy_identity(data, "status_identity"),
        backup_root=_optional_root(data, "backup_root"),
        backup_timer=_optional_timer(data, "backup_timer"),
    )


def load_runtime_config(policy: PathPolicy, *, require_secure: bool = True) -> RuntimeConfig:
    data = _secure_yaml(policy.cluster_file, require_secure=require_secure)
    _only_keys(data, {"schema_version", "clusters"}, "cluster configuration")
    schema_version = data.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise ConfigError("cluster configuration schema_version must be 1")
    raw_clusters = _mapping(data.get("clusters"), "clusters")
    if not raw_clusters:
        raise ConfigError("clusters must not be empty")

    clusters: dict[str, Cluster] = {}
    for cluster_id, raw_value in raw_clusters.items():
        if not CLUSTER_ID.fullmatch(cluster_id):
            raise ConfigError(f"invalid cluster ID in configuration: {cluster_id!r}")
        location = f"clusters.{cluster_id}"
        raw = _mapping(raw_value, location)
        _only_keys(
            raw,
            {
                "display_name",
                "vip",
                "config_path",
                "publish_path",
                "node_path",
                "validation_certs",
                "default_certificate",
                "certificate_ids",
                "trusted_proxy_cidrs",
                "nodes",
            },
            location,
        )
        vip = _required_string(raw, "vip", location)
        try:
            ipaddress.ip_address(vip)
        except ValueError as exc:
            raise ConfigError(f"{location}.vip must be an IP address") from exc
        node_path = _required_string(raw, "node_path", location)
        if not NODE_PATH.fullmatch(node_path):
            raise ConfigError(f"{location}.node_path is invalid")

        raw_certificates = raw.get("certificate_ids")
        if not isinstance(raw_certificates, list) or not raw_certificates:
            raise ConfigError(f"{location}.certificate_ids must be a non-empty list")
        certificate_ids = tuple(raw_certificates)
        if any(
            not isinstance(item, str) or not CERTIFICATE_ID.fullmatch(item)
            for item in certificate_ids
        ):
            raise ConfigError(f"{location}.certificate_ids contains an invalid ID")
        if len(set(certificate_ids)) != len(certificate_ids):
            raise ConfigError(f"{location}.certificate_ids contains duplicates")
        default_certificate = _required_string(raw, "default_certificate", location)
        if default_certificate not in certificate_ids:
            raise ConfigError(f"{location}.default_certificate is not allowlisted")

        raw_cidrs = raw.get("trusted_proxy_cidrs", [])
        if not isinstance(raw_cidrs, list):
            raise ConfigError(f"{location}.trusted_proxy_cidrs must be a list")
        cidrs: list[str] = []
        for item in raw_cidrs:
            if not isinstance(item, str):
                raise ConfigError(f"{location}.trusted_proxy_cidrs contains a non-string")
            try:
                network = ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise ConfigError(
                    f"{location}.trusted_proxy_cidrs contains an invalid CIDR"
                ) from exc
            if network.prefixlen == 0:
                raise ConfigError(
                    f"{location}.trusted_proxy_cidrs may not trust an entire address family"
                )
            cidrs.append(str(network))

        raw_nodes = raw.get("nodes")
        if not isinstance(raw_nodes, list) or len(raw_nodes) != 2:
            raise ConfigError(f"{location}.nodes must contain exactly two nodes")
        nodes: list[Node] = []
        for index, raw_node_value in enumerate(raw_nodes):
            node_location = f"{location}.nodes[{index}]"
            raw_node = _mapping(raw_node_value, node_location)
            _only_keys(raw_node, {"name", "mgmt_host"}, node_location)
            name = _required_string(raw_node, "name", node_location)
            if not NAME.fullmatch(name):
                raise ConfigError(f"{node_location}.name is invalid")
            nodes.append(
                Node(
                    name=name,
                    mgmt_host=_host(
                        _required_string(raw_node, "mgmt_host", node_location),
                        f"{node_location}.mgmt_host",
                    ),
                )
            )
        if len({node.name for node in nodes}) != 2 or len({node.mgmt_host for node in nodes}) != 2:
            raise ConfigError(f"{location}.nodes must have unique names and management hosts")

        clusters[cluster_id] = Cluster(
            cluster_id=cluster_id,
            display_name=_required_string(raw, "display_name", location),
            vip=vip,
            config_path=_under_root(
                _required_string(raw, "config_path", location),
                policy.config_root,
                f"{location}.config_path",
            ),
            publish_path=_under_root(
                _required_string(raw, "publish_path", location),
                policy.publish_root,
                f"{location}.publish_path",
            ),
            node_path=node_path,
            validation_certs=_under_root(
                _required_string(raw, "validation_certs", location),
                policy.validation_certs_root,
                f"{location}.validation_certs",
            ),
            default_certificate=default_certificate,
            certificate_ids=certificate_ids,
            trusted_proxy_cidrs=tuple(cidrs),
            nodes=tuple(nodes),
        )
    return RuntimeConfig(schema_version=1, clusters=clusters)
