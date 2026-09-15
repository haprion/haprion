from __future__ import annotations

import ipaddress
import re
import stat
from collections.abc import Mapping
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

DEFAULT_POLICY_PATH = Path("/etc/haproxy-manager/runtime-policy.yaml")
MAX_CONFIG_BYTES = 1024 * 1024
CLUSTER_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")

#
# What a cluster's single VIP is called when it has never had to be named.
#
DEFAULT_VIP = "main"

#
# The TLS policies a VIP may name. Only the names live here; what each one
# means in HAProxy syntax lives in the generator, which is the module that
# speaks that language. A test holds the two together, since a name this file
# accepts and the generator cannot write would be refused on the node after a
# publish reported success.
#
#   intermediate  TLS 1.2 and 1.3, the cipher set Mozilla calls intermediate.
#                 What a public site serves unless it knows every client.
#   modern        TLS 1.3 only. Everything current speaks it; nothing older
#                 gets a handshake at all.
#   tls12only     TLS 1.2 alone. Not a Mozilla profile and deliberately not
#                 named as though it were: it is a ceiling for one broken
#                 client, and it turns 1.3 off to get there.
#
TLS_POLICY_NAMES = ("intermediate", "modern", "tls12only")

#
# How long the abuse counters look back. Seconds or minutes: the window is a
# burst, and HAProxy keeps one bucket per source for it.
#
ABUSE_WINDOW = re.compile(r"^[1-9][0-9]{0,3}(s|m)$")
DEFAULT_ABUSE_WINDOW = "10s"
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
    # The identity that asks a node to try a health check. Its own, and not the
    # status identity, although neither changes a node: status reads what the
    # node already knows, while this one makes the node open a connection to an
    # address the caller names. That is a different thing to hand out, so it is
    # a different key to hand out - and an installation that has no use for it
    # simply does not configure one.
    #
    probe_identity: DeployIdentity | None = None
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

    #
    # The certificate registry (B135): which certificates exist, where each
    # comes from, and which clusters and receivers it goes to. Optional during
    # the transition - an installation without one keeps its allowlist in
    # `clusters.yaml` - and once declared, the allowlist must have moved.
    #
    certificate_registry: Path | None = None

    #
    # How this installation answers ACME challenges (Phase 11, C3). Each
    # method needs one installation-specific thing that the issue helper must
    # never take from its caller: the credential file for DNS-01, the webroot
    # for HTTP-01. A method whose setting is absent is refused by name.
    #
    # `certbot` is the binary itself (P1): the locked environment's
    # `/opt/haproxy-certbot/current/venv/bin/certbot` once that is installed,
    # the distribution's `/usr/bin/certbot` until then. Left out, the helper
    # uses the distribution's; it never takes the path from its caller.
    #
    # `dns_profiles` (P3, B146) is where the DNS provider credentials the web
    # interface collects end up, and which private keys may open them: the
    # directory the profile helper materialises credential files into, and
    # the key files the installation created. More than one key is listed
    # only while a key is being replaced; the web always seals against the
    # current public key, and a profile sealed against a key no longer listed
    # cannot be applied until it is re-entered.
    #
    acme: AcmePolicy | None = None
    ndes: NdesPolicy | None = None


@dataclass(frozen=True, slots=True)
class AcmePolicy:
    dns_cloudflare_credentials: Path | None
    webroot: Path | None
    certbot: Path | None
    dns_profiles: DnsProfilesPolicy | None


@dataclass(frozen=True, slots=True)
class DnsProfilesPolicy:
    directory: Path
    private_keys: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class NdesPolicy:
    endpoint: str
    tls_ca: Path
    issuing_ca: Path
    client_root: Path
    state_root: Path
    profiles: DnsProfilesPolicy


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
class Vip:
    """One address traffic arrives on, and the address it leaves from.

    Two things that are always decided together, so they are one object.
    `address` is what a generated frontend binds - a virtual IP carried by
    whichever node currently owns it - and `source` is the address HAProxy
    connects to backends from, which an ADC calls a SNIP. A pair of firewall
    rules is usually written against exactly these two, which is why pairing
    them here rather than letting an object pick them separately removes a way
    to get it wrong.

    `source` is this VIP's default and not a rule: HAProxy takes the source
    address per backend, so any object may name a different one from the
    cluster's `sources` table where it has a reason to. Pairing them here is
    about what happens when nobody says otherwise, which is the case that
    should need no words.

    `source` is optional. Without it HAProxy connects from whatever address the
    routing table picks, which is the right answer on a host with one network.
    """

    name: str
    address: str
    source: str | None = None
    tls_policy: str | None = None
    """Which TLS versions and ciphers this listener accepts. None inherits.

    Named rather than written out, because a cipher string is raw OpenSSL
    syntax and this project has decided not to have a field somebody pastes
    raw syntax into. `TLS_POLICIES` in the generator holds what each name
    means.

    None means the listener takes whatever `core/` sets through
    `ssl-default-bind-*`, which is what every cluster does today. It is left
    that way rather than defaulted here because a policy written on the bind
    line overrides `core/` in both directions: a cluster whose `core/` is
    stricter than the named policy would be quietly loosened by a default
    nobody asked for.
    """


@dataclass(frozen=True, slots=True)
class UnknownHost:
    """What a request for a name no object claims is answered with.

    Without this HAProxy answers 503, because no rule matched and there is no
    fallback - a defensible outcome but not a chosen one, and one that reads to
    a visitor as "the site is broken" rather than "there is no site here".
    Exactly one of the two fields is set.
    """

    status: int | None = None
    redirect: str | None = None


@dataclass(frozen=True, slots=True)
class AbuseProtection:
    """A brake on traffic that is obviously not a visitor.

    Deliberately a brake and not a ban list. HAProxy keeps these counters in
    the process, and a reload starts a new one - measured on this machine, an
    address added to a running process was gone after a reload. Since a publish
    reloads, a ban measured in hours would quietly become a ban measured in
    "until somebody edits a site". A brake that releases on its own when the
    traffic stops is honest about what it is.

    Counted per source address over a window. Two independent thresholds
    because two different things look nothing alike: a flood is many requests
    that each look ordinary, and a scanner is few requests that are almost all
    errors.

    None means nothing is generated at all.
    """

    window: str
    max_requests: int | None = None
    max_errors: int | None = None
    max_new_connections: int | None = None
    """The tcp threshold: new connections per source over the window.

    Separate from the two above because a raw connection has no request and no
    status to count. It is the only question that can be asked before a byte is
    forwarded, and it is asked at connection time.
    """


@dataclass(frozen=True, slots=True)
class Cluster:
    cluster_id: str
    display_name: str
    vip: str
    #
    # How a carried address is written into the generated keepalived list.
    # None means a bare address, which keepalived reads as /32 on the
    # vrrp_instance's own interface.
    #
    address_prefix: int | None
    address_interface: str | None
    vips: Mapping[str, Vip]
    default_vip: str
    resolvers: str | None
    sources: Mapping[str, str]
    networks: Mapping[str, tuple[str, ...]]
    unknown_host: UnknownHost | None
    config_path: Path
    publish_path: Path
    node_path: str
    validation_certs: Path
    default_certificate: str
    certificate_ids: tuple[str, ...]
    trusted_proxy_cidrs: tuple[str, ...]
    abuse_protection: AbuseProtection | None
    nodes: tuple[Node, ...]
    traffic_logging: bool = False

    def network(self) -> Network:
        """This cluster's network description, from the repository if it has one.

        The repository wins when the file exists, because that is where the
        description is edited once it has moved. An installation that has not
        moved keeps answering from `clusters.yaml`, and neither has to know
        which of the two the other is doing.
        """

        found = load_network(self.config_path, vip=self.vip)
        if found is not None:
            return found
        return Network(
            vips=self.vips,
            default_vip=self.default_vip,
            sources=self.sources,
            networks=self.networks,
        )


#
# The certificate registry, B135. One file, root-owned, beside `clusters.yaml`.
#
# A certificate is a source, an ID and a set of targets. A receiver is a
# registered place certificates are published to, other than a cluster: a
# directory under the distribution root and the account whose key fetches it.
# Clusters are targets too, but they are described in `clusters.yaml` and only
# named here.
#
# The registry replaces the per-cluster `certificate_ids` allowlist rather than
# sitting beside it: with a registry, a cluster's list is derived from the
# certificates that name it, and the allowlist in `clusters.yaml` is refused so
# there is one answer to "which certificates does this cluster carry".
#
# What root decides is which receivers exist - an account, a key and a
# directory are what let anyone fetch key material at all. Which certificate
# goes to which already-trusted receiver is what the interface may change,
# through a helper that accepts only registered targets.
#
SOURCE_KINDS = frozenset({"acme", "import"})
RECEIVER_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


@dataclass(frozen=True, slots=True)
class CertificateSource:
    kind: str
    #
    # The certbot lineage for `acme`. Defaults to the certificate ID, which is
    # what a certificate issued from the interface gets; stated explicitly
    # where an existing lineage was named before the ID convention existed.
    #
    lineage: str | None
    dns_profile: str | None = None
    #
    # For `import`: the NDES profile whose challenge enrolled the material,
    # when the manager enrolled it itself. Absent for material imported by
    # hand. Named so the interface can say where it came from and the profile
    # cannot be removed from under a certificate that still reads it.
    #
    ndes_profile: str | None = None


@dataclass(frozen=True, slots=True)
class Receiver:
    receiver_id: str
    path: Path
    owner: str


@dataclass(frozen=True, slots=True)
class RegisteredCertificate:
    certificate_id: str
    source: CertificateSource
    clusters: tuple[str, ...]
    receivers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Registry:
    receivers: Mapping[str, Receiver]
    certificates: Mapping[str, RegisteredCertificate]

    def for_cluster(self, cluster_id: str) -> tuple[str, ...]:
        """The certificate IDs that name this cluster, in registry order."""

        return tuple(
            entry.certificate_id
            for entry in self.certificates.values()
            if cluster_id in entry.clusters
        )


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    schema_version: int
    clusters: Mapping[str, Cluster]
    registry: Registry | None = None

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


def _only_keys(value: Mapping[str, Any], allowed: AbstractSet[str], location: str) -> None:
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


def _address(value: Any, location: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{location} must be an IP address")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigError(f"{location} must be an IP address") from exc
    return value


#
# A Linux interface name. Fifteen characters is the kernel's own limit, and the
# character class is what `ip link` accepts without quoting.
#
INTERFACE = re.compile(r"^[A-Za-z0-9._-]{1,15}$")


def _address_form(raw: Mapping[str, Any], location: str) -> tuple[int | None, str | None]:
    """How this cluster's nodes write an address they carry.

    Only the generated keepalived address list reads these. They are here and
    not in `managed/network.yaml` on purpose: a prefix length is a statement
    about the network the pair sits on, not about which addresses the cluster
    serves, and getting it wrong changes routing rather than which site
    answers. `clusters.yaml` is root-owned and the interface cannot write it,
    so this stays with the person who set the nodes up.

    Both are optional, and absent means what keepalived does with a bare
    address: /32, on the vrrp_instance's own interface. That is right for a
    cluster written that way and wrong for one written any other way, which is
    exactly why it is stated rather than assumed.
    """

    prefix = raw.get("address_prefix")
    if prefix is not None and (
        not isinstance(prefix, int) or isinstance(prefix, bool) or not 1 <= prefix <= 128
    ):
        raise ConfigError(f"{location}.address_prefix must be a prefix length between 1 and 128")
    interface = raw.get("address_interface")
    if interface is not None and (
        not isinstance(interface, str) or not INTERFACE.fullmatch(interface)
    ):
        raise ConfigError(f"{location}.address_interface must be an interface name")
    return prefix, interface


def _tls_policy(value: Any, location: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in TLS_POLICY_NAMES:
        raise ConfigError(f"{location} must be one of: {', '.join(TLS_POLICY_NAMES)}")
    return value


def _vips(raw: Mapping[str, Any], vip: str, location: str) -> tuple[Mapping[str, Vip], str]:
    """The addresses this cluster serves on, and which one an object gets by
    default.

    Optional, and absent it means what the deployments that exist today mean: a
    single virtual IP, the one whose ownership `deploy` already watches, with no
    separate source address. A cluster only needs to name its addresses once it
    has more than one, which is the case this exists for - and until then
    nothing has to be written down twice.
    """

    raw_vips = raw.get("vips")
    if raw_vips is None:
        single = Vip(name=DEFAULT_VIP, address=vip)
        default = (
            _required_string(raw, "default_vip", location) if "default_vip" in raw else DEFAULT_VIP
        )
        if default != DEFAULT_VIP:
            raise ConfigError(f"{location}.default_vip names no VIP in this cluster: {default}")
        return {DEFAULT_VIP: single}, DEFAULT_VIP

    entries = _mapping(raw_vips, f"{location}.vips")
    if not entries:
        raise ConfigError(f"{location}.vips must name at least one VIP")

    vips: dict[str, Vip] = {}
    for name, value in entries.items():
        where = f"{location}.vips.{name}"
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ConfigError(f"{where} is not a usable VIP name")
        entry = _mapping(value, where)
        _only_keys(entry, {"address", "source", "tls"}, where)
        source = entry.get("source")
        vips[name] = Vip(
            name=name,
            address=_address(entry.get("address"), f"{where}.address"),
            source=None if source is None else _address(source, f"{where}.source"),
            tls_policy=_tls_policy(entry.get("tls"), f"{where}.tls"),
        )

    addresses = [entry.address for entry in vips.values()]
    if len(set(addresses)) != len(addresses):
        #
        # Two names for one address is two frontends binding the same port on
        # the same interface. HAProxy validates that configuration and then
        # refuses to start, on the node, after a publish reported success.
        #
        raise ConfigError(f"{location}.vips gives one address two names")

    if "default_vip" in raw:
        default = _required_string(raw, "default_vip", location)
    elif len(vips) == 1:
        default = next(iter(vips))
    else:
        raise ConfigError(
            f"{location}.default_vip is required when the cluster names more than one VIP"
        )
    if default not in vips:
        raise ConfigError(f"{location}.default_vip names no VIP in this cluster: {default}")
    return vips, default


def _sources(raw: Mapping[str, Any], location: str) -> Mapping[str, str]:
    """Named source addresses an object may connect out from.

    Separate from the VIP table because the two are not actually locked
    together: HAProxy takes the source address per backend, so a site may leave
    on a different address than the one it arrived on. Most never do, which is
    why each VIP still carries a default - this table is for the exception, and
    an exception should have to be named.
    """

    entries = raw.get("sources")
    if entries is None:
        return {}
    sources: dict[str, str] = {}
    for name, value in _mapping(entries, f"{location}.sources").items():
        where = f"{location}.sources.{name}"
        if not NAME.fullmatch(name):
            raise ConfigError(f"{where} is not a usable source name")
        sources[name] = _address(value, where)
    return sources


def _networks(raw: Mapping[str, Any], location: str) -> Mapping[str, tuple[str, ...]]:
    """Named groups of addresses an object may be restricted to.

    Named rather than written into the object, for the same reason a VIP is:
    the addresses of an office or a VPN pool are environment values, and an
    object that named them directly would mean something different in every
    cluster it was published to.
    """

    entries = raw.get("networks")
    if entries is None:
        return {}
    networks: dict[str, tuple[str, ...]] = {}
    for name, value in _mapping(entries, f"{location}.networks").items():
        where = f"{location}.networks.{name}"
        if not NAME.fullmatch(name):
            raise ConfigError(f"{where} is not a usable network name")
        if not isinstance(value, list) or not value:
            raise ConfigError(f"{where} must list at least one CIDR")
        members: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ConfigError(f"{where} contains a non-string")
            try:
                network = ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise ConfigError(f"{where} contains an invalid CIDR: {item}") from exc
            if network.prefixlen == 0:
                #
                # A group that means "everywhere" is an allowlist that allows
                # everything, which is worse than no allowlist: it reads as a
                # restriction and enforces nothing.
                #
                raise ConfigError(f"{where} may not name an entire address family")
            members.append(str(network))
        networks[name] = tuple(members)
    return networks


#
# The network description as a cluster repository carries it.
#
# The same three tables the engine's own configuration used to hold, moved to
# where the application already writes: `managed/`, under review, versioning
# and revert. What stays behind in `clusters.yaml` is what describes the
# machine rather than what is published on it - paths, identities, keys, the
# resolvers section, and the `vip` line `deploy` checks ownership against. A
# control the interface can rewrite is not a control, which is the whole
# reason that one line does not move.
#
# The certificate allowlist used to be on that list. It moved to the
# certificate registry (B135) with the control one step up: root registers
# receivers, the interface chooses among them.
#
NETWORK_FILE = Path("managed/network.yaml")
NETWORK_KEYS = {"vips", "default_vip", "sources", "networks"}


@dataclass(frozen=True, slots=True)
class Network:
    """Where traffic arrives, where it leaves from, and who may reach it."""

    vips: Mapping[str, Vip]
    default_vip: str
    sources: Mapping[str, str]
    networks: Mapping[str, tuple[str, ...]]
    #
    # Whether this came from the repository or from the fallback. Not a detail:
    # only a description that lives in the repository can be edited through the
    # publish path, so a reader that offers to edit one has to know which it is
    # looking at. A derived table can be shown and never changed.
    #
    from_repository: bool = False


def parse_network(
    raw: Mapping[str, Any], *, vip: str, location: str, from_repository: bool = False
) -> Network:
    """One network description, from wherever it was read.

    `vip` is the cluster's ownership address, and it is only a fallback: a
    description that names no VIP table means the single-address deployment
    that address already describes. Passing it here rather than reading it
    from the description is deliberate - the repository may not name it, and
    must not be able to change it.
    """

    _only_keys(raw, NETWORK_KEYS, location)
    vips, default_vip = _vips(raw, vip, location)
    return Network(
        vips=vips,
        default_vip=default_vip,
        sources=_sources(raw, location),
        networks=_networks(raw, location),
        from_repository=from_repository,
    )


def load_network(config_path: Path, *, vip: str) -> Network | None:
    """The cluster repository's network description, or None if it has none.

    Read with `require_secure=False`, and that is the one real difference from
    every other configuration this module reads. `clusters.yaml` must be
    root-owned because it decides what the engine may do; this file is owned by
    the application, group-writable by design, and describes only what gets
    published. It is therefore untrusted input in a way the other is not -
    which changes nothing about how strictly it is validated, and everything
    about who is allowed to have written it.

    An absent file is not an error. Installations that predate the move keep
    their tables in `clusters.yaml`, and the caller falls back to those.
    """

    path = config_path / NETWORK_FILE
    if not path.exists():
        return None
    # Kept local rather than importing ``managed_network`` at module import:
    # that module uses the Network type and parser defined above.  The delayed
    # import preserves one parser for the repository file and for a document
    # submitted through the managed-publish boundary without a circular import.
    from haproxy_mgmt.managed_network import load_mapping

    return load_mapping(
        _secure_yaml(path, require_secure=False), ownership_vip=vip, location=str(path)
    )


def _unknown_host(value: Any, location: str) -> UnknownHost | None:
    if value is None:
        return None
    data = _mapping(value, location)
    _only_keys(data, {"status", "redirect"}, location)
    status = data.get("status")
    redirect = data.get("redirect")
    if (status is None) == (redirect is None):
        raise ConfigError(f"{location} must set exactly one of status or redirect")
    if status is not None:
        if not isinstance(status, int) or isinstance(status, bool) or not 200 <= status <= 599:
            raise ConfigError(f"{location}.status must be an HTTP status code")
        return UnknownHost(status=status)
    if not isinstance(redirect, str) or not redirect.startswith(("http://", "https://")):
        raise ConfigError(f"{location}.redirect must be an absolute http or https URL")
    if any(character in redirect for character in (" ", '"', "\\", "\r", "\n")):
        raise ConfigError(f"{location}.redirect may not contain spaces, quotes or line breaks")
    return UnknownHost(redirect=redirect)


def _abuse_protection(value: Any, location: str) -> AbuseProtection | None:
    if value is None:
        return None
    data = _mapping(value, location)
    _only_keys(data, {"window", "max_requests", "max_errors", "max_new_connections"}, location)
    window = data.get("window", DEFAULT_ABUSE_WINDOW)
    if not isinstance(window, str) or not ABUSE_WINDOW.fullmatch(window):
        raise ConfigError(f"{location}.window must be a duration such as 10s")

    thresholds: dict[str, int | None] = {}
    for key in ("max_requests", "max_errors", "max_new_connections"):
        limit = data.get(key)
        if limit is not None and (
            not isinstance(limit, int) or isinstance(limit, bool) or limit < 1
        ):
            raise ConfigError(f"{location}.{key} must be a count of at least 1")
        thresholds[key] = limit
    #
    # A section that sets no threshold would generate a counter nobody reads:
    # the table would fill, the file would grow, and nothing would ever be
    # refused. Refused rather than treated as off, because writing the section
    # is somebody saying they want the protection.
    #
    if not any(thresholds.values()):
        raise ConfigError(
            f"{location} must set at least one of max_requests, max_errors or max_new_connections"
        )

    return AbuseProtection(
        window=window,
        max_requests=thresholds["max_requests"],
        max_errors=thresholds["max_errors"],
        max_new_connections=thresholds["max_new_connections"],
    )


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
            "probe_identity",
            "backup_root",
            "backup_timer",
            "certificate_registry",
            "acme",
            "ndes",
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
        probe_identity=_deploy_identity(data, "probe_identity"),
        backup_root=_optional_root(data, "backup_root"),
        backup_timer=_optional_timer(data, "backup_timer"),
        certificate_registry=_optional_root(data, "certificate_registry"),
        acme=_acme_policy(data),
        ndes=_ndes_policy(data),
    )


def _ndes_policy(data: Mapping[str, Any]) -> NdesPolicy | None:
    raw = data.get("ndes")
    if raw is None:
        return None
    location = "runtime policy.ndes"
    entry = _mapping(raw, location)
    _only_keys(
        entry,
        {"endpoint", "tls_ca", "issuing_ca", "client_root", "state_root", "profiles"},
        location,
    )
    from haproxy_mgmt.dns_profiles import ProfileError
    from haproxy_mgmt.ndes_profiles import check_endpoint

    try:
        endpoint = check_endpoint(_required_string(entry, "endpoint", location))
    except ProfileError:
        raise ConfigError(f"{location}.endpoint must be a valid HTTPS URL") from None
    profiles = _dns_profiles_policy({"dns_profiles": entry.get("profiles")}, f"{location}.profiles")
    if profiles is None:
        raise ConfigError(f"{location}.profiles must be configured")
    return NdesPolicy(
        endpoint=endpoint,
        tls_ca=_absolute_path(_required_string(entry, "tls_ca", location), f"{location}.tls_ca"),
        issuing_ca=_absolute_path(
            _required_string(entry, "issuing_ca", location), f"{location}.issuing_ca"
        ),
        client_root=_absolute_path(
            _required_string(entry, "client_root", location), f"{location}.client_root"
        ),
        state_root=_absolute_path(
            _required_string(entry, "state_root", location), f"{location}.state_root"
        ),
        profiles=profiles,
    )


def _acme_policy(data: Mapping[str, Any]) -> AcmePolicy | None:
    raw = data.get("acme")
    if raw is None:
        return None
    location = "runtime policy.acme"
    entry = _mapping(raw, location)
    _only_keys(
        entry, {"dns_cloudflare_credentials", "webroot", "certbot", "dns_profiles"}, location
    )
    return AcmePolicy(
        dns_cloudflare_credentials=_optional_root(entry, "dns_cloudflare_credentials"),
        webroot=_optional_root(entry, "webroot"),
        certbot=_optional_root(entry, "certbot"),
        dns_profiles=_dns_profiles_policy(entry, f"{location}.dns_profiles"),
    )


def _dns_profiles_policy(acme: Mapping[str, Any], location: str) -> DnsProfilesPolicy | None:
    raw = acme.get("dns_profiles")
    if raw is None:
        return None
    entry = _mapping(raw, location)
    _only_keys(entry, {"directory", "private_keys"}, location)
    keys_raw = entry.get("private_keys")
    if not isinstance(keys_raw, list) or not keys_raw:
        raise ConfigError(f"{location}.private_keys must be a non-empty list")
    private_keys: list[Path] = []
    for index, item in enumerate(keys_raw):
        if not isinstance(item, str) or not item:
            raise ConfigError(f"{location}.private_keys[{index}] must be a non-empty string")
        private_keys.append(_absolute_path(item, f"{location}.private_keys[{index}]"))
    if len(set(private_keys)) != len(private_keys):
        raise ConfigError(f"{location}.private_keys lists a key twice")
    return DnsProfilesPolicy(
        directory=_absolute_path(
            _required_string(entry, "directory", location), f"{location}.directory"
        ),
        private_keys=tuple(private_keys),
    )


def load_registry(path: Path, *, require_secure: bool = True) -> Registry:
    """The certificate registry, checked the way the cluster file is.

    Cross-references to clusters are checked by `load_runtime_config`, which
    is the only place both files are known.
    """

    data = _secure_yaml(path, require_secure=require_secure)
    _only_keys(data, {"schema_version", "receivers", "certificates"}, "certificate registry")
    schema_version = data.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise ConfigError("certificate registry schema_version must be 1")

    receivers: dict[str, Receiver] = {}
    for receiver_id, raw_value in _mapping(data.get("receivers", {}), "receivers").items():
        if not RECEIVER_ID.fullmatch(receiver_id):
            raise ConfigError(f"invalid receiver ID in certificate registry: {receiver_id!r}")
        location = f"receivers.{receiver_id}"
        raw = _mapping(raw_value, location)
        _only_keys(raw, {"path", "owner"}, location)
        owner = _required_string(raw, "owner", location)
        if not USERNAME.fullmatch(owner):
            raise ConfigError(f"{location}.owner is not a valid account name")
        receivers[receiver_id] = Receiver(
            receiver_id=receiver_id,
            path=_absolute_path(_required_string(raw, "path", location), f"{location}.path"),
            owner=owner,
        )

    certificates: dict[str, RegisteredCertificate] = {}
    for certificate_id, raw_value in _mapping(data.get("certificates", {}), "certificates").items():
        if not CERTIFICATE_ID.fullmatch(certificate_id):
            raise ConfigError(f"invalid certificate ID in certificate registry: {certificate_id!r}")
        location = f"certificates.{certificate_id}"
        raw = _mapping(raw_value, location)
        _only_keys(raw, {"source", "clusters", "receivers"}, location)

        raw_source = _mapping(raw.get("source"), f"{location}.source")
        _only_keys(
            raw_source, {"kind", "lineage", "dns_profile", "ndes_profile"}, f"{location}.source"
        )
        kind = _required_string(raw_source, "kind", f"{location}.source")
        if kind not in SOURCE_KINDS:
            raise ConfigError(
                f"{location}.source.kind must be one of: {', '.join(sorted(SOURCE_KINDS))}"
            )
        lineage: str | None = None
        dns_profile: str | None = None
        ndes_profile: str | None = None
        if kind == "acme":
            lineage = certificate_id
            if raw_source.get("lineage") is not None:
                lineage = _required_string(raw_source, "lineage", f"{location}.source")
                if not CERTIFICATE_ID.fullmatch(lineage):
                    raise ConfigError(f"{location}.source.lineage is not a lineage name")
            if raw_source.get("dns_profile") is not None:
                dns_profile = _required_string(raw_source, "dns_profile", f"{location}.source")
                if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", dns_profile):
                    raise ConfigError(f"{location}.source.dns_profile is not a profile ID")
        elif raw_source.get("lineage") is not None:
            raise ConfigError(f"{location}.source.lineage belongs to an acme source only")
        elif raw_source.get("dns_profile") is not None:
            raise ConfigError(f"{location}.source.dns_profile belongs to an acme source only")
        if raw_source.get("ndes_profile") is not None:
            if kind != "import":
                raise ConfigError(
                    f"{location}.source.ndes_profile belongs to an import source only"
                )
            ndes_profile = _required_string(raw_source, "ndes_profile", f"{location}.source")
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", ndes_profile):
                raise ConfigError(f"{location}.source.ndes_profile is not a profile ID")

        clusters = _id_list(raw, "clusters", location, CLUSTER_ID)
        named = _id_list(raw, "receivers", location, RECEIVER_ID)
        unknown = sorted(set(named) - set(receivers))
        if unknown:
            raise ConfigError(
                f"{location}.receivers names unregistered receiver(s): {', '.join(unknown)}"
            )
        certificates[certificate_id] = RegisteredCertificate(
            certificate_id=certificate_id,
            source=CertificateSource(
                kind=kind, lineage=lineage, dns_profile=dns_profile, ndes_profile=ndes_profile
            ),
            clusters=clusters,
            receivers=named,
        )
    return Registry(receivers=receivers, certificates=certificates)


def _id_list(
    raw: Mapping[str, Any], key: str, location: str, rule: re.Pattern[str]
) -> tuple[str, ...]:
    """An optional list of identifiers; absent means none, and none is allowed."""

    value = raw.get(key, [])
    if not isinstance(value, list):
        raise ConfigError(f"{location}.{key} must be a list")
    if any(not isinstance(item, str) or not rule.fullmatch(item) for item in value):
        raise ConfigError(f"{location}.{key} contains an invalid ID")
    if len(set(value)) != len(value):
        raise ConfigError(f"{location}.{key} contains duplicates")
    return tuple(value)


def load_runtime_config(policy: PathPolicy, *, require_secure: bool = True) -> RuntimeConfig:
    registry: Registry | None = None
    if policy.certificate_registry is not None:
        registry = load_registry(policy.certificate_registry, require_secure=require_secure)
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
                "address_prefix",
                "address_interface",
                "vips",
                "default_vip",
                "resolvers",
                "sources",
                "networks",
                "unknown_host",
                "abuse_protection",
                "config_path",
                "publish_path",
                "node_path",
                "validation_certs",
                "default_certificate",
                "certificate_ids",
                "trusted_proxy_cidrs",
                "traffic_logging",
                "nodes",
            },
            location,
        )
        vip = _required_string(raw, "vip", location)
        try:
            ipaddress.ip_address(vip)
        except ValueError as exc:
            raise ConfigError(f"{location}.vip must be an IP address") from exc
        vips, default_vip = _vips(raw, vip, location)
        address_prefix, address_interface = _address_form(raw, location)
        resolvers = raw.get("resolvers")
        if resolvers is not None and (
            not isinstance(resolvers, str) or not NAME.fullmatch(resolvers)
        ):
            raise ConfigError(f"{location}.resolvers must name a resolvers section")
        node_path = _required_string(raw, "node_path", location)
        if not NODE_PATH.fullmatch(node_path):
            raise ConfigError(f"{location}.node_path is invalid")

        if registry is not None:
            #
            # One answer, not two. The registry names the clusters each
            # certificate goes to, so a list here would either agree with it
            # (and be redundant) or disagree (and be wrong in a way nothing
            # would notice). Refused, so declaring the registry is the same
            # edit as moving the lists out of this file.
            #
            if "certificate_ids" in raw:
                raise ConfigError(
                    f"{location}.certificate_ids has moved to the certificate registry"
                )
            certificate_ids = registry.for_cluster(cluster_id)
            if not certificate_ids:
                raise ConfigError(f"no certificate in the registry names cluster {cluster_id!r}")
        else:
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

        traffic_logging = raw.get("traffic_logging", False)
        if not isinstance(traffic_logging, bool):
            raise ConfigError(f"{location}.traffic_logging must be true or false")

        clusters[cluster_id] = Cluster(
            cluster_id=cluster_id,
            display_name=_required_string(raw, "display_name", location),
            vip=vip,
            address_prefix=address_prefix,
            address_interface=address_interface,
            vips=vips,
            default_vip=default_vip,
            resolvers=resolvers,
            sources=_sources(raw, location),
            networks=_networks(raw, location),
            unknown_host=_unknown_host(raw.get("unknown_host"), f"{location}.unknown_host"),
            abuse_protection=_abuse_protection(
                raw.get("abuse_protection"), f"{location}.abuse_protection"
            ),
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
            traffic_logging=traffic_logging,
        )
    if registry is not None:
        #
        # A certificate naming a cluster that does not exist is the one
        # cross-reference only this function can check. Refused rather than
        # ignored: a typo here would silently stop a certificate reaching the
        # cluster the operator meant.
        #
        for entry in registry.certificates.values():
            unknown = sorted(set(entry.clusters) - set(clusters))
            if unknown:
                raise ConfigError(
                    f"certificates.{entry.certificate_id}.clusters names unknown "
                    f"cluster(s): {', '.join(unknown)}"
                )
    return RuntimeConfig(schema_version=1, clusters=clusters, registry=registry)
