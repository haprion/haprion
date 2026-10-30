from __future__ import annotations

import grp
import ipaddress
import os
import re
import stat
import types
from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from haprion import accounts, address_ranges, exit_codes, labels, safe_yaml

DEFAULT_POLICY_PATH = Path("/etc/haprion/runtime-policy.yaml")
MAX_CONFIG_BYTES = 1024 * 1024
#
# No `--` and no trailing `-` in a cluster ID or a node name: the traffic
# collector files a node's data as `<cluster>--<node>--<day>`, and a name that
# carries the separator lets one node's cleanup take another's files (review
# 2026-10-30, E4).
#
CLUSTER_ID = re.compile(r"^[a-z](?:[a-z0-9]|-(?=[a-z0-9])){0,62}$")

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
NODE_NAME = CLUSTER_ID
#
# How many nodes one cluster may have. keepalived sets no limit - one VRRP
# instance shares its addresses between any number of nodes by priority - so
# this is a figure nobody is meant to reach, set where it was measured to hold
# (2026-09-30, B211): the pages draw eight without scrolling sideways, and the
# poller reads a node in about 0.3 s, one after another. One is the floor
# (B302): a cluster is created with its first node and the second is added to
# it, and a cluster of one serves - it only has nothing to fail over to.
#
MIN_NODES = 1
MAX_NODES = 8
CERTIFICATE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,254}$")


class ConfigError(ValueError):
    def __init__(self, message: str, *, exit_code: int = exit_codes.REFUSED):
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
    # The directory published certificates are distributed from (one directory
    # per cluster under it, `certificate_directory`), and the identity that
    # triggers a certificate pull. Both optional for the same
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
    # The identity that puts a server in drain or maintenance on a node (Fas
    # 20, B263). Its own key: it changes what HAProxy sends where without a
    # deploy, which neither the status nor the probe identity can, and the
    # deploy identity's forced command takes no words at all.
    #
    server_state_identity: DeployIdentity | None = None
    #
    # The identity that asks a node for its root-produced state archive. Its
    # own key: the stream contains password hashes and private SSH keys, so a
    # status or deploy key must not become interchangeable with it.
    #
    backup_identity: DeployIdentity | None = None
    #
    # Where the backup engine writes each node's state archives, one directory
    # per node. Optional like the others: it is read by one command, and a
    # policy every other command rejected until backups were configured would
    # be worse than one that says what is missing when it is needed.
    #
    backup_root: Path | None = None

    #
    # The certificate registry (B135): which certificates exist, where each
    # comes from, and which clusters and receivers it goes to. Optional during
    # the transition - an installation without one keeps its allowlist in
    # `clusters.yaml` - and once declared, the allowlist must have moved.
    #
    certificate_registry: Path | None = None

    #
    # Where `haprion-cert-receiver` creates a receiver's directory (C7,
    # §9 choice 2). Its own root rather than a corner of `certificate_root`:
    # the distribution root is the manager's own copy of every certificate,
    # while these directories are other machines' mailboxes, owned by their
    # accounts and chrooted into by sshd. Stating the root in the policy also
    # makes it movable without a code change, and a registered receiver keeps
    # the path it was given - the registry, not this root, says where each
    # one actually is.
    #
    receiver_root: Path | None = None

    #
    # How this installation answers ACME challenges (Phase 11, C3). Each
    # method needs one installation-specific thing that the issue helper must
    # never take from its caller: the credential file for DNS-01, the webroot
    # for HTTP-01. A method whose setting is absent is refused by name.
    #
    # `certbot` is the binary itself (P1): the locked environment's
    # `/opt/haprion-certbot/current/venv/bin/certbot` once that is installed,
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

    #
    # The web interface's worker account (B207, 2026-09-29): the one caller
    # whose `requested_by` a version records as who published it. Anyone else
    # is recorded as the account sudo proves.
    #
    interface_account: str = accounts.WORKER

    #
    # The accounts the nodes fetch as (B211): `rrsync -ro` of the published
    # tree and of the certificate tree, one `authorized_keys` line per node.
    # Fixed since B266; no longer read from the policy.
    #
    pull_account: str = accounts.PULL
    cert_pull_account: str = accounts.CERT_PULL

    def certificate_directory(self, cluster_id: str) -> Path | None:
        """Where a cluster's certificates are published and its nodes fetch them (B358).

        With a registry the manager writes them, one directory per cluster,
        and each node's fetch key reads its own cluster's alone - a node of
        one cluster never holds another's key material. Without one the
        directory is filled by something else, flat, and every cluster's
        nodes read the same one.
        """

        if self.certificate_root is None:
            return None
        if self.certificate_registry is None:
            return self.certificate_root
        return cluster_certificates(self.certificate_root, cluster_id)


def cluster_certificates(root: Path, cluster_id: str) -> Path:
    """A cluster's directory under the certificate root, held to the cluster ID."""

    if not CLUSTER_ID.fullmatch(cluster_id):
        raise ConfigError(f"invalid cluster ID: {cluster_id!r}")
    return root / cluster_id


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


#
# The system's CA store, as the distribution's ca-certificates keeps it.
#
SYSTEM_TRUST = Path("/etc/ssl/certs/ca-certificates.crt")


@dataclass(frozen=True, slots=True)
class NdesServer:
    """One NDES server: its address and the CA it issues from.

    Its HTTPS is checked against the system's store, by the confirmation and
    by the enrollment alike (B392). A `tls_ca` in the policy is read as a
    path and kept nowhere: Certmonger's `scep-submit` checks all but its
    first question against the system's store, whatever it is given.
    """

    endpoint: str
    issuing_ca: Path


@dataclass(frozen=True, slots=True)
class NdesPolicy:
    #
    # Each confirmed by an administrator, from its CA's fingerprint (B383, B385).
    # A profile's address must be one of them.
    #
    servers: tuple[NdesServer, ...]
    client_root: Path
    state_root: Path
    profiles: DnsProfilesPolicy
    #
    # When the scheduled renewal asks for a new certificate: this many days
    # before the current one expires. Optional; 30 is certbot's habit.
    #
    renew_days: int = 30

    def server(self, endpoint: str) -> NdesServer | None:
        return next((server for server in self.servers if server.endpoint == endpoint), None)


@dataclass(frozen=True, slots=True)
class DeployIdentity:
    """Who the manager becomes to reach a node, and with which key.

    The account is fixed per purpose (B266, `accounts.IDENTITY_ACCOUNTS`); the
    key path is the installation's and lives in the policy.

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

    http3: bool = False
    """Also serve https over QUIC on this address (B280), and say so in `alt-svc`.

    The VIP's and not an object's, because the UDP listener is the address's
    and every object on it shares it. QUIC carries TLS 1.3 alone, so a policy
    that stops at 1.2 is refused beside it.
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
    default_certificate: str | None
    certificate_ids: tuple[str, ...]
    trusted_proxy_cidrs: tuple[str, ...]
    abuse_protection: AbuseProtection | None
    nodes: tuple[Node, ...]
    traffic_logging: bool = False
    #
    # The CA files the cluster's nodes carry for its pools to verify against
    # (B276). Only from the registry; empty without one.
    #
    authority_ids: tuple[str, ...] = ()
    #
    # The VRRP instance's router ID, when the product writes the nodes'
    # keepalived.conf (B313). Set when the cluster is created; a cluster from
    # before has none, and its nodes keep a keepalived.conf a person wrote.
    #
    vrrp_router_id: int | None = None

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
# An `authority` (B276) is a CA certificate - one or more, no key - that
# clusters verify their pools against. It is registered, imported and
# published like a certificate, but it is never served: it lands beside the
# certificates on a node, in a directory of its own, and is named by a pool's
# `ca-file` rather than by a listener. It goes to clusters only.
#
SOURCE_KINDS = frozenset({"acme", "import", "authority"})
AUTHORITY = "authority"
RECEIVER_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")

#
# A DNS label sequence, lowercase, no trailing dot. Deliberately narrower
# than what DNS allows: this name becomes a certbot lineage name, a file
# name under the distribution root and a registry key, and all three are
# happier without anything outside this class.
#
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)

#
# How a receiver fetches, how its directory is laid out, and in what form the
# material is written there (B138, B159).
#
# `rsync` and `flat` are the defaults because they are what the three
# receivers registered before C7 do, and the reader has to keep reading their
# entries unchanged. That is the only reason: `haprion-cert-receiver` refuses
# to create a new `flat` receiver, since a directory that holds one
# certificate's `fullchain.pem` cannot hold a second certificate at all.
#
# `https` is the sinking of the trust level B138 admits to - a fetch with no
# key, held together by an address whitelist - and the publisher and the
# registry writer fence it in rather than this reader: what may be published
# where is a question about a certificate and its clusters, not about the
# shape of one line of YAML.
#
RECEIVER_TRANSPORTS = ("rsync", "sftp", "https")
RECEIVER_LAYOUTS = ("per-certificate",)
RECEIVER_FORMATS = ("pem", "pkcs12")
DEFAULT_RECEIVER_TRANSPORT = "rsync"
DEFAULT_RECEIVER_LAYOUT = "per-certificate"
DEFAULT_RECEIVER_FORMAT = "pem"


def receiver_id_names_a_host(receiver_id: str) -> bool:
    """B141: a receiver ID is the fetching host's DNS name or its IP address.

    Held here as a function rather than as a pattern because an IP address is
    not a regular expression anyone should write twice, and because two places
    ask the question for the same reason: `haprion-cert-receiver` refuses a
    registration whose ID is not a host, and the lock it writes -
    `from="<id>,<its addresses>"` in `authorized_keys`, `allow <id>` in nginx - is what makes
    the answer matter. Existing entries are not held to it (§3 of the C7
    design); the check belongs at registration, where a name can still be
    chosen.
    """

    if HOSTNAME.fullmatch(receiver_id):
        return True
    try:
        ipaddress.ip_address(receiver_id)
    except ValueError:
        return False
    return True


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
    #
    # Set once, at registration, and never edited: a receiver that woke up to
    # a different transport or a moved path would find out at its next fetch,
    # which is a renewal away (B138). Changing either is remove and register.
    #
    transport: str = DEFAULT_RECEIVER_TRANSPORT
    layout: str = DEFAULT_RECEIVER_LAYOUT
    #
    # `https` only: the addresses and networks nginx lets through. Required
    # and non-empty there, refused everywhere else - an `allow` list on an
    # `rsync` receiver would read as a restriction that nothing enforces.
    #
    allow: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RegisteredCertificate:
    certificate_id: str
    source: CertificateSource
    clusters: tuple[str, ...]
    #
    # The receiver IDs, in registry order. A list element is either the bare
    # ID or a `{id, format}` mapping (B159), and both arrive here as the ID:
    # the format is a property of this pair - one receiver may want PEM for
    # one certificate and a PKCS#12 bundle for another - so it is kept beside
    # the list rather than turned into a second kind of element every reader
    # of `receivers` would have to learn.
    #
    receivers: tuple[str, ...]
    formats: Mapping[str, str] = types.MappingProxyType({})
    #
    # The manager's own interface certificate (B188): renewed like every
    # other entry, published to nginx instead of to targets. At most one entry
    # carries it, and that entry names no cluster and no receiver - the
    # certificate is the application's, not something it distributes.
    #
    interface: bool = False
    #
    # A certificate to be taken out and installed by hand (B255): something
    # that is never connected to this manager - a BMC, a NAS, a printer. It
    # names no cluster and no receiver, and its key may be exported from the
    # interface, which no other entry's may. Decided when the entry is made
    # and never changed: a certificate HAProxy serves must not become one
    # whose key can be taken away.
    #
    exportable: bool = False

    def format_for(self, receiver_id: str) -> str:
        """The form this certificate is written in for that receiver."""

        return self.formats.get(receiver_id, DEFAULT_RECEIVER_FORMAT)


@dataclass(frozen=True, slots=True)
class Registry:
    receivers: Mapping[str, Receiver]
    certificates: Mapping[str, RegisteredCertificate]

    def for_cluster(self, cluster_id: str) -> tuple[str, ...]:
        """The certificate IDs that name this cluster, in registry order.

        Certificates a listener can serve; an authority is not one (B276).
        """

        return tuple(
            entry.certificate_id
            for entry in self.certificates.values()
            if cluster_id in entry.clusters and entry.source.kind != AUTHORITY
        )

    def authorities_for(self, cluster_id: str) -> tuple[str, ...]:
        """The authority IDs that name this cluster, in registry order (B276)."""

        return tuple(
            entry.certificate_id
            for entry in self.certificates.values()
            if cluster_id in entry.clusters and entry.source.kind == AUTHORITY
        )


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    schema_version: int
    clusters: Mapping[str, Cluster]
    registry: Registry | None = None

    def cluster(self, cluster_id: str) -> Cluster:
        if not CLUSTER_ID.fullmatch(cluster_id):
            raise ConfigError("invalid cluster ID", exit_code=exit_codes.USAGE)
        try:
            return self.clusters[cluster_id]
        except KeyError as exc:
            valid = ", ".join(sorted(self.clusters))
            raise ConfigError(
                f"unknown cluster '{cluster_id}'. Valid clusters: {valid}",
                exit_code=exit_codes.USAGE,
            ) from exc


def _mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ConfigError(f"{location} must be a mapping")
    return value


def _only_keys(value: Mapping[str, Any], allowed: AbstractSet[str], location: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConfigError(
            f"{location} contains unknown {labels.noun(len(unknown), 'field')}: {', '.join(unknown)}"
        )


def _required_string(value: Mapping[str, Any], key: str, location: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise ConfigError(f"{location}.{key} must be a non-empty string")
    return result


def _who_may_read(path: Path) -> str:
    """For a refusal: the group that owns the nearest directory, and how to join it.

    The registry directory is the config group's. An administrator in %sudo
    but not in that group got "Permission denied" and nothing more (prod
    26-10-28, F35); the manual's answer is to join the group.
    """

    for directory in (path, *path.parents):
        try:
            gid = directory.stat().st_gid
        except OSError:
            continue
        try:
            group = grp.getgrgid(gid).gr_name
        except KeyError:
            return ""
        account = os.environ.get("SUDO_USER") or os.environ.get("USER") or "<your account>"
        return (
            f"; the group {group} reads it: sudo usermod -a -G {group} {account}, then log in again"
        )
    return ""


def _secure_yaml(path: Path, *, require_secure: bool) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except PermissionError as exc:
        raise ConfigError(
            f"cannot stat configuration file: {exc}{_who_may_read(path.parent)}",
            exit_code=exit_codes.UNAVAILABLE,
        ) from exc
    except OSError as exc:
        raise ConfigError(
            f"cannot stat configuration file: {exc}", exit_code=exit_codes.UNAVAILABLE
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ConfigError(
            "configuration file must be a regular non-symlink", exit_code=exit_codes.UNAVAILABLE
        )
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise ConfigError("configuration file exceeds 1 MiB", exit_code=exit_codes.UNAVAILABLE)
    if require_secure and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022):
        raise ConfigError(
            "configuration file must be root-owned and not group/other-writable",
            exit_code=exit_codes.UNAVAILABLE,
        )
    try:
        loaded = safe_yaml.load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ConfigError(
            f"cannot read configuration file: {exc}", exit_code=exit_codes.UNAVAILABLE
        ) from exc
    return _mapping(loaded, str(path))


def _absolute_path(raw: str, location: str) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        raise ConfigError(f"{location} must be absolute")
    return path.resolve(strict=False)


def _address(value: Any, location: str) -> str:
    """An IP address in its one spelling.

    `2001:db8::10` and `2001:DB8:0::10` are one address. Kept as written, the
    duplicate check compared strings and let both stand - two `bind` lines on
    one address and port, which HAProxy accepts and then shares the traffic
    between (review 2026-10-22, 1A-5) - and `reservations.yaml` missed a VIP
    spelled differently.
    """

    if not isinstance(value, str):
        raise ConfigError(f"{location} must be an IP address")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ConfigError(f"{location} must be an IP address") from exc


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
        _only_keys(entry, {"address", "source", "tls", "http3"}, where)
        source = entry.get("source")
        http3 = entry.get("http3", False)
        if type(http3) is not bool:
            raise ConfigError(f"{where}.http3 must be true or false")
        policy = _tls_policy(entry.get("tls"), f"{where}.tls")
        if http3 and policy == "tls12only":
            raise ConfigError(
                f"{where}: HTTP/3 needs TLS 1.3, and this VIP's TLS version is TLS 1.2 only"
            )
        vips[name] = Vip(
            name=name,
            address=_address(entry.get("address"), f"{where}.address"),
            source=None if source is None else _address(source, f"{where}.source"),
            tls_policy=policy,
            http3=http3,
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
            if address_ranges.refused(item):
                raise ConfigError(f"{where} contains {item}: {address_ranges.HOST_BITS}")
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
    from haprion.managed_network import load_mapping

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


def _publish_path(raw: str, root: Path, cluster_id: str, location: str) -> Path:
    """The cluster's published tree, `<publish root>/<cluster ID>` and nowhere else.

    A node asks for `<cluster>/current/<node path>/` under the publish root,
    and its fetch key reads this directory alone (B358): a tree anywhere else
    is one its nodes would never find.
    """

    path = _under_root(raw, root, location)
    expected = root.resolve(strict=False) / cluster_id
    if path != expected:
        raise ConfigError(
            f"{location} must be {expected}: the nodes fetch {cluster_id}/current/ "
            "under the publish root"
        )
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
    #
    # `user` is refused rather than ignored: the account is fixed (B266), and a
    # policy still naming one was written for an installation that has not been
    # migrated.
    #
    _only_keys(entry, {"key"}, location)
    return DeployIdentity(
        user=accounts.IDENTITY_ACCOUNTS[key],
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
            "server_state_identity",
            "backup_identity",
            "backup_root",
            "certificate_registry",
            "receiver_root",
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
        server_state_identity=_deploy_identity(data, "server_state_identity"),
        backup_identity=_deploy_identity(data, "backup_identity"),
        backup_root=_optional_root(data, "backup_root"),
        certificate_registry=_optional_root(data, "certificate_registry"),
        receiver_root=_optional_root(data, "receiver_root"),
        acme=_acme_policy(data),
        ndes=_ndes_policy(data),
    )


def worker_writable_paths(policy: PathPolicy) -> tuple[Path, ...]:
    """The policy's directories the worker's sandbox opens for its root helpers.

    Rendered into `haprion-worker.service` by platform step 07, so the unit opens
    the roots this installation chose rather than the ones an example names:
    the configuration repositories and their publish and validation roots, the
    registry's directory, and the directories the certificate publisher writes
    in, and the HTTP-01 webroot, where certbot in the worker's namespace writes
    its challenge file. Each once, in this order.
    """

    paths = [policy.config_root, policy.publish_root, policy.validation_certs_root]
    if policy.certificate_registry is not None:
        paths.append(policy.certificate_registry.parent)
    for root in (policy.certificate_root, policy.receiver_root):
        if root is not None:
            paths.append(root.parent)
    if policy.acme is not None and policy.acme.webroot is not None:
        paths.append(policy.acme.webroot)
    return tuple(dict.fromkeys(paths))


def _ndes_policy(data: Mapping[str, Any]) -> NdesPolicy | None:
    raw = data.get("ndes")
    if raw is None:
        return None
    location = "runtime policy.ndes"
    entry = _mapping(raw, location)
    _only_keys(
        entry,
        {
            "servers",
            "endpoint",
            "tls_ca",
            "issuing_ca",
            "client_root",
            "state_root",
            "profiles",
            "renew_days",
        },
        location,
    )
    renew_days = entry.get("renew_days", 30)
    if (
        isinstance(renew_days, bool)
        or not isinstance(renew_days, int)
        or not 1 <= renew_days <= 3650
    ):
        raise ConfigError(f"{location}.renew_days must be an integer between 1 and 3650")
    #
    # One server named in the block itself is how a policy said it before
    # B385, and is read as the only one.
    #
    single = {"endpoint", "tls_ca", "issuing_ca"} & entry.keys()
    if single and "servers" in entry:
        raise ConfigError(f"{location} names its servers in servers, not beside it")
    if single:
        servers: tuple[NdesServer, ...] = (_ndes_server(entry, location),)
    else:
        raw_servers = entry.get("servers")
        if not isinstance(raw_servers, list) or not raw_servers:
            raise ConfigError(f"{location}.servers must be a non-empty list")
        servers = tuple(
            _ndes_server(
                _mapping(item, f"{location}.servers[{index}]"), f"{location}.servers[{index}]"
            )
            for index, item in enumerate(raw_servers)
        )
    endpoints = [server.endpoint for server in servers]
    if len(set(endpoints)) != len(endpoints):
        raise ConfigError(f"{location}.servers names an address twice")
    profiles = _ndes_profiles(entry.get("profiles"), data, f"{location}.profiles")
    return NdesPolicy(
        servers=servers,
        client_root=_absolute_path(
            _required_string(entry, "client_root", location), f"{location}.client_root"
        ),
        state_root=_absolute_path(
            _required_string(entry, "state_root", location), f"{location}.state_root"
        ),
        profiles=profiles,
        renew_days=renew_days,
    )


def _ndes_profiles(raw: object, data: Mapping[str, Any], location: str) -> DnsProfilesPolicy:
    """The NDES profiles' directory, and the keys they are sealed with.

    The keys are the DNS profiles' own (`ndes_profiles`: the web seals both
    with one public key), so a block that lists none reads them from
    `acme.dns_profiles`: one list, which a rotation changes once (review
    2026-10-29, B05). A block that lists its own is read as it says.
    """

    if raw is None:
        raise ConfigError(f"{location} must be configured")
    entry = _mapping(raw, location)
    own = (
        _dns_profiles_policy({"dns_profiles": entry}, location) if "private_keys" in entry else None
    )
    if own is not None:
        return own
    _only_keys(entry, {"directory"}, location)
    acme = data.get("acme")
    dns = (
        _dns_profiles_policy(acme, "runtime policy.acme.dns_profiles")
        if isinstance(acme, Mapping)
        else None
    )
    if dns is None:
        raise ConfigError(
            f"{location} lists no private_keys, and there is no acme.dns_profiles to take them from"
        )
    return DnsProfilesPolicy(
        directory=_absolute_path(
            _required_string(entry, "directory", location), f"{location}.directory"
        ),
        private_keys=dns.private_keys,
    )


def _ndes_server(entry: Mapping[str, Any], location: str) -> NdesServer:
    from haprion.dns_profiles import ProfileError
    from haprion.ndes_profiles import check_endpoint

    if not location.endswith("ndes"):
        _only_keys(entry, {"endpoint", "tls_ca", "issuing_ca"}, location)
    try:
        endpoint = check_endpoint(_required_string(entry, "endpoint", location))
    except ProfileError:
        raise ConfigError(f"{location}.endpoint must be a valid HTTPS URL") from None
    issuing_ca = _absolute_path(
        _required_string(entry, "issuing_ca", location), f"{location}.issuing_ca"
    )
    if entry.get("tls_ca") is not None:
        _absolute_path(_required_string(entry, "tls_ca", location), f"{location}.tls_ca")
    return NdesServer(endpoint=endpoint, issuing_ca=issuing_ca)


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

    # The profile IDs are the profile store's own rule, not a copy of it
    # (B380); imported here because that module reads this one.
    from haprion.dns_profiles import PROFILE_ID

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
        _only_keys(raw, {"path", "owner", "transport", "layout", "allow"}, location)
        owner = _required_string(raw, "owner", location)
        if not USERNAME.fullmatch(owner):
            raise ConfigError(f"{location}.owner is not a valid account name")
        transport = _one_of(
            raw, "transport", location, RECEIVER_TRANSPORTS, DEFAULT_RECEIVER_TRANSPORT
        )
        layout = _one_of(raw, "layout", location, RECEIVER_LAYOUTS, DEFAULT_RECEIVER_LAYOUT)
        receivers[receiver_id] = Receiver(
            receiver_id=receiver_id,
            path=_absolute_path(_required_string(raw, "path", location), f"{location}.path"),
            owner=owner,
            transport=transport,
            layout=layout,
            allow=_allow_list(raw, location, transport),
        )

    certificates: dict[str, RegisteredCertificate] = {}
    for certificate_id, raw_value in _mapping(data.get("certificates", {}), "certificates").items():
        if not CERTIFICATE_ID.fullmatch(certificate_id):
            raise ConfigError(f"invalid certificate ID in certificate registry: {certificate_id!r}")
        location = f"certificates.{certificate_id}"
        raw = _mapping(raw_value, location)
        _only_keys(raw, {"source", "clusters", "receivers", "interface", "exportable"}, location)

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
                if not PROFILE_ID.fullmatch(dns_profile):
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
            if not PROFILE_ID.fullmatch(ndes_profile):
                raise ConfigError(f"{location}.source.ndes_profile is not a profile ID")

        clusters = _id_list(raw, "clusters", location, CLUSTER_ID)
        named, formats = _receiver_list(raw, location)
        unknown = sorted(set(named) - set(receivers))
        if unknown:
            raise ConfigError(
                f"{location}.receivers names unregistered {labels.noun(len(unknown), 'receiver')}: "
                f"{', '.join(unknown)}"
            )
        interface = raw.get("interface", False)
        if type(interface) is not bool:
            raise ConfigError(f"{location}.interface must be true or false")
        if interface and (clusters or named):
            raise ConfigError(
                f"{location} is the interface certificate and cannot name clusters or receivers"
            )
        exportable = raw.get("exportable", False)
        if type(exportable) is not bool:
            raise ConfigError(f"{location}.exportable must be true or false")
        if exportable and (clusters or named or interface):
            raise ConfigError(
                f"{location} is exportable and cannot name clusters or receivers or serve "
                "the interface"
            )
        if kind == AUTHORITY and (named or interface or exportable):
            raise ConfigError(
                f"{location} is an authority and goes to clusters only: no receivers, "
                "not the interface, not exportable"
            )
        if interface:
            taken = [e.certificate_id for e in certificates.values() if e.interface]
            if taken:
                raise ConfigError(
                    f"{location}.interface: {taken[0]} is already the interface certificate"
                )
        certificates[certificate_id] = RegisteredCertificate(
            certificate_id=certificate_id,
            source=CertificateSource(
                kind=kind, lineage=lineage, dns_profile=dns_profile, ndes_profile=ndes_profile
            ),
            clusters=clusters,
            receivers=named,
            formats=types.MappingProxyType(formats),
            interface=interface,
            exportable=exportable,
        )
    return Registry(receivers=receivers, certificates=certificates)


def _one_of(
    raw: Mapping[str, Any], key: str, location: str, allowed: tuple[str, ...], default: str
) -> str:
    """An optional keyword from a closed set; absent means the default."""

    value = raw.get(key)
    if value is None:
        return default
    if value not in allowed:
        raise ConfigError(f"{location}.{key} must be one of: {', '.join(allowed)}")
    return str(value)


def _allow_list(raw: Mapping[str, Any], location: str, transport: str) -> tuple[str, ...]:
    """The `https` whitelist: addresses or networks, and only where it acts.

    Refused on the other transports rather than ignored. A list nothing reads
    is a rule an operator believes in, and the belief is the dangerous part.
    """

    value = raw.get("allow")
    if transport != "https":
        if value is not None:
            raise ConfigError(f"{location}.allow belongs to an https receiver only")
        return ()
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{location}.allow must be a non-empty list for an https receiver")
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ConfigError(f"{location}.allow[{index}] must be a string")
    try:
        return check_allow_entries(value)
    except ValueError as exc:
        raise ConfigError(f"{location}.allow{exc}") from exc


def check_allow_entries(entries: Sequence[str]) -> tuple[str, ...]:
    """The one rule for an `https` whitelist entry, or a `ValueError` naming the entry.

    Stated once, here, because two callers must agree on it before anything is
    written: the loader when it reads the registry, and `haprion-cert-receiver`
    before it renders the entries into nginx's configuration - the rule used
    to live in the loader alone, so an entry the loader would refuse reached
    nginx, and a reload, first (review 2026-09-20). The message starts with
    what the loader appends to its location, `[index] ...`.
    """

    checked: list[str] = []
    for index, item in enumerate(entries):
        #
        # Strict: `192.0.2.1/24` is a typo for either the host or the
        # network, and nginx would silently take the network - which is
        # 255 addresses more than whoever wrote the line meant.
        #
        if address_ranges.has_host_bits(item):
            raise ValueError(f"[{index}] {item!r}: {address_ranges.HOST_BITS}")
        try:
            ipaddress.ip_network(item, strict=True)
        except ValueError:
            raise ValueError(f"[{index}] is not an address or network: {item!r}") from None
        checked.append(item)
    if len(set(checked)) != len(checked):
        raise ValueError(" contains duplicates")
    return tuple(checked)


def _receiver_list(raw: Mapping[str, Any], location: str) -> tuple[tuple[str, ...], dict[str, str]]:
    """A certificate's receivers: bare IDs, `{id, format}` mappings, or both.

    The bare ID is the older form and stays the common one - it means `pem`,
    which is what every receiver registered before B159 gets. The mapping is
    how a pair asks for a PKCS#12 bundle instead, and it is a per-pair choice
    rather than a receiver-wide one because the same host can want PEM for
    HAProxy and a PFX for IIS.
    """

    value = raw.get("receivers", [])
    if not isinstance(value, list):
        raise ConfigError(f"{location}.receivers must be a list")
    named: list[str] = []
    formats: dict[str, str] = {}
    for index, item in enumerate(value):
        where = f"{location}.receivers[{index}]"
        if isinstance(item, str):
            receiver_id, receiver_format = item, DEFAULT_RECEIVER_FORMAT
        elif isinstance(item, Mapping):
            _only_keys(item, {"id", "format"}, where)
            receiver_id = _required_string(item, "id", where)
            receiver_format = _one_of(
                item, "format", where, RECEIVER_FORMATS, DEFAULT_RECEIVER_FORMAT
            )
        else:
            raise ConfigError(f"{where} must be a receiver ID or an {{id, format}} mapping")
        if not RECEIVER_ID.fullmatch(receiver_id):
            raise ConfigError(f"{location}.receivers contains an invalid ID")
        if receiver_id in formats:
            raise ConfigError(f"{location}.receivers contains duplicates")
        named.append(receiver_id)
        formats[receiver_id] = receiver_format
    return tuple(named), formats


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
    #
    # Empty is a manager before its first cluster (B302): it is installed with
    # none, and *Create cluster* adds the first. A command that takes a cluster
    # refuses one it does not find, here as anywhere.
    #
    raw_clusters = _mapping(data.get("clusters"), "clusters")

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
                "vrrp_router_id",
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
            #
            # None is a cluster before its first certificate (B302): a new
            # cluster serves plain HTTP and TCP until one is issued or
            # uploaded for it, and an HTTPS object is refused until then.
            #
            certificate_ids = registry.for_cluster(cluster_id)
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
        #
        # Bookkeeping, never generated from: what the certificate commands
        # refuse to delete or move away from the cluster. Optional since a
        # cluster may start without certificates (B302).
        #
        default_certificate: str | None = None
        if "default_certificate" in raw:
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
        if not isinstance(raw_nodes, list) or not MIN_NODES <= len(raw_nodes) <= MAX_NODES:
            raise ConfigError(
                f"{location}.nodes must contain between {MIN_NODES} and {MAX_NODES} nodes"
            )
        nodes: list[Node] = []
        for index, raw_node_value in enumerate(raw_nodes):
            node_location = f"{location}.nodes[{index}]"
            raw_node = _mapping(raw_node_value, node_location)
            _only_keys(raw_node, {"name", "mgmt_host"}, node_location)
            name = _required_string(raw_node, "name", node_location)
            if not NODE_NAME.fullmatch(name):
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
        if len({node.name for node in nodes}) != len(nodes) or len(
            {node.mgmt_host for node in nodes}
        ) != len(nodes):
            raise ConfigError(f"{location}.nodes must have unique names and management hosts")

        traffic_logging = raw.get("traffic_logging", False)
        if not isinstance(traffic_logging, bool):
            raise ConfigError(f"{location}.traffic_logging must be true or false")
        vrrp_router_id = raw.get("vrrp_router_id")
        if vrrp_router_id is not None and (
            not isinstance(vrrp_router_id, int)
            or isinstance(vrrp_router_id, bool)
            or not 1 <= vrrp_router_id <= 255
        ):
            raise ConfigError(f"{location}.vrrp_router_id must be a number between 1 and 255")

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
            publish_path=_publish_path(
                _required_string(raw, "publish_path", location),
                policy.publish_root,
                cluster_id,
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
            authority_ids=registry.authorities_for(cluster_id) if registry is not None else (),
            vrrp_router_id=vrrp_router_id,
        )
    #
    # Two clusters on one segment with one router ID would take each other's
    # adverts were they ever to meet; the IDs this manager hands out are its
    # own to keep apart (B313).
    #
    taken: dict[int, str] = {}
    for cluster_id, cluster in clusters.items():
        if cluster.vrrp_router_id is None:
            continue
        if cluster.vrrp_router_id in taken:
            raise ConfigError(
                f"clusters.{cluster_id}.vrrp_router_id {cluster.vrrp_router_id} is also "
                f"{taken[cluster.vrrp_router_id]}'s"
            )
        taken[cluster.vrrp_router_id] = cluster_id
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
                    f"{labels.noun(len(unknown), 'cluster')}: {', '.join(unknown)}"
                )
    return RuntimeConfig(schema_version=1, clusters=clusters, registry=registry)
