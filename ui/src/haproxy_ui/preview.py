"""Turn a filled-in form into a proxy object, and that object into configuration.

This is the page where somebody can see what the generator does before any of
it is published. Nothing here writes anything: it builds the YAML document an
object would be stored as, runs it through the engine's own parser, and shows
both that document and the HAProxy configuration it produces.

The form does not build a `Proxy` directly. It writes the same YAML the
application will one day store under `managed/proxies/`, and hands it to
`load_proxy` - the parser the command line uses. A form that constructed the
object itself would be a second interpretation of the schema, and the two would
drift in the direction nobody notices: the interface would accept something the
engine refuses, or refuse something it accepts, and the difference would show up
during a publish rather than here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from haproxy_mgmt.config import AbuseProtection, Cluster, Node, UnknownHost, Vip
from haproxy_mgmt.generate import GeneratorError, generate
from haproxy_mgmt.proxy_model import (
    BALANCE,
    HEALTH_TYPES,
    ModelError,
    dump_document,
    load_proxy,
)

#
# The cluster this page generates against.
#
# It is not this deployment's cluster, and the page says so. The application
# identities deliberately cannot read the engine's configuration - that tree is
# private, and the whole privilege split exists to keep the web process out of
# it - so the real VIP names, certificate IDs and network names are not
# available here yet. Until a privileged helper carries that shape out to the
# poller the way it already carries certificates and inventory, this page
# offers a documented example, so that the form and the output can be judged.
# That is what a preview is for.
#
# Every value below is from the repository's fictional set.
#
PREVIEW_CLUSTER = Cluster(
    cluster_id="alpha",
    display_name="Preview",
    vip="192.0.2.20",
    address_prefix=None,
    address_interface=None,
    vips={
        "internal": Vip(name="internal", address="192.0.2.20", source="192.0.2.25"),
        "dmz": Vip(name="dmz", address="198.51.100.20", source="198.51.100.25"),
    },
    default_vip="internal",
    resolvers="cluster-dns",
    sources={"outbound": "192.0.2.35"},
    networks={"office": ("198.51.100.0/24",), "vpn": ("203.0.113.0/24",)},
    unknown_host=UnknownHost(status=404),
    abuse_protection=AbuseProtection(window="10s", max_requests=100, max_errors=20),
    config_path=Path("/preview"),
    publish_path=Path("/preview"),
    node_path="preview",
    validation_certs=Path("/preview"),
    default_certificate="example.com",
    certificate_ids=("example.com", "example.net", "wildcard-example-com"),
    trusted_proxy_cidrs=(),
    nodes=(Node(name="node-a", mgmt_host="node-a.example.com"),),
)

#
# What the form starts with. A single site on the cluster's default address,
# one backend, one server - the shape most objects have, so the first thing
# somebody sees is the common case rather than an empty page.
#
DEFAULTS = {
    "name": "app",
    "hostnames": "app.example.com",
    "protocol": "https",
    "vip": "",
    "source": "",
    "certificate": "",
    "redirect_http": True,
    "hsts": False,
    "hsts_max_age": "31536000",
    "hsts_subdomains": False,
    "balance": "roundrobin",
    "balance_key": "",
    "cookie": "",
    "servers": "198.51.100.10:8080",
    "health_type": "http",
    "health_path": "/",
    "health_host": "",
    "health_port": "",
    "backend_tls": "",
    "max_connections": "",
    "slow_start": "",
    "allow_from": (),
    "allow_ranges": "",
    "maintenance": "",
    "maintenance_message": "",
    "unavailable_message": "",
    "request_headers": "",
    "response_headers": "",
    "redirect_path": "",
    "redirect_location": "",
    "redirect_status": "301",
}


def suggested_cookie(name: str) -> str:
    """The session cookie name offered for an object that has none yet.

    Prefixed so it is recognisable as this system's in a browser's cookie list,
    and next to the object's own name so two sites do not overwrite each
    other's. Cookie names are case-sensitive, so the suggestion picks one
    casing and stays with it.
    """

    return f"hap_{name}" if name else "hap_site"


@dataclass(frozen=True, slots=True)
class Preview:
    """What the page shows: the object, the configuration, or what is wrong.

    `problem` is a single readable sentence rather than a list, because every
    refusal the engine raises names one thing and says what it should be. Two
    of them at once would mean the first was not answered.
    """

    document: str = ""
    files: dict[str, str] = field(default_factory=dict)
    problem: str | None = None

    @property
    def problem_field(self) -> str:
        """The field a refusal names, when it names one.

        Every refusal the engine raises begins with the path of the thing it is
        about - `app.listen.certificate`, `shop.backends.web.servers` - so the
        page can show that as the subject rather than leaving the reader to
        find it inside a sentence.
        """

        if self.problem is None:
            return ""
        head = self.problem.split(" ", 1)[0]
        return head if "." in head and head[0].isalnum() else ""

    @property
    def problem_text(self) -> str:
        """What is wrong with it, with the field taken off the front."""

        if self.problem is None:
            return ""
        if not self.problem_field:
            return self.problem
        return self.problem[len(self.problem_field) :].lstrip()


def _servers(raw: str) -> list[dict[str, object]]:
    """One `host:port` per line, in the order they were typed.

    Parsed here rather than in the model because this is the only place the
    shorthand exists: the stored object spells host and port out, and a reader
    of that file should not have to know a form convention to understand it.
    """

    servers: list[dict[str, object]] = []
    for line in raw.splitlines():
        entry = line.strip()
        if not entry:
            continue
        host, separator, port = entry.rpartition(":")
        if not separator or not port.isdigit():
            raise ValueError(f"{entry!r} is not a host and port, such as 198.51.100.10:8080")
        server: dict[str, object] = {"host": host, "port": int(port)}
        servers.append(server)
    if not servers:
        raise ValueError("a backend needs at least one server")
    return servers


def build_document(form: dict[str, object]) -> str:
    """The YAML the object would be stored as.

    Built as data and dumped, never assembled as text: a hostname or a cookie
    name typed into a form is not trusted to be YAML-safe, and quoting it by
    hand is how an input ends up meaning something structural.
    """

    def text(key: str) -> str:
        return str(form.get(key, "") or "").strip()

    def flag(key: str) -> bool:
        return bool(form.get(key))

    protocol = text("protocol")
    listen: dict[str, object] = {"protocol": protocol}
    if text("vip"):
        listen["vip"] = text("vip")
    if text("source"):
        listen["source"] = text("source")
    if protocol == "https":
        if text("certificate"):
            listen["certificate"] = text("certificate")
        if flag("redirect_http"):
            listen["redirect_http"] = True
        if flag("hsts"):
            max_age = text("hsts_max_age")
            if not max_age.isdigit():
                raise ValueError("the HSTS lifetime must be a number of seconds")
            listen["hsts"] = {
                "max_age": int(max_age),
                "include_subdomains": flag("hsts_subdomains"),
            }

    health: dict[str, object] = {"type": text("health_type")}
    if text("health_type") != "disabled" and text("health_port"):
        port = text("health_port")
        if not port.isdigit():
            raise ValueError("the health check port must be a number")
        health["port"] = int(port)
    if text("health_type") == "http":
        health["path"] = text("health_path") or "/"
        if text("health_host"):
            health["host"] = text("health_host")

    backend: dict[str, object] = {
        "balance": text("balance"),
        "health": health,
        "servers": _servers(text("servers")),
    }
    if text("balance_key"):
        backend["balance_key"] = text("balance_key")
    if text("cookie"):
        backend["cookie"] = text("cookie")
    if text("backend_tls"):
        backend["tls"] = {"verify": text("backend_tls")}
    if text("max_connections"):
        limit = text("max_connections")
        if not limit.isdigit():
            raise ValueError("the connection limit must be a number")
        backend["max_connections"] = int(limit)
    if text("slow_start"):
        backend["slow_start"] = text("slow_start")

    hostnames = [name.strip() for name in text("hostnames").replace(",", "\n").splitlines()]
    document: dict[str, object] = {
        "schema": 1,
        "name": text("name"),
        "hostnames": [name for name in hostnames if name],
        "listen": listen,
        "routes": _routes(
            text("redirect_path"), text("redirect_location"), text("redirect_status")
        ),
        "backends": {"web": backend},
    }
    selected = form.get("allow_from", ())
    allowed = (
        [str(name) for name in selected if str(name).strip()]
        if isinstance(selected, (list, tuple))
        else []
    )
    allowed += [
        entry.strip()
        for entry in text("allow_ranges").replace(",", "\n").splitlines()
        if entry.strip()
    ]
    if allowed:
        document["allow_from"] = allowed

    #
    # Written last because it is the one field that is about the object's state
    # rather than its shape, and reading it at the end of the document says so.
    # The message is not defaulted here: the engine requires one, and a default
    # written by the form would be this module quietly deciding what a visitor
    # is told.
    #
    if flag("maintenance"):
        document["maintenance"] = {"message": text("maintenance_message")}
    if text("unavailable_message"):
        document["unavailable"] = {"message": text("unavailable_message")}

    headers = {
        phase: _header_edits(text(f"{phase}_headers"), phase) for phase in ("request", "response")
    }
    if any(headers.values()):
        document["headers"] = {phase: edits for phase, edits in headers.items() if edits}

    return dump_document(document)


def _routes(path: str, location: str, status: str) -> list[dict[str, object]]:
    """The object's routes: the pool, plus one redirect where the form asks.

    The preview builds one pool and one route, which is what the page is for -
    seeing what a shape produces. A redirect is the second route rather than a
    replacement for the first, because a redirect that took the whole object
    would be a site with nowhere to send anything.
    """

    routes: list[dict[str, object]] = [{"path": "/", "backend": "web"}]
    if not path and not location:
        return routes
    if not (path and location):
        raise ValueError("a redirect needs both a path and a location")
    if not status.isdigit():
        raise ValueError("the redirect status must be a number")
    routes.append({"path": path, "redirect": {"location": location, "status": int(status)}})
    return routes


def _header_edits(written: str, phase: str) -> dict[str, object]:
    """One line per edit, which is how somebody writes these by hand.

    `Name: value` sets, `+Name: value` adds another field with the same name,
    and `-Name` removes every one. Three shapes rather than three text boxes,
    because the edits belong together and reading them in one place is how a
    contradiction becomes visible.

    Nothing here decides whether a name or a value is usable - the engine does,
    and it is the same refusal a hand-written object gets.
    """

    assigned: dict[str, str] = {}
    added: dict[str, str] = {}
    removed: list[str] = []
    for line in written.splitlines():
        entry = line.strip()
        if not entry:
            continue
        if entry.startswith("-"):
            removed.append(entry[1:].strip())
            continue
        target = added if entry.startswith("+") else assigned
        name, separator, value = entry.lstrip("+").partition(":")
        if not separator:
            raise ValueError(
                f"every {phase} header line must be Name: value, +Name: value or -Name"
            )
        target[name.strip()] = value.strip()

    edits: dict[str, object] = {}
    if assigned:
        edits["set"] = assigned
    if added:
        edits["add"] = added
    if removed:
        edits["delete"] = removed
    return edits


def preview(form: dict[str, object], cluster: Cluster) -> Preview:
    """The whole page's content, or the one thing standing in its way.

    Every refusal below comes from the engine rather than from this module, so
    what the page says about an object is exactly what a publish would say
    about it.
    """

    try:
        document = build_document(form)
    except ValueError as exc:
        return Preview(problem=str(exc))

    try:
        proxy = load_proxy(str(form.get("name", "") or "").strip(), document.encode())
        files = generate(
            [proxy],
            vips=cluster.vips,
            default_vip=cluster.default_vip,
            certificates=cluster.certificate_ids,
            resolvers=cluster.resolvers,
            networks=cluster.networks,
            sources=cluster.sources,
            unknown_host=cluster.unknown_host,
            trusted_proxies=cluster.trusted_proxy_cidrs,
            abuse_protection=cluster.abuse_protection,
        )
    except (ModelError, GeneratorError) as exc:
        return Preview(document=document, problem=str(exc))

    return Preview(document=document, files=files)


def choices(cluster: Cluster) -> dict[str, object]:
    """What the form may offer, taken from the cluster rather than invented."""

    return {
        "vips": sorted(cluster.vips),
        "default_vip": cluster.default_vip,
        "certificates": sorted(cluster.certificate_ids),
        "sources": sorted(cluster.sources),
        "networks": sorted(cluster.networks),
        "balances": BALANCE,
        "health_types": HEALTH_TYPES,
    }
