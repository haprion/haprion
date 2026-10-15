# User manual

Using and administering an installed Haprion environment, through the web interface
and the authoritative command-line engine. For prerequisites, installation and environment
configuration, see the [installation guide](install.md).

Every name in this document is fictional. Substitute your own: the management host is `mgr`, the
clusters are `alpha` and `beta`, and each cluster has two nodes, `node-a` and `node-b`. Addresses
come from the documentation ranges in RFC 5737. Nothing here depends on those names — if a step
only works with the names used below, that is a bug in the software, not in this guide.

## Contents

- [Configuration and deployment](#configuration-and-deployment)
  - [A whole subdomain](#a-whole-subdomain)
  - [A pool's servers](#a-pools-servers)
  - [A pool over HTTPS](#a-pool-over-https)
  - [The client's address on a tcp pool](#the-clients-address-on-a-tcp-pool)
  - [A slow server](#a-slow-server)
  - [Drain and maintenance](#drain-and-maintenance)
  - [Addresses, and what to call them](#addresses-and-what-to-call-them)
  - [Ports the cluster takes itself](#ports-the-cluster-takes-itself)
  - [HTTP/3](#http3)
  - [DNS objects](#dns-objects)
  - [Syslog objects](#syslog-objects)
- [Accounts and signing in](#accounts-and-signing-in)
  - [What the two roles see](#what-the-two-roles-see)
  - [How a session works](#how-a-session-works)
  - [The throttle](#the-throttle)
  - [Signing in through an OpenID Connect provider](#signing-in-through-an-openid-connect-provider)
- [Features and advanced configuration](#features-and-advanced-configuration)
- [Certificates](#certificates)
  - [Publishing certificates](#publishing-certificates)
  - [Issuing a certificate](#issuing-a-certificate)
  - [The life of a profile](#the-life-of-a-profile)
  - [Deleting a certificate](#deleting-a-certificate)
  - [Importing a certificate](#importing-a-certificate)
  - [Enrolling and renewing through NDES](#enrolling-and-renewing-through-ndes)
  - [External certificates](#external-certificates)
  - [Registering a receiver](#registering-a-receiver)
- [Nodes and clusters](#nodes-and-clusters)
  - [Adding and removing a node](#adding-and-removing-a-node)
  - [Creating and removing a cluster](#creating-and-removing-a-cluster)
- [The interface certificate](#the-interface-certificate)
  - [Replacing it](#replacing-it)
  - [From the certificate registry](#from-the-certificate-registry)
- [Backups, and proving they restore](#backups-and-proving-they-restore)
- [Node backups](#node-backups)
- [Restoring a node onto an empty VM](#restoring-a-node-onto-an-empty-vm)
- [What a node keeps, and for how long](#what-a-node-keeps-and-for-how-long)
- [Keeping jobs, sessions and metric history bounded](#keeping-jobs-sessions-and-metric-history-bounded)
- [Traffic logs and metrics](#traffic-logs-and-metrics)
  - [A basic log viewer, on purpose](#a-basic-log-viewer-on-purpose)
  - [Sending the traffic log elsewhere, and metrics](#sending-the-traffic-log-elsewhere-and-metrics)
- [Jobs and status freshness](#jobs-and-status-freshness)
  - [Needs attention, and external monitoring](#needs-attention-and-external-monitoring)
  - [Events: jobs, the nodes and the audit record](#events-jobs-the-nodes-and-the-audit-record)
  - [How often status is refreshed](#how-often-status-is-refreshed)
  - [The worker](#the-worker)
- [Automation from the terminal](#automation-from-the-terminal)
  - [Automating with Ansible](#automating-with-ansible)
- [Maintenance](#maintenance)
  - [Keeping HAProxy current](#keeping-haproxy-current)
  - [Releasing a change](#releasing-a-change)
  - [CLI rollback](#cli-rollback)
  - [Rolling a release back](#rolling-a-release-back)
- [What it does not do](#what-it-does-not-do)
- [Environment reference](#environment-reference)
  - [The shape of a deployment](#the-shape-of-a-deployment)
  - [Prerequisites](#prerequisites)
  - [Part 1 — the management host](#part-1--the-management-host)
  - [Part 2 — the nodes](#part-2--the-nodes)
  - [Part 3 — the versioned CLI release](#part-3--the-versioned-cli-release)
  - [Part 4 — the web platform](#part-4--the-web-platform)
  - [Verifying the installation](#verifying-the-installation)
  - [What is still missing](#what-is-still-missing)

## Configuration and deployment

Editing produces a draft; saving it makes a saved change; publishing produces an immutable
release; deploying brings nodes to that release. Saved changes are published from *Versions*:
each cluster lists what is saved there, by whom, and publishes all of it with one comment as
one version (`changes_publish`, up to 64 objects). A change saved against an older version than
the newest holds the list until it is saved again. Where something is saved, the dashboard's
card offers *Publish & deploy N changes* instead of *Deploy configuration*: a dialog lists the
changes and takes the comment, and one job publishes and deploys - the worker runs the deploy
helper for the version the publish recorded, and the job ends as the deploy ends, with the
publish's answer kept beside it. A draft is unfinished work and is never
published. A saved change goes out with the next publish, and a draft may be started on top of
one without taking it out. *Save as draft* and *Save* in the editor are the two; *Save as
draft* returns to the editor and *Save* to the proxy list, where the row says *New*,
*Changed*, *Renamed* or *Removal* · *not published* until it is. The advanced
config dialog, a WAF exception and *Remove* save directly, and refuse while the object has a
draft. A rename that is saved records the published name it replaces, so the publish that
carries it removes the old name as well. The network description and a cluster's logs and
metrics settings are saved the same way, one document each per cluster: the page shows the
saved document, the object editor checks against a saved network (so an object may name a VIP
the same change adds), and *Discard the changes* drops it. The default VIP confirmation is
asked when the network is saved. Publishing and deploying are separate operations. On the dashboard,
*Deploy certificates* installs the certificates and *Deploy configuration* installs the
published configuration. A rollout deploys the nodes that do not own the VIP first and
the owner last - also when another node cannot be read, and a node whose ownership is
unknown goes between the two. Two nodes that both report the VIP stop the rollout
before anything is changed, whatever else could not be read, and no override lets it
past.

A node counts as running a release once HAProxy has reloaded it, not once the files are
in place: the node marks the switch in `/run/haprion-pull-deploy.pending` until the
reload, its status reports the release HAProxy still runs meanwhile, and the next deploy
finishes the reload of a run that was stopped in between. Each node gets five minutes
to answer a deploy; one that does not is a failed step, and its status decides what it
runs.

At the terminal, inspect the configuration and the nodes before deploying:

```bash
haprion-config-status -c alpha
haprion-status -c alpha
haprion-objects -c alpha
haprion-objects -c alpha --show <name>
haprion-deploy -c alpha
```

A converged deploy skips nodes already current. See the installation guide for
[cluster and network configuration](#cluster-definitions).

**Objects from files**, for automation. Each file is one object's document in the form the interface
stores (`haprion-objects -c alpha --show <name>` prints one), named by the file: `shop.yaml` is the
object `shop`. `apply` publishes what differs from what is stored as one version, against the version
it read, and says what it did; the same files again change nothing. An object no file names is left
alone unless `--prune` is given. `--check` shows the difference and publishes nothing; `--json`
answers with `changed`, and deploying stays its own step:

```bash
sudo haprion-objects apply -c alpha objects/ --check
sudo haprion-objects apply -c alpha objects/ -m "Add the shop"
sudo haprion-objects remove -c alpha staging
haprion-deploy -c alpha
```

More than 64 changed objects are published in batches of 64, each its own version. Every file is
read by the model the publish uses before anything is asked of the manager, so a mistake is named by
its file.

**Say what an object is for.** *Description* in the form's *Frontend* part is one line of at most
200 characters - what the service is and who to ask. The object's page shows it in the *Stored
object* card as *Description:*, and the search finds it. In YAML it is `description:` beside `name:`; nothing generated reads it,
so a publish that changes only the description deploys the same HAProxy configuration.

### A whole subdomain

One hostname may be `*.apps.example.com`: every name one label under `apps.example.com`, as a
wildcard certificate answers for them - `shop.apps.example.com`, not `apps.example.com` and not
`a.b.apps.example.com`. One per object, beside exact names if wanted; two objects cannot claim the
same one. A name another object claims exactly is that object's, wholly: its requests go there and
meet only that object's rules, and the subdomain object's page lists it under *Answered elsewhere*.
A name reserved in `manual/reservations.yaml` under the subdomain is refused at publish. Over https
the certificate must name the subdomain itself (`*.apps.example.com` in its SAN); ACME issues one
over DNS-01, NDES and an import as for any name.

### A pool's servers

The *Servers* field takes one `address:port` or `hostname:port` per line, and two words after
it where wanted, in either order:

```
198.51.100.10:8080 weight 50
198.51.100.11:8080
198.51.100.12:8080 backup
```

- **`weight N`**, 1 to 256, is the server's share of the pool's traffic against the others'
  (HAProxy's default is 1, so a pool written without weights shares evenly). A pool balanced
  with `first` refuses weights - that algorithm ignores them - and so do DNS and syslog pools,
  whose engines have none. Nought is refused too: it is a drain, something done to a server for
  a while, not a setting that outlives the reason for it. Changing a
  weight keeps the server's counters; changing its address or port starts it as a new server.
- **`backup`** makes it a standby: no traffic while any other server is up, all of it when none
  is. A pool cannot be all standbys.

The stored object spells both out (`weight: 50`, `backup: true`) under the server.

### A pool over HTTPS

*Backend TLS* says how the pool is reached:

- **HTTPS, verify the certificate** checks it against the node's own trust store, the one the
  operating system keeps (`ca-file @system-ca`): a certificate from a public CA.
- **HTTPS, verify against a CA** checks it against a CA certificate imported under *Certificates*
  and sent to the cluster ([Importing a certificate](#importing-a-certificate)):
  a service whose certificate the organisation's own CA issued. The node's trust store is not
  touched; the file is read by the pools that name it and by nothing else. The form's server test
  trusts the same CA as the node's check does: the manager sends its copy with the test, since the
  test runs on the node without access to the node's certificate directory. On the command line,
  `haprion-probe ... --tls --verify --ca <id>` does the same.
- **HTTPS, do not verify** encrypts and checks nothing.

Both verified choices need the servers named by hostname rather than address: the name is sent as
SNI and the certificate is checked against it. A pool that names a CA its cluster does not carry is
refused at publish, by name. In the stored object:

```yaml
backends:
  app:
    tls:
      verify: ca
      ca: corp-root
```

### The client's address on a tcp pool

An http pool is told who the client is in `X-Forwarded-For`. A tcp pool sees only the node's
address unless it is sent a PROXY header: *Send the client address (PROXY protocol v2)* in the
pool's group, `proxy_protocol: v2` in the stored object, `send-proxy-v2` on every server line.
The health check sends the header too (`check-send-proxy`), since a server that expects one closes a
connection that opens without it. The servers must be set up to read the header first - a mail
server, a database proxy, another HAProxy with `accept-proxy` - or every connection is refused.

### A slow server

HAProxy waits 50 seconds for a server to answer, and then gives the visitor a 504. The wait is
for silence, not for the whole answer: a download that streams for an hour is never cut, a report
that is computed for two minutes before its first byte is. *Server timeout* in the pool's group
gives one object a longer wait, up to 99 minutes - `server_timeout: 5m` in the stored object,
`timeout server` in the object's own backend. Empty is the 50 seconds. Nothing shared changes: the
visitor's own timeout on the VIP does not run while the visitor is waiting for the server.

A longer wait is also how long a server that has hung keeps its connections, so it belongs on the
object that needs it rather than on all of them.

### Drain and maintenance

Taking a server out for a while - patching it, replacing it - is not a change to the object.
It is set on the nodes, on every node of the cluster at once. On the object's page, the
**Servers** card lists each server with its state on each node, its open sessions and its weight;
tick the servers and press **Drain**, **Maintenance** or **Ready**. The same from the command line:

```
sudo haprion-server-state -c alpha -o shop drain 198.51.100.10:8080
sudo haprion-server-state -c alpha -o shop ready 198.51.100.10:8080
```

- **`drain`** takes the server out of load balancing. A visitor whose session cookie names it
  still reaches it, and it is still health-checked.
- **`maint`** sends it nothing new at all, and stops its health checks.
- **`ready`** puts it back.

Requests already in flight finish in both; nothing is cut off. A server is written as on its line
in the editor, `address:port`; where one object has the same server in two pools, name the pool
first - `api/198.51.100.10:8080`. Every server is looked up in the object's newest version before
any node is asked, so a request with one wrong server in it changes nothing.

Each node keeps the state through deploys, certificate rollouts and restarts until it is set to
`ready` again - a deploy does not quietly put a drained server back. A server that has been given a
new address or port is a new server and starts ready. One node that did not answer is named, and
the result is `PARTIAL`: the other node holds the state, and running the same command again
finishes it. A node that does not run the server yet - published but not deployed - says so.

The card shows a node's own answer: `DRAIN` and `MAINT` for a server somebody took out, otherwise
`UP` or `DOWN` from the health check. An object that leaves from a source address is checked only
by the node holding the VIP, since only that node has the address; the other node reads `BACKUP`, as keepalived calls it. While the nodes are not yet on the object's newest version
the states are not shown, since a pool edited since the deploy may have its servers in another
order. A node that keeps a drain or maintenance it could not put back after a reload or a start - its
HAProxy did not answer in time, or the admin socket is missing - reports it, and the card reads
`DRAIN LOST` or `MAINT LOST` in red on that node: the server takes traffic there. Press the button
again; the deploy itself is not undone. A drained server is not a fault: the Proxies listing does not turn amber for it, and says
how many are drained or in maintenance when you point at the lamp.
The dashboard says on each cluster's card how many servers are in drain or maintenance, so one
left that way is not forgotten; an admin's *Operations* row names the objects, three of them and how
many more, each linked to its *Servers* card. A state the node keeps but HAProxy does not hold is
not counted there - that server takes traffic - and is said on the card in red.

### Addresses, and what to call them

If you arrive from a NetScaler or an F5, three addresses are worth naming before anything else,
because only one of the three has a word that every product agrees on.

| What it is | Here, and in HAProxy | In keepalived | NetScaler | F5 |
|---|---|---|---|---|
| the address clients connect to | `vip`, bound by a frontend | `virtual_ipaddress` | VIP | virtual server address |
| the address we connect out from | `source`, per backend | `virtual_ipaddress`, same block | SNIP | SNAT address / self IP |
| the node's own fixed address | not named; it is just the host | `unicast_src_ip` | NSIP | management address |

Two things follow from the middle row, and both matter more than the vocabulary.

**Keepalived has no separate concept for an outgoing address.** To it, both are entries in the same
`virtual_ipaddress` block - and they belong in the same block, because only the node currently
holding an address answers for it. A source address that does not move together with the VIP sends
its replies to a node that no longer carries the traffic, and that failure appears at failover
rather than at configuration time.

**HAProxy takes the source per backend, not per listener.** A site may therefore leave from a
different address than the one it arrived on. Each VIP still names a default source, so the normal
case needs no words; the [`sources` table](#optional-per-cluster-sections) exists for the exception.

`unicast_src_ip` is spelled out in full everywhere in this document. It is the node's own address,
it never moves, and confusing it with a source address produces a cluster that looks correct and
cannot fail over.

**What uses an address.** *Network* lists, beside each VIP, source address and reachable-from
group, the objects that use it - three by name, then how many more - so a change to a shared
address or group shows what it touches before it is saved. A VIP counts the objects served on it,
a source address the objects that leave from it (its VIP's or one named), and a group the objects
that name it as a source anywhere: who may reach them, who is refused, an access rule or dynamic
blocking's exempt. *not used* is a value nothing names; a dash means the objects could not be read.

### Ports the cluster takes itself

A VIP carries its objects' ports and nothing else: what the cluster runs for itself listens on
the nodes' own addresses or on loopback, so a tcp, DNS or syslog object may take any port its VIP
does not already serve. A publish refuses only:

| Port | Why |
|---|---|
| 80 and 443 | on a VIP that serves http or https objects |
| a port another object takes on the same VIP | one address and port is bound once |
| a port `manual/reservations.yaml` reserves | the handwritten half binds it |
| a port another program holds on every address of a node | it holds the VIP's port too |

The Prometheus exporter, dnsdist's statistics (9521), the shared counters' port and the WAF
engine (9520, loopback) never take a VIP's port. The last row is the nodes' own answer: a
publish that changes objects or the network reads each node's status, and the refusal names the
program and the node - *agent listens on main port 6556/tcp, which cmk-agent-ctl holds on every
address of lb-01*. Have the program listen on the node's own address, or choose another port. A
node that does not answer does not stop the publish; the result names it under
`ports_unchecked`, and the deploy still rolls back if the port is taken there. `haprion-status`
on a node shows the same list as *Every address*.

### HTTP/3

*Network*, a VIP's row in edit mode: *HTTP/3* serves the https sites on that address over QUIC
as well, on UDP at the https port, with the same certificates and TLS version. Every answer over
TCP then carries `alt-svc: h3=":443"; ma=86400`: a browser that can reach UDP moves to HTTP/3 and
remembers it for a day, and one that cannot goes on over TCP without a sign of trouble. It is the
VIP's and not an object's, since the UDP listener is the address's and every site on it shares it;
an https object's page says *HTTP/3 on VIP …*. Access rules, blocking and the WAF act on the
request, so they apply over HTTP/3 as over TCP.

QUIC carries TLS 1.3 alone, so a VIP whose TLS version is *TLS 1.2 only* refuses it, and a dns or
syslog object that takes the same UDP port on the same address is refused at publish. Outside the
interface, UDP to the https port has to be open to the VIP in the nodes' firewall and, for clients
outside, forwarded by the outer firewall; until it is, nothing breaks - clients try QUIC, get no
answer, and stay on TCP. A connection over QUIC is cut by a failover as a TCP one is, and the client
connects again.

### DNS objects

An object whose protocol is *DNS* is served by dnsdist on the same nodes and VIPs, on
UDP and TCP, port 53 unless another is written. The form offers DNS once every node of
the cluster reports dnsdist installed; a node without it refuses a release that carries
a DNS listener. The pool's servers are addresses or host names with a port, and the list
shows the names. dnsdist takes addresses only, so a name is looked up on the manager when
the object is **saved**, by asking `haprion-resolve-helper` over
`/run/haprion/resolve.sock` (the web service itself reaches nothing past
localhost), and the address is stored in the object beside it:

```yaml
servers:
  - host: dc1.example.com
    port: 53
    address: 192.0.2.53      # written when the object was saved
```

A name that gives no address, or several of one family, refuses the save. Publishing looks
nothing up: it writes the stored address, so publishing something else - a log target, a
neighbouring object - never moves a DNS server and never fails because DNS does. A name
stored without an address refuses the publish with *save the object again*; an object
written by hand gives the `address` itself. The address is the one the name had when the
object was saved: `haprion-status` and the object's page say when the name has since moved,
and *Look up again* beside that warning saves the object with the address the name has now,
for the next publish. The stored `address` came with engine API 21; before it, every
publish looked every name up. The balancing is one of dnsdist's - `roundrobin`, `leastOutstanding`,
`firstAvailable` (the first server that is up: active/passive, since dnsdist has no backup
server) and `chashed` (one name keeps one server) - and the health check asks every
server a real question, `a.root-servers.net.` for `A` unless another is given, once a
second by default. *Test health check* asks that question from the nodes before the
object is saved, as dnsdist does: an answer counts unless it is SERVFAIL (NXDOMAIN and
REFUSED count), and a named server is asked at the address the manager looks it up to.
*Reachable from* is who may ask; anybody else is answered REFUSED.
What is HAProxy's - TLS, rate limits, deny lists, the WAF engine, maintenance, headers,
advanced config - is not offered, and refused if written by hand. The client's address
reaches the servers behind as EDNS Client Subnet, so a Pi-hole's per-client limits and
logs see each client rather than the node.

**One DNS object per address and port.** dnsdist tells its objects apart by the
address and port a query arrives on, so two DNS objects cannot share a VIP on port 53,
and the form refuses the second. Two DNS services - the domain controllers and a pair of
Pi-holes, say - need a VIP each: add one on the Network page, publish and deploy it,
and choose it on the second object. No DNS name is needed for it; clients are given a
resolver by address anyway. Another port on the same VIP works only for clients that
can be told to ask on it, which few can.

### Syslog objects

**What a syslog object cannot do, first:**

- **UDP only.** Syslog over TCP or TLS is not forwarded; senders that use it send
  straight to the receivers.
- **No list of who may send.** Every packet that reaches the address and port is
  forwarded. Protect the address in front of the nodes, with the firewall that guards
  the network it is on.
- **The network has to let the senders' addresses through.** A message leaves the node
  with the node's own MAC address and the *sender's* IP address, so the receivers see
  who sent it. Anything that filters on a source IP address between the nodes and the
  receivers drops it: the Proxmox firewall's *IP filter* on the node's network card,
  a switch's *IP Source Guard*, and uRPF or anti-spoofing on a router when the
  receivers are in another network. Filters on the MAC address - VMware's *forged
  transmits*, Proxmox's MAC filter - are not affected. Nothing has to route back
  through the nodes: syslog over UDP is never answered.
- **A udp check cannot see such a filter.** It counts a receiver down only when the
  receiver's host answers that nothing listens; a datagram dropped on the way gets no
  answer, so a receiver behind a firewall that drops it reads as up. Use a *tcp* check
  where the receiver also listens on TCP, or send a test message and look for it.
- **The receivers are addresses**, in the VIP's address family, with a port. There is
  no standby receiver; *firstAvailable* is how a pool says active/passive.

An object whose protocol is *Syslog (UDP)* is forwarded by the kernel's IPVS,
configured by keepalived on the same nodes and VIPs, on port 514 unless another is
written. The form offers it once every node of the cluster reports that
`keepalived.conf` includes `/etc/keepalived/ipvs.conf` at its top level - see
[Installing Haprion](install.md#5-install-optional-components); until then the
choice is greyed out. A node without the include refuses a release that carries a
syslog object, `haprion-status` says *NOT FORWARDING* there and counts the node as
not running its release, and the object list shows *Include missing* with the node. A syslog object shares a port number
with tcp objects and the cluster's own ports, which are TCP, but not with a DNS object
or another syslog object on the same VIP.

The balancing is one of three: *roundrobin* (message by message, in turn), *source*
(one sender keeps one receiver, and when a receiver goes only its senders move) and
*firstAvailable* (every message to the first receiver in the list that is up). The
health check is keepalived's: *udp* sends a datagram to the receiver's port and counts
it down when the receiver's host answers that nothing listens there - a host that is
gone altogether is noticed when the node stops finding it on the network, about
fifteen seconds; *tcp* connects to a port of the receiver's, its own unless another is
given, and nothing more. With no check, a receiver is never taken out. There is an
interval and *Checks to fall*, but no *Checks to rise*: one passing check puts a
receiver back. The form suggests *udp* when the protocol is chosen. *Test health
check* tries the check from the nodes' own addresses, as keepalived does, and shows the
answer of the node holding the VIP: *udp*
sends one empty datagram and waits five seconds for a refusal - keepalived's own wait -
and says *not refused* when none came; *tcp* connects and closes. On the command line,
`haprion-probe -c <cluster> -t <address:port>[,...] --udp` asks the same.

The editor's *What the nodes report* and the lamp in the object list show each
receiver up or down, as keepalived on the node holding the VIP sees it - the node the
messages pass, as for every other object. The object's metrics are
messages and bytes, per pool and per receiver, counted by IPVS on the node that holds
the address; a receiver taken out and put back starts counting from nought, and the
interval it happened in has no figure rather than a wrong one. No message is stored.
What is HAProxy's - TLS, rate limits, deny lists, a source address, the WAF engine,
maintenance, headers, advanced config, cookies and connection limits - is not offered,
and refused if written by hand.

## Accounts and signing in

The installation creates the first break-glass administrator; see
[First administrator](#first-administrator).

Further accounts are a local root action too, or an admin's in the interface
(below):

```bash
sudo haprion-user add operator --role admin
```

The password is typed at the terminal, twice, and there is deliberately no flag
to pass it as an argument — that would put it in the shell history and the
process list. For automation, `--password-stdin` on `add` and `reset` reads it
as one line from a pipe instead.

An account name is at most 64 characters, with no line breaks, invisible
characters or spaces at either end. It is what a version records as who
published it, so the tool, the Users form and a first sign-in through the
provider all refuse a name that could not stand there.

The same tool is the break-glass path when the only administrator is locked
out, forgotten, or gone. An account it creates is a **break-glass** account
unless `--no-break-glass` is given: one that signs in with its password even
while sign-in goes through an OIDC provider (schema `0041`).

| Command | What it does |
|---|---|
| `add <user> --role admin\|reader [--no-break-glass] [--password-stdin]` | create an account |
| `init-admin` | create `admin`, a break-glass admin, if there is no account at all |
| `delete <user> --yes` | remove an account and its sessions for good; without `--yes` it only says what it would do |
| `break-glass <user> [--off]` | mark a local account break-glass, or unmark it |
| `reset <user> [--password-stdin]` | set a new password **and end every session that account has** |
| `role <user> admin\|reader` | give a local account another role |
| `disable <user>` | block sign-in and end every session |
| `enable <user>` | allow sign-in again |
| `unlock <user>` | clear the sign-in throttle |
| `revoke <user>` | end every session without changing the password |
| `list [--json]` | accounts, roles, kind (`local`, `break-glass`, `sso`), and how many live sessions each has |
| `apply <file> [--prune] [--check] [--json]` | the accounts a file lists, written where they differ (below) |

Reset and disable revoke sessions on purpose. An account that cannot sign in
again while its existing cookie keeps working has not actually been taken back
from whoever had it, which is usually why either command is being run.

**Accounts from a file**, for automation. `apply` reads a list of accounts and writes only what
differs from what is stored, through the same code and database guards as the Users page: the last
active admin, and the break-glass admin provider sign-in needs, are refused here too, and nothing of
a refused file is written. A password is compared with the stored one, not set again, so the same
file twice changes nothing; a changed one ends that account's sessions, as `reset` does. The file
carries passwords and is refused unless only its owner may read it (mode `0600`). An account the
provider created takes only `disabled` from the file. One no entry names is left alone unless
`--prune` is given, which removes local accounts only. A new account is not break-glass unless the
file says so.

```yaml
accounts:
  - username: admin
    role: admin
    break_glass: true
    password: "from the vault"
  - username: viewer
    role: reader
    disabled: false
```

```bash
sudo haprion-user apply accounts.yaml --check
sudo haprion-user apply accounts.yaml --json
```

Anyone signed in, reader or admin, can also change their own password from the
account menu (**Change password**). It asks for the current password, and a
wrong one counts as a failed sign-in for that name and address, under the same
throttle, so a session someone else is holding cannot be used to guess it. The
change ends the account's other sessions and keeps the one it was made from; it
is recorded as `password_changed` with `via: web`.

An admin manages the other accounts under **Settings → Users**, on
installations with `management_writes` on: add, change role, disable and
enable, set a new password, mark break-glass, end sessions, unlock and delete —
the same verbs as the table above, recorded under the same audit names plus
`role_changed`, `break_glass_changed` and `account_deleted`, with the admin as
actor and `via: web`. The signed-in admin session is the proof; no second
password is asked. A new role, a new password and the break-glass mark are saved
together, in one transaction. Delete asks first, on its own page. The admin's
own account is not changed there.

The database refuses to leave no active admin, from either path: the last one
cannot be demoted, disabled or deleted. Since `0041` the web role holds `delete`
on the account table — the one table where an application role does. Sessions
go with a deleted account; jobs and the audit trail name it as text and keep
it. An account that signs in through an OIDC provider has no password here, and
its role comes from the provider.

The tool reads the database name and the role to connect as from a root-owned file written by
`02-platform-database`, `/etc/haprion/ui-admin.conf`, so it cannot be pointed at another
database by an environment variable or a working directory.

**Root connects as the migration role**, the one that owns the schema, so the
tool works when nobody can sign in. The web role may write accounts too (schema
`0039`): name, hash and role on a new one; role, `disabled` and hash on an
existing one — never `created_at` or `updated_at`, which the database
sets, and never a delete. **The database refuses to leave no active admin**,
from either path: demoting or disabling the last one fails, under a lock, so two
admins disabling each other at once cannot both succeed. The break-glass answer
to a lost last admin is `add`.

### What the two roles see

A **reader** sees every page and can press nothing. An **admin** can queue the
operations the interface offers, and sees two things a reader does not.

- **The error code** of an operation that did not end cleanly — the stable,
  environment-independent string the engine blamed, such as
  `cluster_not_converged` or `ssh_unreachable`. It is shown verbatim rather than
  translated, and it is the same string the command line prints beside its
  message and the audit trail records, so what a terminal said and what the page
  says can be compared without guessing.
- **The operation's diagnostics** — its redacted stderr, folded away under the
  job until asked for. Private keys, `token`/`password`/`secret` assignments and
  sensitive paths are masked before the text is ever stored, and it is capped at
  64 KiB.

The diagnostics contain **real host names, node names and the proxy's own
output**, which is what makes them worth showing. Masking covers secrets, not
the identity of the environment. So: a screenshot of that panel does not belong
in an issue, a README, a support ticket or anywhere else outside the
installation.

Withholding raw diagnostics from a *reader* is what the contract requires;
withholding them from an administrator as well was a habit that cost the one
person who had to open an SSH session at every failure, and bought nobody
anything in an installation where the reader and the administrator are the same
person.

### How a session works

- **Passwords are Argon2id**, with parameters stated in the code rather than
  taken from library defaults, and a database CHECK refuses any hash that is not
  Argon2id. Changing algorithm has to be a migration, not a dependency upgrade.
- **The session token is opaque and lives only in the cookie.** The database
  stores its SHA-256 hash, so `app_session` read by anything — a dump, a backup,
  a mistake — cannot be replayed as a login. There are no claims in the token and
  no signing key to leak.
- **Cookies are `Secure`, `HttpOnly` and `SameSite=Lax`.** Lax rather than
  Strict, so arriving from a link in a mail or a dashboard still works, which is
  a normal way to reach an operations interface.
- **Two clocks, not one.** Roughly ten hours of inactivity ends a session, and an
  absolute lifetime caps one kept warm by a forgotten browser tab. The web role
  holds no `update` on `expires_at`, so use can move the first clock forward and
  nothing can move the second.
- **CSRF tokens are derived from the session token**, not stored. Producing one
  requires the cookie, which a cross-site form post can make a browser send but
  cannot read. The login form itself is protected the same way, by a short-lived
  cookie scoped to `/login`.
- **A new token on every login**, so nothing a browser held before signing in is
  still valid after.

### The throttle

Failed sign-ins are counted per normalised username **and** client IP together.
Per username alone would let one attacker lock every real user out; per IP alone
would let one address work through a list of names.

The attempts table is **append-only by grant** — the web role can add a row and
read rows, and holds no update or delete. A counter the web process could reset
would be a lock whose key is kept behind the door. An unlock therefore deletes
nothing: `haprion-user unlock` (and, for an admin, the interface) adds a row
to `login_unlock`, and the throttle counts failures since the latest success or
unlock for that name. The failed attempts stay in the record.

The client address is taken from `X-Forwarded-For`, which the nginx site
*overwrites* rather than appends to, so a request cannot contribute its own. An
address that will not parse falls back to loopback rather than becoming an
unthrottled bucket of its own.

Every sign-in, failure, sign-out and account change is written to the audit
trail, in the same transaction as the thing it describes. What the login page
says, on the other hand, is one sentence for every kind of failure — unknown
account, wrong password, disabled account and throttled address are
indistinguishable from outside, and the same amount of time is spent on each.

### Signing in through an OpenID Connect provider

Sign-in through a provider — authentik, Keycloak, Entra ID, ADFS, Authelia,
Okta, Zitadel, or any other that follows OpenID Connect Core and Discovery —
arrives in parts (schema `0041`). What is installed first is the path to the
provider, and it does not go through the web service.

The web service reaches localhost and nothing else (`IPAddressDeny=any`), and
keeps doing so. Every request to the provider goes through
`/run/haprion/oidc.sock` to `haprion-oidc-helper`, installed by platform
step 17. It runs as an account of its own (`OIDC_USER`, the identity policy's
`roles.oidc`), not root, and is the one part that may reach the network. It
takes no URL from the web: the issuer comes from the settings, every other
address from that issuer's own discovery document, over verified TLS — the
system's authorities plus, when set, a CA certificate pasted into the
settings. It follows no redirect, uses no proxy from the environment, and
bounds every answer to ten seconds and one megabyte.

The client secret is sealed by the web against the public key step 17 made,
and only the helper opens it. The sealed text names the issuer and the client
it was saved for, and the helper refuses to open it for any other: changing
the issuer means typing the secret again, so a session that changes where
sign-in goes cannot also send the old secret there.

The helper verifies the id_token as OpenID Connect Core lays out for the authorization code flow (section 3.1.3, step 7) —
signature (RSA, RSA-PSS or ECDSA against the provider's key set; HMAC with the
client secret, which authentik uses when no signing key is chosen; never
`none`), issuer, audience, `azp`, expiry with one minute's leeway, and the
sign-in's own nonce. Userinfo is added when it names the same subject and
ignored otherwise; it is never a reason to refuse. Names and groups are read
from the claims the settings name, as a dotted path (`realm_access.roles`); a
claim that is an object counts as its keys. A provider that sends a pointer to
the groups instead of the groups (Entra's overage, above 200 groups) is refused
with a sentence that says to use app roles.

The role is read from the groups at every sign-in through the provider, and
not between two of them. A session made that way therefore ends after at most
`oidc_absolute_hours` (under `[session]` in `ui.toml`, default 10), whatever
the activity, so a group taken away at the provider stops counting here by
then. The provider's own token lifetime is not used for this; to end someone's
access sooner, **Revoke sessions** on the account does it at once.

An account through the provider is made at its first sign-in, by the role its
groups give; there is no list of them to keep here, and none is made in advance
(schema `0072`). Who may sign in is decided in the provider's groups. It is
bound to the issuer and the subject it first signed in with, not to its name. Changing the issuer — another provider,
or the same provider's application under a new name — therefore leaves every
such account bound to the old one, and sign-in says so. Remove those accounts
under **Settings → Users**; each is made again at its next sign-in.

#### Examples: three providers

In every case the provider gets a confidential client (one with a secret),
the authorization code flow, and exactly one redirect URI: the one the
settings page shows, `https://<SERVER_NAME>/login/oidc/callback`. The issuer
must be typed exactly as the provider states it — **Verify** says so when it is
not, and quotes the provider's own value. Menu names change between provider
versions; what matters is what ends up in the id_token, which **Test sign-in**
shows.

**authentik** (checked against 2026.8)

- Applications → New Application, provider type OAuth2/OIDC, client type
  confidential, redirect URI in strict mode, a signing key chosen (RS256).
- Issuer: `https://id.example.com/application/o/<application slug>/`, with the
  trailing slash. The provider's page shows the discovery URL ending in
  `/.well-known/openid-configuration`; the issuer is what comes before it.
- Scopes, claims: the defaults here (`openid profile email`,
  `preferred_username`, `groups`). authentik's `profile` scope carries the
  groups by name.
- Groups: authentik's own, or those an LDAP source synchronises from Active
  Directory; the claim carries the group's name as authentik shows it.
- Binding the application to the two groups keeps everyone else out at the
  provider as well.

**Keycloak**

- Clients → Create client, OpenID Connect, client authentication on, standard
  flow on, the redirect URI under valid redirect URIs.
- Issuer: `https://id.example.com/realms/<realm>`.
- Groups: add a *Group Membership* mapper to the client's dedicated scope with
  token claim name `groups`, added to the ID token. With *Full group path* on,
  which is the default, groups arrive as paths — type the admin group as
  `/haproxy-admins` here, or turn the option off and type `haproxy-admins`.
- Username claim: `preferred_username` (the default here).

**Microsoft Entra ID**

- App registrations → New registration, platform *Web*, the redirect URI, and
  a client secret under Certificates & secrets.
- Issuer: `https://login.microsoftonline.com/<tenant ID>/v2.0`.
- Groups: Token configuration → Add groups claim. By default the claim carries
  group **object IDs**, not names; type the IDs as the admin and reader
  groups, or, for groups synchronised from on-premises AD, choose
  `sAMAccountName` for the ID token. Someone in more than 200 groups gets a
  pointer instead of the groups, which is refused; choose *Groups assigned to
  the application*, or use app roles with the groups claim set to `roles`.
- Username claim: `preferred_username` (the user's UPN).

The settings are an admin's, under **Settings → Users → OIDC configuration**,
on installations with `management_writes` on: issuer, client ID and secret,
client authentication (`client_secret_basic` or `client_secret_post`),
scopes, the claims for the name and the groups, the admin and reader groups,
the button text, sign-out (this interface only, or also at the provider),
local sign-in (break-glass accounts only, or all), an optional CA
certificate, and whether the
provider is always asked to sign in again. The redirect URI to register at the
provider is shown there, to copy. The web's `ui.toml` names the public key
step 17 made (`[oidc] public_key`, added by the step); without it the page says
the helper is not installed.

**Verify** asks the helper: discovery against the issuer, the key set, the
client's method, the signing algorithm, and whether the provider accepts the
client and its secret — by sending a code that was never issued, which a
provider answers with `invalid_grant` when it accepted the client and
`invalid_client` when it did not. Each check is listed. The database records
the revision that passed, and every change to the settings raises the
revision, so sign-in through the provider can be turned on only at settings
that passed Verify, and only while an active admin is break-glass. Saving
while it is on runs Verify first and saves as verified, or saves nothing.
Each change is audited (`oidc_configured`, `oidc_verified`, `oidc_enabled`,
`oidc_disabled`); the secret never is.

**Settings from a file**, for automation: `haprion-settings` on the manager, as root, sets what
*External monitoring*, *Features* and the OIDC configuration set, through the same code and the same
refusals, audited with `via: cli`. Each of the three sections is optional, and one the file leaves
out is left alone; only what differs from what is stored is written, so the same file twice changes
nothing. `--check` says what would change and keeps nothing; `show --json` prints what is set, the
client secret never.

```yaml
status_access: [192.0.2.10, 198.51.100.0/24]   # [] switches /status/ off
features:
  node_backups: true
  advanced_config: false
oidc:
  issuer: https://idp.example.com/realms/main
  client_id: haprion
  client_secret: "from the vault"
  auth_method: client_secret_basic
  scopes: openid profile
  username_claim: preferred_username
  groups_claim: groups
  admin_group: haprion-admins
  reader_group: haprion-readers
  button_text: Sign in with SSO
  prompt_login: false
  logout_mode: app                 # app or provider
  local_login: break_glass_only    # break_glass_only or all
  enabled: true
  interface_url: https://mgr.example.com
```

```bash
sudo haprion-settings apply settings.yaml --check
sudo haprion-settings apply settings.yaml --json
sudo haprion-settings show --json
```

The provider's settings are what the configuration page saves; `enabled` is its *On* and *Off*,
and turning it on runs Verify first, as the page does - with `interface_url`, the address people sign
in at, for the redirect URI the page would take from the browser. Settings saved while sign-in is
off stay saved when Verify then fails, and the command says why it did not turn on. The client
secret cannot be compared with the stored one, which is sealed for the helper, so it is stored when
none is, when the issuer or the client changes, or with `--replace-oidc-secret`; otherwise the
stored one is kept and the answer says `"sealing": "kept"`. A file that carries it is refused unless
only its owner may read it (mode `0600`); `--oidc-secret-stdin` reads it from one line on standard
input instead.

## Features and advanced configuration

Two capabilities can be turned off under **Settings → Features** (schema
`0040`), by an admin on an installation with `management_writes` on. Off hides
the capability's tab, pages and operations; a kept URL answers 404. Both are
off on a new installation, which enables no backup timer either; an
installation opts in.

- **External certificates**
  off hides the receivers page, the receiver choices in the certificate forms
  and in *Publish to…*/*Remove from…*, the certificates page's second view,
  and *External certificate* with its downloads and key export.
  Receivers already registered go on getting renewed certificates, and a
  certificate's *Used by* still names them; external certificates stay in the
  registry and are renewed as before.
- **Node backups** off also stops every cluster's backup timer: one
  `backup_schedule` job per running timer, with its schedule unchanged and
  `enabled: false`. The schedules it stopped are remembered, and turning it on
  starts exactly those again. Archives already taken are kept. It is refused
  while a cluster has a job running, while a restore is running or waiting,
  and for a cluster whose schedule the form cannot write back.

`haprion-state-backup` and the restore commands on the manager work either way. `haprion-settings
apply` flips the switches from a file, with the same refusals (*Settings from a file*, above).

A third switch, **Cluster colours** (schema `0042`), is on from the start and
hides nothing: it draws the rule down each cluster card's left edge, one of six
colours handed out in the order `clusters` lists them in `ui.toml` — the order
the dashboard draws the cards in, so reordering that list reorders both. With
more than six clusters it is off and cannot be turned on; the name stands
beside every card either way.

A fourth, **Advanced config** (schema `0049`), is off from the start. On, an
object's page has an *Advanced config* button between *Edit* and *Remove* that
opens a dialog for HAProxy configuration pasted as a layer on top of the
object; the object stores it as `advanced` in its YAML. Off hides the button
and the dialog only: an object that has text keeps it, its page says so, and
the generator writes it on every publish, because what a cluster runs must not
depend on an interface setting.

What the layer does, line by line (`haprion-objects -c alpha --advanced <name>`
prints the same answer as the dialog's *Check*):

- Lines outside a section, and under the text's own `frontend` or `listen`, are
  the object's: an http object's go to every pool it has, a tcp object's to its
  frontend where HAProxy takes the keyword there and to its pool otherwise.
  They are written **after** the generated lines of the same section, so the
  cluster's abuse brake and the object's rate limit run first.
- `backend`, `cache`, `http-errors`, `userlist` and `ring` sections are written
  as they stand, under a name that must begin with `<object>-`. A section named
  otherwise is refused, not renamed: other files may refer to it.
- Refused outright: `global`, `defaults`, `program`, `peers`, `resolvers` and
  `mailers` sections; `use_backend`/`default_backend`, `bind`, `guid`, and
  `source`/`usesrc` (also as a server parameter) — routing, listening and the
  outgoing address are the form's; a keyword HAProxy would ignore in that place;
  `track-sc0` (the cluster's counter), `track-sc1` while the object's rate limit
  is on (the limit's counter), `track-sc3` and `track-sc4` while its dynamic
  blocking is on; a `stick-table` on the object's own lines (its
  pool already carries the rate limit's). The text counts on `sc2`, with tables
  in a backend of its own: `track-sc2 src table <object>-logins`. Reading `sc0`
  and `sc1` is allowed.
- `mode` is skipped (the form sets the protocol), and so are lines that set what
  the form owns for the pool — servers, balancing, health checks, cookie, and
  the connect, server, queue, tunnel and check timeouts — while the form writes
  the pool. Ticking
  *The text writes the pool* hands the object's one pool to the text instead:
  the YAML keeps `servers: []` and nothing else, the form shows no pool fields,
  and the text must carry at least one `server` line. Unticking gives the pool
  back with the text's `server name host:port` lines as its servers.

## Access rules

An object can refuse visitors by address, by what a request asks for, and by
the size of what it sends. The keys sit in the object's YAML beside
`allow_from`; the generator writes them into the shared frontend after
`allow_from` and before anything is routed.

```yaml
deny_from:                       # http and tcp
  mode: log                      # log (the default) or deny; tcp takes deny only
  sources: [scanners, 203.0.113.0/24]
deny_rules:                      # http only; tried in order, any one is enough
  - name: admin-post             # lowercase, shown on the traffic record
    mode: deny
    path: /admin                 # prefix by default; match: exact for one path
    methods: [POST, PUT]
    header: {name: User-Agent, contains: sqlmap}   # equals, prefix or contains
    source: [office]
    source_negate: true          # all but these sources; needs source
max_request_body: 10m            # http only; k, m and g are 1024-based
```

Every condition a rule names must hold; `source_negate` turns the source into
"from anywhere but these": the rule above refuses a POST or PUT under `/admin`
whose User-Agent contains `sqlmap`, from anyone outside `office`. A rule that names no condition is refused,
since it would refuse everything the object serves. Header values are matched
as text, never as patterns.

**A rule's path is read as the least strict backend will read it**: percent-decoded, with runs of
slashes made one, as nginx matches its locations; in lower case, as IIS ignores case; with
`;parameters` cut from each segment, as Java servers do; and with dots and spaces cut from a
segment's end, as Windows does. `/%61dmin`, `//admin`, `/admin%2Fusers`, `/Admin`, `/admin;x` and
`/admin.` all meet a rule on `/admin`. A path with a `.` or `..` segment once decoded - `/./admin`,
`/x/../admin`, `/%2e%2e/admin` - is answered 400 and recorded `path-dots:deny`, and one with a
control character - `%00`, a line break - is answered 400 and recorded `path-chars:deny`, on an
object with a refusing path rule (`:log` when its path rules only look); browsers send neither. The
backend still receives the path as it was sent. A rule's own path is therefore written decoded,
without `%`, `//`, `;`, `.` or `..` and with no segment ending in a dot; its case does not matter.
Behind a backend that does tell `/Admin` from `/admin`, a rule on one refuses both.

**Countries.** Wherever a group or a range may be named - `allow_from`,
`deny_from` and a rule's `source` - a country may be too, as `country:SE`
(two letters, as ISO 3166 spells them). Publishing reads the networks of each
country an object names from the IPFire Location database on the management
host and writes them to `managed/maps/geo-se.lst`; the nodes receive the file
with the release, in `maps/`, as they receive every map file. A country the
database does not know refuses the publish.

The database is installed and kept current on the management host:

```bash
sudo apt install location python3-location
sudo location update
sudo systemctl enable --now location-update.timer
```

The timer fetches a new, signed database once a day. A cluster takes it up at
its next publish, whatever that publish changes, and not on its own; *Settings → Location data* shows the
database's date and, for each cluster that names a country, the date its
published lists were made from. The data is IPFire Location, licensed under
CC BY-SA 4.0 (https://location.ipfire.org); each generated file names it in
its first line.

**Look before refusing.** A new rule starts in `log`: the request is served,
and the rule's name is written on its traffic record as `admin-post:log`. In
`deny` the visitor gets 403 and the record says `admin-post:deny`. The first
logged rule a request meets is the one recorded; a refusal always names
itself. `deny_from` is recorded as `deny-from`. On a tcp object there is no
traffic record for a logged match to appear on, so `deny_from` there must say
`deny`.

**Behind a trusted proxy** (the cluster's `trusted_proxies`), every address
condition — `allow_from`, `deny_from` and a rule's `source` — reads the
visitor from the last `X-Forwarded-For` element, as the rate limit counts it.
Before engine API 10, `allow_from` read the connection, which behind a proxy is
the proxy itself; an object restricted that way admitted everything that came
through it, and now admits only the visitors it names. A request from the
proxy with no header has no visitor address: `allow_from` refuses it and
`deny_from` lets it pass.

**The body limit holds the declared size.** A request that says how long its
body is gets 413 (`body-limit:deny`) when that is more than the limit. A
chunked request declares nothing, and HAProxy sees only what fits in its
buffer (16 kB by default, `tune.bufsize`); such a body is refused if what has
arrived is already over the limit, and otherwise let through and marked
`body-unbounded:log`. Browsers send the length with forms and uploads; the
mark shows whether anything else reaches the object. The hard limit for a
chunked body is the backend server's own, such as nginx's
`client_max_body_size`.

Stick tables in the text start their counts again when HAProxy reloads and when
the address moves to the other node; a cluster's shared counters are the
generated tables'
([Sending the traffic log elsewhere, and metrics](#sending-the-traffic-log-elsewhere-and-metrics)). A `haproxy -c` error in a
generated file is reported as the object and the line of its text, and a
publish is refused when HAProxy warns about a pasted line: a warning there means
the line would be ignored, which `-c` alone lets pass. Beyond what
is refused here and what `haproxy -c` checks, what the text does is the author's
responsibility: a valid line can still mean something else than intended, and
the dialog's list of where each line went is the review before a publish.

## Dynamic blocking

An http, https or tcp object can block a source address for a while once it
asks too much: every request from it is refused for the time set, and every
request over the limit during the block starts that time again. A block
therefore lasts as long as the attack and then the time set, and ends on its
own. The rate limit is a brake beside it: it refuses what is over the limit and
serves the rest.

In the object's form, *Dynamic blocking* sits between *Access* and *WAF*.
*Requests* and *Errors* (a tcp object: *New connections*) are what turn it on;
with both empty there is no block. *Window* (`10s`), *Block for* (`30m`) and
*Answer with* (`404`) stand filled in. *Never blocked* takes groups from the
*Network* page and addresses or ranges, as *Reachable from* does.

The object's page lists the addresses its block holds, with the nodes holding
each and the time left; an admin ticks them and presses *Unblock*. The
dashboard says on the cluster's card how many addresses are blocked, and an
admin's *Operations* row names the objects, three of them and how many more,
with a link to each.

The same in the object's YAML:

```yaml
dynamic_block:
  window: 10s          # the default; seconds or minutes
  max_requests: 300    # http/https: requests per window (optional)
  max_errors: 20       # http/https: 4xx answers from the servers per window (optional)
  # tcp instead: max_new_connections
  block_for: 30m       # 1m to 24h
  status: 404          # http/https: 403, 404 or 429; 404 is the default
  exempt: [monitoring, 192.0.2.10]   # groups and ranges never counted or blocked
```

At least one trigger is set. The errors are the 4xx answers the object's
servers give - what a scanner and a password guesser leave behind; a 5xx is
the application's fault and is not counted, and nor are answers HAProxy gives
itself, so a block cannot extend itself. A blocked request's traffic record says
`dynamic-block:deny`, which tells it apart from a 404 the application gave. A tcp
object closes a blocked address's connection before a byte is forwarded.

The address is the one the rate limit counts: behind a trusted proxy the last
`X-Forwarded-For` element, otherwise the address the connection came from.
Many visitors behind one NAT address are blocked together; name such an
address in `exempt`, as well as monitoring that polls the object often. A
country cannot be exempt.

The time is the node's own: the block is an entry in a stick table whose
expiry is `block_for`. On a cluster with shared counters the block reaches the
other nodes and survives a reload and a failover; without them it is per node.
The tables are two backends with no servers, `mgd-<object>-dynblock-rate` and
`mgd-<object>-dynblock`, which `show stat` lists and the node status leaves out.

Dynamic blocking counts on stick counter slots 4 and 5, and HAProxy keeps three
unless `global` says otherwise, so the cluster's `core/haproxy.cfg` needs:

```
    tune.stick-counters 5
```

The nodes list and lift blocks on the admin socket the core names for drain and
maintenance (`stats socket /run/haproxy/manager.sock mode 600 level admin`). A
publish that needs more slots than the core allows, or an object that blocks on
a cluster whose core has no such socket, is refused with the missing line
before anything is validated.

Each node reports its blocked addresses in its status (`blocked`): per object,
how many, and the first 100 with the time left, read on the admin socket
`/run/haproxy/manager.sock`. A block is lifted on a node by
`haprion-server-state unblock <object> <address>...`, which the server state
key's forced command allows; it clears the address from both tables, since one
left in the count is blocked again by its next request. A cleared entry is not
shared, and another node can send it back, so a block is lifted on every node
and checked again.

From the management host, a block is lifted on every node at once, each asked
twice:

```bash
haprion-server-state -c alpha -o shop unblock 203.0.113.7 2001:db8::7
```

`done` means every node no longer blocks any of the addresses; `partial` names
the nodes that still do, or that did not answer, and running it again finishes
the job. A node that runs no blocking for the object yet says to deploy.

## The WAF engine

An http or https object can have its requests inspected by a web application
firewall: Coraza, with the OWASP Core Rule Set (CRS). The engine runs beside
HAProxy on every node, on loopback, and HAProxy asks it about each request of an
object that has `waf` - its query, headers and body, the body as far as
HAProxy's buffer holds it.

```yaml
waf:
  mode: log                # log (the default), block, or off
  on_engine_error: allow   # allow (the default) or deny
  paranoia: 1              # CRS paranoia level, 1 to 4
  exceptions:              # false alarms let through, each as narrow as it can be
    - rule: 942100         # a CRS rule ID
      field: ARGS:q        # optional: one part of the request; absent = all of it
      paths: [/search]     # optional: exact paths; absent = every path
      reason: SQL examples in the docs  # optional: why, one line of at most 200 characters
      by: admin            # who made it, and when (the WAF page fills these in)
      at: 2026-10-03T09:10:00Z
  large_bodies: [/upload]  # optional: paths where a body past the buffer is expected
```

`off` keeps the settings and the exceptions while the engine inspects nothing:
the release then carries no trace of it, as for an object without `waf`.

**Look before refusing.** In `log` a request the engine would refuse is served,
and its traffic record says `crs:log` with the CRS rules it matched and its
anomaly score; in `block` the visitor gets 403 and the record says `crs:deny`.
The engine's checks come after the access rules, so a request those refuse is
never inspected. *WAF logs* shows the records with a match and what each rule
is, from the last seven days (fewer if the traffic log keeps fewer): a finding
leaves the page seven days after its last match. An object turned `off`, or
without `waf`, shows no findings - an exception would change nothing there -
and they come back if the engine is turned on within those days. A rule that matches traffic the site is meant to receive is a false alarm:
let it through with an exception, and the object can leave `log`. A higher
`paranoia` matches more attacks and more false alarms.

**Exceptions** are as narrow as the finding allows. `field` names the part of
the request the rule reacted to, as the rule set's own log names it - `ARGS:q`
(a query or form field), `ARGS:json.q` (a field in a JSON body),
`REQUEST_HEADERS:User-Agent`, `REQUEST_COOKIES:session` - and only that part
stops being inspected by that rule; the rest of the request still is. `paths`
are compared exactly, after the engine decodes and normalises the path:
`/%73earch` is `/search`, while `/search/`, `/search/x` and `/search/../admin`
are not. Without `field` the rule is off for the whole request on those paths;
without `paths` on every path; without either, on the whole object. The rules
that decide and report rather than detect (CRS 949xxx, 959xxx, 980xxx) cannot be
excepted - that would turn the engine off. *Allow* takes an optional *Reason*, which the
exceptions list on *WAF logs* shows in a column of its own: why the traffic is let through
outlives the findings that led to it. A finding an exception covers leaves *Findings*,
unless the rule still matches it after the first deploy that followed the exception: then
the finding stays, and it and the exception are marked *Not working*. An exception without
its time (`at`), or deployed only from the command line, cannot be judged this way.

Findings include the rule set's NOTICE rules - an empty `Accept` or `User-Agent` - which add
to the score like the others.

Each exception also **counts what it lets through**, as a firewall rule counts its hits: the
exceptions list shows *Let through*, *Clients* and *Last seen* for the last seven days. The
engine leaves no trace of a check it was told to skip, so the count comes from a counter the
generator writes beside the exception: the rule itself, as the installed rule set writes it,
narrowed to the exception's field and paths, logging and scoring nothing. It counts a request
the rule would have matched there, also when other rules refuse it. Six exceptions on the same
rule in one object are counted; a seventh, an exception the installed rule set does not define,
and one still in a draft show a dash. Counters came with engine API 27; an exception published
before it counts from the cluster's next publish. A field
name with characters other than letters, digits and `_ . - [ ]` cannot be named; except the
path instead.
`exceptions` came with engine API 13 and replaced engine API 12's
`exclude_rules`, which is refused with a message saying so. `large_bodies`, the
refusal of a body the engine could not read and access rules read on the decoded
path came with engine API 14.

**A body longer than the engine reads.** HAProxy hands the engine as much of
the body as its buffer holds - about 15 kB of 16 kB (`tune.bufsize`) - and the
rest would reach the backend unread, so an attack after enough padding would
pass. In `block` such a request is refused with 413 and recorded
`waf-body:deny`; in `log` it is served and recorded `waf-body:log`, which shows
where large bodies arrive before `block` is turned on. `large_bodies` lists the
paths that expect them - an upload, a large JSON call - each covering itself
and what lies under it, matched as an access rule's path is: there the request
is served with what fitted inspected. `/` covers the whole object. A body that
arrives too slowly is answered 408 after a second, as before.

**A request the engine cannot read.** The rule set inspects what the engine
took apart, so what it could not take apart would pass as clean. The engine
therefore judges, as it judges a rule set match: a body it could not parse
(broken JSON or XML), a malformed multipart upload, more than 1000 arguments
from one source (the query, the path or the body - the rest would go
uninspected), and an address it could not parse. In `block` the request is
refused with 403 and recorded `crs:deny`, in `log` it is served and recorded
`crs:log`; the record carries the rule (1900xx), and *Findings* shows it as
*Unreadable*. These cannot be excepted - what was not read cannot be narrowed
to a field - so a client that sends such requests is corrected, or its object
stays in `log`. On a `large_bodies` path a body cut at the buffer is not
refused as unparseable, since its end never reached the engine; a whole body
that does not parse still is.

**When the engine does not answer** - stopped, restarting, or overloaded -
`allow` serves the request uninspected and records `waf-engine:log`, and `deny`
answers 503 and records `waf-engine:deny`; either answers at once. A node whose
engine is not running while the published release has rules is marked *WAF
engine stopped* on the dashboard, and `haprion-status` shows the engine on each
node with a warning for that node. Each rule the engine matched is
logged on the node with the part of the request and the matched value, in the
engine's own journal (`journalctl --namespace=haprion-waf -u coraza-spoa`),
and collected to the management host with the traffic log, a page of up to
20 000 lines per node and minute, when the management host has a database. The
matched value is the requester's own text: it is kept to 1024 characters and
always shown as text. The part of the request is kept only when an exception
could name it, and the deciding and reporting rules are not kept at all - the
traffic record already carries the score and the decision.

**The engine's memory** is held to a share of the node's: it is slowed and made
to give memory back above 30 % (`MemoryHigh`), and stopped and restarted at
40 % (`MemoryMax`), so HAProxy always keeps at least 60 %. The share is taken of
the memory the kernel sees when the unit is loaded, so a node given more memory
gives the engine more after its next restart. While it restarts,
`on_engine_error` decides what the object's requests get. One object's rules
take about 50 MB, and each further object a few MB more. The dashboard shows
each cluster's CPU and memory in use, the VIP owner's figure with every node's
on hover, and marks a cluster when any node is at 85 % or more.

**Installation.** The engine and the rule set are two packages built from
pinned sources (see the installation guide). The engine package goes on the
management host and on every node, the rule set on the management host only:
publishing compiles the rules there before they leave it, and copies the rule
set into the release's `waf/` - every publish of a cluster with rules, whatever it
changes, takes up the rule set installed then - so a cluster runs the rule set it was published
with. A node starts the engine when a release carries rules and stops it when
one no longer does, and refuses a release with rules if the engine is not
installed. The engine listens on `127.0.0.1:9520`; nothing else on a node may
use that port. CRS is licensed under the Apache License 2.0
(https://coreruleset.org), as is Coraza.

## Certificates

Certificate tools, provider keys and trust are configured during installation. See
[The certificate registry](#the-certificate-registry),
[ACME configuration and challenge routing](#acme-configuration-and-challenge-routing)
and [Preparing Microsoft AD CS / NDES for CSR enrollment](#preparing-microsoft-ad-cs--ndes-for-csr-enrollment).

### Publishing certificates

`haprion-cert-publish` is the one path from a certificate's source to every place it is read.
It runs as root, takes no file, directory or account on its command line, and reads the registry
for all three: which certificates exist, where each comes from, and where each goes.

| Source | Read from |
|---|---|
| `acme` | `/etc/letsencrypt/live/<lineage>/` - `fullchain.pem` and `privkey.pem` |
| `import` | `/etc/haprion/certificates/<id>/` - the same two files, written by the import helper |

| Target | Written as | Owner and mode |
|---|---|---|
| a cluster | `<certificate_root>/<id>.pem`, the private key followed by the full chain - HAProxy's own format | `root`, the group that owns `certificate_root`, `640` |
| a receiver | `<path>/<id>/fullchain.pem` and `<path>/<id>/privkey.pem` | the receiver's `owner`, `600`; the per-certificate directory is `root` with the account's group, `750`, made by the publisher |
| a receiver, `format: pkcs12` | `<path>/<id>/<id>.pfx` and `<path>/<id>/<id>.password` | the receiver's `owner`, `600` |

Every certificate is checked before its first file is written - it parses, its private key
belongs to it, and it has at least seven days left - and all of its targets are resolved first, so
a certificate that cannot be published leaves nothing half-done. Each file is written as a
temporary in its own directory, fsynced and renamed over the previous version: a reader sees the
old file or the new one, never a partial one. A file whose bytes already match is not touched,
which is what lets the command run after every renewal, or by hand at any time, without cost.
The run holds one lock and waits for a concurrent run rather than refusing: the publisher is
idempotent, so the second run does exactly the right thing after the first.

A PKCS#12 bundle is compared by the certificate inside it rather than by its bytes, which are
salted and differ every time the same material is exported. The password is made once per pair and
kept across renewals - the receiver imported the bundle into a certificate store with the password
it fetched, and a new one at every renewal would make every renewal a manual re-import.

An `import` entry whose directory does not exist yet is reported as skipped, not failed, and its
published copy is left as it is, as for a certificate placed in the distribution directory by
hand.

With `--deploy`, every cluster that received a new version is rolled out afterwards with
`haprion-cert-deploy`, once each, after every file is written. Two clusters that carry the same
certificate read the same file; it is written once and both are rolled out.

So is every cluster an earlier run published to without a rollout that succeeded. The files alone
cannot say that - a cluster's PEM is the same whether its nodes took it or not - so the publisher
keeps a note beside the registry, `certificates.pending-deploy.json` (owned and moded like the
registry): a cluster is marked before its material is written and cleared only when
`haprion-cert-deploy` answered 0 for it. Running the same command again after a failed rollout
therefore finishes it, with nothing issued or rewritten, instead of finding the files in place and
answering `done`. Adding a cluster to a certificate (*Publish to…*, `haprion-cert-target-helper`) marks it
the same way. A note that cannot be read counts every cluster as due: each is rolled out once, its
current nodes are skipped, and the file is written whole again. A cluster removed from the
configuration is dropped from it.

```bash
haprion-cert-publish                 # publish what changed, report per certificate
haprion-cert-publish --json          # the same, as a result envelope
haprion-cert-publish --deploy        # ... and roll out the clusters that changed or are still due
haprion-cert-publish --certificate example.com   # one registered certificate only
```

### Issuing a certificate

`haprion-cert-issue` obtains one ACME certificate and takes it all the way to its targets: certbot,
then the registry entry, then the publish and the rollout of the clusters named. Root only. The
whole run is timed and the time is part of its result, because the point of the command is the
number: a certificate on its targets in minutes, from one line.

```bash
sudo haprion-cert-issue --domain www.example.com --method dns-01 --cluster alpha
sudo haprion-cert-issue --domain '*.example.net' --method dns-01 --dns-profile cf-main \
  --cluster alpha --receiver lb-01.example.net
sudo haprion-cert-issue --domain intranet.example.com --method dns-01 --dns-profile cf-main \
  --receiver certserver1.example.net --format certserver1.example.net=pkcs12
```

The ACME policy and challenge routes must already be configured; see
[ACME configuration and challenge routing](#acme-configuration-and-challenge-routing).

The web interface asks for the same thing from **Certificates → New certificate**: a domain, a
method, an in-effect DNS profile for DNS-01, and boxes for the clusters and the registered receivers. It queues one `cert_issue` job
through `haprion-cert-issue-helper` ([worker helper configuration](#what-the-worker-may-run)) and reports on the Jobs page, certbot's output included.
The form cannot register a receiver - one is a directory, an account and a key, made on the host as
in [Registering a receiver](#registering-a-receiver) - and it refuses a wildcard over `http-01` before the job is queued.

The account is the one certbot already has on this host; the command registers none. The
certificate becomes an ordinary certbot lineage, renewed by certbot's timer and published by the
hook in [Publishing certificates](#publishing-certificates) like every other.

The registry is rewritten as a whole, with its ownership and mode kept and the result loaded back
through the engine before it replaces the previous file. Comments in it do not survive the first
machine write; the file's header says so.

### The life of a profile

Profiles are made and retired at **Certificates → DNS providers** (`/dns-profiles`), by an
administrator, or with `haprion-profiles` on the manager (below). A profile is one provider's credentials under a short ID the
operator chooses (`cloudflare-main`: lowercase letters, digits and hyphens, at most 32). The ID is
the profile's name everywhere - the certificate form's choice list, the credentials file, and
`--dns-profile` on the command line - so pick one that reads well typed from memory.

Saving or replacing a profile seals the values in the browser's request against the public key and
queues `dns_profile_apply`. The no-argument root helper opens the sealed row, verifies
profile/provider/key/revision bindings, validates it against the provider catalogue, and atomically
writes a `0600 root:root` credentials file plus root-only metadata under the policy's directory.
The page waits a few seconds for that job before it redraws, so an idle queue shows the new row as
**In effect** straight away; if a certificate job holds the queue, the row says **Applying** and
the page refreshes itself until the file is written. Only a profile whose current revision has a
completed apply job is offered during certificate issuance. The status column reads:

| Status | Meaning |
|---|---|
| In effect | the file certbot reads is the box the row holds; the certificate form offers it |
| Applying / Removing | its job is queued or running |
| Apply failed | the helper refused it - the Jobs page carries its account, without the values |
| Replaced; not applied | a newer revision was saved and its job has not finished |
| Not applied | no apply job for the row was found at all |

The values themselves are never shown again. To change one, **Replace** re-enters every value; the
new box becomes the next revision and is applied by a job of its own. **Remove** uses the same helper
and is refused while either the certificate registry or a Certbot `renewal/*.conf` file still names
the profile; the database row is deleted only after the helper's successful, revision-fenced result.

A lineage issued through a profile renews through it: certbot writes the profile's credentials path
and the catalogue's propagation wait into the lineage's renewal configuration, and [The certbot environment](#the-certbot-environment)'s
`haprion-cert-renew` restores what a plugin cannot persist. Removing a profile a lineage still
renews through would break that renewal, which is why the registry and the renewal files are
checked first.

**From the terminal**, `haprion-profiles` does the same for DNS and NDES profiles, as root: each
profile a file lists is sealed by the form's code against the same key, stored the way the page
stores it, and applied by the same job. The values cannot be compared once sealed, so a stored
profile is left as it is unless `--replace <id>` asks or, for NDES, the endpoint differs; the same
file twice changes nothing. A DNS profile keeps its provider - another provider is another ID.
`--prune` removes the stored profiles of a kind the file lists and does not name, and `remove`
removes one; a removal is refused as on the page. Only one certificate job is queued at a time, so
the command queues each change, waits for the worker to finish it (`--wait`, 120 seconds by
default), and stops at the first that did not apply. The file carries credentials and is refused
unless only its owner may read it (mode `0600`).

```yaml
dns_profiles:
  - id: cloudflare-main
    provider: cloudflare
    fields: {api_token: "from the vault"}
ndes_profiles:
  - id: internal-ca
    endpoint: https://ndes.example.com/certsrv/mscep/mscep.dll
    challenge: "from the vault"
```

```bash
sudo haprion-profiles apply profiles.yaml --check
sudo haprion-profiles apply profiles.yaml --json
sudo haprion-profiles remove dns cloudflare-old
sudo haprion-profiles list --json
```

### Deleting a certificate

Nothing else in this project removes certificate material, and the helpers say so in their
headers: a deletion can erase a certificate a cluster is serving. The cleanup exists anyway,
because a registry that only ever grows is not caution — after a few years it holds hundreds of
certificates that expired or stopped mattering, and for those the missing path is what makes the
registry unusable.

**Where it is.** The registry view at `/certificates?view=registry` has a box on every row and one
button, grey until something is ticked. The button leads to a confirmation page that says, per
certificate, what deleting it means; confirming queues one `cert_delete` job for the whole
selection (at most 32 at a time). One job, not one per certificate: a cleanup of seventy rows must
not become seventy jobs.

**What one deletion is.** Four layers, in this order, for each certificate in the job:

| Layer | What goes | Why this order |
|---|---|---|
| the material | `<certificate_root>/<id>.pem` and the two files in every receiver directory the entry named | |
| the source | `certbot delete --cert-name <lineage>` for `acme`; `/etc/haprion/certificates/<id>/` for `import` | a dead certificate would otherwise renew forever |
| the registry entry | the certificate stops being published | only once the two above are gone: an entry that outlives its material is a certificate the next run can finish, an entry gone before its material is one nothing can find again |
| the node copies | each node of every cluster the entry named is asked `cert-remove <id>` over the trigger identity | last, and the one layer that may lawfully be left behind; a node is asked by name, so it needs no entry |

The whole job holds the publisher's lock (`/run/haprion/locks/cert-publish.lock`), like
issue, publish and target changes do. The renewal timer publishes outside the job queue, and a
renewal that ran between the layers would put a still-registered certificate's material back
and leave a deleted one's node copies behind; under the lock the layers are one step to it.

**A deletion can be run again.** Every layer is idempotent and reports `absent` where there was
nothing to remove. A layer that fails — certbot refuses, a file cannot be unlinked, a node is
unreachable or does not know the verb — is reported on the certificate's row, the entry stays
where the failure was above it, and the same selection deleted again picks up where it stopped.
A certificate that is no longer registered is still looked for by name: its PEM, a lineage of
the same name, its import directory and the copy on every node of every cluster. So the row a
job reports as left is finished by ticking the certificate again, not by hand; only a
certificate nothing holds anywhere is refused as `not_registered`.

**The guards are the operation, not a warning.** A certificate is refused, with nothing touched,
when a proxy object in a cluster's committed configuration still names it, when it is a cluster's
`default_certificate`, when it is the only certificate a cluster that has served certificates has
(its listeners name them, so its next publish would be refused), when another registry entry names the same certbot lineage or the
same receiver directory (the lineage and the receiver's pair are removed whole, so they have to
be the entry's alone), or when a draft in the interface's database still names it. The
draft check is the web's, made on the confirmation page and again as the job is queued; the worker
holds no grant on drafts and does not look, so a draft written after queueing is the one window
left open - its publish then fails on a missing file, which is recoverable. A draft written
between the confirmation page and the confirm is a refusal at the confirm: the question is asked
again with the draft on the row, and nothing is queued until it is confirmed as it now stands. A
refused certificate stops nothing else in the batch: it is reported on its own row and the others
go through. The job's outcome is `done` when every row went, `partial` when any was refused or
left a layer behind, `blocked` when every row was refused, and `failed` when nothing at all went.

**What is left behind, and said.** A node whose trigger does not know the verb yet answers
"unknown request", and the copy is reported as kept, by node. The file is inert there: bind lines
name certificates through crt-lists, and a PEM nothing lists is never loaded. So an installation
can run deletions before its nodes carry the current bundle, and read on the job which node still
holds what. The node's own script refuses an ID that any installed crt-list, `haproxy.cfg` or
`conf.d` fragment names — the same guard as the manager's, measured against what is actually
served rather than what is committed — and it does not reload, because nothing changed for HAProxy.

**The worker's sandbox opens the import store for it.** `07-platform-services` creates
`/etc/haprion/certificates` (root, `700`) before it writes the worker unit, because the unit
names the directory in `ReadWritePaths` without the optional dash: a missing path stops the worker
from starting rather than being skipped in silence. An installation upgraded to this operation
reruns step 7 before releasing the interface that queues it.

**Nothing here can be undone.** A deleted lineage has to be issued again, and a deleted import has
to be imported again. The confirmation page says so, and the job's rows say what went.

**From the terminal**, `haprion-cert-delete` sends the same request to the same helper, as root,
and prints its rows (`--json`: the helper's envelope). A certificate already gone, refused as
`not_registered`, counts as deleted: the command exits 0 when every certificate is removed or was
already gone, so running it again is harmless. It does not read the interface's drafts; publish or
discard a draft that names the certificate first.

```bash
sudo haprion-cert-delete old.example.com stale.example.net --json
```

#### Publishing to another target, and withdrawing from one

The same boxes carry two more buttons, *Publish to…* and *Remove from…*, for the two questions
short of a deletion: a certificate that should also go to the other cluster, and one that was
sent to a cluster (or a receiver) it should not be on. Each leads to a page that offers the
targets the change would touch — for a publish, what some chosen certificate is not on yet; for
a removal, what some chosen certificate is on — and confirming queues one `cert_target` job for
the selection and one delta. The job applies the delta per certificate to whatever the registry
holds when it runs, so thirty certificates sent to the wrong cluster are one job, and a
certificate somebody else changed in between is not overwritten with a stale target set.

**Publishing** registers the certificate for the target, publishes its material there, and rolls
each added cluster out once — a `haprion-cert-deploy` for the cluster, so its nodes pull and
**replace the certificate in the running HAProxy** (`set ssl cert`, no reload), or reload where it
does not hold the certificate yet or refuses the new one. A receiver fetches on its own schedule. A certificate already on a chosen
target is reported `unchanged`.

**Removing** takes the target off the registry entry and removes the copy that target held: each
node of a removed cluster is asked `cert-remove <id>` over the trigger identity (no reload — a
file nothing names is not loaded), and a removed receiver's pair on the manager is unlinked.
What the receiver host already fetched stays there; the manager cannot reach into it. A receiver
another certificate also publishes to keeps its pair. Nothing else is touched: not the material
for the remaining targets, not the lineage, not the entry.

**The guards are the deletion's, scoped to the removed cluster.** A certificate is refused, with
nothing touched, when a proxy object in *that* cluster's committed configuration still names it,
when it is that cluster's `default_certificate`, when it is the only certificate that cluster
has, or when a draft in that cluster names it (the web's check, as for a deletion). An object in
another cluster does not hold it. A refused certificate stops nothing else in the batch; the
job's outcome follows the rows the way a deletion's does, and a node that kept its copy makes the
row `incomplete` — the registry has changed, and running the removal again asks the node again.

**From the terminal**, `haprion-cert-target` sends the same delta to the same helper, as root. A
certificate already as asked is `unchanged`, so the command can be run again; `--format` says how a
receiver added here is written, and `--no-deploy` publishes without rolling the clusters out. Like
`haprion-cert-delete`, it does not read the interface's drafts.

```bash
sudo haprion-cert-target add shop.example.com api.example.com --cluster beta
sudo haprion-cert-target remove shop.example.com --cluster alpha --json
```

### Importing a certificate

`haprion-cert-import` is the other way a certificate reaches the registry: one issued elsewhere -
an internal CA, a purchased certificate, a wildcard exported from a Windows CA - whose key the
maintainer already holds. Root only. Like `haprion-cert-issue` it goes all the way: the import
store, the registry entry, the publish and the rollout of the clusters named.

```bash
sudo haprion-cert-import --id intranet.example --certificate intranet.example.crt --key intranet.example.key \
  --chain issuing-ca.pem --cluster alpha
sudo haprion-cert-import --id intranet.example --pkcs12 intranet.example.pfx --password-file /root/intranet.example.pw \
  --cluster alpha
```

**What is read.** PEM files, or one PKCS#12 (`.pfx`/`.p12`) holding everything. The password for
a PKCS#12 comes from the first line of a file, never from the command line, where every user on
the host can read it (`ps`). An encrypted PEM key is refused - decrypt it first with
`openssl pkey` - because a passphrase the publisher would have to know is a secret in a second
place. Bag attributes and comments between blocks are dropped; a Windows export is read as it is.

**What is checked before anything is written.** The material is taken apart into blocks; the
leaf is the one certificate whose public key is the key's, so a chain handed in the wrong order,
or a PKCS#12 with the CA certificates first, comes out right. A key that belongs to no
certificate is refused (`key_mismatch`). The chain is then followed by issuer from the leaf
upward, and a self-signed root is left out: clients hold it already, and serving it is noise. A
certificate that has already expired is refused (`expired`). An ID certbot has a lineage for
(`already_exists`), an ID registered as `acme` (`not_import`), and an unknown cluster or
receiver are refused too. None of these leave anything behind.

**What is written.** `/etc/haprion/certificates/<id>/` with `privkey.pem`, `cert.pem`,
`chain.pem` and `fullchain.pem`, root-only, in one rename - the same four files certbot's `live/`
holds, so the publisher and the listing read both sources the same way. Then the registry entry,
`source.kind: import`, with the targets named. Then the publish for that one certificate and the
rollout of its clusters, exactly as after an issue.

**Importing again.** The same ID imported a second time replaces the material - a rotated key, a
renewed certificate from the same CA - and keeps every target the entry has; targets named on the
second import are added to them, never a replacement (taking a target away is *Remove from…*, [Deleting a certificate](#deleting-a-certificate)).
The manager does not renew an imported certificate; its expiry is on the registry view,
and a new import before that date is the maintainer's job.

**From the interface.** *Certificates → Import certificate* takes the same material as a file:
PEM (certificate, key and chain in any order), PKCS#12 with its password, a DER certificate or a
PKCS#7 bundle, at most 32 kB, plus the name and the targets. The web process seals the file
against the installation's public key - the pair step 15 creates for DNS provider profiles -
inside the request that carries it, and queues a `cert_import` job whose payload is the
ciphertext. `haprion-cert-import-helper`, run by the worker through its sudoers rule, opens the
box with the private key and imports the material exactly as the command does. So the key is in
clear in the web process for the length of one request and in the root helper; it is never in
the database, the job row or the audit, none of which
the private key can reach. That is a narrower promise than *the web never sees a key*, and it is
stated here because until this feature the interface refused a key on purpose; the command-line
import remains the way in for whoever wants the key to stay off the web entirely.

A file without a key is accepted for a name whose key the manager already holds: an imported
certificate's renewal on the same key, or the certificate a CA returned for a request made here.
*Renew…* under the list, with the imported certificate's row ticked, takes exactly that - only the
certificate; a file holding a key is refused there and pointed at the import page, where replacing
the key is the stated intent. Enrollment from a Microsoft CA needs no file at all ([Preparing Microsoft AD CS / NDES for CSR enrollment](#preparing-microsoft-ad-cs--ndes-for-csr-enrollment)).

**A CA certificate for the pools.** *Import certificate → CA certificate* takes a CA's
certificate - or several: a root and its intermediates, or an old root beside its successor while
servers move over - without a key, and the clusters whose pools may verify against it. *Upload*
takes a file in the forms above, and a key in it is refused; *The NDES CA* takes the issuing CA the
NDES profiles' certificates are signed by, the file the runtime policy names as `ndes.issuing_ca`,
read by root on the manager. Every certificate in it must be a CA (`basicConstraints CA:TRUE`); a
server certificate is refused (`not_authority`), and so is a file in which every certificate has
expired. The registry holds it as `source.kind: authority`, the import store as `fullchain.pem`
alone, and the clusters get it as `ca/<id>.pem` under the distribution directory. The nodes fetch
it into `/etc/haproxy/certs/ca/` (the trigger's `ca-pull`), beside the certificates and not among
them, and reload only when an installed pool names it. Its row reads *CA*, *Used by* lists its
clusters, and the state says which nodes carry it. Imported again under the same name it replaces
the file and keeps the clusters. A CA that a committed object or a draft names cannot be deleted or
taken off that object's cluster. From the terminal:

```bash
sudo haprion-cert-import --id corp-root --authority corp-root.pem --cluster alpha
sudo haprion-cert-import --id corp-root --ndes-ca --cluster alpha
```

A node whose package does not know `ca-pull` answers *unknown request*, and the rollout to it fails
until the node package is updated.

**Renew…** is one button for every source: ticked on a certbot certificate it runs the daily
timer's `certbot renew --cert-name <lineage>` now with `--force-renewal` (`haprion-cert-renew
--acme-now <id>` from the terminal; Let's Encrypt allows five identical certificates a week), on an
NDES certificate it enrolls again from the same profile with the same names and targets ([Preparing Microsoft AD CS / NDES for CSR enrollment](#preparing-microsoft-ad-cs--ndes-for-csr-enrollment)),
and on an imported one or a waiting signing request it is the page with the file field.

**A signing request made here.** For a CA the manager cannot talk to - a purchase, an internal
PKI without SCEP, whoever signs things - the key can be made on the manager instead of imported:

```bash
sudo haprion-cert-request --id intranet.example --domain intranet.example --domain '*.intranet.example' \
  --cluster alpha [--key-type ec-p256|rsa-2048|rsa-4096]
```

writes `/etc/haprion/certificates/<id>/privkey.pem` (root-only, never printed) beside
`request.csr`, `request.json` and `targets.json`, and prints the CSR. The base name is the CN and
the certificate's ID, a wildcard a SAN beside it. EC P-256 is the default; RSA for the CA that
requires it. The request is *not* in the registry - an entry without material would refuse every
rollout to its clusters - and the listing shows it from the store as **Signing request pending**,
with the CSR to download from the row. The name is refused while anything else holds it: a
registry entry, a certbot lineage, imported material, an NDES request in flight.

When the CA has signed, the certificate comes back without a key - `haprion-cert-import --id <id>
--certificate <file> [--chain <file>]` with no `--key`, or *Renew…* with the row ticked - and is
matched against the stored key, imported and published to the targets the request named plus any
named now. A certificate for another key is refused and the request kept. Deleting the row ([Deleting a certificate](#deleting-a-certificate))
removes the key with it; a request nobody signs is otherwise harmless, and stays until it is
deleted. On the interface the same thing is the fourth choice on *New certificate*, **CSR**, with
the key type where the other methods have their profile; it queues a `cert_request` job that
`haprion-cert-request-helper` runs, the fourteenth worker helper (its sudoers rule and step 07 are
part of the release).

### Enrolling and renewing through NDES

After installation, root policy configuration and provider application, the pilot root CLI is:

```sh
haprion-cert-scep --id example-cert --profile internal-ca --domain example.test --domain '*.example.test' --json
```

A CA approval wait returns `state: pending` and envelope outcome `partial`. The certificate is
**not** registered yet: the registry names only certificates that exist, because the cluster's
certificate list and the deploy preflight are built from it and an entry without material would
refuse every rollout to the clusters it names. The request's root-only state holds the key, the
profile, the names and the chosen targets, and the listing helper reads it there, so the row shows
as **Request pending** all the same. Resume with `haprion-cert-scep --id <id> --resume` - the
original key is retained, the targets are the ones the request was made with, and a resume that
disagrees with the record is refused. Returned certificates must pass chain, names, usages and key
validation before the existing import/publication path is called; only then is the certificate
registered and published.

A request the CA rejects, or one Certmonger never took, removes its own state so the same ID can
be asked for again. A request that is neither answered nor rejected - the approval is not coming,
or the process died on it - is given up with `haprion-cert-scep --id <id> --abandon`, which
discards the key; deleting the certificate removes its request state too.

**Scheduled renewal.** `haprion-cert-renew` - the command the daily `haprion-certbot-renew.timer`
runs - makes an NDES pass after certbot's: every registered certificate whose source names an
NDES profile and whose `not_after`, read at its source, is less than `ndes.renew_days` away is
enrolled again under the same ID, with the same profile, the names the current certificate
carries (CN first) and the targets the registry holds. It is the same request as a first
enrollment: a fresh key, and the published material replaced only once the new certificate has
been validated; a request the CA holds is **Renewal pending** on the row, with the same *Resume
enrollment* button, and the next day's pass resumes that request rather than asking anew. One record per certificate under `<state_root>/renewals/` says what the last
attempt did, and the listing shows a failure as **Renewal failed** with the CA's sentence rather
than an expiry creeping closer. `haprion-cert-renew --ndes-now <id>` renews one certificate at
once, threshold or not, and skips certbot's pass: the way to prove the path on a template whose
validity cannot be shortened per request, and to rotate a key. `--acme-now <id>` is the same for
a certbot lineage, forced; the interface's *Renew…* runs both. `--dry-run` says who would renew.


From the interface, *Certificates → New certificate* offers *Microsoft AD CS · NDES* beside
the two Let's Encrypt challenges whenever an NDES profile is in effect; a wildcard becomes the
base name as CN with the wildcard as a SAN. The submission is one `cert_scep` job run by
`haprion-cert-scep-helper` (the twelfth worker helper; a sudoers rule and step 07 are part of
its installation). A pending request shows **Resume enrollment** in its registry row, which
queues the same job with only the ID. Migration `0027` adds provider storage and apply jobs,
`0028` the profile's plain endpoint column and worker deletion, `0029` the `cert_scep` job.
A compatible UI bridge was required before each migration (until `0065`; see
[Verifying it](#verifying-it)).

A certificate the CLI enrolls is registered as `source.kind: import` with
`source.ndes_profile` naming the profile whose challenge enrolled it; the interface shows
such a certificate as **NDES** rather than **Imported**. Removing a profile (Certificates →
NDES providers → Remove) runs one job that deletes the root-only record and then the row;
it is refused while the registry still names the profile or an enrollment request under
`state_root` is still bound to it. A refused removal leaves the profile in effect.

### External certificates

Some places that want a certificate will never be connected to this manager: a server's
BMC, a NAS, a printer, a camera, a UPS card. For those the manager is where the
certificate is ordered and taken out; it is installed by hand. Behind the
**External certificates** switch, with the receivers.

**Making one.** *New certificate* → *External, installed by hand* (the switch under
*Targets*): the same form, for one host name and with no targets. DNS-01, HTTP-01 or NDES; not a CSR,
because the point is a key that can be handed out. The key is RSA 2048, which every
device takes - several take no EC key. A wildcard is refused: its key would answer for
every name under it. From the command line, `haprion-cert-issue --exportable` or
`haprion-cert-scep --exportable` with no `--cluster` and no `--receiver`.

The registry marks the entry `exportable: true`. The mark is set when the entry is made
and never changes, and an exportable entry can never be given a target: *Publish to…*
refuses it. A certificate HAProxy or a receiver carries is therefore never one whose key
can be downloaded. Renewal is the source's as for every certificate - certbot's timer,
or the NDES renewal - and keeps the mark; installing the renewed certificate on the
device is yours.

**Taking it out.** Tick the row and press *Export…* (an admin; the button wakes at one
external row and no other):

- *Certificate and chain*, *Certificate* and *Chain* download the public half as PEM. A device that takes one file wants the first; one that asks for the
  certificate and the issuer separately, the other two.
- *Export key*: the key alone as PEM (*Key, PEM* - for a device that takes
  certificate and key as two files, Supermicro's BMC for one), or a PKCS#12 bundle of key
  and chain under a password you type (8-128 characters). *PKCS#12, modern* is what
  OpenSSL writes today: AES-256, PBKDF2, a SHA-256 MAC. *PKCS#12, compatible* is 3DES and
  a SHA-1 MAC, for older Windows, Java and embedded readers - not OpenSSL's `-legacy`,
  whose certificate part is 40-bit RC2. Type the certificate's name to confirm.

The key is read by `haprion-cert-export-helper`, root, over
`/run/haprion/cert-export.sock`, which only the web account may connect to. It
refuses every entry without the mark, writes nothing, and says in the journal what it
exported for whom (`journalctl -u 'haprion-cert-export-helper@*'`); the web writes a
`certificate_export` audit event with the certificate's fingerprint. Nothing keeps a
copy, and the password is never stored or returned. Root at the terminal can ask the
helper directly with the same request document.

Not every device can take a key at all. HPE iLO makes its own key and asks for its CSR
to be signed; the manager does not sign an uploaded request - see
[What it does not do](#what-it-does-not-do).

### Registering a receiver

A receiver is a machine outside this installation that fetches certificates from the manager. It
is four things at once - an account, a directory only that account may read, a lock binding its key
to that directory, and the registry entry - and `haprion-cert-receiver` makes all four, or none:

```bash
# The receiver makes its own key pair and sends you the public half.
sudo haprion-cert-receiver add lb-02.example.net --transport rsync \
  --public-key /tmp/lb-02.pub

sudo haprion-cert-receiver add lb-03.example.net --transport sftp \
  --public-key /tmp/lb-03.pub --owner crx-lb-03

sudo haprion-cert-receiver add 192.0.2.40 --transport https --allow 192.0.2.0/24 \
  --show-password
sudo haprion-cert-receiver secret 192.0.2.40 --show-password   # the old one stops at once

sudo haprion-cert-receiver list
sudo haprion-cert-receiver remove lb-02.example.net
```

**The account is `crx-` and the ID** with its dots turned into dashes (`crx-lb-02-example-net`):
*crx* for *certificate receiver*, a prefix nothing else on the machine uses, so `ls -l` under the
receiver root names the receiver. Linux holds an account name to 32 characters; an ID that would
not fit is refused rather than cut, and `--owner` names the account instead - two long IDs must
never quietly become one account. An `https` receiver has no account of its own: nginx serves it.

**The ID is the fetching host**: its DNS name or its IPv4 address, and nothing else. That is what the
lock binds to - `from=` in `authorized_keys`, `allow <id>` in nginx. **The key line carries the
name and its addresses both**, `from="lb-02.example.net,192.0.2.10"`: sshd's `UseDNS` is off by
default, and then `from=` matches addresses only - a lock naming the host alone refuses the very
host it was issued for, and the log says *correct key but not from a permitted host*. The
address is what sshd always has; the name is what an operator reads, and what `UseDNS yes` would
match. The addresses are resolved once, at registration, so a host that changes address is
`remove` and `add` again. A name that does not resolve is refused, because there would be
nothing to write into the lock; its PTR record is not looked at. One address commonly carries
several names in a zone - the host's own and one per service it serves - and whichever of them
the reverse lookup answers with, the address half of the lock admits the host. An IPv6 address
is not accepted as an ID (the ID is also a directory name and a URL path segment, and `:` is
neither); a host that fetches over IPv6 is registered under its DNS name, and its IPv6 address
goes into `from=` with the rest.

**Where the directory goes** is `receiver_root` in the runtime policy: a new receiver's
directory is `<receiver_root>/<id>` unless `--path` names another. The registry, not the root,
says where each receiver actually is, so the root is optional until the first `add`, which refuses
with `dependency_unavailable` until it is declared.

**The private key is never given to the manager.** The pair is made on the receiver
(`ssh-keygen -t ed25519`), and `--public-key` takes the `.pub` file. A private key that passed
through the manager has passed through one machine too many.

| Transport | How it fetches | What holds it there |
|---|---|---|
| `rsync` | `rsync` over ssh | `restrict,from="<id>,<addresses>",command="/usr/bin/rrsync -ro <path>"` - one directory, read-only, no shell |
| `sftp` | `sftp`, read-only | the same key line without the forced command, plus a `Match User` block with `ChrootDirectory <path>` and `ForceCommand internal-sftp -R` |
| `https` | `GET` with the receiver's own password | an address whitelist in nginx and the password, both required (`satisfy all`) |

The rsync account has `/bin/sh` as its login shell because OpenSSH runs an
`authorized_keys command="..."` through that shell with `-c`. The shell does not grant an
interactive login: the key still carries `restrict`, `from=` and the fixed `rrsync -ro` command,
and no unrestricted key is installed. An SFTP account keeps `/usr/sbin/nologin` because
`internal-sftp` is sshd's in-process server and does not need a shell.

`https` is a deliberate lowering of the trust level: a password is not a key pair, and what such a
receiver holds - a wildcard, a certificate the clusters serve - is the operator's call, not the
program's. It reaches nothing but its own directory. **The password** is made by whoever registers
the receiver - the interface shows it on the page, the command prints it when given
`--show-password` and refuses without it - once; the manager keeps only its
salted hash, in `/etc/nginx/haprion-receivers/<id>.htpasswd` (`root:www-data`, 0640), and neither
the registry nor the interface's job holds it. A lost password is replaced with `secret` (or
*New secret* on the page); the old one stops working at once. The receiver keeps it in a netrc
file (`/root/.certfetch.netrc`, mode 600) that curl reads with `--netrc-file`, so it is on no
command line. It is served from the interface's own server block, on 443 under the
interface's certificate and hostname, at `https://<server name>/certdist/<id>/<certificate>/`.
The `location` blocks live in `/etc/nginx/snippets/haprion-receivers.conf`, which only this
command writes and which the interface's site pulls in with one `include` line; the interface's
block itself is never edited by a receiver. Not a server block of its own beside the interface's:
nginx serves the first server block for a name and port and silently ignores a second one, so that
block would test clean and never answer. Platform step 05 adds the include and creates the empty
snippet; without them `add --transport https` refuses with `dependency_unavailable` rather than
registering a receiver nothing serves.

**What the receiver trusts.** The interface's certificate is what the receiver's `curl` must
verify, and it is served as a file for that purpose at `https://<server name>/certdist/manager-ui.pem`
(a copy under `/srv/certdist/`, written by `haprion-tls` at every replacement and by
`haprion-tls publish`; the TLS directory itself is root-only, which nginx's workers are not).
The receiver saves it once - `curl -k -o manager-ui.pem …` on that first contact, or with
`openssl s_client` where openssl exists - and passes it as `--cacert` to every fetch after, so it
trusts exactly that certificate. A receiver whose host already trusts the CA that issued the
interface's certificate needs neither the file nor `--cacert`. An installation whose site
predates the `manager-ui.pem` location reruns `05-platform-nginx`, which also publishes the copy.

Every change to sshd's drop-in or nginx's site is followed by `sshd -t` or `nginx -t`, and a
refusal puts the previous file back before reporting: a broken sshd locks out everyone, not only
the receiver being registered.

The account's home is the receiver's directory - one directory per receiver, root-owned, with the
lock in a root-owned `.ssh` inside it. An `sftp` receiver therefore sees `.ssh` in its chroot beside
its certificates: its own public key, readable and not writable, and nothing else.

**Removing** is refused while any certificate still names the receiver - `Remove from...` in the
interface ([Deleting a certificate](#deleting-a-certificate)) is what lets a certificate go of a target, and it is the operation that also
says what that costs. There is no operator command for that step: the interface queues a
`cert_target` job and the worker runs `haprion-cert-target-helper`, which takes its request on
stdin and is not meant to be typed. Once nothing names it, the registry entry, the lock, the
directory and the account go in that order.

Reference fetch scripts for each transport are in
[`../examples/receivers/`](../examples/receivers/). They are what a receiver's own operator
adapts; the manager never pushes.

**The worker's sandbox must be able to look into a receiver's directory.** A receiver's files
belong to its fetch account (`0600`). Root inside the worker's unit is only uid 0 - the mode bits are the law
there unless the bounding set says otherwise - so the worker unit carries `CAP_DAC_READ_SEARCH`,
the read-and-traverse capability the poller already has. Without it a target change from the
interface ends `target_missing` on a directory that `haprion-cert-publish` run as root from a
terminal publishes to without complaint. An installation whose worker unit predates this line
reruns `install/platform/07-platform-services`, which rewrites and restarts the unit.

**From the interface**, *Certificates → Receivers* lists every registered receiver - transport,
account, what it holds - and registers or removes one. The form takes the receiver's name, the
transport, and the public key pasted as text (or, for https, the allowed addresses); the job is
one `cert_receiver` run by `haprion-cert-receiver-helper` - not through `sudo` but on a socket,
`/run/haprion/cert-receiver.sock`, from a unit of its own that step 07 installs (see *The
worker's way to the receiver helper* in the installation guide; migration `0032` lets the queue accept the job). The
helper takes the key as text and never as a path, so the interface cannot point it at a file. What the page adds over the command is the other half of the contract: under each
receiver it writes out the exact commands that host runs to fetch - the account, the manager's
name and each certificate it holds filled in, for Linux and for Windows where the transport
allows both - together with the `ssh-keygen` line the host runs first. Removal from the page is
refused while any certificate names the receiver, as at the terminal.

The receivers page reads its rows from `registry.receiver_records` and the manager's name from
`registry.manager` in the `cert_list` answer (the interface's `SERVER_NAME`); an installation
whose CLI release predates those fields shows the page without rows until the CLI is updated.

## Nodes and clusters

### Adding and removing a node

A node is known to the management host in six root-owned places: its entry in `clusters.yaml`, its
host key in root's `known_hosts`, its two fetch keys in the pull accounts' `authorized_keys`, and -
where the traffic-log collector is installed - its entry in the collector's node list and its host
key in the collector's own `known_hosts`. `haprion-node` and the Nodes card under Settings change
all six as one, through the same root helper:

```bash
# On the node: step 4 prints an enrollment block - one line starting with haproxy-node-v1
# (tools/install-node-package runs it, or with the package installed:)
sudo /usr/share/haprion-node/install/04-node-prepare answers.env alpha

# On the management host, the block on stdin:
sudo haprion-node add -c alpha --host node-c.example.com < block
sudo haprion-node remove -c alpha node-c
sudo haprion-node host -c alpha node-c --host lb-03.example.com
```

The block carries the node's name, its cluster, a suggested host name, its ed25519 host key and the
public halves of its two fetch keys. Copying it from the node's console is the trust - the manager
takes the host key from the block, never from the network - and the fingerprint the command and the
page print is the one to compare with what step 4 printed. `--host` is the name the manager reaches
the node at; the block's suggestion is the node's own `hostname -f` and may not be. With `--json` either
command prints the helper's envelope instead (`schemas/v1/haprion-cluster-node`); `haprion-cluster`
takes it too.

**Changing a node's host.** A node that is renamed or given another address is the same machine,
and is moved rather than rebuilt: *Change host* on its row under *Settings → Nodes*, or
`haprion-node host`. The host keys pinned for the node move to the new name in root's
`known_hosts` and the collector's, its line in `clusters.yaml` follows, and the manager asks the
node at the new name. The answer must come with a key already pinned and name the node and its
cluster; anything else puts every file back, and the node keeps its old host. Its fetch keys name
the node, not the host, and do not change. A machine with another host key is another machine: that
is a restore, or a removal and an addition. With counter sharing on (`peers`), the next publish and
deploy carry the new address to the nodes.

After writing, the manager asks the node for its status as the status identity, with strict host
key checking. The node reports its own host name and cluster, so an answer proves the host key, that
the node already has the manager's key lines from step 3, and that the block described the node that
answered. Anything short of that puts every file back and says why. The node has no certificates
and no release until `haprion-cert-deploy -c <cluster>` and then `haprion-deploy -c <cluster>` run
(*Deploy certificates* and *Deploy configuration* on the dashboard); a deploy before the
certificates stops and says so, since the node has none.

A removal takes the node's lines out of all six files, so it can no longer fetch configuration or
certificates. It is refused for the node that reports holding the VIP and for a cluster's last node; the node
itself is not touched and keeps serving until it is shut down. A cluster has one to eight nodes
([Cluster definitions](#cluster-definitions)). On a cluster created in the interface the next deploy rewrites every
node's `keepalived.conf` with the new peer list ([keepalived on the nodes](#keepalived-on-the-nodes)).

A change cut short - a reboot, a killed process, power - cannot leave the files half changed for
long. Before the first file is touched, the whole change (every file's content before and after, and
for a cluster the directories it creates or moves) is written to
`/var/lib/haprion/change-journal.json`, root-only, and synced; it is removed only once the
change is on disk. While a change runs, the helper holds back SIGTERM, SIGINT and SIGHUP until it
has finished or put everything back. A record left behind is put back by the next node or cluster
change, before that change runs, and the helper's journal says so (`NOTICE: a node add of cluster
'alpha' did not finish and was put back`). A file edited since the interrupted change stops that:
the request is refused with `change_interrupted` and touches nothing, and the record stays for a
person to read and remove once the files are right.

Once written by step 2, `clusters.yaml` is the record: a second run of step 2 keeps it unless
`REWRITE_CLUSTER_FILE=yes` asks for the answers file's version, and step 13 reads the collector's
nodes from it rather than from the answers file. The runtime policy is kept the same way
(`REWRITE_POLICY=yes`): it holds blocks no answer renders, such as `acme` and `ndes`.

### Creating and removing a cluster

A manager may have no clusters, and a cluster may start with one node and no certificate. A
cluster is made by `haprion-cluster`, or *Create cluster* under Settings, through the same root
helper as a node; its next node is added the way any node is
([Adding and removing a node](#adding-and-removing-a-node)):

```bash
# On the node: step 4 prints its enrollment block for the new cluster.
sudo /usr/share/haprion-node/install/04-node-prepare answers.env beta

# On the management host, the block on stdin (two blocks and two --host options make both nodes at once):
sudo haprion-cluster add -c beta --display-name Beta --vip 203.0.113.10 \
    --node-path beta --host node-c.example.com [--certificate example.com] \
    [--prefix 24] [--interface eth0] < block

sudo haprion-cluster remove -c beta
```

A creation writes, as one change: the cluster's entry in `clusters.yaml`; with `--certificate`, that
certificate's entry in the certificate registry, which gains the cluster as a target; a configuration repository
(the bare history and the worktree, seeded with the same `core/haproxy.cfg`, `manual/` and
`managed/network.yaml` step 1 makes, and owned like the others); an empty release directory; a
`sudoedit` rule per handwritten file in the operator editing policy, checked with `visudo -cqf`
before it is installed; the two repositories in root's git `safe.directory`; and its nodes in the
six places of [Adding and removing a node](#adding-and-removing-a-node). Then each node is asked for its
status, as a single added node is. Anything short of that removes the repository and release
directory again and puts every file back. The ID, the node path and the nodes' names and hosts
must all be free; a certificate named must already be in the registry. A cluster without one serves
plain HTTP and TCP; an HTTPS object waits for a certificate issued or uploaded for it.

The new cluster is polled and drawn from the poller's next pass ([Which clusters get
polled](#which-clusters-get-polled)). It has no release until its network description and objects
are published and `haprion-cert-deploy -c <cluster>` and then `haprion-deploy -c <cluster>` run, and no backup schedule until one is set on
the Backups page; its retention is the default until then. The first deploy also writes each node's
`keepalived.conf` and starts keepalived ([keepalived on the nodes](#keepalived-on-the-nodes)).

A removal takes the cluster out of `clusters.yaml`, out of every
certificate's targets, out of the editing policy and `safe.directory`, and takes its nodes out of the
six places; it stops `haprion-state-backup@<cluster>.timer`. Nothing is deleted: the configuration
repository and its history, the release directory, the nodes' backup archives and the retention
file are moved to `.removed/<cluster>-<time>/` under their own roots - the same file system, so a
rename, and whatever protects the root protects the archive. The ID cannot be used again while its
archive is there; deleting an archive is a separate, deliberate step. The nodes are not touched and
keep serving the VIP until they are shut down - the manager only stops managing them. Jobs and
versions in the interface's database stay as history.

## The interface certificate

### Replacing it

Not by rerunning the installer. The command that owns the certificate is
installed by step 5:

```bash
sudo haprion-tls show
sudo haprion-tls install --cert /path/to/ui.crt --key /path/to/ui.key
```

`install` checks that the certificate and key actually belong together by
comparing public halves, refuses an expired certificate, warns under 30 days,
installs the pair root-owned `0600`, runs `nginx -t`, and **puts the previous
pair back if nginx refuses the new one**. A management host whose UI stopped
answering is a worse outcome than a rejected replacement.

The site config has HSTS present but commented out, with the reason next to it:
HSTS makes a certificate warning unclickable, so enabling it while the
certificate is still self-signed locks every operator out of the UI — including
whoever would fix it. Enable it after installing a trusted pair.

### From the certificate registry

The pair can instead come from the certificate registry ([The certificate registry](#the-certificate-registry)): an entry marked
`interface: true`, issued over ACME or NDES or imported like any other certificate, and renewed by
the same timer. Publishing that entry runs `haprion-tls install` with it - the same checks and
the same rollback as above - after two refusals the command does not make itself: the certificate
must name this host's `SERVER_NAME` (a wildcard covers one label), and a certificate nginx already
serves is not installed again, so a renewal of some other certificate costs no reload.

Who runs it depends on where the publish runs. `haprion-cert-publish` and the renewal timer are
root outside any sandbox and install directly. The certificate helpers the worker starts through
`sudo` run inside the worker's `ProtectSystem=strict` namespace, where `/etc/haprion` is
read-only; they name the entry by ID to `haprion-tls-helper` on
`/run/haprion/ui-tls.sock`, a root unit step 07 installs, which reads the registry and the
material itself and refuses any entry not marked `interface: true`. The key never passes through
the web process: the interface names a certificate, never bytes, never a path.

At the terminal the mark is `--interface` on `haprion-cert-issue`, `haprion-cert-scep`,
`haprion-cert-request` and `haprion-cert-import`, with no `--cluster` or `--receiver` beside it; a
signing request or an NDES enrollment the CA is still holding remembers it until the certificate
arrives. A rotated or renewed interface certificate keeps the mark. A new one under another ID takes
it: the registry moves the mark, publishing installs the new certificate, and only once nginx
serves it is the previous entry deleted, through the ordinary deletion. If the install is refused
the previous pair keeps serving, and its entry stays in the listing without the mark and without
targets. The entry that serves the interface cannot be deleted (`serves_interface`).

`haprion-tls install` and `self-signed` stay the way back: running either replaces the served
pair whatever the registry says, and the next publish of the marked entry puts it back.

## Backups, and proving they restore

```bash
sudo haprion-backup dump            # what the daily timer runs
sudo haprion-backup verify-restore  # what the weekly timer runs
sudo haprion-backup list
```

**Dumps are root-owned `0600` in a `0700` directory**, and step 6 verifies that
none of the three application identities can read one. This is not tidiness: a
dump contains every Argon2id password hash and every session hash in the
installation, so it sits behind the same boundary as nginx's private key.

That constraint shapes the restore test. `pg_restore` there runs as the
`postgres` superuser — the only identity that may create and drop a database —
which must not be able to open the dump. So root opens the file and hands the
descriptor over: the archive is read without ever becoming readable to another
account.

#### What the dump does

- `pg_dump --format=custom`, written to a `.partial` name and renamed into
  place, so anything reading the directory sees a complete dump or none — never
  a file still being written that looks finished.
- Read back with `pg_restore --list` **before it is kept**. A zero exit from
  `pg_dump` says the command ran; this says the archive can be opened and its
  contents parsed, which is what a truncated or corrupt dump fails.
- One dump per day — today's replaces today's — and the seven newest are kept.
  Retention counts files rather than calendar days, so a week with the machine
  switched off does not delete the last dump that exists.
- Warns when the filesystem holding the dumps is over 85% full, and dumps
  anyway. A backup that refuses to run because a disk is filling is a backup
  that stops precisely when things are going wrong.

#### What the restore check does

It restores the newest dump into a scratch database that it creates and drops
itself — never a database named in configuration, because a restore test that
can be pointed at the wrong database will eventually overwrite something real.
Then it compares the result with what the archive holds:

- row counts for `app_user`, `app_session`, `audit_event`, `login_attempt` and
  `job`, named explicitly so an empty restore cannot pass by matching zero
  against zero. The expected count is read from the archive's own data section,
  not from the live database: live moves on after the dump — a sign-in adds a
  session, retention removes old jobs — and a check measured against it fails
  on a perfect restore. The live count is printed beside each table as
  information about how far the installation has moved since;
- a hard requirement that the restored `app_user` table is **not empty**, since
  an installation nobody can sign into is not a backup worth verifying;
- one row read back in full — the first account's hash must still be a valid
  Argon2id hash, because counts can match while the contents are unusable.

Any mismatch fails the unit, and the scratch database is dropped either way.

#### What is not covered

This is a database backup, and the database is not the whole installation. It
does not hold the HAProxy configuration — that lives in Git — nor the cluster
definitions, the keys, or the release tree. The DNS profiles it holds are
ciphertext: without the private key in `secrets/dns-profile-keys/` ([The DNS profile key pair](#the-dns-profile-key-pair)) a
restored dump lists every profile and can apply none of them, and the recovery
is to re-enter them. **Nothing here survives losing the
host**, and nor does anything else on it — the release tree, the runtime policy,
the keys, the sudoers rules. **Backing up the management host itself is a very
good idea**, and how that is done is entirely up to whoever runs it. If it is
backed up whole, these dumps are along for the ride.

That does not make them redundant. An image of a running database is
crash-consistent rather than transactionally clean, and restoring a single table
out of a machine image is not something anyone does under pressure. The dump is
what makes "put that one table back" an ordinary afternoon.

#### After restoring the database or the host: waiting jobs and sessions

A restored database holds the jobs that were waiting at the moment of the backup. Those ran at the
time, and running them again would be a new request nobody made — a *Drain* replaced since by
*Ready* would drain the server again. The worker therefore never runs a job that has waited more
than two hours: it ends *blocked* with the code `request_expired`, and the job page says so. The
longest real queue is far shorter. A job the worker had already started is judged as after any
worker failure ([Jobs and status freshness](#jobs-and-status-freshness)), from what the cluster
shows rather than from its age.

The sessions come back as they were at the backup, including ones signed out or revoked since.
After a restore, end them for every account: *Settings → Users*, the account, **End sessions**.

#### After restoring the database on its own: replay the traffic log

Restoring the whole host puts the database and the collector's staging back together, and nothing
more is needed. Restoring **only the database** from a dump does not: the collector keeps, per day
file in staging, how far it has imported, and that position is newer than the dump. Its next run
would go on from there and leave every request between the dump and the restore missing from the
log page, although the records are still in staging ([Mirroring node traffic logs](#mirroring-node-traffic-logs)). After such a restore, run once, as the
collector account (`COLLECTOR_USER`):

```bash
sudo -u <collector> /opt/haprion/current/bin/haprion-traffic-collector \
  --replay-database /etc/haprion/traffic-collector.json
```

It waits for a run in progress, drops the import positions and nothing else — the day files and
how far each node has been fetched stay — and the next run imports every staged day again. A
record the database already holds is passed over by the table's own duplicate check, so nothing is
counted twice. What staging no longer holds (older than the retention window plus one day) cannot
be replayed.

The WAF engine's matches are replayed the same way, from the nodes rather than from staging: the
command also drops how far each node's WAF journal has been imported, and the next runs read each
journal again from its oldest entry, a page per minute. What a node's journal no longer holds
(older than its 14 days) cannot be replayed.

## Node backups

On the Backups page, an administrator can set each cluster's schedule on the manager's
clock, enable or disable it, choose how many archives to retain (1–365), and run a backup
immediately. Schedules may run every day, on chosen weekdays, or on one day of the month
(1–28). The terminal path is:

```bash
sudo haprion-state-backup -c alpha
haprion-list-backups -c alpha
sudo haprion-backup-schedule -c alpha --time 03:30 --weekly Mon,Thu --retention 14
```

`haprion-backup-schedule` asks the same root service the page's *Save* does, and only when the
timer or the retention differs from what is asked - so the same command twice changes nothing.
Without `--weekly` or `--monthly <day>` it runs every day; `--disable` keeps the schedule and
stops the timer; `--check` says whether it would change; `--json` prints the service's envelope
with `changed`. *Node backups* under Features is the interface's switch; the command works either
way, but turning the switch on starts again the schedules it stopped, so set a schedule after the
switch is on.

Archives are root-only and belong to a specific node. For backup identities, storage and
timers, see [Runtime policy](#runtime-policy).

## Restoring a node onto an empty VM

A node that is lost is rebuilt from its state archive: install an empty VM, run
`haprion-node-restore`, and the VM becomes that node - its hostname, address, SSH host keys,
accounts, node scripts and keepalived role - and then fetches its configuration and certificates
the way a deploy does. Nothing is installed on the VM beforehand.

**What counts as an empty VM.** Ubuntu 26.04 or Debian 13, installed from its cloud image - whichever
the node ran before does not matter; both write their network as Netplan, which is what the restore
writes. One network
interface with the same name as the node's, a temporary address the management host can reach,
an administrator account with `sudo`, and neither `haproxy` nor `keepalived` installed - the
restore installs them itself, with their services held off until their configuration is in place. The node's own address must not answer: a restore onto
it while the old node is still up would put two machines on one address, and the preview stops.

The same command also repairs a node that still runs, over itself - see *Repairing the node
itself* below.

**Three steps, each its own command**, run as root on the management host:

```bash
# 1. Choose the node, the archive (by its version, from haprion-list-backups) and the VM.
sudo haprion-node-restore prepare -c alpha --node node-a \
    --archive 2026-01-01_04-00-00 --target 192.0.2.120

# It prints one line. Paste it on the VM, as its administrator. It adds this run's
# one-time key to root's authorized_keys - restricted, and accepted only from the
# management host's address - shows the line that landed, and prints the VM's
# host key fingerprint.

# 2. Compare: the fingerprint it printed is the one the preview is given.
sudo haprion-node-restore preview --run <run> --fingerprint SHA256:...

# 3. Carry out exactly what the preview showed, confirmed with the node's name.
sudo haprion-node-restore run --run <run> --confirm node-a

# To abandon a run: remove its directory and one-time key.
sudo haprion-node-restore discard --run <run>

# How a run stands: running, finished (and how), stopped mid-run, or not started.
sudo haprion-node-restore status --run <run>
```

**The same three steps from the interface.** An administrator with management writes gets
*Restore…* on each archive row of the backup page. The form takes the temporary address and the
mode (the node itself, or a test with its hostname, address and VIP); the run's own page,
`/backups/restore/<run>`, then shows the line to paste, takes the fingerprint, shows the plan and
takes the node's name as confirmation. Each step is one job - `node_restore_prepare`,
`node_restore_preview`, `node_restore` - run by the worker through the root helper on
`node-restore.sock`, the same engine as the command. The page is drawn from those jobs alone;
nothing else is stored. While a job runs it holds the cluster's job slot, so a deploy to that
cluster waits. *Discard* on the run's page is the fourth job, `node_restore_discard`.

**When the run's job loses its answer.** The job ends `unknown` - the helper may have gone on as
root and changed the node - and the page says *Outcome unknown* rather than failed. *Ask for the
outcome* queues the fifth job, `node_restore_status`, which reads the run's directory and changes
nothing. A finished run is then drawn as its own answer; otherwise the page says what was found:
still running, stopped mid-run (look at the target), or never started. The helper's socket takes
one connection at a time, so while a restore still holds it the question is answered *ask again
when it has finished*.

**A run has an hour.** From *prepare* to the start of *run*: past it the run has expired, the
backup page stops listing it, its page takes nothing more, and the command and the helper refuse
it and remove its directory - prepare a new one. Every call to either, and every node state
backup, puts away the runs past their hour that no step is working in. A run that never began writing to the target goes whole;
one that did loses its one-time key, `known_hosts` and preview at the hour and keeps
`request.json`, `prepared.json`, `started.json` and `result.json` for seven days - as long as the
web keeps its jobs - so its outcome can still be read with `status`. The pasted line
carries `expiry-time` two hours after *prepare*, so the VM itself stops accepting the one-time key
even when nothing on the management host ever runs again.

**What the preview shows and what stops it.** The target's OS, interface and MAC address; the
host key fingerprint; the name and address the VM will have; every file written, and every archived
file that is not - the VM's own in a directory it shares with the image, the archive's APT sources,
and old `.replaced-` copies (kept on the node, 30 days - see
[What a node keeps and for how long](#what-a-node-keeps-and-for-how-long)); the node package that will prepare the node, and the WAF engine package when the node ran it; every account with its IDs
and groups; and, in test mode, every rewritten field with its old and new value. It stops on: this
manager's CLI release carrying no node package, or one that does not verify (see
[Part 3](#part-3--the-versioned-cli-release)); for a node that ran the WAF engine and a target
without it, the release carrying no engine package, or one that does not verify; a `node.conf` in the archive that cannot be read back
into answers; a fingerprint that is not the one
given (nothing is sent at all); a target whose clock is more than five minutes from the manager's -
a VM put back from a snapshot often runs days behind, and apt then refuses every repository; an archive that is not of the chosen node; a target that is not
Ubuntu 26.04 or Debian 13; `haproxy` or `keepalived` already installed (unless an earlier restore run left
them there - a run that rolled back can be tried again); the final address, or the node's own,
already answering; and an account whose primary group the archive does not
carry. A number the VM already uses stops nothing: an account or group is its name. One the VM
already has keeps the VM's number, a new one gets the archive's number where it is free and a free
one of the same kind (system or ordinary) where it is not, and the preview lists every such
change; the restored files are owned by name, so they follow. `run` asks the VM again and refuses unless the
archive, the VM and the plan are exactly what the preview saw - so what was approved is what is
written.

**What `run` does, in order.** Three SSH sessions with the one-time key:

1. On the temporary address: the archive's groups and accounts, numbered as above (before any
   package can take a number), password hashes only for accounts that have no password on the VM, the
   HAProxy repository for the VM's own distribution and release on the branch the node ran (the
   archive's APT sources name the release it was taken on and are not written; the VM keeps its
   own; the repository's signing key ships with the product and is used only when its fingerprint
   is the one pinned in the code - it is never fetched at restore time), then `haproxy keepalived rsyslog openssh-server rsync python3 netplan.io` with
   service starts held off until their configuration is in place, then the files. Only paths the
   export copied get the archive's ownership and mode; a directory it created only to hold one is
   made if missing and otherwise left alone. What the product shares with the OS image is restored
   file by file, not directory by directory: in `sudoers.d` and `sysctl.d` only the file
   `04-node-prepare` writes comes back, and `sshd_config` and its drop-ins stay the VM's own. An
   operator's own file there comes back when the node names it in `EXTRA_BACKUP_PATHS`. Then the
   HAProxy release layout, the services, the hostname, and sshd is reloaded. When the archive shows
   the node ran the WAF engine, the engine package the manager's own CLI release carries is installed
   next: it is in no repository, and the node's deploy refuses a release with WAF rules without it.
   Last, the node package of the manager's own CLI release is installed on the VM and its `04-node-prepare` runs,
   with an answers file read back out of the archive's `node.conf` (and the manager's publish
   root): the package puts the node scripts of the running release in place, not the archive's,
   and the step writes `node-installation.json`, the sudo
   rules, the traffic-log directory, and re-renders `node.conf` - to the same bytes, which the
   preview's answers are tested against. If the archive shows the traffic log was on, the bundle's
   `haprion-traffic-log-enable` turns it on again, prune timer included.
2. Still there: the archive's Netplan, bound to the VM's MAC address, applied three seconds after
   the session ends - under a timer that puts the VM's own Netplan back after 180 seconds.
3. On the node's own address, with the archive's host key: the timer is cancelled, HAProxy starts
   on a placeholder release whose only listener is a root-only unix socket, the node's
   `haprion-cert-pull` fetches the cluster's certificates and its `haprion-pull-deploy` the
   published configuration - the same scripts a deploy triggers - keepalived starts as `BACKUP`,
   and **last** root's `authorized_keys` is replaced by the archive's, which removes the one-time
   key.

If the node never answers on its own address, the timer returns the VM to its temporary address
and the run reports `failed` with the network rolled back. A session that breaks or times out
once writing has begun is a `failed` run in that session, never a refusal. The run's result is
kept in `/var/lib/haprion/restore/<run>/result.json`, root-only `0600` in a `0700`
directory, with `started.json` written just before the first write to the target. A restore takes about a minute; the longest part is the package installation.

**Test mode proves a restore before it is needed.** Add `--test --test-hostname <name>
--test-address <address/prefix> --test-vip <address/prefix>` to `prepare`. The node is restored as
above, except that the hostname, the node address in Netplan, keepalived's own address and its
virtual addresses are rewritten to the test values - the preview lists every one - the `include`
of the published address list is removed, keepalived is masked so it can never join the
production pair's VRRP, and the VM keeps its own SSH host keys. The test address must be in the
node's network, because the node's routes come with the archive. `--confirm` takes the test
hostname.

**Repairing the node itself.** The same restore, with the node's own address as `--target`, puts
the archive back over the node - for a node left in a bad state by hand. Nothing is chosen for
this: the preview tells the two cases apart by the host key the target offers. The archived one
means the node itself; any other means an empty VM in its place, with the rules above. The paste
and the three steps are the same; over the node itself, what differs:

- the node must be reached at the address its archive gives it;
- the preview takes a state backup of the cluster and reads the pair: whether this node holds the
  VIP and whether its neighbour is healthy (answering, HAProxy and keepalived active). It lists
  every file whose contents differ from the node's, how many are already equal, what goes to
  quarantine, and whether the network differs;
- `run` refuses when that backup failed, unless `--backup-failed-ok`, and when the node may hold
  the VIP while its neighbour is not healthy, unless `--break-traffic` - which is what it says;
- before its first write the run copies every path it or `04-node-prepare` may change to
  `/var/lib/haprion-restore/<run>/before/` on the node, then stops keepalived, so the VIP moves to
  the neighbour before anything changes. The copy stays 30 days (see
  [What a node keeps and for how long](#what-a-node-keeps-and-for-how-long));
- the node's software is its own: no repository file is written, and only a product package the
  node lacks is installed (`apt-get install --no-upgrade`, from the node's own sources) - the WAF
  engine, which no source has, from this manager's release. The node
  package is not replaced - the node's own `04-node-prepare` runs, and a node without the package
  is refused before anything is written. The HAProxy releases and `current` are not touched;
- what `/etc/haprion` and `/etc/systemd/system/haproxy.service.d` hold beyond the archive
  and what `04-node-prepare` writes goes to quarantine on the node - not deleted by the run, and removed with the
  run's directory after 30 days ([What a node keeps and for how long](#what-a-node-keeps-and-for-how-long)); the directories the product
  shares with the OS image keep the image's files, as for a new VM;
- Netplan is written only when the node's differs from the archive's; otherwise the network
  session is skipped and nothing is applied;
- if a session fails, the node is put back from its copy in the same session - or, after a
  network change that never came up, by the timer and then from the management host once the node
  answers again - keepalived is started again, and the run is `failed` with `rolled_back`. The
  one-time key stays in root's `authorized_keys` until its `expiry-time` when the run was put back.

**What it does not do.** Restore onto an OS other
than Ubuntu 26.04 or Debian 13; configure what is the environment's rather than the product's - a
configuration-management baseline, monitoring agents, an operator's own sudo rules - which runs
afterwards as it would on any new machine.

The restore is one piece of a recovery plan; the rest - where the VM comes from, how the management
host survives, who fails over - is yours to decide. [`DISASTER-RECOVERY.md`](DISASTER-RECOVERY.md)
lists the questions.

## What a node keeps, and for how long

Three kinds of copies build up on a node. The first two are removed automatically after
**30 days**, the third by count, and each only at the moment a new copy of the same kind is made. Nothing runs on the node on a schedule
for this. A node that is never reinstalled or restored keeps its copies until it is.

| What | Where | Made by | Removed |
|---|---|---|---|
| rollback copy of a file an installer replaced | `<file>.replaced-<yyyymmdd-hhmmss>` beside the file, e.g. `/etc/haprion/node.conf.replaced-20260924-200115` | `04-node-prepare` (and so every node package installation and every restore) | when the same file is next installed, if the time in its name is more than 30 days old. **The newest copy of each file always stays, however old.** |
| a configuration release: everything a deploy installed - `haproxy.cfg`, `conf.d/`, the certificate lists, `waf/`, `dns/`, `keepalived/` | `/etc/haproxy/releases/<yyyymmdd-hhmmss>/` | `haprion-pull-deploy`, once per deploy that changed something | after a deploy that completed, all but the newest 10. **The release `current` names, the one running before that deploy and one an interrupted deploy left behind always stay.** `KEEP_RELEASES` in the script; each removal is logged `pruned <path>`. |
| a restore run's directory: the `before/` copy an overwrite took, its `quarantine/`, and the node package it installed | `/var/lib/haprion-restore/<run>/` | `haprion-node-restore` (the terminal or the web page) | when a later restore run begins writing to the same node, if the run is more than 30 days old (by the date in its ID, `r<yymmdd>-…`). The current run is never removed. |

Why 30 days: a copy is for the days after a change, until the change has proved itself. After
that, the nightly state backup on the management host is the node's history and a node package
rollback is done with the previous package (see [node package rollback](#rollback)), not with these copies. The
age of a `.replaced-` copy is the time in its name, not its modification time: `cp -a` keeps the
original's.

To keep something for longer, move it out of those names before the next installation or restore:
anything not named `<file>.replaced-<yyyymmdd-hhmmss>`, and any directory under
`/var/lib/haprion-restore` that is not a run ID, is left alone. The periods are
`REPLACED_KEEP_DAYS` in `install/lib.sh` and `RUN_KEPT_DAYS` in `haprion/restore_agent.py`.
Each removal is printed: `pruned <path>` in the installer's output, and an `old-runs` step in the
restore's `apply` session.

The manager's own installers use the same `install_file` and so the same rule for the files they
write; the manager is backed up as a whole machine and needs no older copies than that.

## Keeping jobs, sessions and metric history bounded

```bash
sudo haprion-retention report              # quick overview; log row counts are estimates
sudo haprion-retention report --exact      # count every traffic/WAF log row
sudo haprion-retention prune --dry-run     # the same, deleting nothing
sudo haprion-retention prune               # what the daily timer runs
```

The quick report sums row estimates and total storage (including indexes) from leaf
partitions only. It labels the counts as estimates and lists partitions without statistics;
run `report --exact` when an exact log count is needed. Both reports leave data unchanged.

**It is a root command because no application role holds `delete` on any table,
and none is going to.** That is the same boundary as the audit trail and the
login attempts: a compromised web or worker process must not be able to remove
the record of what it did. The migration role owns the table and may therefore
delete from it, and the ident map lets root — and only root — be that role for
this database. The step verifies that last part rather than describing it: if an
application identity could connect as the owning role, nothing about `delete`
being ungranted would matter.

#### What it removes, and what it will not

- **Finished jobs older than seven days.** A management request older than that
  has been acted on or superseded, and *what it did* is in the audit trail.
- **Audit records older than two years.** Nothing younger is ever removed, and
  no application role may remove anything at all.
- **Never a `pending` or `running` job**, however old. Those are the states the
  single-active-job index is built on, and removing one would let a second
  operation start against a cluster that is still being changed. Every other
  state carries a `finished_at` by the table's own constraint, so the age test
  cannot match a row that has no timestamp.
- **Never the twenty most recent rows**, whatever their age. Without that floor
  a quiet fortnight empties the jobs page completely, which reads as the
  interface having lost its history rather than as nothing having happened.
  Twenty is the number the page itself lists, **ordered the way the page orders
  them**, so the floor is exactly the set a reader can see. Ordered any other
  way it would select a different twenty rows and quietly stop promising
  anything.
- **OIDC sign-ins in progress older than a day** (schema `0041`). Each sign-in
  through the provider leaves one row, usable for ten minutes and once; a day
  is kept so a failed sign-in can still be looked at the next morning.
- **Sessions that ended more than thirty days ago**, expired or signed out. A
  live session is never touched.
- **Sign-in attempts older than ninety days**, far outside any throttle window
  (at most a day) — **except each name's newest successful attempt**, which is
  what *Last sign-in* on the Users page reads. A break-glass account may go
  unused for longer than ninety days and must not then read as never used.
- **Diffs of versions no longer listed.** The poller keeps what
  each version changed and may only add; after a history reset, or once a
  version is older than the listing reaches, its diff is removed here. A cluster
  whose last listing failed is left alone.
- **Never the audit trail.** It is the record of what every identity did and
  is kept for the life of the installation.

The timer runs daily, after the daily dump rather than before it, so the newest
dump still contains the rows the prune removes.

The same command creates the metric tables' future partitions, writes the pool's
hourly rollup and removes expired partitions. It performs those actions in that
order. The rollup and its `metric_rollup_state` completion boundary are written
by one SQL statement; a failed statement advances neither. Only then may raw
pool partitions be dropped, and only when their complete day is at least one
further day behind that boundary. Listener metrics have no rollup and keep their
fixed seven-day raw retention.

The rollup keeps one reading per pool and hour for a year. The interface no
longer reads it: windows longer than a day are read from per-hour sums of the
samples' stored differences (schema `0055`), which a trigger keeps as samples
arrive, for frontends and pools alike. Schema `0055` filled the pools' older
hours from the rollup once. The command deletes those sums when they are older
than 31 days, one more than the longest window. `report` still prints the rollup
boundary, which decides when raw pool partitions may go.

The timer is daily because that normally keeps the completed edge six days
ahead of the seven-day raw retention. The explicit boundary is what keeps a
longer outage correct; the schedule is not treated as proof that work
finished.

## Traffic logs and metrics

### A basic log viewer, on purpose

The page answers one question: what did the recent requests look like. A filter —
cluster, status class, search, a from/to time — searches every day the database
holds, and the page shows the newest matches, at most `max_lines` of them (500 by
default, at most 10 000). A column heading reorders **those rows**; it does not ask
the database for another order, so sorting on *Bytes* shows the largest of the
newest matches, not the largest of the week. Each row shows the time, cluster and
node, client, request, status, destination and size, and nothing more.

An object's page links to its own requests: *Traffic log* and *WAF logs* on its
*Metrics* card, and beside each backend on the cluster's *Metrics* page, open the
page narrowed to that object, said above the table with a
link back to all of them. An object's requests are those to its backends, and those
for its hostnames that never reached one - refused by an access rule, dynamic
blocking or the WAF, or redirected.

That is deliberate. Aggregation over time, dashboards, alerting, long retention
and correlation with other systems are what dedicated log platforms such as Loki
or Elasticsearch do well, and rebuilding them here would be a second, weaker copy.
An installation that needs them should send the logs to such a platform, and
the nodes can do that themselves: see [Sending the traffic log elsewhere and metrics](#sending-the-traffic-log-elsewhere-and-metrics).

**Under heavy traffic.** Every request is kept on its node and reaches the manager, but the page
shows at most the newest 500 matches - during a flood, a few seconds' worth. A filter narrows those
500; it does not summarise the rest. After a burst the newest rows can arrive a minute or two
late - the collector fetches for up to thirty seconds per node each minute - and the warning says
*catching up* until they have. How many
requests, which statuses and from where over time is the work of the
[exporter](#sending-the-traffic-log-elsewhere-and-metrics) and a log platform: set them up before
they are needed.

### Sending the traffic log elsewhere, and metrics

Each cluster can send its traffic log to up to four external receivers,
expose HAProxy's own Prometheus exporter and share its counters between its
nodes. All three are settings of the cluster's
HAProxy configuration, kept in `managed/cluster.yaml` in its repository and
published as a version like any other change - a lock, a validated candidate,
*Published by*, and a revert that takes them back. Nothing is relayed through the
management host: after `haprion-deploy` the nodes send and listen themselves - the
receivers through the node's own rsyslog, which the deploy configures.

```yaml
# managed/cluster.yaml
log_targets:
  graylog:
    address: 192.0.2.20      # an IP address, never a name
    port: 6514
    disk_mib: 1024           # optional; the queue on the node's disk, 64 to 65536 MiB
    tls: false               # optional
not_logged_from:             # optional; a monitor's answered requests are not logged
  - 192.0.2.40
metrics:
  port: 8405
  sources:
    - 192.0.2.0/24           # who may scrape; everyone else gets 403
peers:
  port: 10000                # optional; counters shared between the nodes
```

An admin edits it under **Settings → Logs & metrics**, one row per cluster and a
page for each (installations with `management_writes` on); saving keeps the
change until it is published from *Versions*, and deploying it is what reaches
the nodes. Or read and set it at the terminal - `--set` publishes at once,
through the helper *Versions* publishes with, against the version it has just
read, so a change
somebody else published in between is refused rather than overwritten. It runs
under `sudo`, and the version records the person who typed it:

```bash
sudo haprion-cluster-settings -c alpha
sudo haprion-cluster-settings -c alpha --set cluster.yaml -m "Send the traffic log to graylog"
haprion-deploy -c alpha
```

For automation, `apply` compares first and publishes only where the file differs from what is
stored; `--check` says whether it would, and `--json` answers with `changed`:

```bash
sudo haprion-cluster-settings apply -c alpha cluster.yaml --check --json
```

**The log** is the same structured record the node's own file gets ([Mirroring node traffic logs](#mirroring-node-traffic-logs)),
with `node`, the host name of the node that wrote it. HAProxy writes one line per request to
the node's syslog socket, and the node's rsyslog writes it to the day file and sends it to each
receiver as syslog over TCP (RFC 5424, octet-counted), whether or not the local stream is on;
the header carries the node's host name and the tag `haproxy-traffic`. One transport reaches the common platforms through their usual
receivers: Graylog takes it directly, Loki through a syslog receiver such as
Grafana Alloy's `loki.source.syslog`, Elasticsearch or OpenSearch through
Logstash or Vector with a syslog input. `tls: true` verifies the receiver's certificate chain
against the node's system trust store (rsyslog's GnuTLS driver, `rsyslog-gnutls`), not its name.

A receiver is named by **address, never by host name**, so what the nodes send to does not depend
on their resolver at the moment rsyslog starts.

**Not logged from** leaves out a monitor that asks every service once a minute - thirty services
make some 43 000 lines a day nobody reads, in the node's file, the *Traffic logs* view, the
dashboard's response times and every receiver. A request from one of the addresses or networks
listed, answered below 400, is written nowhere; one answered 400 or above is logged as any other,
so a monitor that is refused or finds a service down still shows. Only the connection's own address
counts, never a header a request carries. The exporter's counters include these requests either way.

Each receiver has a **queue on the node's disk**, `disk_mib` large, and the queue is what an outage
or a burst is survived with. While a receiver is away or reads slower than the traffic, rsyslog
keeps the lines on disk and sends them when it reads again; the queue survives a restart of
rsyslog or of the node. A deploy that changes the receivers restarts rsyslog, and the lines HAProxy
writes meanwhile wait in its log socket ([HAProxy and keepalived baseline](#haproxy-and-keepalived-baseline)).
If rsyslog refuses the new receivers, the node puts the previous ones back and the deploy fails
with the configuration already live; the node is then not current, as with a half-way address list
below, and the next deploy finishes it. About 800 bytes a line, so 1 GiB holds some 1.3 million. What does not fit
is dropped for that receiver alone and counted - neither the traffic nor the node's own day file
waits for a full queue. Measured with rsyslog 8.2512 on one core: 25 000 lines a second forwarded
and written to file at 9 % of the core; 100 000 lines queued while the receiver was away arrived
about a second after it came back.

Each receiver's queue shows on the node: `haprion-status` prints `Log forward:` per node, the
cluster's page under **Settings → Logs & metrics** has a **Delivery** table - each receiver as each
node sends to it, its queue and its state - and **Needs attention** lists a receiver whose queue has
neither emptied nor shrunk for three minutes or holds 10 000 lines or more, and as critical one that
dropped lines in the last hour ([Needs attention, and external monitoring](#needs-attention-and-external-monitoring)).
The exporter's counters are complete either way.

When the node's rsyslog cannot connect, it says why, and the node passes that on: *Connection
refused* or *Connection timed out* beside the queue, in the terminal as in the table and the
attention row, until the receiver is reached again. What it usually means:

| Reason | Usually |
|---|---|
| *Connection timed out* | a firewall between the node and the receiver drops the connection; or the address is wrong and nothing answers there |
| *Connection refused* | the receiver's host answers but nothing listens on the port: the receiver is stopped, or the port or protocol is wrong (a TLS port given without TLS, or the other way round) |
| none, and lines are not delivered | the connection is made but the receiver does not read: it is overloaded, or TLS is refused after connecting - its own log says which |

**The exporter** answers `GET /metrics` on the port given, on each node's own
address - the address its `mgmt_host` gives, never a VIP - so Prometheus scrapes
the nodes by name, and scraping each node is what shows the passive one as well.
Only the listed sources get an answer; anything else gets 403, and any other
path 404. An object may use the same port on a VIP; a publish refuses a port
that `manual/reservations.yaml` reserves. Letting the scraper through the
nodes' firewall, and letting the nodes reach the log receivers, is part of the
installation, not of this setting.

**Shared counters** keep the abuse brake's and the rate limits' counts the same
on every node of the cluster, so a failover or a deploy no longer starts them
from zero. With `peers` set, a publish writes a `peers` section with one line
per node and has every generated stick table name it; each node keeps the
others up to date over the port, and a node that reloads takes the counts back
from the others within seconds. A node that reloads while no other node is up
starts from zero. What is shared is counters, not connections: a connection open
on the node that fails still ends, and the client's next one is counted with
what it had already used. Persistence is unaffected - it is a cookie or a hash
and needs nothing shared.

The address of each node is looked up from its management host name when the
cluster is published, so a node that changes address needs its DNS record
changed and a publish; a name that does not resolve, or gives more than one
address, refuses the publish and names the node. A node finds its own line by
its host name, which has to be the node's name. The port has to be open between
the nodes, both ways, and nowhere else - that firewall is the installation's;
the traffic is not encrypted and carries client addresses and their counts. On
the dashboard, a node whose counters do not reach another node, or that shares
none while the others do, reads *Counters not shared* with the reason.

**DNS objects are scraped from dnsdist.** A cluster with the exporter and a DNS
object also has dnsdist answer `GET /metrics` on port 9521 of each node's own address,
for the same sources (and on loopback for the node itself); without the exporter it answers on
loopback only. Its metrics are dnsdist's own (`dnsdist_*`), with each server
named `<pool>/s<n>` and each object's queries counted by the rules `<pool>`,
`<pool>/tcp` and `<pool>/refused`. Its API stays closed.

**The names a dashboard shows.** The exporter labels every backend metric with
`proxy="<name>"`, and carries nothing else that could name it - a backend's
`description` is not exported (HAProxy 3.4). So a pool is called in HAProxy
exactly what it is called on the object form: pool `web-80` of object
`shop-web` is the backend `web-80`, on the interface's metrics page and in a
dashboard alike. That is why a pool's name must be unique in the cluster, and
why it may not begin with `mgd-`, which is what the generator's own sections
are called (the exporter's frontend, the VIP frontends, the WAF engine). A
redirect has no pool and is called after its object and path,
`shop-web-redirect-old`.

**A rename keeps its history on the interface's pages.** The metrics page lists
only the backends the cluster's newest poll reports, and each card reads the
names its backend had before as well: any name a publish renamed. A publish counts as a
rename when exactly one of an object's pools goes and one comes, and for a
redirect when its object is renamed; two pools renamed at once are not paired.
The pair is recorded when the publish is done (table `metric_backend_alias`) - a
publish refused or failed renames nothing - and a name given to a backend again stops counting for the one that had it. A
dashboard reading the exporter sees a new series under the new name - HAProxy's
counters begin again with it.

#### Counters across a reload

Every deploy reloads HAProxy, and a reloaded HAProxy starts its counters from
nought unless the cluster's `core/haproxy.cfg` names a file to keep them in:

```
global
    shm-stats-file /run/haproxy/stats.shm
```

A new cluster's core has the line. HAProxy then keeps each frontend's,
listener's and server's counters in that file and finds them again after a
reload by the GUID the generator gives every object, so a deploy puts no
step into a dashboard reading the exporter. Changing a server's address is a
different server and starts again; reordering a pool moves nothing.

- **A pool's own figures still start again on every reload.** HAProxy 3.4.6
  carries a backend's own counters badly - each reload attaches the backend to
  the other of two places in the file, so its totals show the figures of the
  process before last - and so the generator gives backends no GUID until it
  does. Its servers are carried; a redirect, which has no server, is not.
- **A restart still resets everything.** HAProxy gives the file up when it is
  stopped properly, and `/run` is emptied when the node starts. HAProxy opens
  the file as root before it changes into its chroot, so the path is the
  node's own; the validation on the manager gives a check an empty
  `/run/haproxy` to make the file in, so another path is refused there.
- **The interface's own figures were right before and stay right.** A node reports
  whether its HAProxy has the file in use (`runtime.shared_counters` in
  `haprion-status --json`), and the metrics count a reload as a restart only
  when the counters did start again: when they were not kept, or when one of
  them went down.

**A DNS object's card** is counted by dnsdist rather than HAProxy, under the
pool's name like any other: Queries (everything that reached the listener),
Answered (what its servers answered), Refused (refused for `allow_from`),
Unanswered (asked, less refused, less answered - a server that timed out or no
server up to ask) and Over TCP. On the metrics page a DNS object's pool is one of
the backends, in the same list and on the same scale, its line counting queries.
Per-server figures are left to the logging the nodes send elsewhere. Response codes
(NXDOMAIN, SERVFAIL) are not shown: dnsdist 2.1 counts them for the whole
process, not per pool. dnsdist's counters are read on the node and are not part
of HAProxy's exporter, so a dashboard reading the exporter does not see them.

## Jobs and status freshness

### Needs attention, and external monitoring

Under the dashboard's four cards, *Needs attention* lists what is wrong and wants somebody, across
every cluster, the worst first, each row linked to where it is fixed: a certificate that is running
out, unreadable or not where it should be (the interface's own included); a cluster's latest job of
an operation that failed, partly worked, was blocked or ended unknown - until a later run of the
same operation works; a node that is down; an object whose servers are not up, as its lamp on
*Proxies* says it - critical when no node reaches any of them, a warning when some are down or down
on one node only (an object without a health check has no lamp and is not listed); a cluster whose status
has not been read for two poll intervals; a WAF exception marked *Not working*; a node backup that
is missing, old or failed; a node whose traffic log collection failed, has not succeeded for five
minutes or is still behind after five runs or with older days waiting (catching up after a burst
is left to the log page's own warning); a receiver of the traffic log whose queue on the node
has neither emptied nor shrunk for three minutes or holds 10 000 lines or more, with the reason the node's rsyslog
gave when it has one, or - critical - that dropped lines in the last hour. Nothing there, no
box. What somebody chose - a drained server, a
maintenance page, a block, a publish not yet deployed - is not on it: those are on the cluster's
card and *Operations* line, and on *Versions*.

Some things are known and left as they are - a restore given up, a receiver down on purpose. An admin
**acknowledges** such a row, and it is left out of the list and of what the monitor is told until it
has gone: when what it says is put right, or a later run of a job's operation works. The same trouble
coming back after that, or a job of the operation failing again, is a row again. Each
acknowledgement is in *Audit* with who made it and what the row said (schema `0073`).

The same list answers a monitor, without a sign-in:

```
GET https://<manager>/status/attention.json
GET https://<manager>/status/metrics
```

The first is `{"generated_at", "fresh", "counts": {"critical", "warning"}, "items": [...]}`, each
item with `kind`, `severity`, `cluster`, `subject`, `message`, `since` and `link`; `fresh` is false
once any cluster's status reading is older than two poll intervals, which is how a monitor sees that
the manager itself has stopped reading. The second is Prometheus's text format:
`haprion_attention_items{kind, severity}` for every kind and `haprion_status_age_seconds{cluster}`.

Who may ask is a list on *Settings → External monitoring* (*Edit* on its row): addresses or
networks, one per line; an address that stays keeps who added it and when. Every
other address - and every address while the list is empty, which is the endpoint switched off - is
answered 404. The address is the one nginx hands the interface, so with a reverse proxy in front it
is the client the proxy names. A monitor that is answered 404 is not on the list. `haprion-settings apply` sets the
same list from a file (*Settings from a file*).

Any monitor that can make an HTTPS request will do; three ways follow. In each, *healthy* means
nothing red on the dashboard and every cluster read recently. Warnings - a certificate with less
than thirty days left, a backup overdue - are better a second, quieter check than a page at night.

#### What the answers look like

With nothing to do:

```json
{"generated_at":"2026-10-11T20:00:00Z","fresh":true,"counts":{"critical":0,"warning":0},"items":[]}
```

With a certificate running out and a failed node backup:

```json
{
  "generated_at": "2026-10-11T20:24:09Z",
  "fresh": true,
  "counts": {"critical": 2, "warning": 0},
  "items": [
    {"kind": "certificate", "severity": "critical", "cluster": null, "subject": "shop.example.com",
     "message": "expires in 4 days", "since": null, "link": "/certificates?view=registry"},
    {"kind": "backup", "severity": "critical", "cluster": "beta", "subject": "beta",
     "message": "node backup · Last run failed", "since": null, "link": "/backups"}
  ]
}
```

And the metrics, shortened:

```
haprion_attention_items{kind="backup",severity="critical"} 1
haprion_attention_items{kind="certificate",severity="critical"} 1
haprion_attention_items{kind="certificate",severity="warning"} 0
haprion_attention_items{kind="job",severity="critical"} 0
haprion_status_age_seconds{cluster="alpha"} 12
haprion_status_age_seconds{cluster="beta"} 14
```

`kind` is one of `backup`, `certificate`, `forwarding`, `job`, `logs`, `node`, `reading`, `service` and `waf`, and every pair is
present even at 0, so an alert expression never meets a missing series.

#### Uptime Kuma

A monitor of type **HTTP(s) - Json Query**:

| Field | Value |
|---|---|
| URL | `https://<manager>/status/attention.json` |
| Heartbeat interval | `60` |
| Json Query | `counts.critical = 0 and fresh = true` |
| Expected value | `true` (condition `==` where the version asks for one) |
| Method | `GET`, no body, no headers |

It is up while the expression is true and goes down within one interval of anything turning red,
or of the manager no longer reading the clusters. For the quieter second monitor:
`counts.critical = 0 and counts.warning = 0 and fresh = true`.

Uptime Kuma runs on Node.js, which trusts its own list of public CAs rather than the operating
system's. If the manager's certificate is issued by your own CA, the monitor says *unable to verify
the first certificate*. Either give Uptime Kuma the root - its PEM file, named in the environment
variable `NODE_EXTRA_CA_CERTS`, then a restart - or tick *Ignore TLS/SSL errors* on this monitor,
which stops it checking who answered.

#### Prometheus

```yaml
scrape_configs:
  - job_name: haprion
    scheme: https
    metrics_path: /status/metrics
    scrape_interval: 60s
    tls_config:
      ca_file: /etc/prometheus/your-root-ca.pem
    static_configs:
      - targets: ["<manager>:443"]
```

```yaml
groups:
  - name: haprion
    rules:
      - alert: HaprionNeedsAttention
        expr: sum(haprion_attention_items{severity="critical"}) > 0
        for: 2m
        annotations:
          summary: "Haprion: {{ $value }} critical item(s) on the dashboard"
      - alert: HaprionWarnings
        expr: sum(haprion_attention_items{severity="warning"}) > 0
        for: 1h
      - alert: HaprionStatusStale
        expr: max(haprion_status_age_seconds) > 300
        for: 5m
      - alert: HaprionEndpointDown
        expr: up{job="haprion"} == 0
        for: 5m
```

`haprion_status_age_seconds` is the seconds since each cluster was last read; at the default
poll interval of 20 seconds it stays well under a minute.

#### Anything else: a script

For a monitor that runs a command and reads its exit code - Nagios, Icinga, Zabbix, Checkmk, or
cron with mail:

```sh
#!/bin/sh
# 0 OK, 1 warning, 2 critical, 3 unknown - the Nagios convention.
MANAGER=manager.example.com
CA=/etc/ssl/your-root-ca.pem
answer=$(curl -fsS --max-time 10 --cacert "$CA" \
         "https://$MANAGER/status/attention.json") || { echo "UNKNOWN: no answer"; exit 3; }
critical=$(printf '%s' "$answer" | jq -r '.counts.critical')
warning=$(printf '%s' "$answer" | jq -r '.counts.warning')
fresh=$(printf '%s' "$answer" | jq -r '.fresh')
items=$(printf '%s' "$answer" | jq -r '[.items[] | "\(.subject): \(.message)"] | join("; ")')
[ "$fresh" = true ] || { echo "CRITICAL: the manager has stopped reading its clusters"; exit 2; }
[ "$critical" -eq 0 ] || { echo "CRITICAL: $items"; exit 2; }
[ "$warning" -eq 0 ] || { echo "WARNING: $items"; exit 1; }
echo "OK: nothing needs attention"; exit 0
```

The message carries each item's subject and sentence, so the alert says what is wrong without
opening the dashboard.

### Events: jobs, the nodes and the audit record

*Events* has three views. **Jobs** lists the newest jobs, their outcome and diagnostics, and *By*:
who queued each one, from the record. **Nodes** is what the nodes did on their own: a server that
went down or came back up, with the check's reason, the VIP moving from one node to the other, and a
node that stopped answering or answers again. A server's row names its object and links to its
servers. Both roles read it; it pages and filters by cluster, a word and time as *Audit* does, and
the nightly retention removes rows older than 90 days. It is written by the poller, which compares
each status reading with the one before: a server's change is dated by HAProxy's own count of how
long ago it changed, so the time is right to the second, but a server that went down and came back
between two readings leaves no row. Servers are read from the node holding the VIP, as the metrics
are - the other node's check leaves from an address it does not have. A server in drain or
maintenance keeps its last state until it is checked again, and the first reading of a new server
or installation is a starting point rather than an event. A restart of HAProxy is not listed: a
reload starts its uptime again too, so the two cannot be told apart, and a deploy is already under
*Jobs*. **Audit**, for an admin only, is the rest of the record,
newest first, fifty to a page by default: sign-ins and failed attempts, account and role changes, password
changes, the identity provider, feature switches, key exports, saved and discarded changes and
drafts, and every queued job with a link to it while the job is still listed. Each row is one
sentence; a row with more to it opens under itself when clicked. Filter by cluster, who or a word (a
search reaches back 90 days), and page through it as through the traffic log. A failed sign-in under
a name no account has shows as *unknown user* and never the name typed, which may have been a
password. The record is append-only: no role may change or delete a row, and the nightly retention
removes rows older than two years.

On an object's *Servers* card, a server in drain or maintenance says *Set by <name> · <time>*: the
newest request that asked for the state it is in.

### How often status is refreshed

`poller.interval_seconds` in `ui.toml`, 20 by default, bounded to 10-3600. It is
a sleep *after* a pass rather than a fixed period, so the real cadence is the
interval plus however long a pass takes - measured at 2-3 seconds for two
clusters on the reference machine, where one pass is fourteen helper
invocations and two of them reach the nodes.

**A finished job wakes it as well as the clock.** Publishing or deploying
through the interface queues a job, and the poller reads the clusters again as
soon as that job ends - so those changes appear without waiting. What waits is a
change made *outside* the interface: `haprion-publish` or `haprion-deploy` run
on the command line queues no job, nothing is notified, and until the next tick
the pages show the reading taken before the change. An object deployed from the
command line therefore keeps its `Inactive - deploy to add` badge for up to one
interval, which is the interface being careful rather than wrong.

The same holds for what a version changed. `haprion-list -c <cluster> --diff <version>`
prints one version against the version before it, file by file; the poller asks the
helper for the same thing (`diffs`, at most ten commit hashes per request) for each
version it has no diff for yet and keeps the answer, since a version's diff never
changes. Both read it through one function, bounded at 200 files and 256 KiB of
patch text, and a diff past that bound says it was cut.

Two failure kinds are kept apart in the table. `poll_error` means the poller
could not get an answer — sudo refused, the helper is missing, the output was
not JSON. An `outcome` of `failed` or `partial` means the cluster answered and
the answer is bad news. Collapsing them would send somebody to read sudoers when
a node is down, or the reverse.

### The worker

It starts, connects and reports which database role it is actually running as.
With `management_writes` off it claims nothing: that is the state a rollback of
the write path returns to, so it has to be a state that runs.

With writes on it runs each job through an exact privileged helper, over `sudo`
for most and over a root-owned socket for the few that write under `/etc`. Its
unit therefore allows `sudo` to raise privilege (`NoNewPrivileges=no` and a
short, named capability set); every capability is explained in the unit file
beside it. The real limit is not the sandbox but
`/etc/sudoers.d/haprion-worker`, which names each helper and permits no
arguments: widening the unit does not widen what may be run, only that file
does.

Once writes are on, each pass first settles jobs whose worker died. An expired
lease says only that the process holding a job stopped renewing its authority,
so the job is judged by what can be read rather than retried on assumption: a
publish, a revert or a managed-network publish by whether a version carrying that request exists and
whether its release was published, a deploy or a certificate deploy by nothing
at all, because those read the cluster before they act and repeating one is how
they work. Evidence older than the expired lease is not weak evidence but none —
it describes a world in which the operation could still have been running — and
such a job waits rather than being decided. A job is handed to a worker at most
twice; one that has been taken twice and answered neither time ends as
`unknown`, which is the outcome reserved for "nobody can say whether this took
effect" and is never retried automatically.

This too is below the writes check. With writes off nothing moves at all,
including a job somebody would rather see moved — which is what makes the flag a
rollback rather than a pause.

**The worker may not touch `proxy_draft`.** Only the web role holds grants on it. The worker
publishes from the job payload, never from the table, which is why a draft that has been published
is cleared by the interface on its next read rather than by the worker as it finishes. The clearing
matches on the publish's idempotency key, which carries the draft revision — so a draft edited after
the publish was asked for has a different key and is left alone. A draft and a saved change of the
same object are two rows (`stage`), each cleared by its own publish.

## Automation from the terminal

Everything the interface sets can also be set from a shell on the management host, so that a
configuration tool can describe an installation and run again without changing it. The interface
stays the first way in; the commands go through the same helpers, the same code and the same
refusals, and their writes are audited and versioned the same way.

| In the interface | From the terminal |
|---|---|
| *Proxies*: new, edit, remove, advanced config, WAF exceptions | `haprion-objects apply`, `haprion-objects remove` |
| *Network* | `haprion-network apply` |
| A cluster's *Logs & metrics* | `haprion-cluster-settings apply` |
| *Versions*: deploy, revert | `haprion-deploy`, `haprion-revert` |
| Drain, maintenance, unblock | `haprion-server-state` |
| *Settings → Nodes*: nodes and clusters | `haprion-node`, `haprion-cluster` |
| *Certificates*: issue, import, request, NDES, publish | `haprion-cert-issue`, `-import`, `-request`, `-scep`, `-publish`, `-deploy` |
| *Certificates*: renew | certbot's: `haprion-cert-issue --domain <id> --renew`; NDES: `haprion-cert-scep --id <id> …` |
| *Certificates*: publish to, remove from, delete | `haprion-cert-target`, `haprion-cert-delete` |
| *Certificates*: DNS providers and NDES profiles | `haprion-profiles` |
| External certificate receivers | `haprion-cert-receiver` |
| *Node backups*: schedule, run, restore | `haprion-backup-schedule`, `haprion-state-backup -c <cluster> --json`, `haprion-node-restore` |
| *Settings → Users* | `haprion-user` |
| *External monitoring*, *Features*, OIDC | `haprion-settings` |
| The interface's own certificate | `haprion-tls` |

What they share:

- **A file says what should be.** `apply` reads a file (or, for objects, a directory of files) and
  writes only what differs from what is stored, so the same file twice changes nothing. What the
  file does not name is left alone; `--prune`, where a command has it, removes what it does not
  name.
- **`--check`** says what would change and changes nothing.
- **`--json`** prints one envelope (`docs/CONTRACT.md`, `schemas/v1/`), with `changed` where the
  command decides it. The exit code is 0 for done and the envelope's own code otherwise.
- **Publishing is not deploying.** `haprion-objects apply`, `haprion-network apply` and
  `haprion-cluster-settings apply` publish a new version; `haprion-deploy` rolls it out, as
  *Publish & deploy* does in two steps.
- **With sudo, on the manager.** `haprion-user`, `haprion-settings` and `haprion-profiles` write
  the interface's database as root, and `haprion-export` reads it; they need the platform
  installed, and `haprion-profiles` also a running worker with writes on, since a profile takes
  effect as a job. The others are the engine's: they hand their request to a root helper, and run
  as root that helper runs directly and records the person sudo names.
- **Secrets from a file only its owner may read, or from standard input**: never as an argument.
  A file that carries a password, a client secret or credentials is refused unless its mode is
  `0600`. A secret that is stored sealed cannot be compared, so it is replaced only when it must be
  or when the command is asked to (`--replace-oidc-secret`, `--replace <id>`).

What is not a setting has no command: a person's own password, sessions, drafts, previews and
downloads of key material.

`haprion-export` writes what is set now as the files these commands take, as a place to start;
[Automating with Ansible](#automating-with-ansible) shows the whole of it as a playbook.

### Automating with Ansible

A playbook drives the commands above and reads `changed` from their answers. The interface remains
the way in for a person; the playbook is how the same installation is described, rebuilt or kept
from drifting.

**Where it runs.** The commands live on the management host and run as root, so the play targets
that host with `become: true`. Where sudo asks for the password twice - some PAM stacks do -
`--ask-become-pass` waits for an answer that never comes; run `ansible-playbook` itself as root on
the manager (`sudo ansible-playbook …`) and drop `become`.

**Start from what is set.** On the manager:

```sh
sudo haprion-export /home/operator/haprion
```

The directory must be new or empty; it is written `0700`, its files `0600`, and handed to the
person who ran sudo. `--cluster <id>` (repeatable) limits it to some clusters, `--json` answers in
the contract (`haprion-export` in `docs/CONTRACT.md`).

| File | Taken by |
|---|---|
| `accounts.yaml` | `haprion-user apply` |
| `settings.yaml` | `haprion-settings apply` |
| `profiles.yaml` | `haprion-profiles apply` |
| `clusters/<id>/objects/<name>.yaml` | `haprion-objects apply -c <id> clusters/<id>/objects` |
| `clusters/<id>/network.yaml` | `haprion-network apply -c <id>` |
| `clusters/<id>/cluster-settings.yaml` | `haprion-cluster-settings apply -c <id>` |
| `clusters/<id>/backup-schedule.yaml` | the flags of `haprion-backup-schedule -c <id>` |

Applied to the installation it came from, every file changes nothing - that is the first thing to
run. What the export cannot say it lists as `skipped`, with why: an object the generator refuses,
a network that comes from the cluster definition (there is no document to apply), a backup
schedule never set or set to a calendar the form cannot express. `--prune` removes what the files
do not name, so an object that was skipped goes with `haprion-objects apply --prune` on the
export's directory; mend it, or apply without `--prune`.

**What the export leaves out.** Accounts through the provider: each is made at its first
sign-in, by the groups, and a file has nothing to say about one. An account the file does not
name is left alone, and `--prune` never removes one of the provider's. Nothing secret is read
back, so none is written either: no account passwords, no OIDC client secret, no DNS provider credentials (`fields`) or NDES challenge. Applied
where they came from, the stored ones are kept. For a new installation, add them - from Ansible
Vault, never in the files you keep in version control:

- an account's `password` in `accounts.yaml`, which then must be mode `0600`;
- the client secret on standard input with `--oidc-secret-stdin`, and `interface_url` in the `oidc`
  section to turn sign-in on;
- a DNS profile's `fields` and an NDES profile's `challenge` in `profiles.yaml`, mode `0600`.

**The order.** Some steps depend on others:

1. Profiles, before a certificate that is issued through one.
2. Accounts, before the interface settings: sign-in through a provider is turned on only with an
   active break-glass admin. With `--prune`, an account no entry names is removed - never one the
   provider created, and never the last active admin.
3. Interface settings, before the backup schedules: turning *Node backups* on starts the schedules
   it stopped, and `haprion-settings` ends when they have run, so a schedule set after it stays.
4. Per cluster: the network before the objects - an object on a VIP the cluster does not have is
   refused - then *Logs & metrics*, then the deploy.
5. The deploy, on every run. A node that is current is left alone, and a deploy that failed on an
   earlier run is finished on the next.

**Changed and failed.** Every command answers one envelope with `--json`. The exit code is 0 for
done; anything else is a refusal or an error the envelope's `error` names, and the `command` module
already fails the task on it. `changed` is the answer's own:

```yaml
changed_when: (result.stdout | from_json).result.changed
```

`haprion-deploy` reports per node; a node `updated` is the change.

**Check mode.** Ansible skips `command` tasks under `--check`. Give each command its own `--check`
instead, and let the task run:

```yaml
argv: "{{ [...] + (['--check'] if ansible_check_mode else []) }}"
check_mode: false
```

`haprion-deploy` and `haprion-revert` have no `--check`; leave them out of a check run
(`when: not ansible_check_mode`).

**A playbook.** The export's layout under `haprion_files` on the manager, one cluster, the client
secret from Vault. `--oidc-secret-stdin` is for a `settings.yaml` with an `oidc` section; without
one, leave it and `stdin` out. A cluster whose backup schedule the export skipped has no
`backup-schedule.yaml`; leave it out of the schedule's loop.

```yaml
- name: The HAProxy management host
  hosts: manager
  become: true
  gather_facts: false
  vars:
    haprion_files: /srv/haprion
    clusters: [alpha]
    check: "{{ ['--check'] if ansible_check_mode else [] }}"
  tasks:
    - name: DNS and NDES profiles
      ansible.builtin.command:
        argv: "{{ ['haprion-profiles', 'apply', haprion_files ~ '/profiles.yaml', '--json'] + check }}"
      register: profiles
      changed_when: (profiles.stdout | from_json).result.changed
      check_mode: false

    - name: Accounts
      ansible.builtin.command:
        argv: "{{ ['haprion-user', 'apply', haprion_files ~ '/accounts.yaml', '--json'] + check }}"
      register: accounts
      changed_when: (accounts.stdout | from_json).result.changed
      check_mode: false

    - name: Sign-in, External monitoring and features
      ansible.builtin.command:
        argv: >-
          {{ ['haprion-settings', 'apply', haprion_files ~ '/settings.yaml',
              '--oidc-secret-stdin', '--json'] + check }}
        stdin: "{{ vault_oidc_client_secret }}"
      register: settings
      changed_when: (settings.stdout | from_json).result.changed
      check_mode: false
      no_log: true

    - name: Network
      ansible.builtin.command:
        argv: >-
          {{ ['haprion-network', 'apply', '-c', item,
              haprion_files ~ '/clusters/' ~ item ~ '/network.yaml', '--json'] + check }}
      loop: "{{ clusters }}"
      register: network
      changed_when: (network.stdout | from_json).result.changed
      check_mode: false

    - name: Proxy objects
      ansible.builtin.command:
        argv: >-
          {{ ['haprion-objects', 'apply', '-c', item,
              haprion_files ~ '/clusters/' ~ item ~ '/objects', '--json'] + check }}
      loop: "{{ clusters }}"
      register: objects
      changed_when: (objects.stdout | from_json).result.changed
      check_mode: false

    - name: Logs & metrics
      ansible.builtin.command:
        argv: >-
          {{ ['haprion-cluster-settings', 'apply', '-c', item,
              haprion_files ~ '/clusters/' ~ item ~ '/cluster-settings.yaml', '--json'] + check }}
      loop: "{{ clusters }}"
      register: cluster_settings
      changed_when: (cluster_settings.stdout | from_json).result.changed
      check_mode: false

    - name: Read each backup schedule
      ansible.builtin.slurp:
        src: "{{ haprion_files }}/clusters/{{ item }}/backup-schedule.yaml"
      loop: "{{ clusters }}"
      register: schedules

    - name: Node backups
      ansible.builtin.command:
        argv: >-
          {{ ['haprion-backup-schedule', '-c', item.item, '--time', s.time,
              '--retention', s.retention | string]
             + (['--weekly', s.weekly] if s.weekly is defined else [])
             + (['--monthly', s.monthly | string] if s.monthly is defined else [])
             + ([] if s.enabled else ['--disable'])
             + ['--json'] + check }}
      vars:
        s: "{{ item.content | b64decode | from_yaml }}"
      loop: "{{ schedules.results }}"
      register: schedule
      changed_when: (schedule.stdout | from_json).result.changed
      check_mode: false

    - name: Roll out what is published
      ansible.builtin.command:
        argv: [haprion-deploy, -c, "{{ item }}", --json]
      loop: "{{ clusters }}"
      register: deploy
      changed_when: >-
        'updated' in ((deploy.stdout | from_json).result.nodes | map(attribute='outcome'))
      when: not ansible_check_mode
```

**Certificates and nodes** are operations more than settings, and are run as needed rather than
described: `haprion-cert-issue`, `-import`, `-request` and `-scep` make a certificate,
`haprion-cert-target add|remove` and `haprion-cert-delete` are safe to repeat (a target already
there, or a certificate already gone, is no change), and `haprion-node`, `haprion-cluster` and
`haprion-node host` change what the manager reaches. Run the same way, with `--json` and
`changed_when` on the answer.

## Maintenance

### Keeping HAProxy current

The configuration this project generates is written for **HAProxy 3.4 or newer**; Debian 13 ships
3.0 and Ubuntu 26.04 3.2. Where a host has an older HAProxy, the installation steps (step 1 on the
management host, step 4 on a node) add the HAProxy maintainer's repository - Vincent Bernat's PPA on
Ubuntu, `haproxy.debian.net` on Debian, with a pin - and install 3.4 from it: the same key, source
and pin a restored node gets. A host already on 3.4 or newer is left as it is, whatever source it
came from, and a node that already serves a release is never upgraded by them. A publish on a
management host older than 3.4 is refused with that sentence rather than with HAProxy's.

After that, which HAProxy version runs, and when it is upgraded, stays with you. That is a boundary in the
design rather than an omission, and it is worth knowing why before it matters.

Upgrading the package restarts the data plane. The whole privilege model here exists so that this
tool cannot do that on its own: every management identity is a forced command that can ask a node
to *pull* something, and nothing else. There is no push path, and a tool that could silently
restart HAProxy on a live node would need one. Package upkeep belongs to whatever already patches
these hosts — unattended upgrades, a configuration-management run, your own maintenance window —
on a schedule you choose and can pause.

Two things this project does depend on:

**The branch you run should still be receiving fixes.** HAProxy publishes maintenance status per
branch at [haproxy.org](https://www.haproxy.org/), and the binary states it too:

```console
$ haproxy -v
HAProxy version 3.4.4 2026/08/28 - https://haproxy.org/
Status: long-term supported branch - will stop receiving fixes around Q2 2031.
```

Distribution packages are often frozen at an early point release of a branch and carry backported
security fixes only, which is a different thing from running the branch's current release. Both are
defensible; they are worth telling apart deliberately rather than by default.

**The management host and the nodes should run the same branch.** The management host validates a
candidate configuration with its own `haproxy -c` before any node is asked to pull it. That check
is only meaningful while it is at least as strict as the nodes are. A validator on a *newer* branch
can accept a directive the nodes then reject — the deploy fails on the first node and rolls back,
so nothing breaks, but the check stopped doing its job. When you upgrade, do the nodes first and
the management host last, and the validator is never the newer of the two.

**One node at a time is fine, and it is shown.** Patching one node and leaving the other a day or
two - to try a release before the second node gets it, with the old one still there to go back to -
works: nothing here refuses a deploy over it. The dashboard says it on the node that is behind, in
its Runtime cell, until both match; `haprion-status` says the same on that node's version line:

- `Behind 3.4.7` - its HAProxy process is an older release than another node's. The running
  process, not the package: a node patched and not restarted still says it.
- `Behind: keepalived, OpenSSL` - an older package than another node's, for HAProxy's own package,
  keepalived, dnsdist, the WAF engine and the OpenSSL library HAProxy links. Pointing at the line
  gives the versions. Compared as dpkg compares them, the whole version: a security update that
  changes only the revision (`3.5.5-1ubuntu3.7` to `-1ubuntu3.10`) or a PPA rebuild of the same
  release (`3.4.6-1ppa1` to `-1ppa2`) counts, whichever source the package comes from.
- `Manager validates with 3.4.7` - the management host's HAProxy is newer than this node's; see
  the order above.

A package one node does not have is not compared, and the kernel is not either.

Package sources and pinning are described under
[Where the package comes from](#where-the-package-comes-from).

### Releasing a change

Three things install independently — the CLI engine, the web platform, and the
node scripts — and a release ships only the ones a change actually touched.
Which of them a change touched is a question with a measurable answer, so
measure it rather than deciding by feel:

```bash
git show --stat <commit>
```

| What the commit touched | What to release |
|---|---|
| `src/haprion/`, `tools/`, `install/` | the `haprion-cli` package — [Part 3](#part-3--the-versioned-cli-release) |
| `ui/` | the `haprion-ui` package; installing it runs `update-platform-release` |
| `install/node/`, node scripts | the `haprion-node` package on every node, per [Part 2](#part-2--the-nodes) |
| more than one of those | **the CLI package first**, then the platform, then the nodes |

**The CLI package goes first when both move**, and the order is not a preference.
The platform check deliberately compares the independently installed CLI before
it activates a UI candidate, so releasing the UI first stops its own update —
correctly, but after it has already prepared and migrated.

A CLI-only change does not need a UI release, and forcing one would be the
mistake the compatibility check was built to avoid. It compares engine API
levels and helper names, never release hashes, precisely so an engine
correction does not drag an unrelated UI rollout along with it. What decides
whether the running UI still fits the new engine is:

- `src/haprion/compatibility.json` — the engine API the CLI release carries. A
  UI release declares the minimum it needs.
- the console scripts in `pyproject.toml` — the check requires every helper the
  UI names by name.

Unchanged in both means the running UI keeps working, whatever the new release
is called. Changed in either means the UI release moves with it, in that order.

**Prove it afterwards rather than assuming it.** The install steps each prove
their own result; the whole-installation check answers the different question of
whether the independently installed pieces still work together:

```bash
sudo /usr/share/haprion-ui/install/platform/check-compatibility
```

Run it after any of the three.

**Every release is a commit.** Each package is built from one committed source
tree and named after it, because a release built from an edited tree is one
nobody can reproduce, and the moment it runs, "what is in it" has no answer. Run
the full repository gate before building; a release is not the place to find
out that a test fails.

### CLI rollback

Install the retained previous package, which lets apt put the older version in place:

```bash
sudo apt-get install --allow-downgrades /path/to/haprion-cli_<previous version>_all.deb
```

Its `postinst` runs the release installer with the wheel and node package it carries; an already
installed matching release is verified and `current` is atomically switched back. Without the
package, re-run the installer with the retained wheel, node package and their recorded digests.

**Ten releases stay on disk; older ones go when a new one activates.** The installer prunes after
a successful activation and never before it - a failed activation is exactly when nothing may be
removed - and it always keeps the release it just activated and the one that was current before,
whatever their age, so the rollback path is never the one pruned. Ten is enough because a release
is reproducible from its commit: the wheel is built from `git archive <commit>`, so removing an
old directory loses nothing Git holds. `--keep N` changes the number (at least two).

### Rolling a release back

```bash
sudo haprion-rollback --list
sudo haprion-rollback                       # the previous release
sudo haprion-rollback --to <release-id>     # a named one
```

"Point `current` back and restart" is the shape of the rollback, but doing only
that took the interface down when it was measured. Two reasons, neither visible
from the symlink:

- **Configuration is validated strictly.** Unknown keys are refused, which is
  what makes a typo an error rather than a setting that silently does nothing —
  and it means a configuration written for release N makes release N−1 refuse to
  start. **Configuration follows the same expand/contract rule as the schema:** a
  key added for a newer release has to be removed before rolling back past the
  release that introduced it.
- **Units name programs.** A unit installed for a newer release starts a program
  an older release does not contain.

So the command checks both against the target *before* switching — asking the
target's own validator, because the answer is whatever that release says rather
than what the script believes — and verifies the interface answers afterwards,
**rolling forward by itself if it does not**. Somebody running this is already
having a bad day; leaving them on a release that does not answer, with the
rollback reported as done, is the worst outcome available.

Releases are offered oldest-last by build time rather than by name: an id ends
in a commit hash, which sorts alphabetically and says nothing about when it was
built.

How far back that list reaches is bounded: `update-platform-release` keeps the
ten newest releases, pruning the rest only after the update has been proved, and always keeping the
release just activated and the one it replaced. A release is reproducible from
its commit, so nothing older is lost with the directory. `RELEASES_KEPT` in the
command's environment changes the number (at least two).

## What it does not do

Gaps that are not on the way to being filled: each one is either impossible without
changing something the manager does not own, or left out because the alternative is
better done elsewhere. The details are in the section linked.

- **A UDP service whose server answers - RADIUS, NTP, SNMP - is not balanced.** A
  server answers the address it sees. To let it see the client's own, the answer must
  either pass back through the node, which then has to be the servers' gateway or be
  made one by a route in the network, or come from the VIP itself, which then has to be
  configured on every server. Both change the servers or the network; the manager does
  neither. Letting the servers see the node instead would work, but makes the node
  their only client, with one shared secret for every device behind it. DNS is
  balanced because dnsdist understands it and passes the client on inside the query
  ([DNS objects](#dns-objects)); syslog because it is never answered
  ([Syslog objects](#syslog-objects)).
- **A port another program takes on a node after the publish is caught only by the
  deploy.** The publish refuses a port a node reports held on every address
  ([Ports the cluster takes itself](#ports-the-cluster-takes-itself)), but a node that
  did not answer then, or a program started since, is found when HAProxy binds: the
  deploy fails on that node, rolls back to the previous release and shows HAProxy's own
  reason - `cannot bind socket (Address already in use)`.
- **A pool's own counters start again on every reload**, while its servers' and the
  frontends' are kept: HAProxy 3.4.6 does not carry a backend's own counters correctly
  ([Counters across a reload](#counters-across-a-reload)).
- **Syslog over TCP or TLS is not forwarded**, and nothing restricts who may send to a
  syslog object; the network between the nodes and the receivers must let the senders'
  addresses through ([Syslog objects](#syslog-objects)).
- **Two DNS objects cannot share an address and port**: dnsdist tells them apart by
  where a query arrives ([DNS objects](#dns-objects)).
- **A signing request made elsewhere is not signed here.** A device that makes its own
  key and takes only a certificate for its own CSR - HPE iLO, for one - gets it from the
  CA directly: for an internal name, the Microsoft CA's own web enrollment signs an
  uploaded CSR. Every other device takes an
  [external certificate](#external-certificates) with its key.
- **The VIP is not moved from the interface.** Patching a pair is restarting the standby,
  then the node holding the VIP and letting it move, which needs nothing from the manager; a
  button that stopped keepalived on a node would be the first management action able to move
  traffic ([Keeping HAProxy current](#keeping-haproxy-current)).
- **An account through the provider is not made in advance.** It is made at the first
  sign-in, by the groups; to let only some people in, give them a group of their own at
  the provider ([Signing in through an OpenID Connect provider](#signing-in-through-an-openid-connect-provider)).
- **Certificate renewal is the CA client's**: certbot and the NDES run renew on their
  own timers, and the manager publishes what they renew
  ([Certificates](#certificates)).
- **The database dump and its restore check are not watched by the interface.** Backing up
  the management host is the backup; the dump is for putting one table back. Whoever relies
  on it lets their own monitoring follow `haprion-backup.service` and
  `haprion-restore-check.service` ([Backups, and proving they restore](#backups-and-proving-they-restore)).
  The partitions the nightly retention creates need no watching of their own: the traffic
  log's run out first, after seven days, and its import then fails in *Needs attention*.
- **A request the WAF engine could not read cannot be excepted.** A broken body, a malformed
  upload or arguments past the limit are judged by the object's mode, like a rule set match,
  but no exception lets one through: what was not read cannot be narrowed to a field
  ([A request the engine cannot read](#the-waf-engine)).


## Environment reference

Deployment layout, prerequisites, configuration files, service identities, node preparation
and implementation details are collected here for administration and troubleshooting.
For the steps to install the application, use the [installation guide](install.md).

### The shape of a deployment

```text
                 mgr  (management host)
                  |
     authoritative config, published releases,
     the CLI, the privileged helpers, the keys
                  |
        +---------+---------+
        |                   |
     node-a              node-b        cluster alpha
     node-a              node-b        cluster beta
```

Three properties drive the whole design, and every step below follows from one of them:

1. **The management host never pushes.** It asks a node to pull, and nothing else. Every management
   SSH identity is a forced command; none of them can copy a file or run a shell on a node. A node
   fetches its own configuration from the management host over a separate, restricted account.
   The one exception is deliberate and does not stand: restoring a node onto an empty VM
   ([Restoring a node onto an empty vm](#restoring-a-node-onto-an-empty-vm)) writes as root through a key the operator pastes
   into that VM's console for one run, limited to the management host's address, and removed by
   the run itself as its last step.
2. **Configuration is versioned before it is deployed.** Editing produces a draft; publishing
   produces an immutable release; deploying brings nodes to a published release. Each stage is a
   separate command with its own privilege.
3. **The application never holds privilege.** Privileged work happens in small root-owned helpers
   with no caller-supplied paths, reached through exact sudo rules. See
   [`PRIVILEGE.md`](PRIVILEGE.md) for the contract these rules implement.

### Prerequisites

Haprion manages HAProxy's configuration; it does not install, patch or upgrade
HAProxy itself. Before starting, you need:

**On the management host**

- a current Linux distribution with `systemd`
- Python 3.12 or newer at `/usr/bin/python3`
- the operating-system PyYAML package (`python3-yaml`), major version 6
- the operating-system PyNaCl package (`python3-nacl`), major version 1 - the CLI release's
  installer refuses a host without it, as it does without PyYAML
- the operating-system psycopg package (`python3-psycopg`), major version 3 - the collector uses
  it for transactional PostgreSQL COPY and the CLI installer refuses a host without it
- `git`, `rsync`, `openssh-client`
- `sudo` new enough to support the no-argument sudoers form (`command ""`)

**On the management host, only for the web platform (Part 4)**

- PostgreSQL 16 or newer. 16 is the floor rather than a preference: role
  membership carries its own `INHERIT` setting from that version, and the
  installation states it explicitly instead of depending on a role attribute as
  it happened to be when a grant was made
- nginx
- `uv`, for building a release environment from the committed lockfile

**On every node**

- HAProxy, installed and managed by `systemd`, from the source you choose ([Where the package comes
  from](#where-the-package-comes-from))
- `keepalived`, if the cluster uses a virtual address
- `rsync` and `openssh-server`
- `sudo`

**Names and addresses you decide before you start**

| Thing | Example | Notes |
|---|---|---|
| management host | `mgr` | reachable by name from every node |
| cluster IDs | `alpha`, `beta` | lowercase, used in every command as `-c <cluster>` |
| node names | `node-a`, `node-b` | two per cluster in the reference layout |
| virtual address | `192.0.2.10` | per cluster, if keepalived is used |
| management network | `192.0.2.0/24` | how the host and nodes reach each other |

#### Where the package comes from

To run a branch's current release rather than the distribution's frozen one, take HAProxy from the
repositories [haproxy.org](https://www.haproxy.org/) links to, maintained per branch: the
`vbernat/haproxy-<branch>` PPA on Ubuntu, and [haproxy.debian.net](https://haproxy.debian.net/) on
Debian. They follow upstream closely but not instantly - a point release has reached them a day or
two after haproxy.org announced it - so `apt` offers a new release only after its next list update
following the repository's.

Pin the package to that repository, on the management host and on every node alike, so that an
upgrade never quietly falls back to the distribution's older branch:

```text
# /etc/apt/preferences.d/haproxy
Package: haproxy haproxy-doc vim-haproxy
Pin: release o=<origin of the HAProxy repository>
Pin-Priority: 1001

Package: haproxy haproxy-doc vim-haproxy
Pin: release o=Ubuntu
Pin-Priority: -1
```

`1001` takes the repository's package even where that would be a downgrade; `-1` never installs the
distribution's, so a repository that stops answering becomes an error at the next upgrade rather
than a silent change of branch. On Debian the second stanza names `o=Debian`. Read the origin from
the repository's own `Release` file, or from `apt-cache policy` once the source is added
(`release ...,o=LP-PPA-vbernat-haproxy-3.4,...` for the Ubuntu 3.4 PPA) - an origin that is
mistyped matches nothing, and the pin then silently does nothing. `apt-cache policy haproxy` shows
the pin working: the repository's version at priority 1001, the distribution's at -1.

The installation steps do not set this up. The dashboard's *Runtime* column shows the version each
node's HAProxy process is running, read from its runtime socket - after an upgrade, the new version
appears there once the service has restarted.

### Part 1 — the management host

#### Service accounts and the config group

The web, worker, and poller processes run as three distinct, locked, no-login accounts -
`_haprion-web`, `_haprion-worker`, `_haprion-poller` - and only the worker joins the configuration
group, `haprion`. The names are fixed rather than chosen per installation; the underscore is
Debian's mark of a system account and keeps an account from being named like the command it runs.
`install/sysusers/haprion.conf` declares them, and step 1 installs it under `/etc/sysusers.d/`
and applies it with `systemd-sysusers`.

Human operators are deliberately absent from the fragment. Adding an administrator to the config
group is a separate action against an already existing account:

```bash
sudo usermod -a -G haprion <your-account>
```

#### Directory layout

```text
/srv/haprion/config/alpha.git/            authoritative history, bare
/srv/haprion/config/alpha/                linked draft worktree - what you edit
/srv/haprion/config/alpha/{core,managed,manual}

/srv/haprion/published/alpha/releases/    immutable published releases
/srv/haprion/published/alpha/current      symlink to the current release

/srv/haprion/validation/certs/            validation-only certificate material
/etc/haprion/registry/clusters.yaml       cluster definitions
/etc/haprion/runtime-policy.yaml          the outer path boundary
```

**Read your handwritten layers before adding `default-path config`.** It changes how every relative
path in the configuration resolves, and a `crt`, `map` or `errorfile` written relatively would start
resolving somewhere else. Generated configuration writes absolute paths throughout, so only
`manual/` and `core/conf.d` need looking at.

`manual/reservations.yaml` is what the handwritten half of the configuration declares about itself:

```yaml
# Hostnames a handwritten frontend already answers for, and ports it already
# binds. A generated object claiming one is refused before anything is
# committed. Both lists are optional; `{}` reserves nothing, which is what a
# cluster that has never needed one carries.
hostnames:
  - legacy.example.com
tcp_ports:
  - 8443                 # every address this cluster has
  - 192.0.2.10:8443      # only that one
reviewed:
  # Each handwritten fragment, with the SHA-256 of the bytes you read.
  core/conf.d/0010-stats.cfg: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

A bare port and a port written `:8443` mean the same thing: claimed on every
address. That is what a `bind` line without an address does, so a handwritten
listener written that way really has taken the port everywhere. Give the address
when the claim belongs to one VIP — otherwise a cluster with several of them
cannot reserve anything without blocking every managed object on all the others.
An IPv6 address is bracketed, `[2001:db8::1]:8443`, exactly as a bind line
requires.

`reviewed:` is what keeps the promise current. A reservation written once and
never revisited looks exactly like a complete one, so a listener added to a
fragment afterwards would be invisible. Naming each fragment together with the
digest of what you read closes that: when the file changes, the digest stops
matching and the next publish asks you to look again. Get the digest with
`sha256sum core/conf.d/0010-stats.cfg`.

Which files it covers is fixed, not a selection: everything under
`core/conf.d/` and `manual/conf.d/`. Listing a fragment that reserves nothing is
how you say you read it and it claims no listener — that confirmation is the
point, not the reservations it did or did not produce. A confirmation for a file
outside those directories, or a digest that is not SHA-256 hex, is refused
rather than quietly ignored.

It proves currency and that somebody looked. It does not prove the promise is
complete — only reading the fragments could, and nothing here interprets
handwritten HAProxy configuration.

The file is seeded empty by step 1 and named in the operator editing policy by
step 2. Empty is correct while nothing handwritten defines a listener; a publish
says so when the cluster carries handwritten fragments this file does not
account for, and when a fragment has changed since it was confirmed.

`core/haproxy.cfg` is the handwritten `global` and `defaults` for the cluster — the file every
generated fragment is assembled behind. It must declare the TLS defaults every listener falls back
to when it names no policy of its own:

```haproxy
global
    # ... your own log, chroot, socket and user lines ...

    # Relative paths in the configuration resolve against the directory of the
    # file they are written in. A generated bind line reaches its certificate
    # list that way, and the node validates a copy of a release at one path
    # before installing it at another - one line, both places, nothing rewritten.
    default-path config

    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
```

**A publish is refused while these disagree with the manager's own lists**, and the refusal prints
the exact line to write. The reason is that both halves are true at once: a generated bind line that
names a TLS policy carries the manager's list, and every listener naming no policy inherits this
one. While the two differ, what protects a given listener depends on which line HAProxy read last —
and each file looks entirely correct read on its own. That is how one such pair came to be a cipher
apart without anything reporting it.

The list is Mozilla's intermediate recommendation, guideline v5.7; the
manager holds it in `haprion/tls_policy.py` with the date it was last checked. Nothing fetches
it at run time. If you deliberately change it, change it there first and in every cluster's `core/`
after — the refusal will tell you which clusters are still behind.

A **revert** is never refused for this. Going back to a release that was good before must not depend
on a file being current.

An HTTPS object may override its VIP's TLS policy. The generated certificate list then contains an
explicit SNI-filtered row for every object, so several names may use the same wildcard certificate
with different policies. The first, unfiltered row is an intentional fallback: a client with no or
unknown SNI inherits the VIP/bind policy. When one listener carries several effective policies,
HAProxy also returns `421 Misdirected Request` if the HTTP Host belongs to a different policy group
than the connection's SNI; HTTP/2 connection reuse remains possible between names in the same group.

Nothing derives this file — `manual/` is read, never interpreted, and a promise a person writes is
the only thing available. It exists because both collisions are silent: two frontends binding one
port both bind it under `SO_REUSEPORT` and the kernel splits new connections between them at random,
so the publish reports success and the node answers correctly for about half the traffic, and a
hostname claimed twice is answered by whichever frontend HAProxy reached first.

Only two of these paths are fixed by the software: `/etc/haprion/runtime-policy.yaml`, which
is where the code looks unless told otherwise, and `/opt/haprion`, where releases are installed.
Everything else above is a deployment choice — put the trees wherever your environment keeps them,
and name them in the runtime policy.

Repeat the first two blocks per cluster.

Config repositories and published releases are **root-owned and never group-writable**. The config
group reads; it does not write. Publishing is a write into root-owned history and therefore happens
through a helper, not directly.

The split between `alpha.git/` and `alpha/` is a bare repository plus a linked worktree. They are
held together by a path reference in each direction. Restoring only one of them breaks the link;
`git worktree repair` fixes it without touching configuration.

#### Runtime policy

`runtime-policy.yaml` is the outer security boundary, not a convenience file. It names the roots
that every path in `clusters.yaml` must stay inside, and the code refuses any cluster path that
escapes its root.

```yaml
schema_version: 1

cluster_file: /etc/haprion/registry/clusters.yaml
config_root: /srv/haprion/config
publish_root: /srv/haprion/published
validation_certs_root: /srv/haprion/validation

deploy_identity:
  key: "/root/.ssh/id_ed25519_config_deploy"

certificate_root: /srv/certificates/haproxy
cert_deploy_identity:
  key: "/root/.ssh/id_ed25519_cert_deploy"

status_identity:
  key: "/root/.ssh/id_ed25519_status"

probe_identity:
  key: "/root/.ssh/id_ed25519_probe"

server_state_identity:
  key: "/root/.ssh/id_ed25519_server_state"

backup_root: /srv/state-backups
backup_identity:
  key: "/root/.ssh/id_ed25519_node_backup"
```

An identity names only its key. The account it reaches on a node is fixed: the deploy,
certificate and server state keys reach `_haprion-trigger`, the status and probe keys
`_haprion-status`, the backup key `_haprion-backup`.

`certificate_root` is also what a publish reads to check that each site's certificate answers for
its hostnames. HAProxy loads a certificate; it does not check it against the objects using it, so a
name the certificate cannot answer for reaches visitors as a browser error while every layer here
reports success. **Leave the root unconfigured and that check does not run** - the publish succeeds
and nothing says the question went unasked. Choosing a certificate that does not cover the name on
purpose stays possible with the certificate mismatch override, which is asked for per publish rather
than written into the object.

`backup_root` is where the state backup engine writes one directory per node, and it is what
`haprion-list-backups` reads. Called with no cluster, that command lists every configured cluster
in turn - it reads `clusters.yaml` as the calling user, the same way `haprion-cluster-config` does,
only to learn which clusters exist. Each listing is still resolved inside the privilege boundary by
one helper call per cluster. Only metadata is ever reported from it - archive name, size and
modification time. The archives themselves hold password hashes and private SSH keys, so the root
stays root-owned and only one command opens one - `haprion-node-restore`, as root, to restore it
([Restoring a node onto an empty vm](#restoring-a-node-onto-an-empty-vm)); the helper exists precisely so that an unprivileged
caller can learn a backup exists without being able to read it.

`backup_identity` is the separate forced-command SSH identity that fetches the state-export stream
from a node. It must not reuse the deploy or status key: unlike those responses, this stream holds
password hashes and private SSH keys. Step 3 creates the key and prints the exact line to install
for the node's backup account; the private half remains root-only on the manager.

Step 2 installs `haprion-state-backup@.service`. Each instance takes both nodes in exactly one
configured cluster and keeps a bounded number of root-only archives per node — 14 unless the
Backups page set another count, which the root socket helper records in
`/etc/haprion/backup-retention/<cluster>.json` (root-only, 1–365). Every run
reads that file, including the terminal `haprion-state-backup`, so a manual run prunes to the
same count the schedule promised; a file that is present but unreadable stops the run rather
than falling back to 14. The one exception to the count is an archive a node restore run can still
restore - one prepared within the hour and not yet carried out, or being carried out now: it stays
until that run is done, so the count is briefly one more. A run past its hour holds nothing, and
each backup first puts such runs away as a restore command would. The ordinary list and the backup
UI show every retained archive per node and identify the source node because hostnames, network state and SSH identities are not
interchangeable between the pair.

Listings read each cluster's `haprion-state-backup@<cluster>.timer`. An admin can
set its schedule on the manager's clock — every day, chosen weekdays, or one day of the month
(1–28, so no month is skipped) at a given time — enable or disable it, set the retention, and run
an immediate cluster backup on the Backups page. The browser supplies no unit name or systemd
expression: the root socket helper derives both from the configured cluster and the bounded
request (`Mon,Wed,Fri *-*-* 05:00:00`, `*-*-07 05:00:00`), writes them as a drop-in on the
timer instance, and reads the effective state back before reporting success. A calendar edited
by hand on the manager is shown verbatim on the page and is not translated into the form's
shapes. The terminal break-glass path remains `sudo haprion-state-backup [-c <cluster>]`.

`interface_account` names the web interface's worker account. It is the one caller a version
believes about who published it: a publish or revert from the browser records the signed-in person
as *Published by*, beside the worker account that actually ran it. Anyone else who may run those
helpers - an operator at the terminal - is recorded as the account sudo proves, whatever the request
says, so the column can be trusted. Leave it out and every version names the account that ran the
helper, the worker's own name for everything done in the browser.

`pull_account` and `cert_pull_account` name the accounts the nodes fetch as - the `rrsync -ro`
accounts whose `authorized_keys` carry one line per node ([Ssh identities](#ssh-identities)). They are what
lets a node be added or removed with `haprion-node` or the interface's Nodes card
([Adding and removing a node](#adding-and-removing-a-node)): the names exist nowhere else a command reads. Leave
them out and nodes are added by hand, as before.

`status_identity` is the account `haprion-status` becomes to read a node, and `haprion-deploy`
uses it too: a rollout reads the pair before and after every step, and it reads with the identity
that cannot change a node rather than the one it triggers with. Both commands refuse to run
without it instead of falling back to the deploy identity. It is deliberately not
the deploy identity: reading status is the one thing the manager asks a node to do that cannot
change it, so it is the identity that can be granted most widely, and keeping it separate is what
preserves that difference. Without it, `haprion-status` says exactly which field is missing.

`probe_identity` is what the interface uses to ask a node to *try* a health check - open a
connection to the servers an object names, from the address that object leaves from, and report
whether they answered. It logs in as the same account status does and still carries its own key,
because it is a different thing to grant: status reads what a node already knows, while this makes
the node open a connection to an address the caller chose. The forced command behind it needs no
sudo, returns a status and never a response body, and refuses anything that is not a bounded list
of targets. Leave it out and the button in the editor says the probe is unavailable; nothing else
changes.

`server_state_identity` puts a server in drain or maintenance on the nodes
([Drain and maintenance](#drain-and-maintenance)). It logs in as the trigger account with a key of
its own, whose forced command takes one server GUID and one of three states and nothing else; it
changes where HAProxy sends traffic without a deploy, which is why it is neither the deploy nor the
status key. Leave it out and `haprion-server-state` says which field is missing; nothing else
changes. Step 2 writes it, and `status_identity` and `probe_identity`, when the answers file names
their keys.

The file must be root-owned, a regular file (not a symlink), not group- or world-writable, and at
most 1 MiB. The reader rejects unknown fields, so **install a release that understands a new field
before adding it** — otherwise every command that reads the policy fails, not only the new one.

#### Cluster definitions

```yaml
schema_version: 1

clusters:
  alpha:
    display_name: Alpha
    vip: 192.0.2.10
    config_path: /srv/haprion/config/alpha
    publish_path: /srv/haprion/published/alpha
    node_path: a
    nodes:
      - name: node-a
        mgmt_host: node-a.example.com
      - name: node-b
        mgmt_host: node-b.example.com
    validation_certs: /srv/haprion/validation/certs
    certificate_ids:
      - example.com
    default_certificate: example.com

    # Opt in to the separate structured stream used by the traffic-log
    # collector.  The setting reaches the nodes when an object is next
    # published; changing this file alone does not deploy a configuration.
    traffic_logging: true
```

`node_path` is the subdirectory a node fetches from on the management host. It is the only
per-cluster value the node side needs.

A cluster has **between one and eight nodes**. keepalived sets no limit - one VRRP instance shares
its addresses between any number of nodes by priority, so a third node adds a standby, not capacity -
and eight is a ceiling nobody is meant to reach rather than a size to aim for: the pages were measured
to draw eight nodes per cluster without scrolling sideways, and every node costs the poller a read
(below). One is the floor: a cluster is created with its first node and the next is added to it, and a
cluster of one serves - with nothing to fail over to. Each node's `keepalived.conf` - its priority and
its `unicast_peer` list - is written by the deploy for a cluster created in the interface
([keepalived on the nodes](#keepalived-on-the-nodes)).

There is **no hard limit on the number of clusters** in the engine, interface configuration or
database schema. Two is the recommended starting shape - commonly one internal and one external
trust zone - not a maximum.

**It has been run with two clusters of two nodes each, and is built for up to about ten clusters
and twenty nodes.** Nothing enforces that figure; it is where the manager's reads, which run one
after another, stop being comfortable:

- The poller reads cluster by cluster and node by node. At two clusters of two nodes a pass takes
  about two and a half seconds against a default `interval_seconds` of 20: the status read costs
  about 0.3 s per node, and the cluster's other readings about 0.7 s whatever its size. A node that is
  switched off adds five seconds to every pass (the SSH connect timeout); one that connects and
  then never answers adds up to sixty (the status read's own limit). Either delays every
  cluster's reading, not only its own.
- The traffic-log collector runs once a minute and fetches up to eight nodes at once - about a
  second for four current nodes. A node with a backlog is fetched for up to thirty seconds before
  the run imports what it has, and a node that does not answer holds one of the eight for ten to
  thirty seconds; a run that outlasts its minute delays the next, which never overlaps it.
- The worker runs one job at a time for the whole installation: a deploy or backup on one cluster
  queues every other cluster's jobs behind it.

An installation growing past that should time a complete poller pass and a collector run against
their intervals before it adds more.

Each cluster card carries a colour rule, one of six ([Accounts and signing in](#accounts-and-signing-in)). With more
than six clusters the colours are off and the name alone marks the card; that limits the colours,
not the clusters.

A release directory holds that subdirectory and, beside it, `MANIFEST.json` - the manager's own
record of what each object in that release amounts to. It is written outside `node_path`
deliberately: a node fetches that subdirectory whole with `--delete`, and HAProxy loads everything
in `conf.d` with `-f`, so a file the manager keeps for itself has no business being inside either.
Nothing on the node side reads it. A release without the file has the status report each object
as unknown rather than guessing.

`address_prefix` and `address_interface` are optional and describe how this pair's nodes write an
address they carry:

```yaml
    address_prefix: 24          # from the nodes' own virtual_ipaddress block
    address_interface: ens192   # likewise; names differ between installations
```

They are used for one thing: rendering the keepalived address list a release carries. **Read both
values off the nodes rather than choosing them**: whatever stands in their `virtual_ipaddress`
block today is what the generated list has to reproduce. A line reading `<address>/24 dev ens192`
means `address_prefix: 24` and `address_interface: ens192`. Nothing here requires a particular
interface name - the field exists precisely because it differs between installations - and a
cluster whose nodes name no interface should leave `address_interface` out, so that keepalived
keeps using the `vrrp_instance`'s own. Omitted, an address is written bare, which
keepalived reads as `/32` on the `vrrp_instance`'s own interface. **A bare address is not the same
address:** a `/32` carries no subnet route and is not chosen as a source address for the segment,
so a cluster whose nodes use a prefix must say so or moving the list into the generated file would
change the network rather than only where the list is written.

They live here rather than in `managed/network.yaml` because a prefix length is a statement about
the network the pair sits on, not about which addresses the cluster serves - and `clusters.yaml` is
root-owned, so the interface cannot change them.

##### Optional per-cluster sections

Four sections may be added. All of them are optional, and a cluster that omits every one of them
behaves exactly as the example above.

```yaml
    # Named addresses the generated frontends bind, each with the source
    # address it connects to backends from - what an ADC calls a SNIP. A
    # proxy object names the VIP it sits on; it never names an address.
    # Omitted, the cluster has one VIP called `main`, taken from `vip` above.
    vips:
      internal:
        address: 192.0.2.10
        source: 192.0.2.15
      dmz:
        address: 198.51.100.10
        # Which TLS versions and ciphers this listener accepts: `intermediate`
        # for TLS 1.2 and 1.3, `modern` for 1.3 alone. Optional, and left out
        # the listener takes what core/ sets through ssl-default-bind-*, which
        # is what every cluster does today. Read that file before naming a
        # policy here: the bind line overrides those defaults in both
        # directions, so a policy can loosen a stricter cluster as well as
        # tighten a looser one.
        tls: modern
    default_vip: internal

    # The resolvers section in core/ that generated server lines point at.
    # Without it, a backend named by hostname is resolved once at startup and
    # not again until the next reload.
    resolvers: cluster-dns

    # Named source addresses an object may connect out from instead of the one
    # its VIP pairs with. HAProxy takes the source per backend, so the pairing
    # in `vips` is a default rather than a rule.
    sources:
      outbound: 192.0.2.15

    # Named address groups an object may restrict itself to with `allow_from`.
    # An object may also write an address or range directly, for what belongs
    # to one site alone.
    networks:
      office:
        - 198.51.100.0/24

    # What a request for a hostname no object claims is answered with. Without
    # it, HAProxy answers 503. Set exactly one of `status` or `redirect`.
    unknown_host:
      status: 404
```

`vip` keeps its original meaning and is unchanged: it is the address whose ownership `deploy`
checks before it acts. One node holds every virtual address at a time, so that single check answers
for all of them.

**Three of those tables have a second, preferred home.** `vips`, `sources` and `networks` may
instead live in `managed/network.yaml` inside the cluster repository, and that is where a new
installation puts them:

```yaml
# <config_root>/<cluster>/managed/network.yaml
vips:
  internal:
    address: 192.0.2.10
    source: 192.0.2.15
default_vip: internal
sources:
  outbound: 192.0.2.35
networks:
  office:
    - 198.51.100.0/24
```

The file wins where it exists; a cluster without one keeps answering from `clusters.yaml`, and
nothing has to be migrated. The reason for the move is that these three describe *what gets
published*, while everything left in `clusters.yaml` describes *how the system itself runs* -
paths, identities, keys, the resolvers section, the certificate allowlist, and the `vip` line
above. The repository is owned by the application, which means these tables can be edited in the
interface through the same publish path as a proxy object, with the same lock, the same history and
the same revert, and without the web identities gaining any access to the engine's configuration.

`vip` deliberately did not move. It is what `deploy` checks node ownership against, and a control
the interface can rewrite is not a control. `managed/network.yaml` is refused outright if it names
it.

From the terminal, `haprion-network apply` publishes a file as the description, the way *Network*
saves it: compared with what is committed (`haprion-network -c alpha --json` carries it as
`document`), published as one version where it differs and not at all where it does not, against
the version it read. `--check` shows the difference; a cluster answering from `clusters.yaml` has
no description to change and is refused:

```bash
sudo haprion-network apply -c alpha network.yaml --check
sudo haprion-network apply -c alpha network.yaml -m "Add the office network"
haprion-deploy -c alpha
```

**Adding a VIP here does half the job by default.** The other half is keepalived on the nodes: no
node carries the address until it is in the `virtual_ipaddress` block, and until then no traffic
reaches the frontend however correct the generated configuration is. The same applies to a source
address, which additionally must sit in the *same* block as the VIP - see [Addresses, and what to
call them](#addresses-and-what-to-call-them).

**The other half can be handed to the deploy.** A published release carries
`keepalived/addresses.conf`, derived from `managed/network.yaml`: every VIP and every source
address, one per line, with a comment saying which is which. `haprion-pull-deploy` installs it at
`/etc/keepalived/addresses.conf` on each node, and a node whose `keepalived.conf` includes that
path gets a `keepalived --config-test` and a reload - **only** on exit 0, because keepalived skips
an address it cannot parse at runtime and carries on, which would turn a mistyped address into a
VIP that never appears and never says why. A failed test restores the previous list and reports
the deploy as failed with the HAProxy configuration already live.

**That failure leaves the node half-way, and the status says which half.** The configuration is
live on the new release while the address list is the old one, so the release hash alone would
report the node as up to date and a second deploy would pass over the node that still needs the
work. `haprion-node-status` therefore reports three measurements about the list - the digest the
release publishes, the digest the node installed, and whether `keepalived.conf` includes it - and
both `haprion-status` and `haprion-deploy` call a node current only when every component the
release owns is where it should be - the address list, the IPVS file and the log forwarding. Re-running
the deploy after fixing the cause finishes the half that was left; the node script syncs them even on a
release it already runs.

The include is reported and never compared. Putting that line into `keepalived.conf` is a person's
step, taken one node at a time (below), and a deploy that treated it as a target would try forever
to reach a state only a human can put the node in.

#### keepalived on the nodes

Who writes `keepalived.conf` depends on how the cluster came to be.

**A cluster created in the interface** gets a router ID when it is created, and every publish
writes one `keepalived.conf` per node into the release (`keepalived/node-<name>.conf`). The deploy
installs the node's own file, tests it with `keepalived --config-test`, and starts keepalived the
first time or reloads it after. The file is the baseline below in a fixed shape:

- `state BACKUP` and `nopreempt` on every node; the priority follows the cluster's node order
  (100, 90, 80 ...) and decides only who takes the address on a cold start
- unicast to the other nodes, with `check_unicast_src`: an advert from an address that is not a
  peer is discarded and logged once. There is no VRRP password - it is eight bytes of clear text
  on the wire, and VRRPv3 dropped it
- a node alone names `127.0.0.1` as its peer. An empty peer list makes keepalived fall back to
  multicast on the segment, and the node's own address makes it read its own adverts and warn
  every second
- the interface is the cluster's `address_interface`, or else the one carrying the node's own
  address
- the address list included in `virtual_ipaddress`, the IPVS file at the top level, and the
  `notify_` lines

Its first line, `# Written by Haprion - a deploy replaces this file.`, is how the deploy knows
the file is the product's. Delete that line and the file is yours: the deploy leaves it as it is from then on, and only the
address list below is written.

Adding a node changes the peer lists, which reach the nodes with the next deploy as a reload: the
address stays where it is. Until the first deploy a node has no `keepalived.conf`; the dashboard
says *Keepalived not configured*, and since no node carries the address the deploy proceeds with
*no node currently owns the VIP*.

**A cluster whose `keepalived.conf` a person wrote** keeps it. The application writes the address
list and nothing else: `priority`, `virtual_router_id`, `authentication`, `unicast_src_ip`,
`unicast_peer` and the `notify_` lines stay in the file a person edits. Those decide who owns an
address, and getting one wrong gives two masters or none - neither of which `--config-test`
catches, because both are runtime behaviour rather than syntax. An extra line in
`virtual_ipaddress` cannot cause either, which is what makes this half safe to generate.

**Switching a node over to the generated address list, in this order:**

1. Deploy once, so `/etc/keepalived/addresses.conf` exists. Until a node's `keepalived.conf`
   mentions that path the file is installed and inert, and the deploy says so.
2. Compare it against the addresses in the node's own `virtual_ipaddress` block. They must already
   agree; this step changes where the list is written, not what is in it.
3. On **one node at a time, the address owner last**, with a backup of `keepalived.conf`: replace
   the addresses in the block with `include /etc/keepalived/addresses.conf`, run
   `keepalived --config-test -f /etc/keepalived/keepalived.conf`, and reload only if it passes.
4. Prove it from another host - the address still answers ARP from the same node - before touching
   the second node.

An `include` naming a file that does not exist yet is a keepalived that will not start. That is the
whole reason step 1 comes first.

**The node's status helper has to be able to follow that include.** `haprion-node-status` reports
whether this node currently carries the address by reading the `virtual_ipaddress` block and
looking the address up on the interface. Once the block holds nothing but the include, a helper
that reads only the block finds no address and answers that ownership is unknown - on both nodes.
That is not a cosmetic answer: a deploy refuses to run without a known owner, so the whole cluster's
deployment path stops. Install the node scripts from the same release as the manager before
switching a node over, and confirm afterwards with `haprion-status -c <cluster>` that the owner is
named and the state is `single_owner`.

**A cluster that sets `resolvers` must provide the section itself in `core/`**, since nameserver
addresses are environment values the generator never invents:

```text
resolvers cluster-dns
    nameserver ns1 192.0.2.53:53
    resolve_retries 3
    timeout resolve 1s
    timeout retry 1s
    hold valid 10s
```

#### The certificate registry

`certificate_ids` above is the allowlist form: the cluster names the certificates it may carry,
by hand, in a root-owned file. It is what an installation starts with, and it is being replaced by
a registry - one root-owned file beside `clusters.yaml` that says, for every certificate, where it
comes from and where it goes:

```yaml
schema_version: 1

receivers:
  lb-01.example.net:
    path: /srv/certificates/receivers/lb-01.example.net
    owner: svc-app
    transport: sftp            # rsync | sftp | https; left out, rsync
    layout: per-certificate    # the only layout; may be left out
    allow:                     # https only, and required there
      - 192.0.2.0/24

certificates:
  example.com:
    source:
      kind: acme
      lineage: example.com-wildcard
    clusters:
      - alpha
  lb-01.example.net:
    source:
      kind: import
    receivers:
      - lb-01.example.net
```

Name it in the runtime policy as `certificate_registry`, beside `clusters.yaml`
(`/etc/haprion/registry/certificates.yaml`): the worker's sandbox opens the registry's directory. From that moment a cluster's certificates
are the ones that name it under `clusters`, and a `certificate_ids` list left in `clusters.yaml` is
refused - the two would otherwise be two answers to one question, free to drift apart without
anything noticing. Declaring the registry and moving the lists out of `clusters.yaml` is therefore
one edit. `default_certificate` stays in `clusters.yaml` and must still be one the cluster carries.

A **receiver** is somewhere other than a cluster that certificates are published to: a directory
under the distribution root and the account whose fetch key is locked to it. A receiver is
registered with `haprion-cert-receiver` ([Registering a receiver](#registering-a-receiver)), not by hand, because an account, a key and a
directory are what let anyone fetch key material at all and none of the three is safe without the
others. Which certificate goes to which already-registered receiver is the part the interface is
allowed to change, and it does so through a helper that accepts only targets registered in this
file.

One entry may carry `interface: true`: the certificate the management host's own interface is
served with ([HTTPS and the certificate](#https-and-the-certificate)). It is issued, imported and renewed like every other entry, names no cluster and
no receiver - the loader refuses either, and refuses a second such entry - and is published to
nginx instead of to targets.

`transport` says how the receiver fetches, `layout` how its directory is arranged, and `allow` -
`https` only - which addresses may fetch at all. Left out, they are `rsync` and
`per-certificate`, which gives each certificate a directory of its own under the receiver's.
Neither field is edited afterwards: a receiver finds out about a moved path or a changed
transport at its next fetch, which is a renewal away, so a change is `remove` and `add` again.

A certificate's `receivers` list may name a receiver as `{id: <id>, format: pkcs12}` instead of as
a bare ID, and then that pair - this certificate, this receiver - is published as a PKCS#12 bundle
with a password beside it rather than as a PEM pair. A bare ID means `pem`. The choice belongs to
the pair, because one host can want PEM for HAProxy and a `.pfx` for IIS.

The choice is made where the receiver is chosen: `--format <receiver>=pkcs12` beside `--receiver`
on `haprion-cert-issue`, `haprion-cert-import` and `haprion-cert-scep`, and a select beside the
receiver's box on the interface's certificate form and in *Publish to…*. A receiver kept at a
target change keeps its format unless a new one is stated; stating a different one rewrites that
receiver's files in the new format at once.

The bundle's password is not a protection. It is published beside the bundle, in the same
directory with the same owner and mode, so whoever can read the one can read the other; it exists
because a PKCS#12 import asks for one, and it is made once per pair and kept across renewals so
the receiver's import script need not change. What protects the key is the same thing that
protects a PEM pair: the receiver's account, its directory and the transport's lock. Publishing
a `.pfx` to a receiver is exactly as sensitive as publishing `privkey.pem` to it.

`source.kind` is `acme` for a certificate certbot renews and `import` for one signed elsewhere. An
ACME certificate's `lineage` is its certbot lineage name; left out, it is the certificate ID, which
is what a certificate issued from the interface gets. State it only where an existing lineage has
another name - renaming a lineage moves certbot's archive, and is not worth it.

Every command that changes the file - issue, import, delete, a target change, a receiver's
registration or removal, the scheduled renewal - reads it, changes it and writes it back under one
lock, the publisher's (`/run/haprion/locks/cert-publish.lock`). The interface queues one
certificate job at a time, but the renewal timer and an operator's command run outside that queue,
and two writers in the same second would otherwise be a lost update the loader cannot see: the
file that wins is valid, it just lacks what the other one wrote. A command that finds the lock held
for longer than two minutes refuses with `operation_locked` rather than waiting on.

`haprion-cert-list` reports `source` and `targets` for every certificate the registry names, and
`null` for both on a file in the distribution directory that no entry names: a certificate placed
there by hand, listed so it can be registered rather than hidden. `haprion-cert-list -c <cluster>`
answers for one cluster; `haprion-cert-list --registry` asks the manager for the whole registry and
what the interface is served with, and answers before the first cluster exists. The poller reads it
the same way, once a pass.

#### Certificate publication hook

**The certbot hook** is one file, [`../install/certbot-deploy-hook`](../install/certbot-deploy-hook),
installed as `/etc/letsencrypt/renewal-hooks/deploy/50-haprion`:

```bash
sudo install -o root -g root -m 755 install/certbot-deploy-hook \
  /etc/letsencrypt/renewal-hooks/deploy/50-haprion
sudo certbot renew --dry-run --run-deploy-hooks
```

It runs `haprion-cert-publish --deploy` and nothing else. certbot runs every hook in that directory
after every successful renewal, whichever lineage renewed, and the publisher finds the changed one
by comparing bytes - so there is no per-lineage logic in the hook to go stale when a certificate is
added. A hook that filtered on a hardcoded lineage, and a second one that walked a list file, are
what this replaces; remove them when this one is installed, or every renewal publishes twice.

Nothing here renews anything. certbot stays authoritative for renewal, on its own timer; the
publisher is what runs after it has.

#### ACME configuration and challenge routing

What the caller supplies is a domain, a method and target names the registry already knows.
Everything certbot is told beyond that is fixed - `certonly`, the lineage name (which is the
certificate ID), `--key-type ecdsa`, non-interactive, directory hooks off for this one run - or read
from the runtime policy:

```yaml
acme:
  dns_cloudflare_credentials: /etc/letsencrypt/cloudflare/example.ini
  webroot: /var/www/acme
  certbot: /opt/haprion-certbot/current/venv/bin/certbot
  dns_profiles:
    directory: /etc/haprion/dns-profiles
    private_keys:
      - /etc/haprion/ui-secrets/dns-profile-keys/0123456789abcdef.key
```

`certbot` names the binary the helper runs: the locked environment's, once [The certbot environment](#the-certbot-environment) has installed it.
Left out, the helper runs the distribution's `/usr/bin/certbot`, with the distribution's plugins.
`dns_profiles` is where the DNS provider credentials entered through the web interface end up,
and which private keys may open them; [The DNS profile key pair](#the-dns-profile-key-pair) makes the keys.

| Method | certbot | What the installation is responsible for |
|---|---|---|
| `dns-01` | the plugin and root-only file selected by `--dns-profile`; without it, `--dns-cloudflare` with the policy file above | the profile may edit that zone |
| `http-01` | `--webroot -w <webroot>` | `http://<name>/.well-known/acme-challenge/` reaches that directory |

A method whose setting is missing is refused by name before certbot runs. A wildcard
(`*.example.net`, which also covers `example.net`) needs `dns-01` and is refused with `http-01`.
The command does not create routes, touch the published configuration or check that the name
resolves.

`http-01` needs more than the webroot setting, because port 80 for a proxied name terminates at the
cluster VIP, not at the manager. Three things have to be in place, all of them the installation's
to make: the webroot directory named in the policy; something on the manager serving that directory
over plain HTTP - a port-80 `server` block in nginx that exposes only `/.well-known/acme-challenge/`
from the webroot; and a rule in each cluster that sends that path to the manager, written once into
`core/` or `manual/`, never generated:

```text
# core/ or manual/ - hand the ACME HTTP-01 challenge to the manager
backend acme_challenge
    server mgr 192.0.2.10:80

# in the HTTP frontend, before any host routing
acl acme_challenge path_beg /.well-known/acme-challenge/
use_backend acme_challenge if acme_challenge
```

Without all three, an `http-01` request fails at the challenge with certbot's own account of it.
A wildcard cannot use `http-01` at all. When certbot fails, its output is printed after the error line at a terminal and carried
whole under `error.details.diagnostics` in the JSON envelope, so the account of a failed challenge
reaches whoever asked, in certbot's own words.

#### The certbot environment

The distribution's certbot runs on the system Python, which accepts no packages beyond the
distribution's own - and the DNS plugins the distribution packages are a dozen. The product
offers many more, so it carries its own certbot: [`../certbot/pyproject.toml`](../certbot/pyproject.toml)
names certbot and every DNS plugin the web interface can offer, and `certbot/uv.lock` pins the
whole set, with hashes, as resolved together. What the interface can offer is what that lock
resolved. Nothing installs a plugin at runtime.

Platform step 14 builds it:

```bash
cd /usr/share/haprion-ui/install/platform
sudo UV_BIN=/path/to/uv ./14-platform-certbot /path/to/answers.env /usr/share/haprion-ui
```

The step hands the lock to [`../tools/install-certbot-env.py`](../tools/install-certbot-env.py),
which lets uv install exactly the locked set into `/opt/haprion-certbot/releases/<certbot
version>-<lock hash>/venv` and proves that every plugin in it loads. It then runs
`certbot/verify-integrations.py` with the new environment's interpreter. Those checks feed the
catalogue's rendered credentials through every offered plugin's own credential setup, exercise
Azure through its SDK with the network mocked, and run with sockets disabled so a plugin that
reaches out fails instead of passing quietly; a missing, empty or failed report refuses the
release. The catalogue states per provider what has been proved (`packaged`, `loaded`,
`integration-tested`, `live-verified`) and the verifier refuses a catalogue that claims more than
the run showed. The passed check names are recorded in `INSTALLATION.json`. The installer freezes the tree root-owned and read-only and
points `/opt/haprion-certbot/current` at it. Then the platform step runs
`haprion-cert-renew --certbot <new binary> --dry-run --run-deploy-hooks` against every lineage on the host: the
one gate a certbot upgrade has, and a failure puts the previous release back before the step
stops. Only after that does renewal move: the distribution's `certbot.timer` is masked and
`haprion-certbot-renew.timer` - the same schedule, the release's binary, the same
`/etc/letsencrypt` - takes over. Its bounded wrapper invokes Certbot once per lineage. Most plugins
persist their credentials-file flag in the renewal configuration; Route53 has no such flag, so the
wrapper restores `AWS_SHARED_CREDENTIALS_FILE` from the registry's `source.dns_profile` binding.
One certbot owns the lineages; renewal walks all of them and fails
on one whose plugin it cannot load, which is why the distribution's timer is masked rather than
left disabled.

The step also checks that the worker's unit opens certbot's directories (`/etc/letsencrypt`,
`/var/lib/letsencrypt`, `/var/log/letsencrypt`), the runtime policy's roots - among them the
publisher's target and the registry's directory, which step 07 writes into the unit from the
policy - and the DNS profile directory (`/etc/haprion/dns-profiles`). The issue helper runs certbot inside the worker's sandbox,
and without those paths every issuance from the web interface fails on a write such as certbot's
log lock. Step 07 installs the unit; rerun it from a `haprion-ui` package that has them before
running step 14.

Point the runtime policy at the release afterwards - `acme.certbot` in [ACME configuration and challenge routing](#acme-configuration-and-challenge-routing) - and the issue
helper runs it too. Upgrading is the same step with a newer lock, a few times a year: bump
`certbot/uv.lock` in the source tree (`uv lock --upgrade` in `certbot/`), commit it, install the
`haprion-ui` package built from that commit, and run the step with `/usr/share/haprion-ui`; read its
gate. A plugin that no longer resolves against the newer certbot falls out of the lock, and so out
of what the interface offers; a release that fails the dry run is never made current. Rolling back
by hand is one symlink, which the step prints, followed by the same dry run.

#### The DNS profile key pair

A DNS provider's credentials are entered once, in the web interface, and stored sealed: the web
process encrypts them against the installation's public key and keeps only the ciphertext, and the
root helper that runs certbot holds the one private key that opens them (libsodium's sealed box,
through PyNaCl). A compromised web process can therefore add or replace a profile but never read
one back, and a database dump carries nothing a reader can use without root's key file.

Platform step 15 makes the pair:

```bash
cd /usr/share/haprion-ui/install/platform
sudo ./15-platform-dns-keys /path/to/answers.env /usr/share/haprion-ui
```

The private key lands in `/etc/haprion/ui-secrets/dns-profile-keys/<key id>.key`, root-only; the
public key in `/etc/haprion/dns-profile-keys/<key id>.pub`, readable by the platform group. The key id is a digest of
the public key, so it is read off either file rather than assigned, and a stored profile names the
id it was sealed against. Both files are one tagged line, and a private key placed where a public
one belongs is refused by its tag. The step proves the pair by sealing and opening a message
through the files it wrote, and never overwrites an existing key.

Then tell both readers about it. The runtime policy ([ACME configuration and challenge routing](#acme-configuration-and-challenge-routing)) names the private key and the
directory the helper materialises credential files into:

```yaml
acme:
  dns_profiles:
    directory: /etc/haprion/dns-profiles
    private_keys:
      - /etc/haprion/ui-secrets/dns-profile-keys/0123456789abcdef.key
```

and the web interface's `/etc/haprion/ui.toml` names the public key:

```toml
[dns_profiles]
public_key = "/etc/haprion/dns-profile-keys/0123456789abcdef.pub"
```

A new runtime policy key costs a CLI release before the policy is edited, and a platform release
after it, in that order: `check-compatibility` reads the policy through the platform's own copy of
the engine, and the installed engine refuses a key it does not know.

**Replacing the key.** Run the step with `ROTATE=1`: it adds a second pair beside the first. List
both private keys in the policy, point `ui.toml` at the new public key, and re-enter each profile
so it is sealed against the new key; a profile sealed against a key the policy no longer lists
cannot be applied until it is. Remove the old pair last. The private key file is part of the host's
disaster-recovery material like the SSH identities in [SSH identities](#ssh-identities): without it every stored profile is
unreadable, and the recovery is to re-enter them, not to restore a dump.

#### Preparing Microsoft AD CS / NDES for CSR enrollment

**Status:** enrollment from the manager is complete: encrypted NDES provider profiles, the
retained Certmonger client, the root enrollment CLI and its job helper, and the certificate
form's third choice, *Microsoft AD CS · NDES*. Two live enrollments (a DNS name; a wildcard
with its base name) were verified end to end.

**Other SCEP servers.** NDES is Microsoft's SCEP implementation; the client speaks plain SCEP
and the manager makes two choices that NDES needs and other servers accept - a signature-and-
encryption request, and a PrintableString challenge. Only NDES has been verified. Another SCEP
CA (step-ca is the quickest to stand up; EJBCA, OpenXPKI and network appliances also serve
SCEP) should work and is untested; the profile and policy fields keep their NDES names.

**Selected client:** [Certmonger](https://codeberg.org/freeipa/certmonger/) will provide the
SCEP protocol support through a temporary process and private socket, with Certmonger's own
renewal disabled - the manager schedules renewal itself; see the
[user manual](#enrolling-and-renewing-through-ndes). Its installation and runtime dependencies will be included in the manager installation.
Release materials must retain the selected package, corresponding source, license and build
instructions so the selected version remains available independently of its upstream hosting.
The packaging tools are described below. Root installation has not yet been verified.

The intended flow creates an RSA key and a PKCS#10 CSR locally on the manager, sends an enrollment
request through SCEP over verified HTTPS, validates the returned certificate and uses the existing
publication and distribution path. The private key stays on the manager. The manager needs no
domain membership or AD account and does not visit `mscep_admin` during normal operation.

**Manager configuration and packaging (source implementation).** The optional root policy
`ndes` object has the fields `endpoint`, `tls_ca`, `issuing_ca`, `client_root`, `state_root`,
`profiles` and the optional `renew_days` (1–3650, default 30). Paths are absolute. `profiles` contains `directory` and `private_keys`,
a non-empty list of absolute private-key file paths using the existing profile sealing keys. The endpoint must use HTTPS and
match the encrypted provider profile exactly. TLS trust and certificate issuing trust are
configured separately. Suggested roots are `/opt/haprion-scep/current`,
`/etc/haprion/ndes-requests` and `/etc/haprion/ndes-profiles`.
The latter directories are root-owned, mode `0700`; records and keys are mode `0600`.

Build the native bundle with `tools/build-scep-client.py`: supply `--package`, its independently
verified `--package-sha256`, the matching signed `--source-description` and verified
`--source-sha256`, plus `--distribution`, `--distribution-release` and `--output`.
Keep both source archives beside the source description. The bundle retains the package,
complete corresponding source, license and rebuild instructions; a bit-for-bit rebuild has
not been demonstrated. Only matching Debian-family distribution packages are supported.
Before writing the bundle, the tool looks the package version up in the OSV database
under the distribution's release (`Debian:<release>` or `Ubuntu:<release>`) and refuses
the build if any advisory affects it, or if the database holds nothing for that release.
The lookup needs network access to `api.osv.dev` and answers for the day it runs, so
rebuild to check again. The bundle freezes Certmonger's own programs only; the libraries
they load are the distribution's and follow its updates.
Install the reviewed bundle as root with
`install/platform/16-platform-scep <bundle.zip> <verified-bundle-sha256>`.
The installer checks hashes, archive paths, OS release and architecture, installs runtime
library dependencies and activates the three client programs under an immutable release.
It does not install a standing Certmonger service.

**Server prerequisites.** Install and configure the AD CS Network Device Enrollment Service role
with IIS, an issuing CA and valid NDES signing/encryption RA certificates. NDES and the CA may
share a server; co-location is not a product requirement. Microsoft's
[NDES overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/network-device-enrollment-service-overview)
describes the role and its IIS applications. For a dedicated domain service identity, follow
[Microsoft's service-account instructions](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/create-domain-user-account-ndes-service-account).
The identity needs local `IIS_IUSRS` membership, effective CA `Request Certificates` permission
and `Read` + `Enroll` on the dedicated certificate template. It need not be a domain or local
administrator. Ensure the IIS `Default Web Site` exists before NDES configuration; a missing site
caused setup error `0x80070003` in the technical trial. The working SCEP application pool used
`Load User Profile = True`.

**One dedicated, published template.** Set the following values in the certificate template and
publish it on the issuing CA:

| Setting | Required value |
|---|---|
| Request Handling / Purpose | Signature and encryption |
| Cryptography | RSA, minimum 2048 bits |
| Subject Name | Supply in the request |
| Application Policies / EKU | Server Authentication |
| Key Usage | Digital Signature, Key Encipherment |
| CA certificate manager approval | Disabled for immediate unattended issuance |
| Allow private key to be exported | Disabled; the manager generates its own key |
| Template security | Read and Enroll for the NDES service identity |

`Supply in the request` allows the enrolling identity to request names supplied by the client;
restrict template rights and endpoint access according to your PKI policy. SANs are CSR
extensions. The integration does not require enabling the global CA flag
`EDITF_ATTRIBUTESUBJECTALTNAME2`.

Map `GeneralPurposeTemplate` under
`HKLM\SOFTWARE\Microsoft\Cryptography\MSCEP` to the template's **internal name**, rather
than its display name. For example, an installation may name its dedicated template
`HAProxyWebServer`. The signature-and-encryption request selects this mapping; no template is
selected in the manager's interface. The other two mappings need not change for this request type.

**HTTPS and trust.** Expose the SCEP endpoint at
`https://<ndes-fqdn>/certsrv/mscep/mscep.dll` with a server certificate matching the endpoint's DNS
name. The manager must trust its TLS chain and separately validate the certificate issued by the
CA. Provision the trust anchor explicitly: SCEP `GetCACert` retrieves protocol CA/RA material but
does not itself establish trust. Serve the issued leaf plus any intermediate certificates to
HAProxy; omit the root from the served fullchain.

**Reusable challenge.** The intended unattended integration requires these DWORD settings:

| Registry subkey under `HKLM\SOFTWARE\Microsoft\Cryptography\MSCEP` | Value name | Value |
|---|---|---|
| `EnforcePassword` | `EnforcePassword` | `1` |
| `UseSinglePassword` | `UseSinglePassword` | `1` |

An administrator retrieves the master challenge once from
`https://<ndes-fqdn>/certsrv/mscep_admin/` and enters it in the NDES provider profile under Certificates → NDES providers.
As with DNS provider credentials, the web application seals it using the installation public
key, and the database stores only ciphertext. Only the root helper can decrypt it and create
the root-owned, mode `0600` challenge file that Certmonger reads. The profile offers replacement
of the challenge, never plaintext retrieval. NDES uses a separate profile type with validated
identity and revision binding. The helper atomically writes a root-only profile record, then
enrollment creates a temporary challenge file and removes that file when its process ends.
Protected request state can still contain the challenge in its CSR. Normal enrollment uses only
`mscep.dll` and this secret.
Microsoft's historical
[single-password article](https://support.microsoft.com/en-au/topic/two-improvements-are-available-that-shorten-the-time-that-is-required-to-manage-scep-certificates-by-using-the-network-device-enrollment-service-in-windows-server-2008-c497db37-9c87-0cd0-30dc-845eeb8ba9f5)
documents the reusable, non-expiring password and registry setting for Windows Server 2008;
it is a historical reference, not an instruction to install that hotfix on a modern server.
The technical trial verified this mode on Windows Server 2022. In that trial the NDES service
identity needed Full Control on the MSCEP registry subtree for single-password operation;
review the necessary registry permissions in your installation.

The master challenge is a long-lived credential. Endpoint access and NDES protection remain
operator responsibilities. Keep its plaintext out of command arguments, job payloads, logs,
job results and the database; only the sealed ciphertext may be stored in the database. A CSR contains this credential as `challengePassword`, so protect CSRs and any temporary
OpenSSL request configuration as secret material too. Rotate a challenge that has been exposed.

**Interoperability and verification.** The tested NDES installation accepted `challengePassword`
as ASN.1 PrintableString. A missing attribute caused NDES Event ID 28; the trial's initial encoding
caused Event ID 29. OpenSSL `string_mask = nombstr` produced a working PrintableString. This is a
technical trial finding, not a general encoding rule established by the Microsoft links above.
The tested client, `scepclient 2.3.0`, needed a pre-created CSR for multiple SANs and a PKCS#1 RSA
key representation; those are client constraints, not general SCEP requirements or a selected
product dependency.

Verify enrollment from Linux with both a single DNS name and a wildcard plus its base name,
using the same challenge twice. Check the exact SAN set, Subject, Server Authentication EKU,
Key Usage, validity, key match and certificate chain. A responsive landing page or `GetCACaps`
alone does not prove enrollment. Application acceptance will also cover verified TLS,
`GetCACert`, SCEP response correlation, pending/failure handling and diagnostics without secrets.

The integration automates issuance requested through CLI/UI and renews on schedule ([user manual](#enrolling-and-renewing-through-ndes)).
CEP/CES/WSTEP, template discovery and automatic password retrieval from `mscep_admin` are outside
this integration.

#### Validation certificate

Candidate validation runs a real `haproxy -c` against the candidate. Any configuration that
references a certificate therefore needs certificate material present during validation — but the
real private key must never be readable by the validating path.

A dedicated, self-signed certificate under `validation_certs_root` solves this. It is readable only
by root, is copied into the private candidate for the duration of validation, and is removed before
the helper returns. It never leaves the management host and is never deployed.

#### SSH identities

Four key pairs, each with exactly one job:

| Key on the management host | Connects as | Purpose |
|---|---|---|
| `id_ed25519_config_deploy` | `_haprion-trigger` on the node | trigger a configuration pull |
| `id_ed25519_cert_deploy` | `_haprion-trigger` on the node | trigger a certificate pull |
| `id_ed25519_node_status` | `_haprion-status` on the node | read node status |
| the node's own config pull key | `_haprion-pull` on the management host | read the published tree |
| the node's own cert pull key | `_haprion-cert-pull` on the management host | read the certificate tree |

A key that can push configuration must not be able to push certificates, and neither may read
status. Private keys are root-owned; no application identity can read any of them.

**The node's keys are generated on the node, by step 4, and never leave it.** A private key a node
authenticates with has no reason to exist on the management host; copying one there would make the
management host able to impersonate a node. Step 4 prints the public halves and the exact
`authorized_keys` lines for the management host, which is the mirror image of step 3.

One line per node, not one per cluster. Each node has its own key, so a node that is rebuilt or
compromised is revoked on its own.

The pull direction is the mirror image: an account on the management host, restricted to an
`rrsync`-style read-only export of the published tree, which the node authenticates to with its own
key.

`rrsync` is what makes that restriction real: the forced command is
`rrsync -ro <tree>`, which allows a read-only rsync of exactly one directory and nothing else.
Without it a forced `rsync` command is a shell in all but name.

**The published tree belongs to the pull account, not to the config group.** Giving it to the
config group looks reasonable and locks the nodes out of the only tree they are supposed to read —
deploys then fail while every permission still looks deliberate.

#### Sudo rules

Two separate policies, which must not be merged:

- **Application rules.** Exact helper paths, invoked with no arguments (`command ""`), so the
  helper reads its request as one bounded JSON line on stdin. A caller that runs an operation it may
  later need to stop keeps that stream open as a lifeline; see `PRIVILEGE.md`. No rule grants a shell, an interpreter, an
  editor, a wildcard path, environment preservation, or unrestricted arguments. The web identity
  has no sudo rule at all.
- **Operator rules.** A `sudoedit` policy listing the configuration files an administrator may
  edit, by exact path. `sudoedit` is what makes editing possible without making the repositories
  group-writable.

  **Remove the rule in the same change that removes the file.** `sudoedit` creates a file it does
  not find, so a rule naming a path that no longer exists is not merely stale - it is a standing
  way to place a new root-owned file at that path, in a directory the configuration is loaded from,
  outside the set anyone reviewed. Rewrite the whole alias rather than deleting the line: the last
  entry carries no trailing comma, so removing a line can move that position and leave the file
  syntactically broken. Validate with `visudo -cqf` before installing, and keep the backup outside
  `/etc/sudoers.d/` - a superseded policy file inside the directory the privilege system reads is
  protected only by the convention that names containing a dot are skipped.

Every sudoers file is root-owned and read-only (`0440` or stricter). See [`PRIVILEGE.md`](PRIVILEGE.md)
for the full contract and the negative tests that prove it.

### Part 2 — the nodes

The scripts are in [`install/node/`](../install/node/) and reach a node in the
[`haprion-node` package](#installing-and-changing-node-scripts), which puts them in `/usr/sbin` and
[`04-node-prepare`](../install/04-node-prepare) beside its library; that step creates the
accounts, the release layout and the sudo rules.

Every installation and update runs the same idempotent step, but do not mistake an update for a
script-only copy: the step also reconciles service accounts,
directory ownership and modes, `node.conf`, sudoers, the HAProxy baseline and the complete script
attestation. Read every reported `created`, `fixed`, `written` and `installed` line on the pilot
before another node is touched.

This section explains what they do and why; run the script rather than following it by hand.

**Size.** One vCPU and 1 GB of memory per node carries HAProxy and keepalived. **With the WAF engine,
start from 2 GB per node.** The engine is allowed up to 40 % of the node's memory (see
[The WAF engine](#the-waf-engine)), its rules take about 50 MB for the first object
and a few MB for each further one, and HAProxy keeps the rest. The DNS listener adds about 85 MB.

One vCPU is where a node starts, not what every node needs. CPU follows the traffic: requests a
second, new TLS connections - a handshake costs far more than a request on an open connection -
and, most of all, the WAF engine, which reads every request of an object it guards, more so at a
higher paranoia level. How far one vCPU goes also depends on the processor behind it. As a rough
guide, one vCPU at full load, with small requests and answers, a backend that answers at once
and the traffic log on:

| | Connections reused | A new TLS connection per request |
|---|---|---|
| without the WAF | about 6 900 requests a second | about 1 250 |
| WAF, paranoia 1 | about 1 100 | about 700 |
| WAF, paranoia 4 | about 750 | about 500 |

At a tenth of those rates a node uses roughly a sixth to a quarter of its vCPU. Larger bodies,
slower backends and more rules lower them. Only the node holding the VIP carries the traffic,
so a busier cluster needs larger nodes, not more of them. The dashboard shows each node's CPU and memory in use and marks a cluster at 85 %; give
the nodes more vCPUs before they get there.


#### HAProxy and keepalived baseline

The node package installs HAProxy and keepalived, and the project **assumes things about how they
are configured** - for a cluster created in the interface it writes `keepalived.conf` itself
([keepalived on the nodes](#keepalived-on-the-nodes)). Get these wrong and nothing fails loudly — deploys just stop being safe, because the
ordering that protects live traffic quietly stops meaning anything.

**Both nodes must be able to bind the virtual address, whether or not they own it.**

```text
# /etc/sysctl.d/60-haproxy.conf
net.ipv4.ip_nonlocal_bind = 1
```

Without it, HAProxy on the node that does *not* hold the address fails to start: it is asked to
bind an address the kernel says is not there. With it, both nodes run continuously and the virtual
address decides which one traffic reaches. `04-node-prepare` sets this and reports it.

**Nothing else on a node may listen on every address.** A program bound to `0.0.0.0:<port>` holds
that port on the virtual address too, and HAProxy then cannot bind an object there: the deploy
fails on `cannot bind socket (Address already in use)` and rolls back. sshd is the usual case -
out of the box it listens on `0.0.0.0:22`, which rules out a tcp object on port 22 such as an SFTP
service on the virtual address - so `04-node-prepare` gives sshd the node's own address, the one
the node reaches the management host from:

```text
# /etc/ssh/sshd_config.d/05-haprion-listen.conf
ListenAddress 192.0.2.11
```

It does so only while sshd listens on every address; an sshd already on chosen addresses is left
as it is. It refuses the virtual address and an address the node does not have, and after
restarting sshd it checks that sshd answers on the address and no longer on every address -
otherwise it removes the file, puts sshd back as it was and stops. Open sessions survive the
restart. On Ubuntu sshd is socket activated, and the restart is of `ssh.socket`;
`ip_nonlocal_bind` above is what lets it come up at boot before the address does. Any other
program on every address is reported, not changed, and a publish refuses an object on its port
([Ports the cluster takes itself](#ports-the-cluster-takes-itself)).

**HAProxy's log socket outlives rsyslog.** HAProxy runs chrooted in `/var/lib/haproxy`, so its
`log /dev/log` is `/var/lib/haproxy/dev/log`, the socket Ubuntu's `/etc/rsyslog.d/49-haproxy.conf`
has rsyslog listen on. Left to rsyslog, the socket goes away whenever rsyslog stops, and the lines
HAProxy writes until it is back are lost - to the node's day file and to every receiver. So
`04-node-prepare` has systemd hold it, as `syslog.socket` holds the system log's:

```text
# /etc/systemd/system/haprion-haproxy-log.socket
[Socket]
ListenDatagram=/var/lib/haproxy/dev/log
SocketMode=0666
ReceiveBuffer=16M
Service=rsyslog.service

# /etc/sysctl.d/60-haproxy.conf
net.unix.max_dgram_qlen = 8192
```

rsyslog is handed the socket when it starts, and while it restarts the lines wait in it: the queue
length is how many, enough for a restart at 25 000 requests a second. Like `syslog.socket`, it
starts rsyslog when a line arrives and rsyslog is not running. Without `49-haproxy.conf`'s line the
step warns and leaves the socket to rsyslog.

**The unit must load `conf.d`, and must load it exactly once.**

A node's configuration is a main file plus a directory of fragments, and systemd has to be told
about both:

```text
ExecStart=/usr/sbin/haproxy -Ws -f $CONFIG -f $CFGDIR -p $PIDFILE $EXTRAOPTS
```

Upstream's packaging does this and sets `CFGDIR=/etc/haproxy/conf.d`. Some distribution packages
ship a unit with only `-f $CONFIG`, and installations working around that have historically
smuggled the directory in through the variable itself:

```text
# Don't. This breaks the moment the unit gains -f $CFGDIR of its own.
Environment="CONFIG=/etc/haproxy/haproxy.cfg -f /etc/haproxy/conf.d"
```

Against a unit that already loads `CFGDIR`, that reads the directory **twice**, every proxy is
declared twice, and HAProxy refuses to start — duplicate proxy names are an error as of 3.3, where
they were a warning before. Check the effective invocation rather than the unit file, since
drop-ins and `/etc/default/haproxy` both feed into it:

```console
$ systemctl cat haproxy
$ grep -vE '^\s*#|^\s*$' /etc/default/haproxy
```

`systemctl show haproxy -p Environment` is not a substitute: it reports only the unit's own
`Environment=` lines. `EnvironmentFile=` is read when the service starts, never appears there, and
overrides them.

This matters beyond startup. `haprion-pull-deploy` validates with its own explicit arguments —
each file named once — so a configuration can validate cleanly while the service will not start.
The two paths only agree if the unit names each path once too.

**Both nodes run keepalived as `BACKUP`, with `nopreempt`.**

```text
vrrp_instance alpha {
    state           BACKUP        # both nodes - not MASTER on either
    interface       eth0          # whatever carries the VIP on your nodes
    virtual_router_id 51          # unique per VRRP domain on the segment
    priority        100           # 100 on one node, 90 on the other
    nopreempt
    advert_int      1

    unicast_src_ip  192.0.2.11    # this node
    unicast_peer {
        192.0.2.12                # the other node
    }

    authentication {
        auth_type PASS
        auth_pass <shared secret>
    }

    virtual_ipaddress {
        192.0.2.10                # the VIP
    }

    notify_master "/usr/sbin/haprion-keepalived-state MASTER"
    notify_backup "/usr/sbin/haprion-keepalived-state BACKUP"
    notify_fault  "/usr/sbin/haprion-keepalived-state FAULT"
}
```

Three details carry weight:

- **`state BACKUP` on both, plus `nopreempt`.** A node that comes back after a failure does not take
  the address back, even with the higher priority. Preemption would move live traffic for no reason
  — during a rebuild, exactly when you least want it. The priorities still decide who takes it on a
  cold start, when neither holds it.
- **Unicast, not multicast.** `unicast_peer` names the other node explicitly. Multicast VRRP works
  until something on the path quietly stops forwarding it, and then two nodes both believe they are
  master.
- **The `notify_` lines are not optional here.** They are how the management host learns who owns
  the address. Without them the state file is never written, node status cannot report an owner, and
  a deploy has no way to order the nodes.

**Why the ordering matters.** A rollout deploys the non-owner first and the address owner last. If
the new configuration breaks, it breaks on the node not carrying traffic, and the run stops before
reaching the other one. That protection is only real if the owner is actually known — which is why
the three points above are part of the installation and not an operational detail.

**One more line, in the cluster's own configuration rather than the node's.** Status and
statistics are read from a local HAProxy stats socket. A cluster made by *Create cluster*,
`haprion-cluster` or step 1 has it in its `core/haproxy.cfg` from the start; a core written by hand
needs it, or every node of the cluster reads *Stats unavailable* while it serves:

```text
stats socket /run/haproxy/ui-status.sock mode 660 level user
```

`level user` is read-only — enough for status and statistics, not enough to change anything. It is a
local socket and must not be exposed on the network. An existing admin socket is separate and is not
replaced by it.

A copy-paste starting point for the keepalived side is in
[`install/examples/keepalived.conf.example`](../install/examples/keepalived.conf.example).

**One thing to expect after first provisioning.** A clean keepalived config reload does not
necessarily produce a VRRP state transition, so the state file may be empty until the first real
transition. Force one — stop keepalived on one node and start it again — or write the file once by
hand.

#### Node accounts

Four service accounts, identical on every node. They are system accounts with no password, a home
directory for `authorized_keys`, and — deliberately — a real login shell:

| Account | Reached by | May run |
|---|---|---|
| `_haprion-trigger` | the management host's deploy and cert-deploy keys | the pull scripts, through forced commands |
| `_haprion-backup` | the management host's backup path | the state export |
| `_haprion-status` | the management host's status key | the node status reporter, read-only |
| `_haprion-logread` | the collector's traffic-log key | the bounded traffic-log reader, read-only and without sudo |

**The shell looks like a mistake and is not.** sshd runs a forced command through the account's
login shell, so `nologin` here does not harden anything — it stops every forced command from
working, and the only symptom is a nologin message where output was expected.

What constrains these accounts is that each key carries `restrict` and its own forced command, so a
session cannot run anything else. Where sudo is needed, its rules name exact absolute commands;
`_haprion-logread` needs and receives no sudo rule. None of this depends on the shell.

Each key in the account's `authorized_keys` carries its **own** forced command and the `restrict`
option. One key, one command: a shared forced command would make the keys interchangeable and
defeat the separation.

**The account owns nothing in its own home.** `/home/<account>`, `.ssh/` and `authorized_keys`
are `root:root` (`755`, `755`, `644`); sshd accepts a root-owned key file as readily as one owned
by the account. A key file the account could write would let a session rewrite its own forced
command, and a home directory it owned would let it replace `.ssh` wholesale. The shell's dotfiles
are covered by the same rule: Debian's bash sources `~/.bashrc` for a command it runs on behalf of
sshd, before the forced command, so no dotfiles are created and any that exist are made root's on
the next run of step 4. Edit `authorized_keys` with `sudo`.

#### Node scripts

All root-owned under `/usr/sbin`, installed by the `haprion-node` package, not group-writable:

| Script | What it does |
|---|---|
| `haprion-pull-deploy` | fetches the published release, validates it, installs it, reloads once |
| `haprion-cert-trigger` | unprivileged wrapper: validates the verb (`cert-pull` or `cert-remove`) and the certificate IDs, then escalates |
| `haprion-cert-pull` | fetches the requested certificates, validates them, installs, and replaces them in the running HAProxy through `haprion-server-state update-certs` (`set ssl cert`/`commit ssl cert` on the admin socket), reloading instead when HAProxy does not hold one of them or refuses it; a run stopped between installing and reloading leaves `/run/haprion-cert-pull.pending`, the node's status leaves those certificates out until the next run reloads |
| `haprion-cert-remove` | removes the requested certificates from `/etc/haproxy/certs`, refusing any the installed configuration still names; no reload |
| `haprion-node-status` | reports version, health, carried certificates, keepalived state and the address list |
| `haprion-keepalived-state` | records the keepalived transition to a state file |
| `haprion-state-export` | writes this node's permanent state to stdout as a gzipped tar |
| `haprion-health-probe` | opens one connection per named target and reports the status line |
| `haprion-traffic-log-read` | returns whole records after a validated UTC day/cursor, capped at 8 MiB; `waf <cursor>` returns the WAF engine's journal lines after a journal cursor, same cap |
| `haprion-traffic-log-enable` | installs or removes this node's rsyslog route and retention timer |
| `haprion-traffic-log-prune` | deletes traffic day files past the 14-day window, or the oldest over the space budget, whole and never renamed |
| `haprion-server-state-trigger` | unprivileged wrapper: validates `server-state <guid> <ready\|drain\|maint>` or `unblock <object> <address>...`, then escalates |
| `haprion-server-state` | sets one server's state on HAProxy's admin socket and keeps it; reloads HAProxy for the other scripts and puts kept states back on the new worker, and again when HAProxy starts; replaces certificates HAProxy already holds without a reload (`update-certs`); lifts an object's dynamic block on addresses, from its blocked table and its count (`unblock`) |

Step 4 also writes `/etc/haprion/node-installation.json`. It records the
node compatibility API and a SHA-256 digest for each of these thirteen scripts.
`haprion-node-status` recomputes the digests on every reading, so copied metadata
cannot hide a script changed after installation. The report contains code
digests only, never node configuration or key material.

**Your own files in the state backup.** The export carries the product's state
by name. Files that are yours rather than the product's — a local kernel option,
a site drop-in — are listed in `EXTRA_BACKUP_PATHS` in the answers file, which
step 4 renders into `node.conf`. Absolute paths, space-separated, letters, digits
and `. _ @ + - /` only; step 4 refuses anything else, because `node.conf` is
sourced as root. The export copies each one into the archive at its own path and
lists them in `meta/extra-paths.txt`, so a restore can tell them apart. A listed
path that does not exist on the node, or a directory holding a socket, pipe or
device, **fails that node's backup** instead of being skipped — the management
host only shows an export's messages when it fails, and an archive that quietly
lacks a file you asked for is the drift a backup is there to rule out. Every
node that gets the answers file must therefore have every listed path.

Two of these deserve attention:

**`haprion-cert-trigger` exists because sudoers cannot express a list.** The certificate IDs arrive
as SSH command arguments, and no wildcard rule can safely constrain them. So validation happens
twice: unprivileged in the wrapper, and again in the root helper. The wrapper escalates with
`sudo -n` and an exact `NOPASSWD` rule, so a policy mismatch fails immediately instead of falling
back to an interactive password prompt. The wrapper knows two verbs, `cert-pull` and `cert-remove`
([Deleting a certificate](#deleting-a-certificate)), each with its own root helper and its own
sudoers rule.

**`haprion-health-probe` is held to the same TLS floor as the configuration.** A pool whose object
names a `legacy` policy is reached by HAProxy over TLS [Service accounts and the config group](#service-accounts-and-the-config-group), so a probe that kept a floor of its own
would refuse a backend HAProxy accepts and report a healthy pool as down. Each target therefore
carries a `min_version` — `TLSv1.1`, `TLSv1.2` or `TLSv1.3` — and the script refuses anything else.

A target that names none means `TLSv1.2`.

**`haprion-server-state` keeps a drain through reloads and restarts.** A state set over HAProxy's
runtime socket lasts only as long as the worker, and every deploy and certificate rollout starts a
new one. So the node keeps the wanted state per server in `/var/lib/haprion/server-state.json`
(`root`, `0600`) - carried in the node's state archive, so a node restored to a new VM keeps
its drains, while a node restored over itself keeps its own, newer file - named by the server's GUID - derived from its address and port, so reordering a
pool moves nothing and a server given a new address starts ready - and every reload on the node
goes through `haprion-server-state reload`: it reads the worker's pid, reloads, waits for a
worker with another pid, and sets the kept states on a connection whose `show info` proves which
worker took them. A drop-in on `haproxy.service` runs `haprion-server-state reapply` once HAProxy
is ready, prefixed `-` so a state that cannot be set never keeps HAProxy from starting. HAProxy's
own `server-state-file` is not used: it carries a server's old port over a changed configuration
(haproxy/haproxy#3296). It needs a socket at level `admin` that only root can open - one line in
the cluster's `core/haproxy.cfg`:

```
    stats socket /run/haproxy/manager.sock mode 600 level admin
```

The trigger account's key line for it is written by step 4 from `SERVER_STATE_PUBKEY` in the
answers file; a line already there for the same forced command is replaced. A node without the
key, or a core without the socket, offers no server state and refuses a request with the line
that is missing.

**`haprion-pull-deploy` is generic except for its publication path.** Everything else — validation,
release creation, the atomic symlink swap, the rollback on failure — is identical on every node.

#### Node filesystem layout

```text
/etc/haproxy/current -> /etc/haproxy/releases/<timestamp>
/etc/haproxy/haproxy.cfg -> current/haproxy.cfg
/etc/haproxy/conf.d      -> current/conf.d
/etc/haproxy/maps        -> current/maps
/etc/haproxy/certs/          local certificate directory
/run/lock/haprion-deploy.lock
```

The releases root is `root:root 0750`. HAProxy, deployment, status and backup operations read it as
root; no forced-command service account needs to traverse it. Files inside an immutable release
may remain `0644` without thereby exposing the active configuration to those accounts.

A deploy never edits the running configuration. It builds a new immutable release directory, swaps
the `current` symlink atomically, validates again through exactly the paths `systemd` uses, and only
then reloads. If either validation or the reload fails, the symlink is swapped back.

The traffic log ([Traffic logs and metrics](#traffic-logs-and-metrics)) writes its day files under `/var/log/haprion`,
and like the manager's mirror it grows with visitors. Give it a filesystem of its own on a busy
node, mounted there, and make rsyslog wait for it, so a late volume does not let the files land on
the root filesystem underneath the mount point:

```text
# /etc/systemd/system/rsyslog.service.d/10-haprion-logs.conf
[Unit]
RequiresMountsFor=/var/log/haprion
```

The retention window bounds what the files hold; the separate filesystem bounds what a burst
within that window can take from everything else.

`/run/lock` itself belongs to the operating system and is commonly mode `1777`. The node installer
requires it to exist but never changes its owner or permissions; Haprion owns only its
root-created lock files inside the directory.

#### Installing and changing node scripts

There is no unattended management-identity path for this, by design. Every management identity is
a forced command; none of them can copy a file. Installing or changing a node script crosses an
administrator's own interactive SSH login and escalates with `sudo` on the node.

The repository does automate everything around that interactive boundary. A node release is one
Debian package, `haprion-node` (`Architecture: all`): the node scripts in `/usr/sbin`, owned by
dpkg, and `04-node-prepare` with the library it sources under `/usr/share/haprion-node/install/`.
Platform installers, examples, caches and the source tree do not belong in it. Environment answers
remain a separate root-owned input; putting them in the code artifact would make two installations
of the same commit produce different packages.

##### Build and verify the package

Use a clean, committed source tree that has passed the complete repository gate. Build into a
protected staging directory outside the repository:

```bash
tools/node-package.py build \
  --source "$(pwd)" \
  --output-dir /path/to/protected/staging
```

The builder refuses a dirty tree, an existing output file, a missing payload file and an unexpected
Git file mode. It reads payload bytes and modes from the commit rather than the working tree, then
prints the package's path, its version - `<version>+git<commit time>.<commit>`, so a later commit
sorts later - the full commit and the SHA-256. Record the digest beside the artifact; do not derive
trust from a digest received with an untrusted copy.

The package is deterministic: building the same commit twice produces identical bytes. Verify a
retained or transferred copy:

```bash
tools/node-package.py verify \
  --package /path/to/protected/staging/haprion-node_0.1.0+git20261009120000.0123456789ab_all.deb \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Verification rejects an external digest mismatch, another package or architecture, a version this
project does not build, a file that is not one of the node package's or has another mode or owner,
and a package over its size limit.

##### Preflight and install one node

Measure the pair immediately before an update and select the node that does not own the virtual
address:

```bash
haprion-status -c alpha
```

Run the transport as your administrator account, never as root. All paths must be absolute. The dry
run verifies the package locally, opens the operator's normal host-key-checked SSH path, checks the
node's cluster and prerequisites, and writes neither a backup nor a staging file:

```bash
tools/install-node-package --dry-run \
  --node-package /path/to/protected/staging/haprion-node_0.1.0+git20261009120000.0123456789ab_all.deb \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --answers /path/to/answers.env \
  --node node-b \
  --cluster alpha
```

Remove `--dry-run` to install. Rolling one package across a cluster's pair, give the first node
`--skip-backup-after` and the second `--skip-backup-before`: the state backup
(`haprion-state-backup -c <cluster>` from the installed release) archives both nodes of that
cluster, and one before the first write and one after the last is the rule, not one pair per
node. Another cluster's roll-out is its own pair of backups. The tool:

1. verifies the external digest and the package's contents before contacting the node;
2. takes a state backup of the cluster before the first remote write;
3. uses one multiplexed, strictly host-key-checked SSH session for staging and installation;
4. copies only the package and the separate answers file to a random mode-700 directory under
   `/tmp`, then verifies the package digest again on the node;
5. installs the package with apt - without recommended packages, so keepalived stays the operator's
   choice - and runs its `/usr/share/haprion-node/install/04-node-prepare` through the operator's
   interactive `sudo` path. That step checks the package's files with `dpkg --verify` and stops on
   a script edited by hand;
6. takes another state backup and runs `haprion-status` for the cluster; and
7. removes its remote and local staging automatically. A cleanup failure is a visible warning that
   names the exact directory; remove only that named directory after inspecting it.

The SSH login and the node's sudo authentication are deliberately interactive. The shared SSH
session means each is requested once per node, not once per file. The management identities remain
forced commands and gain no file-copy ability.

Stop after the first node and read both the install report and `haprion-status`. A successful copy
proves bytes, modes and ownership; run the command that uses a changed script before proceeding.
Remeasure VIP ownership before every subsequent node — never assume it stayed where the previous
status reading found it.

`haprion-traffic-log-enable` and its `--disable` path restart rsyslog because rsyslog does not load
a changed rule on HUP. HAProxy does not buffer while its local log socket is unavailable, so a
request during that sub-second restart can be absent from both the structured day file and the
classic log. Run the command on the node that does not own the VIP first, remeasure ownership, and
then run it on the owner. The command repeats this loss window in its final output; a successful
restart cannot recover a line emitted while rsyslog was down.

##### Rollback

Keep the previous node package and its recorded SHA-256. A code rollback is the same verified
installation command with that retained package and `--downgrade`, which lets apt put the older
version in place; without it apt refuses, so the wrong file never rolls a node back by accident.
There is no special path that bypasses the digest or contents checks. Re-run the functional
command and `haprion-status` afterwards.

State backups are taken on both sides of every update so account, policy and configuration changes
also have a recovery point. They are not restored automatically: an automatic whole-node restore
after a partial failure could overwrite unrelated state that changed during the window. Stop on a
failure, preserve the reported backup, note any cleanup warning and determine which reported
operation completed before restoring state.

Optional features have their own symmetric rollback. For traffic logging, disable the node route
with `sudo haprion-traffic-log-enable --disable`, remove only that collector key's forced-command
line from `_haprion-logread` and disable the manager collector. Traffic files are deliberately retained;
rollback never deletes evidence.

### Part 3 — the versioned CLI release

The management CLI is installed independently of the application data filesystem: a release lives
under `/opt/haprion` so recovery and diagnostics remain available if application storage is not.

Application code is installed from a wheel, through the `haprion-cli` package. It is never
imported from a checkout, an editable environment, a developer-owned virtual environment, or any
development path.

#### The `haprion-cli` package

This is how the CLI is installed and updated. The package carries the wheel, the node package of
the same commit, the WAF engine package, the release installer and the operators' sudo rules, and
its `postinst` runs the installer described below. Run the complete repository gate first, then
build it from the clean commit, with the `uv` the repository is locked with and the engine package
built by `tools/build-coraza-package.py`:

```bash
tools/build-cli-package.py --source "$(pwd)" --output-dir /path/to/protected/staging --uv /path/to/uv \
    --waf-engine-package /path/to/protected/staging/haprion-coraza-spoa_0.9.0-7_amd64.deb
sudo apt-get install /path/to/protected/staging/haprion-cli_0.1.0+git20261009120000.0123456789ab_all.deb
```

The same commit gives the same bytes. It installs:

| Path | What |
|---|---|
| `/usr/lib/haprion/cli/` | the wheel, the node package, `install-release.py` and `PAYLOAD` with their digests |
| `/usr/bin/haprion-*` | one line per operator command, into `/opt/haprion/current/bin` |
| `/etc/sudoers.d/haprion` | the operators' rules: `%sudo` may run each read helper without a password and each write helper with one; never `%haprion`, which holds the worker. Checked with `visudo` when the package is built |

`apt-get purge haprion-cli` also removes `/opt/haprion`; `remove` leaves the releases.

#### The release installer

The package's `postinst` runs `install-release.py` with the wheel and node package it carries. It
can also be run by hand, which is what installing without the package means. Build into a
protected staging directory outside the repository and record its SHA-256 digest:

```bash
python -m build --wheel --outdir /path/to/protected/staging
sha256sum /path/to/protected/staging/haprion-*.whl
```

Build the node package from the same commit, as in [Installing and changing node scripts](#installing-and-changing-node-scripts),
and record its digest too. The release carries it: a node restore installs exactly the package of
the release that runs it, and a rollback of the CLI takes the package back with it.

Install the absolute wheel and package paths with the digests printed by the previous commands:

```bash
sudo /usr/bin/python3 tools/install-release.py \
  --wheel /path/to/protected/staging/haprion-0.1.0-py3-none-any.whl \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --node-package /path/to/protected/staging/haprion-node_0.1.0+git20261009120000.0123456789ab_all.deb \
  --node-package-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

The package is verified by the new release's own verifier before anything is activated, copied
into the release as `haprion-node.deb` and recorded in `INSTALLATION.json` with its version, commit
and digest. The two package arguments are optional so a wheel installed without them stays
installable for rollback; a release without a package refuses to restore a node and says why. A
release is not changed in place: installing an already installed wheel with another package, or
without the one it has, is refused.

The installer fails closed unless it runs as root and the supplied digest matches. It also rejects
unsafe wheel members and entry points, verifies the runtime baseline (including the distribution's
PyYAML, PyNaCl and psycopg packages) and imports, then installs:

```text
/opt/haprion/
├── current -> releases/<version>-<wheel-hash-prefix>
└── releases/
    └── <version>-<wheel-hash-prefix>/
        ├── INSTALLATION.json
        ├── haprion-node.deb
        ├── bin/
        └── lib/
```

Release directories are `root:root`, directories and launchers are mode `555`, and other files are
mode `444`. The `current` link is replaced atomically only after the new release passes validation.
Short stable wrappers and exact sudoers rules may point into `current/bin`; they must never point
into a source checkout.

**`current/bin` is not on `sudo`'s path.** `sudo` resets `PATH` to its `secure_path`, which does
not include `/opt/haprion/current/bin`. The `haprion-cli` package (above) therefore installs one
line per operator command in `/usr/bin`, of the shape

```bash
#!/bin/sh
exec /opt/haprion/current/bin/haprion-cert-receiver "$@"
```

so that a release switch moves every command at once and nothing points at a release directory
by name. Root helpers get none: a helper is run through its exact sudo rule by its calling half,
never typed. Without the package the full path works the same:
`sudo /opt/haprion/current/bin/haprion-cert-receiver ...`.

`INSTALLATION.json` also records the engine compatibility API carried by the
wheel, which the whole-installation check compares with what the UI needs.

#### Order of operations

Install the release **before** adding runtime-policy fields that a new release introduces. The
policy reader rejects unknown fields, so the reverse order breaks every command that reads the
policy, not only the new one.

### Part 4 — the web platform

Optional, and separate on purpose. The command line is the authoritative engine
and installs and runs without any of this; a management host that only ever uses
the CLI never needs the platform at all. [`../install/platform/`](../install/platform/)
is what you follow; this section explains the shape.

#### What is installed where

```text
/opt/haprion-ui/
├── current -> releases/<version>-<commit>/
├── releases/<version>-<commit>/venv/
└── releases/<version>-<commit>/migration/
/etc/haprion/
├── ui.toml          root-owned, readable by the platform group
├── ui-secrets/      root-only, granted one file at a time
├── dns-profile-keys/, oidc-keys/   public keys, readable by the platform group
└── ui-admin.conf    the database and role the root commands use
/var/lib/haprion-ui/
├── dumps/           database backups, root-only
└── logs/            the traffic-log mirror
```

Configuration, secrets and data live **outside** the releases, each where
Debian puts its kind. A release is replaced wholesale and rolled back by
pointing `current` elsewhere, so anything that has to survive that cannot live
within it. The places are fixed rather than answers, like the account names.

A release is a commit: the `haprion-ui` package is built from one, in a
container of the target distribution, at the release's final path against that
distribution's interpreter — a virtual environment is not relocatable, and an
interpreter under someone's home directory is invisible to a service running
with `ProtectHome`. Both are checked again before `current` is switched. The
package carries the release as an archive whose digest `postinst` checks before
unpacking it, and two builds of one commit give the same bytes.

#### Identities

Three service accounts, one per service, each with its own database role. A
shared account for all three would make a web intrusion equal to worker access,
which is deploy rights. They share one group, and that group grants exactly one
thing: reading the configuration file.

Nothing authenticates to the database with a password. Connections use the local
socket with peer authentication, where the kernel states which operating-system
user is on the other end, and each account is named after its role — so there is
no password to leak, rotate, or find in a process listing.

#### The database

The migration role owns every object and has no operating-system account. That
is what makes "a service process cannot run DDL" true by construction rather
than by a grant somebody could add later: you cannot drop a table you do not
own. Running a migration is a deliberate root action, mapped explicitly in
`pg_ident.conf`.

Table grants live in the migration that creates the table, so a column's
permissions are versioned with the column. They name contract roles —
`app_web`, `app_worker`, `app_poller`, `app_collector` — and never an account; the installation
connects whatever the accounts are called to those roles. Columns are listed one
at a time, because a grant written as a whole table widens itself the next time
somebody adds one.

The web role may state what it wants done. It holds `insert` on three columns of
the job table and no `update` at all, so a queued job is immutable to the role
that queued it and there is no path from "I asked for this" to "this is what
happened". State, request ID and timestamps come from column defaults.

The poller writes cached readings and never removes one, with a single exception: the search
index, `search_entry`. Each reading the poller makes is turned into the values the header's search
looks for, and the poller replaces that reading's rows in one transaction, so it holds `delete` on
that table and on no other. The rows are derived and rebuilt every pass; the web only reads them.

##### Where the data lives

**Give everything that grows with traffic a filesystem of its own, and keep the
root filesystem out of reach of it.** Three things grow with the nodes' visitors
rather than with anything the administrator does: the database (its traffic-log
and WAF-log tables), the database dumps, and the mirror of the nodes' traffic
logs. A full root filesystem stops far more than Haprion - journald, apt,
logins - so a busy week must fill a volume that was sized for it, not `/`. The
reference host has a separate volume mounted at `/apps` for exactly this, and
everything that grows lives on it, each under the path the package expects
through a bind mount, as below. The platform's `/var/lib/haprion-ui` (dumps and
the mirror) belongs on the same volume, mounted the same way:

```text
# /etc/fstab
/apps/haprion-ui  /var/lib/haprion-ui  none  bind,x-systemd.requires-mounts-for=/apps  0 0
```

The units that write there wait for that mount (`RequiresMountsFor`), so a
volume that comes up late does not leave a dump on the root filesystem under it.

Put the cluster's storage on that volume, and keep the
package's path. The reference host mounts the platform volume at `/apps`, and
`/var/lib/postgresql` is a bind mount onto a directory there — not a cluster
reconfigured with a different `data_directory`:

```text
# /etc/fstab
/apps/postgresql  /var/lib/postgresql  none  bind,x-systemd.requires-mounts-for=/apps  0 0

# /etc/systemd/system/postgresql@.service.d/10-apps-mount.conf
[Unit]
RequiresMountsFor=/var/lib/postgresql
```

The directory behind the mount is owned by `postgres` (`755`), because a bind
mount shows the target's top level as the mount point. The drop-in is what makes
the arrangement safe rather than merely working: without it a boot on which the
platform volume comes up late would start the server on an empty directory,
and it would run — initdb-fresh, with no databases — until somebody noticed.

Two things sit behind this shape. The traffic-log table ([Mirroring node traffic logs](#mirroring-node-traffic-logs)) is the one part
of the installation whose growth is set by the nodes' visitors rather than by
the administrator, so it belongs on the volume that was given room for exactly
that, next to the dumps and the mirror; the root filesystem stays predictable.
And the path stays the package's because a cluster at its own path turns every
distribution upgrade into a special case for years, while a mount point leaves
`pg_upgradecluster` and the package tooling looking at the layout they expect.
The price is one ordering condition, proved once at installation:

```bash
findmnt /var/lib/postgresql        # SOURCE must name the platform volume
sudo systemctl restart postgresql  # and the cluster must come back on it
```

Moving an existing cluster is a stop, an `rsync -aHAX --numeric-ids`, a second
dry run that finds nothing left to copy, the mount, and the start — with a
verified dump ([Backups, and proving they restore](#backups-and-proving-they-restore)) taken first, and the old tree kept beside the mount until the
new one has served a day. The backup step's 85 % warning watches the filesystem
holding the dumps, which is now also the one holding the database.

#### Verifying it

`install/platform/03-verify` is read-only and can be run at any time. It is
deliberately a **second description** of the privilege surface, compared against
what the running database reports, and it checks both directions.

Both directions matters more than it sounds. A suite that only asks what a role
must *not* do passes completely when a role has no privileges at all — which is
a broken system reading as a perfectly secured one. Ask what must work too.

`install/platform/check-compatibility` is the read-only check above that local
database proof. Run it after the independently released pieces have been
installed:

```bash
sudo ./check-compatibility
```

The running UI release supplies the accepted database revisions and minimum CLI
and node APIs. The command reports both release IDs, queries `alembic_version`,
checks that worker, poller and web really execute from `current`, compares the
active sudo rules with the helpers the UI requires, and reads each node's installation
through the existing status helper. It ends in one `COMPATIBLE` or `INCOMPATIBLE`
verdict and changes no file, row, service or HAProxy release.

For an update, first run `install-ui-release --prepare <release-id>` on the
release the package unpacked. The candidate is verified but `current` stays on
the old release. Run `check-compatibility
--release <release-id> --before-migration` to prove its CLI, helper and node
requirements, then `migrate --release <release-id>`, `03-verify`, and the candidate
check again without `--before-migration`. Only after those pass is the same
prepared release activated by rerunning `install-ui-release` without `--prepare`.
The final ordinary compatibility check proves the processes after the switch.

`update-platform-release` owns that complete order for normal updates, and the
package's `postinst` runs it when a newer `haprion-ui` is installed over a
running platform:

```bash
sudo ./update-platform-release <release-id>
```

The CLI and node scripts remain independent installations; the command checks
them and stops before migration when either is too old. It also requires that
the currently running UI keeps working on the candidate's database head - both
while the migration runs under it and as the rollback target afterwards. Since
migration `0065` every migration says so itself:

```python
ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "adds a table nothing older reads; no column is changed"
```

The release's metadata names the oldest revision from which every migration
after it is declared safe (`rollback_safe_from`), and the check accepts a
running UI whose own head is at or after it. A migration that changes what
older code reads - a column dropped or renamed, a constraint older code would
break - says `ROLLBACK_SAFE = False`; then first ship a bridge UI release whose
compatibility metadata accepts both revisions, and the migration release after
it. The repository's tests refuse a new migration without the declaration and
metadata that disagrees with the migrations. A failure after activation runs the
installed UI rollback command and checks the restored processes before
returning failure.

#### HTTPS and the certificate

`install/platform/05-platform-nginx` puts nginx in front of the web service and
terminates HTTPS there. The web service itself listens only on
`127.0.0.1:8080`, in plain HTTP, and that leg stays plain deliberately: it never
leaves the host. The rendered site also includes
`/etc/nginx/snippets/haprion-receivers.conf`, created empty by this
step and written afterwards only by `haprion-cert-receiver` ([Registering a receiver](#registering-a-receiver)); a rerun of
the step leaves an existing snippet alone.

**This is the direct address, and it does not go through the HAProxy pair.**
That is the whole point of it. The UI is the tool used to repair that pair, so
putting the UI behind it means a broken publish locks you out of the only thing
that could revert it. A reverse proxy elsewhere — anything from another nginx to
Nginx Proxy Manager on a container host — may be added in front as an *additional*
path, terminating with its own certificate. It must never become the only path.

**The certificate is what a browser meets at login**, not something internal. It
cannot come from the certbot chain the rest of this project uses: that chain is
ACME with DNS-01 against a public domain, and a management host named on an
internal domain cannot be validated that way. So the pair is either self-signed
or issued by your own PKI.

Four answers-file keys control it:

| Key | Meaning |
|---|---|
| `SERVER_NAME` | the name the UI is reached on directly. Required |
| `TLS_CERT` | defaults to `/etc/haprion/tls/ui.crt` |
| `TLS_KEY` | defaults to `/etc/haprion/tls/ui.key` |
| `TRUSTED_PROXIES` | addresses or networks of a reverse proxy in front, space-separated; empty by default. See [Behind another reverse proxy](#behind-another-reverse-proxy) |

If no pair exists at those paths, step 5 generates a self-signed one so the UI
is encrypted from the first login. Point the keys at a pair your clients already
trust and that step never runs.

**Plain HTTP is not a lesser option here, it is a non-working one.** The session
cookie is `Secure`, and a `Secure` cookie is never sent over HTTP, so login
simply stops working. Removing `Secure` to get around that would put the session
for a tool with deploy rights in clear text on the network. A self-signed
certificate gives a browser warning but real encryption, which is the better
trade while a proper pair is being arranged.

##### Behind another reverse proxy

A proxy in front - another nginx, Nginx Proxy Manager, a load balancer - is an additional path; the
direct one stays. Without being told about it, the management host knows every user by the proxy's
address, and three things go wrong:

- the sign-in throttle (`[throttle]` in `ui.toml`, failed sign-ins per address) is shared by everyone, so one
  person, or an attacker, locks every user out; the audit log names the proxy for every action;
- a certificate receiver's `/certdist/<receiver>/` location allows only the receiver's address, so a
  receiver fetching through the proxy is refused - and naming the proxy in its place would open
  certificates, and sometimes keys, to everyone who can reach the proxy;
- the sign-in provider (SSO) sends the browser back to the name the request arrived with.

**Name the proxy** in the answers file and run step 5 again:

```bash
TRUSTED_PROXIES="192.0.2.10"        # one or more addresses or networks, space-separated
sudo ./05-platform-nginx answers.env
```

Step 5 writes `/etc/nginx/snippets/haprion-real-ip.conf` on every run - `set_real_ip_from`
per entry, `real_ip_header X-Forwarded-For` and `real_ip_recursive on` - and the site includes it.
From then on nginx believes `X-Forwarded-For` only on connections from those addresses, and takes
the client to be the last address in it that is not one of them: a value a client wrote into the
header before it reached the proxy is skipped. A client that reaches the manager directly and sends
the header is still known by its own address. Throttle, audit log, receivers' `allow` and the access
log then all see the client. Host names and "every address" (`0.0.0.0/0`, `::/0`) are refused.
Emptying the key and running step 5 again stops believing the proxy.

**What the proxy must do:**

- **Use the manager's `SERVER_NAME`** as the name users reach it by, and send that name upstream as
  `Host`. The management host picks its site by that name, and the SSO provider sends the browser
  back to it; a different public name is not supported.
- **Forward to `https://<manager>:443`**, not to the application port, which listens on loopback only.
- **Append to `X-Forwarded-For`** rather than replace it. Other forwarded headers are optional - the
  manager's nginx sets its own.
- Leave receivers fetching directly where they can; through the proxy they work too, once it is
  named here, because the receiver's own address is then what `allow` sees.

A complete nginx block for the proxy, with made-up names (`ui.example.com` is the manager's
`SERVER_NAME`, `192.0.2.20` its address):

```nginx
server {
    listen 443 ssl;
    server_name ui.example.com;
    ssl_certificate     /etc/ssl/ui.example.com.crt;
    ssl_certificate_key /etc/ssl/ui.example.com.key;
    client_max_body_size 1m;

    location / {
        proxy_pass https://192.0.2.20:443;
        proxy_ssl_server_name on;
        proxy_ssl_name ui.example.com;
        # The manager's certificate, from https://ui.example.com/certdist/manager-ui.pem:
        # proxy_ssl_trusted_certificate /etc/ssl/manager-ui.pem;
        # proxy_ssl_verify on;
        proxy_set_header Host            $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_read_timeout 60s;
    }
}
```

In Nginx Proxy Manager, the same thing is a proxy host for the manager's name with scheme `https`,
the manager's address and port 443, and `client_max_body_size 1m;` in its advanced field. Check in
its generated configuration that `Host` is passed unchanged and `X-Forwarded-For` is appended.

#### First administrator

There is no default password and no first-run setup page. Both are holes that
exist for the whole life of an installation in order to be useful for its first
thirty seconds: a shipped password survives in the field, and an
unauthenticated page that creates an administrator is exactly what it sounds
like.

So the first account is made by the installation itself, on the terminal of
whoever installs it: `haprion-setup` asks for it last, when everything else is
done, and `install-ui-release` run on its own asks when it activates a release.
On an installation that has **no account at all**, they run `haprion-user init-admin`,
which creates `admin` as a break-glass admin and asks for its password, twice,
as `add` does. It is never printed and stored nowhere but as a hash. Every later
release finds accounts and does nothing, and asks nothing. Without a terminal —
the installer run with its input redirected — no account is made and the
installer says to run `init-admin` by hand. Nothing about it is the same on two
installations, and nothing answers on the network before it exists.

For account administration and password recovery, see
[Accounts and signing in](#accounts-and-signing-in).

#### Platform backup installation

`install/platform/06-platform-backup` installs `haprion-backup`, a daily
timer, and a weekly restore check — then takes a dump and restores it
immediately, because the moment to discover that a backup does not work is
during installation rather than during an incident.

For manual dumps, restore checks and recovery, see
[Backups, and proving they restore](#backups-and-proving-they-restore).

#### Retention installation

`install/platform/11-platform-retention` installs `haprion-retention` and a
daily timer. It is optional, and it is separate from the backup step because
it is the only thing here that removes rows from a live table. **The step itself
deletes nothing** — it reports what the first run would remove and leaves the
deciding to the timer or to an operator.

For reports, pruning and retention rules, see
[Keeping jobs, sessions and metric history bounded](#keeping-jobs-sessions-and-metric-history-bounded).

#### Mirroring node traffic logs

`install/platform/13-platform-traffic-collector` installs a fourth, deliberately
small identity and a timer that asks each node for its own traffic log. Optional,
and last: nothing else on the platform depends on it.

```text
/var/lib/haprion-ui/logs/mirror     collector writes freshness metadata, the interface reads
/var/lib/haprion-ui/logs/staging    the collector's alone
/etc/haprion/traffic-collector/{id_ed25519,known_hosts}
/etc/haprion/traffic-collector.json
```

The collector program itself is installed with the CLI engine under
`/opt/haprion/current`, not inside the web release. This is a privilege boundary rather than
packaging trivia: web releases are traversable only by the platform group, while the collector
deliberately does not join that group and therefore cannot read `ui.toml`. The engine release is
root-owned, immutable and executable without granting access to the platform configuration.

**The direction is manager to node, and that is the whole design.** The first
attempt had each node forward its log to the management host over TLS, and a DMZ
node correctly could not open that connection. Nothing here asks for a new
network path in any topology: the management host already reaches every node
over SSH for configuration, certificates and status, so this adds one key to a
path the product already requires. An installation whose firewall differs still
needs nothing new.

**A fourth account with one narrow database direction.** The collector is not a member of the
configuration group and has no sudoers rule. Its `app_collector` contract role can only insert
traffic rows; it cannot select, update or delete them. It owns one
SSH key, and the far end of that key is a forced command that can return one
validated day of one node's traffic log and nothing else. The step checks that
boundary rather than describing it, and checks it by traversal: `ls` on a
directory fails whether or not an account can reach through it, so listing is not
evidence.

**Host keys are copied from what this host already trusts, never scanned.**
`ssh-keyscan` asks a node who it is and believes the answer. If a node has no
pinned key yet, the step refuses and says so; accept that one deliberately,
once, through the path that already exists.

**The dumps beside the mirror are closed by their own mode.** The web account
traverses `/var/lib/haprion-ui` to reach the mirror, and `dumps/` there holds
every session and every audit record in one file, so it is `0700 root`; the step
proves neither the web account nor the collector can enter it. The mirror directory is
set-group-id, because the collector is deliberately outside the web account's
group and could not otherwise create a file the interface can read.

The step fetches nothing on its own. It prints one `authorized_keys` line to add
to `_haprion-logread` on each node, and each node also needs its own log route
switched on with `sudo haprion-traffic-log-enable`.

Enabling or disabling that node route restarts rsyslog; a reload does not apply
the rule. HAProxy does not buffer log lines during the brief restart, so apply
the change to the node that does not own the VIP first, verify it, remeasure VIP
ownership and only then change the owner. A request landing in the restart
window can be absent from both the structured and classic local logs.

The stream is also opt-in per cluster. Set `traffic_logging: true` in that
cluster's entry in `clusters.yaml`, then publish an actual object change so the
generator's log profile reaches the nodes. Rerun platform step 13 whenever a
node is added to or removed from `clusters.yaml`; `check-compatibility` refuses
a running traffic-log view while the collector's installed node list differs.

Only the structured stream removes query strings, and only that stream is
mirrored to the manager and shown in the interface. HAProxy's ordinary
`haproxy.log` remains byte-for-byte unchanged and its traditional HTTP log line
contains the complete request target, including any query string. Treat that
local file accordingly when choosing retention, backup and access controls.

The collector imports complete records with PostgreSQL `COPY` and advances an atomic local
checkpoint only after the database transaction commits. Repeating a batch is safe because each
record has a deterministic identity. The interface reads indexed database rows once
`[traffic_logs]` is enabled in `ui.toml`; the mirror metadata still reports collection freshness.
Successful contact does not mean the log is caught up: the log warning shows whether today's
file is incomplete, the bytes remaining at the last read and older days still pending. Each
run reads today in 8 MiB blocks until it is current, then the older days oldest first, for up
to thirty seconds per node, each block within the 30-second SSH timeout. Every run reads at
least one block of today and one of the oldest open day, so both make progress even while
today's file grows; the transfer cap per response is unchanged. The remaining byte count is an observation,
not a prediction of how much new traffic arrived afterwards.
With the database configured the collector keeps the day files in staging and one metadata file
per node in the mirror directory, and does not join the days into one log file per node: nothing
reads that file, and writing it meant rewriting the whole retained history once a minute. A joined
file left from a configuration without the database is removed on the next run.
`retention_days` defaults to seven (range 1–90). The privileged retention timer creates daily
partitions ahead and removes expired data by dropping whole partitions; application identities
have no `CREATE` or `DELETE`. PostgreSQL's `pg_trgm` extension is installed once by platform step
2 so host, path and backend substring searches use per-day GIN indexes.

**The manager's mirror follows that setting rather than carrying a window of its own.** Each run
takes the days the database still holds, keeps one more as the margin it would replay from after a
restore, and lets the rest go. Nothing is configured twice: a mirrored day the database has no
partition for can be neither read in the interface nor imported, so keeping it would cost disk on
the volume the mirror sits on and buy nothing. A run that cannot reach the database keeps the wider
fallback window instead of pruning — fetching is the part that cannot be caught up later, because
each node drops its own day files on its own schedule. **The nodes keep fourteen days regardless.**
Those cost the node's disk rather than the manager's, and they are what makes raising
`retention_days` a setting rather than a hole in the history.
It never asks a node anything, so an unreachable node cannot make a page slow — it can only make
its own mirror old. The page therefore names every
node and how old its mirror is **before** the records, because a node that
stopped answering renders an empty table that otherwise reads as calm. Log text
is written by whoever made the request and is escaped as text, never as markup.

##### Sizing the traffic table

The numbers below were measured, not estimated, on a management host at the
reference size — 2 vCPU, 4 GiB, PostgreSQL with stock `shared_buffers` of
128 MB, the interface's services running alongside. A throwaway cluster on
the platform volume took the real migrations, was filled through the collector's
own `COPY` path with realistic cardinality (twenty hostnames, three hundred
paths, ten proxies, weighted methods and status codes, seven days of
time-ordered records as the collector writes them), and was read through the
page's own query. Three checkpoints, `analyze` before each:

| Rows | Table | Indexes | Per row | Newest 500 | Substring, one word | Substring, two words | Status 5xx | One day | One cluster, one day |
|---|---|---|---|---|---|---|---|---|---|
| 1 M | 230 MiB | 161 MiB | 411 B | 3 ms | 3 ms | 10 ms | 3 ms | 2 ms | 2 ms |
| 10 M | 2 299 MiB | 1 678 MiB | 417 B | 3 ms | 4 ms | 11 ms | 4 ms | 2 ms | 3 ms |
| 30 M | 6 897 MiB | 4 562 MiB | 401 B | 3 ms | 3 ms | 13 ms | 4 ms | 2 ms | 2 ms |

**Plan on 410 bytes per record, indexes included**, and on the page staying
fast: every query form the interface issues answered in about ten milliseconds
or less at thirty million rows, with the trigram indexes carrying the
substring searches. The write side is not the limit either — the collector's
path sustained about 30 000 records per second throughout the load, flat with
table size, and a run imports a minute's worth of traffic.

So the disk a retention window needs is `records per day × retention_days ×
410 bytes`, plus the collector's day files in staging for the same days (one
more, the replay margin), plus WAL. At the default seven days that is close to **3 GB per
million records a day**. A pair of nodes serving ten thousand requests a day
uses tens of megabytes; an installation nearing a million a day should have that
volume sized for it and the 85 % backup warning ([user manual](#what-the-dump-does)) heeded. The number that grows
without the administrator's say-so is this one, which is why the database sits
on the platform volume ([The database](#the-database)) rather than on the root filesystem.

#### The worker and the poller

`install/platform/07-platform-services` installs both, each as its own operating
system account. That separation is the reason the interface can be safe at all:
a single application user would have made a web intrusion equivalent to deploy
rights.

| Identity | May | May not |
|---|---|---|
| web | authenticate, audit, queue a strictly validated job | no sudo rule, no management group, no key, cannot claim a job |
| worker | call the engine's exact helpers, claim and complete jobs | read key files, run DDL |
| poller | run exact read-only metadata helpers, write the status, inventory and history caches | read private trees directly, write a job, call any write operation |

##### The poller

It never reaches a node itself. The engine's configuration, the status account's
key and the published release tree are all outside this account's reach by
design, so the poller runs the same privileged helper the command line runs,
through exact sudoers rules:

```
<poller> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-status-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-inventory-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-readings-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cluster-list-helper ""
```

Status and inventory reach the nodes. `haprion-readings-helper` answers the six
readings that touch only the management host - versions, backup archives,
certificates, the network description, the cluster settings and the stored
objects - in one call, by running their own helpers, so a pass is one sudo call
rather than six lines in the host's journal.

For the polling interval and refresh behaviour, see
[Jobs and status freshness](#jobs-and-status-freshness).

The configuration file is written by `01-platform-prepare` **only when it is
absent**, so an edit here survives every later release. Changing the value takes
effect when the poller is restarted; it reads its configuration once, at start.

**A rule under `/etc/sudoers.d/` does not travel with a release.** Adding a helper here means
installing its line separately, `visudo`-checked; a release that carries a helper nobody may run
fails at the first call with sudo's refusal in the diagnostics rather than at install time.

The rule is exact because the helper **takes no arguments at all** — the cluster
arrives as a bounded JSON request on one line of stdin. `PRIVILEGE.md` forbids wildcards in
sudoers argument matching, and without the no-argument form a rule naming a
cluster would need one. The helpers read their target inside the boundary. In
particular, inventory reads the exact commit named by the published RELEASE
stamp rather than the repository work tree, so an unpublished change cannot be
presented as live. The list helper reads saved commit metadata — version number,
timestamp and comment — and no file content at all. The backup helper reads
directory metadata under the state backup root and never opens an archive,
which is what lets an account that must not read password hashes and private
SSH keys still report that a backup exists. The certificate helper reports
metadata about the distribution root, and about which certificates certbot is
renewing on this host; private key material never reaches its output, because
what it parses is the leaf certificate alone. The network helper reads one
cluster's `managed/network.yaml` — a file whose directory is group-readable by
the engine's own group and by nobody else, which is why the interface cannot
simply open it — and reports the three address tables plus which of the two
possible sources they came from. None takes a lock, so these
reads stay answerable while a deploy runs.

`haprion-list` itself does not use that helper: a person running it can already
read the cluster repository, so the command reads it directly and requiring
`sudo` for machine-readable output would be privilege for formatting. Both paths
build their result with the same function, so the two cannot come to describe
the same history differently.

The request itself is built by the engine's own code, not by a copy of it in the
interface. Two constructions of the same request are two things to keep in step,
and each looks correct on its own — which is the hardest kind of divergence to
find.

Results go to `cluster_status`, `cluster_inventory` and `cluster_history`, each
with one row per cluster, and every page shows how old the answer it uses is. `observed_at` is
set by the database — by default on insert and by trigger on update — and the
poller holds no `update` on that column: a poller that could write it could
report a cluster it never reached as freshly observed.

##### The sandbox, and the three ways it failed quietly

The poller's unit is hardened like the others, with three deliberate exceptions
that are written in the file with their reasons: `NoNewPrivileges=no`, because
sudo is setuid and the whole point of this service is to run one helper through
it; a capability set that permits changing uid, for the same reason; and network
address families, because the helper reaches nodes from inside this sandbox.

`ProtectProc=invisible` hides the poller's own process from the root sudo runs as, since the
bounding set withholds `CAP_SYS_PTRACE`, and sudo-rs then warns on every call that it *could not get
parent process starting time* - the parent's start time is what it ties a cached password to, and
the rules are NOPASSWD. The poller and worker units drop that one exact line with
`LogFilterPatterns=`; everything else sudo logs, refusals included, reaches the journal as before.

One more is worth stating separately, because it was found by running it rather
than by reasoning about it. The status identity's key is root-owned and lives
under `/root`, so the unit needs a hole in `ProtectHome` — and:

- `ProtectHome=yes` **masks** a `BindReadOnlyPaths` under `/root`. The file
  stays invisible and the service starts perfectly. `ProtectHome=tmpfs` is what
  works, because the bind then lands on top of the empty filesystem.
- A bind mount written with a leading dash is *optional*, and systemd skips it
  in silence when it cannot be satisfied. The service starts, and every cluster
  reports as unreachable — a failure that reads as a broken environment rather
  than as a missing file. The dash is deliberately not used.
- Both of those present identically: SSH exits 255 in under a tenth of a second
  and every node is `ssh_unreachable`. If that is what the cache shows, run the
  helper by hand outside the unit before suspecting the nodes:

```bash
printf '{"schema_version":1,"operation":"status","cluster":"<id>",'\
'"request_id":"'"$(uuidgen)"'","parameters":{}}' \
  | sudo -u <poller> sudo -n /opt/haprion/current/bin/haprion-status-helper
```

If that answers `done`, the sandbox is the problem and not the environment.

**One poller, enforced by the database.** It holds a session-scoped advisory
lock for its whole life; a second one finds the lock taken and exits rather than
doubling the load on every node. The lock is released by the server when the
connection dies, including when the process is killed without cleanup — which is
exactly the case a lock file gets wrong.

##### What the worker may run

Thirteen helpers, each with no arguments, in `/etc/sudoers.d/<worker>`:

```
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-deploy-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-deploy-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-revert-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-changes-publish-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-issue-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-publish-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-target-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-dns-profile-apply-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-delete-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-ndes-profile-apply-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-scep-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-import-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-request-helper ""
```

The last nine are the certificate jobs ([Issuing a certificate](#issuing-a-certificate), [The DNS profile key pair](#the-dns-profile-key-pair), [Deleting a certificate](#deleting-a-certificate), [Importing a certificate](#importing-a-certificate)): they belong to no cluster, and
the queue runs one of them at a time. `cert-delete` is the only rule in the file that removes
key material; [Deleting a certificate](#deleting-a-certificate) says what bounds it. The receiver helper ([Registering a receiver](#registering-a-receiver)), which makes accounts and
edits sshd's and nginx's own configuration, is deliberately not in this file: it is reached over
a socket instead, for the reason given under *The worker's way to the receiver helper*.

Publishing is in that list because the interface is where those decisions are made: an editor that can only save a draft is an editor whose work has to be
finished somewhere else, and asking somebody to leave the screen and log in to a shell to complete
a change is how a change gets left unfinished. Publishing still writes nothing to a node — that is
deploy, a separate helper and a separate decision.

**`07-platform-services` installs this file**, `visudo`-checked. A file installed by hand falls
behind the helpers a release adds, and the first use of a new one meets sudo's refusal; rerun the
step after a release that names a new helper.

##### The web service, and why it has no sudoers rule at all

The web service asks the nodes exactly one thing: try this health check. Nothing
else it does reaches outside the database.

That one thing needs root, because the probe identity's key is root-owned — no
application account may hold a key that reaches a node. The obvious way to grant
it would be a sudoers rule, one exact no-argument helper, the way the poller's
seven are granted. **That does not work here, and it is worth knowing why before
somebody writes the rule again.**

The web unit carries `NoNewPrivileges=yes`, an empty `CapabilityBoundingSet=`
and `RestrictSUIDSGID=yes`. Under `NoNewPrivileges` the kernel ignores the setuid
bit, so `sudo` fails *before it reads `/etc/sudoers.d/`* — it fails however the
rule is written, and the rule then sits on disk saying this account may become
root while granting nothing at all. The poller solves the same problem by
relaxing its own sandbox (`NoNewPrivileges=no`, a capability set that permits
changing uid); doing that to the web service would trade the one boundary most
worth keeping for a button.

So the privilege stays still and the request travels instead:

```
/run/haprion/probe.sock   root:<web> 0660, created by haprion-probe-helper.socket
haprion-probe-helper@.service  runs the helper as root, one instance per connection
```

The web service opens the socket, writes one JSON request, closes its write side,
and reads one JSON answer. The far end takes no arguments and does exactly one
thing, so reaching it is worth no more than the sudo rule would have been — and
the web account keeps a sandbox in which nothing it runs can gain privilege.

`haprion-probe` on the command line still goes through `sudo`, because a person
running it has a terminal and a `%sudo` rule. Both build the request with the
same function, so the two paths cannot come to describe the same probe
differently.

**The socket reaches the real nodes**, so it is off unless asked for: `PROBE_SOCKET=no` in the
answers file is the default, and the interface then says the probe is unavailable rather than
showing an empty result.

##### The worker's way to the receiver helper

The worker *can* `sudo` - fourteen of its helpers go that way. The receiver helper
does not, for a reason on the other side of the boundary: a helper the worker
starts inherits the worker unit's mount namespace, and that unit has
`ProtectSystem=strict` with a short `ReadWritePaths` list. Registering a
receiver writes `/etc` - `useradd` rewrites `/etc/passwd` and its neighbours
through a rename, so the whole directory has to be writable, and the helper
rewrites `/etc/ssh/sshd_config.d/` and `/etc/nginx/snippets/` besides. A
`ReadWritePaths=/etc` on the job runner would end the sandbox for every helper
in order to serve one; a rule that stays fails at the first write.

So this helper, too, sits still and the request travels:

```
/run/haprion/cert-receiver.sock    root:<worker> 0660, created by haprion-cert-receiver-helper.socket
haprion-cert-receiver-helper@.service   runs the helper as root, one instance per connection
```

The worker runs `haprion-cert-receiver-ask` from its own environment, as
itself: no arguments, the request on stdin, the answer on stdout - the same
shape every other helper is run in, so the queue, the lease and the output cap
are unchanged. The client connects to the socket, writes the request, closes its
write side and passes the answer through untouched. When nothing listens, the
answer is an envelope that says so (`dependency_unavailable`), never `unknown`;
a helper that was asked and went quiet leaves the job `unknown` (see the backup
and restore helpers below).
The helper's own stderr goes to the journal (`journalctl -u
'haprion-cert-receiver-helper@*'`), not to the job.

The service's sandbox is `ProtectSystem=yes` - `/usr`, `/boot` and `/efi`
read-only, `/etc` writable - because writing `/etc` is the job. `full` and
`strict` would both take `/etc` away, which is the failure this unit ends.
`haprion-cert-receiver` at the terminal does not go this way; root runs it
directly.

Step 07 installs the socket wherever it installs a worker. It reaches no node.

##### The way to the interface certificate

The same boundary once more, with a different caller. The helpers that issue, enroll and import
certificates run through `sudo` inside the worker's namespace, and publishing the entry marked
`interface: true` ([HTTPS and the certificate](#https-and-the-certificate)) ends in `haprion-tls install`, which writes `/etc/haprion/tls`
and a rollback directory beside it. So those helpers name the entry by ID on a socket:

```
/run/haprion/ui-tls.sock      root:<worker> 0660, created by haprion-tls-helper.socket
haprion-tls-helper@.service     runs the helper as root, one instance per connection
```

The request carries the certificate ID and nothing else; the helper reads the registry and the
material itself and refuses an entry without the mark. The socket takes one connection at a time,
and the helper takes no lock: its callers hold the publisher's lock while they wait for it. The
sandbox is `ProtectSystem=yes`, as for the receiver helper. The renewal timer and
`haprion-cert-publish` do not go this way; root runs them directly. Step 07 installs the socket
wherever it installs a worker.

##### The worker's way to the backup and restore helpers

Node backups from the interface and node restores go the same way as receivers,
for the same reason from the other direction: both read root-only state archives
under `backup_root`, a restore keeps its run and one-time key under
`/var/lib/haprion/restore`, and both reach nodes over SSH as root. A sudoed
child of the worker would inherit its read-only mount namespace.

```
/run/haprion/backup-job.sock       root:<worker> 0660, created by haprion-backup-job-helper.socket
haprion-backup-job-helper@.service      backup_run and backup_schedule, as root, one instance per connection
/run/haprion/node-restore.sock     root:<worker> 0660, created by haprion-node-restore-helper.socket
haprion-node-restore-helper@.service    node_restore_prepare, _preview, node_restore and _discard, as root
```

The worker runs `haprion-backup-job-ask` and `haprion-node-restore-ask` from its
own environment, exactly as it runs the receiver client. Two answers differ from
a helper that ran and refused. Nothing listening is an envelope that says so
(`dependency_unavailable`, `failed`): nothing ran. A helper that was asked and
then went quiet - the client's time ran out, or the connection dropped - is
**no** envelope, and the job ends `unknown`: the root service carries on without
the client and may have finished. The client's sentence is in the job's stderr
excerpt; the helper's own lines are in the journal (`journalctl -u
'haprion-node-restore-helper@*'`).

The restore service needs `AF_NETLINK` besides the usual families: `ip route
get` names the address the target will see the manager come from, which is what
the one-time key's `from=` is limited to. Activating a UI release, and
`haprion-rollback`, restart the worker, so both first pause its claims
(`haprion-drain`) and wait until no job is running - fifteen minutes at most
(`DRAIN_SECONDS`), after which they stop without switching anything and lift
the pause. A pause left behind by a killed run ends by itself five minutes after
its wait would have. Step 07 installs both sockets wherever it installs a
worker; `haprion-node-restore` and `haprion-state-backup` at the terminal do not
go this way, root runs them directly.

##### The worker's way to the node helper

Adding or removing a node writes root's `known_hosts`, the pull accounts' `authorized_keys`, the
cluster file and the collector's files - none of which a helper the worker starts through sudo may
write. Creating or removing a cluster writes those and the editing policy under `/etc/sudoers.d`,
a new repository under the configuration root, and moves directories into `.removed/`. So
`haprion-node-helper` answers both on `/run/haprion/cluster-node.sock` (root, group the
worker's account, `0660`) from `haprion-node-helper@.service`, installed by step 07; the worker's
`haprion-node-ask` carries the request there, and `haprion-node` and `haprion-cluster` from a
terminal run the helper directly as root.

##### Which clusters get polled

The clusters `clusters.yaml` lists, in its order. The poller asks
`haprion-cluster-list-helper` on every pass - through one sudoers rule, because the application
accounts cannot read the engine's configuration and must not - and keeps the answer in one row that
the pages read. A cluster created or removed from Settings is therefore polled and drawn from the
next pass on, and its colour follows its place in the file.

`clusters` in `ui.toml` is the fallback: the list before the poller has read one, and the list
while the helper cannot be read. A pass that cannot read the list polls the clusters it knew
rather than none. An empty `ui.toml` list with no readable cluster file leaves the poller nothing
to do, and it says so instead of starting.

### Verifying the installation

Work outward, and stop at the first step that fails:

1. **Configuration status** — `haprion-config-status -c alpha` reports the published version and a
   clean draft.
2. **Node status** — `haprion-status -c alpha` reaches both nodes and reports the address owner,
   the release each node runs, and whether that is the published one. This proves the status key,
   its forced command, and the node reporter.
3. **The stored objects** — `haprion-objects -c alpha` lists the proxy objects as they are written,
   at the commit the repository is on, and `--show <name>` prints one document exactly as stored;
   `--advanced <name>` prints where each line of its advanced config goes.
   Where `haprion-inventory` parses what a node is serving, this reads the source that produced it -
   so an object the generator refuses is listed with the refusal rather than left out. The listing
   also names the VIP each object is served on, worked out by the generator's own rule against the
   network description, which is what the interface lists and searches by.
4. **A converged deploy** — `haprion-deploy -c alpha` with nodes already current should skip both
   nodes and change nothing. A run that correctly does nothing is a real test. Step 2 should
   already have said the cluster was converged; if the two disagree, believe neither and find out
   why before deploying anything.
5. **A deploy that does something** — publish a harmless change and deploy it. Confirm the non-owner
   is deployed first, the owner last, and that the address does not move.
6. **The negative tests** in [`PRIVILEGE.md`](PRIVILEGE.md), run as the real installed identities
   rather than through mocks.

Do the last two on a cluster that carries no traffic if you have one.

### What is still missing

This guide is honest about its gaps rather than complete on paper:

- **Certificate renewal** is deliberately out of scope and belongs to the ACME client:
  certificates issued through Certbot renew on Certbot's own timer, and those enrolled from a
  Microsoft CA over NDES/SCEP renew through the same daily run. Issuance, import and
  distribution are described in the [user manual](#certificates).
- **A rebuild from this repository alone** has not been verified end to end; that is the last
  step before 1.0.

The acceptance criterion for closing them is mechanical: a new management host and a new pair of nodes, with names of your own choosing, built
from this repository alone by someone who has never seen the maintainer's environment.
