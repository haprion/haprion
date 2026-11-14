# Installing Haprion

This guide installs Haprion for the first time: one manager with the web interface, and the HAProxy nodes it
looks after. When it is done, you continue in the web interface, which walks you through your first cluster.

- The [quickstart](quickstart.md) is the same installation in short.
- The [user manual](user-manual.md) covers configuration, daily use and maintenance.

## Requirements

| Machine | How many | Operating system | Size to start from |
|---|---|---|---|
| Manager | one | Ubuntu 26.04 or Debian 13, amd64 | 2 vCPU, 4 GB memory |
| HAProxy node | one to eight per cluster, two for failover | Ubuntu 26.04 or Debian 13, amd64 | 1 vCPU, 1 GB memory; 2 GB with the WAF |

With thousands of proxies the nodes need more memory: see [Size by number of proxies](#size-by-number-of-proxies).

Only these two distributions are supported; `haprion-setup` refuses any other. You do not need to install
anything else first. The packages and the setup bring the rest: Python, nginx, PostgreSQL, HAProxy, keepalived
and dnsdist.

- **Internet access while installing and upgrading.** The machines fetch packages from Haprion's repository, from
  HAProxy's (its 3.4 branch, newer than the distributions'), from PowerDNS's (dnsdist) and, on Debian 13, from the
  PostgreSQL project's. Which addresses that is, and what the manager reaches while it runs, is under
  [What the machines must reach](#what-the-machines-must-reach).
- **The manager** needs a DNS name that points to it, and ports 80 and 443 free for nginx.
- **The nodes of a cluster** must share one network segment. keepalived moves the virtual address (the VIP)
  between them with VRRP. The manager reaches each node over SSH.
- **PostgreSQL.** The setup installs PostgreSQL 18 when the host has no PostgreSQL cluster. A server that already runs
  version 16 or newer is kept and used. A cluster that is stopped, or is a standby, stops the setup: start or promote
  it first, so a second version is never installed beside it.
- How much traffic one vCPU handles, with and without the WAF, is under *Size* in
  [the manual's part on the nodes](user-manual.md#part-2--the-nodes).

### Size by number of proxies

The sizes above hold up to 2 500 proxies in a cluster. Past that the nodes need more memory. On every reload
HAProxy reads the whole configuration while the old process still serves, so for a moment a node holds it twice.

| Proxies in one cluster | Manager | Each node, simple proxies | Each node, large proxies |
|---|---|---|---|
| up to 2 500 | 2 vCPU, 4 GB | 1 vCPU, 1 GB | 1 vCPU, 1 GB |
| up to 5 000 | 2 vCPU, 4 GB | 1 vCPU, 1 GB | 1 vCPU, 2 GB |
| up to 10 000 | 2 vCPU, 4 GB | 1 vCPU, 2 GB | 1 vCPU, 3 GB |

- A simple proxy has two host names, three routes and three servers. A large one has four host names, six routes
  and ten servers.
- More vCPUs do not make it faster. The manager checks and publishes one step at a time, and HAProxy reads its
  configuration on one core. Memory is what grows.
- How long it takes with 10 000 large proxies: the first `haprion-objects apply` about eight minutes, a publish
  from the interface about 80 seconds, and a deploy about five minutes, of which each node's reload is about a
  minute and a half. With 10 000 simple proxies: under three minutes, under 40 seconds and under a minute.
- Each size above the smallest leaves room. A node one size smaller also managed the row, but with almost all of its memory in use.
- The sizes were measured with one cluster and without the WAF.

### What the machines must reach

Behind a firewall that lets out only what it names, open these. All of them are HTTPS on port 443, except SSH.

| From | To | When |
|---|---|---|
| manager and nodes | `haprion.github.io` | installing and upgrading: Haprion's packages |
| manager and nodes | the distribution's own mirrors | installing and upgrading |
| manager and nodes | `ppa.launchpadcontent.net` on Ubuntu, `haproxy.debian.net` on Debian | installing and upgrading: HAProxy 3.4 |
| manager and nodes | `repo.powerdns.com` | installing and upgrading: dnsdist |
| manager on Debian 13 | `apt.postgresql.org` | installing and upgrading: PostgreSQL 18 |
| manager | each node, SSH | always: the manager asks for deploys, reads status and logs, and takes backups |
| nodes | the manager, SSH | always: each node fetches its releases and certificates |
| API callers | the manager, HTTPS | when you use them: a script or a host that blocks an address from outside, such as fail2ban beside an application ([user manual](user-manual.md#the-api)) |
| manager | `acme-v02.api.letsencrypt.org` | issuing and renewing ACME certificates |
| manager | the DNS provider's API, such as `api.cloudflare.com` | issuing and renewing ACME certificates |
| manager | `location.ipfire.org` | once a day, for countries in access rules; without it the database ages but keeps working |
| manager | `api.github.com` | once a day, only when *Update check* is on |
| manager | your NDES server, identity provider and certificate receivers | when you use them |
| nodes | your log receivers | when you send the traffic log or syslog on |

Haprion itself reaches nothing else; the system's own DNS and time servers are not listed. Without the repositories, install from a release's files instead, as under
[The packages](#the-packages); upgrades then come the same way.

**Disk space on the nodes.** The traffic log is what fills a node's disk. Each request takes about 800 bytes, and
a node keeps 14 days. Each external log receiver can also queue up to `disk_mib` on disk (1 GiB by default, at
most four receivers) while it is unreachable. Plan for about

```text
requests per day × 800 bytes × 14  +  1 GiB per receiver  +  room for the system
```

One million requests a day is about 10 GiB. The log cannot fill the disk on its own: it may use at most a quarter
of the filesystem, an hour that uses up its share stops logging until the next hour, and the oldest days are
removed early when space runs short. Each of these writes a warning to the system log. The manager keeps the same
share of its own disk for its copy of the log
([the manual](user-manual.md#keeping-jobs-sessions-and-metric-history-bounded)).

**Who should reach the interface.** The web interface changes what your clusters serve. Put it on a network only
its administrators can reach – a management network, or a VPN into one – and not on the network your sites face.
Haprion limits sign-in attempts, but which networks can reach it at all is up to the firewall in front of it.

## The packages

Haprion is installed with apt from its own repository, `https://haprion.github.io/haprion/`. Add the repository
once on the manager and on every node: the key first, then the source. (If the machine has no curl:
`sudo apt install curl`.)

On **Ubuntu 26.04**:

```bash
sudo curl -fsSLo /usr/share/keyrings/haprion-archive-keyring.asc \
  https://haprion.github.io/haprion/haprion-archive-keyring.asc
sudo tee /etc/apt/sources.list.d/haprion.sources >/dev/null <<'EOF'
Types: deb
URIs: https://haprion.github.io/haprion/
Suites: ubuntu26.04
Components: main
Signed-By: /usr/share/keyrings/haprion-archive-keyring.asc
EOF
sudo apt update
```

On **Debian 13**:

```bash
sudo curl -fsSLo /usr/share/keyrings/haprion-archive-keyring.asc \
  https://haprion.github.io/haprion/haprion-archive-keyring.asc
sudo tee /etc/apt/sources.list.d/haprion.sources >/dev/null <<'EOF'
Types: deb
URIs: https://haprion.github.io/haprion/
Suites: deb13
Components: main
Signed-By: /usr/share/keyrings/haprion-archive-keyring.asc
EOF
sudo apt update
```

The key's fingerprint is `927422B0C5F005E0B710E4FFF30F5055A9FC0A53`; check it with
`gpg --show-keys /usr/share/keyrings/haprion-archive-keyring.asc`. Because of `Signed-By`, apt trusts this key
for this repository only. After the first install the key file belongs to the `haprion-archive-keyring` package,
so a new signing key arrives with `apt upgrade` before the old one expires.

**Without access to the repository**, download the packages from the
[latest release](https://github.com/haprion/haprion/releases/latest), check them against its `SHA256SUMS`, and
install them together with `sudo apt install ./<file> ...`. For the web interface and certbot, take the files
ending in `ubuntu26.04_amd64.deb` or `deb13_amd64.deb`. To build the packages yourself, see
[Building the packages](#building-the-packages).

| Package | Installed on | What it contains |
|---|---|---|
| `haprion-ui` | the manager | the web interface, `haprion-setup` and the installation steps; it pulls in the manager's other packages |
| `haprion-cli` | the manager | the command-line engine, the commands and their sudo rules, and a copy of the node package |
| `haprion-certbot` | the manager | certbot and the DNS plugins the interface offers |
| `haprion-scep` | the manager | the SCEP client for certificates from Microsoft AD CS over NDES: Certmonger's programs and their source, from the distribution's own package |
| `haprion-crs` | the manager | the WAF rules; each release carries them on to the nodes |
| `haprion-node` | each node | the node's scripts and its preparation step |
| `haprion-coraza-spoa` | the manager and the nodes | the WAF engine; the CLI release carries a copy, so a node restored onto a new VM gets it back |
| `haprion-archive-keyring` | the manager and the nodes | the key the repository is signed with |

### Updating

`sudo apt update && sudo apt upgrade` is the whole update. Update the manager first. Then update the nodes one at a
time, starting with a node that does not hold the VIP: a new WAF engine restarts the engine on that node. The web
interface's package updates the running interface by itself.

Publish a cluster again only once its nodes are updated and prepared: `sudo apt upgrade` on each node, then
`sudo haprion-node-prepare` on it when the update asks for it. A release that logs the traffic stream to HAProxy's
socket is not sent to a node still on the old package. The deploy stops before it touches any node and names them
(`traffic_stream_not_prepared`).

**What is released when.** A version with new functions (1.2, 1.3) is made by hand. A patch version (1.1.1,
1.1.2) never carries a new function. One made by hand fixes bugs; one made automatically carries only updated
dependencies and WAF engine:

- a fix for a known vulnerability in a dependency or the WAF engine is released a day after it is merged at the
  earliest, once the release's own tests have passed, which takes some hours more
- other dependency and WAF updates are released together on the first of the month, when there are any

Nothing is installed by itself; an update is `sudo apt upgrade` when you choose. The WAF engine and its rules
are in the repository as soon as an update of them is merged, before the release that names it. With the
[update check](user-manual.md#features-and-advanced-configuration) on, the header says when a newer release exists.

A new HAProxy is the exception. The manager checks each configuration with its own HAProxy before a node gets it,
so the manager must not be the newer of the two. When `apt list --upgradable` on the manager shows `haproxy`, update
the nodes first and the manager last ([Keeping HAProxy current](user-manual.md#keeping-haproxy-current)).

An installation on Haprion 0.99.10 or older is updated to 0.99.13 first: later releases refuse an older database
schema before they change anything. If `sudo apt upgrade` already refused it, install the 0.99.13 packages from the
repository (`apt list -a haprion-ui` shows their versions) or, for an installation made from files, with
`sudo dpkg -i` on the files of the [GitHub release](https://github.com/haprion/haprion/releases/tag/v0.99.13), then
upgrade again. `sudo dpkg --configure -a` is not needed:

```bash
sudo apt install --allow-downgrades haprion-cli=<version> haprion-ui=<version>
sudo apt upgrade
```

Do not add the repository to unattended-upgrades. An update is something you choose the moment for.

### Removing

Removing the packages is not enough. The installation made accounts, a database, services, an nginx site and
directories that `apt purge` does not touch. A command removes them first. Run it on each node, then on the manager.

First see what it would remove. This changes nothing:

```bash
sudo haprion-node-prepare --remove    # on a node
sudo haprion-setup --remove           # on the manager
```

Then remove it, and purge the packages the last lines name:

```bash
sudo haprion-node-prepare --remove --yes
sudo apt purge haprion-node haprion-coraza-spoa haprion-archive-keyring
```

```bash
sudo haprion-setup --remove --yes
sudo apt purge haprion-ui haprion-certbot haprion-scep haprion-cli haprion-coraza-spoa haprion-crs haprion-archive-keyring
```

Remove the repository's source as well: the file `haprion.sources` under `/etc/apt/sources.list.d/`.

On the manager it removes the services, the database and its roles, the nginx site, the accounts, the keys, the
Let's Encrypt certificates Haprion issued, and every directory the runtime policy names – including the
configuration repositories and the node backups. On a node it removes the accounts and their keys, the sudo rules,
HAProxy's releases and certificates, keepalived's configuration, the rsyslog rules and sshd's listen address, and it
stops HAProxy, keepalived and dnsdist.

It keeps PostgreSQL, nginx, HAProxy, keepalived and dnsdist and their apt sources, since something else may use
them. The last lines say how to remove those as well.

Before it removes anything, it saves the certificate receivers' public keys, the certificate registry and the
runtime policy under `/root/haprion-removed-<time>/`. Register a receiver again with its saved key, and it fetches
as before without anything done on the receiver. The policy is there to read what you set by hand, such as NDES.

## 1. Choose the answers, or keep the defaults

You can install without an answers file. The defaults are: the fixed service accounts, directories under
`/srv/haprion` and `/srv/certdist`, a local PostgreSQL database, the machine's own name (`hostname -f`) for the
web interface, and no cluster yet. Clusters and nodes are created in the web interface afterwards.

To change a default, copy the example and keep only the lines you change. The example comes with the
`haprion-ui` package, so install the package first; step 2 then runs the setup with your file:

```bash
sudo apt install haprion-ui
cp /usr/share/haprion-ui/install/answers.example.env answers.env
$EDITOR answers.env
```

Every setting and its default is described in [install/answers.example.env](../install/answers.example.env). A line
that sets a value to nothing turns that part off – for example, no node backups or no certificate deployment.

## 2. Install the manager

```bash
sudo apt install haprion-ui
sudo haprion-setup [--answers answers.env]
```

`--release <release-id>` names the web interface's release to activate. Without it the setup uses the release that
is active, or the one the package unpacked. When several are unpacked and none is active, it asks you to name one.

`haprion-ui` brings the CLI, certbot, the WAF engine and its rules with it. You need no source tree on the manager.

`haprion-setup` first checks what it can before it changes anything: the distribution, the commands it needs, a
PostgreSQL that is too old, that the server name points to this machine, and that ports 80 and 443 are free. It
lists every problem it finds and stops. A clock that is not synchronised is only a warning.

Then it runs the installation steps. If a step fails, it tells you what went wrong, why, what to do, and where the
full output is (`/var/log/haprion/setup.log`). Every step can safely run again, so the same command continues an
installation that stopped.

Last, it creates the first administrator, `admin`, and asks for its password. Without a terminal it ends with the
command to run instead.

The commands at the terminal read the cluster configuration as the account that runs them, and the configuration
group, `haprion`, reads it. Add your own account to the group once; it takes effect at your next login:

```bash
sudo usermod -a -G haprion <your account>
```

## 3. Install the nodes

On each node, with the repository added:

```bash
sudo apt install haprion-node
```

The WAF engine comes with it. The package creates the node's accounts and keys, and prints the node's *block* –
one line starting with `haprion-node-v2:` – and its host key fingerprint. You paste the block into the web
interface to add the node:

- for your first cluster, the Dashboard's *Set up your first cluster* walks you through it;
- later, *Settings* → *Nodes & clusters*: *Create cluster* for a new cluster, or *Add a node* on an existing one;
- at the terminal, `haprion-cluster add` or `haprion-node add`, with the block on stdin.

`sudo haprion-node-key` prints the block again. While its one-time key is unused and valid it is the same block, and
an upgrade of the package keeps it. `sudo haprion-node-key --again` makes a new one-time key, and an earlier block
stops working.
A node that was prepared but never joined, with its key used up or expired, says so and asks for
`--again`. The node's name is its host name, which must be lowercase letters, digits and hyphens,
starting with a letter; otherwise `haprion-node-key` says to rename the host first.
How a node joins is under [How a node joins](#how-a-node-joins), and preparing one without the web interface under
[A node prepared by hand](#a-node-prepared-by-hand).

A node accepts the manager's keys only from the manager's address. If the manager moves to another address, run
`sudo haprion-node-prepare --manager <new name or address>` on each node.

A node given another address keeps sshd on the old one until `sudo haprion-node-prepare` runs on it: every run
moves sshd to an address the node has. Run it from the node's console before *Change host* or `haprion-node pull-keys`.

A rotated manager key, or one added after the join, reaches a joined node only by hand: on the node,
`sudo haprion-node-prepare --key <purpose>="<public key>"`, where the purpose is `deploy`, `cert_deploy`,
`server_state`, `status`, `probe`, `backup` or `traffic_log`. It replaces that one key with the binding the
join gives it, leaves the others, and refuses a node that has not joined: one a manager joined, or one prepared
by hand with step 4, counts as joined. It checks that the key is a real ssh-ed25519 key and prints its fingerprint, to compare with `ssh-keygen -lf` on the manager's `.pub` file.

## 4. Sign in

Open `https://<server name>` and sign in as `admin`. Until you install a certificate of your own, nginx uses a
self-signed one, so the browser asks you to accept it.

History and metrics are kept within limits on every installation: `haprion-retention` prepares the coming days'
tables and removes old ones. `haprion-setup` installs it.

## Optional components

`haprion-setup` installs all of these except the SCEP client. Each is also a step of its own, which you can run
again after changing the answers. Run them from `/usr/share/haprion-ui/install/platform/`. Where a step takes a
source tree, give it `/usr/share/haprion-ui`.

| Component | Step |
|---|---|
| Database backups of the interface | `sudo ./06-platform-backup /path/to/answers.env` |
| Traffic log collection | `sudo ./13-platform-traffic-collector /path/to/answers.env` |
| Certbot, its DNS plugins and the hook that publishes a renewed certificate | `sudo ./14-platform-certbot /path/to/answers.env /usr/share/haprion-ui` |
| The keys that protect DNS provider and NDES credentials | `sudo ./15-platform-dns-keys /path/to/answers.env /usr/share/haprion-ui` |
| Sign-in through an OpenID Connect provider | `sudo ./17-platform-oidc /path/to/answers.env /usr/share/haprion-ui` |

Step 14 uses the release the `haprion-certbot` package carries. With `UV_BIN=/path/to/uv` it builds one from the
lock file instead.

The installation sets up issuing through a DNS provider (DNS-01). It does not set up HTTP-01, where Let's Encrypt
fetches a file over plain HTTP, and the interface shows that method greyed until you do. It takes three things,
done once: a `webroot` under `acme:` in the runtime policy, followed by step 07 again; an nginx `server` on port 80
that serves only `/.well-known/acme-challenge/` from that directory; and a rule in each cluster that sends that path
to the manager. [ACME configuration and challenge routing](user-manual.md#acme-configuration-and-challenge-routing)
shows all three.

Step 16 installs the SCEP client the `haprion-scep` package carries, for certificates from Microsoft AD CS over
NDES. The setup runs it with the bundle and digest the package names in `/usr/lib/haprion/scep/PAYLOAD`:

```bash
. /usr/lib/haprion/scep/PAYLOAD
sudo ./16-platform-scep "/usr/lib/haprion/scep/$BUNDLE" "$BUNDLE_SHA256" --no-satisfy
```

[install/platform/README.md](../install/platform/README.md) describes each step's inputs and what to set up
afterwards.

## What the nodes run

Installing the packages starts nothing on a node. A service starts when a published configuration needs it, and
stops when it no longer does.

### The WAF engine

The engine runs when a release contains WAF rules. A release with rules is refused on a node that does not have
the engine. The interface offers the WAF on an object only when every node in its cluster has the engine.

The engine starts before HAProxy, and counts as started only when it is listening. It logs each rule match to a
journal of its own, `haprion-waf`, because a match line is longer than the system journal keeps whole. That
journal keeps 14 days; the settings are in `/usr/lib/systemd/journald@haprion-waf.conf.d/`, and you override them
under `/etc`. The traffic log collector reads it.

The release directory `/etc/haproxy/releases` is closed to everyone but root. `04-node-prepare` gives the engine a
group, `_haprion-waf`, that may pass through it and nothing else.

*Details:* the rules reach the engine as `/etc/haproxy/waf`, a link into the release like `maps`. The engine runs
as a dynamic user; its group comes from the drop-in `/etc/systemd/system/coraza-spoa.service.d/haprion.conf`, and
`/etc/tmpfiles.d/haprion-waf-engine.conf` lets that group through the release directory without listing it.
`/etc/tmpfiles.d/haprion-waf.conf` lets the traffic log's read group read the `haprion-waf` journal and nothing
else in the journal.

### DNS listeners

A DNS listener (UDP and TCP, usually port 53) is served by dnsdist, not by HAProxy. dnsdist comes from PowerDNS's
repository, version 2.1. `04-node-prepare` installs it on every node; on the manager it is installed only to check
a listener's configuration before it is published, and never runs. The repository's key ships with Haprion and is
never downloaded, and a pin takes only dnsdist from that repository. The HAProxy repository is pinned the same way.

dnsdist starts when a release has a DNS listener, restarts when the listener changes, and stops when the
listener is removed. A release with a listener is refused on a node that has not been prepared for one, and so is
a configuration dnsdist only warns about. Its counters are on `127.0.0.1:9521`, which is where the interface's DNS
cards get their numbers; the cluster's Prometheus exporter reads them too, on the node's own address.

*Details:* the source is `/etc/apt/sources.list.d/pdns.list`, the pin `/etc/apt/preferences.d/dnsdist-21`, and
the key ships in `install/apt-keys/`. The hosts need to reach `repo.powerdns.com` over HTTPS. On a node, the drop-in
`/etc/systemd/system/dnsdist.service.d/haprion.conf` points dnsdist at `/etc/haproxy/dns/dnsdist.conf` (a link into
the release) and lets it start only when that file exists. dnsdist runs as `_dnsdist` with the member-less group
`_haprion-dns`, which may pass through the release directory (`/etc/tmpfiles.d/haprion-dns.conf`). The counters
need no key; dnsdist's API still requires one, and no console is configured.

### Syslog listeners

A syslog listener (UDP) is served by the kernel's IPVS through keepalived, so your log receivers see the real
sender of each message. Each release carries the cluster's IPVS table, and the deploy installs it as
`/etc/keepalived/ipvs.conf`.

For that file to take effect, `keepalived.conf` must include it at the top level, outside every block:

```text
include /etc/keepalived/ipvs.conf
```

A `keepalived.conf` written by Haprion – for a cluster created in the interface – already has this line
([keepalived on the nodes](user-manual.md#keepalived-on-the-nodes)). If you wrote `keepalived.conf` yourself, add
the line after the first deploy has installed the file, one node at a time, and test with
`keepalived --config-test -f /etc/keepalived/keepalived.conf` before reloading. A release with a syslog listener is
refused on a node without the include, and `04-node-prepare` warns while it is missing.

*Details:* every release carries `keepalived/ipvs.conf`, empty on a cluster without a syslog listener. The deploy
runs `keepalived --config-test` and reloads only when the test passes, putting the previous file back otherwise.
`04-node-prepare` installs `ipvsadm`, which the node status reads the counters with, and masks `ipvsadm.service`:
Debian's package would restore and clear the IPVS table at boot and shutdown, which is keepalived's job. The nodes
need no `ip_forward`, because the receivers never answer through them.

### Sending the traffic log to other receivers

A cluster can send its traffic log to external receivers. Each node's rsyslog sends it, with a queue on disk per
receiver, so nothing is lost while a receiver is down – up to the cluster's `disk_mib` per receiver. The deploy
checks the configuration with `rsyslogd -N1` before using it, restarts rsyslog only when something changed, and
puts the previous configuration back if rsyslog refuses the new one.

HAProxy's log lines wait in a socket that systemd holds while rsyslog restarts, so a restart loses no lines
([HAProxy and keepalived baseline](user-manual.md#haproxy-and-keepalived-baseline)).

*Details:* `04-node-prepare` installs `/etc/rsyslog.d/47-haprion-forward.conf`. It loads rsyslog's `impstats`, which
writes each receiver's queue once a minute to `/var/log/haprion/rsyslog-stats.json` (rotated daily by
`/etc/logrotate.d/haprion-rsyslog-stats`), and includes `/etc/rsyslog.d/haprion/forward.conf` when that file is
there. The deploy copies that file from the release into `/etc/rsyslog.d/haprion/`, because rsyslog's AppArmor
profile cannot read the releases under `/etc/haproxy`. The queues are in rsyslog's work directory
(`/var/spool/rsyslog` on Ubuntu). Receivers over TLS need `rsyslog-gnutls`, which the node package depends on. A
release that names receivers is refused on a node without the include. A site that already loads `impstats` itself
gets a refusal from `rsyslogd -N1` when `04-node-prepare` runs. Two units hold HAProxy's log sockets in its chroot
across rsyslog restarts: `haprion-haproxy-log.socket` holds `dev/log` for the classic log (when `49-haproxy.conf`
listens there) and `haprion-traffic-log.socket` holds `dev/haprion-traffic` for the structured traffic stream,
writable by the `haproxy` account alone (mode `0660`). `net.unix.max_dgram_qlen` is set in
`/etc/sysctl.d/60-haproxy.conf`; taking a socket over restarts rsyslog once. `47-haprion-forward.conf` binds an
rsyslog input and ruleset to the traffic socket and marks what arrives there as HAProxy's; the forwarding rule and
`48-haprion-traffic.conf` act only on a marked line, so the same tag written to `/dev/log` by another local account
is dropped. Step 4 writes `48-haprion-traffic.conf` whenever the traffic log is on: when the answers carry the
collector's key, and when the rule is already there, as on a node prepared again. A route turned off with
`haprion-traffic-log-enable --disable` stays off. rsyslogd's AppArmor profile gets a rule for the traffic socket in
`/etc/apparmor.d/rsyslog.d/haprion-haproxy-log`. HAProxy logs the stream to the socket's full path; for a HAProxy
chrooted in `/var/lib/haproxy`, step 4 links the same path inside the chroot to the socket. A publish that logs the
stream refuses a core that chroots HAProxy elsewhere or runs it as an account that may not write the socket
(`traffic_log_unreachable`). The manager's deploy refuses such a release for a node whose package is too old to
report `traffic_stream`, before anything is sent. `haprion-pull-deploy` refuses a release that logs to the traffic socket on a node
where the socket or its link is missing, or the socket is not `haproxy:haproxy` mode `0660`. The node's status
reports `traffic_stream`: whether the release logs to the socket, whether the day file's rule and the forwarding rule
each keep only marked lines, and whether the socket is held. A node that keeps only marked lines while its release
logs elsewhere drops the traffic log; *Needs attention* lists it until the cluster is published again. A node whose
release logs to the socket while its day file's rule still takes unmarked lines is listed as a warning until
`sudo haprion-node-prepare` has run on it.

## Step by step, without haprion-setup

Use these steps to install without the web interface, or to see one step's full output. `haprion-setup` runs the
same steps, in this order:

1. `01-manager-prepare`, then `platform/01-platform-prepare`, then `platform/15-platform-dns-keys`
2. `02-manager-config`, `03-manager-keys`
3. `platform/02-platform-database`, `platform/migrate`, `platform/03-verify`
4. `platform/check-compatibility --first-install`, `platform/install-ui-release`
5. `platform/04-platform-service`, `05-platform-nginx`, `07-platform-services`
6. `platform/06-platform-backup`, `11-platform-retention`, `13-platform-traffic-collector`, `17-platform-oidc`
7. `platform/14-platform-certbot`, when the `haprion-certbot` package is installed
8. `platform/16-platform-scep`, when the `haprion-scep` package is installed
9. `platform/check-compatibility`

Step 15 comes before `02-manager-config` so that the policy step 2 writes can name the keys step 15 made.

### The CLI engine alone

```bash
sudo apt install haprion-cli
```

The package checks the files it carries against their checksums, installs the release under
`/opt/haprion/releases/` and points `/opt/haprion/current` at it. The commands are in `/usr/bin`. A newer version
of the package is the whole update. More in the manual's [Part 3](user-manual.md#part-3--the-versioned-cli-release).

### The manager's configuration and keys

Run these from `/usr/share/haprion-ui/install/`, or from `install/` in a source tree of the same version when you
install without the web interface:

```bash
sudo ./01-manager-prepare answers.env
sudo ./02-manager-config answers.env
sudo ./03-manager-keys answers.env | tee keys.txt
```

The answers file is optional in every step. Steps 14, 15 and 17 take `-` in its place when a source tree follows.

- `01-manager-prepare` creates the configuration group, the directory trees, and one Git repository per cluster
  named in the answers file, with the standard layout committed. It writes no configuration and contacts no node.
- `02-manager-config` renders `clusters.yaml` and `runtime-policy.yaml` from the answers (an empty cluster file
  when no cluster is named), creates the empty certificate registry the policy names, and creates the
  validation-only certificate. The files are rendered, not edited by hand, so that what the code reads and what
  you reviewed cannot drift apart. When `BACKUP_ROOT` is set, it also installs the `haprion-state-backup@.service`
  template that the backup timer and *Back up now* start. It installs the editing policy too: `sudoedit` rules that
  let the accounts in `CONFIG_EDITORS` edit `core/haproxy.cfg` and `manual/reservations.yaml` without a root
  shell, checked by `visudo` before anything is written. With `CONFIG_EDITORS` empty, the step says it skipped
  that.
- `03-manager-keys` creates the manager's key pairs. Keep the private keys on the machine that made them.

Nodes added in the web interface need nothing from step 3's output: the manager hands the keys over when the node
joins ([how a node joins](#how-a-node-joins)). Step 3's lines are for a [node prepared by hand](#a-node-prepared-by-hand).

### How a node joins

The node's block holds a one-time key, valid for 24 hours. The manager connects with it once, as `_haprion-join`,
whose only command is `haprion-node-join`. The manager hands over its keys, the node's host key, the cluster and the
VIP. The node runs `04-node-prepare` with them: it installs the packages HAProxy and the rest need, the release
layout, the sudo rules and `node.conf`, and puts sshd on the address the manager came in on. Then the key is
removed, and the manager asks the node for its status.

Keep the block to yourself until it is used: whoever holds it can join the node to a manager. A node that names who
may log in (`AllowUsers`, `AllowGroups`) must let `_haprion-join` in. The package warns when it does not.

### Clusters named in the answers file

Clusters are normally created in the web interface. An installation can name them up front instead, in the answers
file; `02-manager-config` reads the lines once, when it first writes the cluster file:

- `CLUSTERS`: the cluster IDs, lowercase, as you will type them after `-c`.
- `NODES_<cluster>`: the nodes, as `name:management-hostname` pairs.
- `VIP_<cluster>`: the virtual address keepalived moves between the nodes.
- `NODE_PATH_<cluster>`: the subdirectory the cluster's nodes fetch from; the cluster's ID when left out.
- `CERTIFICATE_IDS_<cluster>` and `DEFAULT_CERTIFICATE_<cluster>`: the certificates the cluster references, and
  the default one.

[install/answers.example.env](../install/answers.example.env) shows each line with an example.

### A node prepared by hand

A node can be prepared without the web interface and without a join. Put `MANAGER_HOST` (the manager's name as the
node reaches it), the paths of the two fetch keys, and the lines `03-manager-keys` printed in the node's answers
file. That is one line per key, `DEPLOY_PUBKEY=...`, `STATUS_PUBKEY=...` and so on, and `MANAGER_HOST_KEY=...`.
Then run, on the node:

```bash
sudo /usr/share/haprion-node/install/04-node-prepare answers.env alpha
```

The step writes each key with `restrict` and its own forced command, and the manager's host key into root's
`known_hosts`. It prints a block that names the cluster (`haproxy-node-v1:`). Add it the same way as a block from
a joined node. Drain, maintenance and ready also need the admin socket line in the cluster's `core/haproxy.cfg`; a
cluster made in the web interface has it.

### Keepalived written by hand

For a cluster created in the web interface, the deploy writes each node's `keepalived.conf`
([keepalived on the nodes](user-manual.md#keepalived-on-the-nodes)). When a person writes it, it has to meet
[the keepalived baseline](user-manual.md#haproxy-and-keepalived-baseline):

- both nodes bind the virtual address;
- both keepalived instances are `BACKUP` with `nopreempt`;
- the `notify_` lines tell the manager who owns the address.

A mistake in these does not fail loudly. It makes deploys quietly unsafe. Start from
[`install/examples/keepalived.conf.example`](../install/examples/keepalived.conf.example). `04-node-prepare` checks
all three and says which one is missing.

### Check the installation

On the manager, as your own user, from the same directory:

```bash
./05-verify answers.env
```

It changes nothing. It checks file ownership and modes, that the manager's keys exist, that each cluster resolves,
and, the check that matters, that every node answers a status request through its own key and forced command. The
keys belong to root, so it asks for your sudo password once. Without a terminal to ask on, it reports those checks
as `SKIP`.

Every step can be run again. A failed installation continues when you fix what the step named and run it again.
Each item reports `ok`, `fixed`, `created` or `written`, so a second run shows what was already right.

### Then prove it

`05-verify` passing means the installation answers. It does not mean it works. Prove two more things, in this
order, on a cluster that carries no traffic if you have one:

1. Run `haprion-deploy -c alpha` with the nodes already current. It should skip both nodes and change nothing. A
   run that correctly does nothing tests the ordering logic for real.
2. Publish a harmless change and deploy it. Confirm the node that does not own the VIP is deployed first, the
   owner last, and that the VIP does not move.

An installation without the web interface is now complete.

### The web interface

Install the package; it unpacks its release and prints the release ID. Then, from
`/usr/share/haprion-ui/install/platform/` and with the same answers file:

```bash
sudo apt install haprion-ui
cd /usr/share/haprion-ui/install/platform
sudo ./01-platform-prepare /path/to/answers.env
sudo ./02-platform-database /path/to/answers.env
sudo ./migrate --release <release-id>
sudo ./03-verify
sudo ./check-compatibility --release <release-id> --first-install
sudo ./install-ui-release <release-id>
sudo ./04-platform-service /path/to/answers.env
sudo ./05-platform-nginx /path/to/answers.env
sudo ./07-platform-services /path/to/answers.env
sudo ./check-compatibility
```

The first activation creates the `admin` account if there is no account yet, and asks for its password. If there
was no terminal, create it afterwards:

```bash
sudo haprion-user init-admin
```

Later versions of the package update the running interface by themselves. They read no answers file, make the
accounts and directories the steps made, reinstall the units, sudo rules, sockets, timers, nginx site and certbot
deploy hook the steps installed, and leave the previous release running if anything fails. No step needs to be run again by hand after `apt upgrade`.

## Building the packages

Build from a clean, committed source tree that has passed the repository's checks, into a protected directory
outside the tree, with the `uv` version the repository is locked to. One command builds every package, in the
right order:

```bash
tools/build-release-packages --source "$(pwd)" --output-dir <out> --uv /path/to/uv
```

It fetches the pinned Go toolchain, govulncheck and the WAF engine's sources into a cache, checks each against its
checksum, and writes `SHA256SUMS` beside the packages. The web interface and certbot are built inside a container
of the distribution they are for, with rootless podman (`ubuntu26.04` or `debian13`). The SCEP client is built
from each distribution's certmonger package and its source, fetched from the distribution's archive and checked
against the digests `tools/build-scep-package.py` pins.

The WAF engine (Coraza SPOA with the OWASP Core Rule Set) is built from pinned upstream sources, and building the
same version twice gives the same bytes. Before the build, govulncheck checks the source with the pinned Go: the
build stops if the engine can reach a known vulnerability, in its modules or in Go's standard library. A
vulnerability only in code the engine never calls is reported but does not stop it. Then upstream's own tests run
– the engine's, Coraza's and the SPOE library's – and the build stops if any fails.

To build one package at a time, these are the steps the command runs:

```bash
python3 tools/build-coraza-package.py crs --source-dir <dir> --output-dir <out>
python3 tools/build-coraza-package.py coraza --source-dir <dir> --go-root <go> \
    --govulncheck <dir>/govulncheck --output-dir <out>
tools/build-keyring-package.py --source "$(pwd)" --output-dir <out>
tools/build-cli-package.py --source "$(pwd)" --output-dir <out> --uv /path/to/uv \
    --waf-engine-package <out>/haprion-coraza-spoa_<version>_amd64.deb \
    --keyring-package <out>/haprion-archive-keyring_<version>_all.deb
tools/node-package.py build --source . --output-dir <out>
tools/build-ui-package.py --source "$(pwd)" --output-dir <out> --distribution ubuntu26.04 --uv /path/to/uv
tools/build-certbot-package.py --source "$(pwd)" --output-dir <out> --distribution ubuntu26.04 --uv /path/to/uv
```

Install govulncheck with the pinned Go:
`GOBIN=<dir> <go>/bin/go install golang.org/x/vuln/cmd/govulncheck@<version>`.

### How a release reaches the repository

The workflow `.github/workflows/apt-repo.yml` publishes the repository. A release tag builds every package twice,
on two separate runners. The repository is published only when both builds – and the files already attached to the
release – are byte for byte the same.

`tools/build-apt-repo` then starts from what the site already serves, checks every index and package against the
key, adds the new packages, keeps the two newest versions of each, and signs the result with the repository's
signing subkey. Only the workflow's Pages environment holds that subkey.
