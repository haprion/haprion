# Installing Haprion

These are the steps for a first installation of the application: the CLI engine and the
optional web interface. Configuration, usage, administration and maintenance are in the
[user manual](user-manual.md).

## Requirements

On the management host, install:

- a Linux distribution with systemd and Python 3.12 or newer at `/usr/bin/python3`
- `python3-yaml` (major version 6), `python3-nacl` (major version 1) and
  `python3-psycopg` (major version 3)
- `git`, `rsync`, `openssh-client` and `sudo` supporting no-argument rules
- for the web interface: PostgreSQL 16 or newer, nginx 1.25.1 or newer and `uv`

Haprion is installed from Debian packages built from one commit:

| Package | Installed on | Carries |
|---|---|---|
| `haprion-cli` | the management host | the CLI engine, the node package of the same commit, the operators' commands and sudo rules |
| `haprion-ui` | the management host, for the web interface | the interface's release for one distribution (Ubuntu 26.04 or Debian 13) and the platform steps |
| `haprion-node` | each node | the node scripts, the block it prints at installation, and `04-node-prepare` |
| `haprion-coraza-spoa` | the management host and the nodes, for the WAF | the engine; the CLI release also carries it, so a node restored to a new VM gets it back |
| `haprion-crs` | the management host, for the WAF | the rule set; releases carry the rules to the nodes |

Keep the source tree of the same commit for the manager steps in `install/`. The steps need no
answers file: without one they use the defaults in `install/defaults.sh`. An answers file sets only
what should differ, such as `UV_BIN`, which names the uv the certbot step uses.

HAProxy nodes must already be prepared before the application can manage them. The
[node preparation instructions](user-manual.md#part-2--the-nodes) are in the manual.

**Disk on the nodes.** What grows on a node's root filesystem is the traffic log: fourteen days of
day files under `/var/log/haprion` at about 800 bytes a request, and, per external receiver, a
queue on disk under `/var/spool/rsyslog` of up to the cluster's `disk_mib` (1 GiB by default, at
most four receivers). Free space for a node is therefore about

```text
requests a day × 800 bytes × 14  +  disk_mib of every receiver  +  margin for the system
```

At one million requests a day that is about 10 GiB of day files, plus 1 GiB a receiver. A full
root filesystem stops journald and apt as well as the log, so leave the system its own margin. The
day files are also held to a space budget, checked every hour: when they hold more than a quarter
of their filesystem, or less than a tenth of it is free, the oldest finished days go before their
fourteen, each with a warning in the system log. Today's file is never removed, so a filesystem
of its own for `/var/log/haprion` is still the way to keep a flood of requests off the root.

**Who reaches the interface.** The web interface changes what the clusters serve, so it belongs
on a network only its administrators reach - a management network, or a VPN into one - and not
on the one the proxied sites face. Haprion limits sign-in attempts and refuses what it should,
but which networks can reach it at all is decided by the firewall in front of it.

## 1. Choose the answers, or keep the defaults

Without an answers file the installation uses its defaults: the fixed accounts, the places under
`/srv/haprion` and `/srv/certdist`, a local PostgreSQL database, this machine's own name
(`hostname -f`) for the web interface, and no cluster. Clusters and their nodes are created in the
interface, under *Settings* → *Create cluster*.

To choose differently, copy the example from the source tree's `install/` directory and keep the
lines you change:

```bash
cp answers.example.env answers.env
$EDITOR answers.env
```

The file and every default are described in [install/answers.example.env](../install/answers.example.env).
A line that sets a value to nothing keeps it empty, which is how an installation takes no node
backups or deploys no certificates.

**The whole manager in one command.** With both packages installed (sections 2 and 4), the steps of
sections 3 and 4 run in order with

```bash
sudo install/haprion-setup [--answers answers.env] [--release <release-id>]
```

from the source tree. It first checks what it can know in advance - the distribution, the commands
the steps run, the database server, that the server name resolves to this machine, that ports 80
and 443 are free for nginx - and names every problem it found before it changes anything. A step
that fails is reported in words: what went wrong, why, what to do, and where its whole output is
(`/var/log/haprion/setup.log`). Every step is safe to run again, so the same command continues an
installation that stopped. Certbot is installed when `UV_BIN` names a uv; the command says so when
it does not. When everything else is done, it creates the first administrator, `admin`, and asks
for its password at the terminal; without a terminal it ends with the command that does it.

## 2. Install the CLI engine

Build from a clean, committed source tree that has passed the repository checks, into a
protected directory outside the repository, with the `uv` the repository is locked with and the
WAF engine package (`tools/build-coraza-package.py`), which the release carries for restored nodes:

```bash
tools/build-cli-package.py --source "$(pwd)" --output-dir /path/to/protected/staging --uv /path/to/uv \
    --waf-engine-package /path/to/protected/staging/haprion-coraza-spoa_<version>_amd64.deb
sudo apt-get install /path/to/protected/staging/haprion-cli_<version>_all.deb
```

The package's `postinst` verifies the wheel, the node package and the WAF engine package it carries
against their digests, installs the release under `/opt/haprion/releases/` and switches `/opt/haprion/current`.
The operator commands are in `/usr/bin`. A later version of the package is the whole update.
What the installer does, and installing without the package, are in the manual's
[Part 3](user-manual.md#part-3--the-versioned-cli-release).

## 3. Install the manager configuration and keys

From `install/`:

```bash
sudo ./01-manager-prepare answers.env
sudo ./02-manager-config answers.env
sudo ./03-manager-keys answers.env | tee keys.txt
```

The answers file is optional in every step: leave it out to use the defaults. Steps 14, 15 and 17
take `-` in its place when a source tree follows it.

The nodes need nothing from step 3's output when they are added in the interface: each node's
package prints a block, and the management host joins the node with it
([install/README.md](../install/README.md#step-4--each-node)). Step 3's answers lines are for a
node prepared by hand. Keep private keys on the host that generated them.

Check the manager installation from `install/`, as your normal account:

```bash
./05-verify answers.env
```

For a command-line-only installation, the application is now installed.

## 4. Install the web interface

Build the package for the management host's distribution (`ubuntu26.04` or `debian13`); the
release is built inside a container of that distribution with rootless podman:

```bash
tools/build-ui-package.py --source "$(pwd)" --output-dir /path/to/protected/staging \
  --distribution ubuntu26.04 --uv /path/to/uv
```

Install the package; it unpacks the release and prints its ID. Then, with the same answers
file, from `/usr/share/haprion-ui/install/platform/`, prepare the platform, migrate its
database and verify the candidate before activating it:

```bash
sudo apt install ./haprion-ui_<version>~ubuntu26.04_amd64.deb
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

Before step 7, ensure the `clusters` list in the generated `ui.toml` names the configured
clusters. Later versions of the package update the running platform themselves: their
`postinst` runs `update-platform-release` with the release they carry, reads no answers file,
and leaves the previous release running if it fails.

The first activation creates the `admin` account if no account exists and asks for its
password at the terminal. If installation ran without a terminal, create it afterwards:

```bash
sudo haprion-user init-admin
```

## 5. Install optional components

Run the installers for the components your installation needs, from
`/usr/share/haprion-ui/install/platform/`. The steps that take a tree take the package's
`/usr/share/haprion-ui`, which carries the tools and the certbot lock they read:

| Component | Installer |
|---|---|
| Platform database backups | `sudo ./06-platform-backup /path/to/answers.env` |
| History and metrics retention | `sudo ./11-platform-retention /path/to/answers.env` |
| Traffic-log collection | `sudo ./13-platform-traffic-collector /path/to/answers.env` |
| Certbot and DNS plugins | `sudo UV_BIN=/path/to/uv ./14-platform-certbot /path/to/answers.env /usr/share/haprion-ui` |
| Certificate and provider sealing keys | `sudo ./15-platform-dns-keys /path/to/answers.env /usr/share/haprion-ui` |
| OpenID Connect helper | `sudo ./17-platform-oidc /path/to/answers.env /usr/share/haprion-ui` |

The SCEP client uses a separately built and verified bundle:

```bash
sudo ./16-platform-scep /path/to/bundle.zip <verified-bundle-sha256>
```

See [install/platform/README.md](../install/platform/README.md) for each component's
installation inputs and follow-up setup.

The WAF engine (Coraza SPOA with the OWASP Core Rule Set) comes as two Debian packages,
built from pinned upstream sources by `tools/build-coraza-package.py`; building the same
version twice gives the same bytes. Before the engine is built, the tool runs
govulncheck (the version it names in `GOVULNCHECK_VERSION`) over the source with the pinned
Go, and refuses the build if the engine can reach a known vulnerability in its modules or
in Go's standard library; a vulnerability only in code the engine never calls is reported
but does not refuse. The database is read when the package is built, so rebuild to
check again. Install govulncheck with the pinned Go
(`GOBIN=<dir> <go>/bin/go install golang.org/x/vuln/cmd/govulncheck@<version>`).
Install both packages on the manager, where publishing compiles the rules before they
leave it, and the engine package on every node:

```bash
python3 tools/build-coraza-package.py crs --source-dir <dir> --output-dir <out>
python3 tools/build-coraza-package.py coraza --source-dir <dir> --go-root <go> \
    --govulncheck <dir>/govulncheck --output-dir <out>
sudo apt install ./haprion-crs_<version>_all.deb ./haprion-coraza-spoa_<version>_amd64.deb  # manager
sudo apt install ./haprion-coraza-spoa_<version>_amd64.deb                                      # each node
```

Installing the packages starts nothing. On a node, the deploy starts the engine when a
release carries rules (`/etc/haproxy/waf`, a link into the release like `maps`) and stops
it when one no longer does; a release with rules is refused on a node without the engine.
The node status reports the engine's version, and the interface offers the engine on an
object only when every node of its cluster has it.

From package revision 2 the engine starts before HAProxy and counts as started only once
its port listens, and it logs into a journal namespace of its own, `haprion-waf`: each
matched rule is a line carrying the matched value, longer than the system journal and
rsyslog keep whole. The package sets that journal's line length and retention (14 days)
under `/usr/lib/systemd/journald@haprion-waf.conf.d/`; override them in `/etc`.
`04-node-prepare` grants the traffic log's read group read access to that namespace and
nothing else in the journal (`/etc/tmpfiles.d/haprion-waf.conf`), and the
collector reads it through the same forced command as the traffic log.

The engine runs as a dynamic user, which belongs to no group, and `/etc/haproxy/releases`
is closed to every account but root. `04-node-prepare` therefore creates the group
`_haprion-waf`, with no members, lets it pass through that directory without listing it
(`/etc/tmpfiles.d/haprion-waf-engine.conf`), and gives the engine the group in a
drop-in, `/etc/systemd/system/coraza-spoa.service.d/haprion.conf`. A node installation
from before this cannot start the engine: the first deploy with rules fails on that node
and returns it to the previous release.

When updating to a release that reads the engine's journal, install its node package on
every node **before** the release on the management host. The nodes' reader still answers
an older collector; the new collector counts a node whose reader cannot answer it as a
failed run, rather than showing that node's WAF findings as none.

A dns listener (UDP and TCP, typically port 53) is served by dnsdist rather than HAProxy,
which listens on UDP only for log forwarding. dnsdist comes from PowerDNS's own
repository, in its 2.1 series, on Ubuntu 26.04 and Debian 13: `01-manager-prepare`
installs it on the manager, where it only checks a listener's configuration before it is
published (the service is masked), and `04-node-prepare` installs it on every node. Both
write the repository's key, which ships beside the scripts in `install/apt-keys/` and is
never fetched, its source in `/etc/apt/sources.list.d/pdns.list` and a pin in
`/etc/apt/preferences.d/dnsdist-21`, so the hosts need to reach `repo.powerdns.com`.

Installing the package starts nothing. On a node, a drop-in
(`/etc/systemd/system/dnsdist.service.d/haprion.conf`) points dnsdist at
`/etc/haproxy/dns/dnsdist.conf`, a link into the release like `waf`, and lets it start only
when that file exists. The deploy starts dnsdist when a release carries a listener, restarts
it when the listener's file changed, stops it when a release no longer has one, and refuses
a release with a listener on a node that has not been prepared for one. dnsdist runs as
`_dnsdist`; the drop-in gives it the member-less group `_haprion-dns`, which may pass
through `/etc/haproxy/releases` (`/etc/tmpfiles.d/haprion-dns.conf`), as the WAF
engine's group does. A configuration dnsdist warns about is refused like one it cannot
load: its check ignores a setting it does not know with only a warning.

dnsdist serves its counters on `127.0.0.1:9521`, without a key; its
API keeps requiring one, and no console is configured. `haprion-node-status` reads them
while dnsdist runs and reports them per pool and server, which is where the interface's
DNS cards come from. With the cluster's Prometheus exporter its sources read them too, on the
node's own address - never on a VIP.

A syslog listener (UDP only) is served by the kernel's IPVS through keepalived rather than
by HAProxy, so the receivers see each message's sender. Every release carries
`keepalived/ipvs.conf`, the cluster's virtual servers - empty of them on a cluster without
a syslog listener - and the deploy installs it as `/etc/keepalived/ipvs.conf` beside the
address list, by the same rules: inert until `keepalived.conf` includes it, and once it
does, a `keepalived --config-test` and a reload only when the test passes, the previous
file restored otherwise. A release whose file holds virtual servers - a cluster with a
syslog object - is refused on a node without the include, before anything is activated. The include goes **at the top level** of `keepalived.conf`, outside
every block, since that is where keepalived reads a virtual server:

```text
include /etc/keepalived/ipvs.conf
```

The `keepalived.conf` the deploy writes for a cluster created in the interface has it
([keepalived on the nodes](user-manual.md#keepalived-on-the-nodes)). In one a person writes,
add it after the first deploy has installed the file, one node at a time, with
`keepalived --config-test -f /etc/keepalived/keepalived.conf` before the reload;
`04-node-prepare` warns while it is missing. `04-node-prepare` also installs `ipvsadm`, which
`haprion-node-status` reads the counters with, and masks `ipvsadm.service` first: Debian's
package enables it, and it restores and clears the IPVS table at boot and shutdown, which
keepalived owns. The nodes need no `ip_forward`: the receivers never answer through them.

**Forwarding the traffic log.** A cluster's external log receivers are sent to by the node's own
rsyslog, with a queue on disk per receiver. `04-node-prepare` installs
`/etc/rsyslog.d/47-haprion-forward.conf`, which loads rsyslog's `impstats` (each receiver's queue
once a minute, to `/var/log/haprion/rsyslog-stats.json`, rotated daily by
`/etc/logrotate.d/haprion-rsyslog-stats`) and includes `/etc/rsyslog.d/haprion/forward.conf` when
it is there; the package depends on `rsyslog-gnutls` for receivers over TLS. The deploy puts that
file in place from a release that names receivers and removes it from one that does not: it checks
the candidate with `rsyslogd -N1` before anything is activated, copies it to `/etc/rsyslog.d/haprion/`
- rsyslogd's AppArmor profile does not let it read the releases under `/etc/haproxy` - checks the
whole configuration again, and restarts rsyslog only when the file changed, putting the previous
file back if rsyslog refuses it. The queues live in rsyslog's work directory (`/var/spool/rsyslog`
on Ubuntu) and need the room the cluster's `disk_mib` gives each receiver. A release that names
receivers is refused on a node without the include, before anything is activated. A site that
already loads `impstats` itself gets a refusal from `rsyslogd -N1` when `04-node-prepare` runs.
`04-node-prepare` also has systemd hold HAProxy's log socket in its chroot
(`haprion-haproxy-log.socket`, `net.unix.max_dgram_qlen` in `/etc/sysctl.d/60-haproxy.conf`), so a
restart of rsyslog loses no lines; taking the socket over restarts rsyslog once
([HAProxy and keepalived baseline](user-manual.md#haproxy-and-keepalived-baseline)).

## 6. Verify access

Open `https://<SERVER_NAME>` and sign in with the administrator account created during
installation. If no certificate was supplied, the nginx installer generates a self-signed
one and the browser asks you to accept it.

If an installation step fails, correct the error it reports and rerun that step.
The installation scripts support repeated runs.
