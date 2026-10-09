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
- for the web interface: PostgreSQL 16 or newer, nginx and `uv`

Have the source tree, a wheel built from the selected commit and the matching node bundle
available. The scripts use an answers file; its example includes `UV_BIN` and `ALEMBIC_BIN`,
which must name the installed build and migration tools.

HAProxy nodes must already be prepared before the application can manage them. The
[node preparation instructions](user-manual.md#part-2--the-nodes) are in the manual.

## 1. Prepare the answers file

From the source tree's `install/` directory:

```bash
cp answers.example.env answers.env
$EDITOR answers.env
```

Fill in the paths, accounts, database, cluster names and the interface's `SERVER_NAME` for
your installation. The file is described in [install/answers.example.env](../install/answers.example.env).

## 2. Install the CLI engine

Build from a clean, committed source tree that has passed the repository checks. From the
source-tree root, build the wheel into a protected directory outside the repository:

```bash
python -m build --wheel --outdir /path/to/protected/staging
sha256sum /path/to/protected/staging/haproxy_manager-*.whl
```

Build the matching node bundle from the same commit and record the digest it prints:

```bash
tools/node-bundle.py build \
  --source "$(pwd)" \
  --output /path/to/protected/staging/haprion-node-0123456789ab.tar.gz
```

Install the wheel and bundle, using their actual absolute paths and SHA-256 digests:

```bash
sudo /usr/bin/python3 tools/install-release.py \
  --wheel /path/to/protected/staging/haproxy_manager-0.1.0-py3-none-any.whl \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --node-bundle /path/to/protected/staging/haprion-node-0123456789ab.tar.gz \
  --node-bundle-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

## 3. Install the manager configuration and keys

From `install/`:

```bash
sudo ./01-manager-prepare answers.env
sudo ./02-manager-config answers.env
sudo ./03-manager-keys answers.env | tee keys.txt
```

Install the public-key lines printed by step 3 on the corresponding prepared nodes,
following [install/README.md](../install/README.md#step-4--each-node). Keep private keys
on the host that generated them.

Check the manager installation from `install/`, as your normal account:

```bash
./05-verify answers.env
```

For a command-line-only installation, the application is now installed.

## 4. Install the web interface

Use the same answers file. From `install/platform/`, prepare the application, migrate its
database and verify the candidate before activating it:

```bash
sudo ./01-platform-prepare ../answers.env
sudo ./02-platform-database ../answers.env
sudo ./install-ui-release --prepare ../answers.env /path/to/source-tree
sudo ./migrate ../answers.env --release <release-id>
sudo ./03-verify ../answers.env
sudo ./check-compatibility ../answers.env --release <release-id>
sudo ./install-ui-release ../answers.env /path/to/source-tree
sudo ./04-platform-service ../answers.env
sudo ./05-platform-nginx ../answers.env
sudo ./07-platform-services ../answers.env
sudo ./check-compatibility ../answers.env
```

Use the release ID printed when the candidate was prepared. Before step 7, ensure the
`clusters` list in the generated `ui.toml` names the configured clusters.

The first activation creates the `admin` account if no account exists and asks for its
password at the terminal. If installation ran without a terminal, create it afterwards:

```bash
sudo haprion-user init-admin
```

## 5. Install optional components

Run the installers for the components your installation needs, from `install/platform/`:

| Component | Installer |
|---|---|
| Platform database backups | `sudo ./06-platform-backup ../answers.env` |
| History and metrics retention | `sudo ./11-platform-retention ../answers.env` |
| Traffic-log collection | `sudo ./13-platform-traffic-collector ../answers.env` |
| Certbot and DNS plugins | `sudo UV_BIN=/path/to/uv ./14-platform-certbot ../answers.env /path/to/source-tree` |
| Certificate and provider sealing keys | `sudo ./15-platform-dns-keys ../answers.env /path/to/source-tree` |
| OpenID Connect helper | `sudo ./17-platform-oidc ../answers.env /path/to/source-tree` |

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
`haprion-waf`, with no members, lets it pass through that directory without listing it
(`/etc/tmpfiles.d/haprion-waf-engine.conf`), and gives the engine the group in a
drop-in, `/etc/systemd/system/coraza-spoa.service.d/haprion.conf`. A node bundle
from before this cannot start the engine: the first deploy with rules fails on that node
and returns it to the previous release.

When updating to a release that reads the engine's journal, install its node bundle on
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
`_dnsdist`; the drop-in gives it the member-less group `haproxy-dns`, which may pass
through `/etc/haproxy/releases` (`/etc/tmpfiles.d/haprion-dns.conf`), as the WAF
engine's group does. A configuration dnsdist warns about is refused like one it cannot
load: its check ignores a setting it does not know with only a warning.

dnsdist serves its counters on `127.0.0.1:9521`, without a key and to loopback only; its
API keeps requiring one, and no console is configured. `haprion-node-status` reads them
while dnsdist runs and reports them per pool and server, which is where the interface's
DNS cards come from. Nothing outside the node can reach them.

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

Add it after the first deploy has installed the file, one node at a time, with
`keepalived --config-test -f /etc/keepalived/keepalived.conf` before the reload;
`04-node-prepare` warns while it is missing. `04-node-prepare` also installs `ipvsadm`, which
`haprion-node-status` reads the counters with, and masks `ipvsadm.service` first: Debian's
package enables it, and it restores and clears the IPVS table at boot and shutdown, which
keepalived owns. The nodes need no `ip_forward`: the receivers never answer through them.

## 6. Verify access

Open `https://<SERVER_NAME>` and sign in with the administrator account created during
installation. If no certificate was supplied, the nginx installer generates a self-signed
one and the browser asks you to accept it.

If an installation step fails, correct the error it reports and rerun that step.
The installation scripts support repeated runs.
