# Haprion

Run small HAProxy clusters from one place - load balancing, failover, a WAF and certificates -
without having to master HAProxy.

## Project status

Haprion is a personal hobby project. I had outgrown Nginx Proxy Manager and wanted something in
the same spirit that also understood high availability: two or more nodes sharing a virtual
address, certificates issued and distributed from one place, load balancing to the servers behind,
and a WAF in front of them - while staying reasonably easy to use for someone who does not work
with networks, proxies or load balancers on a daily basis. In practice that means a home lab, and
possibly a smaller company.

It is useful to me, and I hope it may be useful to others too, but expectations should be adjusted
accordingly. This is not a commercial product: there is no SLA, no support agreement and no
guaranteed response time, and maintenance is best-effort. There will be bugs.

The project has not reached 1.0 and is **not yet declared ready for production deployment**.
Everything listed below is built and tested.
What remains before 1.0 is a full re-verification of an installation built from this repository,
and documentation.

**Built with AI.** The code is written by [Claude](https://claude.ai) and
[Codex](https://openai.com/codex/). The design, the product decisions and the direction are mine -
I describe what I want, review the results and decide what stays. I have written perhaps ten lines
of shell myself; the rest was done by AI.

## How an installation looks

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/installation-dark.svg">
  <img src="docs/images/installation-light.svg" width="900" alt="Clients reach the virtual address, which keepalived keeps on node-a of the HAProxy cluster; node-a forwards to your servers, and node-b stands by to take the address over. The manager, outside the traffic path, runs the web interface and engine with PostgreSQL. It asks the nodes to fetch over SSH, and the nodes fetch releases and certificates from it; other hosts fetch their certificates from it too.">
</picture>

The **manager** is a machine of its own. It holds the configuration, the published versions, the
keys and the certificates, and runs the web interface; one manager can look after several
clusters. The **nodes** carry the traffic: the one holding the virtual address answers, and when it
fails keepalived moves the address to another. Clients never pass through the manager, so without
it the nodes go on serving - what stops is changing anything.

The manager never pushes to a node. It asks the node to fetch, and the node checks a release before
it switches to it. Other hosts that need a certificate - a mail server, a NAS, a hypervisor - can
be registered to fetch theirs from the manager the same way.

## What you need

| Machine | How many | Operating system | Size to start from |
|---|---|---|---|
| Manager | one | Ubuntu 26.04 or Debian 13, amd64 | 2 vCPU, 4 GB memory |
| HAProxy node | one to eight per cluster, two for failover | Ubuntu 26.04 or Debian 13, amd64 | 1 vCPU, 1 GB memory; 2 GB with the WAF |

- Virtual machines are fine, and are what Haprion is tested on.
- The nodes of a cluster share one network segment: keepalived moves the virtual address between
  them with VRRP. The manager reaches each node over SSH.
- A node's disk grows with its traffic log; [Installing](docs/install.md#requirements) shows how much
  to plan for. How much traffic one vCPU handles, with and without the WAF, is under *Size* in
  [the manual's part on the nodes](docs/user-manual.md#part-2--the-nodes).

## Screenshots

Screenshots will be added.

## Getting started

**Start with the [quickstart](docs/quickstart.md)**: from empty machines to a site served by your
HAProxy nodes. In short:

1. Install the manager with its package and one command, `sudo haprion-setup`.
2. Install each node with its package. It prints a *block*, a line you paste into the manager.
3. Open the web interface. Its dashboard walks you through your first cluster: its name and address, the
   nodes, and the first deploy.

[Installing](docs/install.md) covers the installation in full, and the [user manual](docs/user-manual.md)
everything else.

The packages come from the project's signed apt repository. Add it on the manager and on each node:

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

Then `sudo apt install haprion-ui` and `sudo haprion-setup` on the manager, and
`sudo apt install haprion-node` on each node.

## What it does

**Proxies and clusters**

- HTTP, HTTPS and TCP services, edited as drafts and published as versions; a deploy rolls out exactly
  the version you saw, one node at a time
- DNS load balancing through dnsdist, and syslog over UDP
- a cluster's network and virtual addresses, carried by keepalived
- draining a server, maintenance, and replacing a certificate without reloading HAProxy
- a server name the manager cannot resolve is pointed out when you type it and when you publish, before
  a node finds out
- adding or removing a node in one step: the new membership is published and, if the cluster was up to
  date, deployed too
- counters shared between a cluster's nodes, so a failover or a deploy does not start them again

**Access and protection**

- who may reach an object - by address, range, named network or country - and who may not
- rules on path, method and headers, a per-source rate limit per object, and a brake per cluster
  on any single source address
- a WAF engine (Coraza with the OWASP Core Rule Set), in log or block mode per object, with
  exceptions made from the findings
- an advanced configuration layer per object, behind a feature switch, for what the forms do not
  cover

**Certificates**

- issuance from one form through ACME (Let's Encrypt), with HTTP-01 or DNS-01; DNS provider credentials
  are encrypted by the web interface and can be opened only by a root helper
- enrollment and renewal from a Microsoft CA over NDES/SCEP
- import of a certificate issued elsewhere, a key and signing request made on the manager, and
  export of a certificate marked exportable
- distribution to the nodes and to other hosts that fetch them, and deleting several at once – a
  certificate still in use is refused
- renewal on a schedule, twice a day, for both Let's Encrypt and NDES certificates

**Operations**

- status, metrics and a basic traffic-log viewer (seven days), collected in the background rather than
  asked for while you look at a page
- the traffic log sent to up to four external syslog receivers, and HAProxy's Prometheus exporter
- scheduled node-state backups, and restoring a node from its archive onto an empty VM or over
  itself, with a preview before anything is written
- the interface's own certificate, local accounts, feature switches, and sign-in through an
  OpenID Connect provider with a local break-glass account kept
- every change to a cluster is a job, and how every job ended is recorded – even when the process
  running it died
- Debian packages from a signed apt repository; `apt upgrade` is the update. Every package is built
  twice, on separate machines, and published only when both builds are identical

Everyone signed in can read; an admin can change things. You can also stop all changes for the whole
installation with `management_writes = false` in `ui.toml`: the interface becomes read-only and no job runs
– useful while you look into a problem.
What the product deliberately leaves to others is listed under
[What it does not do](docs/user-manual.md#what-it-does-not-do).

## How it differs from what you might expect

Coming from another load-balancer interface, a few choices here are deliberate and may surprise:

- **The manager is a machine of its own.** It is not one of the HAProxy nodes: a separate host
  holds the configuration, the releases, the keys and the web interface, and manages one or more
  clusters of one to eight nodes - so it is one more machine to run. It is not in the traffic
  path: without it the nodes go on serving and keepalived still moves the virtual address, and
  what stops is changing anything ([what keeps working](docs/DISASTER-RECOVERY.md)).
- **The nodes fetch; the manager never pushes.** Each key the manager holds on a node can run only
  one fixed command there. Configuration and certificates are always fetched by the node, which checks
  a release before it switches to it.
- **Saving, publishing and deploying are three steps.** A change becomes a version when it is
  published; a deploy rolls out exactly the version the person saw, the nodes that do not hold
  the virtual address first and its owner last.
- **The command line is the engine.** The web interface calls the same commands and has no
  configuration path of its own for the clusters, and every change to one is a job with a
  recorded outcome. Accounts, settings and drafts belong to the interface: they are written to its
  database and audited there.
- **The screen never asks the nodes.** What the interface shows comes from a poller, so a page
  load cannot overload or hang on a node.
- **Certificates are renewed with existing tools.** Haprion does not implement ACME itself: it runs
  certbot, and the NDES enrollment client, twice a day on its own schedule, and distributes what they
  renew.
- **Optional capabilities are switched on per installation**, under *Settings → Features*. The
  WAF engine, the advanced configuration layer, distributing certificates to other services -
  hosts that fetch them over rsync, SFTP or HTTPS - and node backups are off on a new
  installation; node backups include restoring a node onto an empty VM or over itself.
- **The interface loads nothing from the internet.** Fonts, scripts and icons are local, so it works
  while the network it manages is broken. The manager itself fetches only an optional daily update
  check (off by default) and updates to the country database.
- **Built to be scripted.** Commands answer with `--json`, and every setting the interface offers can
  be set from the command line, so a tool such as Ansible can drive a whole installation.

## Security model

Environment-specific configuration and credentials never belong in this repository or its Git
history. Real cluster identifiers, hosts, addresses, domains, accounts, paths, SSH keys,
certificates, HAProxy configuration, and published releases are loaded from protected runtime
configuration outside the installed source package.

The web, worker, and poller processes use separate operating-system identities. None of them can
read a certificate's private key or a key that can change a node; the two narrow exceptions – the
traffic collector's read-only key to the nodes' logs, and the sign-in helper's own key – are described
in PRIVILEGE.md. Privileged operations cross narrow, allowlisted helper interfaces. See
[`docs/PRIVILEGE.md`](docs/PRIVILEGE.md) for the frozen target contract. Vulnerabilities are
reported privately, as [`SECURITY.md`](SECURITY.md) describes.

Certificate issuance runs through an exact root helper around Certbot; DNS provider credentials
entered in the web interface are sealed against a host key the web process cannot open. A
certificate file uploaded in the interface - with or without its private key - is sealed the same
way inside the request that carries it, so the web process holds the key only for the duration of
that request and stores nothing it can read back; only the root helper opens the file. A key can
also be made on the manager, with a signing request for any CA to sign; the key then never exists
anywhere else, and the signed certificate is uploaded back without one. Renewal runs twice a day,
through certbot for Let's Encrypt certificates and through the same enrollment path for those from a
Microsoft CA over NDES/SCEP. Node state is backed up on a
schedule and a node can be restored from its archive onto an empty VM or over itself; providing that
VM, backing up the management host and the rest of a recovery plan are the operator's, and
[`docs/DISASTER-RECOVERY.md`](docs/DISASTER-RECOVERY.md) is the template for writing it down.

## Repository layout

```text
src/haprion/      the management engine and its command-line interface
ui/               the web interface, a distribution of its own with its own lockfile
install/          installation steps for the manager, the nodes and the web platform
certbot/          the locked Certbot environment and its DNS plugins
schemas/v1/       versioned JSON command schemas
fixtures/         valid and invalid contract examples
contract-tests/   schema and semantic contract verification
examples/         generic configuration examples
tests/            engine tests
tools/            development, packaging and security gates
docs/             installation, user manual, contracts and security documentation
```

## Development

Python dependencies are resolved in the committed lockfiles (`uv.lock` for the engine,
`ui/uv.lock` for the interface); `.python-version` selects the minimum supported Python 3.13. With
[`uv`](https://docs.astral.sh/uv/) installed, set up both environments, the browser the interface
tests drive, and the pinned standalone checks with:

```bash
./tools/bootstrap-dev
```

Chromium needs a few system libraries; on a host that lacks them,
`sudo .venv-ui/bin/playwright install-deps chromium` adds them. Then run the complete local gate
with the repository's example denylist - the same command `bootstrap-dev` prints:

```bash
PATH="$PWD/.venv/bin:$PWD/.tools/shellcheck/0.11.0:$PWD/.tools/actionlint/1.7.12:$PATH" \
GITLEAKS_BIN="$PWD/.tools/gitleaks/8.30.1/gitleaks" \
HAPRION_UI_PYTHON="$PWD/.venv-ui/bin/python" \
PLAYWRIGHT_BROWSERS_PATH="$PWD/.tools/playwright" \
HAPRION_SECRET_RULES="$PWD/tools/denylist.example.rules" \
./run-checks
```

Maintainers additionally supply a private environment denylist outside the repository. The gate
runs source and history secret scanning, Ruff, ShellCheck, actionlint, zizmor, strict mypy, branch
coverage, unit and frozen contract tests, an sdist/wheel smoke test, and dependency auditing.
CodeQL is the heavier pre-push and release gate described in
[`docs/SECURITY-CHECKS.md`](docs/SECURITY-CHECKS.md).

The gate also runs the interface's migrations, grants and SQL against a disposable real
PostgreSQL cluster with `ui/tools/test-database`, so it needs PostgreSQL installed; its accounts
and isolation boundary are described in [`docs/SECURITY-CHECKS.md`](docs/SECURITY-CHECKS.md#disposable-database-integration-gate).

Versioned installation and rollback under `/opt/haprion` are described in
[`docs/install.md`](docs/install.md) and [`docs/user-manual.md`](docs/user-manual.md).

## License

Haprion is free software under the GNU Affero General Public License, version 3 or (at your option)
any later version - [`LICENSE`](LICENSE). Running a modified version for others over a network obliges
you to offer them its source.
