# Haprion

Haprion is an environment-neutral management engine and web interface for operating
small HAProxy clusters safely. The command-line engine is the authoritative control plane; the
web application calls the same versioned commands rather than implementing a second
configuration path.

**Start with the [quickstart](docs/quickstart.md)**: from an installed manager to a site served by
your HAProxy pair, in the web interface. [Installing](docs/install.md) covers the installation, and
the [user manual](docs/user-manual.md) is the reference for everything else.

## Project status

The project has not reached 1.0 and is **not yet declared ready for production deployment**.
Everything listed below is built and tested. What remains before 1.0 is making every setting the
interface offers available from the command line as well, a full re-verification of an
installation built from this repository, and documentation.

## What it does

**Proxies and clusters**

- HTTP, HTTPS and TCP objects edited as drafts and published as versions; a deploy rolls a
  published version out node by node and is bound to the version the person saw
- DNS load balancing through dnsdist, and syslog over UDP
- a cluster's network and virtual addresses, carried by keepalived
- draining a server, maintenance, and replacing a certificate without reloading HAProxy
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

- issuance from one form through ACME, with HTTP-01 or DNS-01; DNS provider credentials are sealed
  by the web process and opened only by a root helper
- enrollment and renewal from a Microsoft CA over NDES/SCEP
- import of a certificate issued elsewhere, a key and signing request made on the manager, and
  export of a certificate marked exportable
- distribution to the nodes and to registered receivers that fetch them, and cleanup of a whole
  selection that refuses anything still in use

**Operations**

- status, metrics and a basic seven-day traffic-log viewer, fed by a poller rather than by reads
  made while somebody is looking at a screen
- the traffic log sent to up to four external syslog receivers, and HAProxy's Prometheus exporter
- scheduled node-state backups, and restoring a node from its archive onto an empty VM or over
  itself, with a preview before anything is written
- the interface's own certificate, local accounts, feature switches, and sign-in through an
  OpenID Connect provider with a local break-glass account kept
- every write is a job: an immutable queue, an atomic claim under a renewable lease, and a worker
  that records how every job ended, including one whose worker died
- Debian packages from one commit: `haprion-cli` for the engine, `haprion-ui` for the web
  interface on Ubuntu 26.04 or Debian 13, `haprion-node` for the nodes, and the WAF engine and rule
  set; installing a newer package is the update

The interface reads for everyone and writes only for an admin on an installation that sets
`management_writes = true`. With it off, the interface is read-only and the worker claims nothing;
that is the state turning the switch off returns to, so it is a rollback rather than a pause.
What the product deliberately leaves to others is listed under
[What it does not do](docs/user-manual.md#what-it-does-not-do).

## Security model

Environment-specific configuration and credentials never belong in this repository or its Git
history. Real cluster identifiers, hosts, addresses, domains, accounts, paths, SSH keys,
certificates, HAProxy configuration, and published releases are loaded from protected runtime
configuration outside the installed source package.

The web, worker, and poller processes use separate operating-system identities. Application
identities do not own or read SSH private keys, certificate private keys, or unrestricted secrets.
Privileged operations cross narrow, allowlisted helper interfaces. See
[`docs/PRIVILEGE.md`](docs/PRIVILEGE.md) for the frozen target contract.

Certificate issuance runs through an exact root helper around Certbot; DNS provider credentials
entered in the web interface are sealed against a host key the web process cannot open. A
certificate file uploaded in the interface - with or without its private key - is sealed the same
way inside the request that carries it, so the web process holds the key only for the duration of
that request and stores nothing it can read back; only the root helper opens the file. A key can
also be made on the manager, with a signing request for any CA to sign; the key then never exists
anywhere else, and the signed certificate is uploaded back without one. Renewal
stays Certbot's own timer; certificates the manager enrolls from a Microsoft CA over NDES/SCEP
are renewed by the same daily run through the same enrollment path. Node state is backed up on a
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
`ui/uv.lock` for the interface); `.python-version` selects the minimum supported Python 3.12. With
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

Changes to migrations, grants or database read/write paths also run against a disposable real
PostgreSQL cluster with `ui/tools/test-database`; its accounts and isolation boundary are described
in [`docs/SECURITY-CHECKS.md`](docs/SECURITY-CHECKS.md#disposable-database-integration-gate).

Versioned installation and rollback under `/opt/haprion` are described in
[`docs/install.md`](docs/install.md) and [`docs/user-manual.md`](docs/user-manual.md).

## License

Haprion is free software under the GNU Affero General Public License, version 3 or (at your option)
any later version - [`LICENSE`](LICENSE). Running a modified version for others over a network obliges
you to offer them its source.
