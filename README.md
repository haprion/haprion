# Haprion

Haprion is an environment-neutral management engine and web interface for operating
small HAProxy clusters safely. The command-line engine is the authoritative control plane; the
web application calls the same versioned commands rather than implementing a second
configuration path.

**Start with the [quickstart](docs/quickstart.md)**: from an installed manager to a site served by
your HAProxy pair, in the web interface. [Installing](docs/install.md) covers the installation, and
the [user manual](docs/user-manual.md) is the reference for everything else.

## Project status

The project has not reached 1.0 and is **not yet declared ready for production deployment**:
everything below is built and tested, and the remaining work before 1.0 is polish, a full
re-verification of a rebuild from this repository, and documentation. What is built:

- frozen v1 JSON schemas and command semantics
- a strict runtime-policy and cluster-configuration model
- an initial privilege-boundary contract
- generic configuration examples and contract fixtures
- reusable result-envelope and cluster-lookup code
- a strict, size-bounded JSON request protocol for exact privileged helpers
- a validated external identity policy that renders locked system-service accounts without
  granting the web or poller config-group membership
- a path-free candidate-validation helper foundation with deterministic hashing and a hardened
  transient-service sandbox
- a hash-verified, versioned and immutable installation layout under `/opt/haprion`
- reproducible development, security, test, and package-build gates
- every management command running through the packaged CLI, including status, which reports
  whether the nodes are running the published configuration without starting a deployment to
  find out
- a scripted installation covering the management host, the nodes, and the web platform
- Debian packages, reproducible from one commit: `haprion-cli` for the engine, `haprion-ui` for the
  web interface on Ubuntu 26.04 or Debian 13, `haprion-node` for the nodes, and the WAF engine and
  rule set; installing a newer package is the update
- the web platform's foundation: a versioned application release, a database whose schema and
  column-level grants are versioned together, and separate service identities that cannot do each
  other's work
- a web interface over that foundation, fed by a poller rather than by reads made while
  somebody is looking at a screen; it reads for everyone and writes only for an admin on an
  installation that sets `management_writes = true`
- proxy objects edited as drafts and published as versions, a cluster's network and VIPs, and
  deploys that roll a published version out node by node and are bound to the version the
  person saw; every write is a job, and every job is also a command at the terminal
- metrics collected from the nodes and kept as time series
- an optional, manager-pulled traffic-log view backed by seven days of indexed, daily PostgreSQL
  partitions; each cluster must explicitly set `traffic_logging: true`, and the setting reaches
  its nodes with the next object publication. It is a basic log viewer for the recent requests;
  analysis, dashboards and alerting belong in an external log platform, which the product does
  not feed yet
- certificate issuance from one form: a domain, a challenge method and the targets; DNS-01
  through a provider profile whose credentials the web process sealed and only root's helper
  opens, from a catalogue of locked Certbot plugins; and certificate cleanup as one job for a
  whole selection, refusing row by row anything a committed object, a draft or a cluster still
  depends on; a certificate issued elsewhere is imported from PEM or PKCS#12 on the command line
  and taken to its targets the same way; certificates are also distributed from the manager to
  the nodes and to registered receivers that fetch them
- scheduled node-state backups, and restoring a node from its archive onto an empty VM or over
  itself, with a preview before anything is written
- settings for the interface's own certificate, local accounts, feature switches, and sign-in
  through an OpenID Connect provider with a local break-glass account kept
- the job path every management operation runs through: an immutable queue, an atomic claim held
  under a renewable lease, and a worker that records how every job ended — including recovering a
  job whose worker died, which is decided from readable evidence rather than retried on assumption

With `management_writes` off, the interface is read-only and the worker claims nothing; that is
the state turning the switch off returns to, so it is a rollback rather than a pause.

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
src/haproxy_mgmt/   Python management package
schemas/v1/         versioned JSON command schemas
fixtures/           valid and invalid contract examples
contract-tests/     schema and semantic contract verification
tests/              unit tests
tools/              development and security gates
docs/               public contracts and security documentation
```

## Development

Python dependencies are resolved in the committed `uv.lock`; `.python-version` selects the minimum
supported Python 3.12 for a fresh environment. With
[`uv`](https://docs.astral.sh/uv/) installed, bootstrap an editable environment and the pinned
standalone checks with:

```bash
./tools/bootstrap-dev
```

For a generic checkout, run the complete local gate with the repository's example denylist:

```bash
PATH="$PWD/.venv/bin:$PWD/.tools/shellcheck/0.11.0:$PWD/.tools/actionlint/1.7.12:$PATH" \
GITLEAKS_BIN="$PWD/.tools/gitleaks/8.30.1/gitleaks" \
HAPROXY_MANAGER_SECRET_RULES="$PWD/tools/denylist.example.rules" \
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
