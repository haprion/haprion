# HAProxy Manager

HAProxy Manager is an environment-neutral management engine and planned web interface for
operating small HAProxy clusters safely. The command-line engine is the authoritative control
plane; the web application will call the same versioned commands rather than implementing a
second configuration path.

## Project status

The project is in early implementation and is **not yet ready for production deployment**. The
current foundation provides:

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
- a hash-verified, versioned and immutable installation layout under `/opt/haproxy-mgmt`
- reproducible development, security, test, and package-build gates
- every management command running through the packaged CLI, including status, which reports
  whether the nodes are running the published configuration without starting a deployment to
  find out
- a scripted installation covering the management host, the nodes, and the web platform
- the web platform's foundation: a versioned application release, a database whose schema and
  column-level grants are versioned together, and three service identities that cannot do each
  other's work
- a read-only web interface over that foundation, fed by a poller rather than by reads made while
  somebody is looking at a screen
- an optional, manager-pulled traffic-log view; each cluster must explicitly set
  `traffic_logging: true`, and the setting reaches its nodes with the next object publication
- certificate issuance from one form: a domain, a challenge method and the targets; DNS-01
  through a provider profile whose credentials the web process sealed and only root's helper
  opens, from a catalogue of locked Certbot plugins; and certificate cleanup as one job for a
  whole selection, refusing row by row anything a committed object, a draft or a cluster still
  depends on; a certificate issued elsewhere is imported from PEM or PKCS#12 on the command line
  and taken to its targets the same way
- the job path management operations will run through: an immutable queue, an atomic claim held
  under a renewable lease, and a worker that records how every job ended — including recovering a
  job whose worker died, which is decided from readable evidence rather than retried on assumption

Management operations from the web remain **disabled**. The worker is installed, running, and
provably unable to act, which is a stronger statement than not installing it: it is the state
turning the feature off returns to. Enabling them waits on the worker's own privilege being
installed and its gate passed.

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
entered in the web interface are sealed against a host key the web process cannot open. Renewal
stays Certbot's own timer; certificates the manager enrolls from a Microsoft CA over NDES/SCEP
are renewed by the same daily run through the same enrollment path. Disaster recovery and VM rebuild workflows are deliberately outside the
application scope.

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

Versioned installation and rollback under `/opt/haproxy-mgmt` are described in
[`docs/INSTALLATION.md`](docs/INSTALLATION.md).
