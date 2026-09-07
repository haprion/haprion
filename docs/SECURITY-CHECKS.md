# Security and quality checks

The repository has complementary gates. No single scanner replaces the others.

1. `tools/secret_scan.py` rejects generic secret material, non-documentation IP addresses, and
   environment-specific values from a mandatory private denylist.
2. `tools/run-gitleaks` scans the worktree and, once commits exist, the complete Git history using
   Gitleaks' credential patterns.
3. `run-tests` verifies Shell scripts with ShellCheck, GitHub Actions syntax with actionlint and
   security posture with zizmor, Python lint/format with Ruff, and types with strict mypy.
4. The same command measures branch coverage with a non-regression floor, runs unit and frozen
   contract tests, builds both sdist and wheel, imports the installed wheel from an isolated target,
   and runs `pip-audit` against the locked active environment.
5. `tools/run-codeql` performs the heavier CodeQL `security-extended` analysis, Python and
   JavaScript, before the first push and before releases.
6. `ui/run-tests` runs the interface's own suite and type checking in the environment holding its
   dependencies. `run-tests` calls it rather than skipping it: a gate that passes because it could
   not import what it was meant to check is not a gate. It needs `HAPROXY_UI_PYTHON` and fails
   closed without it.
7. `install/platform/03-verify` checks the database privilege surface against the running database,
   in both directions. It is a deployment check rather than a repository one, so it is not part of
   `run-checks` — but it belongs to the same family, and the reason it checks both directions is in
   [`INSTALLATION.md`](INSTALLATION.md#44-verifying-it).
8. `install/platform/check-compatibility` reads the separately installed CLI, UI, schema, service
   processes, sudo rules and node bundle metadata as one result. It changes nothing and fails on an
   unknown compatibility level rather than assuming an older component is usable.
9. `install/platform/update-platform-release` applies those checks to a prepared candidate before
   it migrates or activates anything, and proves the running release accepts the target schema so
   the automatic UI rollback remains a supported combination.

A release wheel is installed only by `tools/install-release.py` with an explicitly supplied
SHA-256 digest. The installer rejects path traversal, symlinks, special files and unexpected entry
points before activating a root-owned, read-only release. See [`INSTALLATION.md`](INSTALLATION.md).

### The scanner exists twice, deliberately

`tools/secret_scan.py` is what `run-checks` and CI run. The pre-commit hook runs a **separate copy
outside the repository**, and that duplication is defence rather than drift: a scanner that lives in
the tree it scans can be weakened by the very commit it is meant to inspect.

Everywhere else in this project two implementations of one rule are a defect. Here the out-of-tree
copy is authoritative for commits, which means a change to the scanner's rules has to be made in
both — and the hook refusing a commit that only changed the in-tree copy is the mechanism working,
not a problem to route around.

The private denylist is never stored in this repository. Local runs provide its path through
`HAPROXY_MANAGER_SECRET_RULES`. GitHub Actions reconstructs it in a mode-600 temporary file from
the required repository secret `HAPROXY_MANAGER_DENYLIST`. The repository-secret value is the
Base64 encoding of the complete file, used as a transport encoding so tabs and line endings remain
exact. A missing or invalid value fails CI closed.

## Local quick gate

Create the locked editable environment and pinned standalone tools once:

```bash
./tools/bootstrap-dev
```

Then run:

```bash
export HAPROXY_MANAGER_SECRET_RULES=/path/to/private.rules
export PATH="$PWD/.venv/bin:$PWD/.tools/shellcheck/0.11.0:$PWD/.tools/actionlint/1.7.12:$PATH"
export GITLEAKS_BIN="$PWD/.tools/gitleaks/8.30.1/gitleaks"
export HAPROXY_UI_PYTHON=/path/to/ui-environment/bin/python
./run-checks
```

The interface has a second locked environment, because it has a second lockfile:
`ui/uv.lock`. `HAPROXY_UI_PYTHON` points at it, and the gate refuses to run without it rather than
quietly leaving the interface unchecked.

## Disposable database integration gate

Cursor imitations catch query shape, but they do not execute migrations, PostgreSQL permissions,
partition routing or SQL semantics. Run the real-database gate after changing a migration, a
database read/write path, role grants, metric rollups or retention:

```bash
HAPROXY_UI_PYTHON=/path/to/ui-environment/bin/python ui/tools/test-database
```

The command must run as the developer, not root. It finds the installed PostgreSQL tools through
`pg_config`, creates a private temporary cluster under `TMPDIR`, listens only on a Unix socket in
that directory, applies every Alembic migration and runs `tests.test_database_integration`. A trap
stops PostgreSQL and removes the complete temporary cluster on success, failure or interruption.
It never reads an answers file and has no connection string for the development or production
databases.

The temporary accounts deliberately mirror the installed privilege model:

| Test role | Login | Purpose |
|---|---:|---|
| `hm_test_migrate` | yes | owns the test database and applies migrations |
| `app_web` | no | fixed contract role for web grants |
| `app_worker` | no | fixed contract role for worker grants |
| `app_poller` | no | fixed contract role for poller grants |
| `hm_test_web` | yes | inherits only `app_web`; exercises browser-facing SQL |
| `hm_test_worker` | yes | inherits only `app_worker`; exercises job SQL |
| `hm_test_poller` | yes | inherits only `app_poller`; exercises cache and metric writes |

PostgreSQL's bootstrap superuser exists only inside the disposable cluster and is used only to
create those roles and the database. Application queries are tested through the corresponding
login role. Add integration cases to `ui/tests/test_database_integration.py`; they are skipped by
the ordinary unit suite unless the harness supplies its private socket and role variables. Never
set those variables by hand against an installed database.

`uv.lock` is committed and CI installs it with `uv sync --locked --group dev`; a stale lockfile
therefore fails instead of being silently refreshed. The local project is installed editable, so
tests do not depend on an implicit `PYTHONPATH`.

## Local CodeQL gate

Use the pinned CodeQL bundle documented by the private build environment. Results and the database
must be written outside the repository:

```bash
CODEQL_BIN=/path/to/codeql tools/run-codeql /path/to/new-results-directory
```

The wrapper rejects an output directory inside the source tree, refuses to overwrite an existing
result directory, and fails if either SARIF file contains an alert. Source snippets are not printed
by the final gate summary.

Two languages are analysed in one run: the engine and the interface in Python, and the interface's
own scripts under `ui/src/haproxy_ui/static` in JavaScript, each against its `security-extended`
suite. Those scripts have no build step and no dependencies, but they are the only code here that
runs inside a reader's browser, and that is where a value's reach is not something the tests answer.
Both result files are judged in one call, because an acceptance that matches nothing is a failure -
checked separately, every Python acceptance would go stale against the JavaScript results.

### Recorded acceptances

A few alerts describe the privilege contract working as designed: `PRIVILEGE.md` requires the
config repository and the published releases to be root-owned and group-readable by the identity
that must read them, which CodeQL reports as an overly permissive mask. Tightening those modes
would lock the worker and the nodes out of the trees they exist to read.

Such a finding is not suppressed in the source - an inline suppression tells the next reader the
query was wrong - but recorded in [`../tools/codeql-accepted.json`](../tools/codeql-accepted.json)
with the reason and the date the decision was taken. Every entry is printed on each run, so the
decision stays visible instead of becoming silence.

An entry matches on rule, file and the exact message text. It carries no line number, which would
have to be rewritten whenever the file moved a line, and the message text keeps a group-readable
acceptance from covering a world-readable finding in the same file. An entry that matches nothing
fails the gate: an acceptance whose finding is gone has stopped being a decision and become a hole.

Accepting a finding is a decision about the privilege contract, not a way to reach a green gate.
Anything that is not the contract working as written is fixed in the code.

## GitHub repository settings

Before the first push, create the repository secret `HAPROXY_MANAGER_DENYLIST`. When the repository
becomes public, enable GitHub CodeQL default setup and secret scanning/push protection. Revisit the
private-denylist job before accepting pull requests from forks, because GitHub deliberately does
not expose repository secrets to untrusted fork workflows.
