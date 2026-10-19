# Security and quality checks

The repository has complementary gates. No single scanner replaces the others.

1. `tools/secret_scan.py` rejects generic secret material, non-documentation IP addresses, and
   environment-specific values from a mandatory private denylist.
2. `tools/run-gitleaks` scans the worktree and, once commits exist, the complete Git history using
   Gitleaks' credential patterns. `.gitleaks.toml` keeps Gitleaks' own rules and lists the fixed
   strings that are not secrets, each with what it is and why a rule meets it, as narrow as the
   string itself. The pre-commit scan reads the same file.
3. `run-tests` verifies Shell scripts with ShellCheck, GitHub Actions syntax with actionlint and
   security posture with zizmor, Python lint/format with Ruff, and types with strict mypy.
4. The same command measures branch coverage with a non-regression floor, runs unit and frozen
   contract tests, builds both sdist and wheel, imports the installed wheel from an isolated target,
   and runs `pip-audit` against the locked active environment (the project itself, installed
   editable and not published, is skipped). The interface's dependencies are audited from
   `ui/uv.lock`, and the certbot environment's from `certbot/uv.lock`, both with `uv audit --locked`,
   which needs `uv` on `PATH`.
5. `tools/run-codeql` performs the heavier CodeQL `security-extended` analysis, Python and
   JavaScript, before the first push and before releases.
6. `ui/run-tests` runs the interface's own suite and type checking in the environment holding its
   dependencies, including the browser suite that drives the traffic chart in a real Chromium -
   `PLAYWRIGHT_BROWSERS_PATH` must name where the browsers are installed, and the gate refuses to
   start without it. `run-tests` runs the same suite and type check rather than skipping them: a
   gate that passes because it could not import what it was meant to check is not a gate. Both need
   `HAPRION_UI_PYTHON` and fail closed without it. The engine's and the interface's test modules
   run through one pool, one module per process (`tools/run_test_modules.py`), heaviest first by
   the previous run's timings; each module's coverage is combined before the report.
   `run-checks` then runs the interface's migrations and database tests against a disposable
   PostgreSQL cluster (`ui/tools/test-database`, below), and fails without PostgreSQL installed.
7. `install/platform/03-verify` checks the database privilege surface against the running database,
   in both directions. It is a deployment check rather than a repository one, so it is not part of
   `run-checks` — but it belongs to the same family, and the reason it checks both directions is in
   [`user-manual.md`](user-manual.md#verifying-it).
8. `install/platform/check-compatibility` reads the separately installed CLI, UI, schema, service
   processes, sudo rules and node package metadata as one result. It changes nothing and fails on an
   unknown compatibility level rather than assuming an older component is usable.
9. `install/platform/update-platform-release` applies those checks to a prepared candidate before
   it migrates or activates anything, and proves the running release accepts the target schema so
   the automatic UI rollback remains a supported combination.

A release wheel is installed only by `tools/install-release.py` with an explicitly supplied
SHA-256 digest. The installer rejects path traversal, symlinks, special files and unexpected entry
points before activating a root-owned, read-only release. See [`install.md`](install.md).

### The scanner exists twice, deliberately

`tools/secret_scan.py` is what `run-checks` and CI run. The pre-commit hook runs a **separate copy
outside the repository**, and that duplication is defence rather than drift: a scanner that lives in
the tree it scans can be weakened by the very commit it is meant to inspect.

Everywhere else in this project two implementations of one rule are a defect. Here the out-of-tree
copy is authoritative for commits, which means a change to the scanner's rules has to be made in
both — and the hook refusing a commit that only changed the in-tree copy is the mechanism working,
not a problem to route around.

The private denylist is never stored in this repository. Local runs provide its path through
`HAPRION_SECRET_RULES`. GitHub Actions reconstructs it in a mode-600 temporary file from
the required repository secret `HAPRION_DENYLIST`. The repository-secret value is the
Base64 encoding of the complete file, used as a transport encoding so tabs and line endings remain
exact. A missing or invalid value fails CI closed.

## Local quick gate

Create the locked editable environment and pinned standalone tools once:

```bash
./tools/bootstrap-dev
```

Then run:

```bash
export HAPRION_SECRET_RULES=/path/to/private.rules
export PATH="$PWD/.venv/bin:$PWD/.tools/shellcheck/0.11.0:$PWD/.tools/actionlint/1.7.12:$PATH"
export GITLEAKS_BIN="$PWD/.tools/gitleaks/8.30.1/gitleaks"
export HAPRION_UI_PYTHON=/path/to/ui-environment/bin/python
./run-checks
```

The interface has a second locked environment, because it has a second lockfile:
`ui/uv.lock`. `HAPRION_UI_PYTHON` points at it, and the gate refuses to run without it rather than
quietly leaving the interface unchecked.

## Disposable database integration gate

Cursor imitations catch query shape, but they do not execute migrations, PostgreSQL permissions,
partition routing or SQL semantics. `run-checks` therefore runs the real-database gate on every
run, in CI as well, and fails when PostgreSQL is not installed rather than skipping it. It can
also be run on its own:

```bash
HAPRION_UI_PYTHON=/path/to/ui-environment/bin/python ui/tools/test-database
```

The command must run as the developer, not root. It finds the installed PostgreSQL tools through
`pg_config`, or in `HAPRION_PG_BINDIR` where more than one major version is installed (CI names
18, the version installations run), creates a private temporary cluster under `TMPDIR`, listens only on a Unix socket in
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
| `app_collector` | no | fixed contract role with traffic-log `INSERT` only |
| `hm_test_web` | yes | inherits only `app_web`; exercises browser-facing SQL |
| `hm_test_worker` | yes | inherits only `app_worker`; exercises job SQL |
| `hm_test_poller` | yes | inherits only `app_poller`; exercises cache and metric writes |
| `hm_test_collector` | yes | inherits only `app_collector`; exercises traffic-log ingestion |

PostgreSQL's bootstrap superuser exists only inside the disposable cluster and is used only to
create those roles and the database. Application queries are tested through the corresponding
login role. Add integration cases to `ui/tests/test_database_integration.py`; they are skipped by
the ordinary unit suite unless the harness supplies its private socket and role variables. Never
set those variables by hand against an installed database.

`uv.lock` is committed and CI installs it with `uv sync --locked --group dev`; a stale lockfile
therefore fails instead of being silently refreshed. The local project is installed editable, so
tests do not depend on an implicit `PYTHONPATH`.

## Installation gate

The unit suite runs on a developer's machine, which has every tool the packages need for other
reasons. A release's packages are therefore installed the way an operator installs them, on
machines that have only systemd and sshd, before they go anywhere else:

```bash
tools/install-test --packages /path/to/release-packages --distribution all
```

The command runs as the developer, with rootless podman. For each of Debian 13 and Ubuntu 26.04 it
starts a manager and two nodes on a private network with RFC 5737 addresses, installs the CLI, UI
and node packages with apt, runs `haprion-setup`, step 3 and `04-node-prepare`, pastes the key
lines, creates a cluster with `haprion-cluster add`, publishes an object and deploys it. It then
checks what an operator would: keepalived and HAProxy running on both nodes, the virtual address on
exactly one, the object answering there, the address moving when its holder's keepalived stops and
staying where it went when it comes back, and a second deploy that changes nothing. The first step
that does not hold stops the run with its output; every machine's output and journal are kept in
the logs directory. `--keep` leaves the machines running for a look inside.

Not covered: syslog objects' IPVS (a rootless container may not load the kernel table), certbot's
environment (it downloads from pypi.org) and the web pages, whose root helpers the CLI drives the
same way.

`tests/test_package_commands.py` is the quick half in the ordinary suite: it reads every script a
package carries and every module the engine imports, and fails when one names a package the
package does not depend on.

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
own scripts under `ui/src/haprion_ui/static` in JavaScript, each against its `security-extended`
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

The second kind of entry is a redirect whose value CodeQL calls user-provided. The interface
answers a form with a 303 back to the page it was on, and some of those carry an identifier the
person acted on, so the page can land on that row. CodeQL does not follow the allowlist check that
far. Such an entry is accepted only when both halves are written down and checkable: the value has
passed a `fullmatch` against a pattern that admits no slash, colon, query or fragment character
before the redirect is built, and it is appended to a literal path, so it can neither begin the
target nor add a parameter. The entry names the pattern and the prefix, so a later reader can
re-check both.

Accepting a finding is a decision about one of those two contracts, not a way to reach a green
gate. Anything that is not a contract working as written is fixed in the code.

## GitHub repository settings

Before the first push, create the repository secret `HAPRION_DENYLIST`. When the repository
becomes public, enable GitHub CodeQL default setup and secret scanning/push protection. Revisit the
private-denylist job before accepting pull requests from forks, because GitHub deliberately does
not expose repository secrets to untrusted fork workflows.
