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
   the previous run's timings. The engine's modules run under coverage, combined before the report.
   `run-checks` then runs the interface's migrations and database tests against a disposable
   PostgreSQL cluster (`ui/tools/test-database`, below), and fails without PostgreSQL installed.
7. `install/platform/03-verify` checks the database privilege surface against the running database,
   in both directions: the column grants, the functions each role may call, and that no definer
   function is open to every role. It is a deployment check rather than a repository one, so it is not part of
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
export PLAYWRIGHT_BROWSERS_PATH=/path/to/playwright-browsers
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
| `app_collector` | no | fixed contract role that may only insert traffic-log rows and WAF matches |
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
tools/install-test --packages /path/to/release-packages \
    --upgrade-from /path/to/previous-release-packages --distribution all
```

The command runs as the developer, with rootless podman. For each of Debian 13 and Ubuntu 26.04 it
starts a manager and two nodes on a private network with RFC 5737 addresses. It installs the
manager's packages with apt and runs `haprion-setup`; on each node it installs only the node package,
whose installation prints the node's block. It creates the cluster with the first node's block
(`haprion-cluster add`), joins the second with `haprion-node add`, publishes an object and deploys it. It then
checks what an operator would: keepalived and HAProxy running on both nodes, the virtual address on
exactly one, the object answering there, the address moving when its holder's keepalived stops and
staying where it went when it comes back, and a second deploy that changes nothing. The first step
that does not hold stops the run with its output; every machine's output and journal are kept in
the logs directory. `--keep` leaves the machines running for a look inside.

`--upgrade-from` tests the update as well. The previous release's packages are installed on a
second set of machines, with a cluster and an object deployed, and then updated to the new ones with
apt. The run then requires every package configured at its new version, the web answering, a deploy
that succeeds and the object answering, and `haprion-rollback` to the previous release and back with
the web answering after each. A release that cannot be installed over the one before
fails here, not on the operator's manager. `--no-upgrade` tests a new installation only, and has to
be given on purpose.

Not covered: syslog objects' IPVS (a rootless container may not load the kernel table), certbot's
dry-run renewal (it needs a public ACME server) and the web pages, whose root helpers the CLI drives
the same way. Certbot itself is installed and run.

`tests/test_package_commands.py` is the quick half in the ordinary suite: it reads every script a
package carries and every module the engine imports, and fails when one names a package the
package does not depend on.

## Local CodeQL gate

Use the pinned CodeQL bundle documented by the private build environment. Results and the database
must be written outside the repository:

```bash
CODEQL_BIN=/path/to/codeql tools/run-codeql /path/to/new-results-directory
```

The wrapper rejects an output directory inside the source tree - compared as resolved paths, so a
relative path or a symbolic link into the tree is rejected too - refuses to overwrite an existing
result directory, and fails if either SARIF file contains an alert. Source snippets are not printed
by the final gate summary.

Two languages are analysed in one run: the engine and the interface in Python, and the interface's
own scripts under `ui/src/haprion_ui/static` in JavaScript, each against its `security-extended`
suite. Those scripts have no build step and no dependencies, but they are the only code here that
runs inside a reader's browser, and that is where a value's reach is not something the tests answer.
Both result files are judged in one call, because an acceptance that matches nothing is a failure -
checked separately, every Python acceptance would go stale against the JavaScript results.

### Recorded acceptances

A few alerts describe a decision working as designed, and are accepted rather than fixed. Most are
file modes the design requires, which CodeQL reports as an overly permissive mask: `PRIVILEGE.md`
requires the config repository, the published releases and each receiver's certificate directory to
be root-owned and group-readable by the identity that must read them, and a fetch account's `.ssh`
directory and a timer's drop-in directory are readable as sshd and systemd expect. Tightening those
modes would lock out the accounts the trees exist for. The others are each explained in their entry:
the TLS versions the node's health probe allows towards a backend, a password the receiver command
prints once to the operator who asked for it, and the credentials file a certbot DNS plugin reads.

Such a finding is not suppressed in the source - an inline suppression tells the next reader the
query was wrong - but recorded in [`../tools/codeql-accepted.json`](../tools/codeql-accepted.json)
with the reason and the date the decision was taken. Every entry is printed on each run, so the
decision stays visible instead of becoming silence.

An entry matches on rule, file and the exact message text. It carries no line number, which would
have to be rewritten whenever the file moved a line, and the message text keeps a group-readable
acceptance from covering a world-readable finding in the same file. An entry that matches nothing
fails the gate: an acceptance whose finding is gone has stopped being a decision and become a hole.

Without a line number, one entry covers every finding with its message in its file, so each entry
also states how many it covers, and its reason names each of them. A finding of the same kind added
to the same file then fails the gate until it is written into the entry, rather than being
accepted by a reason written for another place. The gate reports every kind of failure before its
verdict, so a stale entry does not hide the findings nobody has accepted.

Accepting a finding is a decision written down, not a way to reach a green gate. Anything that is
not a design working as written is fixed in the code.

## Upstream watch

The WAF packages are built from four pins in `tools/build-coraza-package.py` and
`tools/build-release-packages`: the Coraza SPOA engine (a commit), the OWASP Core Rule Set (an LTS
release), the Go that compiles the engine and the govulncheck that reads it. Every night
`.github/workflows/upstream-watch.yml`:

1. runs govulncheck on the pinned engine and asks OSV about the SCEP client's pinned certmonger
   (`tools/upstream-watch vuln`); a finding opens an issue. A certmonger pin is moved by hand, taken
   where apt checked the distribution's signed index (`tools/build-scep-package.py`)
2. asks upstream what is newer (`tools/upstream-watch check`), verifies it - the rule set's signature
   against `keys/upstream/coreruleset.asc`, the Go archive against go.dev's digest, the engine by the
   commit its release tag names - and rewrites the pins on the branch `upstream-watch`, with one pull
   request open for it. A major update is never written: it opens an issue that needs a decision
3. has that pull request merged once every check on it passed - among them the rule set's own regression
   tests (`tools/crs-regression`: go-ftw through the built engine and rules behind the HAProxy branch
   the nodes run, in the rig the engine's source carries, with its list of tests known to fail
   through HAProxy and ours in `tests/crs-regression.yml`), and the installation test on the latest
   release's packages with the proposal's engine and rules in place of the release's, which is what
   the repository serves once it is merged - each upstream release is two days old, and it is not
   labelled `hold`. The label `no-cooldown` lifts the wait; nothing lifts the major rule.
   The merge on `main` builds and publishes the engine and the rules (`apt-repo.yml`)
4. audits the three Python locks the gate audits - `uv.lock`, `ui/uv.lock` and `certbot/uv.lock` -
   with `uv audit` against OSV (`tools/upstream-watch locks`), and upgrades in its lock every package
   an advisory names a fixed version for (`uv lock --upgrade-package`), on the branch
   `dependency-watch` with one pull request open for it. That pull request is merged once the gates
   and the installation test passed on it, with no wait, unless it is labelled `hold`. An advisory
   no upgrade clears - no fixed version yet, or one the project's own constraints keep out - opens
   an issue; until the lock moves, the gate fails on it on every pull request

What counts as major: for the engine a `0.y` step, for the rule set a new LTS line, for Go a new
line, for govulncheck a new major version.

The merges are `.github/workflows/upstream-merge.yml`'s, every hour, so a proposal goes in within the
hour its checks pass rather than the next night. The same workflow merges Dependabot's updates of the
pinned actions (`.github/dependabot.yml`, monthly, opened once a release is two days old): when every
check on the pull request passed, its commits are Dependabot's and signed, and every update the
metadata in their messages names is a patch or minor one (`tools/upstream-watch dependabot`). A
major update waits for a person, and so does anything labelled `hold`. The workflow's own token
cannot do this: it may never write a workflow file, and an update of the actions is nothing else.

GitHub's schedule is best effort: a run it drops leaves no trace, and a watch that stopped would
say nothing. The CI job *The upstream watch still runs* (`tools/upstream-watch ran`) runs on every
push to `main` and every run by hand, and fails when the workflow is not active or the schedule has not started
it in 48 hours - one dropped night is allowed, two are not - and when the hourly merges have not run
in 12. A run started by hand does not count.
A failed scheduled run is not this job's business: GitHub mails it to whoever last changed the
`cron` line.

The watch writes as a GitHub App, not with the workflow's own token: a pull request that token
opens runs no checks, and a merge it makes starts no workflow. To set it up:

- create a GitHub App owned by the organization, with no webhook, and repository permissions
  Contents, Pull requests, Issues and Workflows read and write, Checks read; install it on this
  repository only
- create the environment `upstream-watch`, deployable from `main` only, holding the variable
  `UPSTREAM_WATCH_CLIENT_ID` (the app's client ID), the secret `UPSTREAM_WATCH_PRIVATE_KEY` (a
  private key generated for the app) and, optionally, the variable `UPSTREAM_WATCH_NOTIFY` (the
  login assigned each pull request and issue, so the maintainer is told when one opens and merges)
- create the labels `hold` and `no-cooldown`

Before setting it up, run the CI workflow by hand (`workflow_dispatch`): the rule set's regression
tests and the installation test run then too, and both should pass on the runner before a merge
waits for them.

## GitHub repository settings

Before the first push, create the repository secret `HAPRION_DENYLIST`. When the repository
becomes public, enable GitHub CodeQL default setup and secret scanning/push protection. Revisit the
private-denylist job before accepting pull requests from forks, because GitHub deliberately does
not expose repository secrets to untrusted fork workflows.
