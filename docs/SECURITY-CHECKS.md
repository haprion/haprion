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
5. `tools/run-codeql` performs the heavier CodeQL Python `security-extended` analysis before the
   first push and before releases.

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
./run-checks
```

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
result directory, uses the Python `security-extended` suite, and fails if the SARIF contains any
alerts. Source snippets are not printed by the final gate summary.

## GitHub repository settings

Before the first push, create the repository secret `HAPROXY_MANAGER_DENYLIST`. When the repository
becomes public, enable GitHub CodeQL default setup and secret scanning/push protection. Revisit the
private-denylist job before accepting pull requests from forks, because GitHub deliberately does
not expose repository secrets to untrusted fork workflows.
