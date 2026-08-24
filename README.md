# HAProxy Manager

This repository contains the environment-neutral HAProxy management engine. It is prepared as a
local first-commit candidate; no environment-specific configuration belongs in its history.

Current scope:

- frozen CLI JSON schemas and privilege contract
- strict root-owned runtime policy and cluster configuration model
- generic example configuration
- reusable v1 result envelope helpers
- the internal cluster lookup adapter used by later commands

Real cluster IDs, hosts, addresses, domains, accounts, paths, keys, certificates and HAProxy
configuration never belong in this tree. Runtime configuration stays outside the installed source
package.

## Development

Python dependencies are resolved in the committed `uv.lock`; `.python-version` selects the minimum
supported Python 3.12 for a fresh environment. With uv installed, a fresh checkout can create an
editable project environment and install the pinned standalone checks with:

```bash
./tools/bootstrap-dev
```

The local gate requires that environment plus the private environment denylist outside the
repository:

```bash
PATH="$PWD/.venv/bin:$PWD/.tools/shellcheck/0.11.0:$PWD/.tools/actionlint/1.7.12:$PATH" \
GITLEAKS_BIN="$PWD/.tools/gitleaks/8.30.1/gitleaks" \
HAPROXY_MANAGER_SECRET_RULES=/path/to/private.rules \
./run-checks
```

The gate verifies the lock-aware editable install with secret scanning, Gitleaks, Ruff,
ShellCheck, actionlint, zizmor, strict mypy, branch coverage, unit and frozen contract tests, an
sdist/wheel build smoke test, and a vulnerability audit. CodeQL is the additional heavier
pre-push/release gate documented in `docs/SECURITY-CHECKS.md`.
