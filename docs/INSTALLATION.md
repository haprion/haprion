# Versioned CLI installation

The management CLI is installed independently of the application data filesystem. Source and
development environments may live under `/apps`, but an installed CLI release lives under
`/opt/haproxy-mgmt` so recovery and diagnostics remain available if application storage is not.

## Runtime baseline

The host provides:

- Python 3.12 or newer at `/usr/bin/python3`
- the operating-system PyYAML package, major version 6

Application code is installed from a wheel. It is never imported from a checkout, editable
environment, developer-owned virtual environment, or other path under `/apps`.

## Build and install

Run the complete repository gate before producing the wheel. Build into a protected staging
directory outside the repository and record its SHA-256 digest:

```bash
python -m build --wheel --outdir /path/to/protected/staging
sha256sum /path/to/protected/staging/haproxy_manager-*.whl
```

Install the absolute wheel path with the digest printed by the previous command:

```bash
sudo /usr/bin/python3 tools/install-release.py \
  --wheel /path/to/protected/staging/haproxy_manager-0.1.0-py3-none-any.whl \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The installer fails closed unless it runs as root and the supplied digest matches. It also rejects
unsafe wheel members and entry points, verifies the runtime baseline and imports, then installs:

```text
/opt/haproxy-mgmt/
├── current -> releases/<version>-<wheel-hash-prefix>
└── releases/
    └── <version>-<wheel-hash-prefix>/
        ├── INSTALLATION.json
        ├── bin/
        └── lib/
```

Release directories are `root:root`, directories and launchers are mode `555`, and other files are
mode `444`. The `current` link is replaced atomically only after the new release passes validation.
Short stable wrappers and exact sudoers rules may point into `current/bin`; they must never point
into the source checkout.

## Rollback

Re-run the same installer with the retained previous wheel and its recorded digest. An already
installed matching release is verified and `current` is atomically switched back. Releases are not
deleted automatically, which keeps rollback independent of the source checkout and application
storage.
