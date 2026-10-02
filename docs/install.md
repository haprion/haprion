# Installing HAProxy Manager

These are the steps for a first installation of the application: the CLI engine and the
optional web interface. Configuration, usage, administration and maintenance are in the
[user manual](user-manual.md).

## Requirements

On the management host, install:

- a Linux distribution with systemd and Python 3.12 or newer at `/usr/bin/python3`
- `python3-yaml` (major version 6), `python3-nacl` (major version 1) and
  `python3-psycopg` (major version 3)
- `git`, `rsync`, `openssh-client` and `sudo` supporting no-argument rules
- for the web interface: PostgreSQL 16 or newer, nginx and `uv`

Have the source tree, a wheel built from the selected commit and the matching node bundle
available. The scripts use an answers file; its example includes `UV_BIN` and `ALEMBIC_BIN`,
which must name the installed build and migration tools.

HAProxy nodes must already be prepared before the application can manage them. The
[node preparation instructions](user-manual.md#part-2--the-nodes) are in the manual.

## 1. Prepare the answers file

From the source tree's `install/` directory:

```bash
cp answers.example.env answers.env
$EDITOR answers.env
```

Fill in the paths, accounts, database, cluster names and the interface's `SERVER_NAME` for
your installation. The file is described in [install/answers.example.env](../install/answers.example.env).

## 2. Install the CLI engine

Build from a clean, committed source tree that has passed the repository checks. From the
source-tree root, build the wheel into a protected directory outside the repository:

```bash
python -m build --wheel --outdir /path/to/protected/staging
sha256sum /path/to/protected/staging/haproxy_manager-*.whl
```

Build the matching node bundle from the same commit and record the digest it prints:

```bash
tools/node-bundle.py build \
  --source "$(pwd)" \
  --output /path/to/protected/staging/haproxy-manager-node-0123456789ab.tar.gz
```

Install the wheel and bundle, using their actual absolute paths and SHA-256 digests:

```bash
sudo /usr/bin/python3 tools/install-release.py \
  --wheel /path/to/protected/staging/haproxy_manager-0.1.0-py3-none-any.whl \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --node-bundle /path/to/protected/staging/haproxy-manager-node-0123456789ab.tar.gz \
  --node-bundle-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

## 3. Install the manager configuration and keys

From `install/`:

```bash
sudo ./01-manager-prepare answers.env
sudo ./02-manager-config answers.env
sudo ./03-manager-keys answers.env | tee keys.txt
```

Install the public-key lines printed by step 3 on the corresponding prepared nodes,
following [install/README.md](../install/README.md#step-4--each-node). Keep private keys
on the host that generated them.

Check the manager installation from `install/`, as your normal account:

```bash
./05-verify answers.env
```

For a command-line-only installation, the application is now installed.

## 4. Install the web interface

Use the same answers file. From `install/platform/`, prepare the application, migrate its
database and verify the candidate before activating it:

```bash
sudo ./01-platform-prepare ../answers.env
sudo ./02-platform-database ../answers.env
sudo ./install-ui-release --prepare ../answers.env /path/to/source-tree
sudo ./migrate ../answers.env --release <release-id>
sudo ./03-verify ../answers.env
sudo ./check-compatibility ../answers.env --release <release-id>
sudo ./install-ui-release ../answers.env /path/to/source-tree
sudo ./04-platform-service ../answers.env
sudo ./05-platform-nginx ../answers.env
sudo ./07-platform-services ../answers.env
sudo ./check-compatibility ../answers.env
```

Use the release ID printed when the candidate was prepared. Before step 7, ensure the
`clusters` list in the generated `ui.toml` names the configured clusters.

The first activation creates the `admin` account if no account exists and asks for its
password at the terminal. If installation ran without a terminal, create it afterwards:

```bash
sudo haproxy-ui-user -e prod init-admin
```

## 5. Install optional components

Run the installers for the components your installation needs, from `install/platform/`:

| Component | Installer |
|---|---|
| Platform database backups | `sudo ./06-platform-backup ../answers.env` |
| History and metrics retention | `sudo ./11-platform-retention ../answers.env` |
| Traffic-log collection | `sudo ./13-platform-traffic-collector ../answers.env` |
| Certbot and DNS plugins | `sudo UV_BIN=/path/to/uv ./14-platform-certbot ../answers.env /path/to/source-tree` |
| Certificate and provider sealing keys | `sudo ./15-platform-dns-keys ../answers.env /path/to/source-tree` |
| OpenID Connect helper | `sudo ./17-platform-oidc ../answers.env /path/to/source-tree` |

The SCEP client uses a separately built and verified bundle:

```bash
sudo ./16-platform-scep /path/to/bundle.zip <verified-bundle-sha256>
```

See [install/platform/README.md](../install/platform/README.md) for each component's
installation inputs and follow-up setup.

## 6. Verify access

Open `https://<SERVER_NAME>` and sign in with the administrator account created during
installation. If no certificate was supplied, the nginx installer generates a self-signed
one and the browser asks you to accept it.

If an installation step fails, correct the error it reports and rerun that step.
The installation scripts support repeated runs.
