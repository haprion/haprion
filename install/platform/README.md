# Installing the web platform

Five numbered steps plus two build helpers, all on the management host. They are
separate from the five CLI steps one directory up, and deliberately so: the CLI is the authoritative engine
and installs and runs without any of this. A management host that only ever uses
the command line never needs the platform at all.

Run them after the CLI installation, with the same answers file:

```bash
sudo ./01-platform-prepare ../answers.env
sudo ./02-platform-database ../answers.env
sudo UV_BIN=/path/to/uv ./install-ui-release ../answers.env /path/to/source-tree
sudo ALEMBIC_BIN=/apps/haproxy-manager/current/venv/bin/alembic ./migrate ../answers.env
sudo ./03-verify ../answers.env
sudo ./04-platform-service ../answers.env
sudo ./05-platform-nginx ../answers.env
```

The order is not arbitrary. The release has to exist before the migrations run,
because the migrations belong to the release being installed; and the schema has
to exist before the service starts, because a service that starts against an
empty database reports itself healthy and fails at the first request.

## Step 1 — the filesystem

Creates the release layout and the directories that outlive a release. Config,
secrets and data sit *beside* the releases rather than inside one, because a
release is replaced wholesale and rolled back by pointing `current` somewhere
else; anything that must survive that cannot live within it.

It also creates the read-only group the three services use to reach
configuration. A shared **group**, where a shared **user** would be the mistake:
one identity for web, worker and poller would make a web intrusion equal to
worker access, which is deploy rights.

## Step 2 — the database

Creates the database and one login role per service. The roles have no
privileges on any table, and they never will be granted them here: a table's
grants belong to the migration that creates the table, so a column's permissions
are versioned with the column and cannot drift from it.

**Nothing authenticates with a password.** Connections come over the local Unix
socket and use peer authentication, where the kernel states which OS user is on
the other end. The service accounts are named after their roles, so they connect
with no configuration at all, and there is no password to leak, rotate, or find
in a process listing.

**The migration role has no operating-system account.** It owns every object in
the database, which is what makes "a service process cannot run DDL" true by
construction rather than by a grant somebody could add later. Running a
migration is a deliberate root action: root is mapped to that role explicitly in
`pg_ident.conf`, and nothing else can reach it.

The step ends by proving both properties rather than assuming them — each
service connects, and each fails to create a table. A role that cannot connect
looks exactly like an application bug, and a role that can create a table looks
like nothing at all until the day it does.

## The migrations

`./migrate` applies them, and it is a deliberate root action rather than
something a service does when it starts. The migration role owns every object,
and no operating-system account maps to it except root, so a service that
restarts cannot alter the schema even by accident.

Run it after installing a release, and only then. `ALEMBIC_BIN` names the
`alembic` of the environment holding that release's dependencies; the connection
is built from the answers file, because a role name is deployment data and does
not belong in the repository.

**Grants live in the migration that creates the table**, named against three
contract roles — `app_web`, `app_worker`, `app_poller` — and never against a
service account. Step 2 connects whatever the accounts are actually called to
those roles. It is also the better design: a second worker later is a
membership, not a migration.

Columns are listed one at a time, including where that is currently every
column. A grant written as the whole table silently widens itself the next time
somebody adds one.

## Step 3 — proving it

`./03-verify` is read-only and can be run whenever. It is deliberately a
**second description** of the privilege surface: the migrations say what to
grant, this says what the result must be, and it compares that against what the
running database reports. Two descriptions would be a defect anywhere else in
this project; here it is the point, because a test that derives its expectation
from the thing it is testing proves nothing.

It also checks the negative half, one line per item in the phase gate — the web
role cannot edit or delete the audit trail, cannot write accounts and cannot
backdate a session; the worker cannot read the audit trail; the poller can
neither read accounts nor write audit. Those are the ways the separation could
be lost with nothing looking wrong.

## Installing a release

`./install-ui-release` builds one and activates it.

**A release is a commit.** The installer refuses a source tree with uncommitted
changes, because a release built from an edited tree is one nobody can
reproduce — and the moment it is running, "what is in it" has no answer. The
release is named after the commit, so reading the `current` symlink answers that
question, and answers it the same way in a year.

The release directory holds one thing: a virtual environment with both
distributions installed non-editably. One directory replaced whole is simpler
than code beside an environment, and it cannot half-update.

**It is built at its final path, never staged and renamed.** A virtual
environment is not relocatable: every console script carries an absolute shebang
naming the interpreter at the path it was built in, and `pyvenv.cfg` and the
activate scripts do the same. Moving it leaves all of them pointing at a
directory that no longer exists, and the service then fails to exec a program
that is plainly there.

**It is built against the system interpreter**, not against a Python that a
build tool downloaded into somebody's home directory. The unit sets
`ProtectHome=yes`, so such an interpreter is invisible to the service and exec
reports it as missing rather than as hidden. Both of these are checked before
`current` is switched — the interpreter must be under `/usr`, and the console
scripts must point into the release — because the symptom is `203/EXEC` and
"no such file or directory", which reads as almost anything else.

Nothing becomes current until the release has been imported successfully **as
the account that will run it**. A release the service cannot read, or that
cannot import its own dependencies, must not be what a restart picks up. The
symlink is then written beside and renamed over, so a service restarting during
the switch finds one release or the other and never nothing.

Rolling back is pointing `current` at the previous release and restarting. The
platform is isolated from the command line, so it never touches HAProxy.

## Step 4 — the service

`./04-platform-service` renders the unit from the example with the answers file,
starts it, and then **fetches `/healthz`**. systemd reports a unit as active as
soon as the process is up, which is before it has reached its database; "up but
unable to answer" is exactly the state worth catching during an installation.

The health endpoint answers with the identity the database reports back, not the
one the process believes it has. Running as the wrong role otherwise looks
exactly like running correctly, until something is denied — or allowed.

The service starts with management writes off. That flag lives in
`config/ui.toml` rather than in a release, because turning it off is the
documented rollback for the write path, and that should not require a build.

## Step 5 — HTTPS

`./05-platform-nginx` puts nginx in front of the web service, which keeps
listening only on `127.0.0.1:8080` in plain HTTP. That leg stays plain on
purpose; it never leaves the host.

This is the **direct address**, and it deliberately does not go through the
HAProxy pair. The UI is what you use to repair that pair, so routing the UI
through it means a broken publish locks you out of the tool that would revert it.
Anything you put in front later is an additional path, never a replacement.

The step is also where the packaged nginx default site is disabled — as a
symlink removal, not a file deletion. It answers on port 80 for any name, which
includes this one.

**If no certificate pair exists it generates a self-signed one**, so the UI is
encrypted from the first login. The session cookie is `Secure` and is therefore
never sent over plain HTTP; running without TLS is not a weaker setup here, it is
a login that does not work. `TLS_CERT` and `TLS_KEY` in the answers file default
to `/etc/haproxy-manager/tls/`; point them at a pair your clients trust and the
self-signed path never runs.

The step finishes by asking three questions of the running system rather than
assuming them: that nginx accepts the config, that `https://$SERVER_NAME/healthz`
actually answers, and that **none of the three application identities can read
the private key**. The last one is a line in the phase gate, and it is checked as
the real installed accounts.

## Replacing the certificate

Not by rerunning step 5. The command it installs owns the pair:

```bash
sudo haproxy-ui-tls show
sudo haproxy-ui-tls install --cert <file> --key <file>
```

It verifies that certificate and key belong together by comparing public halves,
refuses an expired certificate, installs root-owned `0600`, tests the config, and
restores the previous pair if nginx refuses the new one.

Doing this from the UI is planned for the phase that turns on management writes,
and it will never be a file upload: the web identity must not read private key
material. The shape is a drop directory the poller lists, an admin choosing a
candidate, and a job carrying that candidate's id — the web process chooses
*which*, never *what*. See B21 in the decision log.

## Step 6 — backups that have been read back

`./06-platform-backup` installs `haproxy-ui-backup`, a daily dump timer and a
weekly restore check, then runs both immediately. A dump nobody has restored is
a belief rather than a backup, and installation is the cheap moment to find that
out.

Dumps are root-owned `0600` in a `0700` directory, and the step verifies that
none of the three application identities can read one — they hold every password
hash in the installation. The restore test therefore has root open the archive
and hand the descriptor to a `pg_restore` running as `postgres`, so the file is
read without becoming readable to another account.

The check restores into a scratch database it creates and drops itself, compares
row counts against the live database table by table, requires the account table
to be non-empty, and reads one password hash back in full — counts can match
while the contents are unusable.

`/apps/haproxy-manager/data/dumps` still has to be picked up by an off-machine
backup. Nothing there survives losing the host.

## The first account

Nothing can sign in until an account exists, and creating one is a root action
rather than a page the interface offers:

```bash
sudo haproxy-ui-user -e prod add operator --role admin
```

The password is typed at a terminal, twice; there is no flag for passing it as
an argument, because that would put it in the shell history and the process
list.

`install-ui-release` installs the tool as a shim in `/usr/local/sbin` that
resolves `current` at every invocation, so an application rollback takes the
account tool back with it. `-e prod` reads
`/etc/haproxy-manager/ui-admin-prod.conf`, written by step 2, which names the
database and the role root connects as — the migration role, because no
application role may write the account table.

The same tool handles `reset`, `disable`, `enable`, `unlock`, `revoke` and
`list`. Reset and disable end every session the account has: an account that
cannot sign in again while its cookie keeps working has not been taken back
from anyone.

See [`docs/INSTALLATION.md`](../../docs/INSTALLATION.md) §4.6 for how a session
and the sign-in throttle behave.
