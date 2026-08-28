# Installing the web platform

Two steps, both on the management host. They are separate from the five CLI
steps one directory up, and deliberately so: the CLI is the authoritative engine
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
