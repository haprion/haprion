# Installing the web platform

Two steps, both on the management host. They are separate from the five CLI
steps one directory up, and deliberately so: the CLI is the authoritative engine
and installs and runs without any of this. A management host that only ever uses
the command line never needs the platform at all.

Run them after the CLI installation, with the same answers file:

```bash
sudo ./01-platform-prepare ../answers.env
sudo ./02-platform-database ../answers.env
sudo ALEMBIC_BIN=/path/to/alembic ./migrate ../answers.env
sudo ./03-verify ../answers.env
```

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

## What these steps do not do

They install no application code and start no service. There is no release to
install yet.
