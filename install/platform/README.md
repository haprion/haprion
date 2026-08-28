# Installing the web platform

Two steps, both on the management host. They are separate from the five CLI
steps one directory up, and deliberately so: the CLI is the authoritative engine
and installs and runs without any of this. A management host that only ever uses
the command line never needs the platform at all.

Run them after the CLI installation, with the same answers file:

```bash
sudo ./01-platform-prepare ../answers.env
sudo ./02-platform-database ../answers.env
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

## What these steps do not do

They install no application code and start no service. There is no release to
install yet, and the database has no tables — the schema arrives as migrations.
