# Installing the web platform

Five numbered steps plus two build helpers, all on the management host. They are
separate from the five CLI steps one directory up, and deliberately so: the CLI is the authoritative engine
and installs and runs without any of this. A management host that only ever uses
the command line never needs the platform at all.

Run them after the CLI installation, with the same answers file:

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
sudo ./check-compatibility ../answers.env
```

Step 11 is optional and comes after them:

```bash
sudo ./11-platform-retention ../answers.env
```

It keeps the job table bounded. Separate from the backup step because it is the
only thing here that touches rows in a live table, and it deletes nothing itself:
it reports what the first run would remove and leaves that to the timer.

For an isolated dev platform the normal path stops at step 4, though step 11 is
worth running there too. If developers
need a direct browser address rather than an SSH tunnel, give the dev answers
file its own `SERVER_NAME` and run the optional step 9 after its service is up:

```bash
sudo ./09-dev-nginx ../answers-dev.env
```

When realistic production values are useful for UI review, the optional step
10 makes one explicit, root-owned snapshot from production into development:

```bash
sudo ./10-dev-production-snapshot ../answers-prod.env ../answers-dev.env
```

It is deliberately a manual action, not a poller or timer. The development web
and poller accounts receive no production credentials, never contact
production, and can only read the bounded static copy written under the dev
platform's `config/` directory.

The order is not arbitrary. A release is first prepared without moving `current`.
Its own immutable migration bundle prepares the schema, and its compatibility is
checked before it becomes active. Only then is the release activated and checked
again with the real running processes. The schema has to exist before the service
starts, because a service that starts against an empty database reports itself
healthy and fails at the first request.

The final compatibility check is read-only. It reports the running UI and CLI
releases, database revision, actual service processes, exact worker/poller sudo
rules and every node bundle. Its verdict uses compatibility levels shipped by
the running UI rather than requiring unrelated release hashes to be equal.
For a non-production answers file it instead proves the deliberately smaller
development boundary: UI release, database revision and web process. Development
has no worker, poller, sudo rules or node list to check; treating their documented
absence as an incompatibility would make the release path impossible to use there.

After the first installation, use the coordinated update command instead of
running the release and migration helpers separately:

```bash
sudo ./update-platform-release ../answers.env /path/to/source-tree
```

**Which pieces a change releases at all, and in what order, is decided in
[`docs/INSTALLATION.md` — Releasing a change](../../docs/INSTALLATION.md#releasing-a-change).**
Read it before running this command. In short: a commit that changes both the
management engine and the UI releases the CLI wheel first — the platform check
compares the independently installed CLI before it activates the UI candidate,
so reversing the order stops the update after it has already migrated — and
where both environments exist, development goes before production. A change
confined to the UI needs only the applicable platform updates; rerun optional
installers such as retention only when their installed files actually changed.

It prepares the candidate without moving `current`, checks the independently
installed CLI, helpers and node bundles, proves that the running UI can tolerate
the candidate's target schema, migrates from the candidate's own bundle, verifies
database privileges, activates, and checks the real processes. A failure after
the symlink moves invokes the installed rollback command and proves the restored
installation before it reports failure.

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

Run it after installing a release, and only then. The connection is built from
the answers file, because a role name is deployment data and does not belong in
the repository.

**`ALEMBIC_BIN` and `UV_BIN` are answered in the answers file**, beside every
other fact about where things are on this machine. They used to be typed on the
command line each time, which meant getting them wrong each time.

`ALEMBIC_BIN` names the **development** environment's alembic, never a release's:
alembic is a development dependency and a release is built with `--no-dev`, so no
release venv contains it - correctly, because a running service must not be able
to alter the schema it reads. The migration files themselves are copied into the
prepared release and verified against its commit. `./migrate --release` reads that
bundle, so the schema cannot accidentally come from a newer checkout. Alembic is
the tool that applies them rather than application code that serves requests.

An environment variable of either name still overrides the answers file, for the
one-off case of testing a different version.

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

`./install-ui-release --prepare` builds a release without activating it. After
its migration and candidate compatibility checks, rerun the command without
`--prepare` to activate that already verified release.

**A release is a commit.** The installer refuses a source tree with uncommitted
changes, because a release built from an edited tree is one nobody can
reproduce — and the moment it is running, "what is in it" has no answer. The
release is named after the commit, so reading the `current` symlink answers that
question, and answers it the same way in a year.

The release directory holds a virtual environment with both distributions
installed non-editably and the matching Alembic environment under `migration/`.
The runtime cannot invoke Alembic, but an operator can prepare exactly the schema
that the named release expects before moving `current`.

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
the account that will run it**. In the update path it is also migrated and
checked by name while the old processes still run. A release the service cannot
read, or that cannot import its own dependencies, must not be what a restart picks up. The
symlink is then written beside and renamed over, so a service restarting during
the switch finds one release or the other and never nothing.

**An existing web service is always restarted and then health-checked by the
release installer.** A running process has already resolved `current` to its
old interpreter, so merely switching the symlink cannot update the UI. On the
first installation the unit does not exist yet; the installer names that as
pending and Step 4 creates, starts and health-checks it instead.

Rolling back is pointing `current` at the previous release and restarting. The
platform is isolated from the command line, so it never touches HAProxy.

## Checking the whole installation

```bash
sudo ./check-compatibility ../answers.env
```

The local install steps each prove their own result. This command answers the
different question: whether the independently installed results work together.
It changes nothing and contacts nodes only through the existing status path.

`COMPATIBLE` requires the database revision accepted by the running UI, an
installed CLI engine API new enough for that UI, every helper named by the UI,
the exact worker and poller sudo rules, all three services executing from the
current UI release, and node bundles at a sufficient API level whose recorded
script digests still match. The release IDs are printed for diagnosis but are
not compared for equality; a UI-only correction must not force an unrelated CLI
or node rollout.

With a non-production answers file, the same command checks only what that
platform installs: the UI release, database and web process. It also requires
the web account to have no sudoers file. The absent worker, poller, standalone
CLI access and nodes are the development isolation boundary, not skipped
production checks.

Before activation, name a prepared release explicitly. The check then reads that
candidate's requirements and omits only the process check, because the processes
correctly still run the previous release:

```bash
sudo ./check-compatibility ../answers.env --release <release-id>
```

Add `--before-migration` for the earlier prerequisite pass. It checks the current
revision against the running UI and requires that UI to accept the candidate's
declared database head. That second condition is what makes both the live
migration and rollback safe. A schema change the running release does not accept
needs a bridge release which accepts both revisions before the migration release.
After `migrate --release`, rerun without the flag so the candidate's own database
contract is proved before activation.

An old component that predates compatibility metadata is reported as
incompatible rather than guessed compatible. Install that component from the
same delivery, then run the check again. The command does not install, migrate,
restart or deploy anything on its own.

The one schema exception is the first bridge from a UI release with no
compatibility file at all: it may activate only while its declared database
head equals the revision already running. That changes no schema and therefore
needs no claim about what the old release could roll back across. Any actual
schema change still stops until a metadata-bearing bridge is active.

## Step 11 — retention

`./11-platform-retention` installs `haproxy-ui-retention` and a daily timer.

**A root command, because no application role holds `delete` on any table and
none is going to.** The audit trail, the login attempts and the job queue follow
the same rule: a compromised web or worker process must not be able to remove
the record of what it did. The migration role owns the tables and may delete
from them, and the ident map lets only root be that role for this database — a
boundary the step verifies rather than describes.

It removes finished jobs older than seven days. Never a `pending` or `running`
one, however old, because those are the states the single-active-job index rests
on; and never the twenty most recent, because a quiet fortnight would otherwise
empty the jobs page and read as lost history rather than as a quiet fortnight.
The audit trail is untouched: this removes the queue's working copy, not the
record of what happened.

It also creates metric partitions, writes the hourly pool rollup and only then
prunes raw metric partitions. Revision `0021` records the continuously completed
rollup boundary. Readers stay on raw rows when that boundary falls behind their
normal seven-day split, and pool raw data is retained until the boundary plus a
safety day proves it replaceable. `report` shows the boundary without changing
it. Listener metrics have no rollup and retain their fixed seven days.

Its units are named after the environment, unlike the backup step's. Development
runs this step and does not run step 6, so these are the units that would
otherwise collide on a machine carrying both platforms — and two timers pruning
each other's database is a failure that would look like retention working.

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

## Optional step 9 — direct development address

The development service normally remains reachable only through an SSH tunnel.
`./09-dev-nginx` is the deliberate exception for browser review: it requires a
separate `SERVER_NAME` in the development answers file, checks that the name
resolves before changing nginx, and renders a second virtual host to the dev
loopback port. It never changes the production site, production certificate or
the listener of either application.

The step creates a separate TLS configuration and `haproxy-ui-dev-tls` command.
It creates a self-signed development pair when no pair is supplied in
`TLS_CERT`/`TLS_KEY`; install an internal-PKI pair later with:

```bash
sudo haproxy-ui-dev-tls install --cert /path/to/dev-ui.crt --key /path/to/dev-ui.key
```

The name must have a DNS record before the step runs. The separate hostname is
also what prevents a browser from mixing development and production host-only
session cookies.

## Step 13 — traffic logs

Production only, after the UI release is installed:

```bash
sudo ./13-platform-traffic-logging answers.env
```

This creates a dedicated private CA and rsyslog server certificate, publishes
only the CA certificate through the existing read-only node export, installs a
TLS listener and a fixed source-address-to-file mapping, sets 14-day compressed
rotation, and gives only the web identity read access. It also enables the
otherwise inert `[traffic_logs]` section in `ui.toml`.

Install `rsyslog-gnutls` first on Debian/Ubuntu. Then update every node bundle
with `04-node-prepare` and run `sudo haproxy-traffic-log-trust` on each node.
Normal server-certificate renewal uses the same CA and therefore requires no
node update.

## Step 7 — the worker and the poller

`./07-platform-services` installs both as their own accounts, plus the two
exact read-only sudoers rules the poller needs. The rules are validated with `visudo -cqf` in a
temporary file **before** it is installed: a sudoers file that does not parse
takes sudo down for everyone on the machine, including whoever would fix it.

The step then waits for the poller to actually write status and inventory rows rather than
treating an active unit as proof — a service that has started is not a service
that has done its job once. It finishes by asking, as the real accounts, that
the web and worker identities cannot run either metadata helper, that the
poller cannot write a job, and that the web role cannot write either cache.

The worker runs with management writes off and claims nothing. That is the phase
4 state and the state a rollback returns to, so it has to be a state that runs.

Set `clusters` in `ui.toml` before running this; with an empty list the poller
has nothing to do and says so instead of starting.

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
