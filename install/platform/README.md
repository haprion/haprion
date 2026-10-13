# Installing the web platform

Numbered steps and the release commands beside them, all on the management host. They are
separate from the five CLI steps one directory up, and deliberately so: the CLI is the authoritative engine
and installs and runs without any of this. A management host that only ever uses
the command line never needs the platform at all.

They come with the `haprion-ui` package, under
`/usr/share/haprion-ui/install/platform/`, and the package unpacks its release
under `/opt/haprion-ui/releases/<release-id>` (the id is printed when it is
installed). Run them after the CLI installation, with the same answers file or
none - every step then uses the defaults in `../defaults.sh`. `haprion-setup`
one directory up runs the whole sequence in order:

```bash
sudo apt install ./haprion-ui_<version>_amd64.deb
cd /usr/share/haprion-ui/install/platform
sudo ./01-platform-prepare /path/to/answers.env
sudo ./02-platform-database /path/to/answers.env
sudo ./migrate --release <release-id>
sudo ./03-verify
sudo ./check-compatibility --release <release-id>
sudo ./install-ui-release <release-id>
sudo ./04-platform-service /path/to/answers.env
sudo ./05-platform-nginx /path/to/answers.env
sudo ./07-platform-services /path/to/answers.env
sudo ./check-compatibility
```

The last check reads the real worker and poller processes, so it comes after step 07.

Steps 11, 13, 14 and 15 are optional and come after them:

```bash
sudo ./11-platform-retention /path/to/answers.env
sudo ./13-platform-traffic-collector /path/to/answers.env
sudo UV_BIN=/path/to/uv ./14-platform-certbot /path/to/answers.env /usr/share/haprion-ui
sudo ./15-platform-dns-keys /path/to/answers.env /usr/share/haprion-ui
```

Step 11 keeps the job table bounded. Separate from the backup step because it is
the only thing here that touches rows in a live table, and it deletes nothing
itself: it reports what the first run would remove and leaves that to the timer.

Step 13 mirrors each node's structured traffic log onto this host and imports it
into daily PostgreSQL partitions. It fetches nothing until
each node has accepted the key it prints. The nodes are the cluster file's; with
no cluster yet the collector starts with none, and adding a node adds it.

Step 14 builds the locked certbot environment - certbot and every DNS plugin
the web interface offers - under `/opt/haprion-certbot`, proves it with the
profile-aware dry-run renewal wrapper, and moves renewal onto it. Rerun with a newer lock to upgrade;
the previous release is restored if the dry run fails.

Step 15 makes the key pair that seals DNS provider credentials between the web
interface and the root helper: private key under `/etc/haprion/ui-secrets/`,
public key under `/etc/haprion/dns-profile-keys/`, never overwritten. It names
the public key in `ui.toml` when that file names none. Run before step 2 of the
manager installation, as `haprion-setup` does, it has that step name the private
keys in the runtime policy too.

The order is not arbitrary. A release is first prepared without moving `current`.
Its own immutable migration bundle prepares the schema, and its compatibility is
checked before it becomes active. Only then is the release activated and checked
again with the real running processes. The schema has to exist before the service
starts, because a service that starts against an empty database reports itself
healthy and fails at the first request.

The final compatibility check is read-only. It reports the running UI and CLI
releases, database revision, actual service processes, exact worker/poller sudo
rules and every node package. Its verdict uses compatibility levels shipped by
the running UI rather than requiring unrelated release hashes to be equal.

After the first installation, installing a newer package is the whole update:
its `postinst` runs the coordinated update command with the release it carries,
and an operator can run the same command again by hand:

```bash
sudo apt install ./haprion-ui_<version>_amd64.deb
sudo ./update-platform-release <release-id>
```

It reads no answers file. When it fails, the package is left unconfigured and
the previous release is the one running.

**Which pieces a change releases at all, and in what order, is decided in
[`docs/user-manual.md` — Releasing a change](../../docs/user-manual.md#releasing-a-change).**
Read it before running this command. In short: a commit that changes both the
management engine and the UI releases the CLI package first — the platform check
compares the independently installed CLI before it activates the UI candidate,
so reversing the order stops the update after it has already migrated. A change
confined to the UI needs only the applicable platform updates; rerun optional
installers such as retention only when their installed files actually changed.

It prepares the candidate without moving `current`, checks the independently
installed CLI, helpers and node packages, proves that the running UI can tolerate
the candidate's target schema, migrates from the candidate's own bundle, verifies
database privileges, activates, and checks the real processes. A failure after
the symlink moves invokes the installed rollback command and proves the restored
installation before it reports failure. After a proved update it prunes old
releases: ten stay
(`RELEASES_KEPT` in the answers file overrides, minimum two), always including
the release just activated and the one it replaced.

## Step 1 — the filesystem

Creates the release layout and the directories that outlive a release, each
where Debian puts its kind:

```text
/opt/haprion-ui/releases/<version>-<commit>/   the releases, and current
/etc/haprion/ui.toml                           root-owned, readable by the platform group
/etc/haprion/ui-secrets/                       root-only, granted one file at a time
/var/lib/haprion-ui/dumps/                     database backups, root-only
/var/lib/haprion-ui/logs/                      the traffic-log mirror (step 13)
```

Configuration, secrets and data live *outside* the releases, because a release
is replaced wholesale and rolled back by pointing `current` somewhere else;
anything that must survive that cannot live within it. The places are fixed,
not answers. What grows with traffic belongs on a volume of its own, mounted at
`/var/lib/haprion-ui` rather than configured elsewhere — see
[Where the data lives](../../docs/user-manual.md#where-the-data-lives).

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

Run it after the package has unpacked a release, and only then.
`./migrate --release <release-id>` reads that release's migrations; without
`--release` it reads those of the release `current` points at, so the schema
always comes from a named delivery.

**Alembic travels with the release, outside the services' environment.** It is
installed under `migration/lib` beside the migrations it applies, from the same
lock, and run by the release's own interpreter. The services' venv has no
schema tool on its path; the role a service connects as is what forbids DDL in
any case.

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
role cannot edit or delete the audit trail, cannot rename an account, change
its kind or date it, cannot set the OIDC provider's revision, and cannot
backdate a session; the worker cannot read the audit trail; the poller can
neither read accounts nor write audit. Those are the ways the separation could
be lost with nothing looking wrong.

## Installing a release

`./install-ui-release --prepare <release-id>` checks an unpacked release without
activating it. After its migration and candidate compatibility checks, rerun
the command without `--prepare` to activate that already verified release.

**A release is a commit.** The package is built from one commit
(`tools/build-ui-package.py`), and the release is named after it, so reading the
`current` symlink answers "what is running", and answers it the same way in a
year. Nothing is built on the management host.

The release directory holds a virtual environment with both distributions
installed non-editably and the matching Alembic environment under `migration/`.
The services cannot invoke Alembic, but an operator can prepare exactly the schema
that the named release expects before moving `current`.

**It is built at its final path**, in a container of the target distribution. A virtual
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
sudo ./check-compatibility
```

The local install steps each prove their own result. This command answers the
different question: whether the independently installed results work together.
It changes nothing and contacts nodes only through the existing status path.

`COMPATIBLE` requires the database revision accepted by the running UI, an
installed CLI engine API new enough for that UI, every helper named by the UI,
the exact worker and poller sudo rules, all three services executing from the
current UI release, and node packages at a sufficient API level whose recorded
script digests still match. The release IDs are printed for diagnosis but are
not compared for equality; a UI-only correction must not force an unrelated CLI
or node rollout.

Before activation, name a prepared release explicitly. The check then reads that
candidate's requirements and omits only the process check, because the processes
correctly still run the previous release:

```bash
sudo ./check-compatibility --release <release-id>
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

## Step 11 — retention

`./11-platform-retention` installs `haprion-retention` and a daily timer.

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
The audit trail is kept for two years: the job rows are the queue's working
copy, the audit trail the record of what happened.

It also creates metric partitions, writes the hourly pool rollup and only then
prunes raw metric partitions. Revision `0021` records the continuously completed
rollup boundary, and pool raw data is retained until the boundary plus a safety
day proves it replaceable. `report` shows the boundary without changing it.
Listener metrics have no rollup and retain their fixed seven days.

The metrics page reads windows longer than a day from per-hour sums
(`metric_frontend_hour_delta`, `metric_backend_hour_delta`, revision `0055`),
kept by a trigger as samples arrive and not partitioned. Revision `0055` filled
the pools' older hours from the rollup once; the page no longer reads the
rollup. The timer deletes hours older than 31 days, one more than the longest
window.

Traffic logs follow the separate `[traffic_logs].retention_days` setting. The
same privileged timer creates upcoming daily partitions and drops only complete
partitions older than that boundary; application roles never receive `delete`.
The WAF page's per-hour counts (`waf_finding_path`, `waf_finding_client`,
revision `0054`) are kept by a trigger as matches are imported and are not
partitioned; the timer deletes their hours before the same boundary.

## Step 4 — the service

`./04-platform-service` installs the unit from the example, starts it, and then
**fetches `/healthz`**. The unit runs `/usr/sbin/haprion-web`, which asks the
current release for its package and reads the port from `ui.toml`, so the unit
is the same file for every release; `update-platform-release` installs it again
before it activates a release. systemd reports a unit as active as
soon as the process is up, which is before it has reached its database; "up but
unable to answer" is exactly the state worth catching during an installation.

The health endpoint answers with the identity the database reports back, not the
one the process believes it has. Running as the wrong role otherwise looks
exactly like running correctly, until something is denied — or allowed.

The example `ui.toml` has management writes on; a file without the line reads
as off. That flag lives in `/etc/haprion/ui.toml` rather than in a release, because
turning it off is the documented rollback for the write path, and that should
not require a build.

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

The site includes `/etc/nginx/snippets/haprion-receivers.conf`, the
file `haprion-cert-receiver` writes its `https` receivers' `location` blocks
into. The step creates it empty when it is absent and never touches an existing
one, so a rerun does not take the receivers with it.

**If no certificate pair exists it generates a self-signed one**, so the UI is
encrypted from the first login. The session cookie is `Secure` and is therefore
never sent over plain HTTP; running without TLS is not a weaker setup here, it is
a login that does not work. `TLS_CERT` and `TLS_KEY` in the answers file default
to `/etc/haprion/tls/`; point them at a pair your clients trust and the
self-signed path never runs.

The step finishes by asking three questions of the running system rather than
assuming them: that nginx accepts the config, that `https://$SERVER_NAME/healthz`
actually answers, and that **none of the three application identities can read
the private key**. The last one is a line in the phase gate, and it is checked as
the real installed accounts.

## Replacing the certificate

Not by rerunning step 5. The command it installs owns the pair:

```bash
sudo haprion-tls show
sudo haprion-tls install --cert <file> --key <file>
```

It verifies that certificate and key belong together by comparing public halves,
refuses an expired certificate, installs root-owned `0600`, tests the config, and
restores the previous pair if nginx refuses the new one.

Doing this from the UI is planned for the phase that turns on management writes,
and it will never be a file upload: the web identity must not read private key
material. The shape is a drop directory the poller lists, an admin choosing a
candidate, and a job carrying that candidate's id — the web process chooses
*which*, never *what*.

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

With management writes off the worker claims nothing. That is the state a
rollback returns to, so it has to be a state that runs.

Set `clusters` in `ui.toml` before running this; with an empty list the poller
has nothing to do and says so instead of starting.

The step also installs the web's way to a name lookup:
`haprion-resolve-helper.socket` (`/run/haprion/resolve.sock`, group
`_haprion-web`) and the per-request `haprion-resolve-helper@.service`, a dynamic
user with the network and nothing else. The editor and the preview look a dns
server's name up through it; the web itself reaches only localhost. The CLI
release must carry `haprion-resolve-helper`.

And the web's way to an exportable certificate's key:
`haprion-cert-export-helper.socket` (`/run/haprion/cert-export.sock`, group
`_haprion-web`) and the per-request `haprion-cert-export-helper@.service`, root with a
read-only sandbox and no network. It gives out the key of a registry entry marked
`exportable` and of no other, and writes nothing. The CLI release must carry
`haprion-cert-export-helper`.

## Step 6 — backups that have been read back

`./06-platform-backup` installs `haprion-backup`, a daily dump timer and a
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

`/var/lib/haprion-ui/dumps` still has to be picked up by an off-machine
backup. Nothing there survives losing the host.

## The first account

Nothing can sign in until an account exists, and creating one is a root action
rather than a page the interface offers. `install-ui-release` makes the first
one: on an installation with no account at all it runs
`haprion-user init-admin`, which creates `admin` as a break-glass admin and
asks for its password. Later releases find accounts and do nothing. More
accounts:

```bash
sudo haprion-user add operator --role admin
```

The password is typed at a terminal, twice; there is no flag for passing it as
an argument, because that would put it in the shell history and the process
list.

The package installs the tool as a shim in `/usr/sbin` that
resolves `current` at every invocation, so an application rollback takes the
account tool back with it. It reads
`/etc/haprion/ui-admin.conf`, written by step 2, which names the
database and the role root connects as — the migration role, because no
application role may write the account table.

The same tool handles `reset`, `disable`, `enable`, `unlock`, `revoke`,
`delete`, `break-glass` and `list`. Reset and disable end every session the account has: an account that
cannot sign in again while its cookie keeps working has not been taken back
from anyone.

See [Accounts and signing in](../../docs/user-manual.md#accounts-and-signing-in) for how a session
and the sign-in throttle behave.

## Step 13 — the traffic collector

`./13-platform-traffic-collector` installs a fourth, deliberately small identity
and a timer that asks each node for its own traffic log.

**Manager to node, never the other way round.** The first attempt at this had
the nodes forward their logs to this host over TLS, and a DMZ node correctly
could not open that connection. Nothing here asks for a new network path: the
management host already reaches every node over SSH for configuration, status
and certificates, so this adds one key on a path the product already requires.

**The collector is not one of the three application accounts and joins no filesystem group.**
Its database role can only insert traffic rows; it has no sudo rule and cannot read `ui-secrets/`, `ui.toml`, the dumps or
any other identity's key. What it owns is one SSH key whose far end is a forced
command that can do nothing but return one validated day of one node's traffic
log. The step proves that boundary rather than describing it, with traversal
rather than listing — `ls` fails whether or not an account can reach through a
directory, which is exactly how an earlier privilege slip went unnoticed.

Complete records are imported with PostgreSQL `COPY` into daily partitions. The
web role can only select them, the collector can only insert them, and the
privileged retention timer drops expired partitions. `[traffic_logs]` defaults
to seven days and may be set from 1 to 90 days.

**Host keys are copied, never scanned.** `ssh-keyscan` asks each node who it is
and believes the answer, which is trust on first use wearing a pinning costume.
The step takes the keys this host already accepted for its existing paths, and
refuses to continue if a node is missing from them — the honest fix is to accept
that one deliberately, once, through the path that already exists.

**The dumps beside the mirror are closed by their own mode.** The web account
traverses `/var/lib/haprion-ui` to reach the mirror, and `dumps/` there holds
every session and every audit record in one file, so it is `0700 root` and the
step proves that neither the web account nor the collector can enter it. The
mirror directory is set-group-id so files land in the web account's group: the
collector is not a member of that group and so could not otherwise create a
file the interface can read.

## Step 17 — the OIDC helper

`./17-platform-oidc <answers-file> /usr/share/haprion-ui` prepares sign-in through an
OpenID Connect provider (schema `0041`). The web service reaches localhost and
nothing else, and keeps doing so: every request to the provider goes through
`/run/haprion/oidc.sock` to `haprion-oidc-helper`, which runs as
`OIDC_USER` — an account of its own, not root, in no group, with no sudo rule.

The step makes the key pair the web seals the client secret against: the
private key in `/etc/haprion/oidc/` (the helper's account, 0600, in a
0500 directory), the public key in `/etc/haprion/oidc-keys/`. A second run keeps the
pair; `ROTATE=1` adds one, and the client secret is then saved again. It
installs the socket (group `_haprion-web`) and the per-request service.

The account must exist first: add `oidc: <name>` under `roles` in the identity
policy, render the sysusers fragment and apply it. The CLI release must carry
`haprion-oidc-helper`.

### Optional SCEP client bundle

`16-platform-scep <bundle.zip> <verified-sha256>` installs a reviewed native Certmonger
bundle and its distribution runtime libraries as root. Build the bundle with
`tools/build-scep-client.py`; retain the matching package, complete source, license
and build instructions. The installer refuses a different OS release or architecture
and activates only three client programs, without installing a Certmonger service.
See user-manual.md, 'Preparing Microsoft AD CS / NDES for CSR enrollment', for root policy and provider configuration. This step is
implemented in source; live installation and enrollment remain to be verified.
