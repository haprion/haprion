# Haprion privilege contract v1

This document says who may do what in an installation, and how that is enforced. It describes the
shape of the boundary, not one installation: account names are fixed and listed here, while hosts,
addresses, keys and paths chosen by configuration stay with each installation.

The rule behind every part of it: **a process gets exactly the privileges its job needs, and each
privileged action is a fixed command that checks its own input.** A compromised web process should
be able to do what an administrator signed in to the interface can ask for, and nothing more.

## Identities

The interface runs as three separate operating-system accounts. Sharing one would make a web
intrusion equal to worker access, which is deploy rights.

| Account | What it is | Root helpers it may reach | Private keys it holds | Database role |
|---|---|---|---|---|
| `_haprion-web` | the web interface | four sockets: probe, name lookup, certificate export, sign-in | none stored | `app_web` |
| `_haprion-worker` | runs the jobs the interface queues | fourteen sudo helpers and five sockets (below) | none | `app_worker` |
| `_haprion-poller` | reads status, metrics and listings in the background | four read-only sudo helpers | none | `app_poller` |
| `_haprion-collector` | fetches the traffic log from the nodes | none | one read-only key to the nodes' logs | `app_collector` |
| `_haprion-oidc` | talks to the sign-in provider for the web | is itself the helper behind the sign-in socket | the key that opens the stored client secret | none |
| `_haprion-pull`, `_haprion-cert-pull` | the accounts the nodes fetch releases and certificates from | none | none (the nodes hold the keys) | none |
| human operators | members of `sudo`; the users in `CONFIG_EDITORS` | the operator helpers, through `%sudo` rules; `sudoedit` on declared files, for the users in `CONFIG_EDITORS` | their own | none |

The operators' sudo rules (`/etc/sudoers.d/haprion`) are granted to `%sudo` and never to `%haprion`,
which also holds the worker. On Ubuntu, membership of `sudo` is already full root; the rules only let
the read helpers run without a password. Membership of `haprion` gives read access to the
configuration repositories, the cluster file and the certificate registry.

The name lookup is done by a per-request helper running as a dynamic user with network access and
nothing else; the web process itself reaches only localhost.

### Private keys

No account of the interface can read a certificate's private key or a key that can change a node.
There are four deliberate, narrow exceptions:

- **The traffic collector's key** reaches the nodes' log reader, which can return a node's traffic
  log for one day, or the WAF engine's journal after a cursor, and nothing else.
- **The sign-in helper's key** opens the stored OIDC client secret. It belongs to `_haprion-oidc`,
  an account with no sudo rule and no database role.
- **An exportable certificate.** A registry entry marked `exportable` - for a device installed by
  hand, never connected here - can have its key handed out. A root helper reads it on a socket only
  the web may reach, gives it to the person who asked in that one response, and writes it nowhere.
  Such an entry has no cluster and no receiver, and the mark is set when it is made, so no key
  HAProxy or a receiver uses can ever be exported.
- **A certificate upload.** The web process receives the file a person chose and encrypts it against
  the installation's public key inside that request; only a root helper can open it. The plain key
  exists in the web process for the duration of the request and nowhere the web can read afterwards.
  The promise is *never stored, never readable back* - not *never seen*. It is the same exposure DNS
  provider credentials have. The command-line import keeps the key off the web entirely, and a
  signing request made on the manager avoids even that exposure: the key is made by a root helper
  and never leaves it.

### Accounts on the nodes

Every node has four service accounts, and the manager holds seven keys that reach them. Each key line
has `restrict` and its own forced command, so a key can run exactly one command and open no shell.

| Node account | Keys from the manager | What they run |
|---|---|---|
| `_haprion-trigger` | config deploy, certificate deploy, server state | fetch and install a release; fetch certificates; drain, maintenance, ready, unblock |
| `_haprion-status` | status, probe | read the node's status; try a health check |
| `_haprion-backup` | state backup | write the node's state archive to the manager |
| `_haprion-logread` | traffic collector | read the traffic log and the WAF journal |

Only the status and probe keys cannot change a node. A fifth account, `_haprion-join`, accepts one
time-limited key once, when a node joins a manager. A node restore authorizes its own one-time key
for root on the target, accepted from the manager's address only, and removes it when the run is discarded or after an hour.

### How the accounts are created

Account names are fixed. Two `sysusers.d` fragments create them - `install/sysusers/haprion.conf` on
the manager and `haprion-node.conf` on each node - and the first installation step on each machine
applies its fragment. The service accounts are locked and have no password. Only the worker is a
member of `haprion`.

Adding a person to `haprion` is left to the administrator, so that installing never creates a local
human account by accident.

## Database boundary

Each service connects as its own PostgreSQL role, and every privilege is granted by name: columns one
at a time for reading and writing, and `delete` on the few tables where a role must remove rows. The
grants are written by the migrations under `ui/migrations/versions/`. `install/platform/03-verify` is
the executable form of this section: it compares every role's column and function privileges with an
expected list in both directions, and tries a set of writes each role must not be able to make. When
the check and this text disagree, the check is right.

| Role | Writes | Reads |
|---|---|---|
| web | jobs (inserts only through the queue's allowlist, plus an admin's answer to a held job); audit events (insert only); sessions; accounts (and deleting one); sign-in attempts and unlocks; drafts and cluster changes; DNS and NDES profiles (encrypted only); feature switches; the sign-in provider and sign-ins in progress; the status endpoint's address list; acknowledgements on *Needs attention*; the getting-started list | what it shows: the caches, metrics, traffic logs, WAF counts (not the raw matches), jobs, audit |
| worker | a claimed job's state, lease and result; audit events; a renamed backend's alias; deleting a removed provider profile; holding the jobs queued before a boot (one function) | jobs, the claim pause, the version listing, the provider profiles it applies |
| poller | the caches it fills from its helpers, the cluster list and its passes, metric samples, the nodes' events and their state, version diffs, the update check, the manager's certificates, the packages waiting in the repository, the search index | what it writes, except the nodes' events, plus the feature switches and the hourly metrics |
| collector | traffic-log rows and WAF matches (insert only) | nothing |

Deleting is granted per table, so it is listed here exactly: the web may delete drafts, accounts,
cluster changes, the status endpoint's addresses, acknowledgements and the getting-started list; the
worker may delete a removed DNS or NDES profile; the poller may delete search entries, the nodes'
event state and waiting packages. No role may delete from the audit trail, the job queue, the sign-in
attempts, metrics or traffic: those are pruned by a root command (`haprion-retention`).

Two boundaries are easy to confuse. An administrator signed in to the interface is held by the
application's checks: role, the write switch, CSRF protection and the queue's allowlist. A compromised
web process is held only by its database role and its account: it could write anything in the web
row above - accounts and drafts included - but not a job's result, not past audit rows, not a cache,
and nothing outside the database its account cannot reach. Everything that changes a cluster still
goes through a job the worker hands to a root helper, and the helper checks the request again.

## Database connections and roles

The services connect over the local Unix socket with peer authentication: the kernel states which
account is connecting, so no service holds a database password.

The migration role owns every object and has no operating-system account; only root is mapped to it.
A service therefore cannot run DDL - it cannot alter a table it does not own - and running a migration
is a deliberate root action. Grants are named against the four contract roles (`app_web`,
`app_worker`, `app_poller`, `app_collector`), never against an account.

The web role says what it wants done and nothing about what happened: it inserts a job's operation,
cluster, payload and idempotency key, while its state, request ID and timestamps come from column
defaults. Its one update on jobs is an admin's answer to a held job (`held_decision`,
`held_decided_by`); the worker acts on that answer. The audit trail is append-only: no role may update
or delete it.

Each role has a `statement_timeout` and an `idle_in_transaction_session_timeout`, so the worker can
never hold a transaction open across a CLI command.

## Filesystem boundary

- Configuration repositories, published releases and the management configuration are root-owned
  and never group-writable.
- The worker gets group read and traverse only where building a candidate requires it. The web and
  the poller are not in that group.
- The certificate distribution trees and the node archives are never readable to an interface
  account. The certificate tree is readable to `_haprion-cert-pull`, which the nodes fetch as.
- The traffic log mirror is written by the collector and readable, never writable, by the web.
- Git trusts each repository by an explicit `safe.directory` entry; wildcard trust is never used.

## Helper boundary

A helper is a root-owned executable, not writable by group or others, that does one kind of
privileged action. It uses absolute paths and a fixed environment, and fails closed. No helper takes
a path or shell text from its caller.

Helpers take no arguments, so a sudo rule can name the helper exactly with no wildcard. Each reads
one JSON request on stdin within a deadline: a helper that answers one operation reads a single
line, and one that answers several on one socket or rule - the backup job, node, node restore and
server state helpers - reads to the end of its input, which the caller closes, so it can see which
operation is asked before it holds the request to that operation's parameters. The helper checks the
operation, cluster ID, request ID, expected target and every value before it looks anything up in
root-owned configuration.

The common request document is exactly:

```json
{
  "schema_version": 1,
  "operation": "status",
  "cluster": "alpha",
  "request_id": "11111111-1111-4111-8111-111111111111",
  "parameters": {}
}
```

Each helper accepts a fixed set of operations - most exactly one - with an allowlist and a validator
for each operation's parameters. The protocol refuses, before any privileged state is read: arguments,
a request over its size limit (64 KiB, or more for the few helpers that take a whole candidate or a
set of changes), invalid UTF-8, duplicate or unknown fields, trailing input, non-finite numbers,
non-canonical request IDs and malformed cluster IDs.

### The lifeline

`lifeline` is an optional boolean beside those fields. Absent or false, the caller has finished with
stdin and anything after the request is refused - this is how a person at a terminal uses a helper.

Set to true, the caller promises to keep stdin open for as long as the operation runs, and the end of
that stream means the caller has let go. A helper that supports it then stops at its next safe point
and reports what it had done; one that does not support it refuses the request. Anything written to
the stream after the request is refused too.

It exists because the caller cannot stop a helper: the helper runs as root, and the service that
started it may not signal it. Closing a stream needs no privilege, and the kernel closes it even if
the caller dies. Once a helper has read its request, it moves that stream aside and gives itself
`/dev/null` as input, so no process it starts - no `ssh` to a node - inherits it.

### The helpers

| Reached by | Helpers |
|---|---|
| the poller, through sudo | status, inventory, readings, cluster list - read only |
| the worker, through sudo | deploy, certificate deploy, revert, changes publish, certificate issue, publish, target, import, request, delete, NDES enrollment, DNS profile apply, NDES profile apply, server state |
| the worker, through a socket | certificate receivers, backup jobs, node restore, the interface certificate, nodes and clusters |
| the web, through a socket | health probe, name lookup, certificate export, sign-in |

A helper that writes `/etc` - accounts, sshd, nginx - answers on a socket from a unit of its own
rather than through sudo: the worker's sandbox keeps `/etc` read-only, and a helper started through
sudo inherits that sandbox. The certificate helpers are the only worker rules that reach private key
material, and they write it to its targets and never return it.

### Candidate validation

A candidate configuration is checked before it is published, by a helper that takes the files as a
JSON object and no path from its caller. It accepts only the release's own layout: `haproxy.cfg`,
`conf.d/*.cfg`, entries below `maps/`, `keepalived/*.conf`, `crt-lists/*.list`, the WAF engine's
files under `waf/`, `dns/dnsdist.conf` and `rsyslog/forward.conf`. Certificate files are never
caller input. It refuses absolute, escaping, special, oversized, NUL-containing and unknown paths,
then writes the exact accepted bytes itself.

Each certificate the configuration names gets a copy of a dedicated validation certificate instead of
the real one. HAProxy then checks the candidate in a sandbox with no network, no capabilities and an
empty read-only root, into which only the system's programs and the candidate are bound. The copies
are removed before the helper returns; the caller receives only the result, bounded diagnostics and
the candidate's hash.

### On the nodes

Every escalation on a node uses `sudo -n`, so a missing rule fails at once instead of waiting for a
password. The rules are in one file, `/etc/sudoers.d/haprion-node`, one per forced command. Most take
no arguments. The certificate rules (`haprion-cert-pull`, `haprion-cert-remove`) and the server-state
rules (`set`, `unblock`) do: a list of certificate IDs, or a server and state, cannot be expressed in
sudoers more tightly than a wildcard. They are checked twice instead - by the unprivileged trigger
the key runs, and again by the root command.

## Sudo policy

- The web has no sudo rule.
- The poller may run only its four read-only helpers.
- The worker may run only the helpers its job operations need.
- No rule grants a shell, an interpreter, an editor, an arbitrary program, a wildcard path, a
  preserved environment or free arguments - except the node rules described above, whose arguments
  are validated twice.
- The operators' `sudoedit` rules are separate from the services' and name each file in full. A rule
  for a file that has been removed is removed in the same change: `sudoedit` creates a file it does
  not find, so the rule would otherwise be a way to add a root-owned file to a configuration directory.
- Rebuilding the manager itself is outside the product.

## Negative tests

A change to an identity, a helper or a rule is not done until these hold again, tested as the real
installed accounts rather than through mocks:

1. the web cannot read configuration, releases, the cluster file, certificate material, archives,
   secrets or any management SSH key, and an upload is encrypted for root within its request
2. the web cannot run any management helper through sudo
3. the poller cannot read private trees or keys, and cannot run a mutating helper
4. the worker cannot read a private key, PEM, secret or raw archive
5. the worker cannot run a helper it is not given, pass arguments to one, choose a path, use `..`, a
   symbolic link or a special file, or keep its environment
6. helper files and their directories are root-owned and not writable by group or others
7. every helper refuses malformed, oversized, trailing, multi-document and unknown-operation requests
8. each manager key maps to its own forced command on every node
9. each role can do exactly what it is meant to

Where they are checked:

- `install/platform/03-verify` - the database: every role's column and function grants both ways, and
  the writes each role must not make.
- `install/platform/07-platform-services` - the sudo rules, as the real accounts: every helper the
  worker's and the poller's sudoers files grant is asked for with `sudo -n -l` by each of the web,
  worker and poller accounts it is not granted to, and must be refused.
- `install/platform/05-platform-nginx`, `06-platform-backup`, `13-platform-traffic-collector` - no
  interface account can read the interface's TLS key or the database dumps, and the collector cannot
  reach beyond its own files.
- `install/05-verify` - ownership and modes of the cluster file and the policy, the keys exist, and
  every node answers the status key.
- The engine's tests - the request protocol's refusals (7).

Items 1, 3, 4 and 5 are covered in part by the checks above; whatever a change touches beyond them is
checked by hand, as the installed accounts, before it is done.
