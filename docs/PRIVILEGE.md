# Haprion privilege contract v1

This contract defines the privilege boundary the installation enforces. It is intentionally
environment-neutral. Production account names, paths selected by runtime configuration, SSH keys,
and sudoers output remain private deployment data.

## Identities

| Role | Production config group | sudo helpers | Private keys | Database write scope |
|---|---|---|---|---|
| web | no | none | none stored; a key in an upload is sealed before the request ends | allowlisted jobs; the interface's own state (sessions, accounts, sign-in attempts, drafts, profiles, switches, sign-in provider); see [Database boundary](#database-boundary) |
| worker | yes, read-only | exact mutation/completion helpers | none | claim, lease, state, result, audit; a renamed backend's alias |
| poller | no | exact read-only metadata helpers | none | poll/cache/metrics and the search index only |
| traffic collector | no | none | one node-log forced-command key | inserts traffic-log and WAF-match rows only |
| human operator | deployment policy | explicit wrappers and `sudoedit` policy | none directly | not used by app |

The traffic collector's key is the one private key an app identity holds: a forced-command key that
can read a node's logs and do nothing else. Apart from it, no app identity owns or can read SSH
private keys, certificate private keys, validation dummy-key material, secret files, or raw backup
archives - with one exception made on purpose: a certificate the registry marks
`exportable`, made for a device that is installed by hand and never connected here. Its key is
read by a root helper on a socket only the web account may reach, handed to the person who asked
in that one response, and written nowhere; the entry has no cluster and no receiver, and the mark
is set when it is made, so no key HAProxy or a receiver uses can ever be exported. The other
qualification is the certificate upload:
the web process receives the file a person chose, seals it against the installation's public key
inside that request, and hands the ciphertext to a job. The plaintext exists in the web process
for the duration of the request and nowhere the web can read afterwards - not the job row, not
the audit. The
root helper is the only thing that opens the box. The promise is therefore *never stored, never
readable back*, not *never seen*; it is the same exposure DNS provider credentials carry, and the
command-line import remains for whoever wants the key to stay off the web entirely. A signing
request made on the manager keeps even that exposure away: the root helper makes the key in the
import store, and what crosses the boundary in either direction is the CSR and, later, the signed
certificate - both public.

Three separate node identities exist, one per thing the manager may ask a node to do: read status,
pull a configuration release, pull a certificate. The status identity is the only one of the three
that cannot change a node, which is what makes it the one a deployment can grant most widely. Each
is a forced command with no argument, and each has its own key; none of them is a login.

### Identity provisioning

Account names are fixed: service accounts are `_haprion-*`, the operators' configuration
group is `haprion`. Two declarative `sysusers.d` fragments create them, `install/sysusers/haprion.conf`
on the management host and `haprion-node.conf` on each node; the first installation step on each
applies its fragment. The web, worker and poller accounts are distinct, locked and no-login; only
the worker is a member of `haprion`.

Human operator membership is deliberately absent from the fragments. It is a separate
administrator action against an already existing human account, avoiding `sysusers.d` semantics
that could implicitly create a missing local account.

## Database boundary

Each service connects as its own PostgreSQL role and is granted columns, not tables. The grants are
written by the migrations under `ui/migrations/versions/`, and `install/platform/03-verify` is the
executable form of this section: it compares every role's column privileges with an expected list
and tries the writes each role must not make. When the two disagree, the check is right and this
text is out of date.

| Role | Writes | Reads |
|---|---|---|
| web | jobs (insert only, through the queue's allowlist, and an admin's answer to a held job); audit events (insert only); sessions; accounts (and deleting one); sign-in attempts and unlocks; drafts and cluster changes; DNS and NDES provider profiles (ciphertext only); feature switches; the sign-in provider and its pending sign-ins; the status endpoint's address list; acknowledgements on *Needs attention*; the getting-started list | everything it shows: the caches, metrics, traffic logs, WAF findings (not the raw matches), jobs, audit |
| worker | a claimed job's state, lease and result; audit events; a renamed backend's alias once its publish is done; deleting a removed provider profile; holding the jobs queued before a boot (one function) | jobs, the claim pause, the version listing, the provider profiles it applies |
| poller | the caches it reads from helpers, each cluster's pass and node list, metric samples, node events and their state, version diffs, the update check, the manager's certificates, its packages waiting in the repository (replaced whole), the search index (and deleting from it) | the same |
| traffic collector | traffic-log and WAF-match rows (insert only) | nothing |

Two boundaries are easy to confuse here. An administrator signed in to the interface is held by the
application's checks: role, write switch, CSRF, and the queue's allowlist of operations. A
compromised web process is held only by its database role and its account: it could write anything
in the web column above - accounts and drafts included - but not a job's result, not the audit
trail's past rows, not a cache, and nothing outside the database that its account cannot reach.
Everything that changes a cluster still goes through a job that the worker hands to a root helper,
and the helper validates the request again.

## Filesystem boundary

- Config repositories, published releases, and management configuration are root-owned and never
  group-writable.
- The worker may receive group read/traverse only where candidate construction or completion proof
  requires it. Web and poller do not join that group.
- Certificate distribution and raw backup trees are never made group-readable to an app identity.
- Traffic-log staging and the collector's SSH identity are private to the collector. Completed
  mirrors and their freshness metadata are collector-owned and group-readable by web, never
  group-writable; web reads those bounded files and cannot alter them.
- Dev identities have no production config group membership and no read access to private
  production trees.
- Git uses explicit repository-specific `safe.directory` entries. Wildcard trust is forbidden.

## Helper boundary

Helpers are root-owned, not group/other writable, use absolute executables, a fixed environment,
and fail closed. The target helper interface has no caller-selected filesystem path or shell text.

Where sudoers argument matching would otherwise require a wildcard, the helper is invoked with no
argv and reads one size-bounded JSON request as a single line on stdin. Sudoers uses the explicit
no-argument form supported by the installed sudo version. The helper validates operation, cluster ID,
request ID, expected target, and all enum values before looking up private paths from root-owned
runtime configuration.

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

`lifeline` is an optional boolean beside those fields. Absent or false, the caller has finished with
stdin and anything after the request is refused, which is how a caller at a terminal uses these
helpers.

Set true, the caller states that it is holding stdin open for the life of the operation, and end of
input on that stream means the caller has let go. A helper that supports it then stops at its next
safe checkpoint and reports what it had done by then; one that does not support it refuses the
request rather than accepting a promise it cannot keep.

This exists because the caller cannot stop the helper. A helper runs as root and the unprivileged
service that starts it holds no `CAP_KILL`, so `kill` is answered with `EPERM`. Closing a descriptor
is the one signal that crosses the boundary without any privilege at all — and it is delivered by
the kernel if the caller dies without running any code. Granting the ability to signal arbitrary
processes, or a helper that kills a caller-supplied process group, would both be broader than the
problem: this model is built on each privileged action being an exact command.

Once its request has been read, a helper with a lifeline moves that descriptor to a private one and
opens `/dev/null` on descriptor 0, so no child of it — every `ssh` to a node included — inherits the
caller's stream.

Each executable compiles in one expected operation and an exact allowlist plus validator for its
operation-specific parameters. The protocol rejects argv, input over 64 KiB, invalid UTF-8,
duplicate or unknown fields, trailing input where no lifeline was declared, non-finite numbers,
non-canonical request IDs, and unrecognised cluster-ID syntax before privileged state is consulted.
Input arriving on a declared lifeline is refused too: the stream is there to be closed, not written
to.

Read-only helper classes:

- status metadata, including the published release the nodes are compared against
- inventory metadata
- version metadata
- backup metadata, never archive contents or absolute paths
- certificate metadata, never PEM or private paths

Mutation helper classes:

- candidate validation using root-only dummy certificate material
- publish/commit/release
- config deploy trigger
- revert/publish
- bounded managed-network publish
- certificate deploy trigger
- operation-specific completion proof

### Candidate-validation helper

Candidate validation accepts no argv and receives the complete candidate as a JSON `files` object.
The only accepted paths are `haproxy.cfg`, one-level `conf.d/*.cfg`, and relative entries below
`maps/`; certificate files are never caller input. The helper rejects absolute, normalised,
escaping, special-purpose, oversized, NUL-containing, and unknown paths, then hashes and
materialises the exact accepted bytes itself using exclusive no-follow file creation.

Only configured certificate IDs receive copies of the dedicated validation PEM. Config references
to the runtime HAProxy map and certificate prefixes are rewritten inside the private candidate.
Validation runs through fixed `systemd-run` argv with no network, no capabilities, a read-only
candidate bind and broad inaccessible private roots. The candidate and dummy PEM copies are
removed before the helper returns; the caller receives only validity, bounded diagnostics and the
candidate hash.

Config deploy, certificate deploy, and status use separate root-owned SSH identities and separate
node-side forced-command mappings. Every node-side sudo invocation uses `sudo -n` and an exact
`NOPASSWD` command rule so a policy mismatch fails immediately instead of attempting an interactive
password path.

## Database connections and roles

The interface's three services connect over the local Unix socket with peer authentication. No
application identity holds a database password, and there is nowhere to put one: each service
account is named after its database role, so the kernel establishes who is connecting.

The migration role owns every object and has no operating-system account. A service process
therefore cannot run DDL by construction rather than by the absence of a grant — you cannot drop a
table you do not own. Running a migration is a deliberate root action, mapped explicitly.

Table grants live in the migration that creates the table, named against three contract roles
rather than against accounts, and column by column rather than table-wide. The web role may state
what it wants done and nothing about what happened: it holds `insert` on the job table's operation,
cluster and payload, while state, request ID and timestamps come from column defaults. Its one
`update` is an admin's answer for a held job (`held_decision`, `held_decided_by`); the worker
changes the job's state when it takes that answer. The audit trail is append-only by grant — no role holds `update` or `delete` on it.

Each role carries a `statement_timeout` and an `idle_in_transaction_session_timeout`, set per role
and per database. The worker must never hold a transaction open across a CLI subprocess, and this
makes that a database rule rather than a discipline.

`install/platform/03-verify` checks the resulting surface against the running database, in both
directions. Only asking what a role must *not* do passes completely for a role with no privileges
at all, which is a broken system reading as a secured one.

## Sudo policy

- Web has no sudo rule.
- Poller may invoke only read-only helpers.
- Worker may invoke only named mutation/completion helpers required by its allowlisted operations.
- No rule grants a shell, interpreter, editor, arbitrary executable, wildcard path, environment
  preservation, or unrestricted command arguments.
- Human `sudoedit` policy is separate from app sudoers and limited to declared config files.
- A declared path whose file has been removed is revoked in the same change. `sudoedit`
  creates what it does not find, so the rule would otherwise remain a way to add a
  root-owned file to a loaded configuration directory.
- DR/rebuild and certificate issuance/distribution remain separate operator policies.

## Mandatory negative tests

Run these tests as the real installed identities, not only through mocks:

1. web cannot read config, published releases, cluster configuration, certificate material,
   backup archives, secrets, or any management SSH key; a certificate file it receives in an
   upload is sealed for root within the request and never stored in clear
2. web cannot execute any management helper through sudo
3. poller cannot read private trees or keys and cannot invoke a mutation helper
4. worker cannot read any private key, PEM, secret, or raw backup archive
5. worker cannot invoke an unlisted helper, pass argv to a no-argument helper, select a path, inject
   `..`, use a symlink/special file, preserve environment, or reuse a request ID with another payload
6. dev identity cannot read production config/published/management trees and is not in the
   production config group
7. helper files and their parent directories are root-owned and not group/other writable
8. every helper rejects malformed, oversized, trailing, multi-document, and unknown-operation JSON
9. deploy/status key identities map to the expected distinct forced commands on every node
10. positive controls prove each role can perform exactly its intended operations

A change to an identity, a helper or a rule is not done until these pass again as the installed
identities. `install/platform/03-verify` carries the database part - what each role must and must not
be able to do - and `install/05-verify` the files, keys and nodes.
