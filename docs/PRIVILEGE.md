# HAProxy Manager privilege contract v1

This contract defines the target privilege boundary that Phase 1 implements. It is intentionally
environment-neutral. Production account names, paths selected by runtime configuration, SSH keys,
and sudoers output remain private deployment data.

## Identities

| Role | Production config group | sudo helpers | Private keys | Database write scope |
|---|---|---|---|---|
| web | no | none | none | validate requests and insert allowlisted jobs only |
| worker | yes, read-only | exact mutation/completion helpers | none | claim, lease, state, result, audit |
| poller | no | exact read-only metadata helpers | none | poll/cache/metrics only |
| human operator | deployment policy | explicit wrappers and `sudoedit` policy | none directly | not used by app |

No app identity owns or can read SSH private keys, certificate private keys, validation dummy-key
material, secret files, or raw backup archives.

Three separate node identities exist, one per thing the manager may ask a node to do: read status,
pull a configuration release, pull a certificate. The status identity is the only one of the three
that cannot change a node, which is what makes it the one a deployment can grant most widely. Each
is a forced command with no argument, and each has its own key; none of them is a login.

### Identity provisioning

Account names are deployment data supplied in a protected identity-policy file. The
`haproxy-render-sysusers --policy <file>` command validates that file and renders a declarative
`sysusers.d` fragment. It creates three distinct, locked, no-login service accounts and the
read-only production config group; only the worker receives supplementary membership in that
group. Rendering does not modify the system.

Human operator membership is deliberately absent from the generated fragment. It is a separate
administrator action against an already existing human account, avoiding `sysusers.d` semantics
that could implicitly create a missing local account. Applying the reviewed fragment and changing
operator membership belong to deployment, not application runtime.

## Filesystem boundary

- Config repositories, published releases, and management configuration are root-owned and never
  group-writable.
- The worker may receive group read/traverse only where candidate construction or completion proof
  requires it. Web and poller do not join that group.
- Certificate distribution and raw backup trees are never made group-readable to an app identity.
- Dev identities have no production config group membership and no read access to private
  production trees.
- Git uses explicit repository-specific `safe.directory` entries. Wildcard trust is forbidden.

## Helper boundary

Helpers are root-owned, not group/other writable, use absolute executables, a fixed environment,
and fail closed. The target helper interface has no caller-selected filesystem path or shell text.

Where sudoers argument matching would otherwise require a wildcard, the helper is invoked with no
argv and reads one size-bounded JSON request from stdin. Sudoers uses the explicit no-argument
form supported by the installed sudo version. The helper validates operation, cluster ID,
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

Each executable compiles in one expected operation and an exact allowlist plus validator for its
operation-specific parameters. The protocol rejects argv, input over 64 KiB, invalid UTF-8,
duplicate or unknown fields, multiple/trailing JSON documents, non-finite numbers, non-canonical
request IDs, and unrecognised cluster-ID syntax before privileged state is consulted.

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

## Sudo policy

- Web has no sudo rule.
- Poller may invoke only read-only helpers.
- Worker may invoke only named mutation/completion helpers required by its allowlisted operations.
- No rule grants a shell, interpreter, editor, arbitrary executable, wildcard path, environment
  preservation, or unrestricted command arguments.
- Human `sudoedit` policy is separate from app sudoers and limited to declared config files.
- DR/rebuild and certificate issuance/distribution remain separate operator policies.

## Mandatory negative tests in Phase 1

Run these tests as the real installed identities, not only through mocks:

1. web cannot read config, published releases, cluster configuration, certificate material,
   backup archives, secrets, or any management SSH key
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

R2 build-readiness freezes this target and audits the current source boundary. Phase 1 creates the
identities/helpers/rules and must make all positive and negative tests pass before its gate closes.
