# Haprion CLI/JSON contract v1

This document freezes the semantics shared by the schemas in `schemas/v1/`. Field-level types,
required fields, nullability, and enums are normative in the schema files. This document is
normative for process behavior, exit codes, redaction, and stable error meanings.

## Command matrix

| Command | Operation | Allowed outcomes | Result purpose |
|---|---|---|---|
| `haprion-status` | `status` | `done`, `partial`, `failed` | Node/service/VIP/release status |
| `haprion-inventory` | `inventory` | `done`, `failed` | Managed and read-only unmanaged proxy inventory |
| `haprion-list` | `list` | `done`, `failed` | Published version history, newest first; each version carries `requested_by` (null before it existed). The helper takes `limit`, 1 to 250, and lists ten without it, and `diffs`, up to ten commit hashes whose changes it adds as `result.diffs` (a hash not on the history is left out) |
| `haprion-list-backups` | `list_backups` | `done`, `partial`, `failed` | Backup metadata only |
| backup job helper | `backup_run` | `done`, `partial`, `failed` | One cluster, separate archive per node |
| backup job helper | `backup_schedule` | `done`, `failed` | Daily, weekly or monthly schedule and per-node retention for one cluster, on the manager's clock. `haprion-backup-schedule` asks only where the timer or the retention differs, and adds `changed` |
| `haprion-node-restore-helper` | `node_restore_prepare` | `done`, `failed`, `blocked` | A restore run for one node's archive and one target VM: the run's one-time key is created and the result carries the line the operator pastes on the target (public key only). `mode` is `new_vm` (as the node) or `test`; whether as the node lands on an empty VM or over the node itself is the preview's to tell. `blocked` is a run, node or archive that cannot be used; nothing was sent |
| `haprion-node-restore-helper` | `node_restore_preview` | `done`, `failed`, `blocked` | The target's host key checked against the fingerprint read on its console, and the plan: every file, account and rewritten field, the archived files it does not write, and the node package of this manager's release that prepares the node (`node_package`, absent when the release carries none). `blocked` with a plan lists the problems that stop the run; `blocked` without one stopped earlier (a fingerprint that does not match - nothing was sent to the target). A target offering the archived host key is the node itself and its plan's `mode` is `overwrite`; that plan also carries `changed`, `unchanged`, `quarantined` and `network_unchanged`, and the result an `overwrite` block: the state backup taken at the preview and the pair as read then |
| `haprion-node-restore-helper` | `node_restore` | `done`, `failed`, `blocked` | The previewed plan carried out in three SSH sessions. `blocked` is a run refused before anything was written (the plan changed after the preview); `failed` names the session it stopped in and whether the target was put back (`rolled_back`; for an overwrite, from the copy the run took on the node, with a `rollback` session after a network that never came up). An overwrite takes `backup_failed_ok` and `break_traffic`, both false when left out. Reached by the worker over `/run/haprion/node-restore.sock` through `haprion-node-restore-ask`, not through sudo; the terminal's `haprion-node-restore` runs the same engine |
| `haprion-node-restore-helper` | `node_restore_discard` | `done`, `failed`, `blocked` | A run given up: its directory and one-time key are removed on the management host (`removed`: whether they were still there - a run swept after its hour answers `false`, still `done`). Nothing is sent to the target; the pasted line carries its own `expiry-time`. `blocked` is a run that a step is working in, or one of another cluster |
| `haprion-node-restore-helper` | `node_restore_status` | `done`, `failed`, `blocked` | How a run stands, read from its directory on the management host; nothing is changed. `state` is `running` (a step holds the run's lock), `finished` (with `outcome`, `error` and the `result` `node_restore` answered, or would have), `stopped` (it began writing to the target and left no outcome) or `not_started`. A run's outcome is kept seven days. `blocked` is a run that is gone or of another cluster, and `restore_busy`: the socket's one connection is held by a restore still running - ask again |
| `haprion-cert-list` | `cert_list` | `done`, `failed` | Deployable certificate metadata only; with a null cluster, the manager's registry |
| `haprion-network` | `network` | `done`, `failed` | Cluster addresses and address groups |
| `haprion-readings-helper` | `readings` | `done`, `failed` | The poller's manager-local readings of one cluster in one call: `parameters.reads` names any of `list`, `list_backups`, `cert_list`, `network`, `cluster_settings` and `objects` with the parameters that reading's own helper takes. The helper runs each reading's helper in its process and answers, per reading, that helper's `envelope` (null when it wrote none), `exit_code` and `stderr` (at most 2048 characters); a reading that fails is that reading's answer and the others still come |
| `haprion-objects` | `objects` | `done`, `failed` | The stored proxy objects at the repository's head, each with what the listing and search need without reading the document: protocol, hostnames, backend count, the VIP and source address worked out by the generator's rule, the servers, and whether any backend is health checked. A network description that cannot be read leaves the addresses null and adds a `network_unreadable` warning. Every listing carries a `fingerprint` of the commit, the network and the engine; a caller that sends it back as `unchanged_since` is answered with `unchanged: true` and no objects while it still matches |
| `haprion-cluster-settings` | `cluster_settings` | `done`, `failed` | The cluster's external log targets and metrics exporter, from `managed/cluster.yaml` at the published head, with that head; `stored` is false and both are empty when the file does not exist |
| `haprion-changes-publish-helper` | `changes_publish` | `done`, `failed`, `blocked` | The changes a person saved, published as one version: up to 64 proxy objects (`null` removes one), the network description and the cluster settings, in any combination and at least one; a part left out is read from the base. `haprion-cluster-settings --set` publishes through it with settings alone. The result names the objects written and removed and whether `network` and `settings` were part of it. `network_invalid` and `settings_invalid` name the document that is wrong on its own, `changes_invalid` a package the managed layer refuses as a whole |
| `haprion-server-state-helper` | `server_state` | `done`, `partial`, `failed` | Drain, maintenance or ready (`parameters.state`) for the servers `parameters.servers` names in the object `parameters.object`, written `host:port` or `pool/host:port`, on every node of the cluster. Each server is found in the object's newest committed version before any node is asked (`server_not_found`); dns and syslog objects are refused. The result lists every node's answer per server - `done`, `refused` (the node does not run that server yet) or `failed` - with one warning per server not taken (`server_not_on_node`, `node_server_state_failed`); `partial` is some taken. No cluster lock: the node serialises it with its own reload. Without `server_state_identity` in the runtime policy it fails `server_state_unavailable` |
| `haprion-publish` | `publish` | `done`, `failed`, `blocked` | Validation and new immutable release |
| `haprion-deploy` | `deploy` | `done`, `partial`, `failed`, `blocked` | Config reconcile per node. `blocked` means no node was touched (split brain, unknown VIP owner, no usable status, missing certificates); a block met after a node already carries the target is `partial`, naming it |
| `haprion-revert` | `revert` | `done`, `failed`, `blocked` | New release built from an older version |
| `haprion-cert-deploy` | `cert_deploy` | `done`, `partial`, `failed`, `blocked` | Certificate reconcile per node; `blocked` and `partial` as for `deploy` |
| `haprion-cert-publish` | `cert_publish` | `done`, `partial`, `failed`, `blocked` | Registry-wide publication to clusters and receivers; `cluster` is always null |
| `haprion-cert-issue` | `cert_issue` | `done`, `failed` | One ACME certificate issued, registered, published and rolled out; `cluster` is always null |
| `haprion-dns-profile-apply-helper` | `dns_profile_apply` | `done`, `failed`, `blocked` | One sealed DNS provider profile opened by root and written as the plugin's credentials file; `cluster` is always null; the result names the profile, never its contents |
| `haprion-cert-target-helper` | `cert_target` | `done`, `partial`, `failed`, `blocked` | A list of certificates and one delta - `add` or `remove` of clusters and receivers - applied per certificate to whatever the registry holds; an add publishes and rolls each added cluster out once, a remove asks the dropped cluster's nodes to remove their copy (no reload) and unlinks a dropped receiver's pair unless another certificate shares it; a remove is refused per certificate by the deletion's guards scoped to the dropped cluster; `cluster` is always null |
| `haprion-cert-delete-helper` | `cert_delete` | `done`, `partial`, `failed`, `blocked` | Certificates removed from the registry, the targets, certbot and the nodes, one row per certificate with every layer's state; a refused certificate is untouched and does not stop the others; `cluster` is always null |
| `haprion-cert-import` | `cert_import` | `done`, `failed`, `blocked` | A certificate issued elsewhere, with its key, put in the import store, registered, published and rolled out to the clusters named; `cluster` is always null |
| `haprion-cert-request` | `cert_request` | `done`, `failed`, `blocked` | A key made on the manager and a signing request for another CA; the result carries the CSR and nothing about the key, which waits in the import store until the signed certificate is imported over it; `cluster` is always null |
| `haprion-cert-scep` | `cert_scep` | `done`, `partial`, `failed`, `blocked` | One certificate enrolled through an NDES profile; `partial` with `state: pending` is a request the CA holds, resumed with `--resume`; `cluster` is always null |
| `haprion-ndes-profile-apply-helper` | `ndes_profile_apply` | `done`, `failed`, `blocked` | One sealed NDES profile opened by root and written as its root-only record, or removed; `cluster` is always null; the result names the profile, never the challenge |
| `haprion-node-helper` | `cluster_node` | `done`, `failed`, `blocked` | A node added to a cluster from its enrollment block, removed, or moved to another host name (`host_changed`, with `previous_host`; the node must answer there with a host key already pinned for it, or nothing changes); `haprion-node --json` prints it |
| `haprion-node-helper` | `cluster_define` | `done`, `failed`, `blocked` | A cluster created with its first two nodes, or removed and archived; `haprion-cluster --json` prints it |
| `haprion-cluster-list-helper` | `cluster_list` | `done`, `failed` | The clusters' IDs and display names in the cluster file's order, for the poller; `cluster` is always null |
| `haprion-objects apply` | `objects_apply` | `done`, `failed` | Proxy objects from files published where they differ, in versions of at most 64 against the head just read; `--prune` removes stored objects no file names; `--check` publishes nothing |
| `haprion-network apply` | `network_apply` | `done`, `failed` | The network description from a file, published as one version where it differs; refused (`network_not_managed`) for a cluster whose network comes from its cluster definition |
| `haprion-cluster-settings apply` | `cluster_settings_apply` | `done`, `failed` | A cluster's *Logs & metrics* from a file, compared field by field with what is stored and published as one version where it differs; `--check` publishes nothing |
| `haprion-user apply` | `user_apply` | `done`, `failed` | Interface accounts from a file, written where they differ through the web's own guards; `cluster` is always null |
| `haprion-settings apply` | `settings_apply` | `done`, `failed` | *External monitoring*, feature switches and the OIDC provider from a file, written where they differ through the web's own code; the client secret is never compared or returned (`sealing`); `cluster` is always null |
| `haprion-profiles apply` | `profiles_apply` | `done`, `failed` | DNS and NDES profiles from a file, sealed and stored as the web stores them, each applied by its job before the next is queued; `cluster` is always null |
| `haprion-export` | `export` | `done`, `failed` | What is set now, written below a new or empty directory as the files the apply commands take: accounts, interface settings and profiles, and per cluster its objects, network, *Logs & metrics* and backup schedule; `skipped` names what could not be written and why. Nothing secret is read back, so none is written; `cluster` is always null |
| `haprion-history-reset` | `reset_history` | `done`, `partial`, `failed` | A cluster's history started over at version 1 with the configuration kept and the old history archived; `partial` is a reset whose publish of version 1 failed. `--json` requires `--confirm` |
| `haprion-cert-receiver-helper` | `cert_receiver` | `done`, `partial`, `failed` | One receiver registered - account, directory, lock, registry entry - with the public key given as text, or removed once nothing names it; the result lists each layer's state and, after a registration, what the receiving host's operator needs; `partial` is a removal that left an account or a directory behind; `cluster` is always null. Reached by the worker over `/run/haprion/cert-receiver.sock` through `haprion-cert-receiver-ask`, not through sudo |
| `haprion-tls-helper` | `ui_tls_install` | `done`, `failed` | The registry entry marked `interface: true`, named by ID and nothing else, installed as the pair nginx serves the interface with through `haprion-tls install`; refused when the certificate does not name the interface's `SERVER_NAME`; `changed` is false when nginx already served that leaf (no reload); `cluster` is always null. Reached by the certificate helpers over `/run/haprion/ui-tls.sock`, not through sudo; the renewal timer and `haprion-cert-publish` install directly |
| `haprion-oidc-helper` | `oidc` | `done`, `failed` | One question to the OpenID Connect provider named by `issuer`, as `parameters.action`: `discover` (its endpoints, checked against the issuer), `verify` (discovery, key set, client method, algorithm, and whether the provider accepts the client, without a sign-in) or `exchange` (a code for the verified subject, name and groups; `claims` only when asked). Takes no URL; follows no redirect; opens the client secret only for the issuer and client it was sealed for; `cluster` is always null. Reached by the web over `/run/haprion/oidc.sock`, as an account of its own |
| `haprion-resolve-helper` | `resolve` | `done`, `failed` | Looks up `parameters.names` (1-20 host names, no addresses) with the manager's resolver, as saving a dns object does for its servers: per name the one address, or the sentence the save is refused with. `done` whatever the names gave; `cluster` is always null. Reached by the web over `/run/haprion/resolve.sock`, as a dynamic user with the network and nothing else |
| `haprion-cert-export-helper` | `cert_export` | `done`, `failed` | One certificate's key, for a registry entry marked `exportable` and no other: `pem-key` (the key alone), `pfx` (key and chain, AES-256, PBKDF2, SHA-256 MAC) or `pfx-compatible` (3DES, SHA-1 MAC) under the caller's 8-128 character `password`, which is never returned; the file as `content_base64` with the name and media type to serve it under. Refused (`not_exportable`) for any entry without the mark or with a target; nothing is written; `cluster` is always null. Reached by the web over `/run/haprion/cert-export.sock`, as root |

The three operations that record a version (`publish`, `revert`, `changes_publish`) take an optional `requested_by`: the person a caller acts for, at most 64
printable characters. The commit carries it as a `Requested-By` trailer, beside `Run-By` - the
account sudo ran the helper as, which the helper can prove. The name is recorded only when that
account is the runtime policy's `interface_account`, the web interface's worker; from any other
caller, and when the policy names no worker, both trailers name the proven account. Without the
parameter both name that account too. A name that is not printable is `bad_input` whoever sends it,
never cleaned.

`blocked` means that no mutation started. `failed` means the request failed or a started operation
could not verify any successful target state. `partial` means at least one target was verified but
the cluster did not converge. `done` includes a verified no-op.

## Envelope invariants

- `ok` is true only for `outcome=done`.
- `partial` has at least one structured warning and a null top-level error.
- `failed` and `blocked` have a structured top-level error.
- `cluster` is null only when input failed before a valid cluster could be resolved, or for an
  operation that spans clusters by definition (`cert_publish`, `cert_issue`), whose result names
  them instead.
- `request_id` is UUID formatted and is returned on every path.
- Messages are for humans. Callers branch only on `operation`, `outcome`, stable codes, and typed
  result fields.
- Unknown fields inside schema v1 are ignored. Unknown enum values or schema versions are not.

## Stable error codes

Every command supports these common codes where applicable:

| Code | Meaning |
|---|---|
| `bad_input` | Invalid arguments or request payload |
| `dependency_unavailable` | A required helper, repository, or target cannot be read |
| `internal_error` | Unexpected implementation failure |
| `operation_locked` | Per-cluster lock is held; no mutation started |
| `request_conflict` | Request ID was reused with a different operation or payload |
| `expected_target_changed` | Expected version/hash/fingerprint changed after lock acquisition |

Command-specific stable codes:

| Operation | Codes |
|---|---|
| `status` | `status_unavailable`, `ssh_unreachable`, `node_status_invalid_json`, `node_status_invalid` |
| `inventory` | `inventory_unavailable`, `inventory_invalid` |
| `list` | `history_unavailable`, `history_invalid` |
| `list_backups` | `backup_metadata_unavailable`, `backup_directory_missing` |
| `cert_list` | `certificate_metadata_unavailable`, `certificate_invalid` |
| `publish` | `candidate_invalid`, `base_version_changed`, `tls_defaults_stale`, `stick_counters_short`, `publish_incomplete` |
| `deploy` | `split_brain`, `vip_unknown`, `node_deploy_failed`, `status_unavailable`, `certificates_not_deployed`, `certificate_missing` |
| `revert` | `dirty_worktree`, `version_not_found`, `candidate_invalid`, `publish_incomplete` |
| `cert_deploy` | `split_brain`, `vip_unknown`, `certificate_missing`, `fingerprint_mismatch`, `node_cert_deploy_failed` |
| `changes_publish` | `dirty_worktree`, `network_missing`, `network_invalid`, `settings_invalid`, `changes_invalid`, `candidate_invalid`, `advanced_ignored`, `tls_defaults_stale`, `stick_counters_short`, `publish_incomplete` |
| `server_state` | `server_not_found`, `server_state_unavailable`, `server_not_on_node`, `node_server_state_failed` |
| `dynamic_unblock` | `server_not_found`, `server_state_unavailable`, `blocking_not_on_node`, `node_unblock_failed` |
| `cert_issue` | `already_exists`, `certbot_failed`, `publish_failed` |

New codes may be added in schema v1 only when an older caller can safely show them as a generic
failure or warning. Removing or changing the meaning of a code requires a new schema version.

A `certbot_failed` error carries certbot's captured output whole under `error.details.diagnostics`
(with `certbot_exit_code` and `certbot_seconds` beside it); `error.message` states only the exit and
the elapsed time. The message is capped at 2048 bytes, and a failed challenge's account is what the
operator needs to read.

## Reconcile invariants

These rules are shared by config deploy and certificate deploy:

- `done` requires `converged=true` and every node verified as `current` or `updated`.
- `partial` requires `converged=false`.
- A node with `current_before=true` is skipped and returned as `outcome=current`.
- `action=deploy` ends as `updated` or `failed`.
- An unreachable node uses `action=none`, `outcome=unavailable`, and a structured node error.
- Nodes not reached because a previous hard failure stopped the operation use `action=none` and
  `outcome=not_attempted`.
- The target version/hash or certificate fingerprints are returned even on partial results.
- Initial and final VIP summaries use the same shape as `haprion-status`.
- A config deploy checks the certificates and CA files the release references against what each
  readable node reports before it touches any node. A node that lacks one, or carries other bytes,
  ends the run as `blocked` with `certificates_not_deployed`; `error.details.nodes` lists each such
  node with its `missing` and `stale` certificate IDs (and, when a CA file is behind,
  `missing_authorities` and `stale_authorities`) and `error.details.next_command` names the
  `haprion-cert-deploy` invocation to run first. Nothing chains the two: the certificate deploy is
  always asked for by name, and a new `haprion-deploy` follows it. A node that did not report
  its certificates or CA files is let through with a `certificates_unverified` warning; a manager
  without a `certificate_root` skips the check with a `certificates_unchecked` warning. A
  referenced certificate the manager itself does not hold is refused as `certificate_missing`, the
  code `cert_deploy` uses for the same fault.
- In a cluster that shares its counters, a deploy waits up to 15 seconds after each node for it to
  report its peers connected before it touches the next, so the reloaded node can take the counts
  back. A node that has not connected by then is named in a `counters_not_shared` warning and the
  deploy goes on.
- A deploy that has updated a node and ends with no node owning the VIP waits up to 15 seconds for
  one to take it before its final status - the first deploy starts keepalived, and every node starts
  as BACKUP. Still none by then is a `vip_not_owned` warning.

## Publish and revert invariants

- Publish validates the exact bytes that cross the privileged boundary.
- A changed publish returns its version/hash/timestamp and always says
  `deployment_required=true`; it never deploys implicitly.
- A no-op publish returns `changed=false`, `deployment_required=false`, and `next_command=null`.
- Revert creates a new version from the selected historical version. It never moves history
  backwards and never deploys implicitly.
- Reverting to the already-current content is a successful no-op and does not claim that deploy is
  required.

## Backup and certificate privacy

- Backup listing returns node, timestamped version, creation time, byte size, and latest marker.
  It never returns archive contents or absolute filesystem paths.
- Certificate listing returns metadata and fingerprints. It never returns PEM bytes, private keys,
  or private filesystem paths.

## stdout, stderr, and persistence limits

- JSON mode writes exactly one UTF-8 JSON document to stdout and no progress text.
- A worker rejects stdout larger than 4 MiB as `internal_error` rather than parsing an unbounded
  response.
- Progress and diagnostics go to stderr. At most 65,536 UTF-8 bytes are persisted per job/audit
  record. If truncated, the persisted value contains the first and last 32 KiB with an explicit
  truncation marker between them.
- Redaction happens before persistence and before UI display. At minimum it masks private-key PEM
  blocks, token/password/secret assignments, and paths containing `.ssh`, `/secrets/`,
  `/etc/ssl/private/`, or private certificate-distribution paths.
- Raw stderr is never used to decide operation state and is never returned to a reader role.
