# HAProxy Manager CLI/JSON contract v1

This document freezes the semantics shared by the schemas in `schemas/v1/`. Field-level types,
required fields, nullability, and enums are normative in the schema files. This document is
normative for process behavior, exit codes, redaction, and stable error meanings.

## Command matrix

| Command | Operation | Allowed outcomes | Result purpose |
|---|---|---|---|
| `haproxy-status` | `status` | `done`, `partial`, `failed` | Node/service/VIP/release status |
| `haproxy-inventory` | `inventory` | `done`, `failed` | Managed and read-only unmanaged proxy inventory |
| `haproxy-list` | `list` | `done`, `failed` | Published version history |
| `haproxy-list-backups` | `list_backups` | `done`, `partial`, `failed` | Backup metadata only |
| backup job helper | `backup_run` | `done`, `partial`, `failed` | One cluster, separate archive per node |
| backup job helper | `backup_schedule` | `done`, `failed` | Daily, weekly or monthly schedule and per-node retention for one cluster, on the manager's clock |
| `haproxy-node-restore-helper` | `node_restore_prepare` | `done`, `failed`, `blocked` | A restore run for one node's archive and one target VM: the run's one-time key is created and the result carries the line the operator pastes on the target (public key only). `mode` is `new_vm`, `test`, or `overwrite` (the parameter `overwrite: true` - the archive over the running node itself, B183). `blocked` is a run, node or archive that cannot be used; nothing was sent |
| `haproxy-node-restore-helper` | `node_restore_preview` | `done`, `failed`, `blocked` | The target's host key checked against the fingerprint read on its console, and the plan: every file, account and rewritten field, the archived files it does not write, and the node bundle of this manager's release that prepares the node (`node_bundle`, absent when the release carries none). `blocked` with a plan lists the problems that stop the run; `blocked` without one stopped earlier (a fingerprint that does not match - nothing was sent to the target). An overwrite's plan also carries `changed`, `unchanged`, `quarantined` and `network_unchanged`, and the result an `overwrite` block: the state backup taken at the preview and the pair as read then |
| `haproxy-node-restore-helper` | `node_restore` | `done`, `failed`, `blocked` | The previewed plan carried out in three SSH sessions. `blocked` is a run refused before anything was written (the plan changed after the preview); `failed` names the session it stopped in and whether the target was put back (`rolled_back`, B176; for an overwrite, from the copy the run took on the node, with a `rollback` session after a network that never came up). An overwrite takes `backup_failed_ok` and `break_traffic`, both false when left out. Reached by the worker over `/run/haproxy-mgmt/node-restore.sock` through `haproxy-node-restore-ask`, not through sudo; the terminal's `haproxy-node-restore` runs the same engine |
| `haproxy-node-restore-helper` | `node_restore_discard` | `done`, `failed`, `blocked` | A run given up: its directory and one-time key are removed on the management host (`removed`: whether they were still there - a run swept after its hour answers `false`, still `done`). Nothing is sent to the target; the pasted line carries its own `expiry-time` (B182). `blocked` is a run that a step is working in, or one of another cluster |
| `haproxy-cert-list` | `cert_list` | `done`, `failed` | Deployable certificate metadata only |
| `haproxy-network` | `network` | `done`, `failed` | Cluster addresses and address groups |
| `haproxy-network-publish-helper` | `network_publish` | `done`, `failed`, `blocked` | Bounded publication of `managed/network.yaml` |
| `haproxy-objects-publish-helper` | `objects_publish` | `done`, `failed`, `blocked` | Bounded publication of `managed/proxies/` |
| `haproxy-publish` | `publish` | `done`, `failed`, `blocked` | Validation and new immutable release |
| `haproxy-deploy` | `deploy` | `done`, `partial`, `failed`, `blocked` | Config reconcile per node |
| `haproxy-revert` | `revert` | `done`, `failed`, `blocked` | New release built from an older version |
| `haproxy-cert-deploy` | `cert_deploy` | `done`, `partial`, `failed`, `blocked` | Certificate reconcile per node |
| `haproxy-cert-publish` | `cert_publish` | `done`, `partial`, `failed`, `blocked` | Registry-wide publication to clusters and receivers; `cluster` is always null |
| `haproxy-cert-issue` | `cert_issue` | `done`, `failed` | One ACME certificate issued, registered, published and rolled out; `cluster` is always null |
| `haproxy-dns-profile-apply-helper` | `dns_profile_apply` | `done`, `failed`, `blocked` | One sealed DNS provider profile opened by root and written as the plugin's credentials file; `cluster` is always null; the result names the profile, never its contents |
| `haproxy-cert-target-helper` | `cert_target` | `done`, `partial`, `failed`, `blocked` | A list of certificates and one delta - `add` or `remove` of clusters and receivers - applied per certificate to whatever the registry holds; an add publishes and rolls each added cluster out once, a remove asks the dropped cluster's nodes to remove their copy (no reload) and unlinks a dropped receiver's pair unless another certificate shares it; a remove is refused per certificate by the deletion's guards scoped to the dropped cluster; `cluster` is always null |
| `haproxy-cert-delete-helper` | `cert_delete` | `done`, `partial`, `failed`, `blocked` | Certificates removed from the registry, the targets, certbot and the nodes, one row per certificate with every layer's state; a refused certificate is untouched and does not stop the others; `cluster` is always null |
| `haproxy-cert-receiver-helper` | `cert_receiver` | `done`, `partial`, `failed` | One receiver registered - account, directory, lock, registry entry - with the public key given as text, or removed once nothing names it; the result lists each layer's state and, after a registration, what the receiving host's operator needs; `partial` is a removal that left an account or a directory behind; `cluster` is always null. Reached by the worker over `/run/haproxy-mgmt/cert-receiver.sock` through `haproxy-cert-receiver-ask`, not through sudo |

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
| `publish` | `candidate_invalid`, `base_version_changed`, `publish_incomplete` |
| `deploy` | `split_brain`, `vip_unknown`, `node_deploy_failed`, `status_unavailable`, `certificates_not_deployed`, `certificate_missing` |
| `revert` | `dirty_worktree`, `version_not_found`, `candidate_invalid`, `publish_incomplete` |
| `cert_deploy` | `split_brain`, `vip_unknown`, `certificate_missing`, `fingerprint_mismatch`, `node_cert_deploy_failed` |
| `network_publish` | `dirty_worktree`, `candidate_invalid`, `publish_incomplete` |
| `objects_publish` | `dirty_worktree`, `network_missing`, `objects_invalid`, `candidate_invalid`, `publish_incomplete` |
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
- Initial and final VIP summaries use the same shape as `haproxy-status`.
- A config deploy checks the certificates the release references against what each readable node
  reports before it touches any node. A node that lacks one, or carries other bytes, ends the run
  as `blocked` with `certificates_not_deployed`; `error.details.nodes` lists each such node with
  its `missing` and `stale` certificate IDs and `error.details.next_command` names the
  `haproxy-cert-deploy` invocation to run first. Nothing chains the two: the certificate deploy is
  always asked for by name, and a new `haproxy-deploy` follows it. A node that did not report
  certificates is let through with a `certificates_unverified` warning; a manager without a
  `certificate_root` skips the check with a `certificates_unchecked` warning. A referenced
  certificate the manager itself does not hold is refused as `certificate_missing`, the code
  `cert_deploy` uses for the same fault.

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

## Current-to-v1 implementation delta

The installed commands remain the regression baseline, but Phase 1 must adapt them to these frozen
contracts:

- status is ported to the packaged CLI and now emits `outcome`, warning objects and an integer
  release version; its result also carries the published `target` and, per node, whether that node
  runs it
- inventory exists and emits the frozen `inventory` result; the certificate-list command does not
  yet exist
- list emits the frozen `list` result under `--json`, and reports the published release alongside
  the schema's `current_version`: `current` means the newest saved version, which is not
  necessarily the one the nodes run
- backup-list, publish, deploy, revert, and cert-deploy still need JSON modes
- current deploy safety blocks and cert-deploy failures do not yet use the frozen exit-code/outcome
  mapping
- the human backup helper's node/`all` syntax remains supported; JSON mode is cluster-bound as
  specified by the UI CLI contract
