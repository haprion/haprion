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
| `haproxy-cert-list` | `cert_list` | `done`, `failed` | Deployable certificate metadata only |
| `haproxy-publish` | `publish` | `done`, `failed`, `blocked` | Validation and new immutable release |
| `haproxy-deploy` | `deploy` | `done`, `partial`, `failed`, `blocked` | Config reconcile per node |
| `haproxy-revert` | `revert` | `done`, `failed`, `blocked` | New release built from an older version |
| `haproxy-cert-deploy` | `cert_deploy` | `done`, `partial`, `failed`, `blocked` | Certificate reconcile per node |

`blocked` means that no mutation started. `failed` means the request failed or a started operation
could not verify any successful target state. `partial` means at least one target was verified but
the cluster did not converge. `done` includes a verified no-op.

## Envelope invariants

- `ok` is true only for `outcome=done`.
- `partial` has at least one structured warning and a null top-level error.
- `failed` and `blocked` have a structured top-level error.
- `cluster` is null only when input failed before a valid cluster could be resolved.
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
| `deploy` | `split_brain`, `vip_unknown`, `node_deploy_failed`, `status_unavailable` |
| `revert` | `dirty_worktree`, `version_not_found`, `candidate_invalid`, `publish_incomplete` |
| `cert_deploy` | `split_brain`, `vip_unknown`, `certificate_missing`, `fingerprint_mismatch`, `node_cert_deploy_failed` |

New codes may be added in schema v1 only when an older caller can safely show them as a generic
failure or warning. Removing or changing the meaning of a code requires a new schema version.

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

- only status currently has a partial JSON implementation
- status warnings are currently strings and release versions are numeric strings
- inventory and certificate-list commands do not yet exist
- list, backup-list, publish, deploy, revert, and cert-deploy still need JSON modes
- current deploy safety blocks and cert-deploy failures do not yet use the frozen exit-code/outcome
  mapping
- the human backup helper's node/`all` syntax remains supported; JSON mode is cluster-bound as
  specified by the UI CLI contract
