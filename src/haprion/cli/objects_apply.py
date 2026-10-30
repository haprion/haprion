"""``haprion-objects apply`` and ``remove`` - the objects from files (Fas 23, B293).

The terminal's way to what *Proxies* saves: each file is one object's document,
named by the file (`shop.yaml` is the object `shop`), in the same form the
interface stores. What is stored is read first, through the same helper the
listing uses, and only what differs is published - as one version, through
the helper the interface publishes saved changes with, against the head just
read. A second run with the same files changes nothing and says so, which is
what lets an Ansible role run again without effect.

An object no file names is left alone unless `--prune` asks for it to go;
`remove` takes names, and a name that is not stored is already removed.
`--check` says what would change and changes nothing. A publish is not a
deploy: `haprion-deploy -c <cluster>` takes it to the nodes.

    haprion-objects apply -c <cluster> <file|dir>... [--prune] [--check] [-m <comment>]
                          [--allow-certificate-mismatch] [--json]
    haprion-objects remove -c <cluster> <name>... [--check] [-m <comment>] [--json]
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from haprion import exit_codes, labels, server_names
from haprion.cli import arguments, changes_publish
from haprion.cli.apply_common import (
    PartlyDone,
    Refused,
    RunHelper,
    RunPublish,
    answer_of,
    diff,
    envelope,
    unreadable,
)
from haprion.cli.cluster_settings import run_publish_helper
from haprion.envelope import new_request_id
from haprion.helper_protocol import write_document
from haprion.proxy_model import (
    MAX_MODEL_BYTES,
    NAME,
    NAME_RULE,
    ModelError,
    load_proxy,
    load_written,
)

OPERATION = "objects_apply"
SUFFIXES = (".yaml", ".yml")


@dataclass(frozen=True, slots=True)
class Plan:
    added: tuple[str, ...]
    changed: tuple[str, ...]
    removed: tuple[str, ...]
    unchanged: tuple[str, ...]
    #
    # What each added or changed object would be published as, and a removal
    # as None: the request the helper is sent, in order.
    #
    documents: Mapping[str, str | None] = field(default_factory=dict)
    diffs: Mapping[str, str] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not (self.added or self.changed or self.removed)


def _parser(command: str) -> argparse.ArgumentParser:
    parser = arguments.ArgumentParser(prog=f"haprion-objects {command}", add_help=True)
    parser.add_argument("-c", "--cluster", required=True)
    parser.add_argument("targets", nargs="+", metavar="FILE|DIR" if command == "apply" else "NAME")
    parser.add_argument(
        "--check", action="store_true", help="say what would change; change nothing"
    )
    parser.add_argument("-m", "--comment", default="")
    parser.add_argument("--json", action="store_true")
    if command == "apply":
        parser.add_argument(
            "--prune", action="store_true", help="remove stored objects no file names"
        )
        parser.add_argument("--allow-certificate-mismatch", action="store_true")
    return parser


def read_files(targets: Sequence[str]) -> dict[str, str]:
    """Every object the files describe, by name, each checked on its own first.

    A directory contributes its `.yaml` and `.yml` files, not its
    subdirectories: what is applied is what somebody can see listed. Each
    document is read by the model the helper reads it with, so a mistake is
    named by its file before anything is asked of the manager.

    A directory named on purpose and holding none is a cluster without objects
    - what `haprion-export` writes for one - and gives nothing to apply (review
    26-10-24, 15-04). Files named that hold no object are still refused.
    """

    files: list[Path] = []
    for target in targets:
        path = Path(target)
        if path.is_dir():
            files.extend(
                sorted(
                    child
                    for child in path.iterdir()
                    if child.is_file() and child.suffix in SUFFIXES
                )
            )
        elif path.is_file():
            files.append(path)
        else:
            raise Refused("not_found", f"{target}: no such file or directory", exit_codes.NOT_FOUND)
    documents: dict[str, str] = {}
    origin: dict[str, Path] = {}
    for path in files:
        name = path.stem
        if not NAME.fullmatch(name):
            raise Refused("invalid_name", f"{path}: {name} is not an object name; use {NAME_RULE}")
        if name in origin:
            raise Refused("duplicate", f"{path}: {name} is also {origin[name]}")
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise unreadable(path, exc) from exc
        if len(data) > MAX_MODEL_BYTES:
            raise Refused("too_long", f"{path}: larger than {MAX_MODEL_BYTES} bytes")
        #
        # Read as a stored object here, and held to the rules for what is
        # written only once the plan says it is written: an export of an
        # object stored before a rule changes nothing when applied, as the
        # plan says, and was refused whole (code review 2026-10-30 again,
        # R12).
        #
        try:
            text = data.decode("utf-8")
            load_proxy(name, data)
        except (UnicodeDecodeError, ModelError) as exc:
            raise Refused("object_invalid", f"{path}: {exc}") from exc
        documents[name] = text
        origin[name] = path
    if not documents and not any(Path(target).is_dir() for target in targets):
        raise Refused("nothing", "no object files found")
    return documents


def stored(result: Mapping[str, Any]) -> tuple[str | None, dict[str, str]]:
    """The head and each stored object's document, from an objects helper result."""

    entries = result.get("objects")
    if not isinstance(entries, list):
        raise Refused(
            "dependency_unavailable",
            "the objects helper returned no object list",
            exit_codes.UNAVAILABLE,
        )
    commit = result.get("commit")
    return (
        commit if isinstance(commit, str) else None,
        {
            str(entry["name"]): str(entry.get("document", ""))
            for entry in entries
            if isinstance(entry, Mapping) and isinstance(entry.get("name"), str)
        },
    )


def plan_apply(wanted: Mapping[str, str], current: Mapping[str, str], *, prune: bool) -> Plan:
    added = tuple(sorted(name for name in wanted if name not in current))
    changed = tuple(
        sorted(name for name in wanted if name in current and current[name] != wanted[name])
    )
    unchanged = tuple(
        sorted(name for name in wanted if name in current and current[name] == wanted[name])
    )
    removed = tuple(sorted(name for name in current if name not in wanted)) if prune else ()
    for name in (*added, *changed):
        try:
            load_written(name, wanted[name].encode())
        except ModelError as exc:
            raise Refused("object_invalid", f"{name}: {exc}") from exc
    #
    # Removed first, then changed, then added: when the plan is published in
    # more than one batch, a name, port or pool a removed or changed object
    # lets go is free before the batch whose new object takes it (code review
    # 2026-10-30 again, R11).
    #
    documents: dict[str, str | None] = dict.fromkeys(removed)
    documents.update({name: wanted[name] for name in (*changed, *added)})
    return Plan(
        added=added,
        changed=changed,
        removed=removed,
        unchanged=unchanged,
        documents=documents,
        diffs={name: diff(name, current[name], wanted[name]) for name in changed},
    )


def plan_remove(names: Sequence[str], current: Mapping[str, str]) -> Plan:
    for name in names:
        if not NAME.fullmatch(name):
            raise Refused("invalid_name", f"{name} is not an object name; use {NAME_RULE}")
    removed = tuple(sorted({name for name in names if name in current}))
    return Plan(
        added=(),
        changed=(),
        removed=removed,
        unchanged=tuple(sorted({name for name in names if name not in current})),
        documents=dict.fromkeys(removed),
    )


def _comment(plan: Plan) -> str:
    parts = []
    for verb, names in (
        ("added", plan.added),
        ("changed", plan.changed),
        ("removed", plan.removed),
    ):
        if names:
            parts.append(f"{verb} {', '.join(names)}")
    return "From the terminal: " + "; ".join(parts)


def publish(
    cluster: str,
    plan: Plan,
    head: str,
    *,
    comment: str,
    allow_certificate_mismatch: bool,
    run_publish: RunPublish,
) -> list[dict[str, Any]]:
    """One version for the plan, or one per batch of what the helper takes at once.

    Each batch is fenced on the version the one before it made, so a change
    somebody else published in between stops the run where it is rather than
    being overwritten. Returns what each publish answered.
    """

    names = list(plan.documents)
    batches = [
        names[start : start + changes_publish.MAX_OBJECTS]
        for start in range(0, len(names), changes_publish.MAX_OBJECTS)
    ]
    answers: list[dict[str, Any]] = []
    for number, batch in enumerate(batches, start=1):
        suffix = f" ({number} of {len(batches)})" if len(batches) > 1 else ""
        request = changes_publish.build_request(
            cluster,
            new_request_id(),
            expected_head=head,
            comment=(comment or _comment(plan)) + suffix,
            objects={name: plan.documents[name] for name in batch},
            allow_certificate_mismatch=allow_certificate_mismatch,
        )
        try:
            result = answer_of(run_publish(request), changes_publish.OPERATION, changes=True)
        except Refused as refused:
            if not answers:
                raise
            raise PartlyDone(
                Refused(
                    refused.code,
                    f"{refused}; {labels.counted(len(answers), 'earlier batch', 'earlier batches')} published",
                    refused.exit_code,
                    refused.details,
                ),
                answers,
            ) from refused
        answers.append(dict(result))
        head = str(result.get("hash") or head)
    return answers


def _summary(plan: Plan, *, check: bool, versions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    changed = (not plan.empty) and (check or any(v.get("changed") for v in versions))
    return {
        "changed": changed,
        "check": check,
        "added": list(plan.added),
        "updated": list(plan.changed),
        "removed": list(plan.removed),
        "unchanged": list(plan.unchanged),
        "versions": [
            {"version": v.get("version"), "hash": v.get("hash"), "changed": v.get("changed")}
            for v in versions
        ],
        "deployment_required": any(v.get("deployment_required") for v in versions),
        #
        # As each publish reported them (finding 72); a check publishes nothing
        # and so looks nothing up.
        #
        "unresolved_servers": list(
            dict.fromkeys(str(name) for v in versions for name in v.get("unresolved_servers") or ())
        ),
    }


def _render(cluster: str, plan: Plan, summary: Mapping[str, Any], writer: TextIO) -> None:
    if plan.empty:
        writer.write(
            f"{cluster}: nothing to change ({labels.counted(len(plan.unchanged), 'object')} as stored).\n"
        )
        return
    lead = "Would" if summary["check"] else "Did"
    for verb, names in (("add", plan.added), ("change", plan.changed), ("remove", plan.removed)):
        for name in names:
            writer.write(f"{lead} {verb} {name}\n")
    for name in plan.changed:
        writer.write(plan.diffs.get(name, ""))
    for version in summary["versions"]:
        writer.write(f"Published version {version['version']} of {cluster}.\n")
    for name in summary["unresolved_servers"]:
        writer.write(f"WARNING: {server_names.warning(name)}\n")
    if summary["deployment_required"]:
        writer.write(f"Deploy it with: haprion-deploy -c {cluster}\n")


def main(
    command: str,
    argv: list[str],
    *,
    run_helper: RunHelper,
    run_publish: RunPublish = run_publish_helper,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
) -> int:
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    args = _parser(command).parse_args(argv)
    cluster = str(args.cluster)
    try:
        wanted = read_files(args.targets) if command == "apply" else {}
        if command == "apply" and not wanted and args.prune:
            raise Refused(
                "nothing",
                "no object files found, and --prune would remove every object; nothing was changed",
            )
        head, current = stored(answer_of(run_helper(cluster, new_request_id()), "objects"))
        plan = (
            plan_apply(wanted, current, prune=args.prune)
            if command == "apply"
            else plan_remove(args.targets, current)
        )
        versions: list[dict[str, Any]] = []
        if not plan.empty and not args.check:
            if head is None:
                raise Refused("no_head", f"{cluster} has nothing committed to publish against")
            versions = publish(
                cluster,
                plan,
                head,
                comment=args.comment,
                allow_certificate_mismatch=bool(getattr(args, "allow_certificate_mismatch", False)),
                run_publish=run_publish,
            )
    except PartlyDone as stopped:
        summary = _summary(plan, check=False, versions=stopped.done)
        errors.write(stopped.report())
        if args.json:
            return write_document(
                writer, envelope(OPERATION, cluster, summary, stopped), stopped.exit_code
            )
        _render(cluster, plan, summary, writer)
        return stopped.exit_code
    except Refused as refused:
        if args.json:
            write_document(writer, envelope(OPERATION, cluster, None, refused), refused.exit_code)
        else:
            errors.write(refused.report())
        return refused.exit_code
    summary = _summary(plan, check=args.check, versions=versions)
    if args.json:
        write_document(writer, envelope(OPERATION, cluster, summary, None), 0)
    else:
        _render(cluster, plan, summary, writer)
    return 0
