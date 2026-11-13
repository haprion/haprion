"""Write one blocklist's definition across the root boundary (B500).

The worker's `blocklist_apply` job sends the list's fields and, when it has a
password or token, the box the web sealed it in. This opens the box with the
installation's DNS profile key, holds it to this list, its source and the
revision the secret was last sealed at, writes the definition root-only under
/etc/haprion/blocklists, and starts the refresh service without waiting for
it: a new list or a new source is fetched and a changed exception reaches the
nodes by that pass, not by the next timer. `remove`
deletes the definition; whether an object still names the list is the web's
check, made before the job is queued.
"""

from __future__ import annotations

import base64
import binascii
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import blocklist_store, blocklists, exit_codes
from haprion.blocklist_store import Stored, StoreError
from haprion.cli import cert_job
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy
from haprion.dns_profile_keys import KeyFileError, read_private_key
from haprion.envelope import envelope
from haprion.helper_protocol import HelperProtocolError, config_error_code, write_document

OPERATION = blocklist_store.OPERATION
PARAMETERS = frozenset(
    {
        "name",
        "revision",
        "secret_revision",
        "url",
        "every_hours",
        "authorization",
        "username",
        "description",
        "excepts",
        "key_id",
        "ciphertext",
        "remove",
    }
)
SYSTEMCTL = "/usr/bin/systemctl"
REFRESH_UNIT = "haprion-blocklist-refresh.service"

Starter = Callable[[], bool]


def start_refresh() -> bool:
    """Ask systemd to run a refresh pass now; whether it took the request."""

    done = subprocess.run(  # noqa: S603 - fixed binary and unit
        [SYSTEMCTL, "start", "--no-block", REFRESH_UNIT],
        capture_output=True,
        check=False,
    )
    return done.returncode == 0


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    directory: Path = blocklist_store.DEFINITIONS,
    state: Path = blocklist_store.STATE,
    starter: Starter = start_refresh,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    try:
        request = cert_job.read_request(
            OPERATION,
            parameters=PARAMETERS,
            input_stream=input_stream,
            argv=argv,
            require_root=require_root,
            helper_name="haprion-blocklist-apply-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code
    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    parameters = request.parameters
    try:
        name = blocklists.checked_name(parameters.get("name"))
        revision = blocklist_store.check_revision(parameters.get("revision"))
        remove = parameters.get("remove", False)
        if not isinstance(remove, bool):
            raise ValueError("remove must be true or false")
        item = None
        secret_revision = 1
        if not remove:
            secret_revision = blocklist_store.check_revision(parameters.get("secret_revision"))
            if secret_revision > revision:
                raise ValueError("secret_revision is ahead of the revision")
            raw = parameters.get("excepts", [])
            if not isinstance(raw, list) or not all(isinstance(e, str) for e in raw):
                raise ValueError("excepts must be a list of text")
            excepts = [str(entry) for entry in raw]
            item = blocklists.definition(
                name=name,
                url=parameters.get("url"),
                every_hours=parameters.get("every_hours"),
                authorization=parameters.get("authorization", "none"),
                username=parameters.get("username", ""),
                description=parameters.get("description", ""),
                excepts=excepts,
            )
        encoded = parameters.get("ciphertext")
        if item is not None and item.authorization != "none" and not isinstance(encoded, str):
            raise ValueError("a list with Authorization needs its sealed secret")
        if encoded is not None and (
            not isinstance(encoded, str) or len(encoded) > blocklist_store.MAX_CIPHERTEXT * 2
        ):
            raise ValueError("ciphertext must be base64")
        ciphertext = base64.b64decode(encoded, validate=True) if encoded else None
        key_id = parameters.get("key_id")
        if ciphertext is not None and not (
            isinstance(key_id, str)
            and len(key_id) == 16
            and all(c in "0123456789abcdef" for c in key_id)
        ):
            raise ValueError("key_id must be a 16-character key ID")
    except (StoreError, ValueError, binascii.Error) as exc:
        return refuse("bad_input", str(exc), exit_codes.REFUSED)

    secret = ""
    if item is not None and ciphertext is not None:
        try:
            policy = load_policy(policy_path, require_secure=require_secure)
        except ConfigError as exc:
            return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)
        keys = policy.acme.dns_profiles if policy.acme is not None else None
        if keys is None:
            return refuse(
                "dependency_unavailable",
                "runtime policy.acme.dns_profiles is not configured; its key seals the secret",
                exit_codes.CONFIG,
            )
        selected = None
        try:
            for path in keys.private_keys:
                candidate = read_private_key(path, require_secure=require_secure)
                if candidate.key_id == key_id:
                    selected = candidate
                    break
        except KeyFileError as exc:
            return refuse("dependency_unavailable", str(exc), exit_codes.CONFIG)
        if selected is None:
            return refuse(
                "profile_key_unavailable",
                "the key the secret was sealed with is not configured",
                exit_codes.CONFIG,
            )
        try:
            secret = blocklist_store.open_secret(
                selected, ciphertext, definition=item, revision=secret_revision
            )
        except StoreError as exc:
            return refuse("binding_mismatch", str(exc), exit_codes.BLOCKED)

    try:
        if item is None:
            removed = blocklist_store.remove(
                name, directory=directory, require_secure=require_secure
            )
            blocklist_store.forget(name, directory=state)
        else:
            blocklist_store.write(
                Stored(
                    definition=item,
                    secret=secret,
                    revision=revision,
                    secret_revision=secret_revision,
                ),
                directory=directory,
                require_secure=require_secure,
            )
    except StoreError as exc:
        return refuse("dependency_unavailable", str(exc), exit_codes.CONFIG)

    result: dict[str, object] = {"name": name, "revision": revision, "refresh_started": starter()}
    if item is None:
        result["removed"] = removed
    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result=result,
        ),
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
