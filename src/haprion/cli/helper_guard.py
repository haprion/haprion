"""One mapping from what a locked publishing run can raise to the envelope it answers with.

The three privileged publishing loops (`publish_helper`, `managed_helper`,
`revert_helper`) each wrapped the cluster's lock in a `try` chain of their own,
and the chains drifted: a sandbox that could not be prepared was a refusal in
one and a traceback in the other two, and a candidate over its limit was a
traceback in all three. A traceback leaves no document, and a worker that reads
none stores `unknown` - "may have acted" - for a refusal that wrote nothing.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from haprion.cluster_lock import LockBusy
from haprion.config import ConfigError
from haprion.git_command import GitError
from haprion.helper_protocol import HelperProtocolError, config_error_code
from haprion.release_install import InstallError
from haprion.release_layout import LayoutError
from haprion.repo_snapshot import ConcurrentUpdate, PublishError


class Refuser(Protocol):
    def __call__(
        self, code: str, message: str, exit_code: int, details: dict[str, Any] | None = None
    ) -> int: ...


def guarded(refuse: Refuser, body: Callable[[], int], *, moved_code: str) -> int:
    """Run `body` under the lock; whatever it raises that is not a bug becomes a refusal.

    `moved_code` is what a branch moved by somebody else is called: a publish
    names the base it was built on, a revert and a managed publish the target.
    """

    try:
        return body()
    except LockBusy as exc:
        return refuse("operation_locked", str(exc), exc.exit_code)
    except ConcurrentUpdate as exc:
        return refuse(moved_code, str(exc), exc.exit_code)
    except (InstallError, LayoutError, PublishError) as exc:
        return refuse("publish_incomplete", str(exc), exc.exit_code)
    except ConfigError as exc:
        #
        # What the run read under the lock - the sandbox's certificate and run
        # root, the network, the certificate inventory - not the request.
        #
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)
    except GitError as exc:
        return refuse("internal_error", str(exc), exc.exit_code)
