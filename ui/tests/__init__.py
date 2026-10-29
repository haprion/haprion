"""The interface's tests.

Every page any test renders is held to closing what it opens (review
26-10-24, 04-13): Jobs' empty state left a <div> open, which the browser
mends and the next change to the template inherits. Checked here, where every
module of the suite passes, rather than in a test that would have to know each
page and each state of it.
"""

from __future__ import annotations

import atexit
import os
import sys
from pathlib import Path
from typing import Any

from haprion import config
from starlette.templating import _TemplateResponse

from haprion_ui import templates
from tests import well_formed

#
# No test reads this machine's runtime policy. The suite runs on a manager,
# where /etc/haprion/runtime-policy.yaml exists, and a test that read it by
# default passed here and failed in CI - twice on 2026-10-28. Asked for by
# default, the policy is now a file no machine has.
#
config.load_policy.__defaults__ = (Path("/nonexistent/haprion-test/runtime-policy.yaml"),)

#
# And a grid rather than a default (review 26-10-29, A09): code that binds the
# policy's path at import, or names another file under /etc/haprion, went
# past the default - `compatibility.main` read this machine's policy in a test
# that passed. Every opening of a path there fails the test that made it, with
# an error no `except OSError` takes for a missing file; one caught by a
# broader handler still fails the run, named, when the interpreter exits.
#
MACHINE_CONFIGURATION = "/etc/haprion"


class MachineConfigurationRead(AssertionError):
    """A test reached for this machine's configuration."""


machine_reads: list[str] = []


def _machine_configuration(event: str, args: tuple[Any, ...]) -> None:
    if event not in ("open", "os.listdir", "os.scandir") or not args:
        return
    path = args[0]
    if not isinstance(path, (str, bytes, os.PathLike)):
        return
    name = os.path.normpath(os.fsdecode(path))
    if name == MACHINE_CONFIGURATION or name.startswith(MACHINE_CONFIGURATION + "/"):
        machine_reads.append(name)
        raise MachineConfigurationRead(f"a test read this machine's configuration: {name}")


def _report_machine_reads() -> None:
    if machine_reads:
        print("tests read this machine's configuration:", file=sys.stderr)
        for name in sorted(set(machine_reads)):
            print(f"  {name}", file=sys.stderr)
        os._exit(1)


sys.addaudithook(_machine_configuration)
atexit.register(_report_machine_reads)

_render = templates.TimedTemplates.TemplateResponse


def _well_formed(self: templates.TimedTemplates, *args: Any, **kwargs: Any) -> _TemplateResponse:
    response = _render(self, *args, **kwargs)
    found = well_formed.problems(bytes(response.body).decode())
    if found:
        name = args[1] if len(args) > 1 else kwargs.get("name", "?")
        raise AssertionError(f"{name} does not close what it opens: " + "; ".join(found))
    return response


templates.TimedTemplates.TemplateResponse = _well_formed  # type: ignore[method-assign]
