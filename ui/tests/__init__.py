"""The interface's tests.

Every page any test renders is held to closing what it opens (review
26-10-24, 04-13): Jobs' empty state left a <div> open, which the browser
mends and the next change to the template inherits. Checked here, where every
module of the suite passes, rather than in a test that would have to know each
page and each state of it.
"""

from __future__ import annotations

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
# And a grid rather than a default (review 26-10-29, A09): a reach for a path
# under /etc/haprion fails the module that made it. It is in the gate's
# runner, `tools/unittest_left_open.py`, which every run of either suite in the
# gate goes through - the pool, the database tests, the run without HAProxy -
# and a targeted run names; a plain `python -m unittest` has none of it.
#

_render = templates.TimedTemplates.TemplateResponse


def _well_formed(self: templates.TimedTemplates, *args: Any, **kwargs: Any) -> _TemplateResponse:
    response = _render(self, *args, **kwargs)
    found = well_formed.problems(bytes(response.body).decode())
    if found:
        name = args[1] if len(args) > 1 else kwargs.get("name", "?")
        raise AssertionError(f"{name} does not close what it opens: " + "; ".join(found))
    return response


templates.TimedTemplates.TemplateResponse = _well_formed  # type: ignore[method-assign]
