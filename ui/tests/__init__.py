"""The interface's tests.

Every page any test renders is held to closing what it opens (review
26-10-24, 04-13): Jobs' empty state left a <div> open, which the browser
mends and the next change to the template inherits. Checked here, where every
module of the suite passes, rather than in a test that would have to know each
page and each state of it.
"""

from __future__ import annotations

from typing import Any

from starlette.templating import _TemplateResponse

from haprion_ui import views
from tests import well_formed

_render = views._TimedTemplates.TemplateResponse


def _well_formed(self: views._TimedTemplates, *args: Any, **kwargs: Any) -> _TemplateResponse:
    response = _render(self, *args, **kwargs)
    found = well_formed.problems(bytes(response.body).decode())
    if found:
        name = args[1] if len(args) > 1 else kwargs.get("name", "?")
        raise AssertionError(f"{name} does not close what it opens: " + "; ".join(found))
    return response


views._TimedTemplates.TemplateResponse = _well_formed  # type: ignore[method-assign]
