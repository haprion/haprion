"""*Test a path* on an object's page (B496, 7): the field, and the answer under it.

The answer is the engine's (`haprion.path_test`), the sentence
`haprion-objects --path` prints. This module adds only what the page knows and
the terminal does not: whether a draft or a saved change sits on top of the
stored object, which the test leaves out.
"""

from __future__ import annotations

from dataclasses import dataclass

from haprion.path_test import PathRefused, answer

from haprion_ui.db import ProxyDraft


@dataclass(frozen=True, slots=True)
class PathQuestion:
    asked: str
    """What the field holds: the path asked, or empty before anything was."""

    answer: str = ""
    tone: str = "unknown"
    notes: tuple[str, ...] = ()


def path_question(
    name: str, document: str | None, asked: str | None, draft: ProxyDraft | None
) -> PathQuestion | None:
    """The field and its answer, or None where the object does not route by path.

    `document` is the stored object's text, None for a proxy that is not an
    http or https object stored here.
    """

    if document is None:
        return None
    if asked is None or asked == "":
        return PathQuestion(asked="")
    try:
        found = answer(name, document, asked)
    except PathRefused as exc:
        return PathQuestion(asked=asked, answer=str(exc), tone="critical")
    route = found.route
    if route is None:
        tone = "warning"
    elif route.redirect is not None:
        tone = "info"
    else:
        tone = "healthy"
    notes = found.notes
    if draft is not None:
        #
        # The test reads the stored object, as the button beside it says. Work
        # on top of it that is not published yet may route differently, and a
        # reader who just changed a route would otherwise test the old one.
        #
        work = "the draft" if draft.stage == "draft" else "the saved change"
        notes = (*notes, f"tested as stored, without {work}")
    return PathQuestion(asked=asked, answer=found.sentence, tone=tone, notes=notes)
