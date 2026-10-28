"""The page templates and what every one of them can read (K01, review 2026-10-28).

One Jinja environment for the whole interface: the globals and filters the
layout and the pages use, the static assets' cache token, the release in the
header, and the theme and clock read from the browser's cookies. Each page
renders through `TEMPLATES`; its render time is counted (`timing`).
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import Request
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse

from haprion_ui import (
    certificates,
    cluster_identity,
    features,
    health,
    metrics,
    moments,
    oidc_web,
    proxies,
    timing,
    update_check,
    waf,
)
from haprion_ui.form_groups import form_groups, waf_exception_count
from haprion_ui.health_rows import health_rows


class TimedTemplates(Jinja2Templates):
    """Every page's template time counted as such (`timing`)."""

    def TemplateResponse(self, *args: Any, **kwargs: Any) -> _TemplateResponse:
        def render() -> _TemplateResponse:
            response: _TemplateResponse = Jinja2Templates.TemplateResponse(self, *args, **kwargs)
            return response

        return timing.rendered(render)


def _layout_context(request: Request) -> dict[str, Any]:
    """What the layout reads on every page, from the application rather than the page.

    Each page passed `management_writes` itself, and one that forgot drew a
    menu without Settings (review 2026-10-22, 2-9).
    """

    config = getattr(request.app.state, "config", None)
    return {} if config is None else {"management_writes": config.management_writes}


TEMPLATES = TimedTemplates(
    directory=str(Path(__file__).parent / "templates"), context_processors=[_layout_context]
)

STATIC_DIRECTORY = Path(__file__).parent / "static"


def asset_token(directory: Path = STATIC_DIRECTORY) -> str:
    """A short token that changes whenever a local asset does.

    Without it a stylesheet change is invisible until every reader empties a
    cache they have no reason to suspect - and worse, it is invisible
    *selectively*: the new markup arrives with the old CSS, which looks like a
    layout bug in the new page rather than like a stale file. That happened
    once; this is the fix that keeps it from happening again.

    Computed from size and modification time rather than from file contents:
    a release is a fresh directory of files, so the two move together, and this
    reads no bytes on a path that runs at startup.
    """

    digest = hashlib.sha256()
    try:
        for path in sorted(directory.iterdir()):
            if path.is_file():
                stat = path.stat()
                digest.update(f"{path.name}:{stat.st_size}:{stat.st_mtime_ns}".encode())
    except OSError:
        # A missing static directory is a deployment fault that the mount will
        # report; it must not stop a page from rendering its own diagnosis.
        return "0"
    return digest.hexdigest()[:12]


def release_label(prefix: str | None = None) -> tuple[str, str]:
    """The version beside the name in the header, and the release it runs from.

    The release is the directory the environment lives in,
    `/opt/haprion-ui/releases/<id>/venv`, reached through `current`; anywhere
    else - a checkout, the tests - there is no release, and the version says it.
    """

    version = f"v{importlib.metadata.version('haprion-ui')}"
    release = Path(prefix or sys.prefix).resolve().parent
    return version, release.name if release.parent.name == "releases" else version


#
# Resolved once, at import. The files cannot change under a running release -
# a release directory is read-only and a new one is a new process.
#
TEMPLATES.env.globals["asset_token"] = asset_token()
TEMPLATES.env.globals["release_version"], TEMPLATES.env.globals["release_id"] = release_label()
INSTALLED_VERSION = importlib.metadata.version("haprion-ui")
TEMPLATES.env.globals["update_available"] = update_check.header
TEMPLATES.env.globals["new_request_key"] = lambda: str(uuid4())
#
# HAProxy's check codes as sentences. A global rather than a field on the row:
# the rows come from the engine's own dataclass, which the CLI shares, and how
# a web page words something is not the engine's business.
#
TEMPLATES.env.globals["check_phrase"] = health.check_phrase
TEMPLATES.env.globals["form_groups"] = form_groups
TEMPLATES.env.globals["waf_exception_count"] = waf_exception_count
TEMPLATES.env.globals["waf_where"] = waf.where
TEMPLATES.env.globals["health_rows"] = health_rows
TEMPLATES.env.globals["feature_on"] = features.is_on
TEMPLATES.env.filters["accent_class"] = cluster_identity.accent_class
TEMPLATES.env.filters["cluster_accent"] = lambda cluster: cluster_identity.accent_class(
    cluster_identity.accent_index(cluster)
)
TEMPLATES.env.globals["through_provider"] = oidc_web.through_provider

#
# The theme is rendered into the document by the server, from a cookie the
# browser maintains. It has to be known before the first byte: a theme applied
# by script is applied after the first paint at the earliest, and between two
# documents the browser paints its own light canvas - a flash on every
# navigation, and every tab here is a full page load.
#
THEME_COOKIE = "haprion_ui_theme"
# The browser's IANA zone, written by zone.js; read, never set, by the server.
ZONE_COOKIE = "haprion_ui_zone"
THEMES = ("light", "dark")


def selected_theme(request: Request) -> str:
    """Return the requested theme, or the default for anything else.

    The value is written by client-side script and is therefore attacker
    controlled. It reaches an HTML attribute, so it is matched against the
    themes that exist rather than escaped and passed through.
    """
    theme = request.cookies.get(THEME_COOKIE, "")
    return theme if theme in THEMES else THEMES[0]


TEMPLATES.env.filters["selected_theme"] = selected_theme


def shown_at(moment: datetime) -> str:
    """One stored moment, in the clock the person reading it is holding.

    Times are stored and reasoned about in UTC everywhere, and the traffic card
    already prints them in the host's zone for the reason written beside
    `metrics.shown`: a page whose times cannot be lined up against `journalctl`
    or a deploy sends people to the wrong minute. The traffic log is the page
    most likely to be read beside a journal, so it uses the same clock and the
    same format rather than a second one.
    """

    return moments.moment(moment)


TEMPLATES.env.filters["shown_at"] = shown_at
TEMPLATES.env.filters["shown_day"] = moments.day
TEMPLATES.env.filters["shown_time"] = moments.time_of_day
TEMPLATES.env.filters["groupby_object"] = waf.by_object
TEMPLATES.env.filters["shown"] = metrics.shown
TEMPLATES.env.filters["certificate_order"] = lambda rows, sort: certificates.TABLE.ordered(
    rows, sort
)
TEMPLATES.env.filters["proxy_order"] = lambda rows, sort, lamps: proxies.TABLE.ordered(
    rows, sort, lamps
)
TEMPLATES.env.filters["proxy_page_link"] = proxies.page_link
TEMPLATES.env.globals["proxy_page_size"] = proxies.PAGE_SIZE
