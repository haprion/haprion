"""What a route matches, and what the backend then sees.

This is the frozen half of the generator. The generator itself will emit `acl`
and `use_backend ... if` lines, and HAProxy will do the matching at runtime -
but the rules those lines have to express are decided here, once, before the
first golden file exists. Every change to this module after that point rewrites
every golden file, which is exactly why it is written and tested on its own
first.

The functions here are a reference model, not a request path. Nothing in
production routes traffic through them: HAProxy does. They exist so the rules
can be stated as executable tests rather than as prose that two people read
differently, and so the generator has one place to ask "which route wins" while
it decides file order.

Three rules are worth reading before the code, because they are the ones that
surprise people:

- A prefix matches on a segment boundary. `/api` matches `/api` and `/api/v1`
  and does not match `/apix`. Plain string prefixes are the classic source of a
  route that steals traffic from a site nobody was thinking about.
- The query string is never matched and never touched. It is split off before
  matching and put back unchanged after rewriting.
- Percent-encoding is compared as it arrived. Normalising first would make the
  result depend on the HAProxy version's idea of normalisation, and a routing
  rule that changes meaning on upgrade is not a rule.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from haprion.proxy_model import FORBIDDEN_IN_VALUE, Route
from haprion.proxy_model import HEADER_NAME as MODEL_HEADER_NAME

#
# An HTTP field name, as RFC 9110 defines a token. Header names are generated
# into configuration, so a name outside this set is not a header with an odd
# spelling - it is something that would change what the surrounding
# configuration line means.
#
# Taken from the model rather than written again here. The predicates below
# were the frozen semantics before the model had header fields; now that it
# does, one definition has to serve both or they will drift apart in the way
# only a visitor notices.
#
HEADER_NAME = MODEL_HEADER_NAME


def split_target(target: str) -> tuple[str, str]:
    """Separate the path from the query string.

    The query is returned with its `?` still attached, or as an empty string
    when there was none, so that putting it back is concatenation and cannot
    invent or lose a separator. `/a?` keeps its empty query for the same
    reason: it is what the client sent, and this layer is not in the business
    of deciding that it meant nothing.
    """

    head, separator, tail = target.partition("?")
    return head, separator + tail if separator else ""


def normalise_for_match(path: str) -> str:
    """The form a path is compared in.

    Only the trailing slash is removed, and only for comparison. `/api` and
    `/api/` are the same route; what the backend is sent is decided by the
    route's prefix fields further down, not by which of the two the client
    happened to type. Root stays `/`, because a path has to start somewhere.
    """

    stripped = path.rstrip("/")
    return stripped or "/"


def matches(route: Route, path: str) -> bool:
    """Whether this one route claims this request path.

    `path` is the request path with the query already split off - passing a
    target with a query would silently compare the query too, which is the bug
    this module exists to prevent, so callers go through `split_target` first.
    """

    candidate = normalise_for_match(path)
    if route.match == "exact":
        return candidate == route.path
    if route.path == "/":
        #
        # The root prefix is every path's ancestor. Stated rather than left to
        # the boundary test below, which would compare against `//`.
        #
        return True
    return candidate == route.path or candidate.startswith(route.path + "/")


def order_routes(routes: Iterable[Route]) -> tuple[Route, ...]:
    """The order the routes are written to the configuration file in.

    This is where longest-prefix-first is decided, and the decision is made
    once, here, at generation time. At runtime the file order is the only truth
    there is: HAProxy evaluates `use_backend` lines top to bottom and takes the
    first that matches, so an ordering mistake shows up as traffic in the wrong
    place rather than as an error.

    Specificity is segment count, not length. `/a/b` beats `/abcdefgh` because a
    deeper path is a more specific statement about the request than a longer
    one, and character counts would make `/api-gateway` outrank `/api/v1`.

    Two further keys make the order total, so that the same object always
    produces byte-identical output:

    - an exact route sorts before a prefix route at the same depth, because a
      prefix route at that depth would otherwise swallow the one request the
      exact route was written for;
    - anything still tied sorts by path, which cannot itself tie: the model
      refuses two routes with the same path and match mode.
    """

    return tuple(
        sorted(
            routes,
            key=lambda route: (-route.segments, 0 if route.match == "exact" else 1, route.path),
        )
    )


def select(ordered: Sequence[Route], target: str) -> Route | None:
    """The route that wins, walking the file the way HAProxy walks it.

    Takes routes already in file order rather than sorting them itself. The
    generator sorts once and writes that order out; if this function sorted
    too, a disagreement between the two would be invisible here and visible
    only in production.

    Returns `None` when nothing matches. An object without a `/` route has
    paths that reach no backend, and that is a fact about the object which the
    caller decides what to do with - it is not this function's place to invent
    a default.
    """

    path, _ = split_target(target)
    for route in ordered:
        if matches(route, path):
            return route
    return None


def rewrite(route: Route, target: str) -> str:
    """The target the backend is given.

    The path is rewritten from what the client actually sent, not from the
    normalised form used for matching: a trailing slash the client typed
    survives unless a prefix rule removes it. The query string is carried
    across untouched.

    The four path modes the plan names are the four combinations of the two
    optional fields. Preserve is both absent, and needs no code.
    """

    path, query = split_target(target)

    if route.strip_prefix is not None:
        #
        # The model has already established that `strip_prefix` is a prefix of
        # the route's own path, and the route matched this request, so the
        # request path starts with it. Stripping cannot leave a fragment of a
        # segment behind.
        #
        path = path[len(route.strip_prefix) :] or "/"
        if not path.startswith("/"):
            path = "/" + path

    if route.add_prefix is not None:
        path = route.add_prefix + path

    return path + query


def header_name_is_usable(name: str) -> bool:
    """Whether a header name can be written into configuration at all."""

    return bool(HEADER_NAME.fullmatch(name))


def header_value_is_usable(value: str) -> bool:
    """Whether a header value is a value rather than a way out of one.

    Checked where the value is accepted, not where configuration is generated.
    A refusal at generation time arrives after somebody has already been told
    their change was saved, and it arrives without a field to point at.
    """

    return not any(character in value for character in FORBIDDEN_IN_VALUE)
