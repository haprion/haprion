"""Settings -> Users -> OIDC configuration: the web's half (Fas 13 part 4, O4; B197-B199).

The web cannot reach the provider and does not try: every question goes to
the OIDC helper over its socket (B196), and this module is the asking. It also
reads the settings form into the provider row's columns, with the rules the
row's own checks hold, so that a mistake is a sentence on the page rather than
a constraint name.

The client secret is sealed here, in the request that typed it, against the
public key platform step 17 made, and bound to the issuer and client it was
typed for. The web keeps the sealed bytes and cannot open them.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import urllib.parse
import uuid
from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from haproxy_mgmt import helper_socket, oidc
from haproxy_mgmt.dns_profile_keys import KeyFileError, read_public_key

from haproxy_ui.db import OidcProvider

SOCKET_PATH = "/run/haproxy-mgmt/oidc.sock"
#
# The helper's own bound is ten seconds a call and three calls; this is its
# unit's start timeout, so a helper that hangs becomes a sentence.
#
TIMEOUT_SECONDS = 45.0
CALLBACK_PATH = "/login/oidc/callback"

CLAIM_PATH = re.compile(r"^[A-Za-z0-9_:./-]{1,128}$")
SCOPE = re.compile(r"^[A-Za-z0-9_:./-]{1,128}$")

LOGOUT_MODES = {"app": "This interface only", "provider": "Also at the provider"}
LOCAL_LOGINS = {"break_glass_only": "Break-glass accounts only", "all": "All local accounts"}
AUTH_METHODS = {
    "client_secret_basic": "client_secret_basic",
    "client_secret_post": "client_secret_post",
}


class OidcProblem(Exception):
    """Either of the two below: a sentence of ours, fit to show on the page."""


class OidcUnavailable(OidcProblem):
    """The helper could not be asked: not installed, not running, or silent."""


class OidcRefused(OidcProblem):
    """The helper answered with a refusal, as its code and sentence."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def redirect_uri(base_url: str) -> str:
    """Where the provider sends the browser back: this interface's callback."""

    return base_url.rstrip("/") + CALLBACK_PATH


def ask(
    action: str,
    provider: OidcProvider,
    *,
    redirect: str,
    path: str = SOCKET_PATH,
    **parameters: Any,
) -> dict[str, Any]:
    """One question to the helper about the stored provider; its result."""

    if provider.issuer is None:
        raise OidcRefused("bad_input", "No issuer is set.")
    fields: dict[str, Any] = {
        "action": action,
        "issuer": provider.issuer,
        **({"ca_pem": provider.ca_pem} if provider.ca_pem else {}),
    }
    if action != "discover":
        if provider.client_id is None or provider.client_secret_sealed is None:
            raise OidcRefused("bad_input", "Set the client ID and the client secret first.")
        fields.update(
            {
                "client_id": provider.client_id,
                "client_secret_sealed": base64.b64encode(provider.client_secret_sealed).decode(
                    "ascii"
                ),
                "key_id": provider.key_id,
                "auth_method": provider.auth_method,
                "redirect_uri": redirect,
            }
        )
    fields.update(parameters)
    request = {
        "schema_version": 1,
        "operation": "oidc",
        "cluster": None,
        "request_id": str(uuid.uuid4()),
        "parameters": fields,
    }
    try:
        raw = helper_socket.ask(request, path=path, timeout=TIMEOUT_SECONDS, what="the OIDC helper")
    except helper_socket.HelperUnavailable as error:
        raise OidcUnavailable(str(error)) from error
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise OidcUnavailable(
            "The OIDC helper answered with something that is not JSON."
        ) from error
    if not isinstance(document, dict):
        raise OidcUnavailable("The OIDC helper answered with something that is not an object.")
    result = document.get("result")
    if document.get("ok") is True and isinstance(result, dict):
        return result
    refusal = document.get("error")
    if not isinstance(refusal, dict):
        refusal = {}
    raise OidcRefused(str(refusal.get("code", "failed")), str(refusal.get("message", "Refused.")))


# - the form ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Parsed:
    settings: dict[str, Any]
    problem: str
    #
    # Whether the issuer or the client changed: the sealed secret is bound to
    # both, so a new one must be typed.
    #
    identity_changed: bool


def _text(form: Mapping[str, str], name: str) -> str:
    return (form.get(name) or "").strip()


def parse(
    form: Mapping[str, str],
    current: OidcProvider,
    *,
    public_key: Path | None,
) -> Parsed:
    """The form as the row's columns, or the first thing wrong with it."""

    def refused(problem: str) -> Parsed:
        return Parsed({}, problem, False)

    try:
        issuer = oidc.issuer_url(_text(form, "issuer"))
    except oidc.OidcError:
        return refused("The issuer must be an https URL without a query.")
    if len(issuer) > 512:
        return refused("The issuer is longer than 512 characters.")
    client_id = _text(form, "client_id")
    if not 1 <= len(client_id) <= 256:
        return refused("Enter the client ID.")
    auth_method = _text(form, "auth_method")
    if auth_method not in AUTH_METHODS:
        return refused("Choose how the client authenticates.")
    scopes = " ".join(_text(form, "scopes").split())
    if (
        "openid" not in scopes.split()
        or len(scopes) > 512
        or not all(SCOPE.fullmatch(scope) for scope in scopes.split())
    ):
        return refused("The scopes must include openid.")
    username_claim = _text(form, "username_claim")
    groups_claim = _text(form, "groups_claim")
    if not CLAIM_PATH.fullmatch(username_claim) or not CLAIM_PATH.fullmatch(groups_claim):
        return refused("A claim is a name or a dotted path, like realm_access.roles.")
    admin_group = _text(form, "admin_group") or None
    reader_group = _text(form, "reader_group") or None
    if admin_group is None and reader_group is None:
        return refused("Name the group for admins, readers or both.")
    if any(group is not None and len(group) > 256 for group in (admin_group, reader_group)):
        return refused("A group name is longer than 256 characters.")
    button_text = _text(form, "button_text")
    if not 1 <= len(button_text) <= 64:
        return refused("The button text is 1 to 64 characters.")
    logout_mode = _text(form, "logout_mode")
    local_login = _text(form, "local_login")
    if logout_mode not in LOGOUT_MODES or local_login not in LOCAL_LOGINS:
        return refused("Choose how sign-out and local sign-in work.")
    ca_pem = (form.get("ca_pem") or "").strip() or None
    if ca_pem is not None:
        try:
            if not x509.load_pem_x509_certificates(ca_pem.encode("ascii")):
                raise ValueError
        except (ValueError, UnicodeEncodeError):
            return refused("The CA certificate is not a PEM certificate.")
        if len(ca_pem) > 65536:
            return refused("The CA certificate is over 64 KiB.")

    settings: dict[str, Any] = {
        "issuer": issuer,
        "client_id": client_id,
        "auth_method": auth_method,
        "scopes": scopes,
        "username_claim": username_claim,
        "groups_claim": groups_claim,
        "admin_group": admin_group,
        "reader_group": reader_group,
        "auto_create": form.get("auto_create") == "on",
        "button_text": button_text,
        "prompt_login": form.get("prompt_login") == "on",
        "logout_mode": logout_mode,
        "local_login": local_login,
        "ca_pem": ca_pem,
    }
    identity_changed = (issuer, client_id) != (current.issuer, current.client_id)
    secret = form.get("client_secret") or ""
    if secret:
        if len(secret) > 1024:
            return refused("The client secret is longer than 1024 characters.")
        if public_key is None:
            return refused("The OIDC helper is not installed here; see platform step 17.")
        try:
            key = read_public_key(public_key)
        except KeyFileError:
            return refused("The OIDC helper's public key could not be read; see platform step 17.")
        settings["client_secret_sealed"] = oidc.seal_client_secret(
            key, issuer=issuer, client_id=client_id, secret=secret
        )
        settings["key_id"] = key.key_id
    elif identity_changed or current.client_secret_sealed is None:
        return refused(
            "Type the client secret: it is kept for the issuer and client it was saved for."
        )
    return Parsed(settings, "", identity_changed)


def summary(provider: OidcProvider | None) -> str:
    """One line for the Users card: whether sign-in goes through a provider, and which."""

    if provider is None or provider.issuer is None:
        return ""
    state = "on" if provider.enabled else "off"
    return f"SSO {state} · {provider.issuer}"


# - signing in (O5) -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LoginTokens:
    state: str
    nonce: str
    verifier: str


def new_login_tokens() -> LoginTokens:
    """Three unguessable values for one sign-in: 43 characters each (RFC 7636)."""

    return LoginTokens(
        state=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        verifier=secrets.token_urlsafe(32),
    )


def discovery(result: Mapping[str, Any]) -> oidc.Discovery:
    """The helper's `discover` answer as the engine's own type."""

    return oidc.Discovery(
        issuer=str(result["issuer"]),
        authorization_endpoint=str(result["authorization_endpoint"]),
        token_endpoint=str(result["token_endpoint"]),
        jwks_uri=str(result["jwks_uri"]),
        userinfo_endpoint=result.get("userinfo_endpoint"),
        end_session_endpoint=result.get("end_session_endpoint"),
        auth_methods=tuple(result.get("auth_methods") or ()),
        algorithms=tuple(result.get("algorithms") or ()),
    )


def authorization_url(
    provider: OidcProvider, found: Mapping[str, Any], tokens: LoginTokens, *, redirect: str
) -> str:
    return oidc.authorization_url(
        discovery(found),
        client_id=provider.client_id or "",
        redirect_uri=redirect,
        scopes=provider.scopes,
        state=tokens.state,
        nonce=tokens.nonce,
        verifier=tokens.verifier,
        prompt_login=provider.prompt_login,
    )


def role_for(provider: OidcProvider, groups: list[str]) -> str | None:
    """The role the provider's groups give, admin before reader; None for neither (B195)."""

    if provider.admin_group is not None and provider.admin_group in groups:
        return "admin"
    if provider.reader_group is not None and provider.reader_group in groups:
        return "reader"
    return None


def end_session_url(
    found: Mapping[str, Any], provider: OidcProvider, *, id_token: str, back_to: str
) -> str | None:
    """Where signing out at the provider goes (RP-initiated logout), or None."""

    endpoint = found.get("end_session_endpoint")
    if not isinstance(endpoint, str) or not endpoint.startswith("https://"):
        return None
    parameters = {
        "id_token_hint": id_token,
        "post_logout_redirect_uri": back_to,
        "client_id": provider.client_id or "",
    }
    separator = "&" if urllib.parse.urlsplit(endpoint).query else "?"
    return endpoint + separator + urllib.parse.urlencode(parameters)


#
# Whether the person signed in on this request came through the provider, for
# the account menu: such an account has no password here to change.
#
_THROUGH_PROVIDER: ContextVar[bool] = ContextVar("through_provider", default=False)


def note_session(source: str) -> None:
    _THROUGH_PROVIDER.set(source == "oidc")


def through_provider() -> bool:
    return _THROUGH_PROVIDER.get()
