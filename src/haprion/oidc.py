"""OpenID Connect, the half that talks to the provider (Fas 13 part 4, O3; B195-B199).

The web interface cannot reach the network - its unit allows localhost and
nothing else - and should not: it is the part a browser talks to. So every
request to the provider is made here, by the OIDC helper, an account of its own
behind a socket (B196). This module is that helper's logic, free of the socket
so that it can be tested against a provider of the test's own making.

What it follows, and what it does not
-------------------------------------
It follows OpenID Connect Core 1.0 and Discovery 1.0, with the authorization
code flow and PKCE, and the deviations of the larger providers that B199 lists:
claims named by a dotted path, a claim that is an object counted as its keys,
userinfo as an addition and never a requirement, and a group overage answered
with a sentence rather than a call to Microsoft Graph.

It never takes a URL from its caller. The issuer comes from the provider row
the web wrote; every other address comes from that issuer's own discovery
document, fetched over verified TLS. Only `https`, no redirect is followed, no
proxy from the environment is used, and every answer is bounded in time and
size, because what answers may be a provider an administrator typed in.

The client secret
-----------------
The web seals it against this installation's public key and cannot read it
back (B146's model). The sealed text names the issuer and the client it is for,
and this module refuses to open it for any other: an administrator session
that changes the issuer cannot have the secret sent to the new one, it has to
type the secret again.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import jwt

from haprion.dns_profile_keys import (
    DnsProfilePrivateKey,
    DnsProfilePublicKey,
    KeyFileError,
    open_sealed,
    seal,
)

TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 1024 * 1024
#
# Clock skew allowed between this host and the provider, in both directions.
#
LEEWAY_SECONDS = 60

ASYMMETRIC = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
)
#
# HMAC with the client secret as the key (OIDC Core 10.1). authentik signs this
# way when no signing key is chosen, which B199 found; the helper holds the
# secret anyway, so verifying it here adds no one who can.
#
SYMMETRIC = frozenset({"HS256", "HS384", "HS512"})
AUTH_METHODS = ("client_secret_basic", "client_secret_post")

SEAL_PURPOSE = "oidc_client_secret"


class OidcError(Exception):
    """Something the provider did or said, as a stable code and a sentence."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# - addresses -------------------------------------------------------------


def https_url(value: object, what: str) -> str:
    """An absolute `https` URL with a host and no credentials, or a refusal."""

    if not isinstance(value, str) or not value or len(value) > 2048:
        raise OidcError("bad_discovery", f"{what} is not a URL")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise OidcError("bad_discovery", f"{what} is not an https URL: {value}")
    if parsed.username is not None or parsed.password is not None:
        raise OidcError("bad_discovery", f"{what} carries credentials")
    if parsed.fragment:
        raise OidcError("bad_discovery", f"{what} has a fragment")
    return value


def issuer_url(value: object) -> str:
    """The issuer as the provider row holds it: https, no query, no fragment."""

    issuer = https_url(value, "the issuer")
    if urllib.parse.urlsplit(issuer).query:
        raise OidcError("bad_issuer", "the issuer has a query")
    return issuer


# - the one way out ---------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer, not an instruction: it is refused, not followed."""

    def redirect_request(self, *_: Any, **__: Any) -> None:
        return None


@dataclass(frozen=True, slots=True)
class Answer:
    status: int
    body: bytes

    def json(self, what: str) -> dict[str, Any]:
        try:
            document = json.loads(self.body)
        except ValueError as exc:
            raise OidcError("bad_response", f"{what} is not JSON") from exc
        if not isinstance(document, dict):
            raise OidcError("bad_response", f"{what} is not a JSON object")
        return document


class Client:
    """HTTPS to the provider and nowhere else, with the limits above.

    `ca_pem` adds a certificate authority to the system's, for a provider
    behind an internal CA (B198); it never replaces them.
    """

    def __init__(
        self,
        *,
        ca_pem: str | None = None,
        timeout: float = TIMEOUT_SECONDS,
        max_bytes: int = MAX_RESPONSE_BYTES,
        context: ssl.SSLContext | None = None,
    ) -> None:
        if context is None:
            context = ssl.create_default_context()
            if ca_pem:
                try:
                    context.load_verify_locations(cadata=ca_pem)
                except (ssl.SSLError, ValueError) as exc:
                    raise OidcError("bad_ca", "the CA certificate could not be read") from exc
        self._timeout = timeout
        self._max_bytes = max_bytes
        #
        # An empty ProxyHandler, so an https_proxy in the environment cannot
        # route the provider's answers through somewhere else.
        #
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )

    def request(
        self,
        url: str,
        *,
        data: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Answer:
        https_url(url, "the address")
        body = None if data is None else urllib.parse.urlencode(data).encode("ascii")
        request = urllib.request.Request(  # noqa: S310 - https only, checked above
            url,
            data=body,
            headers={"Accept": "application/json", **(headers or {})},
            method="GET" if data is None else "POST",
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                return Answer(response.status, self._read(response))
        except urllib.error.HTTPError as exc:
            # A 4xx from the token endpoint is how OAuth says no; its body says why.
            if 300 <= exc.code < 400:
                raise OidcError(
                    "redirected", f"{url} answered with a redirect, which is not followed"
                ) from exc
            return Answer(exc.code, self._read(exc))
        except ssl.SSLError as exc:
            raise OidcError("tls", f"{url}: TLS failed: {exc.reason or exc}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLError):
                raise OidcError("tls", f"{url}: TLS failed: {reason.reason or reason}") from exc
            raise OidcError("unreachable", f"{url} could not be reached: {reason}") from exc

    def _read(self, stream: Any) -> bytes:
        body: bytes = stream.read(self._max_bytes + 1)
        if len(body) > self._max_bytes:
            raise OidcError("too_large", f"the answer is over {self._max_bytes} bytes")
        return body


# - discovery ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Discovery:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None
    end_session_endpoint: str | None
    auth_methods: tuple[str, ...]
    algorithms: tuple[str, ...]


def discover(client: Client, issuer: str) -> Discovery:
    """The provider's configuration, and a refusal if it is not the issuer's own."""

    issuer = issuer_url(issuer)
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    answer = client.request(url)
    if answer.status != 200:
        raise OidcError("bad_discovery", f"{url} answered {answer.status}")
    document = answer.json("the discovery document")
    stated = document.get("issuer")
    #
    # Exactly, as Discovery 4.3 requires - a trailing slash is a different
    # issuer, and authentik's has one (B199). Said in full, because the
    # difference is usually one character.
    #
    if stated != issuer:
        raise OidcError(
            "issuer_mismatch",
            f"the provider calls itself {stated!r}, not {issuer!r}; use its value exactly",
        )

    def optional(key: str) -> str | None:
        value = document.get(key)
        return None if value in (None, "") else https_url(value, key)

    def strings(key: str, default: tuple[str, ...]) -> tuple[str, ...]:
        value = document.get(key)
        if value is None:
            return default
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise OidcError("bad_discovery", f"{key} is not a list of names")
        return tuple(value)

    return Discovery(
        issuer=issuer,
        authorization_endpoint=https_url(
            document.get("authorization_endpoint"), "authorization_endpoint"
        ),
        token_endpoint=https_url(document.get("token_endpoint"), "token_endpoint"),
        jwks_uri=https_url(document.get("jwks_uri"), "jwks_uri"),
        userinfo_endpoint=optional("userinfo_endpoint"),
        end_session_endpoint=optional("end_session_endpoint"),
        # The defaults are the specification's (Discovery 3).
        auth_methods=strings("token_endpoint_auth_methods_supported", ("client_secret_basic",)),
        algorithms=strings("id_token_signing_alg_values_supported", ("RS256",)),
    )


def signing_keys(client: Client, discovery: Discovery) -> jwt.PyJWKSet:
    answer = client.request(discovery.jwks_uri)
    if answer.status != 200:
        raise OidcError("bad_keys", f"{discovery.jwks_uri} answered {answer.status}")
    try:
        return jwt.PyJWKSet.from_dict(answer.json("the key set"))
    except jwt.PyJWKSetError as exc:
        raise OidcError("bad_keys", f"the key set has no usable key: {exc}") from exc


# - the client secret -------------------------------------------------------


def seal_client_secret(
    key: DnsProfilePublicKey, *, issuer: str, client_id: str, secret: str
) -> bytes:
    """What the web stores: the secret, bound to the issuer and the client."""

    plaintext = {
        "purpose": SEAL_PURPOSE,
        "key_id": key.key_id,
        "issuer": issuer,
        "client_id": client_id,
        "secret": secret,
    }
    return seal(key, json.dumps(plaintext, sort_keys=True).encode("utf-8"))


def open_client_secret(
    key: DnsProfilePrivateKey, sealed: bytes, *, issuer: str, client_id: str
) -> str:
    """The secret, if it was sealed for exactly this issuer and client."""

    try:
        document = json.loads(open_sealed(key, sealed))
    except (KeyFileError, ValueError) as exc:
        raise OidcError("bad_secret", "the client secret could not be opened") from exc
    if not isinstance(document, dict) or document.get("purpose") != SEAL_PURPOSE:
        raise OidcError("bad_secret", "the sealed text is not a client secret")
    if document.get("key_id") != key.key_id:
        raise OidcError("bad_secret", "the client secret was sealed for another key")
    if document.get("issuer") != issuer or document.get("client_id") != client_id:
        raise OidcError(
            "secret_for_another_client",
            "the client secret was saved for another issuer or client; type it again",
        )
    secret = document.get("secret")
    if not isinstance(secret, str) or not secret:
        raise OidcError("bad_secret", "the sealed client secret is empty")
    return secret


# - the token endpoint ------------------------------------------------------


def _client_authentication(
    client_id: str, secret: str, method: str
) -> tuple[dict[str, str], dict[str, str]]:
    """Form fields and headers for the client's method (RFC 6749 2.3.1)."""

    if method == "client_secret_basic":
        # Each half form-encoded before the pair is, as the RFC says and some
        # providers check.
        pair = f"{urllib.parse.quote(client_id, safe='')}:{urllib.parse.quote(secret, safe='')}"
        token = base64.b64encode(pair.encode("utf-8")).decode("ascii")
        return {}, {"Authorization": f"Basic {token}"}
    if method == "client_secret_post":
        return {"client_id": client_id, "client_secret": secret}, {}
    raise OidcError("bad_input", f"unknown client authentication method: {method}")


def _token_request(
    client: Client,
    discovery: Discovery,
    *,
    client_id: str,
    secret: str,
    method: str,
    fields: Mapping[str, str],
) -> Answer:
    extra, headers = _client_authentication(client_id, secret, method)
    return client.request(discovery.token_endpoint, data={**fields, **extra}, headers=headers)


def _oauth_error(answer: Answer) -> tuple[str, str]:
    try:
        document = answer.json("the error")
    except OidcError:
        return "", ""
    error = document.get("error")
    description = document.get("error_description")
    return (
        error if isinstance(error, str) else "",
        description if isinstance(description, str) else "",
    )


def check_client(
    client: Client,
    discovery: Discovery,
    *,
    client_id: str,
    secret: str,
    method: str,
    redirect_uri: str,
) -> tuple[bool, str]:
    """Whether the provider accepts this client, without anyone signing in.

    A code that was never issued is sent. `invalid_grant` means the provider got
    as far as the code, so it accepted the client and its secret;
    `invalid_client` or `unauthorized_client` means it did not. Anything else is
    reported as it came.
    """

    answer = _token_request(
        client,
        discovery,
        client_id=client_id,
        secret=secret,
        method=method,
        fields={
            "grant_type": "authorization_code",
            "code": "haprion-verify-" + hashlib.sha256(client_id.encode()).hexdigest()[:16],
            "redirect_uri": redirect_uri,
            "code_verifier": "v" * 43,
        },
    )
    error, description = _oauth_error(answer)
    if error == "invalid_grant":
        return True, "the provider accepted the client and its secret"
    if error in ("invalid_client", "unauthorized_client"):
        return False, f"the provider refused the client: {description or error}"
    if answer.status == 200:
        return False, "the provider accepted a code that was never issued"
    return False, f"the provider answered {answer.status} {error or ''} {description}".strip()


# - the id_token --------------------------------------------------------------


def verify_id_token(
    token: str,
    *,
    discovery: Discovery,
    keys: jwt.PyJWKSet,
    client_id: str,
    secret: str,
    nonce: str,
) -> dict[str, Any]:
    """The id_token's claims, if every check OIDC Core asks of it holds (section 3.1.3, step 7)."""

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise OidcError("bad_token", "the id_token is not a JWT") from exc
    algorithm = header.get("alg")
    if algorithm not in ASYMMETRIC | SYMMETRIC:
        raise OidcError("bad_token", f"the id_token is signed with {algorithm!r}, which is refused")

    key: Any
    if algorithm in SYMMETRIC:
        key = secret.encode("utf-8")
    else:
        key = _key_for(keys, header.get("kid"), algorithm)

    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            key=key,
            algorithms=[algorithm],
            audience=client_id,
            issuer=discovery.issuer,
            leeway=LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise OidcError("bad_token", "the id_token has expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise OidcError("bad_token", "the id_token is for another client") from exc
    except jwt.InvalidIssuerError as exc:
        raise OidcError("bad_token", "the id_token is from another issuer") from exc
    except jwt.PyJWTError as exc:
        raise OidcError("bad_token", f"the id_token was refused: {exc}") from exc

    audience = claims.get("aud")
    authorized = claims.get("azp")
    if isinstance(audience, list) and len(audience) > 1 and authorized is None:
        raise OidcError("bad_token", "the id_token names several audiences and no azp")
    if authorized is not None and authorized != client_id:
        raise OidcError("bad_token", "the id_token was issued to another party (azp)")
    stated = claims.get("nonce")
    #
    # As bytes, for the reason `csrf_token_is_valid` gives: a nonce outside
    # ASCII made `compare_digest` raise instead of refuse (CR-05).
    #
    if not isinstance(stated, str) or not hmac.compare_digest(
        stated.encode("utf-8", "surrogatepass"), nonce.encode("utf-8", "surrogatepass")
    ):
        raise OidcError("bad_token", "the id_token's nonce is not this sign-in's")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise OidcError("bad_token", "the id_token has no subject")
    return claims


def _key_for(keys: jwt.PyJWKSet, kid: object, algorithm: str) -> Any:
    """The key the header names, or the only one that fits when it names none."""

    if isinstance(kid, str) and kid:
        try:
            chosen = keys[kid]
        except KeyError as exc:
            raise OidcError("bad_token", f"no key {kid!r} in the provider's key set") from exc
    else:
        family = {"R": "RSA", "P": "RSA", "E": "EC"}[algorithm[0]]
        fitting = [key for key in keys.keys if key.key_type == family]
        if len(fitting) != 1:
            raise OidcError("bad_token", "the id_token names no key and several could fit")
        chosen = fitting[0]
    return chosen.key


# - claims -------------------------------------------------------------------


def claim(claims: Mapping[str, Any], path: str) -> Any:
    """A claim by dotted path (`realm_access.roles`, B199), or None.

    A claim whose own name contains dots - Zitadel's `urn:zitadel:...` has
    colons, Keycloak's may have dots - is found by its whole name first.
    """

    if path in claims:
        return claims[path]
    value: Any = claims
    for part in path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def claim_values(claims: Mapping[str, Any], path: str) -> list[str]:
    """A claim read as a list of names.

    A string is one name, a list is its strings, and an object is its keys -
    Zitadel's roles are an object with the role names as keys (B199).
    """

    value = claim(claims, path)
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, Mapping):
        return [key for key in value if isinstance(key, str)]
    return []


def group_overage(claims: Mapping[str, Any], path: str) -> bool:
    """Whether the provider sent a pointer to the groups rather than the groups.

    Entra does, for someone in more than 200 groups: the claim is left out and
    `_claim_names` points at Microsoft Graph, or `hasgroups` says there are
    some. Neither is followed (B199).
    """

    names = claims.get("_claim_names")
    root = path.split(".", 1)[0]
    return (isinstance(names, Mapping) and root in names) or claims.get("hasgroups") is True


@dataclass(frozen=True, slots=True)
class SignedIn:
    issuer: str
    subject: str
    username: str
    groups: tuple[str, ...]
    id_token: str
    userinfo: str
    claims: dict[str, Any]


def fetch_userinfo(
    client: Client, discovery: Discovery, access_token: str | None, subject: str
) -> tuple[dict[str, Any], str]:
    """Userinfo as an addition, and a sentence about whether it was used.

    Never a reason to refuse a sign-in (B199 point 9). ADFS answers with the
    subject alone and its userinfo call is reported to fail; Authelia keeps the
    name and the groups there by default. A different subject means the answer
    is about someone else and must not be used (OIDC Core 5.3.2).
    """

    if discovery.userinfo_endpoint is None:
        return {}, "the provider has no userinfo endpoint"
    if not access_token:
        return {}, "no access token came with the id_token"
    try:
        answer = client.request(
            discovery.userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"}
        )
        if answer.status != 200:
            return {}, f"userinfo answered {answer.status}; not used"
        document = answer.json("userinfo")
    except OidcError as exc:
        return {}, f"userinfo failed and was not used: {exc}"
    if document.get("sub") != subject:
        return {}, "userinfo named another subject and was not used"
    return document, "userinfo used"


def exchange(
    client: Client,
    discovery: Discovery,
    keys: jwt.PyJWKSet,
    *,
    client_id: str,
    secret: str,
    method: str,
    code: str,
    verifier: str,
    redirect_uri: str,
    nonce: str,
    username_claim: str,
    groups_claim: str,
) -> SignedIn:
    """Trade the code for tokens, verify the id_token, and read who signed in."""

    answer = _token_request(
        client,
        discovery,
        client_id=client_id,
        secret=secret,
        method=method,
        fields={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )
    if answer.status != 200:
        error, description = _oauth_error(answer)
        raise OidcError(
            "token_refused",
            f"the provider refused the code: {description or error or answer.status}",
        )
    tokens = answer.json("the token response")
    id_token = tokens.get("id_token")
    if not isinstance(id_token, str):
        raise OidcError("bad_token", "the token response has no id_token")
    access_token = tokens.get("access_token")

    claims = verify_id_token(
        id_token,
        discovery=discovery,
        keys=keys,
        client_id=client_id,
        secret=secret,
        nonce=nonce,
    )
    extra, note = fetch_userinfo(
        client,
        discovery,
        access_token if isinstance(access_token, str) else None,
        claims["sub"],
    )
    #
    # The id_token wins where it says something; a claim it carries as null
    # says nothing, and does not hide what userinfo said.
    #
    merged = {**extra, **{name: value for name, value in claims.items() if value is not None}}

    if group_overage(merged, groups_claim) and not claim_values(merged, groups_claim):
        raise OidcError(
            "group_overage",
            "The provider sent a group overage instead of groups; use app roles (claim `roles`).",
        )
    username = claim(merged, username_claim)
    if not isinstance(username, str) or not username.strip():
        raise OidcError("no_username", f"the provider sent no {username_claim!r}")
    return SignedIn(
        issuer=discovery.issuer,
        subject=claims["sub"],
        username=username.strip(),
        groups=tuple(claim_values(merged, groups_claim)),
        id_token=id_token,
        userinfo=note,
        claims=merged,
    )


def code_challenge(verifier: str) -> str:
    """PKCE S256 (RFC 7636 4.2)."""

    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def authorization_url(
    discovery: Discovery,
    *,
    client_id: str,
    redirect_uri: str,
    scopes: str,
    state: str,
    nonce: str,
    verifier: str,
    prompt_login: bool,
) -> str:
    """Where the browser is sent to sign in."""

    parameters = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge(verifier),
        "code_challenge_method": "S256",
    }
    if prompt_login:
        parameters["prompt"] = "login"
    separator = "&" if urllib.parse.urlsplit(discovery.authorization_endpoint).query else "?"
    return discovery.authorization_endpoint + separator + urllib.parse.urlencode(parameters)
