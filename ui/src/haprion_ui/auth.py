"""Passwords, sessions and the CSRF token, kept apart from both SQL and routing.

Three decisions are worth stating before the code, because they are the ones
that would be expensive to change later:

* **The session token is opaque and lives only in the cookie.** The database
  stores its SHA-256 hash, so a dump of `app_session` - or that table read by
  anything that should not have it - cannot be replayed as a login. There is
  nothing to decrypt and no signing key to leak, because the token carries no
  claims: it is a random number that names a row.
* **The CSRF token is derived from the session token**, not stored. A caller
  that cannot read the cookie cannot compute it, which is exactly the property
  CSRF protection needs, and it means there is no second piece of state to
  expire, rotate or forget to clean up.
* **Timing is equalised on the failing paths.** An unknown username verifies
  against a fixed hash before answering, so "no such user" and "wrong password"
  cost the same and take the same time. Otherwise the login form doubles as a
  way to enumerate who exists.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from haprion_ui.config import Session as SessionPolicy
from haprion_ui.db import AuthenticatedSession

#
# `__Host-` names: a browser takes them only with Secure, Path=/ and no Domain,
# so a sibling domain cannot plant either (review 26-10-24, 09-06). Without
# Secure they go by their plain names on the wire (`plain_cookies`).
#
SESSION_COOKIE = "__Host-haprion_ui_session"
#
# A second, short-lived cookie that exists only to give the login form itself a
# CSRF token. Without it the one unprotected state-changing request in the
# application would be the login post - the one an attacker most wants to aim a
# forged submission at, to sign a victim in as somebody the attacker controls.
#
# Path=/ as the prefix demands, and replaced by the real session cookie on
# success.
#
PRE_SESSION_COOKIE = "__Host-haprion_ui_login"
CSRF_FIELD = "csrf_token"
TOKEN_BYTES = 32

#
# Deliberately explicit rather than the library defaults, so a dependency
# upgrade cannot quietly make every login cheaper to attack. These are around
# the OWASP second recommended configuration - 64 MiB, three passes - which
# costs a few hundred milliseconds on this class of hardware. That is
# unnoticeable on a login form and expensive in bulk, which is the whole point.
#
_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)

#
# A real Argon2id hash of a value nobody has. Verified against when the username
# does not exist, purely so that path burns the same time as a real check.
#
_ABSENT_USER_HASH = _HASHER.hash(secrets.token_urlsafe(32))

#
# Long enough that no realistic password reaches it, short enough that a
# multi-megabyte body cannot be turned into a denial of service by way of a
# memory-hard hash function. Argon2 does not care about input length; the
# machine does.
#
MAX_PASSWORD_BYTES = 1024

#
# The NIST SP 800-63B floor, and no composition rules for the reason that
# document gives: rules mostly produce one predictable substitution per class
# and a password nobody can remember, while length is what actually costs an
# attacker something against a memory-hard hash.
#
# Eight is a floor rather than a recommendation. Online guessing is already
# bounded by the throttle; this number is what stands between a stolen database
# dump and the accounts in it, together with Argon2id.
#
MINIMUM_PASSWORD_LENGTH = 8


class PasswordTooLong(ValueError):
    """The submitted password is longer than anything a person types."""


def hash_password(password: str) -> str:
    """Argon2id, in the format the CHECK constraint on the column requires."""

    _refuse_oversized(password)
    return _HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Whether the password matches, without saying which way it failed.

    A malformed hash returns False rather than raising. A row whose hash the
    library cannot parse is a broken account, and the honest answer to "can this
    person log in" is no - not a stack trace on the login path.

    Rehashing on login is deliberately absent. The web role can write
    `password_hash` (migration 0039, for an administrator setting a password and
    for a person changing their own), but the sign-in path writes nothing about
    the account: a login that rewrote the hash would turn every sign-in into an
    account change. New parameters reach a hash the next time its password is
    set.
    """

    try:
        _refuse_oversized(password)
        return _HASHER.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError, PasswordTooLong):
        return False


#
# What a sign-in may cost the machine (B305, security review S01). Argon2 takes
# 64 MiB and three passes per check; this many run at once, and a sign-in that
# waits longer than the wait for one is told to try again rather than queued.
# The account budget is the per-source limit times this, across every address:
# enough to stop many sources guessing at one account, not so little that one
# person's typos from two machines lock it.
#
HASHING_AT_ONCE = 2
HASHING_WAIT_SECONDS = 5
HASHING = threading.BoundedSemaphore(HASHING_AT_ONCE)
ACCOUNT_FAILURE_FACTOR = 10


def burn_absent_user_time(password: str) -> None:
    """Spend the same time on a username that does not exist.

    Called instead of `verify_password` when there is no account. Without it the
    two answers differ by the cost of an Argon2 verification, which is hundreds
    of milliseconds - a difference a script can measure reliably, turning the
    login form into a list of who has an account here.

    The oversize check has to come first, and be the same check, because
    `verify_password` refuses before it hashes. Truncating and hashing here
    instead reopened the very oracle in the other direction: an over-long
    password answered instantly for an account that exists and slowly for one
    that does not. Measured on 2026-08-31 as 0.0 ms against 62.6 ms, using 700
    characters that are 1400 bytes - long enough in bytes to pass the limit,
    short enough in characters to pass the form's own length check.

    Refusing rather than hashing is also the only answer that keeps what the
    limit is for: nobody should be able to make this machine run a memory-hard
    function over a megabyte.
    """

    try:
        _refuse_oversized(password)
        _HASHER.verify(_ABSENT_USER_HASH, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError, PasswordTooLong):
        return


def _refuse_oversized(password: str) -> None:
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise PasswordTooLong(f"password exceeds {MAX_PASSWORD_BYTES} bytes")


def new_session_token() -> str:
    """A fresh opaque token. 256 bits from the system CSPRNG, and no structure.

    Carrying no structure is a feature: there is nothing in it to parse, forge
    or tamper with, so the only way to have a valid token is to have been given
    one.
    """

    return secrets.token_urlsafe(TOKEN_BYTES)


def token_hash(token: str) -> bytes:
    """What the database stores. SHA-256, matching the 32-byte CHECK on the column.

    A fast hash rather than a password hash, and correctly so: the input is 256
    bits of randomness, not something guessable, so there is nothing for a slow
    hash to protect against - and this runs on every authenticated request.
    """

    return hashlib.sha256(token.encode("utf-8")).digest()


def csrf_token(session_token: str) -> str:
    """The CSRF token for a session, derived rather than stored.

    Keyed on the session token itself, so producing it requires the cookie. A
    cross-site form post can make a browser send the cookie but cannot read it,
    which is what stops the attacker from supplying a matching field.
    """

    return hmac.new(session_token.encode("utf-8"), b"csrf", hashlib.sha256).hexdigest()


def csrf_token_is_valid(session_token: str, submitted: str | None) -> bool:
    """Compared in constant time, because the comparison is a secret comparison.

    As bytes: `compare_digest` refuses a str with a character outside ASCII by
    raising, so `å` in the field was a 500 instead of a refusal (review
    2026-10-04, CR-05). `surrogatepass` encodes whatever the form decoded to.
    """

    #
    # An empty secret is no secret: the HMAC of "" is anyone's to compute, and
    # a login posted with no pre-session cookie at all was accepted that way
    # (security review 26-10-13, S09).
    #
    if not submitted or not session_token:
        return False
    return hmac.compare_digest(
        csrf_token(session_token).encode("ascii"), submitted.encode("utf-8", "surrogatepass")
    )


@dataclass(frozen=True, slots=True)
class SessionVerdict:
    """Whether a session may be used, and if not, why.

    The reason is kept because it is what an audit line and a log line need. It
    is never shown to the person logging in: "your session expired" and "your
    account was disabled" are different facts, and only one of them is theirs.
    """

    usable: bool
    reason: str | None = None


def evaluate_session(
    session: AuthenticatedSession | None, policy: SessionPolicy, *, now: datetime | None = None
) -> SessionVerdict:
    """Apply the session policy to a row that was read without policy in it.

    Four ways to fail, checked in the order that costs least to reason about.
    The two clocks are separate on purpose: `expires_at` is the absolute limit
    the session was issued with and the web role cannot extend it, while
    `last_seen_at` carries the inactivity timeout and is the only thing use
    moves forward.
    """

    if session is None:
        return SessionVerdict(False, "no_session")
    moment = now or datetime.now(UTC)
    if session.revoked_at is not None:
        return SessionVerdict(False, "revoked")
    if session.disabled:
        return SessionVerdict(False, "account_disabled")
    if moment >= session.expires_at:
        return SessionVerdict(False, "expired")
    if moment - session.last_seen_at >= timedelta(minutes=policy.inactivity_minutes):
        return SessionVerdict(False, "inactive")
    return SessionVerdict(True)


def absolute_expiry(
    policy: SessionPolicy, *, now: datetime | None = None, through_provider: bool = False
) -> datetime:
    """When a session issued now must end, whatever happens in between.

    A sign-in through the provider ends at the shorter of the two limits: its
    role came from groups the provider is not asked about again (B203).
    """

    hours = policy.absolute_hours
    if through_provider:
        hours = min(hours, policy.oidc_absolute_hours)
    return (now or datetime.now(UTC)) + timedelta(hours=hours)
