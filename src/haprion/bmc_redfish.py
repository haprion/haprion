"""Installing an exportable certificate on a Supermicro BMC over Redfish (B526, B536).

The BMC takes a certificate and its key through Supermicro's own action
(`SmcSSLCert.Upload`, X12/X13/H13): a multipart form with the server
certificate alone - one certificate; a chain is refused - and the key. It
serves the new pair only after a restart of the BMC (`Manager.Reset` with
`GracefulRestart`; an empty body is silently ignored by some firmware). Those
are the facts this module is built on, read from a tool that does the same
(LukeEvansTech/supermicro-ipmi-cert) and measured on our own BMC where we
could; no code is taken from it.

What decides that an install happened
-------------------------------------
The socket. After the restart the BMC is asked for its certificate until it
serves the one installed, or the wait runs out. What the upload's answer says
is kept for the record and decides nothing: a firmware that answers 200 and
keeps the old pair is a failed install, and is said as one.

Trust
-----
The BMC serves a certificate nobody else vouches for until the first install,
so every connection is pinned: before a byte is sent, the certificate the BMC
presented is held against the fingerprints the caller trusts - the one an
administrator confirmed, and the one the manager installed. A BMC that serves
anything else is not sent the account. `served` alone connects without a
pin: it sends nothing, and reports what is there to be confirmed.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import json
import secrets
import socket
import ssl
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Any

from haprion.certificates import CERTIFICATE_BLOCK, CertificateError

SESSIONS = "/redfish/v1/SessionService/Sessions"
MANAGERS = "/redfish/v1/Managers"
UPLOAD = "/redfish/v1/UpdateService/Oem/Supermicro/SSLCert/Actions/SmcSSLCert.Upload"
#
# A BMC that is switched off or behind a firewall answers nothing; a reading
# of it should cost seconds, not the minutes a TCP connect may wait (B536:
# a BMC that does not answer is no fault, and is asked again later).
#
CONNECT_TIMEOUT = 5.0
REQUEST_TIMEOUT = 30.0
#
# *Check* and *Save* run in the web's helper, whose unit lives 90 s: the
# handshake and four calls (sign-in, manager, firmware, the upload question)
# fit inside it at this bound, so a slow BMC is said, not cut off.
#
CHECK_TIMEOUT = 15.0
#
# The upload has been seen to take well over 30 s on X12/H12 firmware.
#
UPLOAD_TIMEOUT = 180.0
#
# A restart is about two minutes; asked every ten seconds for five.
#
RESTART_WAIT = 300.0
RESTART_INTERVAL = 10.0
MAX_ANSWER_BYTES = 1024 * 1024


class BmcError(Exception):
    """A step that did not happen, with the code it is reported under.

    `unreachable` - nothing answered (switched off, a firewall): never a fault
    on its own. `tls_failed` - it answered, and no TLS 1.2 or later was agreed.
    `interrupted` - the upload was cut off after it began. `untrusted` - the BMC served a certificate nobody confirmed,
    and was sent nothing. `login_refused` - the account was not let in.
    `refused` - the BMC answered a step with an error. `not_served` - it was
    restarted and does not serve the installed certificate. `bad_answer` - an
    answer that is not what a Redfish BMC answers.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class Served:
    """The certificate a BMC presents, read from the TLS handshake."""

    fingerprint_sha256: str
    pem: str


@dataclass(frozen=True, slots=True)
class Firmware:
    model: str
    version: str


@dataclass(frozen=True, slots=True)
class Installed:
    fingerprint_sha256: str
    firmware: Firmware
    upload_said: str
    seconds: float


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def leaf_only(fullchain: str) -> str:
    """The first certificate of a chain, the one the BMC is to serve."""

    match = CERTIFICATE_BLOCK.search(fullchain)
    if match is None:
        raise CertificateError("the file contains no certificate")
    return match.group(0).strip() + "\n"


def pem_fingerprint(pem: str) -> str:
    return fingerprint(ssl.PEM_cert_to_DER_cert(leaf_only(pem)))


def _context() -> ssl.SSLContext:
    #
    # No verification by the store: a BMC's certificate is checked against the
    # pin instead (see the module's note), which is stricter than any CA.
    #
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def served(address: str, port: int = 443, *, timeout: float = CONNECT_TIMEOUT) -> Served:
    """What the BMC presents now. Sends nothing; `unreachable` when nothing answers."""

    try:
        raw = socket.create_connection((address, port), timeout=timeout)
    except OSError as exc:
        raise BmcError("unreachable", f"{address}:{port} did not answer: {_said(exc)}") from exc
    try:
        with raw, _context().wrap_socket(raw, server_hostname=address) as secure:
            der = secure.getpeercert(binary_form=True)
    except (ssl.SSLEOFError, ssl.SSLZeroReturnError) as exc:
        #
        # Closed in the handshake: a BMC going down or coming up. Transient.
        #
        raise BmcError("unreachable", f"{address}:{port} closed the connection") from exc
    except ssl.SSLError as exc:
        #
        # It answered, and no TLS this client speaks (1.2 or later) was agreed:
        # a fault to be said, not a BMC that is off.
        #
        raise BmcError(
            "tls_failed", f"{address}:{port} answered, but TLS failed: {_said(exc)}"
        ) from exc
    except OSError as exc:
        raise BmcError("unreachable", f"{address}:{port} did not answer: {_said(exc)}") from exc
    if not der:
        raise BmcError("bad_answer", f"{address}:{port} presented no certificate")
    return Served(fingerprint(der), ssl.DER_cert_to_PEM_cert(der))


def _said(exc: BaseException) -> str:
    if isinstance(exc, TimeoutError | socket.timeout):
        return "timed out"
    return str(exc) or type(exc).__name__


class _Pinned(http.client.HTTPSConnection):
    """An HTTPS connection that closes before sending when the BMC is not the trusted one."""

    def __init__(self, address: str, port: int, *, trusted: Collection[str], timeout: float):
        super().__init__(address, port, timeout=timeout, context=_context())
        self._trusted = frozenset(trusted)

    def connect(self) -> None:
        super().connect()
        der = self.sock.getpeercert(binary_form=True) if self.sock is not None else None
        if not der or fingerprint(der) not in self._trusted:
            presented = fingerprint(der) if der else "nothing"
            self.close()
            raise BmcError(
                "untrusted",
                f"{self.host} serves a certificate that was not confirmed ({presented}); "
                "it was sent nothing",
            )


class Session:
    """One Redfish session with a BMC, logged out when it ends.

    A session rather than Basic authentication on every call: that is what the
    BMC's own tools use, and the session is ended here, so a BMC with a small
    session limit is not left full of ours.
    """

    def __init__(
        self,
        address: str,
        port: int,
        *,
        trusted: Collection[str],
        username: str,
        password: str,
        timeout: float = REQUEST_TIMEOUT,
    ) -> None:
        self.address = address
        self.port = port
        self.trusted = frozenset(trusted)
        self._timeout = timeout
        self._username = username
        self._password = password
        self._token: str | None = None
        self._location: str | None = None

    def __enter__(self) -> Session:
        status, headers, body = self._call(
            "POST",
            SESSIONS,
            json.dumps({"UserName": self._username, "Password": self._password}).encode(),
            {"Content-Type": "application/json"},
            authenticated=False,
        )
        if status in (401, 403):
            raise BmcError("login_refused", f"{self.address} refused the account {self._username}")
        token = headers.get("x-auth-token")
        if not 200 <= status < 300 or not token:
            raise BmcError(
                "bad_answer",
                f"{self.address} did not open a session (HTTP {status}): {_text(body)}",
            )
        self._token = token
        self._location = headers.get("location")
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._token is None:
            return
        path = _path(self._location) if self._location else None
        if path is not None:
            #
            # Best effort: a BMC already restarting cannot be asked, and its
            # sessions end with the restart.
            #
            with contextlib.suppress(BmcError):
                self._call("DELETE", path, None, {}, timeout=CONNECT_TIMEOUT)
        self._token = None

    def _call(
        self,
        method: str,
        path: str,
        body: bytes | None,
        headers: dict[str, str],
        *,
        authenticated: bool = True,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        timeout = self._timeout if timeout is None else timeout
        sent = dict(headers)
        if authenticated:
            if self._token is None:
                raise BmcError("bad_answer", "no session")
            sent["X-Auth-Token"] = self._token
        connection = _Pinned(self.address, self.port, trusted=self.trusted, timeout=timeout)
        try:
            connection.request(method, path, body=body, headers=sent)
            response = connection.getresponse()
            answer = response.read(MAX_ANSWER_BYTES + 1)
            if len(answer) > MAX_ANSWER_BYTES:
                raise BmcError("bad_answer", f"{self.address} answered {path} with too much")
            return (
                response.status,
                {name.lower(): value for name, value in response.getheaders()},
                answer,
            )
        except BmcError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise BmcError(
                "unreachable", f"{self.address}: {method} {path} failed: {_said(exc)}"
            ) from exc
        finally:
            connection.close()

    def _json(self, path: str) -> dict[str, Any]:
        status, _headers, body = self._call("GET", path, None, {"Accept": "application/json"})
        if status in (401, 403):
            raise BmcError("login_refused", f"{self.address} refused {path} to the account")
        if status != 200:
            raise BmcError("bad_answer", f"{self.address} answered {path} with HTTP {status}")
        try:
            document = json.loads(body)
        except ValueError as exc:
            raise BmcError("bad_answer", f"{self.address} answered {path} with no JSON") from exc
        if not isinstance(document, dict):
            raise BmcError("bad_answer", f"{self.address} answered {path} with no object")
        return document

    def manager(self) -> str:
        """The BMC's own manager resource: the first member of the collection."""

        members = self._json(MANAGERS).get("Members")
        if isinstance(members, list) and members and isinstance(members[0], dict):
            path = _path(members[0].get("@odata.id"))
            if path is not None:
                return path
        raise BmcError("bad_answer", f"{self.address} lists no manager")

    def firmware(self, manager: str) -> Firmware:
        document = self._json(manager)
        return Firmware(
            model=str(document.get("Model") or ""),
            version=str(document.get("FirmwareVersion") or ""),
        )

    def may_upload(self) -> bool | None:
        """Whether the account may upload a certificate, asked with an upload that holds no file.

        Measured on X13 firmware 01.09.06 (26-11-26): an account with
        `ConfigureManager` is answered 400 `SMC.1.0.OemSslcertMissingItem`, one
        without it 403 `Base.1.10.InsufficientPrivilege`, and nothing changes.
        None when the BMC answers anything else: then it cannot be told here.
        """

        boundary = secrets.token_hex(16)
        status, _headers, answer = self._call(
            "POST",
            UPLOAD,
            f"--{boundary}--\r\n".encode(),
            {"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        if status in (401, 403):
            return False
        if status == 400 and b"OemSslcertMissingItem" in answer:
            return True
        return None

    def upload(self, leaf_pem: str, key_pem: str) -> str:
        """Hand the BMC the certificate and key; what it said, when it took them."""

        boundary = secrets.token_hex(16)
        parts = []
        for field, filename, content in (
            ("cert_file", "cert.pem", leaf_pem),
            ("key_file", "key.pem", key_pem),
        ):
            parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n".encode()
                + content.encode("ascii")
                + b"\r\n"
            )
        body = b"".join(parts) + f"--{boundary}--\r\n".encode()
        status, _headers, answer = self._call(
            "POST",
            UPLOAD,
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary}"},
            timeout=UPLOAD_TIMEOUT,
        )
        said = _text(answer)
        if status in (401, 403):
            raise BmcError(
                "login_refused", f"{self.address} did not let the account upload a certificate"
            )
        if not 200 <= status < 300:
            raise BmcError("refused", f"{self.address} refused the certificate: {said}")
        return said

    def restart(self, manager: str) -> None:
        try:
            status, _headers, answer = self._call(
                "POST",
                f"{manager}/Actions/Manager.Reset",
                json.dumps({"ResetType": "GracefulRestart"}).encode(),
                {"Content-Type": "application/json"},
            )
        except BmcError as exc:
            if exc.code != "unreachable":
                raise
            #
            # Cut off as it went down: the restart has begun. What it serves
            # when it is back decides, as after any restart.
            #
            self._token = None
            return
        if status in (401, 403):
            raise BmcError("login_refused", f"{self.address} did not let the account restart it")
        if not 200 <= status < 300:
            raise BmcError("refused", f"{self.address} refused the restart: {_text(answer)}")
        #
        # The restart ends every session, and the BMC that comes back serves the
        # new certificate, which this session is not pinned to: nothing to log
        # out of.
        #
        self._token = None


def _path(value: object) -> str | None:
    """A Redfish resource path the BMC named, held to its own tree."""

    if not isinstance(value, str):
        return None
    if "://" in value:
        value = "/" + value.split("://", 1)[1].split("/", 1)[-1]
    if not value.startswith("/redfish/v1/") or ".." in value or any(c.isspace() for c in value):
        return None
    return value


def _text(body: bytes) -> str:
    """A BMC's answer, as one line short enough for a record."""

    try:
        document = json.loads(body)
    except ValueError:
        document = None
    if isinstance(document, dict) and isinstance(document.get("error"), dict):
        error = document["error"]
        extended = error.get("@Message.ExtendedInfo")
        if isinstance(extended, list) and extended and isinstance(extended[0], dict):
            message = extended[0].get("Message")
            if isinstance(message, str):
                return message[:300]
        if isinstance(error.get("message"), str):
            return str(error["message"])[:300]
    text = body.decode("utf-8", "replace")
    return " ".join(text.split())[:300] or "(nothing)"


def install(
    address: str,
    port: int,
    *,
    trusted: Collection[str],
    username: str,
    password: str,
    fullchain: str,
    key_pem: str,
    wait: float = RESTART_WAIT,
    interval: float = RESTART_INTERVAL,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Installed:
    """Upload, restart, and wait until the BMC serves the certificate."""

    leaf = leaf_only(fullchain)
    expected = pem_fingerprint(leaf)
    started = clock()
    with Session(address, port, trusted=trusted, username=username, password=password) as session:
        manager = session.manager()
        firmware = session.firmware(manager)
        try:
            said = session.upload(leaf, key_pem)
        except BmcError as exc:
            if exc.code != "unreachable":
                raise
            #
            # The certificate and key were on their way: whatever the BMC did
            # with them, this is an install that failed, not a BMC that was off.
            #
            raise BmcError("interrupted", f"the upload was cut off: {exc}") from exc
        session.restart(manager)
    deadline = clock() + wait
    last = "nothing"
    while True:
        try:
            now = served(address, port)
            if now.fingerprint_sha256 == expected:
                return Installed(expected, firmware, said, clock() - started)
            last = now.fingerprint_sha256
        except BmcError as exc:
            #
            # Coming up: closed, refused or not yet speaking TLS, all part of a
            # restart until the wait runs out.
            #
            if exc.code not in {"unreachable", "tls_failed"}:
                raise
            last = "nothing (restarting)"
        if clock() >= deadline:
            raise BmcError(
                "not_served",
                f"{address} was restarted and still serves {last}, not the installed "
                f"certificate ({expected})",
            )
        sleep(interval)


@dataclass(frozen=True, slots=True)
class Checked:
    served: Served
    firmware: Firmware
    may_upload: bool | None = None


def check(address: str, port: int, *, username: str, password: str) -> Checked:
    """What the BMC serves, that the account is let in, and whether it may upload.

    For the administrator to confirm.
    The session is pinned to what the BMC served a moment before, so the
    account goes to the certificate that is then shown, and to no other.
    """

    now = served(address, port)
    with Session(
        address,
        port,
        trusted={now.fingerprint_sha256},
        username=username,
        password=password,
        timeout=CHECK_TIMEOUT,
    ) as session:
        firmware = session.firmware(session.manager())
        may_upload = session.may_upload()
    return Checked(now, firmware, may_upload)


__all__ = [
    "CHECK_TIMEOUT",
    "CONNECT_TIMEOUT",
    "RESTART_INTERVAL",
    "RESTART_WAIT",
    "UPLOAD",
    "UPLOAD_TIMEOUT",
    "BmcError",
    "Checked",
    "Firmware",
    "Installed",
    "Served",
    "Session",
    "check",
    "fingerprint",
    "install",
    "leaf_only",
    "pem_fingerprint",
    "served",
]
