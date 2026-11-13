"""Whether Let's Encrypt's HTTP-01 challenge would reach this manager for a name (B496 nr 3, B499).

HTTP-01 fails at the CA, after a minute of certbot, when the path the CA takes
does not end in the webroot: the name points somewhere else, or the cluster
has no rule that sends `/.well-known/acme-challenge/` to the manager. The
check walks the same path from the manager before anything is asked of the
CA: a file with a random name and random content is written in the webroot,
fetched over `http://<name>/.well-known/acme-challenge/<file>`, and removed
again whatever the fetch gave - in one process, so no answer and no failure
leaves it behind.

Four answers, each about the path and none about the CA:

    reached     the file came back: the path ends in this webroot
    other       something answered, but not with the file - another service,
                or a cluster without the rule
    silent      the name resolves, and nothing answered on it
    unresolved  the name does not resolve from this manager

All from the manager, not from the internet: a manager that reaches the
cluster's VIP on an inside address proves the rule and the webroot, not the
firewall in front of the cluster. Every answer that fetched says so.

Redirects are followed the way the CA follows them - at most ten, to http or
https on ports 80 and 443, an https certificate not checked - since a cluster
that sends port 80 on to https before the ACME rule still passes the CA's
challenge.
"""

from __future__ import annotations

import contextlib
import errno
import http.client
import ipaddress
import os
import secrets
import signal
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urljoin, urlsplit

from haprion import exit_codes
from haprion.config import CERTIFICATE_ID, HOSTNAME

type Answer = Literal["reached", "other", "silent", "unresolved"]
ANSWERS: tuple[Answer, ...] = ("reached", "other", "silent", "unresolved")

CHALLENGE_PATH = ".well-known/acme-challenge"
#
# The CA's own bound on redirects, and on where one may lead.
#
MAX_REDIRECTS = 10
PORTS = {"http": 80, "https": 443}
#
# Per connection and in all. The whole check stays well inside the helper
# unit's RuntimeMaxSec and the web's wait for it (`http01_check_socket`).
#
CONNECT_SECONDS = 10.0
TOTAL_SECONDS = 25.0
#
# The answer is compared with the file's content and nothing else is read: a
# service that answers with a page is "other" after its first bytes.
#
MAX_BODY_BYTES = 4096
USER_AGENT = "haprion-http01-check"


class CheckError(Exception):
    """The check could not be made at all; the answer says nothing about the name."""

    def __init__(self, code: str, message: str, *, exit_code: int = exit_codes.REFUSED) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class Reply:
    """One HTTP answer: its status, the first bytes of its body, where it redirects, who sent it."""

    status: int
    body: bytes
    location: str | None
    address: str | None


type Fetch = Callable[[str, float], Reply]
type Resolve = Callable[[str], list[str]]


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    answer: Answer
    address: str | None
    """The address the name gave, or that answered; None when it did not resolve."""
    status: int | None
    """The HTTP status the other service answered with (`other` only)."""
    problem: str | None
    """Why nothing answered (`silent`), or where a redirect led nowhere (`other`)."""

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "answer": self.answer,
            "address": self.address,
            "status": self.status,
            "problem": self.problem,
        }

    def sentence(self) -> str:
        """The answer in plain words, the way the terminal says it."""

        where = "Checked from this manager, not from the internet."
        if self.answer == "reached":
            return (
                f"Reached: a test file in the webroot came back over http://{self.name}/. {where}"
            )
        if self.answer == "other" and self.problem is not None:
            return f"Another service answers: {self.name} is {self.address}, which {self.problem}. {where}"
        if self.answer == "other":
            said = (
                "200 without the test file"
                if self.status == 200
                else f"{self.status} for the test file"
            )
            return f"Another service answers: {self.name} is {self.address}, which answered {said}. {where}"
        if self.answer == "silent":
            return f"Nothing answers: {self.name} is {self.address}, and {self.problem}. {where}"
        return f"{self.name} does not resolve from this manager."


def parse_name(text: str) -> str:
    """The one name HTTP-01 can prove, or CheckError with the reason."""

    name = text.strip().lower()
    if not name:
        raise CheckError("bad_input", "write the name the certificate is for, then check it")
    if name.startswith("*."):
        raise CheckError("bad_input", "HTTP-01 does not prove a wildcard; a wildcard needs DNS-01")
    if (
        not HOSTNAME.fullmatch(name)
        or not CERTIFICATE_ID.fullmatch(name)
        or "." not in name
        or _is_address(name)
    ):
        raise CheckError("bad_input", f"not a domain name: {text!r}")
    return name


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def resolve(name: str) -> list[str]:
    """The addresses the manager's resolver gives the name, in the order it gives them."""

    try:
        found = socket.getaddrinfo(name, 80, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return []
    return list(dict.fromkeys(str(entry[4][0]) for entry in found))


def fetch(url: str, timeout: float) -> Reply:
    """One GET, no redirect followed: the status, the first bytes and where it points next."""

    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or PORTS[parts.scheme]
    connection: http.client.HTTPConnection
    if parts.scheme == "https":
        #
        # The CA does not check the certificate of an https address it was
        # redirected to, so neither does this.
        #
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    else:
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(
            "GET",
            parts.path + (f"?{parts.query}" if parts.query else ""),
            headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"},
        )
        peer = connection.sock.getpeername()[0] if connection.sock is not None else None
        response = connection.getresponse()
        body = response.read(MAX_BODY_BYTES)
        return Reply(
            response.status, body, response.getheader("Location"), str(peer) if peer else None
        )
    finally:
        connection.close()


def _reason(error: OSError | http.client.HTTPException, port: int) -> str:
    """What the connection said, in the words the answer uses."""

    if isinstance(error, http.client.HTTPException):
        return f"port {port} did not answer with HTTP ({type(error).__name__})"
    if isinstance(error, TimeoutError | socket.timeout):
        return f"port {port} did not answer in time"
    if isinstance(error, ConnectionRefusedError) or error.errno == errno.ECONNREFUSED:
        return f"port {port} refused the connection"
    if isinstance(error, ssl.SSLError):
        return f"https on port {port} failed ({error.reason or error})"
    reason = error.strerror or str(error) or type(error).__name__
    return f"port {port} could not be reached ({reason})"


class _Placed:
    """The test file in the webroot, made and removed through directory descriptors.

    Nothing is followed through a link: each directory is opened with
    O_NOFOLLOW from the one before it and the file is created new in the last,
    so a link planted in the webroot - before the check or during it - does
    not make root write or remove anywhere else.
    """

    def __init__(self, webroot: Path, token: str, content: bytes) -> None:
        self.token = token
        self.opened: list[int] = []
        self.made: list[str] = []
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            self.opened.append(os.open(webroot, flags))
        except OSError as error:
            raise CheckError(
                "dependency_unavailable",
                f"the webroot {webroot} is not a directory on this manager",
                exit_code=exit_codes.CONFIG,
            ) from error
        try:
            for part in CHALLENGE_PATH.split("/"):
                parent = self.opened[-1]
                try:
                    os.mkdir(part, 0o755, dir_fd=parent)
                except FileExistsError:
                    made = False
                else:
                    made = True
                try:
                    self.opened.append(os.open(part, flags, dir_fd=parent))
                except OSError as error:
                    raise CheckError(
                        "dependency_unavailable",
                        f"{webroot}/{CHALLENGE_PATH} is not a directory",
                        exit_code=exit_codes.CONFIG,
                    ) from error
                if made:
                    os.fchmod(self.opened[-1], 0o755)
                    self.made.append(part)
            descriptor = os.open(
                token,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o644,
                dir_fd=self.opened[-1],
            )
            try:
                os.fchmod(descriptor, 0o644)
                os.write(descriptor, content)
            finally:
                os.close(descriptor)
        except BaseException:
            self.remove()
            raise

    def remove(self) -> None:
        """The file gone, then the directories this check made, then every descriptor closed."""

        try:
            if len(self.opened) == len(CHALLENGE_PATH.split("/")) + 1:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(self.token, dir_fd=self.opened[-1])
            #
            # Only the directories made here, innermost first, and only while
            # each one is empty: certbot may be using its own beside the file.
            #
            for depth in range(len(self.opened) - 1, 0, -1):
                part = CHALLENGE_PATH.split("/")[depth - 1]
                if part not in self.made:
                    break
                try:
                    os.rmdir(part, dir_fd=self.opened[depth - 1])
                except OSError:
                    break
        finally:
            for descriptor in reversed(self.opened):
                os.close(descriptor)
            self.opened.clear()


@contextmanager
def _stopped_as_an_exception() -> Iterator[None]:
    """SIGTERM raised as SystemExit while the test file is in the webroot.

    systemd ends the helper with SIGTERM at its unit's RuntimeMaxSec - a server
    that drips its answer holds a fetch past the check's own deadline - and
    Python's default for it ends the process without a `finally`. Raised
    instead, the file is removed before the process goes. Only in the main
    thread, the one signals reach; a caller in another has no unit to end it.
    """

    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def stop(signum: int, _frame: object) -> None:
        raise SystemExit(128 + signum)

    before = signal.signal(signal.SIGTERM, stop)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, before)


def check(
    name: str,
    webroot: Path,
    *,
    fetch: Fetch = fetch,
    resolve: Resolve = resolve,
    clock: Callable[[], float] = time.monotonic,
) -> Check:
    """Write a test file in the webroot, fetch it over the name, and remove it again.

    Raises CheckError when the check cannot be made (a name that is not one,
    a webroot that cannot be written); every answer about the name is a Check.
    """

    name = parse_name(name)
    addresses = resolve(name)
    if not addresses:
        return Check(name, "unresolved", None, None, None)

    token = secrets.token_urlsafe(32)
    content = secrets.token_urlsafe(32).encode()
    with _stopped_as_an_exception():
        try:
            placed = _Placed(webroot, token, content)
        except OSError as error:
            raise CheckError(
                "dependency_unavailable",
                f"the test file could not be written in the webroot {webroot}: "
                f"{error.strerror or error}",
                exit_code=exit_codes.CONFIG,
            ) from error
        try:
            return _walk(name, addresses[0], token, content, fetch=fetch, clock=clock)
        finally:
            placed.remove()


def _walk(
    name: str,
    first: str,
    token: str,
    content: bytes,
    *,
    fetch: Fetch,
    clock: Callable[[], float],
) -> Check:
    deadline = clock() + TOTAL_SECONDS
    url = f"http://{name}/{CHALLENGE_PATH}/{token}"
    address = first
    status: int | None = None
    for hop in range(MAX_REDIRECTS + 1):
        target = urlsplit(url)
        port = target.port or PORTS[target.scheme]
        left = deadline - clock()
        try:
            if left <= 0:
                raise TimeoutError
            reply = fetch(url, min(CONNECT_SECONDS, left))
        except (OSError, http.client.HTTPException) as error:
            reason = _reason(error, port)
            if hop == 0:
                return Check(name, "silent", address, None, reason)
            #
            # Something answered, with a redirect the CA would follow too, and
            # where it led nothing did.
            #
            where = (
                f"{target.scheme}://{target.hostname}{'' if target.port is None else f':{port}'}/"
            )
            return Check(name, "other", address, status, f"redirected to {where}, where {reason}")
        if hop == 0 and reply.address is not None:
            address = reply.address
        status = reply.status
        if reply.status == 200 and reply.body.strip() == content:
            return Check(name, "reached", address, None, None)
        if reply.status in (301, 302, 303, 307, 308) and reply.location:
            try:
                following = urljoin(url, reply.location)
                onward = urlsplit(following)
                port_ok = onward.port in (None, *PORTS.values())
            except ValueError:
                #
                # A port that is no number or a bracket never closed: not
                # an address, and no CA follows it either.
                #
                return Check(
                    name,
                    "other",
                    address,
                    reply.status,
                    "redirected to an address that is not one",
                )
            if onward.scheme in PORTS and onward.hostname and port_ok:
                url = following
                continue
        return Check(name, "other", address, reply.status, None)
    return Check(name, "other", address, status, f"redirected more than {MAX_REDIRECTS} times")
