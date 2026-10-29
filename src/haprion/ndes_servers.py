"""The NDES servers a manager enrolls with, each confirmed from its CA (B383, B385).

An administrator gives an NDES server's address. The manager asks the server
for its CA with SCEP's `GetCACert`, over HTTPS checked against the system's
store (B381: the store a manager has already trusts an internal CA it was
given), and shows each CA certificate with its fingerprints. Only when the
administrator confirms them - by their SHA-256s, asked again from the server,
which must still give exactly those certificates (review 2026-10-28, U02: what
is confirmed is what is saved) - is the server written into the runtime
policy's `ndes.servers`, with the CA certificates in a file of their own.

The policy is otherwise left as it is: only the `ndes:` block is replaced, so
the rest of the file and its comments stay, and the result is read back with
the engine's own parser before it replaces the file. A block in the form
before B385 - one `endpoint` beside the rest - becomes the first server.

Every change to the block reads the policy again under one lock, held by the
command, the web's helper and the profile apply helper alike (review
2026-10-28, F05): an atomic replace keeps a file whole, not a change two
writers made from the same reading. The question to the server stays outside
the lock; only the local reading and writing is inside it.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from base64 import b64decode
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from haprion import atomic_file, cert_lock, exit_codes, safe_yaml
from haprion.cert_import import ImportError_, _names, _openssl, read_bytes
from haprion.certificates import CERTIFICATE_BLOCK
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy
from haprion.dns_profiles import ProfileError
from haprion.ndes_profiles import check_endpoint

CA_DIRECTORY = Path("/etc/haprion/ndes-ca")
CLIENT_ROOT = "/opt/haprion-scep/current"
STATE_ROOT = "/etc/haprion/ndes-requests"
PROFILE_DIRECTORY = "/etc/haprion/ndes-profiles"
#
# Under /run/haprion, which the worker's sandbox and the socket helper's both
# write. Held only for local files: milliseconds, so a short wait.
#
LOCK_PATH = Path("/run/haprion/locks/ndes-policy.lock")
LOCK_WAIT_SECONDS = 30
#
# SCEP's GetCACert answers with the CA and the RA certificates: a few kB.
#
MAX_ANSWER = 256 * 1024
TIMEOUT = 20.0
SHA256 = re.compile(r"[0-9a-f]{64}")
TOP_LEVEL = re.compile(r"^[A-Za-z_][\w-]*:", re.MULTILINE)

type Fetch = Callable[[str], bytes]


class NdesServerError(Exception):
    def __init__(self, code: str, message: str, exit_code: int = exit_codes.REFUSED) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class Authority:
    """One CA certificate the server gave, as the administrator compares it."""

    subject: str
    sha256: str
    #
    # Windows shows a certificate's SHA-1 as its thumbprint; the administrator
    # of the CA reads that one.
    #
    sha1: str
    pem: str
    #
    # Whether it issued the server's RA certificate: the CA the NDES server
    # enrolls for.
    #
    issues_ra: bool

    def summary(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "issues_ra": self.issues_ra,
        }


def get_ca_cert(endpoint: str) -> bytes:
    """`GetCACert` over HTTPS, the server's certificate checked with the system's store."""

    url = endpoint + "?operation=GetCACert&message=ca"
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as response:  # noqa: S310 - checked https
            data: bytes = response.read(MAX_ANSWER + 1)
    except urllib.error.HTTPError as exc:
        # The error is the response too, and is closed (review 2026-10-28, F04).
        with exc:
            raise NdesServerError(
                "unreachable", f"{endpoint} answered HTTP {exc.code}", exit_codes.UNAVAILABLE
            ) from None
    except OSError as exc:
        raise NdesServerError(
            "unreachable", f"{endpoint} did not answer: {exc}", exit_codes.UNAVAILABLE
        ) from None
    if len(data) > MAX_ANSWER:
        raise NdesServerError(
            "bad_answer",
            f"{endpoint} answered with more than a CA could be",
            exit_codes.UNAVAILABLE,
        )
    return data


def _der(pem: str) -> bytes:
    match = CERTIFICATE_BLOCK.search(pem)
    if match is None:
        raise NdesServerError(
            "bad_answer", "the server's answer holds no certificate", exit_codes.UNAVAILABLE
        )
    return b64decode("".join(match.group(1).split()))


def authorities(endpoint: str, *, fetch: Fetch = get_ca_cert) -> tuple[Authority, ...]:
    """The CA certificates the server gives, the one that issued its RA certificate first."""

    try:
        endpoint = check_endpoint(endpoint)
    except ProfileError:
        raise NdesServerError(
            "bad_input", "the address must be an HTTPS URL without credentials or query"
        ) from None
    try:
        certificates, _keys = read_bytes(fetch(endpoint))
    except ImportError_ as exc:
        raise NdesServerError(
            "bad_answer", f"{endpoint} answered with no CA: {exc}", exit_codes.UNAVAILABLE
        ) from None
    found: list[Authority] = []
    issuers = set()
    authority_pems = []
    for certificate in certificates:
        constraints = _openssl(
            ["x509", "-noout", "-ext", "basicConstraints"],
            stdin=certificate,
            what="read a certificate from the NDES server",
        )
        subject, issuer = _names(certificate)
        if "CA:TRUE" in constraints.replace(" ", ""):
            authority_pems.append((subject, certificate))
        else:
            issuers.add(issuer)
    for subject, certificate in authority_pems:
        der = _der(certificate)
        #
        # The SHA-1 is shown, never decided on: the thumbprint Windows and
        # certutil show, read as openssl prints a certificate's fingerprint.
        # What is confirmed is the SHA-256 (review 2026-10-28: CodeQL took a
        # SHA-1 of a certificate in this process for a weak hash of a secret).
        #
        thumbprint = _openssl(
            ["x509", "-noout", "-fingerprint", "-sha1"],
            stdin=certificate,
            what="read a certificate's thumbprint from the NDES server",
        )
        found.append(
            Authority(
                subject=subject,
                sha256=hashlib.sha256(der).hexdigest(),
                sha1=thumbprint.partition("=")[2].strip().replace(":", "").lower(),
                pem=certificate,
                issues_ra=subject in issuers,
            )
        )
    if not found:
        raise NdesServerError(
            "bad_answer", f"{endpoint} answered with no CA certificate", exit_codes.UNAVAILABLE
        )
    return tuple(sorted(found, key=lambda authority: not authority.issues_ra))


def saved_fingerprints(path: Path) -> frozenset[str]:
    """The SHA-256s of the CA certificates saved for a server; none when the file cannot be read."""

    try:
        text = path.read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return frozenset()
    return frozenset(
        hashlib.sha256(b64decode("".join(match.group(1).split()))).hexdigest()
        for match in CERTIFICATE_BLOCK.finditer(text)
    )


def confirmation(found: Sequence[Authority], saved: Path | None) -> str:
    """`new`, `confirmed` (the saved chain is the one given now) or `changed`.

    Review 2026-10-29, B01: a server in the policy was "confirmed" whatever it
    gave, so a CA renewed with a new key could not be confirmed again.
    """

    if saved is None:
        return "new"
    if saved_fingerprints(saved) == {authority.sha256 for authority in found}:
        return "confirmed"
    return "changed"


@contextmanager
def locked(path: Path | None = None) -> Iterator[None]:
    """Hold the NDES policy lock around a read-modify-write of the `ndes:` block.

    Taken once per process: a second take in the same process waits for the
    first, as `cert_lock` says.
    """

    with cert_lock.hold(
        LOCK_PATH if path is None else path,
        wait=LOCK_WAIT_SECONDS,
        refuse=lambda message: NdesServerError("operation_locked", message, exit_codes.BLOCKED),
    ):
        yield


def ca_file(endpoint: str, directory: Path = CA_DIRECTORY) -> Path:
    return directory / f"{hashlib.sha256(endpoint.encode()).hexdigest()[:16]}.pem"


def _ndes_block(data: dict[str, Any], policy_path: Path) -> dict[str, Any]:
    """The policy's ndes block in the form with servers; a new one with the defaults."""

    raw = data.get("ndes")
    if raw is None:
        acme = data.get("acme")
        if not isinstance(acme, dict):
            acme = {}
        dns = acme.get("dns_profiles") or {}
        return {
            "servers": [],
            "client_root": CLIENT_ROOT,
            "state_root": STATE_ROOT,
            "profiles": {
                "directory": PROFILE_DIRECTORY,
                "private_keys": list(dns.get("private_keys") or []),
            },
        }
    if not isinstance(raw, dict):
        raise NdesServerError(
            "bad_policy", f"{policy_path}: ndes is not a mapping", exit_codes.CONFIG
        )
    block = dict(raw)
    if "endpoint" in block:
        server = {"endpoint": block.pop("endpoint"), "issuing_ca": block.pop("issuing_ca", None)}
        if "tls_ca" in block:
            server["tls_ca"] = block.pop("tls_ca")
        block = {"servers": [server], **block}
    block.setdefault("servers", [])
    return block


def with_ndes(text: str, block: dict[str, Any]) -> str:
    """The policy's text with its ndes block replaced, or added at its end."""

    rendered = yaml.safe_dump({"ndes": block}, sort_keys=False, default_flow_style=False)
    start = re.search(r"^ndes:", text, re.MULTILINE)
    if start is None:
        return text.rstrip("\n") + "\n\n" + rendered
    following = TOP_LEVEL.search(text, start.end())
    end = following.start() if following else len(text)
    return text[: start.start()] + rendered + ("\n" if following else "") + text[end:]


def without_ndes(text: str) -> str:
    start = re.search(r"^ndes:", text, re.MULTILINE)
    if start is None:
        return text
    following = TOP_LEVEL.search(text, start.end())
    return (
        text[: start.start()].rstrip("\n")
        + "\n"
        + ("\n" + text[following.start() :] if following else "")
    )


def _write_policy(policy_path: Path, text: str) -> None:
    """Read back with the engine's parser, then put in place as the file it replaces is."""

    staged = policy_path.with_name(f".{policy_path.name}.ndes")
    try:
        atomic_file.write_like(staged, text.encode(), like=policy_path)
        try:
            load_policy(staged, require_secure=False)
        except ConfigError as exc:
            raise NdesServerError(
                "bad_policy", f"the changed policy would not load: {exc}", exit_codes.CONFIG
            ) from None
        atomic_file.move(staged, policy_path)
    finally:
        staged.unlink(missing_ok=True)


def add(
    endpoint: str,
    fingerprints: Sequence[str],
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    ca_directory: Path | None = None,
    fetch: Fetch = get_ca_cert,
) -> dict[str, Any]:
    """Confirm the server whose CA certificates have these SHA-256s, and write it into the policy.

    Every certificate the server gives is saved, so every one is confirmed: a
    server that now gives one more, one fewer or another is refused.
    """

    ca_directory = CA_DIRECTORY if ca_directory is None else ca_directory
    if not fingerprints or any(SHA256.fullmatch(each) is None for each in fingerprints):
        raise NdesServerError("bad_input", "each fingerprint must be a SHA-256 in hexadecimal")
    found = authorities(endpoint, fetch=fetch)
    endpoint = check_endpoint(endpoint)
    if {authority.sha256 for authority in found} != set(fingerprints):
        raise NdesServerError(
            "changed",
            f"{endpoint} no longer gives the CA certificates confirmed; fetch them again and compare",
        )
    path = ca_file(endpoint, ca_directory)
    with locked():
        ca_directory.mkdir(mode=0o755, exist_ok=True)
        atomic_file.write(path, "".join(a.pem for a in found).encode(), mode=0o644)
        text = policy_path.read_text()
        data = safe_yaml.load(text) or {}
        block = _ndes_block(data, policy_path)
        servers = [s for s in block["servers"] if s.get("endpoint") != endpoint]
        block["servers"] = [*servers, {"endpoint": endpoint, "issuing_ca": str(path)}]
        _write_policy(policy_path, with_ndes(text, block))
    return {
        "endpoint": endpoint,
        "issuing_ca": str(path),
        "sha256": [authority.sha256 for authority in found],
    }


def remove(
    endpoint: str,
    *,
    used_by: Callable[[], Sequence[str]],
    policy_path: Path = DEFAULT_POLICY_PATH,
) -> dict[str, Any]:
    """Take the server out of the policy, unless a profile still uses it.

    `used_by` is asked under the lock, so a profile applied a moment before is
    seen: the profile apply helper checks its server under the same lock.
    """

    with locked():
        return _remove(endpoint, used_by=used_by(), policy_path=policy_path)


def _remove(endpoint: str, *, used_by: Sequence[str], policy_path: Path) -> dict[str, Any]:
    if used_by:
        raise NdesServerError(
            "in_use", f"{endpoint} is used by the NDES profile {', '.join(sorted(used_by))}"
        )
    text = policy_path.read_text()
    data = safe_yaml.load(text) or {}
    if data.get("ndes") is None:
        raise NdesServerError(
            "not_found", f"{endpoint} is not an NDES server here", exit_codes.NOT_FOUND
        )
    block = _ndes_block(data, policy_path)
    servers = [s for s in block["servers"] if s.get("endpoint") != endpoint]
    if len(servers) == len(block["servers"]):
        raise NdesServerError(
            "not_found", f"{endpoint} is not an NDES server here", exit_codes.NOT_FOUND
        )
    #
    # The last server takes the block with it: what else it holds are the
    # defaults a new one is made with.
    #
    if servers:
        block["servers"] = servers
        _write_policy(policy_path, with_ndes(text, block))
    else:
        _write_policy(policy_path, without_ndes(text))
    return {"endpoint": endpoint}


def profiles_using(directory: Path, endpoint: str) -> tuple[str, ...]:
    """The materialized profiles whose address is this server's."""

    found = []
    for record in sorted(directory.glob("*.json")) if directory.is_dir() else ():
        try:
            row = json.loads(record.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(row, dict) and row.get("endpoint") == endpoint:
            found.append(str(row.get("profile_id") or record.stem))
    return tuple(found)
