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
import os
import re
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from base64 import b64decode
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from haprion import atomic_file, cert_lock, exit_codes, http_answer, safe_yaml
from haprion.cert_import import ImportError_, _names, _openssl, read_bytes, split_blocks
from haprion.cert_inventory import OPENSSL, OPENSSL_TIMEOUT, describe
from haprion.certificates import CERTIFICATE_BLOCK, CertificateError
from haprion.config import DEFAULT_POLICY_PATH, SYSTEM_TRUST, ConfigError, load_policy
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
#
# The socket's bound on one operation - connecting, the TLS handshake, one
# read - and the whole answer's (review 2026-10-29, B08: a server that sent a
# byte at a time held the helper, and with it the NDES pages, for as long as
# it liked). Together under the helper unit's RuntimeMaxSec, which is under
# the web's wait.
#
TIMEOUT = 10.0
DEADLINE = 20.0
SHA256 = re.compile(r"[0-9a-f]{64}")
#
# How many CA certificates a chain may take from the store: a root, and the
# intermediates between it and what the server gave.
#
MAX_COMPLETION = 4
#
# The next line in the first column that is not the ndes block's: a key or a
# document marker. A comment or a sequence item there can still be the block's.
#
TOP_LEVEL = re.compile(r"^(?!-\s|#)\S", re.MULTILINE)

#
# The server's address, and the store its HTTPS is checked against.
#
type Fetch = Callable[[str, Path], bytes]


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
    #
    # Taken from the manager's certificate store, to complete a chain the
    # server gave without its root (B388).
    #
    from_store: bool = False

    def summary(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "issues_ra": self.issues_ra,
            "from_store": self.from_store,
        }


def _opener(trust: Path) -> urllib.request.OpenerDirector:
    """HTTPS checked with `trust`, straight to the server.

    Review 2026-10-29, B07: `urlopen` followed a redirect to http and took a
    proxy from the environment, so the CA shown could come over neither the
    HTTPS nor the server the administrator named.
    """

    context = ssl.create_default_context(cafile=str(trust))
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        http_answer.NoRedirect(),
    )


def _store(trust: Path) -> str:
    if trust == SYSTEM_TRUST:
        return "this manager's certificate store"
    return f"the server's tls_ca {trust}"


def _tls_said(error: ssl.SSLError) -> str:
    """OpenSSL's own words: why the certificate failed, or the reason it gave."""

    for words in (getattr(error, "verify_message", None), getattr(error, "reason", None)):
        if isinstance(words, str) and words:
            return words
    return http_answer.said(error)


def get_ca_cert(endpoint: str, trust: Path = SYSTEM_TRUST) -> bytes:
    """`GetCACert` over HTTPS, the server's certificate checked with `trust`.

    The store is the one enrollment checks the server with - its `tls_ca`,
    or the system's - and the one a chain short of its root is completed
    from (review 2026-10-29 again, BB07).
    """

    url = endpoint + "?operation=GetCACert&message=ca"
    deadline = time.monotonic() + DEADLINE
    try:
        opener = _opener(trust)
    except (OSError, ssl.SSLError) as exc:
        raise NdesServerError(
            "tls",
            f"{_store(trust)} cannot be read: {http_answer.said(exc)}",
            exit_codes.CONFIG,
        ) from None
    try:
        with opener.open(url, timeout=TIMEOUT) as response:
            data = http_answer.read_body(response, MAX_ANSWER, deadline=deadline)
    except urllib.error.HTTPError as exc:
        # The error is the response too, and is closed (review 2026-10-28, F04).
        with exc:
            if 300 <= exc.code < 400:
                location = exc.headers.get("Location", "")[:300] or "another address"
                raise NdesServerError(
                    "redirected",
                    f"{endpoint} redirected to {location}; give the address it redirects to",
                    exit_codes.UNAVAILABLE,
                ) from None
            raise NdesServerError(
                "unreachable", f"{endpoint} answered HTTP {exc.code}", exit_codes.UNAVAILABLE
            ) from None
    except http_answer.BROKEN as exc:
        #
        # The server answered, but not over HTTPS this manager trusts - the
        # likeliest failure at a first setup, and not "did not answer" (review
        # 2026-10-29 again, BB07). URLError carries the TLS error as its reason.
        #
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        if isinstance(reason, ssl.SSLCertVerificationError):
            raise NdesServerError(
                "tls",
                f"{endpoint}: its HTTPS certificate is not trusted by {_store(trust)} "
                f"({_tls_said(reason)}); add the CA that issued it to the store",
                exit_codes.UNAVAILABLE,
            ) from None
        if isinstance(reason, ssl.SSLError):
            raise NdesServerError(
                "tls",
                f"{endpoint}: TLS failed: {_tls_said(reason)}",
                exit_codes.UNAVAILABLE,
            ) from None
        raise NdesServerError(
            "unreachable",
            f"{endpoint} did not answer: {http_answer.said(exc)}",
            exit_codes.UNAVAILABLE,
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


def authorities(
    endpoint: str, *, fetch: Fetch = get_ca_cert, trust: Path = SYSTEM_TRUST
) -> tuple[Authority, ...]:
    """The CA certificates the server gives, the one that issued its RA certificate first.

    A chain that does not reach a self-signed root is completed from `trust` -
    the store the server's HTTPS is checked against - and refused when it
    cannot be: a certificate issued from it would not verify (review
    2026-10-29, B09, decided in B388).
    """

    try:
        endpoint = check_endpoint(endpoint)
    except ProfileError:
        raise NdesServerError(
            "bad_input", "the address must be an HTTPS URL without credentials or query"
        ) from None
    try:
        certificates, _keys = read_bytes(fetch(endpoint, trust))
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
                authority_pems.append((subject, issuer, certificate))
            else:
                issuers.add(issuer)
        if not authority_pems:
            raise NdesServerError(
                "bad_answer", f"{endpoint} answered with no CA certificate", exit_codes.UNAVAILABLE
            )
        completed = _completed(authority_pems, trust)
        if completed is None:
            raise NdesServerError(
                "no_root",
                f"{endpoint} gives no root CA, and none in the manager's certificate store "
                "issues its CA; add the root CA to the store",
            )
        found = [
            _authority(certificate, subject, issues_ra=subject in issuers)
            for subject, _issuer, certificate in authority_pems
        ] + [
            _authority(certificate, subject, from_store=True) for subject, certificate in completed
        ]
    except ImportError_ as exc:
        raise NdesServerError(
            "bad_answer", f"{endpoint} answered with no CA: {exc}", exit_codes.UNAVAILABLE
        ) from None
    return tuple(sorted(found, key=lambda authority: not authority.issues_ra))


def _authority(
    certificate: str, subject: str, *, issues_ra: bool = False, from_store: bool = False
) -> Authority:
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
    return Authority(
        subject=subject,
        sha256=hashlib.sha256(_der(certificate)).hexdigest(),
        sha1=thumbprint.partition("=")[2].strip().replace(":", "").lower(),
        pem=certificate,
        issues_ra=issues_ra,
        from_store=from_store,
    )


def _completed(chain: Sequence[tuple[str, str, str]], trust: Path) -> list[tuple[str, str]] | None:
    """The CA certificates from `trust` that take the chain to a self-signed root.

    None when it cannot be taken there. A candidate has the issuer's name -
    by openssl's name hash - and must have signed the certificate it is to
    issue: a name alone is not a CA.
    """

    subjects = {subject for subject, _issuer, _pem in chain}
    tops = [(issuer, pem) for subject, issuer, pem in chain if issuer != subject]
    dangling = [(issuer, pem) for issuer, pem in tops if issuer not in subjects]
    if not dangling:
        return []
    try:
        pool = split_blocks(trust.read_text(encoding="ascii", errors="replace"))[0]
    except OSError:
        return None
    hashes: list[str] | None = None
    added: list[tuple[str, str]] = []
    while dangling:
        issuer, child = dangling.pop()
        if issuer in subjects:
            continue
        if len(added) == MAX_COMPLETION:
            return None
        if hashes is None:
            hashes = [_name_hash(pem, "-subject_hash") for pem in pool]
        wanted = _name_hash(child, "-issuer_hash")
        parent = next(
            (
                pem
                for pem, hashed in zip(pool, hashes, strict=True)
                if hashed == wanted and _signed(child, pem)
            ),
            None,
        )
        if parent is None:
            return None
        subject, its_issuer = _names(parent)
        added.append((subject, parent))
        subjects.add(subject)
        if its_issuer != subject:
            dangling.append((its_issuer, parent))
    return added


def _name_hash(certificate: str, which: str) -> str:
    try:
        return _openssl(
            ["x509", "-noout", which], stdin=certificate, what="read a CA certificate's name"
        ).strip()
    except ImportError_:
        # A block in a store openssl cannot read is no candidate.
        return ""


def _signed(child: str, parent: str) -> bool:
    """Whether `parent` signed `child`, as openssl verifies it with `parent` as the anchor."""

    with tempfile.TemporaryDirectory() as raw:
        anchor = Path(raw) / "anchor.pem"
        anchor.write_text(parent)
        try:
            verified = subprocess.run(  # noqa: S603 - fixed binary, a private temporary file
                [OPENSSL, "verify", "-partial_chain", "-CAfile", str(anchor)],
                input=child,
                capture_output=True,
                text=True,
                timeout=OPENSSL_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
    return verified.returncode == 0


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


def ca_expires(path: Path) -> str | None:
    """When the first of a server's saved CA certificates expires, as an ISO time (B389).

    The chain ends with its shortest-lived certificate: from then on every
    certificate the server issues is refused. None when the file cannot be
    read, holds no certificate, or one of them cannot be read.
    """

    try:
        text = path.read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return None
    ends = []
    for match in CERTIFICATE_BLOCK.finditer(text):
        try:
            ends.append(describe(match.group(0)).not_after)
        except CertificateError:
            return None
    if not ends:
        return None
    return min(ends).isoformat(timespec="seconds").replace("+00:00", "Z")


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


def ca_file(endpoint: str, content: bytes, directory: Path = CA_DIRECTORY) -> Path:
    """Named by the server and by what it holds (review 2026-10-29, B03).

    A new CA goes to a file of its own, so a policy that is refused leaves the
    file the old one names as it was; the old file goes once the new policy is
    in place.
    """

    server = hashlib.sha256(endpoint.encode()).hexdigest()[:16]
    return directory / f"{server}-{hashlib.sha256(content).hexdigest()[:16]}.pem"


def _forget_ca(previous: object, servers: Sequence[Any], directory: Path) -> None:
    """Remove a CA file no server names any more, when the manager wrote it.

    Only a file in the manager's own directory: a policy from before B385
    names its CA file where the installation put it. A server names a file
    as its `issuing_ca` or as its `tls_ca` - the same root may issue both -
    and the names are compared as paths, not as the policy spells them
    (review 2026-10-29 again, BB05).
    """

    if not isinstance(previous, str):
        return
    path = os.path.normpath(previous)
    if Path(path).parent != Path(os.path.normpath(directory)):
        return
    if any(
        isinstance(s, dict)
        and any(
            isinstance(s.get(field), str) and os.path.normpath(s[field]) == path
            for field in ("issuing_ca", "tls_ca")
        )
        for s in servers
    ):
        return
    Path(path).unlink(missing_ok=True)


def _dns_keys(data: dict[str, Any]) -> list[Any] | None:
    acme = data.get("acme")
    dns = acme.get("dns_profiles") if isinstance(acme, dict) else None
    keys = dns.get("private_keys") if isinstance(dns, dict) else None
    return keys if isinstance(keys, list) and keys else None


def _ndes_block(data: dict[str, Any], policy_path: Path) -> dict[str, Any]:
    """The policy's ndes block in the form with servers; a new one with the defaults."""

    raw = data.get("ndes")
    if raw is None:
        #
        # The profiles' keys are the DNS profiles' own, read from there
        # (review 2026-10-29, B05).
        #
        return {
            "servers": [],
            "client_root": CLIENT_ROOT,
            "state_root": STATE_ROOT,
            "profiles": {"directory": PROFILE_DIRECTORY},
        }
    if not isinstance(raw, dict):
        raise NdesServerError(
            "bad_policy", f"{policy_path}: ndes is not a mapping", exit_codes.CONFIG
        )
    #
    # A block that lists keys of its own keeps them: an engine before B05
    # reads only those (review 2026-10-29, B05).
    #
    block = dict(raw)
    if "endpoint" in block:
        server = {"endpoint": block.pop("endpoint"), "issuing_ca": block.pop("issuing_ca", None)}
        if "tls_ca" in block:
            server["tls_ca"] = block.pop("tls_ca")
        block = {"servers": [server], **block}
    block.setdefault("servers", [])
    return block


def _block(text: str) -> tuple[int, int] | None:
    """Where the policy's ndes block starts and ends.

    The comments in the first column right before what follows - the next key,
    or the end of the file - are what follows them, and stay (review
    2026-10-29, B04: the regex ended the block at the next key, so a comment
    above it went with the block).
    """

    start = re.search(r"^ndes:", text, re.MULTILINE)
    if start is None:
        return None
    following = TOP_LEVEL.search(text, start.end())
    end = following.start() if following else len(text)
    cut = position = end
    for line in reversed(text[start.end() : end].splitlines(keepends=True)[1:]):
        if line.startswith("#"):
            position -= len(line)
            cut = position
        elif not line.strip():
            position -= len(line)
        else:
            break
    return start.start(), cut


def with_ndes(text: str, block: dict[str, Any]) -> str:
    """The policy's text with its ndes block replaced, or added at its end."""

    rendered = yaml.safe_dump({"ndes": block}, sort_keys=False, default_flow_style=False)
    found = _block(text)
    if found is None:
        return text.rstrip("\n") + "\n\n" + rendered
    start, end = found
    rest = text[end:]
    return text[:start] + rendered + ("\n" if rest else "") + rest


def without_ndes(text: str) -> str:
    found = _block(text)
    if found is None:
        return text
    start, end = found
    rest = text[end:]
    return text[:start].rstrip("\n") + "\n" + ("\n" + rest if rest else "")


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


def _require_profile_key(policy_path: Path) -> None:
    """A server is for profiles, and a profile is sealed with a key the policy lists."""

    data = safe_yaml.load(policy_path.read_text()) or {}
    ndes = data.get("ndes") if isinstance(data, dict) else None
    profiles = ndes.get("profiles") if isinstance(ndes, dict) else None
    if isinstance(profiles, dict) and profiles.get("private_keys"):
        return
    if isinstance(data, dict) and _dns_keys(data) is not None:
        return
    raise NdesServerError(
        "no_profile_key",
        "This installation has no profile key; see The DNS profile key pair in the user manual.",
        exit_codes.CONFIG,
    )


def add(
    endpoint: str,
    fingerprints: Sequence[str],
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    ca_directory: Path | None = None,
    fetch: Fetch = get_ca_cert,
    trust: Path = SYSTEM_TRUST,
) -> dict[str, Any]:
    """Confirm the server whose CA certificates have these SHA-256s, and write it into the policy.

    Every certificate the server gives is saved, so every one is confirmed: a
    server that now gives one more, one fewer or another is refused.
    """

    ca_directory = CA_DIRECTORY if ca_directory is None else ca_directory
    if not fingerprints or any(SHA256.fullmatch(each) is None for each in fingerprints):
        raise NdesServerError("bad_input", "each fingerprint must be a SHA-256 in hexadecimal")
    _require_profile_key(policy_path)
    found = authorities(endpoint, fetch=fetch, trust=trust)
    endpoint = check_endpoint(endpoint)
    if {authority.sha256 for authority in found} != set(fingerprints):
        raise NdesServerError(
            "changed",
            f"{endpoint} no longer gives the CA certificates confirmed; fetch them again and compare",
        )
    content = "".join(a.pem for a in found).encode()
    path = ca_file(endpoint, content, ca_directory)
    with locked():
        ca_directory.mkdir(mode=0o755, exist_ok=True)
        existed = path.exists()
        atomic_file.write(path, content, mode=0o644)
        try:
            text = policy_path.read_text()
            data = safe_yaml.load(text) or {}
            block = _ndes_block(data, policy_path)
            entry: dict[str, Any] = {"endpoint": endpoint, "issuing_ca": str(path)}
            #
            # A server confirmed again keeps what the confirmation does not
            # decide: its own HTTPS CA, which would otherwise fall back to the
            # system's store unsaid (review 2026-10-29, B02).
            #
            servers = list(block["servers"])
            place = next(
                (i for i, s in enumerate(servers) if s.get("endpoint") == endpoint), len(servers)
            )
            previous = None
            if place < len(servers):
                previous = servers[place].get("issuing_ca")
                if servers[place].get("tls_ca") is not None:
                    entry["tls_ca"] = servers[place]["tls_ca"]
                servers[place] = entry
            else:
                servers.append(entry)
            block["servers"] = servers
            _write_policy(policy_path, with_ndes(text, block))
        except BaseException:
            if not existed:
                path.unlink(missing_ok=True)
            raise
        _forget_ca(previous, servers, ca_directory)
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
    ca_directory: Path | None = None,
) -> dict[str, Any]:
    """Take the server out of the policy, unless a profile still uses it.

    `used_by` is asked under the lock, so a profile applied a moment before is
    seen: the profile apply helper checks its server under the same lock.
    """

    with locked():
        return _remove(
            endpoint,
            used_by=used_by(),
            policy_path=policy_path,
            ca_directory=CA_DIRECTORY if ca_directory is None else ca_directory,
        )


def _remove(
    endpoint: str, *, used_by: Sequence[str], policy_path: Path, ca_directory: Path
) -> dict[str, Any]:
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
    gone = [s for s in block["servers"] if s.get("endpoint") == endpoint]
    if not gone:
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
    for entry in gone:
        _forget_ca(entry.get("issuing_ca"), servers, ca_directory)
        _forget_ca(entry.get("tls_ca"), servers, ca_directory)
    return {"endpoint": endpoint}


def profiles_using(directory: Path, endpoint: str) -> tuple[str, ...]:
    """The materialized profiles whose address is this server's.

    A record that cannot be read may be any server's, so it holds each of them,
    by its file's name - as `ndes_profiles.pending_requests` counts a request
    it cannot read as bound (review 2026-10-29, B10).
    """

    found = []
    for record in sorted(directory.glob("*.json")) if directory.is_dir() else ():
        try:
            row = json.loads(record.read_text())
        except (OSError, ValueError):
            row = None
        if not isinstance(row, dict):
            found.append(record.stem)
        elif row.get("endpoint") == endpoint:
            found.append(str(row.get("profile_id") or record.stem))
    return tuple(found)
