"""A short-lived Certmonger instance behind the root boundary.

Certmonger owns SCEP/CMS and restartable protocol state. The engine owns names,
trust configuration, validation and publication. No system bus or renewal service.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlsplit

from haprion import exit_codes
from haprion.cert_import import Material, assemble, check, split_blocks
from haprion.config import CERTIFICATE_ID, HOSTNAME, NdesPolicy
from haprion.dns_profiles import ProfileError
from haprion.ndes_profiles import OpenedProfile, check_challenge, secure_directory
from haprion.ndes_state import remove_request, request_directory

MAX_BYTES = 1024 * 1024
COMMAND_TIMEOUT = 15
ENROLL_TIMEOUT = 90


class NdesError(Exception):
    def __init__(
        self, code: str, message: str, *, exit_code: int = exit_codes.REFUSED, discard: bool = False
    ):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code
        #
        # True when the request this failed has nothing left to resume: the
        # CA said no, or Certmonger never took the request. `enroll` then
        # removes the request directory, so the ID can be asked for again
        # and the profile removed (review 2026-09-17, finding 2). A timeout
        # in a state that may still complete keeps it.
        #
        self.discard = discard


def names(values: Sequence[str]) -> tuple[str, ...]:
    if not values or len(values) > 32:
        raise NdesError("bad_input", "specify between one and 32 DNS names")
    checked = []
    for value in values:
        bare = value[2:] if value.startswith("*.") else value
        if not HOSTNAME.fullmatch(bare):
            raise NdesError("bad_input", "invalid DNS name")
        checked.append(value)
    return tuple(dict.fromkeys(checked))


def validate_policy(policy: NdesPolicy, *, require_secure: bool = True) -> None:
    endpoint = urlsplit(policy.endpoint)
    if (
        endpoint.scheme != "https"
        or not endpoint.hostname
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.query
        or endpoint.fragment
        or any(c.isspace() for c in policy.endpoint)
    ):
        raise NdesError(
            "bad_input", "NDES endpoint must be an HTTPS URL without credentials or query"
        )
    for path in (policy.tls_ca, policy.issuing_ca):
        secure_file(path, require_secure=require_secure)
    for name in ("certmonger", "getcert", "scep-submit"):
        binary = (policy.client_root / "bin" / name).resolve()
        if require_secure:
            for parent in binary.parents:
                info = parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise NdesError(
                        "dependency_unavailable",
                        "NDES client ancestors are not protected",
                        exit_code=exit_codes.CONFIG,
                    )
        secure_file(binary, require_secure=require_secure)
        if not os.access(binary, os.X_OK):
            raise NdesError(
                "dependency_unavailable",
                f"NDES client is not executable: {binary}",
                exit_code=exit_codes.CONFIG,
            )


def secure_file(path: Path, *, require_secure: bool, secret: bool = False) -> bytes:
    """Open once without following a final symlink; never return a diagnostic containing data."""
    if not path.is_absolute():
        raise NdesError("bad_input", "NDES paths must be absolute")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise NdesError(
                    "dependency_unavailable",
                    "NDES file is not a bounded regular file",
                    exit_code=exit_codes.CONFIG,
                )
            if require_secure and (info.st_uid != 0 or info.st_mode & (0o077 if secret else 0o022)):
                raise NdesError(
                    "dependency_unavailable",
                    "NDES files must be root-owned and protected",
                    exit_code=exit_codes.CONFIG,
                )
            content = handle.read(MAX_BYTES + 1)
            if len(content) > MAX_BYTES:
                raise NdesError(
                    "dependency_unavailable",
                    "NDES file exceeds its bounds",
                    exit_code=exit_codes.CONFIG,
                )
            return content
    except OSError:
        raise NdesError(
            "dependency_unavailable", f"NDES file unavailable: {path}", exit_code=exit_codes.CONFIG
        ) from None


def environment(directory: Path) -> dict[str, str]:
    return {
        "LANG": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "CERTMONGER_SYSTEM_LOCK_FILE": str(directory / "lock"),
        "CERTMONGER_PVT_ADDRESS": "unix:path=" + str(directory / "socket"),
        "CERTMONGER_CONFIG_DIR": str(directory / "config"),
        "CERTMONGER_REQUESTS_DIR": str(directory / "requests"),
        "CERTMONGER_CAS_DIR": str(directory / "cas"),
        "CERTMONGER_LOCAL_CA_DIR": str(directory / "local"),
    }


def command(policy: NdesPolicy, directory: Path, arguments: Sequence[str]) -> str:
    try:
        with tempfile.TemporaryFile() as output:
            completed = subprocess.run(  # noqa: S603 - protected binary, fixed grammar
                [str(policy.client_root / "bin/getcert"), *arguments],
                env=environment(directory),
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.DEVNULL,
                timeout=COMMAND_TIMEOUT,
                check=False,
            )
            if completed.returncode or output.tell() > 65536:
                raise NdesError(
                    "scep_failed", "Certmonger command failed", exit_code=exit_codes.FAILED
                )
            output.seek(0)
            return output.read(65536).decode("utf-8")
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        raise NdesError(
            "dependency_unavailable",
            "Certmonger command unavailable or timed out",
            exit_code=exit_codes.CONFIG,
        ) from None


@contextmanager
def instance(policy: NdesPolicy, directory: Path) -> Iterator[None]:
    socket = directory / "socket"
    if socket.exists() or socket.is_symlink():
        if not stat.S_ISSOCK(socket.lstat().st_mode):
            raise NdesError("bad_input", "unexpected file at private socket path")
        socket.unlink()
    for name in ("config", "requests", "cas", "local"):
        (directory / name).mkdir(mode=0o700, exist_ok=True)
    # Socket paths are bounded by sockaddr_un, independently of filename validity.
    if len(os.fsencode(directory / "socket")) > 100:
        raise NdesError("bad_input", "NDES state path is too long for a private socket")
    try:
        process = subprocess.Popen(  # noqa: S603 - protected binary, private fixed socket
            [
                str(policy.client_root / "bin/certmonger"),
                "-L",
                "-P",
                str(directory / "socket"),
                "-n",
            ],
            env=environment(directory),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        raise NdesError(
            "dependency_unavailable", "Certmonger could not start", exit_code=exit_codes.CONFIG
        ) from None
    try:
        deadline = time.monotonic() + 5
        while not (directory / "socket").exists():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise NdesError(
                    "dependency_unavailable",
                    "Certmonger private socket unavailable",
                    exit_code=exit_codes.CONFIG,
                )
            time.sleep(0.05)
        yield
    finally:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        (directory / "socket").unlink(missing_ok=True)


CA_DATA_TIMEOUT = 30
CA_DATA_MARK = "SCEP CA certificate thumbprint"


def wait_for_ca(policy: NdesPolicy, directory: Path, *, timeout: float = CA_DATA_TIMEOUT) -> None:
    """Block until Certmonger has fetched the CA's certificates, or give up.

    `add-ca` returns before the daemon has asked the CA for its RA and CA
    certificates; it fetches them on its own. A request submitted before
    they are there makes `scep-submit` answer *unconfigured* ("No RA
    certificate given"), and Certmonger parks the request in
    `CA_UNCONFIGURED` for good - it never retries that state. The two live
    enrollments of 2026-09-15 and the one of 2026-09-19 won the race; job
    932 on 2026-09-21 lost it. `getcert list-cas` prints the CA
    certificate's thumbprints once the data is in, and that is waited for.
    """

    deadline = time.monotonic() + timeout
    while True:
        text = command(policy, directory, ["list-cas", "-c", "ndes"])
        if CA_DATA_MARK in text:
            return
        if time.monotonic() >= deadline:
            raise NdesError(
                "dependency_unavailable",
                "Certmonger could not fetch the NDES CA certificate",
                exit_code=exit_codes.CONFIG,
                discard=True,
            )
        time.sleep(0.5)


def status(policy: NdesPolicy, directory: Path) -> str:
    text = command(policy, directory, ["list", "-i", "enrollment"])
    match = re.search(r"^\s*status: ([A-Z_]+)$", text, re.MULTILINE)
    if match is None:
        raise NdesError(
            "scep_failed",
            "Certmonger returned no request status",
            exit_code=exit_codes.FAILED,
            discard=True,
        )
    return match.group(1)


@dataclass(frozen=True, slots=True)
class Enrollment:
    state: str
    directory: Path
    material: Material | None = field(default=None, repr=False)


def _enroll(
    policy: NdesPolicy,
    *,
    certificate_id: str,
    profile: OpenedProfile,
    domains: Sequence[str],
    resume: bool = False,
    require_secure: bool = True,
    timeout: float = ENROLL_TIMEOUT,
) -> Enrollment:
    """Enroll into isolated staging. Published material is never touched here."""
    if not CERTIFICATE_ID.fullmatch(certificate_id):
        raise NdesError("bad_input", "invalid certificate ID")
    requested = names(domains)
    if requested[0].startswith("*."):
        raise NdesError(
            "bad_input", "use the base DNS name as primary CN and list the wildcard as a SAN"
        )
    validate_policy(policy, require_secure=require_secure)
    directory = request_directory(policy.state_root, certificate_id)
    if directory.is_symlink() or policy.state_root.is_symlink():
        raise NdesError("bad_input", "NDES state directories cannot be symlinks")
    #
    # A request the CA has answered is over: its certificate was imported
    # and the directory should have gone with it, but one that stayed - an
    # older run, a death between import and cleanup - is not a request to
    # resume. Asking anew is a new key and a new request, which is what a
    # renewal is; only a directory *without* the certificate is a request
    # the CA still holds, and that one is refused below (2026-09-21, job
    # 925: "resume it instead" about a certificate issued two days before).
    #
    if not resume and (directory / "request.json").exists() and (directory / "cert.pem").exists():
        remove_request(policy.state_root, certificate_id)
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.stat()
    if require_secure and (info.st_uid != 0 or info.st_mode & 0o077):
        raise NdesError(
            "dependency_unavailable",
            "NDES state must be root-owned mode 0700",
            exit_code=exit_codes.CONFIG,
        )
    record = directory / "request.json"
    expected = {
        "certificate": certificate_id,
        "profile": profile.profile_id,
        "revision": profile.revision,
        "key_id": profile.key_id,
        "endpoint": policy.endpoint,
        "issuing_ca_sha256": hashlib.sha256(
            secure_file(policy.issuing_ca, require_secure=require_secure)
        ).hexdigest(),
        "tls_ca_sha256": hashlib.sha256(
            secure_file(policy.tls_ca, require_secure=require_secure)
        ).hexdigest(),
        "domains": list(requested),
    }
    if resume:
        try:
            existing = json.loads(secure_file(record, require_secure=require_secure, secret=True))
        except (ValueError, UnicodeError):
            raise NdesError("bad_input", "NDES request record is unreadable") from None
        if existing != expected:
            raise NdesError(
                "bad_input", "resume must use the original endpoint, trust and DNS names"
            )
    elif record.exists():
        raise NdesError(
            "already_exists", "an NDES request exists; resume it instead of replacing its key"
        )
    else:
        fd = os.open(record, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(expected, handle)
    for source, filename in ((policy.tls_ca, "tls-ca.pem"), (policy.issuing_ca, "issuing-ca.pem")):
        content = secure_file(source, require_secure=require_secure)
        destination = directory / filename
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
    old_umask = os.umask(0o077)
    try:
        challenge = directory / "challenge"
        fd = os.open(challenge, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(profile.challenge + "\n")
        with instance(policy, directory):
            if not resume:
                helper = shlex.join(
                    [
                        str(policy.client_root / "bin/scep-submit"),
                        "-u",
                        policy.endpoint,
                        "-R",
                        str(directory / "tls-ca.pem"),
                        "-N",
                        str(directory / "issuing-ca.pem"),
                    ]
                )
                try:
                    command(policy, directory, ["add-ca", "-c", "ndes", "-e", helper])
                    wait_for_ca(policy, directory)
                except NdesError as exc:
                    exc.discard = True
                    raise
                arguments = [
                    "request",
                    "-c",
                    "ndes",
                    "-I",
                    "enrollment",
                    "-k",
                    str(directory / "privkey.pem"),
                    "-f",
                    str(directory / "cert.pem"),
                    "-N",
                    "CN=" + requested[0],
                    "-G",
                    "RSA",
                    "-g",
                    "2048",
                    "-R",
                    "-l",
                    str(challenge),
                    "-u",
                    "digitalSignature",
                    "-u",
                    "keyEncipherment",
                    "-m",
                    "600",
                    "-M",
                    "600",
                ]
                for domain in requested:
                    arguments.extend(["-D", domain])
                try:
                    command(policy, directory, arguments)
                except NdesError as exc:
                    #
                    # No request reached Certmonger, so there is nothing to
                    # resume; a directory left here would refuse the next
                    # attempt with "resume it instead".
                    #
                    exc.discard = True
                    raise
            deadline = time.monotonic() + timeout
            while True:
                state = status(policy, directory)
                if state == "MONITORING":
                    certs, stray_keys = split_blocks(
                        secure_file(directory / "cert.pem", require_secure=require_secure).decode(
                            "ascii"
                        )
                    )
                    if stray_keys:
                        raise NdesError(
                            "scep_failed",
                            "certificate output contains a private key",
                            exit_code=exit_codes.FAILED,
                        )
                    chain, _ = split_blocks(
                        secure_file(
                            directory / "issuing-ca.pem", require_secure=require_secure
                        ).decode("ascii")
                    )
                    _, keys = split_blocks(
                        secure_file(
                            directory / "privkey.pem", require_secure=require_secure, secret=True
                        ).decode("ascii")
                    )
                    return Enrollment("issued", directory, assemble([*certs, *chain], keys))
                if state in {
                    "CA_REJECTED",
                    "NEED_GUIDANCE",
                    "NEED_SCEP_ENCRYPTION_CERT",
                    "CA_UNCONFIGURED",
                    "NEED_CERTSAVE_PERMS",
                    "INVALID",
                    "NEED_SCEP_RSA_CLIENT_KEY",
                    "NEED_CSR_GEN_PIN",
                    "NEED_KEY_GEN_PIN",
                }:
                    raise NdesError(
                        "scep_failed",
                        "Certmonger enrollment stopped: " + state,
                        exit_code=exit_codes.FAILED,
                        discard=True,
                    )
                if time.monotonic() >= deadline:
                    if state == "CA_WORKING":
                        return Enrollment("pending", directory)
                    raise NdesError(
                        "scep_timeout",
                        "Certmonger enrollment timed out: " + state,
                        exit_code=exit_codes.FAILED,
                    )
                time.sleep(0.2)
    finally:
        (directory / "challenge").unlink(missing_ok=True)
        os.umask(old_umask)


@contextmanager
def enroll(
    policy: NdesPolicy,
    *,
    certificate_id: str,
    profile: OpenedProfile,
    domains: Sequence[str],
    resume: bool = False,
    require_secure: bool = True,
    timeout: float = ENROLL_TIMEOUT,
) -> Iterator[Enrollment]:
    if not CERTIFICATE_ID.fullmatch(certificate_id) or profile.endpoint != policy.endpoint:
        raise NdesError("bad_input", "certificate ID or NDES profile endpoint is invalid")
    policy = replace(policy, client_root=policy.client_root.resolve())
    try:
        check_challenge(profile.challenge)
        secure_directory(policy.state_root, require_secure=require_secure)
    except ProfileError as exc:
        raise NdesError("dependency_unavailable", str(exc), exit_code=exit_codes.CONFIG) from None
    lock_path = policy.state_root / (
        hashlib.sha256(certificate_id.encode()).hexdigest()[:24] + ".lock"
    )
    #
    # The lock and the enrollment's own files are asked about here, and not the
    # caller's block: the `try` used to hold the `yield`, so a disk-full error
    # in the caller's import was reported as "NDES state is unavailable" and a
    # BlockingIOError there as "busy" - after the material may have been
    # written (review 2026-10-22, 4-4).
    #
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        raise NdesError(
            "dependency_unavailable",
            "protected NDES state is unavailable",
            exit_code=exit_codes.CONFIG,
        ) from None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise NdesError(
                "busy",
                "another enrollment is running for this certificate",
                exit_code=exit_codes.BLOCKED,
            ) from None
        except OSError:
            raise NdesError(
                "dependency_unavailable",
                "protected NDES state is unavailable",
                exit_code=exit_codes.CONFIG,
            ) from None
        try:
            try:
                enrollment = _enroll(
                    policy,
                    certificate_id=certificate_id,
                    profile=profile,
                    domains=domains,
                    resume=resume,
                    require_secure=require_secure,
                    timeout=timeout,
                )
            except OSError:
                raise NdesError(
                    "dependency_unavailable",
                    "protected NDES state is unavailable",
                    exit_code=exit_codes.CONFIG,
                ) from None
            yield enrollment
        except NdesError as exc:
            if exc.discard:
                remove_request(policy.state_root, certificate_id)
            raise
    finally:
        os.close(fd)


def abandon(policy: NdesPolicy, certificate_id: str, *, require_secure: bool = True) -> bool:
    """Give up a request the CA has not answered, key and all, under its lock.

    For the request that is neither finished nor rejected - one the process
    died on, or one whose approval will never come. True when there was one.
    """

    if not CERTIFICATE_ID.fullmatch(certificate_id):
        raise NdesError("bad_input", "invalid certificate ID")
    try:
        secure_directory(policy.state_root, require_secure=require_secure)
    except ProfileError as exc:
        raise NdesError("dependency_unavailable", str(exc), exit_code=exit_codes.CONFIG) from None
    lock_path = policy.state_root / (
        hashlib.sha256(certificate_id.encode()).hexdigest()[:24] + ".lock"
    )
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return remove_request(policy.state_root, certificate_id)
        finally:
            os.close(fd)
    except BlockingIOError:
        raise NdesError(
            "busy",
            "another enrollment is running for this certificate",
            exit_code=exit_codes.BLOCKED,
        ) from None
    except OSError:
        raise NdesError(
            "dependency_unavailable",
            "protected NDES state is unavailable",
            exit_code=exit_codes.CONFIG,
        ) from None


def validate_certificate(material: Material, requested: Sequence[str], directory: Path) -> None:
    """Validate the issued chain, exact subject/SAN and server usages before import."""
    domains = names(requested)
    facts, _ = check(material)
    if facts.common_name != domains[0] or set(facts.sans) != set(domains):
        raise NdesError(
            "certificate_mismatch",
            "issued certificate subject or SAN does not match the request",
            exit_code=exit_codes.FAILED,
        )
    leaf = directory / "verify-leaf.pem"
    chain = directory / "verify-chain.pem"
    for path, content in ((leaf, material.leaf), (chain, "".join(material.chain))):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
    arguments = [
        "/usr/bin/openssl",
        "verify",
        "-purpose",
        "sslserver",
        "-CAfile",
        str(directory / "issuing-ca.pem"),
    ]
    if material.chain:
        arguments.extend(["-untrusted", str(chain)])
    arguments.append(str(leaf))
    try:
        verified = subprocess.run(arguments, capture_output=True, timeout=15, check=False)  # noqa: S603 - protected staging, fixed verification grammar
        if verified.returncode:
            raise NdesError(
                "untrusted_certificate",
                "issued certificate chain or server purpose is invalid",
                exit_code=exit_codes.FAILED,
            )

        def extension(name: str) -> str:
            result = subprocess.run(  # noqa: S603 - public certificate, fixed OpenSSL grammar
                ["/usr/bin/openssl", "x509", "-in", str(leaf), "-noout", "-ext", name],
                env={"LANG": "C", "PATH": "/usr/bin:/bin"},
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )  # verified public certificate, fixed OpenSSL options
            if result.returncode:
                raise NdesError(
                    "certificate_mismatch",
                    "issued certificate extensions cannot be read",
                    exit_code=exit_codes.FAILED,
                )
            return result.stdout

        # A CA certificate must carry basicConstraints with CA:TRUE (RFC 5280,
        # Basic Constraints); a leaf need not carry the extension at all, and AD CS
        # leaves issued from a web-server template do not. Absence is a leaf.
        if "CA:TRUE" in extension("basicConstraints"):
            raise NdesError(
                "certificate_mismatch",
                "issued certificate is a CA certificate, not an end-entity certificate",
                exit_code=exit_codes.FAILED,
            )
        eku = extension("extendedKeyUsage")
        usage = extension("keyUsage")
        sans = extension("subjectAltName")
        subject = subprocess.run(  # noqa: S603 - public certificate, fixed OpenSSL grammar
            [
                "/usr/bin/openssl",
                "x509",
                "-in",
                str(leaf),
                "-noout",
                "-subject",
                "-nameopt",
                "RFC2253",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )  # protected public certificate, fixed options
        if subject.returncode or subject.stdout.strip() != "subject=CN=" + domains[0]:
            raise NdesError(
                "certificate_mismatch",
                "issued certificate subject differs from the CSR",
                exit_code=exit_codes.FAILED,
            )
        entries = [
            value.strip()
            for line in sans.splitlines()[1:]
            for value in line.split(",")
            if value.strip()
        ]
        if set(entries) != {"DNS:" + value for value in domains}:
            raise NdesError(
                "certificate_mismatch",
                "issued certificate has unexpected SAN entries",
                exit_code=exit_codes.FAILED,
            )
        if (
            "TLS Web Server Authentication" not in eku
            or "Digital Signature" not in usage
            or "Key Encipherment" not in usage
        ):
            raise NdesError(
                "certificate_mismatch",
                "issued certificate lacks the required server EKU or key usages",
                exit_code=exit_codes.FAILED,
            )
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        raise NdesError(
            "dependency_unavailable",
            "certificate verification could not run",
            exit_code=exit_codes.CONFIG,
        ) from None
    finally:
        leaf.unlink(missing_ok=True)
        chain.unlink(missing_ok=True)
