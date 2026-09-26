"""Installing the interface's own certificate: registry in, nginx out (B188).

The manager's interface certificate is an ordinary registry entry marked
`interface: true`. It is issued, imported and renewed by exactly the code every
other certificate uses; the one thing that differs is where it is published.
A cluster certificate becomes a file the nodes pull. This one becomes the pair
nginx serves the interface with, and that pair has had one installer since the
platform was built: `haproxy-ui-tls install`, with its checks, its `nginx -t`,
its reload and its rollback. This module hands the material to that command and
does not grow a second path.

What it adds in front of the command
------------------------------------
Two refusals `haproxy-ui-tls` does not make, because an operator at a root
shell choosing a file is trusted to have chosen the right one and a renewal
timer is not:

- the certificate must name the interface's `SERVER_NAME`. A certificate that
  does not would install cleanly, pass `nginx -t`, and put a browser warning in
  front of everyone who logs in afterwards.
- a certificate nginx already serves is not installed again. The publisher runs
  after every renewal of anything, and a reload of the interface each time
  another certificate renewed would be noise with a cost.

Where it runs
-------------
As root, outside the worker's sandbox: from the renewal timer and an operator's
`haproxy-cert-publish` directly, and from the interface through its own socket
helper (D3), because the worker's sandbox cannot write the pair's directory.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from haproxy_mgmt.cert_publish import Material, PublishError
from haproxy_mgmt.certificates import CertificateError, leaf_fingerprint

UI_TLS_CONFIG = Path("/etc/haproxy-manager/ui-tls.conf")
UI_TLS_COMMAND = Path("/usr/local/sbin/haproxy-ui-tls")
INSTALL_TIMEOUT = 120

#
# The file is written by 05-platform-nginx and sourced by a shell script, so it
# is shell syntax - but only the narrow part of it that installer writes. Read
# with a pattern rather than a shell: a line this does not recognise is refused,
# not evaluated.
#
_ASSIGNMENT = re.compile(r"^([A-Z_]+)=([^\s'\"`$;&|<>()\\]+)$")

type Runner = Callable[..., subprocess.CompletedProcess[str]]
type Installer = Callable[[Material], bool]


@dataclass(frozen=True, slots=True)
class InterfaceConfig:
    cert: Path
    key: Path
    server_name: str


def read_config(path: Path = UI_TLS_CONFIG) -> InterfaceConfig:
    """`TLS_CERT`, `TLS_KEY` and `SERVER_NAME`, as `haproxy-ui-tls` reads them."""

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PublishError("dependency_unavailable", f"cannot read {path}: {exc}") from exc
    values: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ASSIGNMENT.fullmatch(stripped)
        if match is None:
            raise PublishError("dependency_unavailable", f"{path}:{number}: not a plain assignment")
        values[match.group(1)] = match.group(2)
    missing = sorted({"TLS_CERT", "TLS_KEY", "SERVER_NAME"} - values.keys())
    if missing:
        raise PublishError("dependency_unavailable", f"{path} does not set {', '.join(missing)}")
    cert, key = Path(values["TLS_CERT"]), Path(values["TLS_KEY"])
    if not cert.is_absolute() or not key.is_absolute():
        raise PublishError(
            "dependency_unavailable", f"{path}: TLS_CERT and TLS_KEY must be absolute"
        )
    return InterfaceConfig(cert=cert, key=key, server_name=values["SERVER_NAME"].lower())


def covers(names: tuple[str, ...], server_name: str) -> bool:
    """Whether a browser asking for `server_name` accepts a certificate with these SANs.

    A wildcard stands for exactly one leftmost label, as RFC 6125 has it: a
    certificate for `*.example.net` serves `mgr.example.net` but not `example.net`
    and not `a.mgr.example.net`.
    """

    wanted = server_name.lower()
    for name in (n.lower() for n in names):
        if name == wanted:
            return True
        if name.startswith("*.") and "." in wanted and wanted.split(".", 1)[1] == name[2:]:
            return True
    return False


def served_fingerprint(config: InterfaceConfig) -> str | None:
    """The leaf nginx is configured with now, or None when there is none to read."""

    try:
        return leaf_fingerprint(config.cert.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, CertificateError):
        return None


def install(
    material: Material,
    *,
    config_path: Path = UI_TLS_CONFIG,
    command: Path = UI_TLS_COMMAND,
    run: Runner = subprocess.run,
) -> bool:
    """Make nginx serve this certificate. True when it was installed, False when it already was.

    Refusals are `PublishError`, like every other reason the publisher did not
    publish, so the report reads the same whichever target a certificate has.
    """

    config = read_config(config_path)
    if not covers(material.facts.sans, config.server_name):
        raise PublishError(
            "name_mismatch",
            f"the certificate does not name {config.server_name}, the name the interface is "
            "served on; not installed",
        )
    if served_fingerprint(config) == material.fingerprint:
        return False

    #
    # The key is written only to a directory this process just made, mode 0700,
    # and removed with it. `haproxy-ui-tls` copies the pair into place itself;
    # the paths it is given are never the served ones.
    #
    with tempfile.TemporaryDirectory(prefix="haproxy-ui-tls-") as directory:
        cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
        cert.write_bytes(material.fullchain)
        descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(material.privkey)
        try:
            completed = run(
                [
                    str(command),
                    "--config",
                    str(config_path),
                    "install",
                    "--cert",
                    str(cert),
                    "--key",
                    str(key),
                ],
                capture_output=True,
                text=True,
                timeout=INSTALL_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PublishError("install_failed", f"haproxy-ui-tls could not run: {exc}") from exc
    if completed.returncode != 0:
        #
        # The command's own last word, which is its reason: it prints
        # `ERROR: ...` and has already put the previous pair back.
        #
        said = [line for line in (completed.stderr or "").splitlines() if line.strip()]
        reason = said[-1] if said else f"exit {completed.returncode}"
        raise PublishError("install_failed", f"haproxy-ui-tls refused the certificate: {reason}")
    return True
