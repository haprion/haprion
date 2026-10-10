"""What a health check actually does, decided once.

A check is spelled across two objects and four fields - the pool's TLS, the
check's own TLS, its port, its type - and none of them means anything alone.
Whether the check speaks TLS is the clearest case: nothing said follows the
pool, a check port breaks that inheritance, and saying it plainly on a TLS pool
is a third answer again. Every one of those was measured on 3.4.4 rather than
reasoned about, and they are recorded in `generate._check_encryption`.

The reason this module exists is that two readers were answering that question
from two different inputs. The generator read the model and wrote HAProxy's
words; the interface's probe read the form's fields and built a request from
them. Two derivations of one question drift, and this pair had already drifted
once: B92 found the probe reading the wrong field in four places, so ticking
the check's own TLS box changed the configuration and changed nothing about
what was probed. It was fixed there by teaching the second reader the same
rules - which leaves two copies of the rules.

So the rules live here, and both readers ask. The generator keeps writing the
words, because how a decision is spelled in a configuration file is its own
business; what it no longer keeps is a private opinion about what the decision
is.

**This is the check, not the traffic.** They differ deliberately: a check may
speak TLS to a plain pool, or plaintext to a TLS one, and it never verifies a
certificate - HAProxy's check sends no SNI, so there is no name to check one
against. `verify` here describes the connection the pool is reached over, and
is reported so a probe can hold itself to the same terms rather than being
stricter or laxer than the thing it stands in for.
"""

from __future__ import annotations

from dataclasses import dataclass

from haprion.proxy_model import Backend, Health, Proxy, Server
from haprion.tls_policy import BACKEND_MIN_VERSION, DEFAULT_MIN_VERSION

DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class EffectiveCheck:
    """One server's health check, as it will actually be run.

    Everything a reader needs to reproduce the check, and nothing about how it
    is written: no HAProxy keywords, no form field names. Both are spellings of
    this.
    """

    host: str
    port: int
    type: str
    """`http`, `tcp`, `dns` or `disabled` - the check's kind, not the pool's protocol."""

    encrypted: bool
    """Whether the check opens a TLS connection, whatever the pool does."""

    verify: bool
    """Whether the pool's certificate has to be trusted on the traffic path.

    A property of the connection rather than of the check: HAProxy's check
    judges no certificate, because verifying one means checking a name and the
    check sends none. Carried so that anything standing in for the check can
    hold itself to the same terms.
    """

    min_version: str
    """The oldest handshake the pool may be reached over, in HAProxy's words."""

    path: str | None = None
    host_header: str | None = None
    expect_status: str | None = None
    #
    # The conditions that need more than a connection and a status line. Named
    # rather than left out, because whoever stands in for the check has to be
    # able to say which parts of it they did not run.
    #
    expect_body: str | None = None
    send: str | None = None
    expect: str | None = None
    #
    # A dns check's question (B253): dnsdist asks it of every server, and
    # whatever stands in for the check asks the same.
    #
    query_name: str | None = None
    query_type: str | None = None

    @property
    def runs(self) -> bool:
        return self.type != DISABLED


def check_speaks_tls(backend: Backend, health: Health) -> bool:
    """Whether the check's connection is encrypted.

    Three answers from two fields, and the middle one is the one people get
    wrong. Nothing said follows the pool - HAProxy checks a TLS pool over TLS
    and a plain one in plain. `true` is a check that speaks TLS whatever the
    pool does, which a plain pool with a TLS health endpoint needs. `false` is
    one that does not, which a TLS pool with a plaintext management port needs
    and could not say at all before B92.

    A check port does not change the answer, only how it is written: the
    inheritance stops at a different port, so the generator says `check-ssl`
    there rather than relying on it. That is spelling, and it stays in the
    generator.
    """

    if health.tls is not None:
        return health.tls
    return backend.tls is not None


def effective_check(backend: Backend, server: Server) -> EffectiveCheck:
    """What the check against one server does."""

    health = backend.health
    return EffectiveCheck(
        host=server.host,
        #
        # The check's own port replaces the traffic port where one is set,
        # which is what HAProxy does with `check port`.
        #
        port=health.port if health.port is not None else server.port,
        type=health.type,
        encrypted=check_speaks_tls(backend, health),
        verify=backend.tls is not None and backend.tls.verify != "none",
        min_version=(
            BACKEND_MIN_VERSION[backend.tls.policy]
            if backend.tls is not None
            else DEFAULT_MIN_VERSION
        ),
        path=health.path,
        host_header=health.host,
        expect_status=health.expect_status,
        expect_body=health.expect_body,
        send=health.send,
        expect=health.expect,
        query_name=health.query_name,
        query_type=health.query_type,
    )


def effective_checks(proxy: Proxy) -> tuple[EffectiveCheck, ...]:
    """Every check this object runs, in the order its pools are written.

    A disabled check is left out rather than returned as a row that does
    nothing: the caller's question is what will be run, and an object that
    checks nothing has an empty answer rather than a list of silences.

    Pools in the order the generator writes them, servers in the order they
    were written, so a reader comparing this against a configuration file is
    reading the same list twice rather than matching two orderings by eye.
    """

    return tuple(
        effective_check(backend, server)
        for name in sorted(proxy.backends)
        for backend in [proxy.backends[name]]
        if backend.health.type != DISABLED
        for server in backend.servers
    )
