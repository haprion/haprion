"""One rule for an address range with host bits set, in every list that takes ranges.

`192.0.2.1/24` is a typo for either the host or the network. Some lists took
the network without a word - 255 addresses more than whoever wrote one of them
meant - and others refused it, each in words of its own (review 26-10-24,
15-06). Now every way to write a list refuses it, in the words below:
the forms, `apply`, and the helpers that publish what those send.

A document already stored is read as it was written, though. An object or a
network group saved with host bits before this rule keeps loading - as the
network it always stood for - so nothing that publishes today stops; only
writing it again asks for the change. Writing is a context the write paths
enter (`writing()`); a read anywhere else is left as it was.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

HOST_BITS = (
    "a range's host bits must be zero: write the network, such as 192.0.2.0/24, "
    "or one address, such as 192.0.2.1"
)

_WRITING: ContextVar[bool] = ContextVar("haprion_address_ranges_writing", default=False)


@contextmanager
def writing() -> Iterator[None]:
    """Hold the ranges read inside to what may be written: no host bits."""

    token = _WRITING.set(True)
    try:
        yield
    finally:
        _WRITING.reset(token)


#
# Python's `ipaddress` takes an IPv6 address with a zone ID after `%`, and the
# zone may hold nearly anything: a space, `#`, a line break (measured on 3.13:
# `ip_address("fe80::1%eth0\nglobal")` is an address). Written into a
# configuration file, such a value is more lines. Nothing here has a use for a
# zone, so an address is read through these two and nothing else is one.
#
_PLAIN = re.compile(r"[0-9A-Fa-f:./]+")


def _plain_text(value: str) -> str:
    if not isinstance(value, str) or not _PLAIN.fullmatch(value):
        raise ValueError(
            f"{value!r} is not a plain address: digits, letters a-f, ':', '.' and '/' only"
        )
    return value


def plain_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """`ipaddress.ip_address`, refusing anything but the bare address: no zone ID, no spaces."""

    return ipaddress.ip_address(_plain_text(value))


def plain_network(
    value: str, *, strict: bool = True
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """`ipaddress.ip_network`, refusing anything but the bare address or range."""

    return ipaddress.ip_network(_plain_text(value), strict=strict)


def has_host_bits(entry: str) -> bool:
    """Whether `entry` is a range whose host bits are not zero, as `192.0.2.1/24` is."""

    try:
        plain_network(entry, strict=True)
    except ValueError:
        pass
    else:
        return False
    try:
        plain_network(entry, strict=False)
    except ValueError:
        return False
    return True


#
# IPv4 written as IPv6 (`::ffff:192.0.2.0/120`). The web knows a client by its
# IPv4 form since 2026-10-31, so a list entry in this form would never match;
# the lists say how to write it instead.
#
_MAPPED = ipaddress.IPv6Network("::ffff:0:0/96")


def mapped_ipv4(entry: str) -> str | None:
    """The IPv4 form of an IPv4-mapped address or network, or None for anything else."""

    try:
        network = plain_network(entry, strict=False)
    except ValueError:
        return None
    if not isinstance(network, ipaddress.IPv6Network) or not network.subnet_of(_MAPPED):
        return None
    first = network.network_address.ipv4_mapped
    if first is None:
        return None
    if network.prefixlen == 128:
        return str(first)
    return str(ipaddress.IPv4Network(f"{first}/{network.prefixlen - 96}", strict=False))


def refused(entry: str) -> bool:
    """Whether `entry` is refused where it is read: a range with host bits, being written."""

    return _WRITING.get() and has_host_bits(entry)
