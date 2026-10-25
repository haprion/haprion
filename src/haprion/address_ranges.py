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


def has_host_bits(entry: str) -> bool:
    """Whether `entry` is a range whose host bits are not zero, as `192.0.2.1/24` is."""

    try:
        ipaddress.ip_network(entry, strict=True)
    except ValueError:
        pass
    else:
        return False
    try:
        ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    return True


def refused(entry: str) -> bool:
    """Whether `entry` is refused where it is read: a range with host bits, being written."""

    return _WRITING.get() and has_host_bits(entry)
