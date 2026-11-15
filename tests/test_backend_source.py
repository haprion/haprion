"""Every backend a listener reaches out through leaves from the listener's source address.

A VIP's `source` is the address a firewall further in is written against: the
nodes' own addresses are deliberately never in such a rule. One backend that
the generator wrote without `source` left from the node's own address instead
- the HTTP-01 challenge's, 26-11-15, found in production when the cluster's
traffic to the manager was handed to a web filter. This holds the rule for
every backend in every golden case rather than for the one that broke it.
"""

from __future__ import annotations

import unittest

from haprion.golden import cases, network, produced


def sections(text: str) -> dict[str, list[str]]:
    """Each `frontend`/`backend` section's lines, by `kind name`."""

    found: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            words = line.split()
            if words[0] in ("frontend", "backend") and len(words) > 1:
                current = found.setdefault(f"{words[0]} {words[1]}", [])
            else:
                current = None
        elif current is not None and line.strip():
            current.append(line.strip())
    return found


def bound_address(line: str) -> str:
    address = line.split()[1].rsplit(":", 1)[0]
    return address.strip("[]")


def targets(lines: list[str]) -> set[str]:
    return {
        line.split()[1]
        for line in lines
        if line.split()[0] in ("use_backend", "default_backend") and len(line.split()) > 1
    }


class EveryBackendLeavesFromItsListenersSource(unittest.TestCase):
    def test_every_golden_case(self) -> None:
        checked: dict[str, int] = {}
        for case in cases():
            vips, _default = network(case)
            sources = {vip.address: vip.source for vip in vips.values()}
            found = sections("\n".join(produced(case).values()))
            for name, lines in found.items():
                if not name.startswith("frontend "):
                    continue
                bound = {bound_address(line) for line in lines if line.startswith("bind ")}
                wanted = {sources[address] for address in bound if sources.get(address)}
                if not wanted:
                    continue
                for target in sorted(targets(lines)):
                    backend = found.get(f"backend {target}", [])
                    if not any(line.startswith("server ") for line in backend):
                        continue  # an answer the frontend gives itself
                    checked[case.name] = checked.get(case.name, 0) + 1
                    with self.subTest(case=case.name, frontend=name, backend=target):
                        self.assertTrue(
                            any(line.startswith("source ") for line in backend),
                            f"{target} has no source; it would leave from the node's own address",
                        )
        # Not empty: the three cases whose VIPs name a source are all held to it
        # (measured 26-11-15), the challenge's among them.
        self.assertEqual(sorted(checked), ["acme-challenge", "syslog", "two-vips"])


if __name__ == "__main__":
    unittest.main()
