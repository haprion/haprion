"""The words the interface and the tools use, one per thing (review 2026-10-22, 7-2 and 8-3).

A state had up to seven names, and a service four. The glossary (decided
26-10-23) is here and in the manual's table; `RETIRED` is what the gate in
`ui/tests/test_glossary.py` refuses on the pages. A count says its noun in its
number (`counted`); `tests/test_labels.py` refuses the bracketed plural. The
web interface imports these through `haprion_ui.labels`.
"""

from __future__ import annotations

#
# A cluster or node that does not run the published version, and a node whose
# packages are older than another's. Two facts, two words: the node row said
# *Behind* for both.
#
BEHIND = "Behind"
OLDER_PACKAGE = "Older package"
#
# The words the pages no longer use, each with the one that replaced it.
# *Object* stays the word of the command line and the YAML (`haprion-objects`).
#
RETIRED = {
    "Not on the latest version": BEHIND,
    "Version drift": BEHIND,
    "Behind target": BEHIND,
    "Nodes are not on the release": BEHIND,
    "Target release": "Published version",
    "saved version": "version",
    "Provider profile": "DNS profile",
    "DNS provider profile": "DNS profile",
    "DNS providers": "DNS profiles",
    "External certificates": "Certificates for other hosts",
    "New object": "New proxy",
    "Edit object": "Edit proxy",
    "Validate the object": "Validate the proxy",
    "Create your first site": "Create your first proxy",
}


def noun(count: int, word: str, plural: str = "") -> str:
    """`word` for one, its plural for any other count: `plural`, or `word` with an s."""

    return word if count == 1 else plural or word + "s"


def counted(count: int, word: str, plural: str = "") -> str:
    """The count and its noun: "1 node", "2 nodes", "0 nodes"."""

    return f"{count} {noun(count, word, plural)}"
