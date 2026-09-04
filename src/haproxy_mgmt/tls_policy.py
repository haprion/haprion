"""What each named TLS policy means, and where the cipher lists came from.

One place, because there were two. The generator held these lists and each
cluster's `core/haproxy.cfg` held its own copy of the same Mozilla
recommendation; measured 2026-09-04, they had drifted by one cipher
(`DHE-RSA-CHACHA20-POLY1305`, present here and missing there). Two readers of
one list that look correct on their own is the hardest kind of difference to
find, so the list lives here and everything that needs it asks.

Why the strings are whole
-------------------------
A cipher list is an *ordered* preference: OpenSSL walks it and takes the first
the client also offers. Code that assembled one out of shared pieces would make
that order an accident of how the pieces were joined, so each policy is written
out in full even where two of them overlap.

Why there is no free-text field anywhere above this
---------------------------------------------------
These are raw OpenSSL syntax, and the project has decided not to have a field
somebody pastes raw syntax into - see the plan's scope section. The interface
chooses a name; this module is where a name becomes syntax.
"""

from __future__ import annotations

import re
from datetime import date

#
# Where these came from, so the next reader does not have to guess how old they
# are. Verified against the published guideline rather than copied from memory:
# the intermediate list below is v5.7's, cipher for cipher and in its order.
#
# `REVIEWED` is the date somebody last *looked*, which is not the same as the
# date the list last changed - Mozilla's intermediate list moves rarely, and a
# review that confirms it is unchanged is still a review. Move the date when you
# look, whether or not you edit anything below it.
#
# Deliberately not fetched at build or run time. A generator that must reach the
# network to emit a configuration cannot run where configuration is generated,
# and an external source that can quietly change a published configuration has
# the wrong shape for this.
#
MOZILLA_GUIDELINE = "5.7"
MOZILLA_GUIDELINE_URL = "https://ssl-config.mozilla.org/guidelines/5.7.json"
REVIEWED = date(2026, 9, 4)

#
# How long a review stays good before the suite asks for another. Long, because
# these lists change on the order of years and a check that cries every quarter
# is one somebody learns to silence. `test_tls_policy` fails when it expires.
#
REVIEW_INTERVAL_DAYS = 548

#
# Mozilla "intermediate": what a general-purpose listener should offer. TLS 1.2
# and 1.3, and the 1.2 suites are all AEAD - there is no CBC and no SHA-1 here,
# which is also why this list cannot reach below TLS 1.2. AES-GCM requires 1.2.
#
TLS_1_2_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"
)

#
# TLS 1.3 names its suites separately from the 1.2 ciphers, and HAProxy takes
# them on their own keyword. The same three in both Mozilla configurations.
#
TLS_1_3_CIPHERSUITES = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

#
# What each policy a VIP may name means on a bind line. The names are
# `config.TLS_POLICY_NAMES`.
#
# Both were put through `haproxy -c` on 3.4.4, and `modern` was run: a client
# held to TLS 1.2 got no handshake at all, and a TLS 1.3 client was served.
#
TLS_POLICIES = {
    "intermediate": (
        f" ssl-min-ver TLSv1.2 ciphers {TLS_1_2_CIPHERS} ciphersuites {TLS_1_3_CIPHERSUITES}"
    ),
    "modern": f" ssl-min-ver TLSv1.3 ciphersuites {TLS_1_3_CIPHERSUITES}",
}


#
# The two `global` keywords a cluster's own `core/haproxy.cfg` uses to say the
# same thing this module says. The floor - `ssl-default-bind-options
# ssl-min-ver` - is deliberately not checked here: which versions a listener
# accepts is about to become a choice per VIP and per object, and a check that
# pinned one answer would have to be unpicked to build that.
#
_CORE_KEYWORDS = ("ssl-default-bind-ciphers", "ssl-default-bind-ciphersuites")


def _stated(core_cfg: str, keyword: str) -> str | None:
    """What `core/` sets this keyword to, or None if it does not set it."""

    found = re.search(rf"^[ \t]*{keyword}[ \t]+(\S+)[ \t]*$", core_cfg, re.MULTILINE)
    return found.group(1) if found is not None else None


def core_defaults_problem(core_cfg: bytes, *, cluster: str, config_path: str) -> str | None:
    """Why this cluster's `core/haproxy.cfg` disagrees with these lists, if it does.

    A cluster's own configuration repository carries the same Mozilla
    recommendation on `ssl-default-bind-*`, because those are `global` keywords
    and this project does not own that file - the configuration repositories are
    separate systems on purpose. What this module can do is refuse to publish a
    release built from lists that no longer agree with it.

    Why it is worth refusing rather than warning: a generated bind line that
    names a policy carries the list from here, and everything that names none
    inherits the list from there. When the two disagree, what protects a given
    listener depends on which line HAProxy read last - and both files look
    entirely correct on their own, which is what let them drift by one cipher
    for as long as they did.

    The message is the whole point of the check. Somebody meets it during a
    publish, on a cluster whose configuration they may not have written, and it
    has to be enough on its own.
    """

    text = core_cfg.decode("utf-8", errors="replace")
    expected = {
        "ssl-default-bind-ciphers": TLS_1_2_CIPHERS,
        "ssl-default-bind-ciphersuites": TLS_1_3_CIPHERSUITES,
    }

    for keyword in _CORE_KEYWORDS:
        stated = _stated(text, keyword)
        wanted = expected[keyword]
        if stated == wanted:
            continue

        if stated is None:
            what = f"core/haproxy.cfg does not set {keyword} at all"
        else:
            have = stated.split(":")
            want = wanted.split(":")
            missing = [name for name in want if name not in have]
            extra = [name for name in have if name not in want]
            differences = []
            if missing:
                differences.append(f"missing {', '.join(missing)}")
            if extra:
                differences.append(f"carrying {', '.join(extra)}, which is not on the list")
            if not differences:
                differences.append("in a different order, and the order is a preference")
            what = f"core/haproxy.cfg's {keyword} is {' and '.join(differences)}"

        return (
            f"{cluster}: {what}.\n"
            f"\n"
            f"  Fix it, then publish again:\n"
            f"    sudoedit {config_path}/core/haproxy.cfg\n"
            f"    set {keyword} to exactly this, in this order:\n"
            f"      {wanted}\n"
            f"\n"
            f"  Why this stops a publish: a generated bind line that names a TLS policy\n"
            f"  carries the list from haproxy_mgmt/tls_policy.py, and every listener that\n"
            f"  names no policy inherits the list from core/. While the two disagree, what\n"
            f"  protects a listener depends on which line HAProxy read last - and both\n"
            f"  files look correct on their own.\n"
            f"\n"
            f"  The list is Mozilla's guideline v{MOZILLA_GUIDELINE} ({MOZILLA_GUIDELINE_URL}),\n"
            f"  last checked {REVIEWED}. A deliberate change belongs in tls_policy.py first,\n"
            f"  and in every cluster's core/ after it.\n"
            f"\n"
            f"  A revert is never stopped by this: going back to a release that was good\n"
            f"  before must not depend on a file being current."
        )

    return None


def core_defaults_lines(indent: str = "    ") -> str:
    """The `global` lines a cluster's `core/haproxy.cfg` is expected to carry.

    Rendered from the same constants the check compares against, so the
    installation guide, a test fixture and the refusal cannot come to show three
    slightly different lists. The floor line is included because a person
    setting up a cluster needs the whole block, not the part this file polices.
    """

    return (
        f"{indent}ssl-default-bind-ciphers {TLS_1_2_CIPHERS}\n"
        f"{indent}ssl-default-bind-ciphersuites {TLS_1_3_CIPHERSUITES}\n"
        f"{indent}ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets\n"
    )
