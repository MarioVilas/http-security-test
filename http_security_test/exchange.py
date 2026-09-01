#!/usr/bin/python3

# http-security-test - HTTP security header analysis
# Copyright (C) 2026  Mario Vilas
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""One HTTP exchange: a request, its response, and the facts neither carries.

A request does not record when it was sent, and `Date` is the server's clock on
the response side. The hostname, IP and port actually connected to are
deliberately apart from `Host:`, because `Host:` can be forged and a test that
forges it is a thing security tools do on purpose -- Burp and mitmproxy both
model the two separately for that reason.

That is why this type exists now even though every exchange-level *rule* is
still parked: the rules can wait, the data has nowhere else to live.
"""

import collections
import urllib.parse

# What a raw blob is, worst last. `capture` is the bytes as they crossed the
# wire; `reconstructed` is a reassembly from a parsed model, which includes
# EVERY HTTP/2 exchange, since h2 has no start line and whatever rendered it
# invented one; `redacted` is a reconstruction known to have lost content.
FIDELITY = ("capture", "reconstructed", "redacted")

Connection = collections.namedtuple("Connection", "host ip port scheme", defaults=(None, None, None, None))

Exchange = collections.namedtuple("Exchange", "request response timestamp connection", defaults=(None, None))


def scheme(url):
    """The lowercased scheme, or "" when the URL will not parse.

    This replaces the old `secure` argument. A scheme that is stated cannot be
    defaulted to the flattering value, which is what `secure=True` did.
    """
    try:
        return urllib.parse.urlsplit(url).scheme.lower()
    except ValueError:
        return ""


def host(url):
    """The lowercased hostname with any root-zone trailing dot removed."""
    try:
        name = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return ""
    return (name or "").lower().rstrip(".")


def url_was_mangled(url):
    """Whether urlsplit would silently drop characters from this URL.

    `urlsplit` strips ASCII CR, LF and TAB from anywhere in a URL -- the
    bpo-43882 hardening -- so `https://example.com/x\\r\\nSet-Cookie: evil=1`
    parses to a clean-looking path and `geturl()` does not round-trip. Correct
    for a client avoiding SSRF, wrong for a tool whose job is to notice the
    payload. Nothing decides on this yet; it is kept so it is not lost.
    """
    return any(c in url for c in "\r\n\t")
