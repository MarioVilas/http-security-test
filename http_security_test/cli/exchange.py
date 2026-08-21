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

"""What an input source yields.

Every input format this tool will grow -- Burp XML, HAR, SAZ, WCAT -- is a
multi-exchange container carrying both request and response, so a source yields
an *iterable* of these, never a single one, and one live target yields an
iterable of one.

`secure` and `host` are not fields. They are derived from `url` per exchange,
which matters on a redirect chain: the plaintext leg is analysed with
secure=False so HSTS findings are correctly suppressed there, and the last leg
may have a different hostname and so a different preload lookup.
"""

import collections
import urllib.parse

Hop = collections.namedtuple(
    "Hop", "origin code destination followed refused", defaults=(True, None)
)

# `destination` rather than `target`, because Exchange.target already means the
# string the operator typed. On the wire a hop is {"from": ..., "to": ...},
# which reads better in JSON; `from` cannot be a field because it is a keyword.
Exchange = collections.namedtuple(
    "Exchange",
    "kind target url status reason headers hops raw_response raw_request",
    defaults=((), None, None),
)

Failure = collections.namedtuple("Failure", "target kind message")

# Observable failure kinds. Not "retryable": that is a prediction, and only the
# kind is a fact. A calling tool reads these and decides for itself.
FAILURE_KINDS = ("dns", "refused", "timeout", "reset", "tls", "protocol", "other")


def secure(url):
    """Whether this response arrived over TLS, which analyze_all cannot know."""
    # Guard against malformed URLs from HAR/Burp/SAZ/WCAT file sources, which may
    # contain invalid IPv6 authorities or other parse errors that would raise.
    try:
        return urllib.parse.urlsplit(url).scheme.lower() == "https"
    except ValueError:
        return False


def host(url):
    """The hostname, lowercased, with any root-zone trailing dot removed."""
    try:
        name = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return ""
    return (name or "").lower().rstrip(".")
