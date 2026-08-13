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

"""The header mapping every analysis works from.

A response may repeat a header, and the RFCs define what that means only for
some of them, so the mapping keeps every value. Nothing here knows what any
header means: this is the shape, not the analysis, and a request carries headers
the same way a response does.
"""

import email.parser


def parse_headers(pairs):
    """The mapping analyze_all wants, from (name, value) pairs off the wire.

    Build it with this rather than by hand. A dict comprehension over the same
    pairs -- the obvious thing to write -- keeps only the last value of a
    repeated header, and repeated headers are not a corner case: a browser
    enforces every Content-Security-Policy a response carries, so dropping one
    inverts the verdict on the rest.

    `http.client`'s getheaders() returns exactly the pairs this expects.
    """
    present = {}
    for name, value in pairs:
        present.setdefault(name.strip().lower(), []).append(value)
    return present


def parse_raw_headers(raw):
    """The same mapping, from a raw header block as captured off the wire.

    Accepts bytes or text, with or without a leading status or request line.
    """
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("latin-1")
    block = raw.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    first, newline, rest = block.partition("\n")
    if newline and ":" not in first:
        block = rest  # a status or request line, not a header
    return parse_headers(email.parser.Parser().parsestr(block).items())


def _normalize(present):
    """`present` keyed by stripped, lowercased names, every value in a list.

    Header names are case-insensitive, so two spellings are one header. A value
    may be given as a string or as a list of them: a caller with one value per
    header -- the ordinary case -- passes the mapping it already has, and one
    holding a repeated header passes its values without having to choose.
    """
    normalized = {}
    for name, value in present.items():
        values = [value] if isinstance(value, str) else list(value)
        normalized.setdefault(name.strip().lower(), []).extend(values)
    return normalized


def _lookup(present, name):
    """The first value of `name`, or None when the response does not carry it.

    Every header this is asked about carries one value; where a response repeats
    one anyway, the first is what a browser's own single-value lookup returns.
    """
    values = present.get(name.lower())
    return values[0] if values else None


def _lookup_all(present, name):
    """Every value of `name`, in the order the response carried them."""
    return present.get(name.lower(), [])


def _sole_value(present, name):
    """The value of `name` when the response is unambiguous about it.

    None when the header is absent, and None when it was sent more than once
    with values that disagree: no specification says which of those a client
    honours, so the response cannot be relied on to mean either.
    """
    values = present.get(name.lower(), [])
    distinct = {value.strip() for value in values}
    return values[0] if len(distinct) == 1 else None


def _single_or_list(values):
    """One value as itself, several as a list.

    A header is normally sent once, and a caller should not have to unwrap a
    list to read it; a repeated one keeps every value, because that is what the
    response said and a browser acts on all of them.
    """
    return values[0] if len(values) == 1 else list(values)


def _filter_headers(present, wanted):
    # Normalised here too: these are public entry points, and a caller has no
    # reason to know that analyze_all happens to do it for the other path.
    present = _normalize(present)
    filtered = {}
    for name in wanted:
        values = present.get(name.lower())
        if values:
            filtered[name] = _single_or_list(values)
    return filtered
