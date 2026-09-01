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

import collections
import email.parser


def parse_headers(pairs):
    """The present mapping -- the same shape mapping() builds from a headers
    tuple -- from (name, value) pairs off the wire.

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
    # reason to know that mapping() already does it for the other path.
    present = _normalize(present)
    filtered = {}
    for name in wanted:
        values = present.get(name.lower())
        if values:
            filtered[name] = _single_or_list(values)
    return filtered


_REQUEST_FIELDS = "url method version headers body raw fidelity"
_RESPONSE_FIELDS = "status reason version headers body raw fidelity"


class Request(collections.namedtuple("Request", _REQUEST_FIELDS, defaults=(None, None, (), None, None, None))):
    """One HTTP request as this package models it.

    `url` is required and is the one fact the wire cannot supply: an
    origin-form request line plus a Host header says nothing about the scheme,
    and the scheme is what decides HSTS suppression. Everything else is
    optional, because a redacted or truncated capture may genuinely lack it.

    `headers` is a tuple of (name, value) pairs in the order received, never a
    mapping: a mapping keeps one value per name, and repeated headers are not a
    corner case. Use mapping() for the derived view the analysers consume.
    """

    __slots__ = ()

    @classmethod
    def from_parts(cls, url, method=None, version=None, headers=(), body=None, raw=None, fidelity=None):
        """A request from already-parsed pieces, as an adaptor supplies them."""
        return cls(url, method, version, tuple(tuple(p) for p in headers), body, raw, fidelity)

    @classmethod
    def from_bytes(cls, data, url, fidelity=None):
        """A request parsed from the bytes of one message, plus its URL.

        The URL is not optional and is not in the bytes: an origin-form request
        line carries a path, Host carries an authority, and neither says http
        or https.
        """
        data = _as_bytes(data)
        head, body = _split_head(data)
        start, pairs = _parse_head(head.decode("latin-1"))
        method = version = None
        if start is not None and start[0] == "request":
            _, method, _target, version = start
        return cls(url, method, version, pairs, body, data, fidelity)


class Response(collections.namedtuple("Response", _RESPONSE_FIELDS, defaults=(None, None, None, (), None, None, None))):
    """One HTTP response as this package models it.

    `reason` is None for an HTTP/2 exchange rather than empty: RFC 9113 carries
    only :status, so a reason phrase in an h2 capture was invented by whatever
    rendered it.
    """

    __slots__ = ()

    @classmethod
    def from_parts(cls, status=None, reason=None, version=None, headers=(), body=None, raw=None, fidelity=None):
        """A response from already-parsed pieces, as an adaptor supplies them."""
        return cls(status, reason, version, tuple(tuple(p) for p in headers), body, raw, fidelity)

    @classmethod
    def from_bytes(cls, data, fidelity=None):
        """A response parsed from the bytes of one message.

        The primary constructor. It is what makes a byte-oriented source
        supportable at all -- scapy's structured model returns the LAST of two
        repeated headers, so its adaptor must ignore the model and come
        through here.
        """
        data = _as_bytes(data)
        head, body = _split_head(data)
        start, pairs = _parse_head(head.decode("latin-1"))
        status = reason = version = None
        if start is not None and start[0] == "response":
            _, version, status, reason = start
        return cls(status, reason, version, pairs, body, data, fidelity)


def mapping(headers):
    """The lowercased `name -> [values]` view the analysers work from.

    Derived on demand rather than stored, so the pairs stay the single source
    of truth for order, duplication and reproduction of the head.
    """
    present = {}
    for name, value in headers:
        present.setdefault(name.strip().lower(), []).append(value)
    return present


def _as_bytes(data):
    """Bytes from bytes or text; text is latin-1, which is what headers are."""
    if isinstance(data, str):
        return data.encode("latin-1", "replace")
    return bytes(data)


def _split_head(data):
    """(head, body) at the first blank line, tolerating CRLF and bare LF.

    body is None when there is no blank line at all -- a truncated capture is
    a head with nothing after it, not a head with an empty body.
    """
    for separator in (b"\r\n\r\n", b"\n\n"):
        head, found, body = data.partition(separator)
        if found:
            return head, (body if body else None)
    return data, None


def parse_start_line(line):
    """Discriminate and split an HTTP start line, or None if it is neither.

    Returns ("response", version, status, reason) or
    ("request", method, target, version). Both forms are three
    space-separated fields, and which of them holds the version is what tells
    the two apart -- so `HTTP/2 202 Accepted` is a response and
    `POST /x HTTP/2` is a request, which is exactly how every capture tool
    renders an h2 exchange despite h2 having no start line at all.
    """
    fields = line.strip().split(" ", 2)
    if not fields[0]:
        return None
    if fields[0].upper().startswith("HTTP/"):
        if len(fields) < 2:
            return None
        try:
            status = int(fields[1].strip())
        except ValueError:
            # str.isdigit() would admit '\xb2' etc. (Latin-1 superscript
            # digits) that int() then rejects -- catch rather than guard, so
            # a further Unicode surprise cannot reopen this.
            return None
        reason = fields[2].strip() if len(fields) > 2 and fields[2].strip() else None
        return ("response", fields[0], status, reason)
    if len(fields) == 3 and fields[2].upper().startswith("HTTP/"):
        return ("request", fields[0], fields[1], fields[2].strip())
    return None


def _parse_head(head):
    """(start_line_fields_or_None, header_pairs) from a decoded head block.

    Nothing here raises. This parses what a server actually sent, and a strict
    parser would refuse exactly the response most worth analysing.
    """
    lines = head.replace("\r\n", "\n").split("\n")
    start, offset = None, 0
    if lines:
        start = parse_start_line(lines[0])
        if start is not None:
            offset = 1
        elif ":" not in lines[0]:
            # An unparseable first line that is not a header either: skip it
            # rather than treating its text as a header name.
            offset = 1
    pairs = []
    for line in lines[offset:]:
        if not line.strip():
            continue
        if line[:1] in (" ", "\t") and pairs:
            # obs-fold: deprecated by RFC 9110 but still on the wire.
            name, value = pairs[-1]
            pairs[-1] = (name, value + " " + line.strip())
            continue
        name, found, value = line.partition(":")
        if not found or not name.strip():
            continue
        pairs.append((name.strip(), value.strip()))
    return start, tuple(pairs)
