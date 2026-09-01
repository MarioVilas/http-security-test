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

"""Converters from live HTTP library objects into this package's types.

A convenience, never a requirement: a caller who wants to control loading,
streaming or truncation builds Request and Response directly. These exist for
the case where our decisions are acceptable.

Nothing here imports the library it adapts. Every adaptor is attribute reads,
so the package keeps its zero dependencies and the tests need nothing
installed. There is deliberately no introspection dispatch either: requests and
httpx both spell it `.headers`, both are dict-like, and one of them destroys
duplicates -- so a converter that guessed from attribute names would pick the
destroying one and say nothing.

**No adaptor reads a body.** aiohttp's read() is a coroutine, so a synchronous
adaptor structurally cannot; and where it is possible it is harmful, since
touching requests' .content on a stream=True response materialises the whole
body with no error to notice. The body is always the caller's explicit act.
"""

from http_security_test.message import Request, Response

_CURL_VERSIONS = {
    0: None,
    1: "HTTP/1.0",
    2: "HTTP/1.1",
    3: "HTTP/2",
    4: "HTTP/2",
    5: "HTTP/2",
    30: "HTTP/3",
    31: "HTTP/3",
}


def curl_version(value):
    """libcurl's CURL_HTTP_VERSION_* constant as a wire token.

    V1_1 is 2 and V2_0 is 3, so the naive reading of `2` is off by one whole
    protocol version. pycurl and curl_cffi both report it this way.
    """
    return _CURL_VERSIONS.get(value)


def http_version(value):
    """One of the five encodings we found, as the wire token.

    'HTTP/1.1' passes through; 11 and 10 are the stdlib/urllib3 integers;
    aiohttp hands over a namedtuple with .major and .minor; None stays None.
    NOT libcurl's -- that one is ambiguous with the integers and has its own
    function.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value if value.upper().startswith("HTTP/") else None
    if isinstance(value, int):
        return {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(value)
    major = getattr(value, "major", None)
    minor = getattr(value, "minor", None)
    if major is None:
        return None
    return "HTTP/%d.%d" % (major, minor or 0)


_NIQUESTS_VERSIONS = {9: "HTTP/0.9", 10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2", 30: "HTTP/3"}


def _niquests_version(value):
    """niquests' own `raw.version` scheme -- 9/11/20/30, not the stdlib's.

    niquests (via urllib3.future) negotiates HTTP/2 and HTTP/3 itself, so its
    low-level response carries an integer that looks like the stdlib's 10/11
    but is not: 20 means HTTP/2 and 30 means HTTP/3. Routing it through
    http_version() would read either as unknown and silently drop it, the
    same trap curl_version() exists to own for libcurl's own numbers.
    """
    return _NIQUESTS_VERSIONS.get(value)


def _pairs(container):
    """Ordered (name, value) pairs from any header container that has them.

    Tried in the order that preserves duplicates. `items()` is last because it
    is the only one CaseInsensitiveDict has, and for that type it is already
    lossy -- callers that could hit one must reach past it first.

    `get_all` is tried LAST among the four, not first: tornado's HTTPHeaders
    also defines a `get_all`, but a zero-argument one returning every (name,
    value) pair at once, an entirely different shape from stdlib's
    `get_all(name)` that this same word means everywhere else. Calling it
    with a name raises TypeError instead of silently misbehaving, which is
    how a live check against real tornado caught this rather than a fake.
    `get_list` -- tornado's actual per-name accessor -- is tried first
    instead, and every other library checked (urllib3, werkzeug,
    geventhttpclient) exposes `get_all(name)` and one of the other three
    spellings side by side with identical behaviour, so trying them in a
    different order changes nothing for them.

    The explicit `.keys()` below is deliberate, not the redundant call a
    linter reads it as: werkzeug's Headers -- one of the containers this
    reaches -- defines `__iter__` to yield (name, value) pairs, not names, so
    `for name in container` is not the same loop it looks like everywhere
    else. Verified live rather than assumed, after the same shortcut broke it.
    """
    for accessor in ("getlist", "getall", "get_list", "get_all"):
        if hasattr(container, accessor) and hasattr(container, "keys"):
            names = []
            for name in container.keys():  # noqa: SIM118 -- see above
                if name.lower() not in [n.lower() for n in names]:
                    names.append(name)
            pairs = []
            for name in names:
                for value in getattr(container, accessor)(name):
                    pairs.append((name, value))
            return tuple(pairs)
    return tuple((k, v) for k, v in container.items())


def from_requests(response):
    """(Request, Response) from a requests.Response.

    Reads `.raw.headers`, NOT `.headers`. The latter is a CaseInsensitiveDict
    that has already comma-joined repeated headers with no accessor to recover
    them: two CSP policies become one string, which inverts the conjunctive
    rule, and two Set-Cookie values become unparseable because an Expires date
    contains a comma. Those five lines are the whole value of this function.
    """
    raw = response.raw
    reply = Response.from_parts(
        status=response.status_code,
        version=http_version(getattr(raw, "version", None)),
        headers=_pairs(raw.headers),
    )
    sent = response.request
    query = Request.from_parts(
        url=sent.url,
        method=sent.method,
        headers=_pairs(sent.headers),
    )
    return query, reply


def from_niquests(response):
    """(Request, Response) from a niquests.Response.

    niquests mirrors requests' API closely enough that the same fix applies
    to the same trap: `.raw.headers` recovers what `.headers` has already
    comma-joined. Version is the one place it diverges -- `.raw.version` is
    niquests' own 9/11/20/30 scheme, not the stdlib's, so it goes through
    _niquests_version() rather than http_version().
    """
    raw = response.raw
    reply = Response.from_parts(
        status=response.status_code,
        version=_niquests_version(getattr(raw, "version", None)),
        headers=_pairs(raw.headers),
    )
    sent = response.request
    query = Request.from_parts(
        url=sent.url,
        method=sent.method,
        headers=_pairs(sent.headers),
    )
    return query, reply


def from_httpx(response):
    """(Request, Response) from an httpx.Response.

    `.headers` is httpx.Headers, which recovers duplicates through
    get_list() -- unlike requests, nothing here is thrown away by the
    ordinary accessor. Reason is read from `.extensions`, NOT the
    `.reason_phrase` property: that property invents a phrase from the status
    code (`codes.get_reason_phrase()`) whenever the transport did not supply
    one, which is exactly the HTTP/2 case this package's Response.reason
    contract says must stay None rather than be invented.
    """
    reason = response.extensions.get("reason_phrase")
    if isinstance(reason, (bytes, bytearray)):
        reason = reason.decode("ascii", "ignore")
    reply = Response.from_parts(
        status=response.status_code,
        reason=reason or None,
        version=http_version(response.http_version),
        headers=_pairs(response.headers),
    )
    sent = response.request
    query = Request.from_parts(
        url=str(sent.url),
        method=sent.method,
        headers=_pairs(sent.headers),
    )
    return query, reply


def from_aiohttp(response):
    """(Request, Response) from an aiohttp.ClientResponse.

    Synchronous despite the library: status, headers, version and the
    recorded request are all available before the body arrives. `.read()` and
    `.text()` are coroutines and this never calls them. `.headers` is a
    CIMultiDictProxy, and `.getall()` is what recovers duplicates.
    """
    info = response.request_info
    reply = Response.from_parts(
        status=response.status,
        reason=response.reason or None,
        version=http_version(response.version),
        headers=_pairs(response.headers),
    )
    query = Request.from_parts(
        url=str(info.url),
        method=info.method,
        headers=_pairs(info.headers),
    )
    return query, reply


def from_urllib3(response):
    """Response from a urllib3.HTTPResponse.

    Low-level: nothing here retains what was sent, so only a Response comes
    back. `.headers` is an HTTPHeaderDict; `.get_all()` (tried first inside
    _pairs) is what recovers duplicates.
    """
    return Response.from_parts(
        status=response.status,
        reason=response.reason or None,
        version=http_version(response.version),
        headers=_pairs(response.headers),
    )


def from_http_client(response):
    """Response from an http.client.HTTPResponse, once begin() has run.

    `.headers` is the HTTPMessage begin() built -- the reference case this
    package's whole approach to duplicates is modeled on, via `.get_all()`.
    Nothing here retains what was sent, so only a Response comes back.
    """
    return Response.from_parts(
        status=response.status,
        reason=response.reason or None,
        version=http_version(response.version),
        headers=_pairs(response.headers),
    )


def from_tornado(response):
    """(Request, Response) from a tornado.httpclient.HTTPResponse.

    tornado's HTTPResponse carries no version field at all, so none is set --
    there is nothing for http_version() to normalise. `.headers` is an
    HTTPHeaders, whose `.get_all()` (tried first inside _pairs) recovers
    duplicates.
    """
    reply = Response.from_parts(
        status=response.code,
        reason=response.reason or None,
        headers=_pairs(response.headers),
    )
    sent = response.request
    query = Request.from_parts(
        url=sent.url,
        method=sent.method,
        headers=_pairs(sent.headers),
    )
    return query, reply


def from_curl_cffi(response):
    """(Request, Response) from a curl_cffi.requests.Response.

    `.http_version` is libcurl's own enum, not the stdlib's -- curl_version(),
    not http_version(), reads it. `.headers` has `.get_list()`, so unlike
    requests there is no lossy `.headers` to route around here.
    """
    reply = Response.from_parts(
        status=response.status_code,
        reason=response.reason or None,
        version=curl_version(response.http_version),
        headers=_pairs(response.headers),
    )
    sent = response.request
    query = Request.from_parts(
        url=sent.url,
        method=sent.method,
        headers=_pairs(sent.headers),
    )
    return query, reply


def from_pycurl_bytes(raw, version=None):
    """Response from pycurl's raw header block, plus an optional version.

    pycurl exposes no structured header object at all: the ordinary
    integration point is a HEADERFUNCTION accumulating every line pycurl
    hands it, status line included, into one buffer -- which already carries
    the wire version as text in the common case, so this reads like a byte
    capture rather than an attribute-read adaptor. `version` is an escape
    hatch for a caller holding only curl_easy_getinfo(CURLINFO_HTTP_VERSION):
    pass it through curl_version() first, never through http_version() -- it
    is libcurl's enum, the same trap curl_cffi's adaptor exists to own.
    """
    response = Response.from_bytes(raw, fidelity="capture")
    if response.version is None and version is not None:
        response = response._replace(version=version)
    return response


def from_geventhttpclient(response):
    """Response from a geventhttpclient HTTPResponse.

    `.headers` is not a mapping here at all -- it is `property(items)`, so
    every access already returns a fresh generator over every header line,
    duplicates included, and is used directly rather than through _pairs(),
    which would fail looking for `.items()` on a generator.
    `.get_http_version()` returns the wire token as text already.
    """
    return Response.from_parts(
        status=response.status_code,
        reason=getattr(response, "status_message", None) or None,
        version=http_version(response.get_http_version()),
        headers=tuple(response.headers),
    )


def from_mitmproxy(flow):
    """(Request, Response) from a mitmproxy HTTPFlow.

    Both sides' headers are mitmproxy's own Headers, whose `.get_all()`
    (tried first inside _pairs) recovers duplicates that `.items()` would
    already have comma-joined. `response` is None when the flow's response has
    not arrived yet -- a request can be inspected on its own.
    """
    sent = flow.request
    query = Request.from_parts(
        url=sent.url,
        method=sent.method,
        version=http_version(sent.http_version),
        headers=_pairs(sent.headers),
    )
    if flow.response is None:
        return query, None
    resp = flow.response
    reply = Response.from_parts(
        status=resp.status_code,
        reason=resp.reason or None,
        version=http_version(resp.http_version),
        headers=_pairs(resp.headers),
    )
    return query, reply


def from_scapy_bytes(raw):
    """Response from the raw bytes scapy round-trips byte-identically.

    scapy is the inverse of every other library here: its parse is exact but
    its named fields return only the LAST of two repeated headers, so the
    only correct adaptor ignores the model entirely and comes through
    Response.from_bytes(), which reads the wire form directly.
    """
    return Response.from_bytes(raw, fidelity="capture")


def from_scapy(pkt):
    """Response from a scapy HTTPResponse packet, bypassing its field model.

    `bytes(pkt)` is scapy's own build() and needs no import of scapy to call
    -- Packet defines __bytes__ -- and it round-trips byte-identically to the
    wire form, which from_scapy_bytes() already knows how to read correctly.
    """
    return from_scapy_bytes(bytes(pkt))


def from_werkzeug(headers):
    """(name, value) pairs from a werkzeug Headers object.

    Werkzeug is WSGI and the same Headers type serves both the request and
    the response side, so only the pairs belong here -- the caller supplies
    the rest through Request.from_parts or Response.from_parts. `.get_all()`
    is what recovers duplicates that `.items()` would comma-join.
    """
    return _pairs(headers)


def from_starlette(headers):
    """(name, value) pairs from a starlette Headers object.

    Same shape as from_werkzeug and for the same reason: starlette's Headers
    serves both directions, so only the pairs belong here. `.getlist()`
    recovers duplicates that `.items()` would already have comma-joined.
    """
    return _pairs(headers)
