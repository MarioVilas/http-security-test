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

import types

import pytest

from http_security_test import adaptors
from http_security_test.message import mapping

PAIRS = [
    ("Content-Security-Policy", "default-src 'self'"),
    ("Content-Security-Policy", "script-src 'none'"),
    ("Set-Cookie", "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT"),
]


class FakeHeaderDict:
    """urllib3's HTTPHeaderDict: get_all() is right, [name] comma-joins."""

    def __init__(self, pairs):
        self._pairs = list(pairs)

    def keys(self):
        # Real HTTPHeaderDict.keys() is already deduplicated, case-preserved,
        # first-appearance order -- without this, _pairs()'s accessor branch
        # is never reached and both tests below prove nothing about it.
        seen = []
        for name, _ in self._pairs:
            if name.lower() not in [s.lower() for s in seen]:
                seen.append(name)
        return seen

    def get_all(self, name):
        return [v for k, v in self._pairs if k.lower() == name.lower()]

    def items(self):
        return iter(self._pairs)

    def __getitem__(self, name):
        return ", ".join(self.get_all(name))


class FakeCaseInsensitiveDict(dict):
    """requests' CaseInsensitiveDict: duplicates already destroyed."""


class FakeTornadoHeaders:
    """tornado's HTTPHeaders, awkwardness included.

    get_all() takes NO name -- it returns every (name, value) pair at once,
    an entirely different shape from the get_all(name) every other library
    spells the same word as. Calling it with a name is exactly what broke
    against the real library; get_list(name) is tornado's real per-name
    accessor.
    """

    def __init__(self, pairs):
        self._pairs = list(pairs)

    def keys(self):
        seen = []
        for name, _ in self._pairs:
            if name.lower() not in [s.lower() for s in seen]:
                seen.append(name)
        return seen

    def get_all(self):
        return iter(self._pairs)

    def get_list(self, name):
        return [v for k, v in self._pairs if k.lower() == name.lower()]

    def items(self):
        return iter(self._pairs)


class FakeWerkzeugHeaders:
    """werkzeug's Headers, awkwardness included.

    keys() returns one name per pair, duplicates included -- not a deduped
    view -- and getlist(name) is the real per-name accessor. __iter__ yields
    (name, value) PAIRS, not names, unlike an ordinary mapping: "for name in
    container" binds a tuple to `name` here rather than a header name.
    """

    def __init__(self, pairs):
        self._pairs = list(pairs)

    def keys(self):
        return [name for name, _ in self._pairs]

    def getlist(self, name):
        return [v for k, v in self._pairs if k.lower() == name.lower()]

    def items(self):
        return iter(self._pairs)

    def __iter__(self):
        return iter(self._pairs)


class FakeHttpxHeaders:
    """httpx.Headers: get_list(name) recovers duplicates, tried third in
    _pairs()'s accessor order -- unlike requests' CaseInsensitiveDict,
    httpx's own ordinary accessor does not comma-join them away first, but
    the adaptor goes through get_list() regardless.
    """

    def __init__(self, pairs):
        self._pairs = list(pairs)

    def keys(self):
        seen = []
        for name, _ in self._pairs:
            if name.lower() not in [s.lower() for s in seen]:
                seen.append(name)
        return seen

    def get_list(self, name):
        return [v for k, v in self._pairs if k.lower() == name.lower()]

    def items(self):
        return iter(self._pairs)


@pytest.mark.parametrize(
    "value,expected",
    [
        (11, "HTTP/1.1"),
        (10, "HTTP/1.0"),
        ("HTTP/1.1", "HTTP/1.1"),
        ("HTTP/2", "HTTP/2"),
        (types.SimpleNamespace(major=1, minor=1), "HTTP/1.1"),
        (None, None),
    ],
)
def test_http_version_normalises_every_encoding_we_found(value, expected):
    assert adaptors.http_version(value) == expected


def test_libcurls_integer_2_means_http_1_1_not_http_2():
    # CurlHttpVersion.V1_1 == 2, V2_0 == 3, V3 == 30. Reading `2` as HTTP/2 is
    # the trap this adaptor exists to own, and it is libcurl's rather than
    # curl_cffi's -- pycurl reports it identically.
    assert adaptors.curl_version(2) == "HTTP/1.1"
    assert adaptors.curl_version(3) == "HTTP/2"
    assert adaptors.curl_version(30) == "HTTP/3"


def test_niquests_version_uses_its_own_9_11_20_30_scheme_not_the_stdlibs():
    # niquests negotiates HTTP/2 and HTTP/3 itself via urllib3.future, so its
    # raw.version carries 9/11/20/30 -- NOT the stdlib's 10/11. Routing 20 or
    # 30 through http_version() instead would find neither key and silently
    # normalise a negotiated HTTP/2 or HTTP/3 connection to None, the exact
    # trap curl_version() exists to own for libcurl's own integers.
    assert adaptors._niquests_version(9) == "HTTP/0.9"
    assert adaptors._niquests_version(10) == "HTTP/1.0"
    assert adaptors._niquests_version(11) == "HTTP/1.1"
    assert adaptors._niquests_version(20) == "HTTP/2"
    assert adaptors._niquests_version(30) == "HTTP/3"
    assert adaptors._niquests_version(99) is None


def test_from_requests_reads_raw_headers_not_headers():
    # .headers is a CaseInsensitiveDict and has already comma-joined the two
    # CSP policies with no accessor to recover them. Reading it would invert
    # the conjunctive-enforcement rule and make Set-Cookie unparseable.
    fake = types.SimpleNamespace(
        status_code=200,
        headers=FakeCaseInsensitiveDict({"Content-Security-Policy": "a, b"}),
        raw=types.SimpleNamespace(version=11, headers=FakeHeaderDict(PAIRS)),
        request=types.SimpleNamespace(
            method="GET",
            url="https://example.com/",
            headers=FakeCaseInsensitiveDict({"Accept": "*/*"}),
        ),
    )
    request, response = adaptors.from_requests(fake)
    assert mapping(response.headers)["content-security-policy"] == [
        "default-src 'self'",
        "script-src 'none'",
    ]
    assert response.version == "HTTP/1.1"
    assert request.url == "https://example.com/"


def test_an_adaptor_never_touches_the_body():
    # aiohttp's .read() is a coroutine, so a sync adaptor structurally cannot
    # read a body; and reading requests' .content on a stream=True response
    # materialises the whole thing silently. So no adaptor reads one, and the
    # caller passes it explicitly if they want it.
    touched = []

    class Trap:
        status_code = 200
        raw = types.SimpleNamespace(version=11, headers=FakeHeaderDict(PAIRS))
        request = types.SimpleNamespace(method="GET", url="https://x/", headers={})
        headers = FakeCaseInsensitiveDict()

        @property
        def content(self):
            touched.append(True)
            raise AssertionError("adaptor read the body")

    adaptors.from_requests(Trap())
    assert touched == []


def test_from_scapy_ignores_the_model_and_parses_the_bytes():
    # scapy is the inverse of every other library: byte-identical round trip,
    # but its named fields return the LAST of two repeated headers. The only
    # correct adaptor takes raw(pkt) and comes through from_bytes().
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Security-Policy: default-src 'self'\r\n"
        b"Content-Security-Policy: script-src 'none'\r\n\r\n"
    )
    response = adaptors.from_scapy_bytes(raw)
    assert mapping(response.headers)["content-security-policy"] == [
        "default-src 'self'",
        "script-src 'none'",
    ]
    assert response.fidelity == "capture"


def test_pairs_uses_get_list_not_tornados_incompatible_get_all():
    # Regression test for the tornado fix: with the accessor tuple in its
    # original ("get_all", "getlist", "getall", "get_list") order, get_all()
    # is tried first, found (tornado's HTTPHeaders has one), and called with
    # a name it does not accept -- TypeError, not a wrong answer. get_list()
    # must be the one _pairs() actually reaches.
    headers = FakeTornadoHeaders(PAIRS)
    pairs = adaptors._pairs(headers)
    values = [v for k, v in pairs if k.lower() == "content-security-policy"]
    assert values == ["default-src 'self'", "script-src 'none'"]


def test_pairs_reads_dot_keys_not_iter_for_werkzeug_shaped_headers():
    # Regression test for the SIM118 noqa: werkzeug's Headers.__iter__ yields
    # (name, value) pairs, so "for name in container" (ruff's suggested fix
    # for "for name in container.keys()") would bind a tuple to `name` and
    # break the case-insensitive dedup below it. .keys() must be read
    # explicitly.
    headers = FakeWerkzeugHeaders(PAIRS)
    pairs = adaptors._pairs(headers)
    values = [v for k, v in pairs if k.lower() == "content-security-policy"]
    assert values == ["default-src 'self'", "script-src 'none'"]


def test_there_is_no_httplib2_adaptor():
    # Its Response is a dict subclass; duplicates are comma-joined with no
    # accessor and no underlying object. The data is destroyed before we could
    # see it, so the absence is deliberate and this pins it.
    assert not hasattr(adaptors, "from_httplib2")


def test_from_httpx_never_invents_a_reason_phrase_for_http2():
    # httpx.Response.reason_phrase is a PROPERTY that invents a phrase from
    # the status code table (codes.get_reason_phrase()) whenever the
    # transport supplied none -- exactly the h2 case, since h2 has no reason
    # phrases at all and this package's Response.reason contract says it must
    # stay None rather than be invented. The adaptor must read
    # response.extensions.get("reason_phrase") and never touch the property,
    # so a fake that raises from the property proves the adaptor never reads
    # it.
    class NoInventingReasonPhrase:
        status_code = 200
        http_version = "HTTP/2"
        extensions = {}  # h2: the transport supplied no reason phrase at all
        headers = FakeHttpxHeaders(PAIRS)
        request = types.SimpleNamespace(url="https://example.com/", method="GET", headers=FakeHttpxHeaders([]))

        @property
        def reason_phrase(self):
            raise AssertionError("adaptor read the inventing .reason_phrase property")

    _, response = adaptors.from_httpx(NoInventingReasonPhrase())
    assert response.reason is None
    assert response.version == "HTTP/2"


def test_from_httpx_decodes_a_real_reason_phrase_from_extensions():
    # For HTTP/1.1 the transport DOES put a reason phrase in extensions, as
    # bytes -- the adaptor must decode it rather than pass bytes through as
    # Response.reason.
    fake = types.SimpleNamespace(
        status_code=404,
        http_version="HTTP/1.1",
        extensions={"reason_phrase": b"Not Found"},
        headers=FakeHttpxHeaders(PAIRS),
        request=types.SimpleNamespace(url="https://example.com/", method="GET", headers=FakeHttpxHeaders([])),
    )
    _, response = adaptors.from_httpx(fake)
    assert response.reason == "Not Found"
    assert mapping(response.headers)["content-security-policy"] == [
        "default-src 'self'",
        "script-src 'none'",
    ]


def test_from_geventhttpclient_bypasses_pairs_and_keeps_duplicates():
    # geventhttpclient's .headers is `property(items)`: every access returns
    # a FRESH GENERATOR of (name, value) tuples, duplicates included, with no
    # .items() method of its own for _pairs() to find -- routing it through
    # _pairs() would look for .items() on a generator and raise
    # AttributeError. The adaptor must consume it directly as
    # tuple(response.headers) instead.
    class FakeGeventHTTPResponse:
        status_code = 200
        status_message = "OK"

        def get_http_version(self):
            return "HTTP/1.1"

        @property
        def headers(self):
            return iter(PAIRS)  # a fresh generator on every access

    response = adaptors.from_geventhttpclient(FakeGeventHTTPResponse())
    assert mapping(response.headers)["content-security-policy"] == [
        "default-src 'self'",
        "script-src 'none'",
    ]
    assert mapping(response.headers)["set-cookie"] == ["a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT"]
    assert response.status == 200
    assert response.reason == "OK"
    assert response.version == "HTTP/1.1"
