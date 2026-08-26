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

from http_security_test.message import Request, Response, mapping, parse_start_line

RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Security-Policy: default-src 'self'\r\n"
    b"Content-Security-Policy: script-src 'none'\r\n"
    b"Set-Cookie: a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT\r\n"
    b"\r\n"
    b"<html></html>"
)


def test_a_response_yields_status_reason_version_headers_and_body():
    r = Response.from_bytes(RESPONSE)
    assert (r.status, r.reason, r.version) == (200, "OK", "HTTP/1.1")
    assert mapping(r.headers)["content-security-policy"] == [
        "default-src 'self'", "script-src 'none'"
    ]
    assert r.body == b"<html></html>"
    assert r.raw == RESPONSE


def test_repeated_set_cookie_survives_the_comma_in_an_expires_date():
    # Comma-joining is the fourth wrong answer in CLAUDE.md's mapping table and
    # the nastiest, because the result still looks like a header value.
    r = Response.from_bytes(RESPONSE)
    assert mapping(r.headers)["set-cookie"] == [
        "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT"
    ]


def test_http_2_in_a_1_1_shaped_start_line_is_accepted():
    # Every capture tool writes this. Burp's own export is
    # `POST /x HTTP/2` with a Host header, and `HTTP/2 202 Accepted` with a
    # reason phrase h2 does not have. Rejecting it refuses the commonest input.
    r = Response.from_bytes(b"HTTP/2 202 Accepted\r\nDate: x\r\n\r\n")
    assert (r.version, r.status, r.reason) == ("HTTP/2", 202, "Accepted")
    q = Request.from_bytes(b"POST /x HTTP/2\r\nHost: a.example\r\n\r\n",
                           url="https://a.example/x")
    assert (q.method, q.version) == ("POST", "HTTP/2")


def test_bare_lf_is_accepted():
    r = Response.from_bytes(b"HTTP/1.1 200 OK\nX-A: 1\n\nbody")
    assert (r.status, r.body) == (200, b"body")


def test_a_response_with_no_reason_phrase_parses():
    # h11 serialises exactly this: "HTTP/1.1 200 \r\n".
    r = Response.from_bytes(b"HTTP/1.1 200 \r\nX-A: 1\r\n\r\n")
    assert (r.status, r.reason) == (200, None)


def test_garbage_never_raises_and_leaves_unknowns_none():
    r = Response.from_bytes(b"\x00\x01 not http at all")
    assert r.status is None and r.version is None
    assert r.raw == b"\x00\x01 not http at all"


def test_an_empty_message_never_raises():
    assert Response.from_bytes(b"").status is None


def test_a_latin1_header_value_survives():
    r = Response.from_bytes(b"HTTP/1.1 200 OK\r\nServer: caf\xe9-server\r\n\r\n")
    assert mapping(r.headers)["server"] == ["caf\xe9-server"]


def test_a_header_with_no_colon_is_skipped_not_fatal():
    r = Response.from_bytes(b"HTTP/1.1 200 OK\r\ngarbage line\r\nX-A: 1\r\n\r\n")
    assert mapping(r.headers) == {"x-a": ["1"]}


def test_no_body_gives_none_not_empty_bytes():
    # Absent beats empty: a message with no body and one with a zero-length
    # body are different facts.
    assert Response.from_bytes(b"HTTP/1.1 204 No Content\r\nX-A: 1\r\n\r\n").body is None


def test_text_input_is_accepted_and_encoded_latin_1():
    r = Response.from_bytes("HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\n")
    assert r.status == 200 and isinstance(r.raw, bytes)


def test_parse_start_line_discriminates_and_returns_none_on_nonsense():
    assert parse_start_line("HTTP/1.1 200 OK")[0] == "response"
    assert parse_start_line("GET / HTTP/1.1")[0] == "request"
    assert parse_start_line("nonsense") is None


def test_a_superscript_digit_in_the_status_field_does_not_raise():
    # str.isdigit() is True for '\xb2' but int() rejects it, and _parse_head
    # decodes latin-1, so one byte off the wire reached a ValueError. The
    # parser's whole contract is that it never raises on what a server sent.
    r = Response.from_bytes(b"HTTP/1.1 \xb2 OK\r\nX-A: 1\r\n\r\n")
    assert r.status is None
    assert mapping(r.headers) == {"x-a": ["1"]}
