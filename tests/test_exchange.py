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

from http_security_test.exchange import (
    FIDELITY,
    Connection,
    Exchange,
    host,
    scheme,
    url_was_mangled,
)
from http_security_test.message import Request, Response


def _exchange(url="https://example.com/", **kw):
    return Exchange(Request.from_parts(url=url), Response.from_parts(status=200), **kw)


def test_scheme_and_host_come_from_the_url():
    assert scheme("https://Example.COM/a") == "https"
    assert host("https://Example.COM/a") == "example.com"


def test_host_drops_a_root_zone_trailing_dot():
    assert host("https://example.com./") == "example.com"


def test_host_strips_userinfo():
    assert host("https://user:pw@example.com/") == "example.com"


def test_host_strips_the_port():
    # Load-bearing: _is_loopback() in response.py compares this against
    # "127.0.0.1" / "::1" / "localhost", and a port left attached would make
    # every loopback target fail the comparison and lose the
    # reporting-ineffective suppression silently.
    assert host("https://127.0.0.1:8080/") == "127.0.0.1"


def test_host_drops_a_root_zone_trailing_dot_with_a_port():
    assert host("https://example.com.:443/") == "example.com"


def test_scheme_is_case_insensitive():
    assert scheme("HTTPS://example.com/") == "https"


def test_a_malformed_url_yields_empty_rather_than_raising():
    # File sources hand over whatever was recorded, including invalid IPv6
    # authorities. A source of bad data must not become a traceback.
    assert host("http://[::1") == ""
    assert scheme("::::") == ""


def test_url_was_mangled_catches_what_urlsplit_silently_strips():
    # urlsplit removes CR, LF and TAB anywhere in the URL (bpo-43882). That is
    # right for a client avoiding SSRF and wrong for a tool whose job is to
    # notice a CRLF payload, so the fact is kept rather than the parse trusted.
    assert url_was_mangled("https://example.com/x\r\nSet-Cookie: evil=1") is True
    assert url_was_mangled("https://exam\rple.com/") is True
    assert url_was_mangled("https://example.com/ordinary") is False


def test_timestamp_and_connection_belong_to_the_exchange_not_a_message():
    # A request does not carry when it was sent, and Date is the server's
    # clock on the response. The hostname actually connected to is separate
    # from Host: because Host: can be forged.
    e = _exchange(
        timestamp="2026-08-24T12:00:00Z",
        connection=Connection(host="example.com", ip="93.184.216.34", port=443, scheme="https"),
    )
    assert e.timestamp == "2026-08-24T12:00:00Z"
    assert e.connection.ip == "93.184.216.34"


def test_knowing_nothing_about_the_connection_is_one_none():
    assert _exchange().connection is None


def test_fidelity_vocabulary_is_closed_and_ordered_worst_last():
    assert FIDELITY == ("capture", "reconstructed", "redacted")
