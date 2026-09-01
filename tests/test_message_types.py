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

import pytest

from http_security_test.message import Request, Response, mapping


def test_headers_keep_order_and_duplicates():
    # The whole reason the type stores pairs rather than a mapping: a dict
    # keeps one value per name, and repeated CSP is enforced conjunctively.
    r = Response.from_parts(
        status=200,
        headers=[
            ("Content-Security-Policy", "default-src 'self'"),
            ("Set-Cookie", "a=1"),
            ("Content-Security-Policy", "script-src 'none'"),
        ],
    )
    assert r.headers == (
        ("Content-Security-Policy", "default-src 'self'"),
        ("Set-Cookie", "a=1"),
        ("Content-Security-Policy", "script-src 'none'"),
    )


def test_mapping_is_derived_lowercased_and_keeps_every_value():
    r = Response.from_parts(headers=[("Content-Security-Policy", "a"), ("CONTENT-SECURITY-POLICY", "b")])
    assert mapping(r.headers) == {"content-security-policy": ["a", "b"]}


def test_mapping_of_no_headers_is_empty():
    assert mapping(Response.from_parts().headers) == {}


def test_a_request_requires_a_url():
    with pytest.raises(TypeError):
        Request.from_parts()


def test_value_types_are_immutable():
    r = Response.from_parts(status=200)
    with pytest.raises(AttributeError):
        r.status = 404


def test_optional_fields_default_to_none_not_to_a_flattering_value():
    # secure=True was a policy default wearing a fact's clothes. Nothing here
    # may repeat that: an unknown fact is None, and a check that needs it is
    # disabled rather than answered.
    r = Response.from_parts()
    assert (r.status, r.reason, r.version, r.body, r.raw, r.fidelity) == (
        None,
        None,
        None,
        None,
        None,
        None,
    )
