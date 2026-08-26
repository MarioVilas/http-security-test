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

"""fidelity: the provenance label that rides beside `raw`, and is never
validated.

A separate file rather than an addition to test_headers.py -- that corpus was
closed and reviewed before this behaviour landed, and CLAUDE.md's hard
constraints keep it that way. This is the whole of what Task 7 added to
report()'s contract; the rest of report()'s schema is pinned in
test_headers.py already.
"""

import http_security_test as headers
from http_security_test.exchange import Exchange
from http_security_test.message import Request, Response


def _bare_exchange():
    """An exchange whose messages carry no raw bytes at all."""
    return Exchange(
        Request.from_parts(url="https://example.com/"),
        Response.from_parts(status=200, headers=[("X-Frame-Options", "DENY")]),
    )


def test_report_takes_an_exchange_and_keeps_its_shape():
    doc = headers.report(_bare_exchange())
    assert set(doc["response"]) >= {"findings", "inventory", "references"}
    assert "url" not in doc["response"]  # a response does not know where it came from


def test_fidelity_rides_beside_raw_and_is_absent_when_raw_is():
    body = b"HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\n"
    e = Exchange(
        Request.from_parts(url="https://example.com/"),
        Response.from_bytes(body, fidelity="capture"),
    )
    doc = headers.report(e)
    assert doc["response"]["fidelity"] == "capture"
    assert "raw" in doc["response"]

    bare = headers.report(_bare_exchange())
    assert "raw" not in bare["response"] and "fidelity" not in bare["response"]


def test_a_reconstruction_is_never_presented_as_a_capture():
    # from_parts has no wire bytes to offer, so it offers none rather than
    # reassembling them. Absent beats empty.
    e = Exchange(Request.from_parts(url="https://example.com/"),
                 Response.from_parts(status=200))
    assert "raw" not in headers.report(e)["response"]


def test_fidelity_is_not_validated_against_the_vocabulary():
    # The controller ruling: fidelity is a caller assertion about provenance
    # this package has no way to verify -- validating it would reject a typo
    # while doing nothing about a lie -- so report() emits whatever string
    # the message carries, FIDELITY included or not.
    e = Exchange(
        Request.from_parts(url="https://example.com/"),
        Response.from_parts(status=200, raw=b"whatever", fidelity="not-a-real-value"),
    )
    assert headers.report(e)["response"]["fidelity"] == "not-a-real-value"


def test_the_request_side_carries_its_own_fidelity():
    e = Exchange(
        Request.from_parts(url="https://example.com/", raw=b"GET / HTTP/1.1\r\n\r\n",
                            fidelity="reconstructed"),
        Response.from_parts(status=200),
    )
    doc = headers.report(e)
    assert doc["request"]["fidelity"] == "reconstructed"
    # And when the request carries no raw, it carries no fidelity either --
    # the response side's fidelity above must not leak across.
    assert "request" not in headers.report(_bare_exchange())
