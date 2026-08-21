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

from http_security_test.cli import exchange


def test_a_hop_defaults_to_followed_with_no_reason():
    hop = exchange.Hop("http://a/", 301, "https://a/")
    assert hop.followed is True
    assert hop.refused is None


def test_a_refused_hop_carries_its_reason():
    hop = exchange.Hop("https://a/", 302, "https://b/", False, "scope")
    assert (hop.followed, hop.refused) == (False, "scope")


def test_an_exchange_defaults_its_optional_passthrough():
    item = exchange.Exchange("live", "a.example", "https://a.example/", 200, "OK", {})
    assert item.hops == ()
    assert item.raw_response is None
    assert item.raw_request is None


def test_a_failure_names_the_target_and_the_kind():
    bad = exchange.Failure("a.example", "dns", "Name or service not known")
    assert bad.kind in exchange.FAILURE_KINDS


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://example.com/", True),
        ("http://example.com/", False),
        ("HTTPS://example.com/", True),
        ("ftp://example.com/", False),
    ],
)
def test_secure_reads_the_scheme(url, expected):
    assert exchange.secure(url) is expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://Example.COM/path", "example.com"),
        ("https://example.com.:443/", "example.com"),
        ("https://user:pw@example.com/", "example.com"),
        ("https://127.0.0.1:8080/", "127.0.0.1"),
        ("not a url", ""),
    ],
)
def test_host_is_lowercased_and_stripped(url, expected):
    assert exchange.host(url) == expected


def test_a_malformed_authority_does_not_raise_from_either_derivation():
    # These strings come from HAR / Burp / SAZ files in later tasks, not from
    # urllib's own output, so neither derivation may raise on one.
    assert exchange.secure("http://[::1") is False
    assert exchange.host("http://[::1") == ""
