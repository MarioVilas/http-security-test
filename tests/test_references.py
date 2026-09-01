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

import http_security_test as headers
from http_security_test import references


def test_an_mdn_header_resolves_to_the_mdn_pattern():
    assert references.header_url("Content-Security-Policy") == (
        "https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Content-Security-Policy"
    )


def test_a_header_mdn_does_not_document_falls_back_to_http_dev():
    assert references.header_url("X-WebKit-CSP") == "https://http.dev/x-webkit-csp"


def test_a_header_with_a_permanent_spec_prefers_it_over_http_dev():
    # RFC and W3C /TR/ URLs are permanent by their publishers' written policy,
    # which http.dev does not have. That ordering is the whole design.
    assert references.header_url("Public-Key-Pins") == ("https://www.rfc-editor.org/rfc/rfc7469")
    assert references.header_url("P3P") == "https://www.w3.org/TR/P3P"


def test_lookup_is_case_insensitive():
    # duplicate-headers findings carry a lowercased name; a case-sensitive
    # lookup would silently produce None for them.
    assert references.header_url("x-frame-options") == references.header_url("X-Frame-Options")


def test_an_unknown_header_resolves_to_none():
    # Coverage is 40/40 today, which is exactly what makes this branch look
    # like dead code. A header added later would be in no source at all.
    assert references.header_url("X-Not-A-Real-Header") is None


def test_every_header_a_finding_can_name_resolves():
    for code, header in headers.CODE_HEADER.items():
        if header is None:
            continue
        assert references.header_url(header) is not None, code


def test_every_security_deprecated_and_cache_header_resolves():
    # test_every_header_a_finding_can_name_resolves only walks CODE_HEADER, so
    # a header with no finding of its own -- Cache-Control, ETag, Expires,
    # Last-Modified, Pragma, all inventory-only -- is invisible to it and to
    # every other test in this file. Deleting one of the five from _MDN passes
    # the rest of the suite; this is the test that has to notice.
    for header in headers.SECURITY_HEADERS + headers.DEPRECATED_HEADERS + headers.CACHE_HEADERS:
        assert references.header_url(header) is not None, header


def test_taxonomy_urls():
    assert references.taxonomy_url("CWE-79") == ("https://cwe.mitre.org/data/definitions/79.html")
    assert references.taxonomy_url("CAPEC-63") == ("https://capec.mitre.org/data/definitions/63.html")


def test_an_unrecognised_taxonomy_scheme_resolves_to_none():
    assert references.taxonomy_url("TID-319") is None
    assert references.taxonomy_url("nonsense") is None


def test_every_url_is_https_and_has_no_whitespace():
    # Shape only. Nothing here fetches anything, in this test or any other.
    for url in list(references.HEADER_DOCS.values()) + [
        references.taxonomy_url("CWE-79"),
        references.taxonomy_url("CAPEC-63"),
    ]:
        assert url.startswith("https://")
        assert url == url.strip()
        assert " " not in url
