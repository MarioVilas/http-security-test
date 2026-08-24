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

"""Where to read more, as URLs derived from names this package already has.

Nothing here is fetched and nothing here is curated beyond three entries. A
header name and a CWE identifier both resolve to a stable URL by pattern, which
is why the report carries identifiers rather than links: a name does not rot.

Resolution is ordered by the publisher's permanence policy, not by how official
the source sounds. The IETF and W3C keep published documents in perpetuity; MDN
redirects a page when a header is superseded, which is exactly how Feature-Policy
disappeared; http.dev states no policy at all and is the last resort.
"""

_MDN_PATTERN = "https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/%s"
_HTTP_DEV_PATTERN = "https://http.dev/%s"

_MDN = (
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Headers",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Origin",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
    "Cache-Control",
    "Clear-Site-Data",
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
    "Content-Type",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "ETag",
    "Expect-CT",
    "Expires",
    "Integrity-Policy",
    "Integrity-Policy-Report-Only",
    "Last-Modified",
    "Permissions-Policy",
    "Pragma",
    "Referrer-Policy",
    "Report-To",
    "Reporting-Endpoints",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-DNS-Prefetch-Control",
    "X-Frame-Options",
    "X-XSS-Protection",
)

_HTTP_DEV = (
    "Cross-Origin-Embedder-Policy-Report-Only",
    "Cross-Origin-Opener-Policy-Report-Only",
    "Feature-Policy",
    "X-Content-Security-Policy",
    "X-Download-Options",
    "X-Permitted-Cross-Domain-Policies",
    "X-WebKit-CSP",
)

# The only curated URLs in the package. Permanent by their publishers' written
# policy, which is what earns them the exception -- do NOT read three entries as
# licence to add a fourth because the table is still short. The distinction is
# permanence, not brevity.
_SPEC = {
    "Public-Key-Pins": "https://www.rfc-editor.org/rfc/rfc7469",
    "Public-Key-Pins-Report-Only": "https://www.rfc-editor.org/rfc/rfc7469",
    "P3P": "https://www.w3.org/TR/P3P",
}

# One positive name-to-URL table, built once. Positive rather than a pair of
# "headers MDN lacks" exclusion sets, and the direction is the point: an
# exclusion set lets an unrecognised header fall through to the MDN pattern and
# emit a URL that 404s, so it fails OPEN exactly when it is most out of date.
HEADER_DOCS = {}
HEADER_DOCS.update({name: _MDN_PATTERN % name for name in _MDN})
HEADER_DOCS.update({name: _HTTP_DEV_PATTERN % name.lower() for name in _HTTP_DEV})
HEADER_DOCS.update(_SPEC)

_LOWER = {name.lower(): url for name, url in HEADER_DOCS.items()}

_TAXONOMY = {
    "CWE": "https://cwe.mitre.org/data/definitions/%s.html",
    "CAPEC": "https://capec.mitre.org/data/definitions/%s.html",
}


def header_url(name):
    """Where to read about a header, or None.

    Case-insensitive because a duplicate-headers finding carries the lowercased
    name it read out of the header mapping, unlike every other finding.
    """
    return _LOWER.get(name.lower())


def taxonomy_url(identifier):
    """Where to read about a taxonomy entry, or None for an unknown scheme.

    Identifiers are self-prefixing -- CWE-79, CAPEC-63 -- which is why the
    report can carry one flat list and adding a taxonomy needs no schema change.
    """
    scheme, _, number = identifier.partition("-")
    if not number.isdigit() or scheme not in _TAXONOMY:
        return None
    return _TAXONOMY[scheme] % number
