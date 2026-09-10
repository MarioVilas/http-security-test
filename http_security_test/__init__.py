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

"""HTTP security header analysis.

Reports what is wrong with a header value: each finding carries a stable code, a
message, and a rating chosen to line up with SARIF levels. Findings are facts,
and so are the header tables -- which headers exist and what a value means is
knowledge. What a badly configured header is worth to a particular site is not,
so a consumer is free to remap the ratings or ignore them entirely.

Build a Response -- from_bytes() for raw wire bytes, from_parts() for pieces
already split out, headers as (name, value) pairs -- and a Request the same
way, wrap both in an Exchange, and hand that to report():

    >>> from http_security_test import Exchange, Request, Response, report
    >>> response = Response.from_parts(
    ...     status=200,
    ...     headers=[("Strict-Transport-Security",
    ...               "max-age=31536000; includeSubDomains")],
    ... )
    >>> request = Request.from_parts(url="https://example.com/")
    >>> result = report(Exchange(request, response))

report() returns the findings and the inventories as plain data ready to
serialise. analyze() is the same analysis as Finding objects, and inventory()
is what the response carries before anything is judged about it. mapping() is
the lowercased name -> [values] view analyze() and inventory() derive from
`exchange.response.headers` internally; parse_headers() and
parse_raw_headers() build that same view directly from (name, value) pairs or
a raw header block, for a caller who wants it without a Response around it.

A finding carries no prose: it is `(header, code, data, level)`, and describe()
turns one into a sentence from the catalog. A consumer that would rather write
its own wording, or none, can read `data` and ignore the catalog entirely.

`level` is the fourth field and is usually None, meaning "the rating this code
always has" -- `severity(code)`. A finding whose severity depends on what its
`data` says fills it in instead, which today is the cookie hardening ladder and
nothing else: `ESCALATABLE` names exactly the codes allowed to. Read a level
with `level_of(finding)`, which resolves the two; reading `severity(f.code)`
gets the floor, not the verdict. Unpacking a finding as three values raises
`ValueError`, so `identity(finding)` is what to key on rather than a
hand-written tuple.

`adaptors` and (later) `formats` are deliberately NOT imported here. Importing
this package pulls in the analysis core and nothing else, which is what lets it
sit in a Burp extension or a CI job without dragging a tool along. Reach for
`from http_security_test import adaptors` when you want one.
"""

from .catalog import CONSEQUENCES, MESSAGES, Consequence, describe
from .csp import parse_csp, split_policies
from .exchange import Connection, Exchange
from .findings import (
    CODE_CONSEQUENCES,
    CODE_HEADER,
    CODE_TAXONOMY,
    ESCALATABLE,
    FINDING_SEVERITY,
    SEVERITIES,
    Finding,
    consequences,
    identity,
    level_of,
    order_findings,
    severity,
    taxonomy,
)
from .legacy import DEPRECATED_HEADERS
from .message import Request, Response, mapping, parse_headers, parse_raw_headers
from .policies import parse_feature_policy, parse_permissions_policy
from .references import HEADER_DOCS, header_url, taxonomy_url
from .reporting import finding_as_dict, report
from .response import (
    CACHE_HEADERS,
    INFORMATION_HEADERS,
    SECURITY_HEADERS,
    analyze,
    inventory,
)

__all__ = [
    "CACHE_HEADERS",
    "CODE_CONSEQUENCES",
    "CODE_HEADER",
    "CODE_TAXONOMY",
    "CONSEQUENCES",
    "DEPRECATED_HEADERS",
    "ESCALATABLE",
    "FINDING_SEVERITY",
    "HEADER_DOCS",
    "INFORMATION_HEADERS",
    "MESSAGES",
    "SECURITY_HEADERS",
    "SEVERITIES",
    "Connection",
    "Consequence",
    "Exchange",
    "Finding",
    "Request",
    "Response",
    "analyze",
    "consequences",
    "describe",
    "finding_as_dict",
    "header_url",
    "identity",
    "inventory",
    "level_of",
    "mapping",
    "order_findings",
    "parse_csp",
    "parse_feature_policy",
    "parse_headers",
    "parse_permissions_policy",
    "parse_raw_headers",
    "report",
    "severity",
    "split_policies",
    "taxonomy",
    "taxonomy_url",
]
