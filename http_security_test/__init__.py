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

Build the mapping with parse_headers() or parse_raw_headers() and hand it to
report(), which returns the findings and the inventories as plain data ready to
serialise. analyze_all() is the same analysis as Finding objects, and analyze()
judges one header on its own.

A finding carries no prose: it is `(header, code, data)`, and describe() turns
one into a sentence from the catalog. A consumer that would rather write its own
wording, or none, can read `data` and ignore the catalog entirely.
"""

from .catalog import CONSEQUENCES, MESSAGES, Consequence, describe
from .csp import parse_csp
from .findings import (
    CODE_CONSEQUENCES,
    CODE_HEADER,
    CODE_TAXONOMY,
    FINDING_SEVERITY,
    SEVERITIES,
    Finding,
    consequences,
    identity,
    order_findings,
    severity,
    taxonomy,
)
from .legacy import DEPRECATED_HEADERS
from .message import parse_headers, parse_raw_headers
from .policies import parse_feature_policy, parse_permissions_policy
from .references import HEADER_DOCS, header_url, taxonomy_url
from .reporting import finding_as_dict, report
from .response import (
    CACHE_HEADERS,
    INFORMATION_HEADERS,
    SECURITY_HEADERS,
    analyze,
    analyze_all,
    inventory,
)

__all__ = [
    "CACHE_HEADERS",
    "CODE_CONSEQUENCES",
    "CODE_HEADER",
    "CODE_TAXONOMY",
    "CONSEQUENCES",
    "DEPRECATED_HEADERS",
    "FINDING_SEVERITY",
    "HEADER_DOCS",
    "INFORMATION_HEADERS",
    "MESSAGES",
    "SECURITY_HEADERS",
    "SEVERITIES",
    "Consequence",
    "Finding",
    "analyze",
    "analyze_all",
    "consequences",
    "describe",
    "finding_as_dict",
    "header_url",
    "identity",
    "inventory",
    "order_findings",
    "parse_csp",
    "parse_feature_policy",
    "parse_headers",
    "parse_permissions_policy",
    "parse_raw_headers",
    "report",
    "severity",
    "taxonomy",
    "taxonomy_url",
]
