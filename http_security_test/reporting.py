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

"""The whole analysis of one exchange, as plain data.

Everything here is JSON-serialisable with no encoder of its own -- strings,
numbers, lists and dicts. The shape is:

    {
      "response": {
        "findings": [
          {"header": ..., "code": ..., "level": ..., "data": {...},
           "consequences": [...], "message": ...}
        ],
        "inventory": {
          "security": {name: value}, "missing": [name],
          "deprecated": {name: value}, "information": {name: value},
          "caching": {name: value}
        },
        "references": {"headers": [...], "taxonomy": [...]},
        "raw": "<base64>"
      },
      "request": {"raw": "<base64>"}
    }

The two sides are nested rather than flat because a header name does not say
which message it came from -- `Cache-Control` is both -- so once requests are
analysed too, `request` grows the same `findings` and `inventory` keys and
nothing else has to change. A finding about the exchange rather than either
message belongs under `response`, with the request's part of it in `data`: the
defect is what the response did, and the request is the stimulus.

There is no key for the URL. A response does not know where it came from, and a
tool that fetched several wraps as many of these as it fetched -- which is a
question about the run, not about any one response.

`level` is derived from `code` and could be looked up by the consumer, but it is
written out anyway: the common case is a reader who wants to sort by severity
without also carrying the table. `data` is the machine-readable half of a
finding and is always present, empty dict included, so a consumer never has to
test for the key. `message` is the human half and can be left out entirely.

The `references` block is the reading list for this response, as identifiers
rather than links: a header name and a CWE identifier both resolve to a stable
URL by pattern, and a name does not rot. `references.header_url()` and
`taxonomy_url()` resolve them. It is fed by findings only, so a response with
nothing wrong carries two empty lists. A response whose only finding is
`duplicate-headers` is a second, narrower way to get an empty `headers` list
despite carrying a finding: `CODE_HEADER["duplicate-headers"]` is `None`
because that code is about the response, not about any one header, so it
names no header for `references` to collect. Deliberate, not a bug -- see
`CODE_HEADER`'s own comment in `findings.py`.

The `raw` blobs are optional passthrough: this package never fetches anything,
so they are whatever the caller hands over. Two things about them.

They make a report reproducible. `raw` is exactly what `parse_raw_headers()`
accepts, so an archived report can be re-analysed by a later version of this
package and the findings diffed. Base64 is not decoration -- header values are
latin-1 and a `Server: caf\xe9-server` banner is not valid UTF-8, so a JSON
string cannot carry one losslessly.

**They carry credentials.** A raw response head normally includes `Set-Cookie`
with a live session token; a raw request includes `Cookie` and `Authorization`.
Nothing here can police that, and a report is a thing people paste into tickets
and dashboards. Passing only the header block, or redacting first, or passing
nothing, is the caller's decision -- but it should be a decision.

Keys the caller did not supply are absent rather than empty: no blob means no
`raw` key, and nothing known about the request means no `request` key at all.
That is the opposite of `data`, which is always present, and the rule behind
both is the same -- content this package derived is always there, passthrough it
was never given is not.
"""

import base64

from . import catalog
from .findings import (
    CODE_HEADER,
    _identifier_sort_key,
    consequences,
    order_findings,
    severity,
    taxonomy,
)
from .response import analyze_all, inventory


def _blob(raw):
    """A raw message as base64, from bytes or from text.

    Text is encoded latin-1, which is what `parse_raw_headers()` decodes with,
    so a value that came from there survives the round trip unchanged.
    """
    if isinstance(raw, str):
        raw = raw.encode("latin-1")
    return base64.b64encode(bytes(raw)).decode("ascii")


def finding_as_dict(finding, message=True):
    """One finding as plain data.

    Pass message=False for a consumer that renders its own prose, or none.
    """
    row = {
        "header": finding.header,
        "code": finding.code,
        "level": severity(finding.code),
        "data": dict(finding.data or {}),
        # Always present, [] included, so a consumer never tests for the key.
        # A hint about potential risk, never a claim the risk is reachable.
        "consequences": list(consequences(finding.code)),
    }
    if message:
        row["message"] = catalog.describe(finding)
    return row


def _references(findings):
    """The reading list for one response: identifiers, never URLs.

    Fed by findings only -- a header appears because something was said about
    it. Header names come from CODE_HEADER rather than from the finding,
    because a duplicate-headers finding carries the lowercased name it read out
    of the mapping and every other finding carries canonical casing.
    """
    names, ids = set(), set()
    for finding in findings:
        declared = CODE_HEADER.get(finding.code)
        if declared is not None:
            names.add(declared)
        ids.update(taxonomy(finding.code))
    return {
        "headers": sorted(names),
        # By scheme then NUMERIC id: lexically, CWE-1021 sorts before CWE-79.
        "taxonomy": sorted(ids, key=_identifier_sort_key),
    }


def report(present, secure=True, host=None, message=True, raw=None, request_raw=None):
    """Findings and inventories for one exchange, ready to serialise.

    `present`, `secure` and `host` mean what they mean to analyze_all. Findings
    come out worst first, which is the order a reader wants and the order the
    tables already guarantee is stable from run to run.

    `raw` and `request_raw` are the verbatim messages, as bytes or text, and are
    base64-encoded here so that one encoding decision is made in one place.
    Read the module docstring before passing either: they carry credentials.
    """
    findings = order_findings(analyze_all(present, secure=secure, host=host))
    response = {
        "findings": [finding_as_dict(f, message=message) for f in findings],
        "inventory": inventory(present),
        "references": _references(findings),
    }
    if raw is not None:
        response["raw"] = _blob(raw)

    result = {"response": response}
    if request_raw is not None:
        result["request"] = {"raw": _blob(request_raw)}
    return result
