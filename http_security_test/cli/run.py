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

"""The whole run as one plain-data document.

`report` holds the library's document quoted verbatim and unmutated. That is
the structural move everything else depends on: the analyser's ruling that a
response does not know where it came from stays literally true, and the run
facts sit in a sibling `source` key instead of being spliced in. It also keeps
the two contracts separable -- `schema` versions this envelope, `tool.version`
versions what is inside it.

`source.kind` is where a new input format shows up: a HAR result reads
{"kind": "har", "file": ..., "entry": 12, ...} in the same slot. The
polymorphism lives in the document rather than the call graph, which is why
there is no source registry.
"""

import datetime

from . import meta

# Incremented only on a breaking change. Consumers ignore keys they do not
# know. A version belongs to a serialised artifact, and this subpackage is what
# writes files that outlive the process -- report() returns a dict and owns no
# version of its own.
SCHEMA_VERSION = 1


def timestamp(moment=None):
    """An instant as ISO 8601 UTC with a trailing Z."""
    if moment is None:
        moment = datetime.datetime.now(datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _hop(hop):
    """One redirect as wire data. `from` is a keyword, hence origin/destination."""
    row = {
        "from": hop.origin,
        "code": hop.code,
        "to": hop.destination,
        "followed": bool(hop.followed),
    }
    if hop.refused:
        row["refused"] = hop.refused
    return row


def analysed(item, report):
    """One analysed exchange as a result object.

    The full redirect chain is repeated on every result derived from a target
    rather than stored once. NDJSON is a reserved output format, and an NDJSON
    line that needs a sibling line to be understood is a broken format.
    """
    source = {"kind": item.kind, "url": item.url}
    if item.status is not None:
        source["status"] = item.status
    if item.reason:
        source["reason"] = item.reason
    source["hops"] = [_hop(hop) for hop in item.hops]
    return {
        "outcome": "ok",
        "target": item.target,
        "source": source,
        "report": report,
    }


def failed(failure):
    """One target that could not be fetched.

    In the same list as the successes, not a parallel one: a consumer diffing
    two runs has to see that a target was attempted and did not answer.
    """
    return {
        "outcome": "failed",
        "target": failure.target,
        "failure": {"kind": failure.kind, "message": failure.message},
    }


def run_document(results, started, finished):
    """The envelope. `results` are already-built result objects, in order.

    Order is contractual -- targets as given, hops in chain order -- for the
    same reason the analyser's tables are tuples and not sets.

    Deliberately absent: the command line. It carries `-H 'Authorization: ...'`
    and proxy credentials, and redacting means guessing at secrets. The precise
    provenance record is the --raw request head, which already carries a
    credential warning.
    """
    return {
        "schema": SCHEMA_VERSION,
        "tool": {"name": meta.TOOL_NAME, "version": meta.tool_version()},
        "run": {"started": started, "finished": finished},
        "results": list(results),
    }
