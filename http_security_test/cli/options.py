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

"""The whole command-line contract, in one file.

Read this to know what the tool accepts. Verb-first: `hst scan URL`, never
`hst URL` -- see the spec for why the bare form is deliberately a usage error.
"""

import argparse

from . import commands, meta

VERBS = ("scan", "explain")


def misplaced_target(argv):
    """The 'did you mean' message for `hst example.com`, or None.

    argparse's own "invalid choice" is accurate but not directive, and this is
    the error a returning user hits most. Only fires when the stray token looks
    like a host, so a genuine typo still gets the ordinary message.

    This runs in main() BEFORE parse_args, so argparse has not spoken yet and
    is not there to police what argv[0] means. Only argv[0] is examined, on
    purpose: that is the one case the feature exists for (`hst example.com`).
    Scanning past a leading flag used to also catch `--proxy
    http://127.0.0.1:8080 scan a.com`, hijacking argparse's accurate message
    for the proxy URL and telling the operator to scan their own Burp proxy.
    """
    if not argv:
        return None
    token = argv[0]
    if token.startswith("-"):
        return None
    if token in VERBS:
        return None
    if "." in token or "://" in token:
        return "%s is not a verb; did you mean: hst scan %s" % (token, token)
    return None


def build_parser():
    parser = argparse.ArgumentParser(
        prog="hst", description="HTTP security header analysis."
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%s %s" % (meta.TOOL_NAME, meta.tool_version()),
    )
    verbs = parser.add_subparsers(dest="verb", required=True, metavar="VERB")
    _add_scan(verbs)
    _add_explain(verbs)
    return parser


def _add_scan(verbs):
    parser = verbs.add_parser(
        "scan",
        help="fetch URLs and analyse their security headers",
        description="Fetch each URL and analyse the response. The terminal "
        "always shows the run; -o writes evidence files.",
    )
    parser.add_argument(
        "url", nargs="+", metavar="URL", help="target; '-' reads targets from stdin"
    )

    request = parser.add_argument_group("request")
    request.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="extra request header, repeatable",
    )
    request.add_argument("-A", "--user-agent", default=meta.USER_AGENT)
    request.add_argument("-X", "--method", default="GET", help="default GET")
    request.add_argument("-t", "--timeout", type=float, default=15.0)
    request.add_argument(
        "-k", "--insecure", action="store_true", help="do not verify TLS certificates"
    )
    request.add_argument("--proxy", metavar="URL", help="send through this proxy")

    wander = parser.add_argument_group("redirects and scope")
    wander.add_argument(
        "-n",
        "--no-redirect",
        action="store_true",
        help="analyse the first response instead of following redirects",
    )
    wander.add_argument("--max-redirects", type=int, default=10)
    wander.add_argument(
        "--scope",
        action="append",
        default=[],
        metavar="PATTERN",
        help="host pattern: example.com, '*.example.com' or '*' -- QUOTE the "
        "wildcard. Repeatable. Defaults to each target host and its "
        "subdomains.",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "-o",
        "--output",
        action="append",
        default=[],
        metavar="FORMAT:PATH",
        help="write a file; format may be omitted when the extension says it. "
        "'-' means stdout. Repeatable.",
    )
    output.add_argument(
        "-oA", "--output-all", metavar="PREFIX", help="write every format as PREFIX.*"
    )
    output.add_argument(
        "-j", "--json", action="store_true", help="shorthand for -o json:-"
    )
    output.add_argument(
        "--color", choices=("auto", "always", "never"), default="auto"
    )
    output.add_argument(
        "-q", "--quiet", action="store_true", help="findings only, no inventories"
    )
    output.add_argument(
        "-c", "--codes", action="store_true", help="show each finding's code and data"
    )
    output.add_argument(
        "--min-level",
        choices=meta.LEVELS,
        default="note",
        help="hide findings below this level, on the terminal only",
    )
    output.add_argument(
        "--fail-on",
        choices=("never",) + meta.LEVELS,
        default="never",
        help="exit 1 when a finding reaches this level (default: never)",
    )
    output.add_argument(
        "--raw",
        action="store_true",
        help="include the base64 raw blobs (CARRIES Set-Cookie / Authorization)",
    )

    parser.set_defaults(run=commands.do_scan)
    return parser


def _add_explain(verbs):
    parser = verbs.add_parser(
        "explain",
        help="what a finding code means",
        description="Print each code's level and message template. "
        "With no arguments, list every code.",
    )
    parser.add_argument("code", nargs="*", metavar="CODE")
    parser.set_defaults(run=commands.do_explain)
    return parser
