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

"""Throwaway fetcher for driving the analyser against a live site.

NOT part of the package and not its CLI -- the library deliberately has none,
and it never fetches anything either. This is the missing half, kept crude on
purpose: fetch a URL, hand the headers to report(), print what came back.

    python3 scan.py https://example.com
    python3 scan.py -j https://example.com | jq .
    python3 scan.py -k -n http://example.com https://example.com

Everything the analyser cannot know about a response, this decides here:
`secure` from the final URL's scheme, `host` from its hostname (that is what the
HSTS preload check needs), and whether to carry the raw blobs at all.
"""

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

from http_security_test import parse_headers, report
from http_security_test.hsts import hstspreload

UA = "Mozilla/5.0 (X11; Linux x86_64) http-security-test/scan.py"

COLORS = {"error": "\033[31m", "warning": "\033[33m", "note": "\033[36m"}
RESET = "\033[0m"
BOLD = "\033[1m"


class _Chain(urllib.request.HTTPRedirectHandler):
    """A redirect handler that remembers the hops, or refuses to take them."""

    def __init__(self, follow=True):
        self.follow = follow
        self.hops = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.follow:
            return None  # urllib then surfaces the 3xx itself, which we analyse
        self.hops.append((req.full_url, code, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, args):
    """The response for `url`, redirects included, 4xx and 5xx not raised.

    Returns (response, hops). A response is a response whatever its status: an
    error page's headers are exactly as worth analysing as a 200's, so the
    HTTPError urllib raises for one is caught and used rather than reported.
    """
    chain = _Chain(follow=not args.no_redirect)
    handlers = [chain]
    if args.insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)

    request = urllib.request.Request(url, method=args.method)
    request.add_header("User-Agent", args.user_agent)
    for header in args.header:
        name, _, value = header.partition(":")
        request.add_header(name.strip(), value.strip())

    try:
        response = opener.open(request, timeout=args.timeout)
    except urllib.error.HTTPError as error:
        response = error  # 3xx with -n, or any 4xx/5xx: still a response
    if args.method != "HEAD":
        response.read(4096)  # drained, not kept; nothing here reads a body
    response.close()
    return response, chain.hops


def raw_head(response):
    """The response head as text, in the shape parse_raw_headers() accepts.

    Rebuilt from the pairs rather than taken from the wire, because urllib does
    not keep the original bytes. Duplicates survive, which is the part that
    matters.
    """
    version = getattr(response, "version", 11)
    status = getattr(response, "status", None) or response.code
    line = "HTTP/%s %s %s\r\n" % (
        "1.1" if version == 11 else "1.0",
        status,
        getattr(response, "reason", "") or "",
    )
    return line + "".join("%s: %s\r\n" % pair for pair in response.headers.items())


def raw_request(url, args):
    """The request head as text, near enough for the round trip."""
    parts = urllib.parse.urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    lines = ["%s %s HTTP/1.1" % (args.method, path)]
    lines.append("Host: %s" % parts.netloc)
    lines.append("User-Agent: %s" % args.user_agent)
    lines.extend(args.header)
    return "\r\n".join(lines) + "\r\n\r\n"


def paint(text, level, color):
    if not color:
        return text
    return "%s%s%s" % (COLORS.get(level, ""), text, RESET)


def show(url, response, hops, result, args, color):
    """The report as text. -j prints the document instead; this is for reading."""
    status = getattr(response, "status", None) or response.code
    head = "=== %s ===" % url
    print(BOLD + head + RESET if color else head)
    print("    %s %s   %s" % (status, getattr(response, "reason", ""), response.url))
    for origin, code, target in hops:
        print("    %s -> %s -> %s" % (origin, code, target))
    print()

    findings = result["response"]["findings"]
    if findings:
        counts = {}
        for finding in findings:
            counts[finding["level"]] = counts.get(finding["level"], 0) + 1
        summary = ", ".join(
            "%d %s" % (counts[level], level)
            for level in ("error", "warning", "note")
            if level in counts
        )
        print("findings (%s):" % summary)
        for finding in findings:
            # Padded before it is painted: %-8s counts the escape bytes as
            # content, so colouring first collapses the column to nothing.
            level = paint("%-8s" % finding["level"], finding["level"], color)
            print(
                "  %s %-34s %s"
                % (
                    level,
                    finding["header"],
                    finding.get("message", finding["code"]),
                )
            )
            if args.codes:
                print(
                    "           %s %s" % (finding["code"], json.dumps(finding["data"]))
                )
    else:
        print("findings: none")
    print()

    if args.quiet:
        return

    inventory = result["response"]["inventory"]
    for table in ("security", "deprecated", "information", "caching"):
        entries = inventory[table]
        if not entries:
            continue
        print("%s:" % table)
        for name, value in entries.items():
            for one in [value] if isinstance(value, str) else value:
                print("  %s: %s" % (name, one))
        print()
    if inventory["missing"]:
        print("missing:")
        for name in inventory["missing"]:
            print("  %s" % name)
        print()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Fetch a URL and analyse its security headers."
    )
    parser.add_argument("url", nargs="+")
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="extra request header, repeatable",
    )
    parser.add_argument("-A", "--user-agent", default=UA)
    parser.add_argument("-X", "--method", default="GET", help="GET (default) or HEAD")
    parser.add_argument("-t", "--timeout", type=float, default=15.0)
    parser.add_argument(
        "-k", "--insecure", action="store_true", help="do not verify TLS certificates"
    )
    parser.add_argument(
        "-n",
        "--no-redirect",
        action="store_true",
        help="analyse the first response instead of following redirects",
    )
    parser.add_argument("-j", "--json", action="store_true", help="print the report")
    parser.add_argument(
        "--raw",
        action="store_true",
        help="include the base64 raw blobs (CARRIES Set-Cookie / Authorization)",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="findings only")
    parser.add_argument(
        "-c", "--codes", action="store_true", help="show each finding's code and data"
    )
    args = parser.parse_args(argv)

    color = sys.stdout.isatty() and not args.json
    if hstspreload is None:
        print(
            "note: hstspreload is not installed, so hsts-not-preloaded cannot fire",
            file=sys.stderr,
        )

    documents = []
    failed = False
    for url in args.url:
        if "://" not in url:
            url = "https://" + url
        try:
            response, hops = fetch(url, args)
        except Exception as error:  # a pentest target fails in many ways
            print("%s: %s: %s" % (url, type(error).__name__, error), file=sys.stderr)
            failed = True
            continue

        final = response.url
        parts = urllib.parse.urlsplit(final)
        result = report(
            parse_headers(response.headers.items()),
            secure=parts.scheme == "https",
            host=parts.hostname,
            raw=raw_head(response) if args.raw else None,
            request_raw=raw_request(final, args) if args.raw else None,
        )
        if args.json:
            result["url"] = final  # not part of the schema; a fact about the run
            documents.append(result)
        else:
            show(url, response, hops, result, args, color)

    if args.json:
        print(json.dumps(documents if len(documents) != 1 else documents[0], indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
