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

"""Fetching one URL, which is the only thing in this package that uses a socket.

Kept behind one narrow function on purpose. `urllib` normalises what it sends
and cannot emit a malformed request, which active tests will eventually need --
duplicate headers, odd methods, a forged Origin. Swapping this out should be a
file, not surgery.
"""

import collections
import contextlib
import http.client
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

from ..exchange import Exchange, host
from ..message import Request, Response
from . import outcome, scope

# Everything the fetcher needs, so this module never sees an argparse Namespace.
Options = collections.namedtuple(
    "Options",
    "method headers user_agent timeout insecure proxy no_redirect max_redirects "
    "patterns raw",
)


def classify(error):
    """Which observable kind of failure this is, or None if it is a response.

    Not "retryable" -- that is a prediction and this is a fact. A calling tool
    reads the kind and predicts for itself.
    """
    if isinstance(error, urllib.error.HTTPError):
        return None  # a 403 is a response, and its headers are worth analysing
    reason = getattr(error, "reason", None)
    if not isinstance(reason, BaseException):
        reason = error
    if isinstance(reason, socket.gaierror):
        return "dns"
    if isinstance(reason, ssl.SSLError):
        return "tls"
    if isinstance(reason, ConnectionRefusedError):
        return "refused"
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "timeout"
    # RemoteDisconnected subclasses this AND BadStatusLine, so it lands here.
    # A separate branch for it below would be unreachable.
    if isinstance(reason, ConnectionResetError):
        return "reset"
    if isinstance(reason, http.client.HTTPException):
        return "protocol"
    return "other"


class _Chain(urllib.request.HTTPRedirectHandler):
    """Remembers the redirects, and refuses the ones out of scope.

    A refusal is recorded rather than merely acted on: "the target tried to
    bounce us to login.example.net" is a fact worth keeping in an evidence
    file, and a guard that stops silently is a mystery.
    """

    def __init__(self, patterns, follow=True, limit=10):
        self.patterns = tuple(patterns)
        self.follow = follow
        self.limit = limit
        self.hops = []
        # HTTPRedirectHandler carries its own ceilings -- max_redirections
        # (10) and max_repeats (4) -- and CPython calls redirect_request()
        # first, applies its own limits after. Left at their defaults,
        # self.limit only wins below 10; at or above it urllib's ceiling
        # fires first, raises HTTPError carrying the 3xx, and fetch() treats
        # that as an ordinary response -- no refusal recorded, indistinguishable
        # from a site that genuinely answered 302. Pinning both to our own
        # limit makes self.limit always fire first, so a refusal is always
        # the one that gets recorded.
        self.max_redirections = self.max_repeats = limit

    def _refuse(self, origin, code, newurl, why):
        # Returns None (implicit): urllib then surfaces the 3xx itself, which we
        # go on to analyse like any other response.
        self.hops.append(outcome.Hop(origin, code, newurl, False, why))

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        origin = req.full_url
        if not self.follow:
            return self._refuse(origin, code, newurl, "no-redirect")
        if len(self.hops) >= self.limit:
            return self._refuse(origin, code, newurl, "max-redirects")
        if not scope.allows(self.patterns, host(newurl)):
            return self._refuse(origin, code, newurl, "scope")
        self.hops.append(outcome.Hop(origin, code, newurl, True, None))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_opener(options):
    """An opener honouring the request options, and the chain it will fill."""
    chain = _Chain(
        options.patterns,
        follow=not options.no_redirect,
        limit=options.max_redirects,
    )
    handlers = [chain]
    if options.insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))
    if options.proxy:
        handlers.append(
            urllib.request.ProxyHandler({"http": options.proxy, "https": options.proxy})
        )
    return urllib.request.build_opener(*handlers), chain


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


def raw_request(url, options):
    """The request head as text, near enough for the round trip."""
    parts = urllib.parse.urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    lines = [
        "%s %s HTTP/1.1" % (options.method, path),
        "Host: %s" % parts.netloc,
        "User-Agent: %s" % options.user_agent,
    ]
    lines.extend(options.headers)
    return "\r\n".join(lines) + "\r\n\r\n"


def fetch(target, options, opener=None, chain=None):
    """The run facts and analysed exchange for one target, or one failure.

    Always an iterable of one `(facts, exchange)` pair -- because every file
    format this seam will grow is a multi-exchange container and two shapes
    would have to be unified badly -- except that on failure there is no
    exchange to pair, so the second element is None: `(Failure, None)`. Either
    way a caller writes `for facts, item in source(target, options):` and
    tests `isinstance(facts, outcome.Failure)` to tell the two apart, never
    needing to know which shape it is looking at before unpacking it.
    """
    if opener is None:
        opener, chain = build_opener(options)

    request = urllib.request.Request(target, method=options.method)
    request.add_header("User-Agent", options.user_agent)
    for header in options.headers:
        name, _, value = header.partition(":")
        request.add_header(name.strip(), value.strip())

    try:
        response = opener.open(request, timeout=options.timeout)
    except urllib.error.HTTPError as error:
        response = error  # a 3xx we would not follow, or any 4xx/5xx
    except Exception as error:  # a pentest target fails in many ways
        failure = outcome.Failure(target, classify(error) or "other", str(error))
        return ((failure, None),)

    if options.method != "HEAD":
        # Drained, not kept; nothing here reads a body. Any failure while
        # draining is ignored -- the headers are what we came for and we
        # already have them.
        with contextlib.suppress(Exception):
            response.read(4096)
    response.close()

    url = getattr(response, "url", None) or target
    status = getattr(response, "status", None) or getattr(response, "code", None)
    reason = getattr(response, "reason", "") or ""

    # live.py never captures wire bytes: urllib does not expose them, and
    # raw_head()/raw_request() rebuild an approximation from what was parsed
    # (see their own docstrings). The rebuild demonstrably differs from what
    # crossed the wire -- the real request carries `Accept-Encoding: identity`
    # (http.client.HTTPConnection.putrequest) and `Connection: close`
    # (urllib.request.AbstractHTTPHandler.do_open), and raw_request() emits
    # neither. So the label is "reconstructed", never "capture", and only
    # present at all when --raw asked for the bytes to be kept.
    raw_response_text = raw_head(response) if options.raw else None
    raw_request_text = raw_request(url, options) if options.raw else None

    # Headers reach the analyser from response.headers.items() always,
    # --raw or not -- the reassembled text in raw_response_text is attached
    # as evidence, via `raw`, and is never re-parsed to build the headers
    # analyze() sees. Re-parsing it would let --raw change the analysis
    # itself: Response.from_bytes() has its own obs-fold handling, which
    # does not necessarily agree with email.message.Message's, and a flag
    # that controls evidence must not also control what gets analysed.
    response_message = Response.from_parts(
        status=status,
        reason=reason,
        headers=list(response.headers.items()),
        raw=raw_response_text,
        fidelity="reconstructed" if raw_response_text is not None else None,
    )
    request_message = (
        Request.from_bytes(raw_request_text, url=url, fidelity="reconstructed")
        if raw_request_text is not None
        else Request.from_parts(url=url)
    )

    facts = outcome.Run(
        kind="live",
        target=target,
        url=url,
        status=status,
        reason=reason,
        hops=tuple(chain.hops) if chain is not None else (),
    )
    return ((facts, Exchange(request_message, response_message)),)
