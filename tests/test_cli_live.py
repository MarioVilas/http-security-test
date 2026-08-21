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

import email.message
import http.client
import http.server
import socket
import ssl
import threading
import urllib.error
import urllib.request

import pytest

from http_security_test.cli import exchange, live

OPTIONS = live.Options(
    method="GET",
    headers=[],
    user_agent="test-agent",
    timeout=5.0,
    insecure=False,
    proxy=None,
    no_redirect=False,
    max_redirects=10,
    patterns=("example.com", "*.example.com"),
    raw=False,
)


class FakeResponse:
    def __init__(self, url, status=200, reason="OK", pairs=()):
        self.url = url
        self.status = status
        self.code = status
        self.reason = reason
        self.version = 11
        self.headers = email.message.Message()
        for name, value in pairs:
            self.headers.add_header(name, value)
        self.closed = False

    def read(self, size=None):
        return b""

    def close(self):
        self.closed = True


class FakeOpener:
    def __init__(self, result):
        self.result = result
        self.request = None

    def open(self, request, timeout=None):
        self.request = request
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


# urllib.request.AbstractHTTPHandler.do_open wraps only h.request() (connect
# and send) in `except OSError as err: raise URLError(err)`; h.getresponse()
# sits outside that guard, so anything it raises -- BadStatusLine,
# RemoteDisconnected -- propagates bare, never wrapped in URLError. Verified
# empirically against two loopback servers (a garbage status line, a bare
# close). So the connect-phase cases below (gaierror, ConnectionRefusedError,
# TimeoutError, the ssl errors) stay URLError-wrapped -- that really is what
# urllib raises for them -- while the two response-phase cases are bare. Do
# not "tidy" these into one consistent shape.
CLASSIFY_CASES = [
    (urllib.error.URLError(socket.gaierror(-2, "Name or service not known")), "dns"),
    (urllib.error.URLError(ConnectionRefusedError(111, "Connection refused")), "refused"),
    (urllib.error.URLError(TimeoutError("timed out")), "timeout"),
    (urllib.error.URLError(socket.timeout("timed out")), "timeout"),
    (urllib.error.URLError(ConnectionResetError(104, "Connection reset by peer")), "reset"),
    (urllib.error.URLError(ssl.SSLCertVerificationError("bad cert")), "tls"),
    (urllib.error.URLError(ssl.SSLError("handshake failure")), "tls"),
    (http.client.BadStatusLine("garbage"), "protocol"),
    (urllib.error.URLError(ValueError("something else")), "other"),
    (ValueError("not even a URLError"), "other"),
]


@pytest.mark.parametrize("error,kind", CLASSIFY_CASES)
def test_classify(error, kind):
    assert live.classify(error) == kind
    assert kind in exchange.FAILURE_KINDS


def test_remote_disconnected_is_a_reset():
    # It subclasses both ConnectionResetError and BadStatusLine; the reset
    # branch must win, so do NOT add a separate RemoteDisconnected branch --
    # it would be unreachable. Bare, not URLError-wrapped: urllib's
    # do_open wraps only what h.request() raises, and getresponse() sits
    # outside that guard, so this arrives exactly as constructed here.
    assert live.classify(http.client.RemoteDisconnected("closed")) == "reset"


def test_an_http_error_is_a_response_not_a_failure():
    error = urllib.error.HTTPError("https://a.test/", 403, "Forbidden", None, None)
    assert live.classify(error) is None


def test_fetch_returns_an_iterable_of_one_exchange():
    opener = FakeOpener(FakeResponse("https://example.com/", pairs=[("Server", "nginx")]))
    result = live.fetch("https://example.com/", OPTIONS, opener=opener)
    assert len(result) == 1
    assert isinstance(result[0], exchange.Exchange)
    assert result[0].kind == "live"
    assert result[0].target == "https://example.com/"
    assert result[0].status == 200


def test_fetch_hands_over_headers_the_library_can_read():
    opener = FakeOpener(
        FakeResponse("https://example.com/", pairs=[("Server", "nginx"), ("Server", "b")])
    )
    item = live.fetch("https://example.com/", OPTIONS, opener=opener)[0]
    # parse_headers keeps duplicates as a list under a lowercased name.
    assert item.headers["server"] == ["nginx", "b"]


def test_fetch_sends_the_user_agent_and_extra_headers():
    options = OPTIONS._replace(headers=["X-Test: yes", "Cookie: a=1"])
    opener = FakeOpener(FakeResponse("https://example.com/"))
    live.fetch("https://example.com/", options, opener=opener)
    sent = opener.request
    assert sent.get_header("User-agent") == "test-agent"
    assert sent.get_header("X-test") == "yes"
    assert sent.get_header("Cookie") == "a=1"


def test_fetch_treats_an_error_status_as_a_response():
    error = urllib.error.HTTPError("https://example.com/", 403, "Forbidden", None, None)
    error.headers = email.message.Message()
    opener = FakeOpener(error)
    item = live.fetch("https://example.com/", OPTIONS, opener=opener)[0]
    assert item.status == 403


def test_fetch_turns_a_transport_error_into_a_classified_failure():
    opener = FakeOpener(urllib.error.URLError(socket.gaierror(-2, "no such host")))
    result = live.fetch("https://nope.test/", OPTIONS, opener=opener)
    assert len(result) == 1
    assert isinstance(result[0], exchange.Failure)
    assert result[0].kind == "dns"
    assert result[0].target == "https://nope.test/"


def test_raw_blobs_are_absent_unless_asked_for():
    opener = FakeOpener(FakeResponse("https://example.com/"))
    item = live.fetch("https://example.com/", OPTIONS, opener=opener)[0]
    assert item.raw_response is None
    assert item.raw_request is None


def test_raw_blobs_round_trip_through_the_library_parser():
    from http_security_test import parse_raw_headers

    options = OPTIONS._replace(raw=True)
    opener = FakeOpener(
        FakeResponse("https://example.com/", pairs=[("Server", "nginx")])
    )
    item = live.fetch("https://example.com/", options, opener=opener)[0]
    assert parse_raw_headers(item.raw_response)["server"] == ["nginx"]
    assert item.raw_request.startswith("GET / HTTP/1.1")


def test_the_chain_follows_an_in_scope_redirect():
    chain = live._Chain(("example.com", "*.example.com"))
    request = urllib.request.Request("https://example.com/")
    result = chain.redirect_request(
        request, None, 302, "Found", email.message.Message(), "https://www.example.com/"
    )
    assert result is not None
    assert chain.hops[-1].followed is True


def test_the_chain_refuses_an_out_of_scope_redirect():
    chain = live._Chain(("example.com", "*.example.com"))
    request = urllib.request.Request("https://example.com/")
    result = chain.redirect_request(
        request, None, 302, "Found", email.message.Message(), "https://evil.test/"
    )
    assert result is None
    assert chain.hops[-1].followed is False
    assert chain.hops[-1].refused == "scope"
    assert chain.hops[-1].destination == "https://evil.test/"


def test_the_chain_records_a_refusal_when_redirects_are_off():
    chain = live._Chain(("example.com",), follow=False)
    request = urllib.request.Request("https://example.com/")
    assert (
        chain.redirect_request(
            request, None, 301, "Moved", email.message.Message(), "https://example.com/x"
        )
        is None
    )
    assert chain.hops[-1].refused == "no-redirect"


def test_build_opener_installs_a_proxy_for_both_schemes():
    options = OPTIONS._replace(proxy="http://127.0.0.1:8080")
    opener, chain = live.build_opener(options)
    proxies = [
        h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)
    ]
    assert len(proxies) == 1
    assert proxies[0].proxies["https"] == "http://127.0.0.1:8080"
    assert chain.patterns == options.patterns


def test_build_opener_disables_verification_only_when_insecure():
    # The default opener also carries an HTTPSHandler with a context, so the
    # test has to look at verify_mode rather than at whether one exists.
    def verify_modes(options):
        opener, _ = live.build_opener(options)
        return [
            h._context.verify_mode
            for h in opener.handlers
            if isinstance(h, urllib.request.HTTPSHandler)
        ]

    assert ssl.CERT_NONE not in verify_modes(OPTIONS)
    assert ssl.CERT_NONE in verify_modes(OPTIONS._replace(insecure=True))


def test_the_chain_stops_at_the_redirect_limit():
    chain = live._Chain(("*.example.com", "example.com"), limit=1)
    request = urllib.request.Request("https://example.com/")
    chain.redirect_request(
        request, None, 302, "Found", email.message.Message(), "https://a.example.com/"
    )
    chain.redirect_request(
        request, None, 302, "Found", email.message.Message(), "https://b.example.com/"
    )
    assert chain.hops[-1].refused == "max-redirects"


class _LoopingRedirectHandler(http.server.BaseHTTPRequestHandler):
    """302s between /a and /b forever -- a redirect loop with no natural end."""

    def do_GET(self):
        other = "/b" if self.path == "/a" else "/a"
        self.send_response(302)
        self.send_header("Location", other)
        self.end_headers()

    def log_message(self, *args, **kwargs):
        pass  # keep test output quiet


def test_max_redirects_above_ten_is_honoured_past_urllibs_own_ceiling():
    # urllib.request.HTTPRedirectHandler carries its own max_redirections (10)
    # and max_repeats (4), applied to every redirect AFTER redirect_request()
    # runs. Left at their defaults, urllib's ceiling fires first at or above
    # 10 hops on a two-URL loop, raises HTTPError carrying the 3xx, and
    # fetch() would treat that as an ordinary response -- no refusal
    # recorded, indistinguishable from a site that genuinely answered 302.
    # That interaction lives in urllib's own bookkeeping rather than in
    # _Chain, so a loopback server is the only way to observe it -- a
    # loopback HTTP server is explicitly allowed for exactly this reason.
    server = http.server.HTTPServer(("127.0.0.1", 0), _LoopingRedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        options = OPTIONS._replace(max_redirects=20, patterns=("127.0.0.1",))
        target = "http://127.0.0.1:%d/a" % port
        item = live.fetch(target, options)[0]
        followed = [hop for hop in item.hops if hop.followed]
        assert len(followed) == 20  # the flag is honoured well past urllib's 10
        assert item.hops[-1].followed is False
        assert item.hops[-1].refused == "max-redirects"
    finally:
        server.shutdown()
        thread.join(timeout=5)
