#!/usr/bin/python3
# fmt: off

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

import collections
import os
import pathlib
from unittest import mock

import pytest

import http_security_test as headers
from http_security_test import hsts, policies

# ---------------------------------------------------------------------------
# Per-header analyzers
# ---------------------------------------------------------------------------
# Each case is (header, value, expected codes). analyze() looks at one header in
# isolation, so these never involve suppression.

ANALYZER_CASES = [
    # Content-Security-Policy
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'", []),
    ("Content-Security-Policy", "default-src 'self'", ["csp-no-frame-ancestors", "csp-no-base-uri"]),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'unsafe-inline'", ["csp-unsafe-inline"]),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'unsafe-eval'", ["csp-unsafe-eval"]),
    ("Content-Security-Policy", "img-src 'self'; base-uri 'none'; frame-ancestors 'none'", ["csp-no-default-src", "csp-no-object-src"]),
    ("Content-Security-Policy", "default-src *; base-uri 'none'; frame-ancestors 'none'", ["csp-wildcard"]),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors *", ["csp-frame-ancestors-wildcard"]),
    # A nonce or a hash makes browsers ignore 'unsafe-inline' in the same list,
    # which is why strict-CSP guidance tells you to serve both
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'nonce-r4nd0mV4lue=' 'strict-dynamic' 'unsafe-inline' https:", []),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; style-src 'sha384-AbC=' 'unsafe-inline'", []),
    # ...but only in the list that carries it: script-src and style-src are
    # evaluated separately
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'nonce-r4nd0mV4lue=' 'unsafe-inline'; style-src 'unsafe-inline'", ["csp-unsafe-inline-style"]),
    # Inline scripts and inline styles are different defects: a nonced script-src
    # still stops script injection, whatever style-src allows, so they are
    # reported separately rather than as one verdict on the policy.
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; style-src 'unsafe-inline'", ["csp-unsafe-inline-style"]),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'", ["csp-unsafe-inline", "csp-unsafe-inline-style"]),
    # Inline content is governed by -elem (an inline <script> or <style>) and
    # -attr (an event handler or a style attribute), each falling back to its
    # base directive and then to default-src. Checking only the base directive
    # misses a policy that overrides one surface.
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'self'; script-src-elem 'unsafe-inline'", ["csp-unsafe-inline"]),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'self'; script-src-attr 'unsafe-inline'", ["csp-unsafe-inline"]),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; style-src 'self'; style-src-elem 'unsafe-inline'", ["csp-unsafe-inline-style"]),
    # inherited from default-src, with no script-src or style-src in sight
    ("Content-Security-Policy", "default-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'", ["csp-unsafe-inline", "csp-unsafe-inline-style"]),
    # 'strict-dynamic' makes the allowlist and 'unsafe-inline' inert, but only
    # for script: it has no meaning in a style list.
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'strict-dynamic' 'unsafe-inline' https:", []),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; style-src 'strict-dynamic' 'unsafe-inline'", ["csp-unsafe-inline-style"]),
    # unquoted, nonce-abc is a host source and silences nothing
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src nonce-abc 'unsafe-inline'", ["csp-unsafe-inline", "csp-invalid-keyword"]),
    # Syntax defects: a policy that does not say what it appears to say. A
    # browser reads it, discards the broken part, and enforces the rest without
    # complaint, so these survive review precisely because the header looks right.
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'self' object-src 'none'", ["csp-missing-semicolon"]),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src self", ["csp-invalid-keyword"]),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'unsafe-inlien'", ["csp-invalid-keyword"]),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; scritp-src 'self'", ["csp-unknown-directive"]),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; reflected-xss block", ["csp-deprecated-directive"]),
    # ...but directives that take bare tokens of their own must not be mistaken
    # for source lists with forgotten quotes
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; sandbox allow-scripts", []),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; trusted-types 'none'", []),
    # A bare scheme where script comes from admits every host reachable over it
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src https:", ["csp-plain-scheme"]),
    # ...unless 'strict-dynamic' is there to make the allowlist inert, which is
    # the documented fallback for browsers that do not support it
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'nonce-r4nd0mV4lue=' 'strict-dynamic' https:", []),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src http://cdn.example.com", ["csp-http-source"]),
    # a development entry that reached production
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 127.0.0.1:*", ["csp-ip-source"]),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'nonce-abc'", ["csp-nonce-weak"]),
    ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'nonce-sh0rt!!'", ["csp-nonce-weak"]),
    # Strict-Transport-Security
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains", []),
    ("Strict-Transport-Security", "includeSubDomains", ["hsts-malformed"]),
    ("Strict-Transport-Security", "max-age=abc", ["hsts-malformed"]),
    ("Strict-Transport-Security", "max-age=0; includeSubDomains", ["hsts-max-age-zero"]),
    ("Strict-Transport-Security", "max-age=31536000", ["hsts-no-include-subdomains"]),
    # Regression: the old substring test read this as max-age=0
    ("Strict-Transport-Security", "max-age=086400; includeSubDomains", ["hsts-max-age-short"]),
    # preload is a submission to a list with entry requirements: below one year,
    # or without includeSubDomains, the domain is not accepted and the token does
    # nothing while the operator believes otherwise.
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload", []),
    # exactly on the floor: long enough to stick, still short of preload's year
    ("Strict-Transport-Security", "max-age=15552000; preload", ["hsts-no-include-subdomains", "hsts-preload-ineffective"]),
    ("Strict-Transport-Security", "max-age=31536000; preload", ["hsts-no-include-subdomains", "hsts-preload-ineffective"]),
    ("Strict-Transport-Security", "max-age=15768000; includeSubDomains; preload", ["hsts-preload-ineffective"]),
    # X-Frame-Options
    ("X-Frame-Options", "DENY", []),
    ("X-Frame-Options", "sameorigin", []),
    ("X-Frame-Options", "ALLOW-FROM https://example.com", ["xfo-allow-from"]),
    ("X-Frame-Options", "ALLOWALL", ["xfo-invalid"]),
    # X-Content-Type-Options -- not checked at all before this backport
    ("X-Content-Type-Options", "nosniff", []),
    ("X-Content-Type-Options", "sniff", ["xcto-invalid"]),
    # Referrer-Policy
    ("Referrer-Policy", "no-referrer", []),
    ("Referrer-Policy", "strict-origin-when-cross-origin", []),
    ("Referrer-Policy", "unsafe-url", ["rp-unsafe-url"]),
    ("Referrer-Policy", "nonsense", ["rp-invalid"]),
    # the list is a fallback chain: the last recognised token is the one that
    # applies, so an old spelling may lead and a modern policy follow
    ("Referrer-Policy", "no-referrer, unsafe-url", ["rp-unsafe-url"]),
    ("Referrer-Policy", "unsafe-url, strict-origin-when-cross-origin", []),
    ("Referrer-Policy", "strict-origin, bogus", []),
    ("Referrer-Policy", "", ["rp-invalid"]),
    ("Referrer-Policy", "bogus,", ["rp-invalid"]),
    # Permissions-Policy
    ("Permissions-Policy", "geolocation=(), camera=(self)", []),
    ("Permissions-Policy", 'camera=(self "https://example.com")', []),
    ("Permissions-Policy", "geolocation 'self'; camera 'none'", ["pp-legacy-syntax"]),
    ("Permissions-Policy", "geolocation=(self), camera", ["pp-invalid"]),
    ("Permissions-Policy", "geolocation=*", ["pp-wildcard"]),
    ("Permissions-Policy", "fullscreen=(*)", ["pp-wildcard"]),
    ("Permissions-Policy", "", ["pp-empty"]),
    # Cross-origin trio
    ("Cross-Origin-Opener-Policy", "same-origin", []),
    ("Cross-Origin-Opener-Policy", "unsafe-none", ["coop-unsafe-none"]),
    # noopener-allow-popups severs the document's own opener while letting it
    # open popups that keep theirs -- protective, just not isolating
    ("Cross-Origin-Opener-Policy", "noopener-allow-popups", []),
    ("Cross-Origin-Embedder-Policy", "require-corp", []),
    ("Cross-Origin-Embedder-Policy", "nonsense", ["coep-invalid"]),
    ("Cross-Origin-Embedder-Policy", "unsafe-none", ["coep-unsafe-none"]),
    ("Cross-Origin-Resource-Policy", "same-origin", []),
    ("Cross-Origin-Resource-Policy", "cross-origin", ["corp-cross-origin"]),
    ("Cross-Origin-Resource-Policy", "nonsense", ["corp-invalid"]),
    # all three are structured field items: the report-to parameter the HTML
    # standard's reporting integration adds does not change the policy
    ("Cross-Origin-Opener-Policy", 'same-origin; report-to="coop"', []),
    ("Cross-Origin-Embedder-Policy", 'require-corp; report-to="coep"', []),
    ("Cross-Origin-Resource-Policy", 'same-origin; report-to="corp"', []),
    ("Cross-Origin-Opener-Policy", 'unsafe-none; report-to="coop"', ["coop-unsafe-none"]),
    # CORS: the header carries one origin or the wildcard, and nothing else
    ("Access-Control-Allow-Origin", "https://example.test", []),
    ("Access-Control-Allow-Origin", "null", ["acao-null"]),
    ("Access-Control-Allow-Origin", "https://a.test https://b.test", ["acao-multiple-origins"]),
    ("Access-Control-Allow-Origin", "https://a.test, https://b.test", ["acao-multiple-origins"]),
    ("Access-Control-Allow-Origin", "*", ["acao-wildcard"]),
    # All three engines compare this header byte-for-byte against the request's
    # serialized origin -- Chromium `*allow_origin_header != origin.Serialize()`,
    # Firefox `!allowedOriginHeader.Equals(origin)`, WebKit
    # `accessControlOriginString != securityOriginString`. So a value that is
    # not a serialized origin matches nothing, ever, and the CORS the operator
    # configured is simply not happening.
    ("Access-Control-Allow-Origin", "https://*.example.test", ["acao-invalid-origin"]),
    ("Access-Control-Allow-Origin", "*.example.test", ["acao-invalid-origin"]),
    ("Access-Control-Allow-Origin", "example.test", ["acao-invalid-origin"]),
    # a serialized origin has no path -- not even the bare slash a copy-paste
    # from the address bar leaves behind
    ("Access-Control-Allow-Origin", "https://example.test/", ["acao-invalid-origin"]),
    ("Access-Control-Allow-Origin", "https://example.test/api", ["acao-invalid-origin"]),
    ("Access-Control-Allow-Origin", "https://example.test?x=1", ["acao-invalid-origin"]),
    ("Access-Control-Allow-Origin", "https://example.test#f", ["acao-invalid-origin"]),
    ("Access-Control-Allow-Origin", "https://user@example.test", ["acao-invalid-origin"]),
    # the request's origin is always serialized lower-case, and no engine folds
    # case before comparing, so a capitalised one can never match either
    ("Access-Control-Allow-Origin", "https://Example.test", ["acao-invalid-origin"]),
    ("Access-Control-Allow-Origin", "HTTPS://example.test", ["acao-invalid-origin"]),
    # ...and the shapes that are valid serialized origins must stay silent
    ("Access-Control-Allow-Origin", "https://example.test:8443", []),
    ("Access-Control-Allow-Origin", "http://localhost:3000", []),
    ("Access-Control-Allow-Origin", "moz-extension://a1b2c3", []),
    # Content-Type. Only the charset parameter is decidable from a header that
    # describes a body nobody here sees, and only for markup a browser parses.
    ("Content-Type", "text/html; charset=UTF-8", []),
    ("Content-Type", "text/html;charset=utf-8", []),
    ("Content-Type", 'text/html; charset="utf-8"', []),
    # the media type and the parameter name are both case-insensitive
    ("Content-Type", "Text/HTML; CharSet=UTF-8", []),
    ("Content-Type", "text/html", ["ct-no-charset"]),
    ("Content-Type", "text/html; boundary=x", ["ct-no-charset"]),
    # present but empty declares nothing
    ("Content-Type", "text/html; charset=", ["ct-no-charset"]),
    # JSON is UTF-8 by definition and plain text is never parsed as markup
    ("Content-Type", "application/json", []),
    ("Content-Type", "text/plain", []),
    ("Content-Type", "image/png", []),
    # Clear-Site-Data. The types are quoted strings and the quotes are load
    # bearing: Chromium splits the header on commas, trims, and compares each
    # token against a constant that includes them (net/url_request/
    # clear_site_data.cc), so an unquoted type matches nothing and is dropped
    # without complaint. A logout sending it clears nothing.
    ("Clear-Site-Data", '"cache", "cookies", "storage"', []),
    ("Clear-Site-Data", '"*"', []),
    ("Clear-Site-Data", '"cookies"', []),
    # whitespace around a member is trimmed, and quoting is all that matters
    ("Clear-Site-Data", '  "cookies" ,"storage"  ', []),
    ("Clear-Site-Data", "cookies", ["csd-unquoted"]),
    ("Clear-Site-Data", "cache, cookies, storage", ["csd-unquoted"]),
    ("Clear-Site-Data", "*", ["csd-unquoted"]),
    # one quoted member is enough to keep the header working, so the unquoted
    # one beside it is a partial defect rather than a dead header
    ("Clear-Site-Data", '"cookies", storage', ["csd-unquoted"]),
    # spec-defined but unimplemented is not the same as misspelled: Chromium
    # has no executionContexts, and the spec has no storag
    ("Clear-Site-Data", '"executionContexts"', []),
    ("Clear-Site-Data", '"storag"', ["csd-unknown-type"]),
    ("Clear-Site-Data", '"cookies", "storag"', ["csd-unknown-type"]),
    # the comparison is byte-for-byte, so the camelCase spellings are the only
    # ones that work and a plausible-looking "Cookies" clears nothing
    ("Clear-Site-Data", '"Cookies"', ["csd-unknown-type"]),
    ("Clear-Site-Data", '"clienthints"', ["csd-unknown-type"]),
    # both defects at once come out worst-first
    ("Clear-Site-Data", '"storag", cookies', ["csd-unquoted", "csd-unknown-type"]),
    # the bucket form Chromium accepts, and the empty header that says nothing
    ("Clear-Site-Data", '"storage:inbox"', []),
    ("Clear-Site-Data", "", ["csd-empty"]),
    ("Clear-Site-Data", "   ", ["csd-empty"]),
    # Integrity-Policy. A structured field dictionary whose members are inner
    # lists of tokens, and every case below is pinned by the cross-browser test
    # suite (wpt/subresource-integrity/integrity-policy/parsing.html), which is
    # worth more than the prose: several spellings that look right parse to
    # nothing and enforce nothing.
    ("Integrity-Policy", "blocked-destinations=(script)", []),
    ("Integrity-Policy", "blocked-destinations=(script), sources=(inline)", []),
    ("Integrity-Policy", "blocked-destinations=(script), endpoints=(ip-endpoint)", []),
    # inner list items are separated by spaces; the comma habit from CSP and
    # Permissions-Policy produces a header that parses to nothing
    ("Integrity-Policy", "blocked-destinations=(script,style)", ["ip-invalid"]),
    # ...as does a bare token, a quoted string, or an unclosed list
    ("Integrity-Policy", "blocked-destinations=script", ["ip-invalid"]),
    ("Integrity-Policy", 'blocked-destinations=("script")', ["ip-invalid"]),
    ("Integrity-Policy", "blocked-destinations=('script')", ["ip-invalid"]),
    ("Integrity-Policy", "blocked-destinations=(script", ["ip-invalid"]),
    ("Integrity-Policy", "blocked-destinations=(script), sources=(invalid", ["ip-invalid"]),
    # parses, but nothing is left that any browser acts on
    ("Integrity-Policy", "", ["ip-no-blocked-destinations"]),
    ("Integrity-Policy", "endpoints=(e)", ["ip-no-blocked-destinations"]),
    ("Integrity-Policy", "blocked-destinations=()", ["ip-no-blocked-destinations"]),
    ("Integrity-Policy", "blocked-destinations=(scripts)", ["ip-no-blocked-destinations"]),
    # style is in the specification and in no engine, so alone it blocks nothing
    ("Integrity-Policy", "blocked-destinations=(style)", ["ip-no-blocked-destinations"]),
    # ...but beside a destination that works it costs nothing; script still blocks
    ("Integrity-Policy", "blocked-destinations=(script style)", ["ip-style-unsupported"]),
    ("Integrity-Policy", "blocked-destinations=(script scripts)", ["ip-unknown-destination"]),
    # The trap. `sources` defaults to (inline) when absent, but once present it
    # must say so: the browser appends inline only if the list is missing or
    # already contains it, so a sources that omits it leaves nothing enforcing
    # while blocked-destinations is spelled perfectly.
    ("Integrity-Policy", "blocked-destinations=(script), sources=(telepathy)", ["ip-sources-without-inline"]),
    ("Integrity-Policy", "blocked-destinations=(script), sources=()", ["ip-sources-without-inline"]),
    # an extra token beside inline is ignored and costs nothing
    ("Integrity-Policy", "blocked-destinations=(script), sources=(inline telepathy)", []),
    # Deprecated headers
    ("Expect-CT", "max-age=86400, enforce", ["ect-deprecated"]),
    # Never standardised rather than withdrawn: OWASP's own browser testing
    # found DNS prefetching is a Chromium behaviour and that only Chrome acts
    # on the header at all, so it is a Chrome-only measure, not a policy.
    ("X-DNS-Prefetch-Control", "off", ["xdpc-nonstandard"]),
    ("X-DNS-Prefetch-Control", "on", ["xdpc-nonstandard"]),
    # Superseded, not dead: Chromium still enforces Feature-Policy, so a page
    # sending only this one is protected there and nowhere else
    ("Feature-Policy", "geolocation 'none'", ["fp-deprecated"]),
    ("Feature-Policy", "geolocation *", ["fp-deprecated", "fp-wildcard"]),
    ("Feature-Policy", "", ["fp-deprecated", "fp-empty"]),
    # every browser removed key pinning, so the pins bind nothing
    ("Public-Key-Pins", 'max-age=5184000; pin-sha256="abc="', ["hpkp-deprecated"]),
    # IE-only, and IE is retired: the values carry nothing worth parsing
    ("P3P", 'CP="CAO PSA OUR"', ["p3p-deprecated"]),
    ("P3P", 'CP="This is not a P3P policy!"', ["p3p-deprecated"]),
    ("X-Download-Options", "noopen", ["xdo-deprecated"]),
    ("Public-Key-Pins-Report-Only", 'pin-sha256="abc="', ["hpkp-ro-deprecated"]),
    # the vendor-prefixed CSP spellings, unread since Firefox 23 / Chrome 25
    ("X-Content-Security-Policy", "default-src 'self'", ["xcsp-deprecated"]),
    ("X-WebKit-CSP", "default-src 'self'", ["xwkcsp-deprecated"]),
    ("X-Permitted-Cross-Domain-Policies", "none", ["xpcdp-deprecated"]),
    ("X-Permitted-Cross-Domain-Policies", "none-this-response", ["xpcdp-deprecated"]),
    ("X-Permitted-Cross-Domain-Policies", "all", ["xpcdp-all"]),
    ("X-Permitted-Cross-Domain-Policies", "master-only", ["xpcdp-policy-file"]),
    ("X-Permitted-Cross-Domain-Policies", "nonsense", ["xpcdp-invalid"]),
    ("X-XSS-Protection", "0", ["xxp-deprecated"]),
    ("X-XSS-Protection", "1", ["xxp-enabled"]),
    ("X-XSS-Protection", "1; mode=block", ["xxp-blocked"]),
    ("X-XSS-Protection", "2", ["xxp-invalid"]),
]


@pytest.mark.parametrize("name,value,expected", ANALYZER_CASES)
def test_analyze_returns_expected_codes(name, value, expected):
    assert [f.code for f in headers.analyze(name, value)] == expected


def test_analyze_ignores_unknown_headers():
    assert headers.analyze("X-Whatever", "anything") == []


def test_analyze_ignores_none_values():
    assert headers.analyze("X-Frame-Options", None) == []


def test_inline_findings_name_the_directive_actually_consulted():
    """The offending list may be spelled under a directive the operator never
    wrote, so pointing at script-src when the sources came from default-src
    sends them looking for something that is not there."""
    inherited = headers.analyze(
        "Content-Security-Policy", "default-src 'unsafe-inline'; base-uri 'none'"
    )
    finding = next(f for f in inherited if f.code == "csp-unsafe-inline")
    assert finding.data == {"directives": ["default-src"]}
    assert "in default-src" in headers.describe(finding)

    overridden = headers.analyze(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self'; script-src-elem 'unsafe-inline'",
    )
    finding = next(f for f in overridden if f.code == "csp-unsafe-inline")
    assert finding.data == {"directives": ["script-src-elem"]}
    assert "in script-src-elem" in headers.describe(finding)


def test_preload_message_reads_cleanly_when_both_requirements_are_unmet():
    finding = next(
        f
        for f in headers.analyze("Strict-Transport-Security", "max-age=300; preload")
        if f.code == "hsts-preload-ineffective"
    )
    assert finding.data["unmet"] == ["include-subdomains", "max-age"]
    assert "requires includeSubDomains and a max-age of at least" in headers.describe(
        finding
    )


def test_findings_name_their_header():
    findings = headers.analyze("Strict-Transport-Security", "max-age=1")
    assert all(f.header == "Strict-Transport-Security" for f in findings)
    assert all(headers.describe(f) for f in findings)


# ---------------------------------------------------------------------------
# Cross-header suppression
# ---------------------------------------------------------------------------
# X-Frame-Options and the CSP frame-ancestors directive govern the same thing,
# so one gap must not be reported twice. Only an effective header suppresses.

SAFE_CSP = "default-src 'none'; base-uri 'none'"


def framing_codes(present):
    codes = [f.code for f in headers.analyze_all(present)]
    return sorted(c for c in codes if "frame" in c or c.startswith("xfo"))


def test_valid_xfo_suppresses_the_csp_frame_ancestors_finding():
    assert framing_codes({"content-security-policy": SAFE_CSP, "x-frame-options": "DENY"}) == []


def test_invalid_xfo_suppresses_nothing():
    codes = framing_codes({"content-security-policy": SAFE_CSP, "x-frame-options": "ALLOWALL"})
    assert codes == ["csp-no-frame-ancestors", "xfo-invalid"]


def test_allow_from_suppresses_nothing():
    codes = framing_codes({"content-security-policy": SAFE_CSP, "x-frame-options": "ALLOW-FROM https://a.com"})
    assert codes == ["csp-no-frame-ancestors", "xfo-allow-from"]


def test_frame_ancestors_suppresses_the_missing_xfo_finding():
    assert framing_codes({"content-security-policy": SAFE_CSP + "; frame-ancestors 'none'"}) == []


def test_wildcard_frame_ancestors_suppresses_nothing():
    # frame-ancestors * permits exactly what its absence permits
    codes = framing_codes({"content-security-policy": SAFE_CSP + "; frame-ancestors *"})
    assert codes == ["csp-frame-ancestors-wildcard", "xfo-missing"]


def test_neither_header_reports_the_missing_one():
    assert framing_codes({}) == ["xfo-missing"]


# ---------------------------------------------------------------------------
# Missing headers, and the secure flag
# ---------------------------------------------------------------------------


def test_every_security_header_is_reported_missing_when_none_are_present():
    # COEP is the exception: it buys cross-origin isolation only alongside a COOP
    # of same-origin, so on a response that asks for no isolation its absence is
    # the ordinary state of the web rather than a gap. It is still listed in the
    # caller's `missing` inventory -- that is a fact -- it just earns no finding.
    codes = {f.code for f in headers.analyze_all({})}
    assert codes == {"csp-missing", "coop-missing", "corp-missing",
                     "pp-missing", "rp-missing", "hsts-missing", "xcto-missing", "xfo-missing"}


def test_coep_is_reported_missing_once_coop_asks_for_isolation():
    codes = {f.code for f in headers.analyze_all({"cross-origin-opener-policy": "same-origin"})}
    assert "coep-missing" in codes


def test_hsts_is_not_reported_missing_on_a_plaintext_response():
    codes = {f.code for f in headers.analyze_all({}, secure=False)}
    assert "hsts-missing" not in codes
    assert "csp-missing" in codes


def test_a_present_hsts_header_is_still_analyzed_on_a_plaintext_response():
    codes = [f.code for f in headers.analyze_all({"strict-transport-security": "max-age=0"}, secure=False)]
    assert "hsts-max-age-zero" in codes


def test_a_finding_quotes_the_whole_value_it_was_sent():
    # the parameter is stripped to decide, not to report: the operator sent it
    finding, = headers.analyze("Cross-Origin-Opener-Policy", 'unsafe-none; report-to="coop"')
    assert finding.data == {"value": 'unsafe-none; report-to="coop"'}
    assert 'unsafe-none; report-to="coop"' in headers.describe(finding)


def test_missing_findings_are_ordered_the_same_on_every_run():
    # the tables are tuples, not sets, so output does not depend on hash seeding
    once = [f.code for f in headers.analyze_all({})]
    assert once == [f.code for f in headers.analyze_all({})]
    assert once[0] == "csp-missing"


# ---------------------------------------------------------------------------
# Header name casing
# ---------------------------------------------------------------------------
# Header names are case-insensitive, so analyze_all() takes them in any casing:
# a caller that has not lowercased its response must not be told that the
# headers it sent are missing.


def test_analyze_all_accepts_any_casing():
    codes = [f.code for f in headers.analyze_all({
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": SAFE_CSP + "; frame-ancestors 'none'",
        "REFERRER-POLICY": "no-referrer",
    })]
    assert "xfo-missing" not in codes
    assert "csp-missing" not in codes
    assert "rp-missing" not in codes
    # and the CSP it did analyze is the sound one, not a second, absent policy
    assert not [c for c in codes if c.startswith("csp-")]


def test_two_spellings_of_one_header_do_not_repeat_a_code():
    codes = [f.code for f in headers.analyze_all({
        "X-Frame-Options": "ALLOWALL",
        "x-frame-options": "ALLOWALL",
    })]
    assert codes.count("xfo-invalid") == 1


def test_two_spellings_of_a_name_are_one_header_with_two_values():
    # Header names are case-insensitive, so this response repeated the header
    # rather than sending two. Both values are real and both are analyzed.
    codes = [f.code for f in headers.analyze_all({
        "X-Frame-Options": "DENY",
        "x-frame-options": "ALLOWALL",
    })]
    assert "xfo-invalid" in codes
    assert "xfo-missing" not in codes
    # ...and the defect is named once, however many times it occurs
    assert codes.count("xfo-invalid") == 1


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def test_parse_csp_lowercases_directives_and_keeps_source_case():
    parsed = headers.parse_csp("Default-Src 'self' https://CDN.example.com/Path")
    assert parsed == {"default-src": ["'self'", "https://CDN.example.com/Path"]}


def test_parse_csp_keeps_the_first_of_a_repeated_directive():
    # CSP tells user agents to ignore repeats after the first
    assert headers.parse_csp("default-src 'self'; default-src *") == {"default-src": ["'self'"]}


def test_parse_permissions_policy_keeps_the_last_of_a_repeated_feature():
    # structured fields say the last member wins -- the opposite of CSP
    assert headers.parse_permissions_policy("geolocation=(self), geolocation=*") == {"geolocation": ["*"]}


def test_parse_feature_policy_reads_the_predecessor_syntax():
    # semicolons and space-separated allowlists, where the successor uses commas
    # and parentheses -- unquoted here so the two compare directly
    parsed = headers.parse_feature_policy("geolocation 'self' https://example.com; camera 'none'")
    assert parsed == {"geolocation": ["self", "https://example.com"], "camera": ["none"]}


def test_parse_permissions_policy_unwraps_allowlists():
    parsed = headers.parse_permissions_policy('camera=(self "https://example.com"), geolocation=()')
    assert parsed == {"camera": ["self", "https://example.com"], "geolocation": []}


# ---------------------------------------------------------------------------
# Taxonomy helpers
# ---------------------------------------------------------------------------

RESPONSE = {
    "server": "nginx/1.18",
    "cache-control": "no-store",
    "x-xss-protection": "0",
    "x-frame-options": "DENY",
}


def test_inventory_returns_canonical_names_and_values():
    found = headers.inventory(RESPONSE)
    assert found["information"] == {"Server": "nginx/1.18"}
    assert found["caching"] == {"Cache-Control": "no-store"}
    assert found["deprecated"] == {"X-XSS-Protection": "0"}
    assert found["security"] == {"X-Frame-Options": "DENY"}


def test_stack_fingerprinting_headers_are_inventoried():
    response = {
        "x-generator": "Drupal 10 (https://www.drupal.org)",
        "x-runtime": "0.019382",
        "x-drupal-cache": "HIT",
        "$wsep": "",
        "x-powered-by": "PHP/8.2",
    }
    found = headers.inventory(response)["information"]
    assert set(found) == {"$WSEP", "X-Drupal-Cache", "X-Generator", "X-Powered-By", "X-Runtime"}
    # inventoried, never judged: only a human can say whether a value is a leak
    assert headers.analyze("X-Generator", "Drupal 10") == []


def test_mesh_and_tracing_headers_are_inventoried_too():
    # The table is the union with OWASP's headers_remove.json, which reaches
    # past version banners into service-mesh plumbing: correlation identifiers
    # that map the internals, and per-hop latencies that time them.
    response = {
        "x-envoy-upstream-service-time": "12",
        "x-b3-traceid": "80f198ee56343ba8",
        "x-datadog-parent-id": "5678",
        "x-kong-upstream-latency": "3",
        "x-nextjs-matched-path": "/blog/[slug]",
        "x-dtagentid": "abc",
    }
    found = headers.inventory(response)["information"]
    assert set(found) == {
        "X-B3-TraceId",
        "X-Datadog-Parent-Id",
        "X-Envoy-Upstream-Service-Time",
        "X-Kong-Upstream-Latency",
        "X-Nextjs-Matched-Path",
        "X-dtAgentId",
    }
    # still an inventory: a name on this table earns no finding by being there
    assert headers.analyze_all(response, secure=True) == [
        f for f in headers.analyze_all({}, secure=True)
    ]


def test_the_information_table_keeps_the_names_this_project_had():
    # The union is not a replacement: OWASP's list lacks these four, and
    # adopting theirs wholesale would have quietly dropped them.
    assert set(headers.INFORMATION_HEADERS) >= {
        "X-Drupal-Cache",
        "X-Drupal-Dynamic-Cache",
        "X-Rack-Cache",
        "X-Runtime",
    }


def test_x_dns_prefetch_control_is_inventoried_as_one_to_drop():
    # It sits in the deprecated table without a -deprecated code: never
    # standardised is not the same as withdrawn, and the note says which.
    assert "X-DNS-Prefetch-Control" in headers.DEPRECATED_HEADERS
    found = headers.inventory({"x-dns-prefetch-control": "off"})["deprecated"]
    assert found == {"X-DNS-Prefetch-Control": "off"}


def test_integrity_policy_is_never_reported_missing():
    # Enforcing it means every script and stylesheet must carry integrity
    # metadata, which is a deployment commitment rather than a switch.
    assert "Integrity-Policy" not in headers.SECURITY_HEADERS
    assert not [f for f in headers.analyze_all({}) if f.code.startswith("ip-")]


def test_an_empty_charset_parameter_declares_nothing():
    # _charset() promises the charset or None, and "charset=" is neither a
    # declaration nor an absence until it is made one. _analyze_ct only asks
    # whether it is truthy, so nothing else would notice the difference.
    from http_security_test import response

    assert response._charset("text/html; charset=") is None
    assert response._charset("text/html") is None
    assert response._charset('text/html; charset="utf-8"') == "utf-8"
    assert response._charset("text/html; CharSet=UTF-8") == "UTF-8"


def test_content_type_is_never_reported_missing():
    # analyze_all sees no status line, and a 204 or 304 carries no
    # representation to describe, so absence decides nothing.
    assert "Content-Type" not in headers.SECURITY_HEADERS
    assert not [f for f in headers.analyze_all({}) if f.code.startswith("ct-")]


def test_clear_site_data_is_never_reported_missing():
    # It is what a logout endpoint sends, not something every response should
    # carry, so its absence is not a gap on any page.
    assert "Clear-Site-Data" not in headers.SECURITY_HEADERS
    assert not [f for f in headers.analyze_all({}) if f.code.startswith("csd-")]


def test_the_missing_inventory_is_a_fact_not_a_judgment():
    # HSTS is absent over plaintext and the inventory says so; the *finding* is
    # what secure=False suppresses. Deriving one from the other loses this.
    absent = headers.inventory({})["missing"]
    assert "Strict-Transport-Security" in absent
    assert absent == list(headers.SECURITY_HEADERS)
    reported = {f.code for f in headers.analyze_all({}, secure=False)}
    assert "hsts-missing" not in reported


def test_inventories_never_judge_what_they_list():
    # These two tables exist precisely because no finding can be made from
    # them: only a human can say whether a given banner is a leak.
    noisy = {n.lower(): "x" for n in headers.INFORMATION_HEADERS + headers.CACHE_HEADERS}
    assert {f.code for f in headers.analyze_all(noisy)} == {
        f.code for f in headers.analyze_all({})
    }
    assert len(headers.inventory(noisy)["information"]) == len(headers.INFORMATION_HEADERS)


def test_the_header_tables_do_not_overlap():
    security = set(headers.SECURITY_HEADERS)
    assert not security & set(headers.DEPRECATED_HEADERS)
    assert not security & set(headers.INFORMATION_HEADERS)
    assert not security & set(headers.CACHE_HEADERS)


# ---------------------------------------------------------------------------
# Invariants the JSON schema relies on
# ---------------------------------------------------------------------------
# findings is {severity: [code, ...]} with no header key. That is lossless only
# while a code identifies exactly one header and cannot repeat within a response.

EVERY_VALUE = [(name, value) for name, value, _ in ANALYZER_CASES]


# ---------------------------------------------------------------------------
# Cross-origin isolation
# ---------------------------------------------------------------------------
# COOP and COEP only buy cross-origin isolation together, so neither is judged
# alone: COEP's absence is a gap only on a page whose COOP asks for isolation,
# and a COEP that opts in while COOP does not is paying for nothing. These cases
# cover verdicts no single header produces by itself.

SEEKS = {"cross-origin-opener-policy": "same-origin"}

ISOLATION_CASES = [
    # nothing set: the ordinary state of the web, so COEP is not a gap
    ({}, ["coop-missing", "corp-missing"]),
    # Only the absence is excused as the ordinary state of the web. A response
    # that actually sent unsafe-none said something, and is answered for it.
    ({"cross-origin-embedder-policy": "unsafe-none"}, ["coep-unsafe-none", "coop-missing", "corp-missing"]),
    # ...and the same for the CORP value that permits what no header permits
    ({"cross-origin-resource-policy": "cross-origin"}, ["coop-missing", "corp-cross-origin"]),
    # COOP asks for isolation, so now COEP's absence really is a gap
    (dict(SEEKS), ["coep-missing", "corp-missing"]),
    (dict(SEEKS, **{"cross-origin-embedder-policy": "unsafe-none"}), ["coep-unsafe-none", "corp-missing"]),
    # both halves present: isolated, nothing to say
    (dict(SEEKS, **{"cross-origin-embedder-policy": "require-corp"}), ["corp-missing"]),
    # COEP opts in but COOP does not back it: cost without the benefit
    ({"cross-origin-embedder-policy": "require-corp"}, ["coep-no-isolation", "coop-missing", "corp-missing"]),
    # same-origin-allow-popups keeps the opener relationship, so browsers do not
    # grant crossOriginIsolated for it
    (
        {"cross-origin-opener-policy": "same-origin-allow-popups",
         "cross-origin-embedder-policy": "credentialless"},
        ["coep-no-isolation", "corp-missing"],
    ),
    # the reporting integration's parameters must not change any of this -- the
    # groups are defined here so that the isolation verdict is what is under
    # test and not the reporting cross-check
    (
        {"cross-origin-opener-policy": 'same-origin; report-to="coop"',
         "cross-origin-embedder-policy": 'require-corp; report-to="coep"',
         "reporting-endpoints": 'coop="https://example.test/c", coep="https://example.test/e"'},
        ["corp-missing"],
    ),
    # a typo is still a typo: the operator meant to opt in and did not
    (dict(SEEKS, **{"cross-origin-embedder-policy": "require-corps"}), ["coep-invalid", "corp-missing"]),
]


def cross_origin_codes(present):
    return sorted(
        f.code for f in headers.analyze_all(present) if f.code.startswith(("coep", "coop", "corp"))
    )


@pytest.mark.parametrize("present,expected", ISOLATION_CASES)
def test_cross_origin_isolation_is_judged_across_the_pair(present, expected):
    assert cross_origin_codes(present) == expected


def test_hardening_coop_adds_nothing_but_the_isolation_hint():
    # Moving from same-origin-allow-popups to the stronger same-origin must not
    # make the report worse. It does surface coep-missing -- the site is now one
    # header from isolation -- and the caller rates that as a hint, not a defect.
    weaker = set(cross_origin_codes({"cross-origin-opener-policy": "same-origin-allow-popups"}))
    stronger = set(cross_origin_codes({"cross-origin-opener-policy": "same-origin"}))
    assert stronger - weaker == {"coep-missing"}
    assert not weaker - stronger


def test_each_code_belongs_to_exactly_one_header():
    owners = {}
    for name, value in EVERY_VALUE:
        for finding in headers.analyze(name, value):
            owners.setdefault(finding.code, set()).add(finding.header)
    for finding in headers.analyze_all({}):
        owners.setdefault(finding.code, set()).add(finding.header)
    # duplicate-headers is the one code a response can raise against more than
    # one header, since any header may be repeated. Each Finding still names its
    # own header; it is only a code-keyed view of them that cannot tell apart.
    owners.pop("duplicate-headers", None)
    ambiguous = {code: owner for code, owner in owners.items() if len(owner) > 1}
    assert ambiguous == {}


def test_a_response_never_emits_the_same_code_twice():
    worst = {
        "content-security-policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval' *; frame-ancestors *",
        "strict-transport-security": "max-age=100",
        "x-frame-options": "ALLOW-FROM https://a.com",
        "x-content-type-options": "sniff",
        "referrer-policy": "unsafe-url",
        "permissions-policy": "geolocation=*",
        "cross-origin-opener-policy": "unsafe-none",
        "cross-origin-embedder-policy": "nonsense",
        "cross-origin-resource-policy": "nonsense",
        "expect-ct": "max-age=1",
        "x-permitted-cross-domain-policies": "all",
        "x-xss-protection": "1",
    }
    codes = [f.code for f in headers.analyze_all(worst)]
    assert len(codes) == len(set(codes))


# ---------------------------------------------------------------------------
# HSTS preload membership
# ---------------------------------------------------------------------------
# Whether a domain is on the list is the one question a response cannot answer
# about itself, and the list is too large to carry here -- so this is checked
# only when the optional hstspreload package is installed, and silently skipped
# when it is not.

PRELOAD_CLAIM = {"strict-transport-security": "max-age=63072000; includeSubDomains; preload"}


class FakePreloadList:
    """Stand-in for the optional hstspreload package."""

    def __init__(self, *listed):
        self.listed = set(listed)

    def in_hsts_preload(self, host):
        return host in self.listed


def preload_codes(present, host, package):
    with mock.patch.object(hsts, "hstspreload", package):
        return [f.code for f in headers.analyze_all(present, host=host)]


def test_a_preload_claim_goes_unchecked_without_the_optional_package():
    # the dependency is optional, so its absence must be silent
    assert "hsts-not-preloaded" not in preload_codes(PRELOAD_CLAIM, "example.com", None)


def test_a_domain_claiming_preload_but_absent_from_the_list_is_reported():
    codes = preload_codes(PRELOAD_CLAIM, "example.com", FakePreloadList("elsewhere.test"))
    assert "hsts-not-preloaded" in codes


def test_a_genuinely_preloaded_domain_is_not_reported():
    codes = preload_codes(PRELOAD_CLAIM, "example.com", FakePreloadList("example.com"))
    assert "hsts-not-preloaded" not in codes


def test_a_domain_that_never_claimed_preload_is_not_reported():
    present = {"strict-transport-security": "max-age=63072000; includeSubDomains"}
    assert "hsts-not-preloaded" not in preload_codes(present, "example.com", FakePreloadList())


def test_membership_is_unchecked_when_the_caller_gives_no_host():
    # analyze_all stays usable without one; it just cannot answer this
    codes = preload_codes(PRELOAD_CLAIM, None, FakePreloadList())
    assert "hsts-not-preloaded" not in codes


# ---------------------------------------------------------------------------
# Severity policy
# ---------------------------------------------------------------------------
# Every code the module can emit needs a rating, or findings quietly fall back
# to the default. The corpus above is what makes that checkable.


def _every_finding_headers_can_emit():
    """Every finding the corpus can produce, not just its code.

    The severity tests only need the codes, but the catalog tests need the
    findings themselves: a template that names a field the data does not carry
    is only discoverable by rendering one.
    """
    return [f for f in _emitted()]


def _emitted():
    for name, value, _ in ANALYZER_CASES:
        yield from headers.analyze(name, value)
    for present in (
        {},
        BOTH,
        WILDCARD_WITH_CREDENTIALS,
        REPORT_ONLY_ONLY,
        REPORTS_NOWHERE,
        CSP_REPORTS_NOWHERE,
        COOP_REPORTS_NOWHERE,
        COEP_REPORTS_NOWHERE,
        UNDELIVERABLE_ENDPOINT,
        INVALID_ENDPOINTS,
        LEGACY_UNDELIVERABLE,
        LEGACY_INVALID,
        {"x-frame-options": ["DENY", "SAMEORIGIN"]},
    ):
        yield from headers.analyze_all(present)
    # the -ineffective pair needs the response to have arrived over plaintext,
    # which no other case in this corpus does
    for present in (DEFINED_ENDPOINT, LEGACY_DEFINED):
        yield from headers.analyze_all(present, secure=False, host="example.test")
    for present, _ in ISOLATION_CASES:
        yield from headers.analyze_all(present)
    with mock.patch.object(hsts, "hstspreload", FakePreloadList()):
        yield from headers.analyze_all(PRELOAD_CLAIM, host="example.com")


def _every_code_headers_can_emit():
    codes = {f.code for name, value, _ in ANALYZER_CASES for f in headers.analyze(name, value)}
    codes |= {f.code for f in headers.analyze_all({})}
    # Some codes exist only in combinations -- coep-no-isolation is about the
    # COOP/COEP pair and no single header can produce it.
    codes |= {
        f.code
        for present, _ in ISOLATION_CASES
        for f in headers.analyze_all(present)
    }
    # ...and fp-conflicts and acao-credentials-wildcard each need a pair
    codes |= {f.code for f in headers.analyze_all(BOTH)}
    codes |= {f.code for f in headers.analyze_all(WILDCARD_WITH_CREDENTIALS)}
    codes |= {f.code for f in headers.analyze_all(REPORT_ONLY_ONLY)}
    # ...and ip-endpoints-undefined needs a policy naming a group beside a
    # Reporting-Endpoints header that does not define it
    codes |= {f.code for f in headers.analyze_all(REPORTS_NOWHERE)}
    # ...and the three other headers that name a reporting group the same way
    for present in (CSP_REPORTS_NOWHERE, COOP_REPORTS_NOWHERE, COEP_REPORTS_NOWHERE,
                    UNDELIVERABLE_ENDPOINT, INVALID_ENDPOINTS, LEGACY_UNDELIVERABLE,
                    LEGACY_INVALID):
        codes |= {f.code for f in headers.analyze_all(present)}
    # ...and the -ineffective pair, which only exists on a plaintext response
    for present in (DEFINED_ENDPOINT, LEGACY_DEFINED):
        codes |= {
            f.code for f in headers.analyze_all(present, secure=False, host="example.test")
        }
    codes |= {f.code for f in headers.analyze_all({"x-frame-options": ["DENY", "SAMEORIGIN"]})}
    # hsts-not-preloaded needs the optional preload list to be emittable at all
    with mock.patch.object(hsts, "hstspreload", FakePreloadList()):
        codes |= {
            f.code for f in headers.analyze_all(PRELOAD_CLAIM, host="example.com")
        }
    return codes


def test_every_finding_code_has_a_severity():
    assert _every_code_headers_can_emit() <= set(headers.FINDING_SEVERITY)


def test_no_severity_is_mapped_for_a_code_that_cannot_be_emitted():
    assert set(headers.FINDING_SEVERITY) <= _every_code_headers_can_emit()


# ---------------------------------------------------------------------------
# The report schema
# ---------------------------------------------------------------------------
# report() is the whole analysis as plain data: a list of findings and the
# inventories. Findings are a list rather than codes grouped under a severity,
# because a code is no longer unique within a response -- duplicate-headers
# names several headers today, and per-cookie findings will repeat within one.


def test_report_is_json_serialisable_with_no_encoder():
    import json

    encoded = json.dumps(headers.report(RESPONSE))
    assert json.loads(encoded) == headers.report(RESPONSE)


def test_the_two_sides_are_nested_so_a_header_name_is_never_ambiguous():
    # Cache-Control is both a request and a response header, so once requests
    # are analysed a bare "header" field could not say which one it meant.
    out = headers.report(RESPONSE)
    assert set(out) == {"response"}
    assert set(out["response"]) == {"findings", "inventory"}


def test_a_finding_row_carries_its_level_and_data():
    row, = [
        r
        for r in headers.report({"x-frame-options": "ALLOWALL"})["response"]["findings"]
        if r["code"] == "xfo-invalid"
    ]
    assert row == {
        "header": "X-Frame-Options",
        "code": "xfo-invalid",
        "level": "error",
        "data": {"value": "ALLOWALL"},
        "message": headers.describe(headers.Finding(
            "X-Frame-Options", "xfo-invalid", {"value": "ALLOWALL"}
        )),
    }


def test_data_is_always_present_even_when_empty():
    # so a consumer never has to test for the key
    rows = headers.report({})["response"]["findings"]
    assert all("data" in row for row in rows)
    assert all(row["data"] == {} for row in rows if row["code"].endswith("-missing"))


def test_the_message_can_be_left_out_entirely():
    rows = headers.report(RESPONSE, message=False)["response"]["findings"]
    assert rows
    assert all("message" not in row for row in rows)
    assert all(row["data"] is not None for row in rows)


def test_findings_come_out_worst_first():
    levels = [
        r["level"]
        for r in headers.report({"x-frame-options": "ALLOWALL"})["response"]["findings"]
    ]
    assert levels == sorted(levels, key=headers.SEVERITIES.index)


def test_one_code_may_appear_twice_in_a_report():
    # the shape the old severity-keyed schema could not express
    rows = headers.report({"x-frame-options": ["ALLOWALL", "NONSENSE"]})["response"]["findings"]
    invalid = [r for r in rows if r["code"] == "xfo-invalid"]
    assert [r["data"]["value"] for r in invalid] == ["ALLOWALL", "NONSENSE"]


def test_the_report_carries_all_four_inventories():
    assert set(headers.report(RESPONSE)["response"]["inventory"]) == {
        "security",
        "missing",
        "deprecated",
        "information",
        "caching",
    }


# ---------------------------------------------------------------------------
# The raw blobs
# ---------------------------------------------------------------------------
# Optional passthrough: this package never fetches anything. They are here so a
# report is reproducible -- the bytes that produced the findings travel with
# them and a later version can be run over the same input.

RAW_RESPONSE = b"HTTP/1.1 200 OK\r\nServer: caf\xe9-server/1.0\r\nX-Frame-Options: ALLOWALL\r\n\r\nbody \xff"
RAW_REQUEST = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"


def test_a_report_without_blobs_has_neither_key():
    out = headers.report(RESPONSE)
    assert "raw" not in out["response"]
    assert "request" not in out


def test_the_response_blob_round_trips_to_the_same_bytes():
    import base64

    out = headers.report(headers.parse_raw_headers(RAW_RESPONSE), raw=RAW_RESPONSE)
    assert base64.b64decode(out["response"]["raw"]) == RAW_RESPONSE


def test_the_blob_stays_analysable_so_a_report_is_reproducible():
    import base64

    out = headers.report(headers.parse_raw_headers(RAW_RESPONSE), raw=RAW_RESPONSE)
    again = headers.parse_raw_headers(base64.b64decode(out["response"]["raw"]))
    assert [r["code"] for r in out["response"]["findings"]] == [
        f.code for f in headers.order_findings(headers.analyze_all(again))
    ]


def test_text_is_encoded_the_way_parse_raw_headers_decodes_it():
    # latin-1 both ways, so a value that came out of parse_raw_headers goes
    # back in unchanged -- utf-8 here would corrupt the caf\xe9 banner
    import base64

    as_text = RAW_RESPONSE.decode("latin-1")
    out = headers.report({}, raw=as_text)
    assert base64.b64decode(out["response"]["raw"]) == RAW_RESPONSE


def test_a_request_blob_gets_its_own_key():
    out = headers.report(RESPONSE, request_raw=RAW_REQUEST)
    assert set(out) == {"response", "request"}
    assert set(out["request"]) == {"raw"}
    assert "findings" not in out["request"]


def test_a_report_with_blobs_is_still_json_serialisable():
    import json

    out = headers.report(RESPONSE, raw=RAW_RESPONSE, request_raw=RAW_REQUEST)
    assert json.loads(json.dumps(out)) == out


# ---------------------------------------------------------------------------
# The message catalog
# ---------------------------------------------------------------------------
# The analysers hold no prose: they emit (header, code, data) and catalog.py
# turns that into a sentence. Three things can go wrong, and each is pinned
# here, because none of them shows up as a failing analysis -- they show up as
# a crash or a blank in whatever renders the findings.


SNAPSHOT = pathlib.Path(__file__).parent / "rendered_messages.txt"


def _rendered():
    """Every distinct sentence the package can produce, sorted.

    A set, not a list: the corpus renders some codes from several cases and
    the duplicates say nothing. Sorted so the file is a readable diff rather
    than a churn of reordered lines.
    """
    rows = {
        "%s\t%s\t%s" % (f.code, f.header, headers.describe(f))
        for f in _every_finding_headers_can_emit()
    }
    return "".join(line + "\n" for line in sorted(rows))


def test_rendered_messages_match_the_snapshot():
    """The wording of every finding, pinned.

    The catalog is one file of prose that nothing else reads, which makes an
    accidental edit to it invisible: no analysis changes, no test about codes
    fails, and the sentence a consumer sees is quietly different. This is the
    check that noticed nothing when the messages moved out of the analysers --
    275 renderings, zero drift -- and it is here so the next edit gets the same
    treatment for free.

    Regenerate deliberately, never to make a red test green:

        UPDATE_MESSAGE_SNAPSHOT=1 python -m pytest tests/ -k snapshot

    then read the diff before keeping it.
    """
    current = _rendered()
    if os.environ.get("UPDATE_MESSAGE_SNAPSHOT"):
        SNAPSHOT.write_text(current)
    assert current == SNAPSHOT.read_text()


def test_the_snapshot_covers_every_code():
    # Without this the snapshot could pin three messages and pass forever.
    pinned = {line.split("\t")[0] for line in SNAPSHOT.read_text().splitlines()}
    assert pinned == set(headers.FINDING_SEVERITY)


def test_every_emittable_code_has_a_message():
    assert _every_code_headers_can_emit() <= set(headers.MESSAGES)


def test_no_message_is_written_for_a_code_that_cannot_be_emitted():
    assert set(headers.MESSAGES) <= _every_code_headers_can_emit()


def test_every_finding_renders_without_a_missing_field():
    # The failure this catches: a template naming {sources} beside data that
    # carries "directives". Nothing else notices until a consumer asks for the
    # sentence, which may be long after the analysis was trusted.
    for finding in _every_finding_headers_can_emit():
        rendered = headers.describe(finding)
        assert rendered
        assert "{" not in rendered


def test_no_analyser_builds_a_sentence():
    """The point of the split, stated as the thing that would undo it.

    Prose in a comment or a docstring is ordinary English and welcome; what
    must not come back is a sentence passed to Finding(), because that is the
    coupling the catalog exists to remove. So this reads the syntax rather than
    the text: the third argument to Finding() is data, and data is never a
    string and never a string being formatted.
    """
    import ast
    import pathlib

    import http_security_test

    root = pathlib.Path(http_security_test.__file__).parent
    offenders = []
    for module in sorted(root.glob("*.py")):
        for node in ast.walk(ast.parse(module.read_text())):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Finding"):
                continue
            if len(node.args) < 3:
                continue
            if isinstance(node.args[2], (ast.Constant, ast.BinOp, ast.JoinedStr)):
                offenders.append("%s:%d" % (module.name, node.lineno))
    assert offenders == []


def test_data_is_the_machine_readable_half():
    finding, = headers.analyze("X-Frame-Options", "ALLOWALL")
    assert finding.data == {"value": "ALLOWALL"}
    # ...and the sentence is built from exactly that, not from a second copy
    assert headers.describe(finding) == headers.MESSAGES["xfo-invalid"].format(
        value="ALLOWALL"
    )


def test_unknown_codes_fall_back_to_warning():
    # a new check upstream must not crash a scan
    assert headers.severity("some-future-code") == "warning"


def test_severity_values_match_the_documented_policy():
    # The completeness tests above check only which codes are rated. These
    # anchor what they are rated, so a flipped value cannot land silently.
    counts = collections.Counter(headers.FINDING_SEVERITY.values())
    assert counts == {"error": 35, "warning": 26, "note": 35}
    # An explicitly-defaulted header is rated exactly as its absence is, so
    # neither spelling of the same posture reads better than the other
    assert (
        headers.FINDING_SEVERITY["coep-unsafe-none"]
        == headers.FINDING_SEVERITY["coep-missing"]
    )
    assert (
        headers.FINDING_SEVERITY["corp-cross-origin"]
        == headers.FINDING_SEVERITY["corp-missing"]
    )
    # Hardening COOP to same-origin surfaces coep-missing. That must never cost
    # the site a warning, or the tool would penalise the stronger configuration.
    assert headers.FINDING_SEVERITY["coep-missing"] == "note"
    # One anchor per severity, each a policy decision the design calls out
    assert headers.FINDING_SEVERITY["hsts-missing"] == "error"
    assert headers.FINDING_SEVERITY["csp-no-base-uri"] == "warning"
    assert headers.FINDING_SEVERITY["pp-missing"] == "note"
    # The code names the value, not its age: ALLOW-FROM is an error because no
    # browser honours it, which a -deprecated suffix would have understated.
    assert headers.FINDING_SEVERITY["xfo-allow-from"] == "error"


def test_order_findings_puts_the_worst_first():
    findings = [
        headers.Finding("H", "csp-no-base-uri", "warning-level"),
        headers.Finding("H", "xxp-deprecated", "info-level"),
        headers.Finding("H", "csp-unsafe-inline", "error-level"),
    ]
    ordered = headers.order_findings(findings)
    assert [f.code for f in ordered] == [
        "csp-unsafe-inline",
        "csp-no-base-uri",
        "xxp-deprecated",
    ]


def test_order_findings_keeps_equal_severities_in_emission_order():
    findings = [
        headers.Finding("H", "csp-no-base-uri", "first"),
        headers.Finding("H", "csp-no-object-src", "second"),
    ]
    ordered = headers.order_findings(findings)
    assert [f.code for f in ordered] == ["csp-no-base-uri", "csp-no-object-src"]


# ---------------------------------------------------------------------------
# Feature-Policy alongside its successor
# ---------------------------------------------------------------------------
# Only Chromium reads either header, and it reads both, so the superseded
# spelling decides something only when it stands alone.

STANDALONE = {"feature-policy": "geolocation *"}
BOTH = dict(STANDALONE, **{"permissions-policy": "geolocation=()"})


def fp_codes(present):
    return sorted(f.code for f in headers.analyze_all(present) if f.code.startswith("fp-"))


def test_a_standalone_feature_policy_is_judged_on_its_contents():
    assert fp_codes(STANDALONE) == ["fp-deprecated", "fp-wildcard"]


def test_its_contents_are_not_judged_once_the_successor_is_present():
    # Chromium has the modern header, so what the old one permits decides nothing
    assert "fp-wildcard" not in fp_codes(BOTH)


def test_two_policies_that_disagree_are_reported():
    assert "fp-conflicts" in fp_codes(BOTH)


def test_two_policies_that_agree_are_not_reported():
    agreeing = {"feature-policy": "geolocation 'none'", "permissions-policy": "geolocation=()"}
    assert "fp-conflicts" not in fp_codes(agreeing)


def test_the_two_spellings_of_no_origins_compare_equal():
    # Feature-Policy writes it 'none'; Permissions-Policy writes it ()
    assert policies._allowlist(["'none'".strip("'")]) == policies._allowlist([])


def test_features_only_one_header_names_are_not_a_disagreement():
    partial = {"feature-policy": "camera 'none'", "permissions-policy": "geolocation=()"}
    assert "fp-conflicts" not in fp_codes(partial)


# ---------------------------------------------------------------------------
# CORS across the pair
# ---------------------------------------------------------------------------

WILDCARD_WITH_CREDENTIALS = {
    "access-control-allow-origin": "*",
    "access-control-allow-credentials": "true",
}


def acao_codes(present):
    return sorted(f.code for f in headers.analyze_all(present) if f.code.startswith("acao-"))


def test_a_wildcard_with_credentials_is_the_pairing_browsers_refuse():
    assert acao_codes(WILDCARD_WITH_CREDENTIALS) == ["acao-credentials-wildcard"]


def test_the_refused_pairing_subsumes_the_plain_wildcard_note():
    # the wildcard never takes effect at all, so saying it is permissive misleads
    assert "acao-wildcard" not in acao_codes(WILDCARD_WITH_CREDENTIALS)


def test_credentials_without_a_wildcard_is_an_ordinary_configuration():
    present = {
        "access-control-allow-origin": "https://a.test",
        "access-control-allow-credentials": "true",
    }
    assert acao_codes(present) == []


# ---------------------------------------------------------------------------
# Policies under test
# ---------------------------------------------------------------------------
# Report-only is how a policy is rolled out safely, so it is never a defect --
# but a response carrying only the report-only spelling enforces nothing, which
# is easy to mistake for protection.

REPORT_ONLY_ONLY = {
    "content-security-policy-report-only": "default-src 'none'",
    "cross-origin-embedder-policy-report-only": 'require-corp; report-to="coep"',
    "cross-origin-opener-policy-report-only": "same-origin",
    "integrity-policy-report-only": "blocked-destinations=(script)",
}


def unenforced_codes(present):
    return sorted(f.code for f in headers.analyze_all(present) if f.code.endswith("-ro-unenforced"))


def test_a_policy_only_in_report_only_mode_is_reported():
    assert unenforced_codes(REPORT_ONLY_ONLY) == [
        "coep-ro-unenforced",
        "coop-ro-unenforced",
        "csp-ro-unenforced",
        "ip-ro-unenforced",
    ]


def test_report_only_beside_an_enforcing_policy_is_ordinary_practice():
    # testing the next policy while the current one enforces
    present = dict(REPORT_ONLY_ONLY)
    present.update({
        "content-security-policy": "default-src 'self'",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-opener-policy": "same-origin",
        "integrity-policy": "blocked-destinations=(script)",
    })
    assert unenforced_codes(present) == []


# ---------------------------------------------------------------------------
# Integrity-Policy reporting
# ---------------------------------------------------------------------------
# The endpoints directive carries group names; the URLs behind them live in a
# Reporting-Endpoints header. Neither header can answer this alone.

REPORTS_NOWHERE = {"integrity-policy": "blocked-destinations=(script), endpoints=(sri)"}


def ip_codes(present):
    return sorted(f.code for f in headers.analyze_all(present) if f.code.startswith("ip-"))


def test_a_reporting_group_nothing_defines_is_reported():
    assert ip_codes(REPORTS_NOWHERE) == ["ip-endpoints-undefined"]


def test_a_defined_reporting_group_is_ordinary_practice():
    present = dict(REPORTS_NOWHERE, **{"reporting-endpoints": 'sri="https://example.test/r"'})
    assert ip_codes(present) == []


def test_only_the_named_group_counts():
    # a Reporting-Endpoints header that defines some other group leaves this
    # policy reporting into nothing just as surely as no header at all
    present = dict(REPORTS_NOWHERE, **{"reporting-endpoints": 'csp="https://example.test/r"'})
    assert ip_codes(present) == ["ip-endpoints-undefined"]


def test_a_policy_that_names_no_endpoints_is_not_asked_about_reporting():
    assert ip_codes({"integrity-policy": "blocked-destinations=(script)"}) == []


def test_an_unreadable_report_to_earns_integrity_policy_the_doubt_too():
    present = dict(REPORTS_NOWHERE, **{"report-to": "not json at all"})
    assert ip_codes(present) == []


def test_a_policy_that_blocks_nothing_is_not_asked_about_reporting():
    # _analyze_ip already answers "once the policy enforces nothing, what its
    # other directives say decides nothing either" -- the cross-header rule has
    # to agree, or it renders "violations are caught and never delivered" about
    # a policy that can catch none
    assert ip_codes({"integrity-policy": "endpoints=(ep)"}) == ["ip-no-blocked-destinations"]
    assert ip_codes({"integrity-policy": "blocked-destinations=(style), endpoints=(ep)"}) == [
        "ip-no-blocked-destinations"
    ]


def test_an_unparseable_policy_is_not_also_asked_about_reporting():
    # it enforces nothing, so where it would have reported decides nothing
    assert ip_codes({"integrity-policy": "blocked-destinations=script"}) == ["ip-invalid"]


def test_the_report_only_spelling_is_left_alone():
    # principle: report-only content is never analyzed, even where the same
    # defect in it would arguably matter more
    present = {"integrity-policy-report-only": "blocked-destinations=(script), endpoints=(sri)"}
    assert "ip-endpoints-undefined" not in ip_codes(present)


def test_the_content_of_a_report_only_header_is_not_judged():
    # it blocks nothing, so what it permits decides nothing
    assert headers.analyze("Content-Security-Policy-Report-Only", "script-src 'unsafe-inline'") == []


# ---------------------------------------------------------------------------
# CSP, COOP and COEP reporting groups
# ---------------------------------------------------------------------------
# The same defect Integrity-Policy already reports, for the three other headers
# that name a reporting group. Each still enforces; what it loses is any way of
# finding out that it fired.

CSP_REPORTS_NOWHERE = {
    "content-security-policy": "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-to csp-ep"
}
COOP_REPORTS_NOWHERE = {"cross-origin-opener-policy": 'same-origin; report-to="coop-ep"'}
COEP_REPORTS_NOWHERE = {"cross-origin-embedder-policy": 'require-corp; report-to="coep-ep"'}
UNDELIVERABLE_ENDPOINT = {"reporting-endpoints": 'csp-ep="http://example.test/r"'}
DEFINED_ENDPOINT = {"reporting-endpoints": 'csp-ep="https://example.test/r"'}
INVALID_ENDPOINTS = {"reporting-endpoints": 'CSP-EP="https://example.test/r"'}
LEGACY_UNDELIVERABLE = {"report-to": '{"group":"g","endpoints":[{"url":"http://example.test/r"}]}'}
LEGACY_DEFINED = {"report-to": '{"group":"g","endpoints":[{"url":"https://example.test/r"}]}'}
LEGACY_INVALID = {"report-to": "not json at all"}


def group_codes(present):
    return sorted(
        f.code for f in headers.analyze_all(present) if f.code.endswith("-report-to-undefined")
    )


def test_a_csp_reporting_group_nothing_defines_is_reported():
    assert group_codes(CSP_REPORTS_NOWHERE) == ["csp-report-to-undefined"]


def test_a_coop_reporting_group_nothing_defines_is_reported():
    assert group_codes(COOP_REPORTS_NOWHERE) == ["coop-report-to-undefined"]


def test_a_coep_reporting_group_nothing_defines_is_reported():
    assert group_codes(COEP_REPORTS_NOWHERE) == ["coep-report-to-undefined"]


def test_a_defined_group_is_ordinary_practice():
    present = dict(CSP_REPORTS_NOWHERE, **{"reporting-endpoints": 'csp-ep="https://example.test/r"'})
    assert group_codes(present) == []


def test_only_the_group_the_policy_names_counts():
    present = dict(CSP_REPORTS_NOWHERE, **{"reporting-endpoints": 'other="https://example.test/r"'})
    assert group_codes(present) == ["csp-report-to-undefined"]


def test_a_policy_naming_no_group_is_not_asked_about_reporting():
    assert group_codes({"content-security-policy": "default-src 'none'"}) == []
    assert group_codes({"cross-origin-opener-policy": "same-origin"}) == []


def test_a_policy_that_applies_nothing_is_not_asked_about_reporting():
    # COEP unsafe-none opts into nothing, so it blocks nothing, so it has
    # nothing to report -- and the sentence this code renders ("the policy
    # applies and every report it would have sent is discarded") would be false
    assert group_codes({"cross-origin-embedder-policy": 'unsafe-none; report-to="grp"'}) == []
    assert group_codes({"cross-origin-opener-policy": 'unsafe-none; report-to="grp"'}) == []


def test_a_policy_browsers_will_not_honour_is_not_asked_about_reporting():
    # an unrecognised value falls back to unsafe-none, which is the same case
    assert group_codes({"cross-origin-embedder-policy": 'require-corps; report-to="grp"'}) == []
    assert group_codes({"cross-origin-opener-policy": 'same-origins; report-to="grp"'}) == []


def test_some_other_parameter_is_not_mistaken_for_a_reporting_group():
    # a structured field item may carry any parameter; only report-to names a
    # group, and reading the wrong one invents a finding out of nothing
    assert group_codes({"cross-origin-opener-policy": 'same-origin; anonymous="x"'}) == []
    assert group_codes({"cross-origin-embedder-policy": 'require-corp; foo="bar"'}) == []


def test_the_data_carries_every_undefined_group():
    present = {
        "content-security-policy": "default-src 'none'; report-to a b",
        "reporting-endpoints": 'b="https://example.test/r"',
    }
    finding = next(f for f in headers.analyze_all(present) if f.code == "csp-report-to-undefined")
    assert finding.data == {"groups": ["a"]}


def test_report_only_spellings_are_left_alone():
    # parked deliberately: a report-only policy is a trial the author knows is
    # not enforcing, so its plumbing belongs behind a tool's switch
    present = {
        "content-security-policy-report-only": "default-src 'none'; report-to csp-ep",
        "cross-origin-opener-policy-report-only": 'same-origin; report-to="coop-ep"',
    }
    assert group_codes(present) == []


# -- an endpoint the browser will not deliver to ------------------------------
# A defect in the endpoint's definition belongs to the header that defined it,
# not to every policy that named the group: one bad URL is one fact however
# many policies point at it. So the group counts as defined -- the referencing
# headers stay quiet -- and Reporting-Endpoints answers for the URL.


def endpoint_codes(present, **kwargs):
    # both spellings of the defining header, so a code cannot hide behind the
    # prefix the helper happens to look for
    return sorted(
        f.code
        for f in headers.analyze_all(present, **kwargs)
        if f.code.startswith(("re-", "rt-"))
    )


def test_an_endpoint_the_browser_discards_is_the_defining_headers_defect():
    present = dict(CSP_REPORTS_NOWHERE, **{"reporting-endpoints": 'csp-ep="http://example.test/r"'})
    assert endpoint_codes(present) == ["re-endpoint-undeliverable"]
    # ...and the policy that named it is not also blamed for it
    assert group_codes(present) == []


def test_the_undeliverable_endpoint_is_named():
    present = {"reporting-endpoints": 'a="http://example.test/r", b="https://example.test/r"'}
    finding, = [f for f in headers.analyze_all(present) if f.code == "re-endpoint-undeliverable"]
    assert finding.data == {"endpoints": ["a"]}


def test_an_undeliverable_endpoint_nothing_references_is_still_reported():
    # the defect is in the definition, so it does not depend on being used
    assert endpoint_codes({"reporting-endpoints": 'a="http://example.test/r"'}) == [
        "re-endpoint-undeliverable"
    ]


def test_a_loopback_endpoint_is_left_alone():
    # the engines disagree here -- Firefox delivers to it, Chromium does not --
    # so it is not a defect we can assert
    present = dict(CSP_REPORTS_NOWHERE, **{"reporting-endpoints": 'csp-ep="http://localhost:9000/r"'})
    assert endpoint_codes(present) == []
    assert group_codes(present) == []


# -- the whole header is void on a plaintext response -------------------------
# Reporting API step 1: "Abort these steps if response's HTTPS state is not
# 'modern', and the origin of response's url is not potentially trustworthy."
# So every group it defines is undefined -- which is one fact about the header,
# not four about the policies that named its groups.


def test_reporting_is_ineffective_on_a_plaintext_response():
    present = dict(CSP_REPORTS_NOWHERE, **{"reporting-endpoints": 'csp-ep="https://example.test/r"'})
    assert endpoint_codes(present, secure=False, host="example.test") == ["re-ineffective"]
    # the policy naming the group is not blamed for the response's scheme
    assert group_codes(present) == []


def test_reporting_over_plaintext_loopback_is_left_alone():
    # a loopback origin is potentially trustworthy, so the header applies
    present = {"reporting-endpoints": 'csp-ep="https://example.test/r"'}
    assert endpoint_codes(present, secure=False, host="localhost") == []


def test_a_secure_response_is_not_told_its_reporting_is_ineffective():
    present = {"reporting-endpoints": 'csp-ep="https://example.test/r"'}
    assert endpoint_codes(present, secure=True, host="example.test") == []


# -- Report-To, the predecessor, still defines groups -------------------------
# It is deprecated in favour of Reporting-Endpoints and BCD marks it so, but
# both engines still parse and honour it -- Chromium reporting_service.cc:250,
# Firefox ReportingHeader.cpp:211. A response that defines its groups only this
# way is configured correctly, so reading only Reporting-Endpoints invents a
# defect where there is none.


def test_a_group_defined_by_report_to_is_defined():
    present = dict(
        CSP_REPORTS_NOWHERE,
        **{"report-to": '{"group":"csp-ep","max_age":10886400,'
                        '"endpoints":[{"url":"https://example.test/r"}]}'},
    )
    assert group_codes(present) == []


def test_report_to_without_a_group_name_defines_the_default_group():
    present = {
        "content-security-policy": "default-src 'none'; report-to default",
        "report-to": '{"max_age":10886400,"endpoints":[{"url":"https://example.test/r"}]}',
    }
    assert group_codes(present) == []


def test_several_report_to_groups_are_all_defined():
    present = {
        "content-security-policy": "default-src 'none'; report-to b",
        "report-to": '{"group":"a","endpoints":[{"url":"https://example.test/a"}]},'
                     '{"group":"b","endpoints":[{"url":"https://example.test/b"}]}',
    }
    assert group_codes(present) == []


def test_an_unreadable_report_to_earns_the_benefit_of_the_doubt():
    # it may well define the group; claiming otherwise is the false positive
    # this package exists to avoid
    present = dict(CSP_REPORTS_NOWHERE, **{"report-to": "not json at all"})
    assert group_codes(present) == []


def test_a_report_to_that_defines_some_other_group_still_leaves_this_one_undefined():
    present = dict(
        CSP_REPORTS_NOWHERE,
        **{"report-to": '{"group":"other","endpoints":[{"url":"https://example.test/r"}]}'},
    )
    assert group_codes(present) == ["csp-report-to-undefined"]


# -- syntax of the definitions themselves --------------------------------------
# Whether an endpoint answers is an active question and out of scope. Whether
# the header that declares it is well formed is not: both engines drop a
# Reporting-Endpoints header whose dictionary will not parse -- Firefox
# `SFV::ParseDict(...); if (!dict.IsValid()) return 0;`, Chromium
# ParseDictionary returning nullopt -- and structured field keys are lowercase
# by grammar (RFC 9651: key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-"
# / "." / "*" )).


def test_an_uppercase_key_voids_the_whole_header():
    assert endpoint_codes({"reporting-endpoints": 'CSP-EP="https://example.test/r"'}) == [
        "re-invalid"
    ]


def test_a_key_with_a_forbidden_character_voids_the_whole_header():
    assert endpoint_codes({"reporting-endpoints": 'csp ep="https://example.test/r"'}) == [
        "re-invalid"
    ]


def test_the_keys_the_grammar_allows_are_left_alone():
    present = {"reporting-endpoints": 'csp-ep_1.a="https://example.test/r", *b="https://example.test/s"'}
    assert endpoint_codes(present) == []


def test_a_policy_naming_a_group_in_a_void_header_is_not_blamed_for_it():
    # the defect is the header's, and reporting it against every policy that
    # named one of its groups would be the same fact up to four times
    present = dict(CSP_REPORTS_NOWHERE, **{"reporting-endpoints": 'CSP-EP="https://example.test/r"'})
    assert group_codes(present) == []


# -- Report-To gets the same treatment ----------------------------------------
# Deprecated is not unhonoured: both engines still read it, and Chromium runs
# its endpoints through the very same ProcessEndpointURLString.


def test_a_report_to_endpoint_the_browser_discards_is_reported():
    present = {"report-to": '{"group":"g","endpoints":[{"url":"http://example.test/r"}]}'}
    assert endpoint_codes(present) == ["rt-endpoint-undeliverable"]


def test_a_report_to_that_is_not_json_is_reported():
    assert endpoint_codes({"report-to": "not json at all"}) == ["rt-invalid"]


def test_a_well_formed_report_to_is_left_alone():
    present = {"report-to": '{"group":"g","endpoints":[{"url":"https://example.test/r"}]}'}
    assert endpoint_codes(present) == []


def test_report_to_is_ineffective_on_a_plaintext_response():
    present = {"report-to": '{"group":"g","endpoints":[{"url":"https://example.test/r"}]}'}
    assert endpoint_codes(present, secure=False, host="example.test") == ["rt-ineffective"]


def test_report_to_is_inventoried_but_never_reported_missing():
    inventory = headers.inventory({"report-to": '{"group":"g","endpoints":[]}'})
    assert "Report-To" in inventory["security"]
    assert "Report-To" not in headers.inventory({})["missing"]


def test_reporting_endpoints_is_inventoried_when_present():
    inventory = headers.inventory({"reporting-endpoints": 'csp-ep="https://example.test/r"'})
    assert "Reporting-Endpoints" in inventory["security"]


def test_reporting_endpoints_is_never_reported_missing():
    # a response that configures no reporting is the ordinary state of the web,
    # so its absence is not a gap and must reach neither list nor finding
    inventory = headers.inventory({})
    assert "Reporting-Endpoints" not in inventory["missing"]
    assert not [f for f in headers.analyze_all({}) if f.header == "Reporting-Endpoints"]


def test_the_whole_loopback_range_is_left_alone():
    # potentially trustworthy is 127.0.0.0/8, not just 127.0.0.1
    present = dict(CSP_REPORTS_NOWHERE, **{"reporting-endpoints": 'csp-ep="http://127.0.0.2/r"'})
    assert group_codes(present) == []


def test_a_bracketed_ipv6_loopback_endpoint_is_left_alone():
    # the port comes off after the closing bracket, not at the first colon
    present = dict(CSP_REPORTS_NOWHERE, **{"reporting-endpoints": 'csp-ep="http://[::1]:9000/r"'})
    assert group_codes(present) == []


def test_a_relative_endpoint_is_left_alone():
    # both engines resolve it against the document's own origin
    present = dict(CSP_REPORTS_NOWHERE, **{"reporting-endpoints": 'csp-ep="/reports"'})
    assert group_codes(present) == []


def test_a_comma_inside_a_quoted_url_does_not_invent_a_group():
    present = {
        "content-security-policy": "default-src 'none'; report-to b",
        "reporting-endpoints": 'csp-ep="https://example.test/r?a=1,b=2"',
    }
    assert group_codes(present) == ["csp-report-to-undefined"]


# -- repeated CSP ------------------------------------------------------------
# Each policy carries its own report-to, and a browser enforces every policy,
# so a group undefined for one policy is that policy's reports going nowhere
# whatever its siblings say. Any policy counts, as with the syntax codes.


def test_any_policy_reporting_nowhere_counts():
    present = {
        "content-security-policy": [
            "default-src 'none'; report-to good",
            "default-src 'none'; report-to bad",
        ],
        "reporting-endpoints": 'good="https://example.test/r"',
    }
    finding = next(f for f in headers.analyze_all(present) if f.code == "csp-report-to-undefined")
    assert finding.data == {"groups": ["bad"]}


def test_repeated_headers_that_disagree_earn_nothing():
    # no specification says which COOP wins, so nothing can be concluded
    present = {
        "cross-origin-opener-policy": [
            'same-origin; report-to="a"',
            'same-origin; report-to="b"',
        ]
    }
    assert group_codes(present) == []


def test_report_only_findings_come_out_in_table_order():
    once = unenforced_codes(REPORT_ONLY_ONLY)
    assert once == unenforced_codes(REPORT_ONLY_ONLY)


# ---------------------------------------------------------------------------
# Repeated headers
# ---------------------------------------------------------------------------
# A browser enforces every Content-Security-Policy a response carries: a
# resource must satisfy all of them, so the effective policy is their
# intersection. Reporting each in isolation would call a directive missing that
# a sibling policy sets.

COVERS_DEFAULT = "default-src 'self'; base-uri 'none'"
COVERS_FRAMING = "frame-ancestors 'none'"
AIRTIGHT = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"


def csp_codes(*policies):
    return sorted(
        f.code
        for f in headers.analyze_all({"content-security-policy": list(policies)})
        if f.code.startswith("csp-")
    )


def test_a_gap_one_policy_leaves_and_another_closes_is_not_a_gap():
    # each alone looks deficient; together they cover everything
    assert csp_codes(COVERS_DEFAULT) == ["csp-no-frame-ancestors"]
    assert csp_codes(COVERS_FRAMING) == ["csp-no-base-uri", "csp-no-default-src", "csp-no-object-src"]
    assert csp_codes(COVERS_DEFAULT, COVERS_FRAMING) == []


def test_a_weakness_only_one_policy_permits_is_not_effective():
    # the strict policy still blocks inline script, so nothing runs
    permissive = "script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
    assert "csp-unsafe-inline" in csp_codes(permissive)
    assert "csp-unsafe-inline" not in csp_codes(permissive, AIRTIGHT)


def test_a_weakness_every_policy_permits_is_effective():
    permissive = "script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
    assert "csp-unsafe-inline" in csp_codes(permissive, permissive)


def test_a_syntax_defect_in_any_policy_is_real():
    # the text is broken whatever a sibling policy says
    broken = "script-src 'self' object-src 'none'"
    assert "csp-missing-semicolon" in csp_codes(broken, AIRTIGHT)


def test_one_policy_is_still_judged_alone():
    assert csp_codes(AIRTIGHT) == []
    assert csp_codes("default-src 'self'") == ["csp-no-base-uri", "csp-no-frame-ancestors"]


def test_a_repeated_header_names_each_distinct_defect():
    # Identity is (header, code, data), so two bad values are two facts. It was
    # (header, code) while a finding carried prose, which collapsed these into
    # one -- and would collapse two cookies missing Secure into one as well.
    findings = [
        f
        for f in headers.analyze_all({"x-frame-options": ["ALLOWALL", "NONSENSE"]})
        if f.code == "xfo-invalid"
    ]
    assert [f.data["value"] for f in findings] == ["ALLOWALL", "NONSENSE"]


def test_a_repeated_header_still_names_an_identical_defect_once():
    codes = [f.code for f in headers.analyze_all({"x-frame-options": ["ALLOWALL", "ALLOWALL"]})]
    assert codes.count("xfo-invalid") == 1


# ---------------------------------------------------------------------------
# Building the mapping
# ---------------------------------------------------------------------------


def test_parse_headers_keeps_every_value_of_a_repeated_header():
    # the mistake this exists to prevent: a dict comprehension over these pairs
    # keeps only the last, and the last is not the whole policy
    pairs = [("Content-Security-Policy", COVERS_DEFAULT),
             ("Content-Security-Policy", COVERS_FRAMING),
             ("Server", "nginx")]
    assert headers.parse_headers(pairs) == {
        "content-security-policy": [COVERS_DEFAULT, COVERS_FRAMING],
        "server": ["nginx"],
    }


def test_parse_raw_headers_reads_a_block_off_the_wire():
    raw = (b"HTTP/1.1 200 OK\r\n"
           b"Content-Security-Policy: " + COVERS_DEFAULT.encode() + b"\r\n"
           b"Content-Security-Policy: " + COVERS_FRAMING.encode() + b"\r\n"
           b"Server: nginx\r\n\r\n<html>body is not a header</html>")
    assert headers.parse_raw_headers(raw) == {
        "content-security-policy": [COVERS_DEFAULT, COVERS_FRAMING],
        "server": ["nginx"],
    }


def test_parse_raw_headers_accepts_a_block_with_no_status_line():
    assert headers.parse_raw_headers("Server: nginx\r\n\r\n") == {"server": ["nginx"]}


def test_analyze_all_still_takes_a_plain_string_per_header():
    # the ordinary caller has one value per header and should not have to wrap it
    codes = [f.code for f in headers.analyze_all({"x-content-type-options": "sniff"})]
    assert "xcto-invalid" in codes


# ---------------------------------------------------------------------------
# Illegally repeated headers
# ---------------------------------------------------------------------------
# The RFCs say what a client does with a header that may recur, and nothing
# about one that may not. Browsers mostly take the last, but that is habit, not
# specification -- and a header sent twice is a signal in itself.


def duplicate_findings(present):
    return sorted(
        f.header for f in headers.analyze_all(present) if f.code == "duplicate-headers"
    )


def test_a_header_repeated_without_a_rule_for_it_is_reported():
    assert duplicate_findings({"x-frame-options": ["DENY", "ALLOWALL"]}) == ["x-frame-options"]


def test_repeating_a_header_defined_to_repeat_is_not_reported():
    # several policies are a feature: a browser enforces every one of them
    assert duplicate_findings({"content-security-policy": ["default-src 'none'", "frame-ancestors 'none'"]}) == []
    assert duplicate_findings({"set-cookie": ["a=1", "b=2"]}) == []


def test_identical_values_still_count_as_repeated():
    # the response is still one no specification describes
    assert duplicate_findings({"x-frame-options": ["DENY", "DENY"]}) == ["x-frame-options"]


def test_each_illegally_repeated_header_gets_its_own_finding():
    # every Finding names the header it is about, so a consumer grouping by
    # header files each one correctly
    assert duplicate_findings({
        "x-frame-options": ["DENY", "DENY"],
        "referrer-policy": ["no-referrer", "unsafe-url"],
    }) == ["referrer-policy", "x-frame-options"]


# ---------------------------------------------------------------------------
# Ambiguity and the cross-header checks
# ---------------------------------------------------------------------------


def framing_verdict(present):
    return sorted(
        f.code for f in headers.analyze_all(present)
        if "frame" in f.code or f.code.startswith("xfo")
    )


def test_a_second_policy_that_restricts_framing_covers_the_missing_xfo():
    # regression: the check read only the first policy, so this reported
    # xfo-missing although framing is restricted
    present = {"content-security-policy": ["default-src 'self'; base-uri 'none'",
                                           "frame-ancestors 'none'"]}
    assert framing_verdict(present) == []


def test_a_contradictory_xfo_earns_no_suppression():
    # regression: the first value was DENY, so the CSP gap was suppressed on the
    # strength of a header clients disagree about and several discard
    present = {"x-frame-options": ["DENY", "ALLOWALL"],
               "content-security-policy": "default-src 'none'; base-uri 'none'"}
    assert "csp-no-frame-ancestors" in framing_verdict(present)


def test_a_header_repeated_with_one_value_is_not_ambiguous():
    present = {"x-frame-options": ["DENY", "DENY"],
               "content-security-policy": "default-src 'none'; base-uri 'none'"}
    assert "csp-no-frame-ancestors" not in framing_verdict(present)
