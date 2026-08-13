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
    ("X-Frame-Options", "ALLOW-FROM https://example.com", ["xfo-deprecated"]),
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
    # Deprecated headers
    ("Expect-CT", "max-age=86400, enforce", ["ect-deprecated"]),
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
    message = next(f.message for f in inherited if f.code == "csp-unsafe-inline")
    assert "in default-src" in message

    overridden = headers.analyze(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self'; script-src-elem 'unsafe-inline'",
    )
    message = next(f.message for f in overridden if f.code == "csp-unsafe-inline")
    assert "in script-src-elem" in message


def test_preload_message_reads_cleanly_when_both_requirements_are_unmet():
    finding = next(
        f
        for f in headers.analyze("Strict-Transport-Security", "max-age=300; preload")
        if f.code == "hsts-preload-ineffective"
    )
    assert "requires includeSubDomains and a max-age of at least" in finding.message


def test_findings_name_their_header():
    findings = headers.analyze("Strict-Transport-Security", "max-age=1")
    assert all(f.header == "Strict-Transport-Security" for f in findings)
    assert all(f.message for f in findings)


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
    assert codes == ["csp-no-frame-ancestors", "xfo-deprecated"]


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
    assert 'unsafe-none; report-to="coop"' in finding.message


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


def test_find_information_headers_returns_canonical_names_and_values():
    assert headers.find_information_headers(RESPONSE) == {"Server": "nginx/1.18"}


def test_stack_fingerprinting_headers_are_inventoried():
    response = {
        "x-generator": "Drupal 10 (https://www.drupal.org)",
        "x-runtime": "0.019382",
        "x-drupal-cache": "HIT",
        "$wsep": "",
        "x-powered-by": "PHP/8.2",
    }
    found = headers.find_information_headers(response)
    assert set(found) == {"$WSEP", "X-Drupal-Cache", "X-Generator", "X-Powered-By", "X-Runtime"}
    # inventoried, never judged: only a human can say whether a value is a leak
    assert headers.analyze("X-Generator", "Drupal 10") == []


def test_find_cache_headers_returns_canonical_names_and_values():
    assert headers.find_cache_headers(RESPONSE) == {"Cache-Control": "no-store"}


def test_find_deprecated_headers_returns_canonical_names_and_values():
    assert headers.find_deprecated_headers(RESPONSE) == {"X-XSS-Protection": "0"}


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
    # the reporting integration's parameters must not change any of this
    (
        {"cross-origin-opener-policy": 'same-origin; report-to="coop"',
         "cross-origin-embedder-policy": 'require-corp; report-to="coep"'},
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


def test_unknown_codes_fall_back_to_warning():
    # a new check upstream must not crash a scan
    assert headers.severity("some-future-code") == "warning"


def test_severity_values_match_the_documented_policy():
    # The completeness tests above check only which codes are rated. These
    # anchor what they are rated, so a flipped value cannot land silently.
    counts = collections.Counter(headers.FINDING_SEVERITY.values())
    assert counts == {"error": 30, "warning": 23, "note": 21}
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
    # ALLOW-FROM is deprecated *and* dangerous: no browser honours it
    assert headers.FINDING_SEVERITY["xfo-deprecated"] == "error"


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
}


def unenforced_codes(present):
    return sorted(f.code for f in headers.analyze_all(present) if f.code.endswith("-ro-unenforced"))


def test_a_policy_only_in_report_only_mode_is_reported():
    assert unenforced_codes(REPORT_ONLY_ONLY) == [
        "coep-ro-unenforced",
        "coop-ro-unenforced",
        "csp-ro-unenforced",
    ]


def test_report_only_beside_an_enforcing_policy_is_ordinary_practice():
    # testing the next policy while the current one enforces
    present = dict(REPORT_ONLY_ONLY)
    present.update({
        "content-security-policy": "default-src 'self'",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-opener-policy": "same-origin",
    })
    assert unenforced_codes(present) == []


def test_the_content_of_a_report_only_header_is_not_judged():
    # it blocks nothing, so what it permits decides nothing
    assert headers.analyze("Content-Security-Policy-Report-Only", "script-src 'unsafe-inline'") == []


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


def test_a_repeated_header_never_names_a_defect_twice():
    codes = [f.code for f in headers.analyze_all({"x-frame-options": ["ALLOWALL", "NONSENSE"]})]
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
