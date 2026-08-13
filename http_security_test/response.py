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

"""Analysing a whole HTTP response.

The header modules each answer what is wrong with one header. This one answers
what is wrong with a response: which headers should have been there, what the
ones present mean together, and which findings a sibling header has already made
moot. The headers that belong to no family are judged here too.
"""

from .csp import _analyze_csp, _analyze_csp_all, parse_csp
from .findings import Finding
from .hsts import _analyze_hsts, _analyze_preload
from .isolation import (
    _analyze_acao,
    _analyze_coep,
    _analyze_coop,
    _analyze_corp,
    _analyze_cors,
    _analyze_isolation,
    _seeks_isolation,
    _shares_credentials_with_everyone,
)
from .legacy import (
    DEPRECATED_HEADERS,
    _analyze_ect,
    _analyze_hpkp,
    _analyze_hpkp_report_only,
    _analyze_p3p,
    _analyze_xcsp,
    _analyze_xdo,
    _analyze_xpcdp,
    _analyze_xwkcsp,
    _analyze_xxp,
)
from .message import (
    _filter_headers,
    _lookup,
    _lookup_all,
    _normalize,
    _sole_value,
)
from .policies import _analyze_fp, _analyze_policy_overlap, _analyze_pp

# 180 days, the floor recommended for a policy that is meant to stick.


REFERRER_TOKENS = frozenset(
    [
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    ]
)


# Security headers that should be enabled.
SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Permissions-Policy",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
)


# Headers a response may legally repeat, because repetition is defined for them
# and means something. Every other header repeated is a response nobody
# specified: the RFCs say what to do with a header that may recur, and nothing
# about one that may not, so browsers diverge and last-wins is only a habit.
REPEATABLE_HEADERS = frozenset(
    [
        "content-security-policy",
        "content-security-policy-report-only",
        "set-cookie",
    ]
)


# The report-only spelling of a policy, and the header that actually enforces
# it. Report-only is the right way to roll a policy out -- violations are
# reported and nothing breaks -- but it is easy to mistake for protection.
REPORT_ONLY_HEADERS = {
    "Content-Security-Policy-Report-Only": (
        "Content-Security-Policy",
        "csp-ro-unenforced",
    ),
    "Cross-Origin-Embedder-Policy-Report-Only": (
        "Cross-Origin-Embedder-Policy",
        "coep-ro-unenforced",
    ),
    "Cross-Origin-Opener-Policy-Report-Only": (
        "Cross-Origin-Opener-Policy",
        "coop-ro-unenforced",
    ),
}


# Headers that describe the stack rather than the response. None is a defect on
# its own -- the value is what matters, and only a human can judge it -- so these
# are inventoried rather than analyzed. Most name the software and often its
# version; X-Runtime is the odd one out, publishing how long the request took,
# which turns a login endpoint into a timing oracle.
INFORMATION_HEADERS = (
    "$WSEP",
    "Server",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Drupal-Cache",
    "X-Drupal-Dynamic-Cache",
    "X-Generator",
    "X-Powered-By",
    "X-Rack-Cache",
    "X-Runtime",
)


# Cache control headers.
CACHE_HEADERS = (
    "Cache-Control",
    "ETag",
    "Expires",
    "Last-Modified",
    "Pragma",
)


def _analyze_xfo(value):
    normalized = value.strip().upper()
    if normalized.startswith("ALLOW-FROM"):
        return [
            Finding(
                "X-Frame-Options",
                "xfo-deprecated",
                "present but uses ALLOW-FROM, which no current browser supports; "
                "a CSP frame-ancestors directive is the replacement",
            )
        ]
    if normalized not in ("DENY", "SAMEORIGIN"):
        return [
            Finding(
                "X-Frame-Options",
                "xfo-invalid",
                "present but has an unrecognised value (%s), so browsers ignore it "
                "and the page stays framable" % value.strip(),
            )
        ]
    return []


def _analyze_xcto(value):
    if value.strip().lower() != "nosniff":
        return [
            Finding(
                "X-Content-Type-Options",
                "xcto-invalid",
                "present but set to %s rather than nosniff, so MIME type sniffing "
                "stays enabled" % value.strip(),
            )
        ]
    return []


def _analyze_rp(value):
    # The header is a fallback list, not a set: the browser walks it and keeps
    # the last token it recognises, so an old spelling can lead and the policy
    # that actually applies follow it.
    # https://www.w3.org/TR/referrer-policy/#parse-referrer-policy-from-header
    effective = None
    for token in value.split(","):
        token = token.strip().lower()
        if token and token in REFERRER_TOKENS:
            effective = token

    if effective is None:
        return [
            Finding(
                "Referrer-Policy",
                "rp-invalid",
                "present but carries no recognised policy token (%s), so the "
                "browser default applies instead" % value.strip(),
            )
        ]
    if effective == "unsafe-url":
        return [
            Finding(
                "Referrer-Policy",
                "rp-unsafe-url",
                "present but set to unsafe-url, which leaks the full URL, query "
                "string included, to third-party origins",
            )
        ]
    return []


_ANALYZERS = {
    "content-security-policy": _analyze_csp,
    "cross-origin-embedder-policy": _analyze_coep,
    "cross-origin-opener-policy": _analyze_coop,
    "cross-origin-resource-policy": _analyze_corp,
    "access-control-allow-origin": _analyze_acao,
    "expect-ct": _analyze_ect,
    "feature-policy": _analyze_fp,
    "p3p": _analyze_p3p,
    "public-key-pins": _analyze_hpkp,
    "public-key-pins-report-only": _analyze_hpkp_report_only,
    "x-content-security-policy": _analyze_xcsp,
    "x-download-options": _analyze_xdo,
    "x-webkit-csp": _analyze_xwkcsp,
    "referrer-policy": _analyze_rp,
    "permissions-policy": _analyze_pp,
    "strict-transport-security": _analyze_hsts,
    "x-content-type-options": _analyze_xcto,
    "x-frame-options": _analyze_xfo,
    "x-permitted-cross-domain-policies": _analyze_xpcdp,
    "x-xss-protection": _analyze_xxp,
}


def analyze(name, value):
    """Findings for one header in isolation.

    Unknown header names and None values yield no findings.
    """
    if value is None:
        return []
    analyzer = _ANALYZERS.get(name.strip().lower())
    if analyzer is None:
        return []
    return analyzer(value)


def _missing_tag(name):
    if name == "Strict-Transport-Security":
        return "hsts-missing"
    return "".join(x for x in name if x.isupper()).lower() + "-missing"


def _report_missing(present, secure=True):
    """Reports missing security headers as findings.

    Over a plaintext connection browsers ignore HSTS entirely, so its absence
    there is not a defect and is not reported.
    """
    findings = []
    for name in SECURITY_HEADERS:
        if name.lower() in present:
            continue
        if not secure and name == "Strict-Transport-Security":
            continue
        findings.append(Finding(name, _missing_tag(name), "missing"))
    return findings


def _restricts_framing(present):
    """Whether the CSP's frame-ancestors directive actually constrains framing.

    A directive listing `*` permits every origin, which is the state it would be
    reported for lacking, so it does not count as covering anything.
    """
    # Every policy is enforced, so framing is restricted if any of them says so.
    for value in _lookup_all(present, "Content-Security-Policy"):
        sources = parse_csp(value).get("frame-ancestors")
        if bool(sources) and "*" not in sources:
            return True
    return False


def _protects_framing(present):
    """Whether X-Frame-Options is present and browsers will act on it.

    A header repeated with values that disagree earns nothing: clients differ on
    which one wins, and several discard the header outright.
    """
    value = _sole_value(present, "X-Frame-Options")
    return value is not None and not _analyze_xfo(value)


def _duplicated(present):
    """Names of headers the response repeated but may not legally repeat."""
    return sorted(
        name
        for name, values in present.items()
        if len(values) > 1 and name not in REPEATABLE_HEADERS
    )


def _analyze_duplicates(present):
    """Headers sent more than once where no behaviour is specified for that.

    Worth saying whatever the values are. Browsers mostly take the last, but
    that is a habit rather than a rule, so the response means different things
    to different clients -- and a header that appears twice is a signal in
    itself: a backend assembling responses inconsistently, a proxy bolting one
    on, or a response-splitting attempt.
    """
    return [
        Finding(
            name,
            "duplicate-headers",
            "sent more than once, which no specification defines: clients differ "
            "on which value wins, so the response does not mean one thing",
        )
        for name in _duplicated(present)
    ]


def _analyze_report_only(present):
    """Policies under test with nothing enforcing beside them.

    The content of a report-only header is deliberately not analyzed: it blocks
    nothing, so what it permits decides nothing either.
    """
    findings = []
    for name, (enforcing, code) in REPORT_ONLY_HEADERS.items():
        if _lookup(present, name) is None:
            continue
        if _lookup(present, enforcing) is not None:
            continue
        findings.append(
            Finding(
                name,
                code,
                "present but %s is not, so the policy is measured and never "
                "applied; nothing here blocks anything" % enforcing,
            )
        )
    return findings


def _suppress_redundant(findings, present):
    """Drop findings a sibling header has already made moot.

    X-Frame-Options and the CSP frame-ancestors directive govern the same thing,
    so a page covered by one has no gap in the other: that is one finding, not
    two. Only an effective header earns the suppression -- an X-Frame-Options
    browsers ignore protects nothing, and neither does `frame-ancestors *`.

    COEP is judged the same way. It buys cross-origin isolation only alongside
    COOP same-origin, so on a page that does not ask for isolation its absence
    is the ordinary state of the web rather than a gap, and saying otherwise
    would report every site on the internet.
    """
    suppressed = set()
    if _protects_framing(present):
        suppressed.add("csp-no-frame-ancestors")
    if _restricts_framing(present):
        suppressed.add("xfo-missing")
    if not _seeks_isolation(present):
        # Only the *absence* is excused. A response that actually sent
        # unsafe-none said something, and is answered wherever it says it.
        suppressed.add("coep-missing")
    if _shares_credentials_with_everyone(present):
        # The pair being rejected is the stronger statement, and it says the
        # wildcard never takes effect at all.
        suppressed.add("acao-wildcard")
    if _lookup(present, "Permissions-Policy") is not None:
        # Chromium is the only engine that reads either header, and it has the
        # modern one, so what the superseded spelling permits decides nothing.
        suppressed.add("fp-wildcard")
        suppressed.add("fp-empty")
    if not suppressed:
        return findings
    return [f for f in findings if f.code not in suppressed]


def analyze_all(present, secure=True, host=None):
    """analyze() across every present header, plus the missing ones and any
    cross-header suppressions.

    `present` maps header names to their raw values, in any casing: names are
    normalised here, so a response spelled `X-Frame-Options` is neither reported
    missing nor analyzed twice. `secure` tells whether the response arrived over
    TLS, which decides whether a missing HSTS header means anything, and `host`
    is the name it was fetched from, which is the one question a response cannot
    answer about itself. This is the entry point callers should use; analyze() is
    public for unit testing.
    """
    present = _normalize(present)
    findings = _report_missing(present, secure)
    for name, values in present.items():
        if name == "content-security-policy":
            findings.extend(_analyze_csp_all(values))
            continue
        for value in values:
            findings.extend(analyze(name, value))
    findings.extend(_analyze_isolation(present))
    findings.extend(_analyze_policy_overlap(present))
    findings.extend(_analyze_cors(present))
    findings.extend(_analyze_report_only(present))
    findings.extend(_analyze_duplicates(present))
    findings.extend(_analyze_preload(present, host))
    # A repeated header can raise the same defect twice, and a defect is the pair
    # of a header and what is wrong with it: the second occurrence adds nothing.
    # Two *different* headers sharing a code stay, because they are two findings.
    seen = set()
    unique = [
        f
        for f in findings
        if not ((f.header, f.code) in seen or seen.add((f.header, f.code)))
    ]
    return _suppress_redundant(unique, present)


def find_cache_headers(present):
    """Return only the headers that implement cache related features.

    Note that the values of these headers are NOT analyzed."""
    return _filter_headers(present, CACHE_HEADERS)


def find_information_headers(present):
    """Return only the headers that are commonly associated with information leaks.

    Note that the values of these headers are NOT analyzed."""
    return _filter_headers(present, INFORMATION_HEADERS)


def find_deprecated_headers(present):
    """Return only the obsolete security headers the response carries.

    Unlike the other two, the values of these headers ARE analyzed: see
    analyze()."""
    return _filter_headers(present, DEPRECATED_HEADERS)
