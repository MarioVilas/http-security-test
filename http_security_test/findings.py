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

"""Findings and how bad they are.

A finding is a fact about a header: a stable code, a message, and a rating. The
ratings are SARIF levels, so a consumer can adopt them directly, remap them, or
ignore them and apply its own model -- what a badly configured header is worth
to a particular site is not something this package can know.
"""

import collections
import json

# A finding is a header, a stable code, the values that made it true, and
# optionally its own level. `level=None` means "use FINDING_SEVERITY", which is
# the code's default and not its only possible rating: one defect can be worth
# more on one cookie than on another, and that is a rating rather than a
# different fact. This is SARIF's shape -- `result.level` overrides
# `rule.defaultConfiguration.level` -- and the report schema was already on
# this side of the line, denormalising `level` onto every finding.
Finding = collections.namedtuple("Finding", "header code data level", defaults=(None, None))


def identity(finding):
    """What makes two findings the same finding.

    The header and the code are not enough once a code can fire more than once
    against one header -- two cookies each missing Secure are two defects, not
    one -- so the data is part of it. Serialised rather than hashed because the
    values are lists and dicts, and sorted so that key order cannot make one
    finding look like two.

    The level is deliberately not part of it. A level is always derived from
    `data`, so two findings with the same identity cannot disagree about it.
    """
    return (
        finding.header,
        finding.code,
        json.dumps(finding.data, sort_keys=True, default=str),
    )


# How bad each finding is. A consumer is free to ignore these and apply its own
# model -- for most sites a badly configured header is a low-risk issue whatever
# it says here -- but they are SARIF levels, so they can be adopted directly.
# An error means the header does not deliver the protection its presence
# implies: browsers ignore it, or it permits the very thing it exists to stop.
# A warning means it protects, but a hardening directive is missing. A note is
# a fact with no defect.
FINDING_SEVERITY = {
    "acac-ineffective": "error",
    "acah-credentials-wildcard": "error",
    "acam-credentials-wildcard": "error",
    "aceh-credentials-wildcard": "error",
    "acao-credentials-wildcard": "error",
    "acao-invalid-origin": "error",
    "acao-multiple-origins": "error",
    "acao-null": "error",
    "coep-invalid": "error",
    "cookie-control-character": "error",
    "cookie-domain-mismatch": "error",
    "cookie-hidden-prefix": "error",
    "cookie-oversized": "error",
    "cookie-partitioned-insecure": "error",
    "cookie-prefix-violated": "error",
    "cookie-samesite-invalid": "error",
    "cookie-samesite-none-insecure": "error",
    "cookie-secure-over-plaintext": "error",
    "corp-invalid": "error",
    "csd-unquoted": "error",
    "csp-invalid-keyword": "error",
    "csp-missing-semicolon": "error",
    "csp-plain-scheme": "error",
    "csp-frame-ancestors-wildcard": "error",
    "csp-no-default-src": "error",
    "csp-unsafe-eval": "error",
    "csp-unsafe-inline": "error",
    "csp-wildcard": "error",
    "hsts-malformed": "error",
    "ip-invalid": "error",
    "ip-no-blocked-destinations": "error",
    "ip-sources-without-inline": "error",
    "hsts-max-age-zero": "error",
    "hsts-missing": "error",
    "hsts-preload-ineffective": "error",
    "hsts-not-preloaded": "error",
    "pp-invalid": "error",
    "pp-legacy-syntax": "error",
    "rp-invalid": "error",
    "rp-unsafe-url": "error",
    "xcto-invalid": "error",
    "xfo-allow-from": "error",
    "xfo-invalid": "error",
    "xpcdp-all": "error",
    "xpcdp-invalid": "error",
    "xxp-blocked": "error",
    "xxp-enabled": "error",
    "xxp-invalid": "error",
    "coep-no-isolation": "warning",
    "coop-missing": "warning",
    "coop-unsafe-none": "warning",
    "corp-cross-origin": "warning",
    "corp-missing": "warning",
    "csd-empty": "warning",
    "csd-unknown-type": "warning",
    "csp-http-source": "warning",
    "csp-nonce-weak": "warning",
    "csp-unknown-directive": "warning",
    "fp-empty": "warning",
    "fp-wildcard": "warning",
    "duplicate-headers": "warning",
    "csp-missing": "warning",
    "csp-no-base-uri": "warning",
    "csp-no-frame-ancestors": "warning",
    "csp-no-object-src": "warning",
    "csp-unsafe-inline-style": "warning",
    "hsts-max-age-short": "warning",
    # The reporting family is rated `note` throughout. A reporting failure
    # costs the operator information and nothing else: no browser protection is
    # withheld by it, and there is no way for an attacker to reach the site or
    # its users through a report that was never collected. That the operator
    # plainly meant the reports to arrive is what makes it worth saying at all.
    "ip-endpoints-undefined": "note",
    "csp-report-to-undefined": "note",
    "coop-report-to-undefined": "note",
    "coep-report-to-undefined": "note",
    "re-endpoint-undeliverable": "note",
    "re-ineffective": "note",
    "re-invalid": "note",
    "rt-endpoint-undeliverable": "note",
    "rt-ineffective": "note",
    "rt-invalid": "note",
    "ip-unknown-destination": "warning",
    "hsts-no-include-subdomains": "warning",
    "pp-empty": "warning",
    "pp-wildcard": "warning",
    "rp-missing": "warning",
    "xcto-missing": "warning",
    "xfo-missing": "warning",
    "coep-missing": "note",
    "coep-unsafe-none": "note",
    "csp-deprecated-directive": "note",
    "ct-no-charset": "note",
    "csp-ip-source": "note",
    "fp-deprecated": "note",
    "hpkp-deprecated": "note",
    "ip-ro-unenforced": "note",
    "ip-style-unsupported": "note",
    "xdpc-nonstandard": "note",
    "hpkp-ro-deprecated": "note",
    "sc2-deprecated": "note",
    "xcsp-deprecated": "note",
    "xwkcsp-deprecated": "note",
    "fp-conflicts": "note",
    "p3p-deprecated": "note",
    "xdo-deprecated": "note",
    "acao-wildcard": "note",
    # Neither of these withholds anything a browser would otherwise do: a
    # forbidden method is one no browser sends however it is answered, and a
    # max-age that will not parse costs a preflight round trip, not a
    # protection. Both are facts about a configuration that does nothing.
    "acam-forbidden-method": "note",
    "acma-invalid": "note",
    "coep-ro-unenforced": "note",
    "coop-ro-unenforced": "note",
    "csp-ro-unenforced": "note",
    "ect-deprecated": "note",
    "pp-missing": "note",
    "xpcdp-deprecated": "note",
    "xpcdp-policy-file": "note",
    "xxp-deprecated": "note",
    "cookie-domain-broad": "note",
    "cookie-no-httponly": "note",
    "cookie-no-samesite": "note",
    "cookie-no-secure": "note",
    "cookie-persistent": "note",
    "cookie-samesite-none": "note",
    "cookie-unknown-attribute": "note",
}


# Which header a code belongs to, declared rather than inferred. The prefix of a
# code is a mnemonic and not a lookup -- `re-` is Reporting-Endpoints and `rp-`
# is Referrer-Policy -- so a consumer that wants the owning header has no way to
# ask without this. `explain` is the first caller and a SARIF writer's rules[]
# will be the second. None means the response rather than any one header.
CODE_HEADER = {
    # duplicate-headers is about the response, not any one header: any
    # header may be repeated, so a code-keyed view cannot name an owner.
    "duplicate-headers": None,
    # -- Access-Control-Allow-Credentials
    "acac-ineffective": "Access-Control-Allow-Credentials",
    # -- Access-Control-Allow-Headers
    "acah-credentials-wildcard": "Access-Control-Allow-Headers",
    # -- Access-Control-Allow-Methods
    "acam-credentials-wildcard": "Access-Control-Allow-Methods",
    "acam-forbidden-method": "Access-Control-Allow-Methods",
    # -- Access-Control-Allow-Origin
    "acao-credentials-wildcard": "Access-Control-Allow-Origin",
    "acao-invalid-origin": "Access-Control-Allow-Origin",
    "acao-multiple-origins": "Access-Control-Allow-Origin",
    "acao-null": "Access-Control-Allow-Origin",
    "acao-wildcard": "Access-Control-Allow-Origin",
    # -- Access-Control-Expose-Headers
    "aceh-credentials-wildcard": "Access-Control-Expose-Headers",
    # -- Access-Control-Max-Age
    "acma-invalid": "Access-Control-Max-Age",
    # -- Clear-Site-Data
    "csd-empty": "Clear-Site-Data",
    "csd-unknown-type": "Clear-Site-Data",
    "csd-unquoted": "Clear-Site-Data",
    # -- Content-Security-Policy
    "csp-deprecated-directive": "Content-Security-Policy",
    "csp-frame-ancestors-wildcard": "Content-Security-Policy",
    "csp-http-source": "Content-Security-Policy",
    "csp-invalid-keyword": "Content-Security-Policy",
    "csp-ip-source": "Content-Security-Policy",
    "csp-missing": "Content-Security-Policy",
    "csp-missing-semicolon": "Content-Security-Policy",
    "csp-no-base-uri": "Content-Security-Policy",
    "csp-no-default-src": "Content-Security-Policy",
    "csp-no-frame-ancestors": "Content-Security-Policy",
    "csp-no-object-src": "Content-Security-Policy",
    "csp-nonce-weak": "Content-Security-Policy",
    "csp-plain-scheme": "Content-Security-Policy",
    "csp-report-to-undefined": "Content-Security-Policy",
    "csp-unknown-directive": "Content-Security-Policy",
    "csp-unsafe-eval": "Content-Security-Policy",
    "csp-unsafe-inline": "Content-Security-Policy",
    "csp-unsafe-inline-style": "Content-Security-Policy",
    "csp-wildcard": "Content-Security-Policy",
    # -- Content-Security-Policy-Report-Only
    "csp-ro-unenforced": "Content-Security-Policy-Report-Only",
    # -- Content-Type
    "ct-no-charset": "Content-Type",
    # -- Cross-Origin-Embedder-Policy
    "coep-invalid": "Cross-Origin-Embedder-Policy",
    "coep-missing": "Cross-Origin-Embedder-Policy",
    "coep-no-isolation": "Cross-Origin-Embedder-Policy",
    "coep-report-to-undefined": "Cross-Origin-Embedder-Policy",
    "coep-unsafe-none": "Cross-Origin-Embedder-Policy",
    # -- Cross-Origin-Embedder-Policy-Report-Only
    "coep-ro-unenforced": "Cross-Origin-Embedder-Policy-Report-Only",
    # -- Cross-Origin-Opener-Policy
    "coop-missing": "Cross-Origin-Opener-Policy",
    "coop-report-to-undefined": "Cross-Origin-Opener-Policy",
    "coop-unsafe-none": "Cross-Origin-Opener-Policy",
    # -- Cross-Origin-Opener-Policy-Report-Only
    "coop-ro-unenforced": "Cross-Origin-Opener-Policy-Report-Only",
    # -- Cross-Origin-Resource-Policy
    "corp-cross-origin": "Cross-Origin-Resource-Policy",
    "corp-invalid": "Cross-Origin-Resource-Policy",
    "corp-missing": "Cross-Origin-Resource-Policy",
    # -- Expect-CT
    "ect-deprecated": "Expect-CT",
    # -- Feature-Policy
    "fp-conflicts": "Feature-Policy",
    "fp-deprecated": "Feature-Policy",
    "fp-empty": "Feature-Policy",
    "fp-wildcard": "Feature-Policy",
    # -- Integrity-Policy
    "ip-endpoints-undefined": "Integrity-Policy",
    "ip-invalid": "Integrity-Policy",
    "ip-no-blocked-destinations": "Integrity-Policy",
    "ip-sources-without-inline": "Integrity-Policy",
    "ip-style-unsupported": "Integrity-Policy",
    "ip-unknown-destination": "Integrity-Policy",
    # -- Integrity-Policy-Report-Only
    "ip-ro-unenforced": "Integrity-Policy-Report-Only",
    # -- P3P
    "p3p-deprecated": "P3P",
    # -- Permissions-Policy
    "pp-empty": "Permissions-Policy",
    "pp-invalid": "Permissions-Policy",
    "pp-legacy-syntax": "Permissions-Policy",
    "pp-missing": "Permissions-Policy",
    "pp-wildcard": "Permissions-Policy",
    # -- Public-Key-Pins
    "hpkp-deprecated": "Public-Key-Pins",
    # -- Public-Key-Pins-Report-Only
    "hpkp-ro-deprecated": "Public-Key-Pins-Report-Only",
    # -- Referrer-Policy
    "rp-invalid": "Referrer-Policy",
    "rp-missing": "Referrer-Policy",
    "rp-unsafe-url": "Referrer-Policy",
    # -- Report-To
    "rt-endpoint-undeliverable": "Report-To",
    "rt-ineffective": "Report-To",
    "rt-invalid": "Report-To",
    # -- Reporting-Endpoints
    "re-endpoint-undeliverable": "Reporting-Endpoints",
    "re-ineffective": "Reporting-Endpoints",
    "re-invalid": "Reporting-Endpoints",
    # -- Set-Cookie
    "cookie-control-character": "Set-Cookie",
    "cookie-domain-broad": "Set-Cookie",
    "cookie-domain-mismatch": "Set-Cookie",
    "cookie-hidden-prefix": "Set-Cookie",
    "cookie-no-httponly": "Set-Cookie",
    "cookie-no-samesite": "Set-Cookie",
    "cookie-no-secure": "Set-Cookie",
    "cookie-oversized": "Set-Cookie",
    "cookie-partitioned-insecure": "Set-Cookie",
    "cookie-persistent": "Set-Cookie",
    "cookie-prefix-violated": "Set-Cookie",
    "cookie-samesite-invalid": "Set-Cookie",
    "cookie-samesite-none": "Set-Cookie",
    "cookie-samesite-none-insecure": "Set-Cookie",
    "cookie-secure-over-plaintext": "Set-Cookie",
    "cookie-unknown-attribute": "Set-Cookie",
    # -- Set-Cookie2
    "sc2-deprecated": "Set-Cookie2",
    # -- Strict-Transport-Security
    "hsts-malformed": "Strict-Transport-Security",
    "hsts-max-age-short": "Strict-Transport-Security",
    "hsts-max-age-zero": "Strict-Transport-Security",
    "hsts-missing": "Strict-Transport-Security",
    "hsts-no-include-subdomains": "Strict-Transport-Security",
    "hsts-not-preloaded": "Strict-Transport-Security",
    "hsts-preload-ineffective": "Strict-Transport-Security",
    # -- X-Content-Security-Policy
    "xcsp-deprecated": "X-Content-Security-Policy",
    # -- X-Content-Type-Options
    "xcto-invalid": "X-Content-Type-Options",
    "xcto-missing": "X-Content-Type-Options",
    # -- X-DNS-Prefetch-Control
    "xdpc-nonstandard": "X-DNS-Prefetch-Control",
    # -- X-Download-Options
    "xdo-deprecated": "X-Download-Options",
    # -- X-Frame-Options
    "xfo-allow-from": "X-Frame-Options",
    "xfo-invalid": "X-Frame-Options",
    "xfo-missing": "X-Frame-Options",
    # -- X-Permitted-Cross-Domain-Policies
    "xpcdp-all": "X-Permitted-Cross-Domain-Policies",
    "xpcdp-deprecated": "X-Permitted-Cross-Domain-Policies",
    "xpcdp-invalid": "X-Permitted-Cross-Domain-Policies",
    "xpcdp-policy-file": "X-Permitted-Cross-Domain-Policies",
    # -- X-WebKit-CSP
    "xwkcsp-deprecated": "X-WebKit-CSP",
    # -- X-XSS-Protection
    "xxp-blocked": "X-XSS-Protection",
    "xxp-deprecated": "X-XSS-Protection",
    "xxp-enabled": "X-XSS-Protection",
    "xxp-invalid": "X-XSS-Protection",
}


# What each code's misconfiguration could lead to. Empty is a result and not an
# omission: a reporting failure costs the operator information and withholds no
# protection, and most CORS defects fail closed -- the preflight fails, nothing
# is over-shared -- so those carry nothing. The ratings and this table are
# independent axes on purpose: acao-credentials-wildcard is an error with no
# consequence, and acao-wildcard is a note with a real one.
CODE_CONSEQUENCES = {
    # -- Content-Security-Policy
    "csp-deprecated-directive": (),  # parsed and ignored; nothing was lost
    "csp-frame-ancestors-wildcard": ("clickjacking",),
    "csp-http-source": ("mitm", "xss"),  # a plaintext script source is swappable
    "csp-invalid-keyword": ("xss",),
    "csp-ip-source": (),  # browsers do not match it; a dev leftover
    "csp-missing": ("xss",),
    "csp-missing-semicolon": ("xss",),
    "csp-no-base-uri": ("xss",),
    "csp-no-default-src": ("xss",),
    "csp-no-frame-ancestors": ("clickjacking",),
    "csp-no-object-src": ("xss",),
    "csp-nonce-weak": ("xss",),
    "csp-plain-scheme": ("xss",),
    "csp-report-to-undefined": (),  # reporting: the operator loses a report
    "csp-ro-unenforced": (),  # report-only content decides nothing
    "csp-unknown-directive": (),  # what it meant to do is unknowable
    "csp-unsafe-eval": ("xss",),
    "csp-unsafe-inline": ("xss",),
    # Not xss: the message is explicit that injected CSS cannot run script. It
    # can redress the interface and read page data through selector-driven
    # requests, which is those two slugs exactly.
    "csp-unsafe-inline-style": ("clickjacking", "data-disclosure"),
    "csp-wildcard": ("xss",),
    # -- Strict-Transport-Security
    "hsts-malformed": ("mitm",),
    "hsts-max-age-short": ("mitm",),
    "hsts-max-age-zero": ("mitm",),
    "hsts-missing": ("mitm",),
    "hsts-no-include-subdomains": ("mitm",),
    "hsts-not-preloaded": ("mitm",),
    "hsts-preload-ineffective": ("mitm",),
    # -- X-Frame-Options
    "xfo-allow-from": ("clickjacking",),
    "xfo-invalid": ("clickjacking",),
    "xfo-missing": ("clickjacking",),
    # -- X-Content-Type-Options
    # CAPEC names this exactly -- CAPEC-209 "XSS Using MIME Type Mismatch" --
    # which is why there is no separate mime-confusion slug. The overlay in
    # Task 7 attaches that id to the code.
    "xcto-invalid": ("xss",),
    "xcto-missing": ("xss",),
    # -- Referrer-Policy
    "rp-invalid": ("data-disclosure",),
    "rp-missing": ("data-disclosure",),
    "rp-unsafe-url": ("data-disclosure",),
    # -- Access-Control-* : nine of eleven carry nothing, and that is the result.
    # Read the messages: these describe a response that FAILS CLOSED. "the
    # preflight fails", "no cross-origin read succeeds", "browsers refuse
    # outright". They are availability and interop defects, not exposure -- the
    # same reading CLAUDE.md already applies to ACAH: *. Only the two below
    # widen access to anybody.
    "acac-ineffective": (),
    "acah-credentials-wildcard": (),
    "acam-credentials-wildcard": (),
    "acam-forbidden-method": (),
    "aceh-credentials-wildcard": (),
    "acma-invalid": (),
    "acao-credentials-wildcard": (),
    "acao-invalid-origin": (),
    "acao-multiple-origins": (),
    "acao-null": ("cors-data-theft",),  # any sandboxed frame can send Origin: null
    "acao-wildcard": ("cors-data-theft",),
    # -- Cross-Origin-Embedder-Policy
    "coep-invalid": ("cross-origin-leak",),
    "coep-missing": ("cross-origin-leak",),
    # Loss of function, not of protection: the message is about
    # crossOriginIsolated staying false and SharedArrayBuffer being unavailable.
    "coep-no-isolation": (),
    "coep-report-to-undefined": (),
    "coep-ro-unenforced": (),
    "coep-unsafe-none": ("cross-origin-leak",),
    # -- Cross-Origin-Opener-Policy
    "coop-missing": ("cross-origin-leak",),
    "coop-report-to-undefined": (),
    "coop-ro-unenforced": (),
    "coop-unsafe-none": ("cross-origin-leak",),
    # -- Cross-Origin-Resource-Policy
    "corp-cross-origin": ("cross-origin-leak",),
    "corp-invalid": ("cross-origin-leak",),
    "corp-missing": ("cross-origin-leak",),
    # -- Clear-Site-Data: every one of these is a logout that does not clear.
    "csd-empty": ("cache-exposure",),
    "csd-unknown-type": ("cache-exposure",),
    "csd-unquoted": ("cache-exposure",),
    # -- X-Permitted-Cross-Domain-Policies. CWE-942 is literally "Permissive
    # Cross-domain Security Policy with Untrusted Domains", written for this.
    "xpcdp-all": ("cors-data-theft",),
    "xpcdp-deprecated": (),  # the restrictive setting; no defect
    "xpcdp-invalid": ("cors-data-theft",),
    "xpcdp-policy-file": ("cors-data-theft",),
    # -- X-XSS-Protection
    "xxp-blocked": ("cross-origin-leak",),  # the message names a side channel
    "xxp-deprecated": (),  # "present but disabled" is correct
    "xxp-enabled": ("xss",),  # the auditor introduced XSS
    "xxp-invalid": (),  # falls back to a default that is inert
    # -- Permissions-Policy / Feature-Policy
    "pp-empty": ("permission-abuse",),
    "pp-invalid": ("permission-abuse",),  # whole header ignored
    "pp-legacy-syntax": ("permission-abuse",),  # whole header ignored
    "pp-missing": ("permission-abuse",),
    "pp-wildcard": ("permission-abuse",),
    "fp-conflicts": (),  # says which header wins, not a risk
    "fp-deprecated": (),
    "fp-empty": ("permission-abuse",),
    "fp-wildcard": ("permission-abuse",),
    # -- Integrity-Policy. Its job is to refuse subresources with no integrity
    # metadata, so a policy that enforces nothing leaves a compromised CDN
    # script running in the page.
    "ip-endpoints-undefined": (),  # reporting only
    "ip-invalid": ("xss",),
    "ip-no-blocked-destinations": ("xss",),
    "ip-ro-unenforced": (),
    "ip-sources-without-inline": ("xss",),
    "ip-style-unsupported": (),  # no engine implements it either way
    "ip-unknown-destination": ("xss",),
    # -- Reporting. The whole family carries nothing, which is the same
    # reasoning that rates it all `note`: a reporting failure costs the
    # operator information and withholds no browser protection.
    "re-endpoint-undeliverable": (),
    "re-ineffective": (),
    "re-invalid": (),
    "rt-endpoint-undeliverable": (),
    "rt-ineffective": (),
    "rt-invalid": (),
    # -- Legacy CSP aliases: if one of these is the only policy sent, the page
    # has no policy at all.
    "xcsp-deprecated": ("xss",),
    "xwkcsp-deprecated": ("xss",),
    # -- Everything else that withholds no protection.
    "ct-no-charset": (),  # the message says outright: not a defect
    "ect-deprecated": (),
    "hpkp-deprecated": (),  # browsers removed pinning; the pins bind nothing
    "hpkp-ro-deprecated": (),
    "p3p-deprecated": (),
    # No browser stores the cookie, so nothing it could have carried -- a
    # session token included -- is exposed by it. What the header costs its
    # operator is the parked hygiene question, which is not this vocabulary.
    "sc2-deprecated": (),
    "xdo-deprecated": (),
    "xdpc-nonstandard": (),  # `on` is the default everywhere it works
    # Ambiguity rather than a named risk: which value wins is client-specific,
    # so what it costs depends on which header repeated and cannot be said here.
    "duplicate-headers": (),
    # -- Set-Cookie. The empty ones fail closed: a discarded cookie and a
    # rejected Partitioned attribute both leave a feature absent rather than
    # anything over-shared.
    "cookie-control-character": (),
    "cookie-domain-broad": ("session-theft",),
    "cookie-domain-mismatch": ("session-theft",),
    "cookie-hidden-prefix": ("session-theft",),
    "cookie-no-httponly": ("session-theft",),
    "cookie-no-samesite": ("csrf",),
    "cookie-no-secure": ("mitm", "session-theft"),
    "cookie-oversized": (),
    "cookie-partitioned-insecure": (),
    "cookie-persistent": ("session-theft", "cache-exposure"),
    "cookie-prefix-violated": ("session-theft",),
    "cookie-samesite-invalid": ("csrf",),
    "cookie-samesite-none": ("csrf",),
    "cookie-samesite-none-insecure": ("csrf", "mitm"),
    "cookie-secure-over-plaintext": ("mitm", "session-theft"),
    # Empty because the note asserts no defect. Where a misspelling does cause
    # one, the consequences are carried by the absence finding it escalates,
    # which already holds exactly the right slugs.
    "cookie-unknown-attribute": (),
}


def consequences(code):
    """The consequence slugs for a code, worst-case first in table order."""
    return CODE_CONSEQUENCES.get(code, ())


# A sparse overlay: a specific published entry, where one describes a code
# better than its slug's general classification does. Most codes have no entry
# and simply inherit. This is the one table in the package that is NOT a
# bijection with the emittable codes, and that is deliberate -- an absent entry
# means "no better id was found", never "none exists".
CODE_TAXONOMY = {
    # CAPEC-209 "XSS Using MIME Type Mismatch" is the exact mechanism.
    "xcto-invalid": ("CAPEC-209",),
    "xcto-missing": ("CAPEC-209",),
    # CAPEC-102 "Session Sidejacking" is the specific loss, where the slug's
    # CAPEC-117 "Interception" is the Meta-level parent.
    "hsts-malformed": ("CAPEC-102",),
    "hsts-max-age-zero": ("CAPEC-102",),
    "hsts-missing": ("CAPEC-102",),
    # CAPEC-222 "iFrame Overlay" joins CWE-1021 and names the delivery.
    "xfo-allow-from": ("CAPEC-222",),
    "xfo-invalid": ("CAPEC-222",),
    "xfo-missing": ("CAPEC-222",),
    "csp-frame-ancestors-wildcard": ("CAPEC-222",),
    "csp-no-frame-ancestors": ("CAPEC-222",),
}


def _identifier_sort_key(identifier):
    # By scheme then NUMERIC id. Lexically, CWE-1021 sorts before CWE-79.
    scheme, _, number = identifier.partition("-")
    return (scheme, int(number))


def taxonomy(code):
    """Every taxonomy identifier for a code: its slugs' union the overlay's."""
    # Function-local, not module-level. catalog.py imports nothing from this
    # package today, so a module-scope import here would not actually be a
    # cycle -- but deferring it keeps catalog.py free to import findings.py
    # later without one opening up, which a module-scope import would foreclose.
    from .catalog import CONSEQUENCES

    ids = {i for s in consequences(code) for i in CONSEQUENCES[s].taxonomy}
    ids.update(CODE_TAXONOMY.get(code, ()))
    return tuple(sorted(ids, key=_identifier_sort_key))


# Worst first; also the order findings are printed in.
SEVERITIES = ("error", "warning", "note")


def severity(code):
    """How bad a finding is. Unknown codes are warnings, never crashes."""
    return FINDING_SEVERITY.get(code, "warning")


# Codes whose level can be raised above their default by evidence in `data`.
# `hst explain` reads this so it can say the level it prints is a floor.
ESCALATABLE = frozenset(
    [
        "cookie-domain-broad",
        "cookie-no-httponly",
        "cookie-no-samesite",
        "cookie-no-secure",
        "cookie-persistent",
        "cookie-samesite-none",
    ]
)


def level_of(finding):
    """A finding's level: its own if it carries one, else its code's default.

    `severity()` answers about a *code* and stays the public spelling of that
    question. This answers about a *finding*, which is what a renderer wants.
    """
    return finding.level or severity(finding.code)


def order_findings(findings):
    """Worst first, so a header's headline problem reads first."""
    return sorted(findings, key=lambda f: SEVERITIES.index(level_of(f)))
