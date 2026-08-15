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

"""What a finding says in English, and nothing else.

Every sentence the package can produce lives here. The analysers do not import
this module and hold no prose of their own: they emit `(header, code, data)`,
where `data` carries the values that made the finding true, and the rendering
happens here or in a consumer that would rather write its own.

That split follows SARIF, which the ratings already follow: a template belongs
to the rule (`messageStrings`) and the values belong to the result
(`message.arguments`). It also means a consumer can translate these, shorten
them for a terminal, or ignore them and read `data` -- which is the point, since
the analysis is the asset and the wording is not.

The templates use `str.format` field names matching the keys of `data`. A field
that is a list is joined with commas by default; the handful of codes whose
sentence cannot be written that way have an entry in `_DISPLAY` instead, which
is the only place a fragment of a sentence is assembled in code.
"""

MESSAGES = {
    # -- absence ------------------------------------------------------------
    # Every -missing code says the same thing, and the header it belongs to is
    # on the finding, so the sentence has nothing to add.
    "coep-missing": "missing",
    "coop-missing": "missing",
    "corp-missing": "missing",
    "csp-missing": "missing",
    "hsts-missing": "missing",
    "pp-missing": "missing",
    "rp-missing": "missing",
    "xcto-missing": "missing",
    "xfo-missing": "missing",
    # -- the response as a whole --------------------------------------------
    "duplicate-headers": (
        "sent more than once, which no specification defines: clients differ "
        "on which value wins, so the response does not mean one thing"
    ),
    "coep-ro-unenforced": (
        "present but {enforcing} is not, so the policy is measured and never "
        "applied; nothing here blocks anything"
    ),
    "coop-ro-unenforced": (
        "present but {enforcing} is not, so the policy is measured and never "
        "applied; nothing here blocks anything"
    ),
    "csp-ro-unenforced": (
        "present but {enforcing} is not, so the policy is measured and never "
        "applied; nothing here blocks anything"
    ),
    "ip-ro-unenforced": (
        "present but {enforcing} is not, so the policy is measured and never "
        "applied; nothing here blocks anything"
    ),
    # -- Content-Security-Policy --------------------------------------------
    "csp-unsafe-inline": (
        "present but allows unsafe-inline in {directives}, defeating most of "
        "the cross-site scripting protection a policy provides"
    ),
    "csp-unsafe-inline-style": (
        "present but allows unsafe-inline in {directives}, so injected CSS can "
        "redress the interface and, where the policy allows an outbound "
        "source, read page data through selector-driven requests; it cannot "
        "run script"
    ),
    "csp-unsafe-eval": (
        "present but allows unsafe-eval in script-src, permitting strings to "
        "be executed as code"
    ),
    "csp-no-default-src": (
        "present but sets neither default-src nor script-src, so script "
        "loading is left unrestricted"
    ),
    "csp-wildcard": (
        "present but uses a wildcard source (*) in {directives}, allowing "
        "content from any origin"
    ),
    "csp-no-frame-ancestors": (
        "present but sets no frame-ancestors directive, so the page can be "
        "framed by any origin"
    ),
    "csp-frame-ancestors-wildcard": (
        "present but sets frame-ancestors to *, so the page can be framed by "
        "any origin, exactly as if the directive were absent"
    ),
    "csp-no-object-src": (
        "present but sets neither object-src nor default-src, so plugin "
        "content is left unrestricted"
    ),
    "csp-no-base-uri": (
        "present but sets no base-uri directive, so an injected <base> tag can "
        "redirect every relative URL on the page"
    ),
    "csp-plain-scheme": (
        "present but allows the bare scheme {schemes}, so anything served over "
        "it counts as an allowed source: every host on the web for http: and "
        "https:, any attacker-authored payload for data:"
    ),
    "csp-http-source": (
        "present but allows {sources} over plaintext HTTP, which anyone on the "
        "path can replace"
    ),
    "csp-ip-source": (
        "present but allows the IP address {addresses}, which browsers do not "
        "match against and which usually means a development entry reached "
        "production"
    ),
    "csp-missing-semicolon": (
        "present but lists {directives} as a source value, so a semicolon is "
        "missing and that directive is not in force at all"
    ),
    "csp-unknown-directive": (
        "present but sets {directives}, which no browser recognises, so that "
        "part of the policy does nothing"
    ),
    "csp-deprecated-directive": (
        "present but sets {directives}, which was dropped from the standard "
        "and is parsed and ignored"
    ),
    "csp-invalid-keyword": (
        "present but lists {sources}, which is read as a hostname rather than "
        "the keyword it resembles"
    ),
    "csp-nonce-weak": (
        "present but its nonce {nonces} is guessable: nonces need at least "
        "{minimum} base64 characters and a fresh value per response"
    ),
    # -- Strict-Transport-Security ------------------------------------------
    "hsts-malformed": "present but {problem}, so browsers ignore the policy entirely",
    "hsts-max-age-zero": (
        "present but set to max-age=0, which tells browsers to forget the "
        "policy and permits plaintext connections again"
    ),
    "hsts-max-age-short": (
        "present but its max-age is only {max_age} seconds, below the "
        "recommended minimum of {minimum} (six months)"
    ),
    "hsts-no-include-subdomains": (
        "present but does not set includeSubDomains, leaving subdomains "
        "reachable over plaintext HTTP"
    ),
    "hsts-preload-ineffective": (
        "present with preload, but the preload list requires {unmet}, so the "
        "domain would not be accepted"
    ),
    "hsts-not-preloaded": (
        "present with preload, but {host} is not on the list browsers ship, so "
        "the very first visit is still unprotected"
    ),
    # -- cross-origin isolation and CORS ------------------------------------
    "coop-unsafe-none": (
        "present but effectively unsafe-none ({value}), which provides no "
        "cross-origin isolation"
    ),
    "coep-invalid": (
        "present but has an unrecognised value ({value}); expected unsafe-none, "
        "require-corp or credentialless"
    ),
    "coep-unsafe-none": (
        "present but set to unsafe-none, which is the default and embeds "
        "cross-origin resources without requiring them to opt in"
    ),
    "coep-no-isolation": (
        "present and opting in, but Cross-Origin-Opener-Policy is not "
        "same-origin, so crossOriginIsolated stays false and the "
        "SharedArrayBuffer-class APIs remain unavailable; expected for a "
        "document meant to be embedded, since COOP is inert in a frame"
    ),
    "corp-invalid": (
        "present but has an unrecognised value ({value}); expected same-site, "
        "same-origin or cross-origin"
    ),
    "corp-cross-origin": (
        "present but set to cross-origin, so it keeps no ordinary embedder "
        "out; that is a deliberate opt-in for resources meant to stay loadable "
        "by cross-origin isolated pages, and not a restriction"
    ),
    "acao-null": (
        "present but set to null, which any sandboxed iframe or data: URL can "
        "send as its Origin, so any page can read the response"
    ),
    "acao-multiple-origins": (
        "present but lists more than one origin ({value}), which the header "
        "does not allow, so browsers reject it and no cross-origin read "
        "succeeds"
    ),
    "acao-wildcard": (
        "present and set to *, so any origin may read the response; that is "
        "deliberate for public assets and a leak for anything user-specific"
    ),
    "acao-credentials-wildcard": (
        "present as * alongside Access-Control-Allow-Credentials: true, a "
        "combination browsers refuse outright, so every credentialed "
        "cross-origin request fails"
    ),
    # -- Permissions-Policy and Feature-Policy ------------------------------
    "pp-legacy-syntax": (
        "present but written in the older Feature-Policy syntax ({value}), "
        "which browsers cannot parse, so the whole header is ignored"
    ),
    "pp-invalid": (
        "present but {item} is not a feature=allowlist pair, so browsers "
        "ignore the whole header"
    ),
    "pp-empty": "present but sets no feature, so it restricts nothing",
    "pp-wildcard": (
        "present but allows {features} in every origin (*), including third "
        "party frames the page embeds"
    ),
    "fp-deprecated": (
        "present but superseded by Permissions-Policy, which uses a different "
        "syntax; only Chromium still honours this header"
    ),
    "fp-empty": "present but sets no feature, so it restricts nothing",
    "fp-wildcard": (
        "present but allows {features} in every origin (*), including third "
        "party frames the page embeds"
    ),
    "fp-conflicts": (
        "present alongside Permissions-Policy, and the two disagree about "
        "{features}; which one applies is an implementation detail, so the "
        "policy should be stated once"
    ),
    # -- the headers with no family -----------------------------------------
    "xfo-deprecated": (
        "present but uses ALLOW-FROM, which no current browser supports; a CSP "
        "frame-ancestors directive is the replacement"
    ),
    "xfo-invalid": (
        "present but has an unrecognised value ({value}), so browsers ignore "
        "it and the page stays framable"
    ),
    "xcto-invalid": (
        "present but set to {value} rather than nosniff, so MIME type sniffing "
        "stays enabled"
    ),
    "rp-invalid": (
        "present but carries no recognised policy token ({value}), so the "
        "browser default applies instead"
    ),
    "rp-unsafe-url": (
        "present but set to unsafe-url, which leaks the full URL, query string "
        "included, to third-party origins"
    ),
    # -- Clear-Site-Data ----------------------------------------------------
    "csd-empty": "present but names no data type, so nothing is cleared",
    "csd-unquoted": (
        "present but {members} is not quoted, and the quotes are part of the "
        "value; browsers match the type with them, so this member is skipped "
        "and whatever it names is not cleared"
    ),
    "csd-unknown-type": (
        "present but {types} is not a data type browsers know, and the "
        "comparison is byte-for-byte, so the member is ignored"
    ),
    # -- Integrity-Policy ---------------------------------------------------
    "ip-invalid": (
        "present but is not a dictionary of inner lists ({value}); browsers "
        "parse the header whole or not at all, so nothing is enforced. The "
        "items of a list are separated by spaces, not commas, and are bare "
        "tokens rather than quoted strings"
    ),
    "ip-no-blocked-destinations": (
        "present but {detail}, so every script and stylesheet still loads "
        "without integrity metadata"
    ),
    "ip-sources-without-inline": (
        "present but sources is set to ({sources}) and does not include "
        "inline, and the browser supplies that default only when the directive "
        "is absent, so the policy enforces nothing despite naming a destination"
    ),
    "ip-unknown-destination": (
        "present but blocked-destinations names {destinations}, which is not a "
        "request destination the policy defines, so that entry is ignored"
    ),
    "ip-style-unsupported": (
        "present and asks for style, which no engine implements yet -- Firefox "
        "only behind a preference; the script destination beside it is "
        "unaffected"
    ),
    "ip-endpoints-undefined": (
        "present and reports to {endpoints}, which no Reporting-Endpoints "
        "header defines, so violations are caught and never delivered"
    ),
    # -- the obsolete headers -----------------------------------------------
    "ect-deprecated": "present but deprecated since June 2021",
    "p3p-deprecated": (
        "present but P3P was only ever read by Internet Explorer, which is "
        "retired, and the specification was abandoned"
    ),
    "xdo-deprecated": (
        "present but only Internet Explorer read it, to stop a download being "
        "opened in the site's own origin; no current browser does"
    ),
    "hpkp-deprecated": (
        "present but every browser has removed key pinning, so the pins bind "
        "nothing; it was withdrawn because a mistake could lock users out of a "
        "site for the lifetime of the policy"
    ),
    "hpkp-ro-deprecated": (
        "present but every browser has removed key pinning, so nothing is "
        "measured and nothing is reported"
    ),
    "xcsp-deprecated": (
        "present but no browser has read this header since Firefox 23; if it "
        "is the only policy sent, the page has none"
    ),
    "xwkcsp-deprecated": (
        "present but no browser has read this header since Chrome 25; if it is "
        "the only policy sent, the page has none"
    ),
    "xdpc-nonstandard": (
        "present but no specification defines it: browser testing finds DNS "
        "prefetching is a Chromium behaviour and that only Chrome acts on the "
        "header, so this is a Chrome-only measure rather than a policy other "
        "engines can be expected to honour"
    ),
    "xpcdp-deprecated": (
        "present but permits no cross-domain policy file, which is the "
        "restrictive setting; only Flash and Acrobat clients ever read it"
    ),
    "xpcdp-all": (
        "present but set to all, so any file on the server can serve as a "
        "cross-domain policy, including whatever a user can upload"
    ),
    "xpcdp-policy-file": (
        "present and set to {value}, which leaves cross-domain access to the "
        "policy file; check crossdomain.xml"
    ),
    "xpcdp-invalid": (
        "present but has an unrecognised value ({value}), so clients fall back "
        "to their default policy"
    ),
    "xxp-deprecated": "present but disabled",
    "xxp-enabled": (
        "present and enabled, which in some cases can create XSS "
        "vulnerabilities in otherwise safe websites"
    ),
    "xxp-blocked": (
        "present and enabled in blocked mode, which may lead to side channel "
        "attacks on iframe embeddable websites"
    ),
    "xxp-invalid": (
        "present but has an unrecognised value ({value}), expected '0', '1' or "
        "'1; mode=block'"
    ),
}


def _quoted_types(data):
    return {"types": ", ".join('"%s"' % name for name in data["types"])}


def _scheme_pairs(data):
    # The pairing is what makes this readable -- a scheme is a defect in the
    # directive that lists it, not on its own -- so the data keeps them
    # together and only the sentence flattens them.
    return {
        "schemes": ", ".join(
            "%s in %s" % (item["scheme"], item["directive"]) for item in data["schemes"]
        )
    }


def _hsts_problem(data):
    # Two ways to have no usable max-age, and the sentence differs. The data
    # does not: max_age is None when the directive was absent, and the string
    # the response sent when it was there and unreadable.
    if data["max_age"] is None:
        return {"problem": "specifies no max-age"}
    return {"problem": "its max-age is not a number (%s)" % data["max_age"]}


def _hsts_unmet(data):
    unmet = []
    if "include-subdomains" in data["unmet"]:
        unmet.append("includeSubDomains")
    if "max-age" in data["unmet"]:
        unmet.append(
            "a max-age of at least %d (one year) rather than %d"
            % (data["minimum"], data["max_age"])
        )
    return {"unmet": " and ".join(unmet)}


def _ip_detail(data):
    if not data["destinations"]:
        return {"detail": "names no destination to block"}
    return {
        "detail": "names only %s, which no engine blocks on"
        % ", ".join(data["destinations"])
    }


def _ip_sources(data):
    # A structured field inner list is space separated, and quoting it as the
    # response wrote it is the point of showing it back.
    return {"sources": " ".join(data["sources"])}


# The codes whose sentence cannot be written as a template over `data` alone.
# Everything else is a plain format string; keep this list short, because each
# entry is a piece of prose that a translator has to find.
_DISPLAY = {
    "csd-unknown-type": _quoted_types,
    "csp-plain-scheme": _scheme_pairs,
    "hsts-malformed": _hsts_problem,
    "hsts-preload-ineffective": _hsts_unmet,
    "ip-no-blocked-destinations": _ip_detail,
    "ip-sources-without-inline": _ip_sources,
}


def _joined(value):
    """A data value as a sentence says it.

    Lists are the common case -- a finding usually names several directives or
    several sources -- and every one of them reads as a comma-separated list.
    """
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    return value


def describe(finding):
    """The sentence for a finding.

    Raises KeyError for a code with no template, which is what the test suite
    checks: a code that can be emitted and cannot be worded is a bug, not a
    finding to render as best it can.
    """
    display = _DISPLAY.get(finding.code)
    data = finding.data or {}
    fields = display(data) if display else {k: _joined(v) for k, v in data.items()}
    return MESSAGES[finding.code].format(**fields)
