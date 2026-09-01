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
this module and hold no prose of their own: they emit
`(header, code, data, level)`, where `data` carries the values that made the
finding true, and the rendering happens here or in a consumer that would rather
write its own.

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

import collections

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
        "present but {enforcing} is not, so the policy is measured and never applied; nothing here blocks anything"
    ),
    "coop-ro-unenforced": (
        "present but {enforcing} is not, so the policy is measured and never applied; nothing here blocks anything"
    ),
    "csp-ro-unenforced": (
        "present but {enforcing} is not, so the policy is measured and never applied; nothing here blocks anything"
    ),
    "ip-ro-unenforced": (
        "present but {enforcing} is not, so the policy is measured and never applied; nothing here blocks anything"
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
    "csp-unsafe-eval": ("present but allows unsafe-eval in script-src, permitting strings to be executed as code"),
    "csp-no-default-src": (
        "present but sets neither default-src nor script-src, so script loading is left unrestricted"
    ),
    "csp-wildcard": ("present but uses a wildcard source (*) in {directives}, allowing content from any origin"),
    "csp-no-frame-ancestors": (
        "present but sets no frame-ancestors directive, so the page can be framed by any origin"
    ),
    "csp-frame-ancestors-wildcard": (
        "present but sets frame-ancestors to *, so the page can be framed by "
        "any origin, exactly as if the directive were absent"
    ),
    "csp-no-object-src": (
        "present but sets neither object-src nor default-src, so plugin content is left unrestricted"
    ),
    "csp-no-base-uri": (
        "present but sets no base-uri directive, so an injected <base> tag can redirect every relative URL on the page"
    ),
    "csp-plain-scheme": (
        "present but allows the bare scheme {schemes}, so anything served over "
        "it counts as an allowed source: every host on the web for http: and "
        "https:, any attacker-authored payload for data:"
    ),
    "csp-http-source": ("present but allows {sources} over plaintext HTTP, which anyone on the path can replace"),
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
        "present but sets {directives}, which no browser recognises, so that part of the policy does nothing"
    ),
    "csp-deprecated-directive": (
        "present but sets {directives}, which was dropped from the standard and is parsed and ignored"
    ),
    "csp-invalid-keyword": (
        "present but lists {sources}, which is read as a hostname rather than the keyword it resembles"
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
        "present but its max-age is only {max_age} seconds, below the recommended minimum of {minimum} (six months)"
    ),
    "hsts-no-include-subdomains": (
        "present but does not set includeSubDomains, leaving subdomains reachable over plaintext HTTP"
    ),
    "hsts-preload-ineffective": (
        "present with preload, but the preload list requires {unmet}, so the domain would not be accepted"
    ),
    "hsts-not-preloaded": (
        "present with preload, but {host} is not on the list browsers ship, so "
        "the very first visit is still unprotected"
    ),
    # -- cross-origin isolation and CORS ------------------------------------
    "coop-unsafe-none": ("present but effectively unsafe-none ({value}), which provides no cross-origin isolation"),
    "coep-invalid": (
        "present but has an unrecognised value ({value}); expected unsafe-none, require-corp or credentialless"
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
        "present but has an unrecognised value ({value}); expected same-site, same-origin or cross-origin"
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
    "acao-invalid-origin": (
        "present but {value} is not a serialized origin, which browsers compare "
        "byte for byte, so it matches nothing and no cross-origin read succeeds"
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
    "acac-ineffective": (
        "present as {value}, which browsers compare against the byte string "
        "true and so read as a refusal, leaving every credentialed "
        "cross-origin request blocked; expected true in lower case"
    ),
    "acam-credentials-wildcard": (
        "present as * alongside Access-Control-Allow-Credentials: true, and a "
        "credentialed request reads the * as a method literally named *, so no "
        "method is allowed and the preflight fails; expected each method listed"
    ),
    "acah-credentials-wildcard": (
        "present as * alongside Access-Control-Allow-Credentials: true, and a "
        "credentialed request reads the * as a header literally named *, so no "
        "header is allowed and the preflight fails; expected each header listed"
    ),
    "aceh-credentials-wildcard": (
        "present as * alongside Access-Control-Allow-Credentials: true, and a "
        "credentialed request reads the * as a header literally named *, so the "
        "script sees only the safelisted response headers; expected each "
        "header listed"
    ),
    "acam-forbidden-method": (
        "present and allows {methods}, which browsers refuse to send whatever a "
        "preflight answers, so allowing them permits nothing"
    ),
    "acma-invalid": (
        "present but its value ({value}) is not a number of seconds, so the "
        "preflight cache interval asked for is not the one used: Chromium falls "
        "back to five seconds and Firefox caches nothing"
    ),
    # -- Permissions-Policy and Feature-Policy ------------------------------
    "pp-legacy-syntax": (
        "present but written in the older Feature-Policy syntax ({value}), "
        "which browsers cannot parse, so the whole header is ignored"
    ),
    "pp-invalid": ("present but {item} is not a feature=allowlist pair, so browsers ignore the whole header"),
    "pp-empty": "present but sets no feature, so it restricts nothing",
    "pp-wildcard": ("present but allows {features} in every origin (*), including third party frames the page embeds"),
    "fp-deprecated": (
        "present but superseded by Permissions-Policy, which uses a different "
        "syntax; only Chromium still honours this header"
    ),
    "fp-empty": "present but sets no feature, so it restricts nothing",
    "fp-wildcard": ("present but allows {features} in every origin (*), including third party frames the page embeds"),
    "fp-conflicts": (
        "present alongside Permissions-Policy, and the two disagree about "
        "{features}; which one applies is an implementation detail, so the "
        "policy should be stated once"
    ),
    # -- the headers with no family -----------------------------------------
    "xfo-allow-from": (
        "present but uses ALLOW-FROM, which no current browser supports; a CSP "
        "frame-ancestors directive is the replacement"
    ),
    "xfo-invalid": (
        "present but has an unrecognised value ({value}), so browsers ignore it and the page stays framable"
    ),
    "xcto-invalid": ("present but set to {value} rather than nosniff, so MIME type sniffing stays enabled"),
    "rp-invalid": ("present but carries no recognised policy token ({value}), so the browser default applies instead"),
    "rp-unsafe-url": (
        "present but set to unsafe-url, which leaks the full URL, query string included, to third-party origins"
    ),
    "ct-no-charset": (
        "present as {media_type} with no charset parameter, so the encoding is "
        "whatever the browser falls back to. The injection this once enabled "
        "needed UTF-7, which current browsers dropped, and a <meta charset> in "
        "the document settles it just as well -- worth knowing, not a defect"
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
        "present but {detail}, so every script and stylesheet still loads without integrity metadata"
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
        "present and reports to {endpoints}, which no Reporting-Endpoints or "
        "Report-To header defines, so violations are caught and never delivered"
    ),
    "csp-report-to-undefined": (
        "present and reports violations to {groups}, which no Reporting-Endpoints "
        "or Report-To header defines, so the policy enforces and every violation "
        "it catches is discarded"
    ),
    "coop-report-to-undefined": (
        "present and reports to {groups}, which no Reporting-Endpoints or "
        "Report-To header defines, so the policy applies and every report it "
        "would have sent is discarded"
    ),
    "coep-report-to-undefined": (
        "present and reports to {groups}, which no Reporting-Endpoints or "
        "Report-To header defines, so the policy applies and every report it "
        "would have sent is discarded"
    ),
    "re-endpoint-undeliverable": (
        "present but the endpoint behind {endpoints} is not a URL browsers "
        "deliver reports to -- it must be HTTPS, or a loopback address -- so "
        "anything reporting to that group is discarded"
    ),
    "re-ineffective": (
        "present on a response that did not arrive over HTTPS, where browsers "
        "ignore the header entirely, so every group it defines is undefined and "
        "no report of any kind is delivered"
    ),
    "re-invalid": (
        "present but is not a structured field dictionary; browsers parse the "
        "header whole or not at all, so every group it meant to define is "
        "undefined. Keys are lower-case: a-z, digits and _ - . * only"
    ),
    "rt-endpoint-undeliverable": (
        "present but the endpoint behind {endpoints} is not a URL browsers "
        "deliver reports to -- it must be HTTPS, or a loopback address -- so "
        "anything reporting to that group is discarded"
    ),
    "rt-ineffective": (
        "present on a response that did not arrive over HTTPS, where browsers "
        "ignore the header entirely, so every group it defines is undefined and "
        "no report of any kind is delivered"
    ),
    "rt-invalid": (
        "present but its value is not the JSON the header is defined as "
        "carrying, so browsers read no endpoint group out of it at all"
    ),
    # -- the obsolete headers -----------------------------------------------
    "ect-deprecated": "present but deprecated since June 2021",
    "p3p-deprecated": (
        "present but P3P was only ever read by Internet Explorer, which is retired, and the specification was abandoned"
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
        "present but every browser has removed key pinning, so nothing is measured and nothing is reported"
    ),
    "xcsp-deprecated": (
        "present but no browser has read this header since Firefox 23; if it is the only policy sent, the page has none"
    ),
    "xwkcsp-deprecated": (
        "present but no browser has read this header since Chrome 25; if it is the only policy sent, the page has none"
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
        "present and set to {value}, which leaves cross-domain access to the policy file; check crossdomain.xml"
    ),
    "xpcdp-invalid": ("present but has an unrecognised value ({value}), so clients fall back to their default policy"),
    "xxp-deprecated": "present but disabled",
    "xxp-enabled": (
        "present and enabled, which in some cases can create XSS vulnerabilities in otherwise safe websites"
    ),
    "xxp-blocked": (
        "present and enabled in blocked mode, which may lead to side channel attacks on iframe embeddable websites"
    ),
    "xxp-invalid": ("present but has an unrecognised value ({value}), expected '0', '1' or '1; mode=block'"),
    # -- Set-Cookie -----------------------------------------------------------
    "cookie-control-character": (
        "{cookie} contains a control character, so browsers discard the whole "
        "Set-Cookie header and the cookie is never set"
    ),
    "cookie-oversized": (
        "{cookie} has a name and value totalling {octets} octets, over the "
        "4096-octet limit, so browsers discard it entirely"
    ),
    "cookie-samesite-invalid": (
        "{cookie} {setting}, which no browser recognises, so it "
        "falls back to the default -- Lax in Chrome, and no cross-site "
        "restriction at all in Firefox and Safari"
    ),
    "cookie-samesite-none-insecure": (
        "{cookie} sets SameSite=None without Secure, so Chrome and Firefox "
        "reject the cookie outright and Safari sends it cross-site in "
        "cleartext"
    ),
    "cookie-secure-over-plaintext": (
        "{cookie} is marked Secure on a response that did not arrive over a "
        "trustworthy origin, so the cookie is not stored at all"
    ),
    "cookie-partitioned-insecure": (
        "{cookie} sets Partitioned without Secure, so the partitioning attribute is rejected"
    ),
    "cookie-prefix-violated": (
        "{cookie} carries the {prefix} prefix but does not meet its "
        "requirements ({unmet}), so browsers reject the cookie"
    ),
    "cookie-hidden-prefix": (
        "a nameless cookie carries a value beginning {prefix}, which browsers "
        "reject and anything re-parsing it would read as a prefixed cookie "
        "that never met the prefix rules"
    ),
    "cookie-domain-mismatch": (
        "{cookie} sets Domain={domain}, which is not {host} nor a parent of it, so browsers reject the cookie"
    ),
    "cookie-no-secure": (
        "{cookie} has no Secure attribute, so the browser will send it over plaintext HTTP to this host"
    ),
    "cookie-no-httponly": ("{cookie} has no HttpOnly attribute, so scripts running in the page can read it"),
    "cookie-no-samesite": (
        "{cookie} has no SameSite attribute; Chrome defaults it to Lax, while "
        "Firefox and Safari send it on cross-site requests"
    ),
    "cookie-samesite-none": (
        "{cookie} sets SameSite=None, so it is sent on cross-site requests to this host by design"
    ),
    "cookie-persistent": ("{cookie} sets an expiry, so it is written to disk and outlives the browser session"),
    "cookie-domain-broad": ("{cookie} sets Domain={domain}, so every subdomain of it receives the cookie"),
    "cookie-unknown-attribute": ("{cookie} sets the attribute {attribute}, which no browser recognises{detail}"),
}


def _quoted_types(data):
    return {"types": ", ".join('"%s"' % name for name in data["types"])}


def _scheme_pairs(data):
    # The pairing is what makes this readable -- a scheme is a defect in the
    # directive that lists it, not on its own -- so the data keeps them
    # together and only the sentence flattens them.
    return {"schemes": ", ".join("%s in %s" % (item["scheme"], item["directive"]) for item in data["schemes"])}


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
        unmet.append("a max-age of at least %d (one year) rather than %d" % (data["minimum"], data["max_age"]))
    return {"unmet": " and ".join(unmet)}


def _ip_detail(data):
    if not data["destinations"]:
        return {"detail": "names no destination to block"}
    return {"detail": "names only %s, which no engine blocks on" % ", ".join(data["destinations"])}


def _ip_sources(data):
    # A structured field inner list is space separated, and quoting it as the
    # response wrote it is the point of showing it back.
    return {"sources": " ".join(data["sources"])}


def _cookie_subject(data):
    """`data`, with an empty {cookie} given a readable placeholder.

    An empty name is a legal cookie -- rfc6265bis 5.2 step 3, see the
    docstring of `cookies.parse_set_cookie` -- and every cookie template's
    sentence opens with the cookie naming itself as the subject. Left alone, a
    nameless cookie renders a leading space where a subject belongs.
    `cookie-hidden-prefix` never hits this because its own template has no
    {cookie} field at all ("a nameless cookie carries a value beginning...");
    every other cookie code does, tier 1 and tier 2 alike, so all of them
    route through here rather than through the default
    `{k: _joined(v) ...}` path `describe()` otherwise uses.
    """
    fields = {k: _joined(v) for k, v in data.items()}
    if fields.get("cookie") == "":
        fields["cookie"] = "a nameless cookie"
    return fields


def _samesite_invalid(data):
    """The SameSite clause, which reads differently for the two spellings.

    `Set-Cookie: a=b; SameSite` carries no value at all, so `data` has no
    `value` key and there is nothing to quote back; a placeholder rendered
    "sets SameSite=(none)", telling the reader the response wrote something it
    did not. The defect is identical either way -- rfc6265bis algorithm [11]
    sets enforcement to Default for both -- so it stays one code and the
    clause is what varies.
    """
    fields = _cookie_subject(data)
    value = data.get("value")
    fields["setting"] = "sets SameSite=%s" % value if value is not None else "sets SameSite as a flag with no value"
    return fields


def _unknown_attribute(data):
    # Composes with _cookie_subject rather than reading data["cookie"]
    # directly: _DISPLAY maps a code to exactly ONE function, and this code's
    # template also opens with {cookie} as its subject. Setting the key here
    # would reintroduce the nameless-cookie leading space that
    # _cookie_subject exists to prevent.
    fields = _cookie_subject(data)
    suspected = data.get("suspected")
    fields["attribute"] = data["attribute"]
    fields["detail"] = " and may be a misspelling of %s" % suspected if suspected else ""
    return fields


# The codes whose sentence cannot be written as a template over `data` alone.
# Everything else is a plain format string; keep this list short, because each
# entry is a piece of prose that a translator has to find. Thirteen of the
# fifteen cookie entries share one function rather than being thirteen
# fragments of prose: nothing there is code-specific, so it is one shared
# substitution, not a "handful" of one-off ones. The other two compose with it
# -- `_unknown_attribute` and `_samesite_invalid` each add one clause of their
# own on top of the shared subject.
_DISPLAY = {
    "csd-unknown-type": _quoted_types,
    "csp-plain-scheme": _scheme_pairs,
    "hsts-malformed": _hsts_problem,
    "hsts-preload-ineffective": _hsts_unmet,
    "ip-no-blocked-destinations": _ip_detail,
    "ip-sources-without-inline": _ip_sources,
    "cookie-control-character": _cookie_subject,
    "cookie-domain-broad": _cookie_subject,
    "cookie-domain-mismatch": _cookie_subject,
    "cookie-no-httponly": _cookie_subject,
    "cookie-no-samesite": _cookie_subject,
    "cookie-no-secure": _cookie_subject,
    "cookie-oversized": _cookie_subject,
    "cookie-partitioned-insecure": _cookie_subject,
    "cookie-persistent": _cookie_subject,
    "cookie-prefix-violated": _cookie_subject,
    "cookie-samesite-invalid": _samesite_invalid,
    "cookie-samesite-none": _cookie_subject,
    "cookie-samesite-none-insecure": _cookie_subject,
    "cookie-secure-over-plaintext": _cookie_subject,
    "cookie-unknown-attribute": _unknown_attribute,
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


# What a misconfiguration could lead to. A hint about potential risk, never a
# claim that the risk is reachable: whether an injected script exists, whether
# the page is worth framing, whether anything sensitive is in the URL, are all
# facts about an application that a response header cannot report. The wording
# of every entry says so, because a consumer will paste it into a ticket.
#
# The slug is the contract and the taxonomy identifier is an attribute of it.
# That is not a preference: CWE 4.20 has no weakness for MIME sniffing, for
# XS-Leaks, or written for permission delegation, so a CWE-keyed vocabulary
# would have had entries with no identifier or a forced one.
Consequence = collections.namedtuple("Consequence", "name taxonomy text")

CONSEQUENCES = {
    "xss": Consequence(
        "Cross-site scripting",
        ("CWE-79", "CAPEC-63"),
        "Script an attacker controls could run in this origin, with the same "
        "access to cookies, storage and the DOM as the site's own code. "
        "Whether an injection point exists is not determined here.",
    ),
    "clickjacking": Consequence(
        "Clickjacking",
        ("CWE-1021", "CAPEC-103"),
        "The page could be framed by another site and overlaid, or redressed "
        "in place by an attacker's injected styles, so a user clicking what "
        "they see acts on what they do not. Whether the page has an action "
        "worth stealing is not determined here.",
    ),
    "mitm": Consequence(
        "Network interception",
        ("CWE-319", "CAPEC-117"),
        "A request could be carried in cleartext where someone on the path "
        "can read or alter it, session cookies included. Whether an attacker "
        "is on the path is not determined here.",
    ),
    "data-disclosure": Consequence(
        "Sensitive data sent to third parties",
        ("CWE-200",),
        "The browser could hand data to a third party as part of ordinary "
        "browsing -- a URL carrying a token, for instance -- or an "
        "attacker's injected styles could read it through selector-driven "
        "requests. Whether anything sensitive travels that way is not "
        "determined here.",
    ),
    "cors-data-theft": Consequence(
        "Cross-origin data theft",
        ("CWE-942",),
        "Another origin could read this response, including anything in it "
        "specific to the logged-in user. Whether the response carries "
        "user-specific content is not determined here.",
    ),
    "cache-exposure": Consequence(
        "Sensitive data left in the browser",
        ("CWE-525", "CAPEC-204"),
        "Data could remain in the browser after it should have been cleared, "
        "readable by the next person using the device. Whether anything "
        "sensitive was stored is not determined here.",
    ),
    "cross-origin-leak": Consequence(
        "Cross-origin state or resource leak",
        ("CAPEC-663",),
        "A page the user visits could measure something about this origin "
        "that the same-origin policy is meant to hide, using the user's own "
        "session. Whether anything measurable is worth learning is not "
        "determined here.",
    ),
    "permission-abuse": Consequence(
        "Powerful browser feature left available",
        ("CWE-732",),
        "A powerful capability such as the camera, microphone or location "
        "could be reachable by the page or by a third party it embeds. "
        "Whether anything embedded would use it is not determined here.",
    ),
    "session-theft": Consequence(
        "Session token theft",
        # CAPEC-31 was the first choice by name match and is wrong by this
        # project's own rule: CAPEC 2.1 cross-references CAPEC-31 against
        # CWE-113/20/302/311/315/384/472/539/565/602/642, never CWE-1004, and
        # no pattern in CAPEC 2.1 cross-references CWE-1004 at all. CWE-1004
        # "Sensitive Cookie Without 'HttpOnly' Flag" is exactly the weakness
        # this slug names and is kept alone rather than traded for a CAPEC
        # that does not cross-reference it -- the same single-id shape as
        # `data-disclosure`, which is `("CWE-200",)`.
        ("CWE-1004",),
        "An attacker could obtain the cookie carrying this session and act as "
        "the user without their credentials. Whether the cookie carries a "
        "session is not determined here.",
    ),
    "csrf": Consequence(
        "Cross-site request forgery",
        ("CWE-352", "CAPEC-62"),
        "Another site could cause the browser to make an authenticated "
        "request to this origin using the user's own cookies. Whether the "
        "application has a state-changing endpoint that would accept one is "
        "not determined here.",
    ),
}
