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

import json
import re

from .csp import _analyze_csp, _analyze_csp_all, parse_csp
from .findings import Finding, identity
from .hsts import _analyze_hsts, _analyze_preload
from .isolation import (
    COOP_VALUES,
    _analyze_acac,
    _analyze_acam,
    _analyze_acao,
    _analyze_acma,
    _analyze_coep,
    _analyze_coop,
    _analyze_corp,
    _analyze_cors,
    _analyze_isolation,
    _bare_item,
    _item_parameter,
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
    _analyze_xdpc,
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


# Security-relevant headers that are inventoried when present but never
# reported missing, because their absence is the ordinary state of the web
# rather than a gap. This is deliberately not part of SECURITY_HEADERS: that
# tuple is read three times -- for the `security` inventory, for the `missing`
# one, and by _report_missing -- and only the first of the three is wanted here.
# A response that configures no reporting is not thereby defective, so an
# `re-missing` finding would fire on very nearly every site analysed.
REPORTING_HEADERS = ("Report-To", "Reporting-Endpoints")


# The CORS response headers, inventoried on the same terms as the reporting pair
# and for the same reason: a response that shares nothing across origins is the
# ordinary state of the web, not a gap, so none of these is ever reported
# missing and none belongs in SECURITY_HEADERS. Sharing is nonetheless the
# entire subject of these headers, so what a response does say has to be
# visible -- and until now Access-Control-Allow-Origin appeared in no inventory
# at all, however permissive its value.
CORS_HEADERS = (
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
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
    "Integrity-Policy-Report-Only": (
        "Integrity-Policy",
        "ip-ro-unenforced",
    ),
}


# Headers that describe the stack rather than the response. None is a defect on
# its own -- the value is what matters, and only a human can judge it -- so these
# are inventoried rather than analyzed. Most name the software and often its
# version. Two other kinds are here: the timing ones (X-Runtime, the Kong and
# Envoy latencies) publish how long the request took, which turns a login
# endpoint into a timing oracle, and the tracing ones (B3, Datadog, Tyk) leak
# internal topology and correlation identifiers that were never meant to leave
# the mesh.
#
# The bulk of this table is the union of what this project already had with
# OWASP's `ci/headers_remove.json`, which is regenerated by their CI from
# `mainsite/03_best_practices.md`. Embedding a curated list is a thing this
# project otherwise refuses to do -- see csp-evaluator's bypass lists under
# "Not embedded" -- and the distinction is that this one feeds an *inventory*
# rather than a finding. A name that goes stale here can only under-report; a
# stale entry in a list that drives findings becomes a false positive. That is
# the whole of the difference, and it is why the answer went the other way.
INFORMATION_HEADERS = (
    "$WSEP",
    "Host-Header",
    "K-Proxy-Request",
    "Liferay-Portal",
    "OracleCommerceCloud-Version",
    "Pega-Host",
    "Powered-By",
    "Product",
    "Server",
    "SourceMap",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Atmosphere-error",
    "X-Atmosphere-first-request",
    "X-Atmosphere-tracking-id",
    "X-B3-ParentSpanId",
    "X-B3-Sampled",
    "X-B3-SpanId",
    "X-B3-TraceId",
    "X-Backside-Transport",
    "X-BEServer",
    "X-CalculatedBETarget",
    "X-CF-Powered-By",
    "X-CMS",
    "X-Cocoon-Version",
    "X-Content-Encoded-By",
    "X-Datadog-Origin",
    "X-Datadog-Parent-Id",
    "X-Datadog-Sampling-Priority",
    "X-Datadog-Tags",
    "X-Datadog-Trace-Id",
    "X-DiagInfo",
    "X-Drupal-Cache",
    "X-Drupal-Dynamic-Cache",
    "X-dtAgentId",
    "X-dtHealthCheck",
    "X-dtInjectedServlet",
    "X-Envoy-Attempt-Count",
    "X-Envoy-External-Address",
    "X-Envoy-Internal",
    "X-Envoy-Original-Dst-Host",
    "X-Envoy-Upstream-Service-Time",
    "X-FEServer",
    "X-Framework",
    "X-Generated-By",
    "X-Generator",
    "X-Gitlab-Meta",
    "X-Jitsi-Release",
    "X-Joomla-Version",
    "X-Kong-Admin-Latency",
    "X-Kong-Client-Latency",
    "X-Kong-Proxy-Latency",
    "X-Kong-Request-Id",
    "X-Kong-Response-Latency",
    "X-Kong-Third-Party-Latency",
    "X-Kong-Total-Latency",
    "X-Kong-Upstream-Latency",
    "X-Kong-Upstream-Status",
    "X-Kubernetes-PF-FlowSchema-UI",
    "X-Kubernetes-PF-PriorityLevel-UID",
    "X-LiteSpeed-Cache",
    "X-Litespeed-Cache-Control",
    "X-LiteSpeed-Purge",
    "X-LiteSpeed-Tag",
    "X-LiteSpeed-Vary",
    "X-Mod-Pagespeed",
    "X-Nextjs-Cache",
    "X-Nextjs-Matched-Path",
    "X-Nextjs-Page",
    "X-Nextjs-Redirect",
    "X-Old-Content-Length",
    "X-OneAgent-JS-Injection",
    "X-OWA-Version",
    "X-Page-Speed",
    "X-Php-Version",
    "X-Powered-By",
    "X-Powered-By-Plesk",
    "X-Powered-CMS",
    "X-Rack-Cache",
    "X-Redirect-By",
    "X-Runtime",
    "X-ruxit-JS-Agent",
    "X-Server-Powered-By",
    "X-SourceFiles",
    "X-SourceMap",
    "X-Turbo-Charged-By",
    "X-Tyk-Trace-Id",
    "X-Umbraco-Version",
    "X-Varnish-Backend",
    "X-Varnish-Server",
    "X-Woodpecker-Version",
)


# The data types Clear-Site-Data can name. The spec's grammar is
# `1#( quoted-string )`, and Chromium takes that literally: it splits the header
# on commas, trims, and compares each token against a constant that has the
# quotes baked into it -- kDatatypeCookies is `"\"cookies\""`, not `"cookies"`.
# So the quotes are part of the value and the comparison is byte-for-byte.
#
# Evidence, and its limit: that tokenizer was read directly (net/url_request/
# clear_site_data.cc -- ClearSiteDataHeaderContents is a bare comma split, and
# kDatatypeCookies is the literal "\"cookies\""), so csd-unquoted is rated error
# on one engine's source rather than on all three. Firefox and Safari are
# inferred from the grammar in the specification, which is `1#( quoted-string )`
# and agrees, but was not tested. If a cross-browser suite for this appears --
# the way wpt has one for Integrity-Policy -- prefer it to both.
#
# executionContexts is in the specification and in OWASP's table but not in
# Chromium's list; it is accepted here anyway, because a site following the spec
# has done nothing wrong and this table decides only what is *recognisable*.
# storage: is a prefix -- `"storage:inbox"` names one storage bucket.
CSD_TYPES = frozenset(
    [
        "*",
        "cache",
        "clientHints",
        "cookies",
        "executionContexts",
        "prefetchCache",
        "prerenderCache",
        "storage",
    ]
)


CSD_BUCKET_PREFIX = "storage:"


# Integrity-Policy asks the browser to refuse any <script> or stylesheet that
# carries no integrity attribute, which makes it the one header here that can
# turn Subresource Integrity from an option into a rule.
#
# The value is a structured field dictionary whose members are inner lists of
# tokens, and browsers parse it whole or not at all. The cases below are pinned
# by the cross-browser suite at wpt/subresource-integrity/integrity-policy/
# parsing.html rather than by reading the grammar, because several spellings
# that look correct enforce nothing: a bare token instead of an inner list,
# quoted strings instead of tokens, and -- the easy one to write by habit --
# commas inside the list where the syntax wants spaces.
IP_DIRECTIVES = frozenset(["blocked-destinations", "endpoints", "sources"])


IP_DESTINATIONS = frozenset(["script", "style"])


# What any engine actually blocks on today. `style` is in the specification and
# in nobody's implementation: Chrome and Safari do not support it and Firefox
# only behind security.integrity_policy.stylesheet.enabled (MDN BCD, checked
# against OWASP's own browser testing). Recheck before treating a style-only
# policy as inert -- this is the sort of entry that goes stale.
IP_BLOCKING_DESTINATIONS = frozenset(["script"])


# `sources` names where integrity metadata may come from, and inline -- the
# attribute on the tag -- is the only value defined. The default is (inline),
# but only when the directive is absent: a browser appends inline if the list
# is missing or already contains it, so a list that omits it leaves nothing.
IP_SOURCE_INLINE = "inline"


# sf-token: ( ALPHA / "*" ) *( tchar / ":" / "/" ). The leading character is
# what rejects "script" and 'script' -- a quoted string is not a token, and a
# member that is not a token makes the whole dictionary unparseable.
_IP_TOKEN = re.compile(r"[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*\Z")


def parse_integrity_policy(value):
    """Parse an Integrity-Policy header into a {directive: [token, ...]} mapping.

    Returns None when the value is not a well formed dictionary of inner lists,
    which is the answer that matters most: a header that does not parse is not
    a weaker policy, it is no policy, and it looks identical in a response.
    """
    policy = {}
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, sep, items = chunk.partition("=")
        name = name.strip().lower()
        items = items.strip()
        if not sep or not name:
            return None
        if not (items.startswith("(") and items.endswith(")")):
            return None
        tokens = items[1:-1].split()
        if not all(_IP_TOKEN.match(token) for token in tokens):
            return None
        policy[name] = tokens
    return policy


# The media types where declaring a charset decides anything. Only markup a
# browser parses is affected, and only text/html is parsed as markup: JSON is
# UTF-8 by definition and the parameter is meaningless on it, and text/plain is
# never parsed as markup in the first place.
CT_CHARSET_TYPES = frozenset(["text/html"])


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
        return [Finding("X-Frame-Options", "xfo-allow-from")]
    if normalized not in ("DENY", "SAMEORIGIN"):
        return [Finding("X-Frame-Options", "xfo-invalid", {"value": value.strip()})]
    return []


def _analyze_xcto(value):
    if value.strip().lower() != "nosniff":
        return [
            Finding("X-Content-Type-Options", "xcto-invalid", {"value": value.strip()})
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
        return [Finding("Referrer-Policy", "rp-invalid", {"value": value.strip()})]
    if effective == "unsafe-url":
        return [Finding("Referrer-Policy", "rp-unsafe-url")]
    return []


def _media_type(value):
    return value.split(";")[0].strip().lower()


def _charset(value):
    """The charset parameter, or None when the header declares no encoding.

    A parameter present but empty declares nothing, so it answers None too.
    """
    for chunk in value.split(";")[1:]:
        name, sep, charset = chunk.partition("=")
        if sep and name.strip().lower() == "charset":
            return charset.strip().strip('"') or None
    return None


def _analyze_ct(value):
    """Findings for Content-Type.

    A representation header, describing a body this package never sees, so
    almost nothing about it is decidable here -- whether the type is *right* is
    a question about the bytes. The charset parameter is the exception: whether
    the response declares its encoding is visible in the header itself.

    Only text/html is asked. Everywhere else the parameter is either defined
    away (application/json is UTF-8 by definition) or decides nothing, and
    absence of the header is not reported at all: analyze_all sees no status
    line, and a 204 or 304 carries no representation to describe.
    """
    if _media_type(value) not in CT_CHARSET_TYPES or _charset(value):
        return []
    return [
        Finding("Content-Type", "ct-no-charset", {"media_type": _media_type(value)})
    ]


def _analyze_csd(value):
    """Findings for Clear-Site-Data.

    Absence is never reported: this is the header a logout endpoint sends, not
    one every response should carry, so a missing one says nothing. What it does
    say is easy to get wrong -- a member that is not a correctly spelled, quoted
    type is skipped in silence, and a logout that clears nothing looks exactly
    like a logout that works.
    """
    members = [member.strip() for member in value.split(",") if member.strip()]
    if not members:
        return [Finding("Clear-Site-Data", "csd-empty")]

    unquoted = []
    unknown = []
    for member in members:
        if len(member) < 2 or not (member.startswith('"') and member.endswith('"')):
            unquoted.append(member)
            continue
        name = member[1:-1]
        if name not in CSD_TYPES and not name.startswith(CSD_BUCKET_PREFIX):
            unknown.append(name)

    findings = []
    if unquoted:
        findings.append(
            Finding("Clear-Site-Data", "csd-unquoted", {"members": unquoted})
        )
    if unknown:
        findings.append(
            Finding("Clear-Site-Data", "csd-unknown-type", {"types": unknown})
        )
    return findings


def _analyze_ip(value):
    """Findings for Integrity-Policy.

    Absence is never reported. Enforcing it means every script and stylesheet
    the page loads must carry integrity metadata, which is a deployment
    commitment rather than a header to switch on, so a page without one is in
    the ordinary state of the web.
    """
    policy = parse_integrity_policy(value)
    if policy is None:
        return [Finding("Integrity-Policy", "ip-invalid", {"value": value.strip()})]

    destinations = policy.get("blocked-destinations", [])
    blocking = [name for name in destinations if name in IP_BLOCKING_DESTINATIONS]
    if not blocking:
        return [
            Finding(
                "Integrity-Policy",
                "ip-no-blocked-destinations",
                {"destinations": destinations},
            )
        ]

    # Once the policy enforces nothing, what its other directives say decides
    # nothing either, so this answers before the remarks below.
    sources = policy.get("sources")
    if sources is not None and IP_SOURCE_INLINE not in sources:
        return [
            Finding(
                "Integrity-Policy", "ip-sources-without-inline", {"sources": sources}
            )
        ]

    findings = []
    unknown = sorted(set(destinations) - IP_DESTINATIONS)
    if unknown:
        findings.append(
            Finding(
                "Integrity-Policy", "ip-unknown-destination", {"destinations": unknown}
            )
        )
    if "style" in destinations:
        findings.append(Finding("Integrity-Policy", "ip-style-unsupported"))
    return findings


_ANALYZERS = {
    "clear-site-data": _analyze_csd,
    "content-security-policy": _analyze_csp,
    "content-type": _analyze_ct,
    "cross-origin-embedder-policy": _analyze_coep,
    "cross-origin-opener-policy": _analyze_coop,
    "cross-origin-resource-policy": _analyze_corp,
    "access-control-allow-origin": _analyze_acao,
    "access-control-allow-credentials": _analyze_acac,
    "access-control-allow-methods": _analyze_acam,
    "access-control-max-age": _analyze_acma,
    "expect-ct": _analyze_ect,
    "feature-policy": _analyze_fp,
    "integrity-policy": _analyze_ip,
    "p3p": _analyze_p3p,
    "public-key-pins": _analyze_hpkp,
    "public-key-pins-report-only": _analyze_hpkp_report_only,
    "x-content-security-policy": _analyze_xcsp,
    "x-dns-prefetch-control": _analyze_xdpc,
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
        findings.append(Finding(name, _missing_tag(name)))
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
    return [Finding(name, "duplicate-headers") for name in _duplicated(present)]


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
        findings.append(Finding(name, code, {"enforcing": enforcing}))
    return findings


# Schemes a browser will deliver a report to. Both engines test the scheme
# rather than the URL as a whole: Chromium requires SchemeIsCryptographic()
# outright, Firefox accepts any potentially trustworthy origin, which is a
# superset -- see _defines_group for what that difference costs.
REPORTING_SCHEMES = frozenset(["https", "wss"])


def _is_loopback(host):
    """Whether a host is one Firefox counts as trustworthy over plaintext.

    Firefox delivers reports here and Chromium does not, so an endpoint on one
    of these is the single case this package cannot call either way. The
    definition follows the potentially-trustworthy rule: localhost and anything
    under it, the IPv6 loopback, and the whole of 127.0.0.0/8 rather than just
    127.0.0.1.
    """
    if host == "localhost" or host.endswith(".localhost"):
        return True
    if host == "[::1]":
        return True
    octets = host.split(".")
    return len(octets) == 4 and octets[0] == "127" and all(o.isdigit() for o in octets)


def _split_dictionary(value):
    """A structured field dictionary's members, split on the commas that separate
    them rather than the ones inside a quoted URL.

    `csp="https://example.com/r?a=1,b=2"` is one member, and splitting it naively
    invents a second group named `b`. A phantom group can only ever make a name
    look defined that is not, so the error runs towards saying nothing -- which
    is the wrong direction for a helper four findings consult.
    """
    members = []
    current = []
    quoted = False
    for character in value:
        if character == '"':
            quoted = not quoted
        if character == "," and not quoted:
            members.append("".join(current))
            current = []
            continue
        current.append(character)
    members.append("".join(current))
    return members


def _delivers(url):
    """Whether a browser would deliver reports to this endpoint URL.

    Both engines drop an endpoint they cannot deliver to *before* registering
    its name -- Firefox `ReportingHeader.cpp` returns early on
    IsPotentiallyTrustworthyOrigin, Chromium's ProcessEndpointURLString on
    SchemeIsCryptographic -- so a dropped endpoint leaves its group undefined
    rather than merely unreachable. That is why this belongs here and not in a
    finding of its own.

    Two shapes are left alone because the engines disagree about them, and a
    disagreement cannot be a defect: a loopback endpoint over plaintext, which
    Firefox delivers to and Chromium discards, and a relative URL, which both
    resolve but against different rules about what counts as relative.
    """
    url = url.strip().strip('"').strip()
    scheme, separator, rest = url.partition("://")
    if not separator:
        # Relative, or not a URL at all. Firefox resolves anything relative
        # against the document; Chromium only a leading-slash path. Saying
        # nothing is the only answer true of both.
        return True
    if scheme.lower() in REPORTING_SCHEMES:
        return True
    authority = rest.partition("/")[0].strip().lower()
    # A bracketed IPv6 literal carries colons of its own, so the port comes off
    # after the closing bracket rather than at the first colon.
    if authority.startswith("["):
        host = authority.partition("]")[0] + "]"
    else:
        host = authority.partition(":")[0]
    return _is_loopback(host)


def _report_to_pairs(present):
    """(group name, endpoint URL) for every endpoint a Report-To header declares,
    or None if the header is present and is not readable JSON.

    Chromium runs these through the same ProcessEndpointURLString that serves
    Reporting-Endpoints, so the URL rule is shared; it processes each group
    separately, so one unusable group does not void the rest.
    """
    values = _lookup_all(present, "Report-To")
    if not values:
        return []
    pairs = []
    for value in values:
        try:
            groups = json.loads("[%s]" % value)
        except ValueError:
            return None
        if not isinstance(groups, list):
            return None
        for group in groups:
            if not isinstance(group, dict):
                return None
            name = group.get("group", "default")
            if not isinstance(name, str):
                return None
            endpoints = group.get("endpoints")
            urls = endpoints if isinstance(endpoints, list) else []
            found = False
            for endpoint in urls:
                if isinstance(endpoint, dict) and isinstance(endpoint.get("url"), str):
                    pairs.append((name, endpoint["url"]))
                    found = True
            if not found:
                # The group is still declared, and naming it is not a defect.
                pairs.append((name, None))
    return pairs


def _report_to_names(present):
    """The group names a Report-To header defines, or None if it cannot be read.

    Report-To is the Reporting API's first spelling and is deprecated in favour
    of Reporting-Endpoints, but deprecated is not ignored: both engines still
    parse and honour it -- Chromium wires it up at reporting_service.cc:250 and
    Firefox at ReportingHeader.cpp:211 -- so a response that defines its groups
    only this way is configured correctly and must not be told otherwise.

    The value is one or more JSON objects separated by commas, which is not
    itself valid JSON; wrapping them in brackets is what makes it parseable. A
    group key is optional and its absence names the group `default`.

    Returns None rather than an empty set when the header is present but
    unreadable. The caller treats that as "cannot tell", because a header this
    package failed to parse may still define the group, and claiming a defect
    on the strength of our own parser giving up is exactly the false positive
    this project exists to avoid.
    """
    pairs = _report_to_pairs(present)
    if pairs is None:
        return None
    return {name for name, _url in pairs}


# A structured field dictionary key, RFC 9651: `key = ( lcalpha / "*" )
# *( lcalpha / DIGIT / "_" / "-" / "." / "*" )`, where lcalpha is a-z only. An
# uppercase letter is the easy way to get this wrong, and it is not a
# forgiving mistake: both engines drop the entire header when the dictionary
# will not parse, rather than the one member that broke it.
_SFV_KEY = re.compile(r"[a-z*][a-z0-9_.*-]*\Z")


def _reporting_endpoints(present):
    """(group name, endpoint URL) for a Reporting-Endpoints header, or None if
    the header will not parse as a structured field dictionary."""
    pairs = []
    for value in _lookup_all(present, "Reporting-Endpoints"):
        for member in _split_dictionary(value):
            name, separator, url = member.partition("=")
            if not separator:
                continue
            name = name.strip()
            if not _SFV_KEY.match(name):
                return None
            pairs.append((name, url))
    return pairs


def _reporting_endpoints_apply(secure, host):
    """Whether a browser reads a Reporting-Endpoints header on this response.

    Reporting API step 1: "Abort these steps if response's HTTPS state is not
    'modern', and the origin of response's url is not potentially trustworthy."
    Note the conjunction -- a plaintext response from a loopback origin is
    still potentially trustworthy, so the header applies there.
    """
    return secure or (host is not None and _is_loopback(host.strip().lower()))


# The two headers that define reporting groups, each with the codes for the
# three things that can be wrong with a definition. Report-To is deprecated in
# favour of Reporting-Endpoints and both engines still honour it, so it is
# analysed rather than waved through -- but its absence is not a gap, which is
# why neither of these is in SECURITY_HEADERS.
REPORTING_DEFINERS = (
    ("Reporting-Endpoints", _reporting_endpoints, "re-invalid", "re-ineffective",
     "re-endpoint-undeliverable"),
    ("Report-To", _report_to_pairs, "rt-invalid", "rt-ineffective",
     "rt-endpoint-undeliverable"),
)


def _analyze_reporting_endpoints(present, secure=True, host=None):
    """Defects in the definition of a reporting endpoint.

    These belong to the header that defined the endpoint rather than to every
    policy that named the group: one endpoint URL nothing can be delivered to
    is one fact, however many policies point at it, and blaming each of them
    would report the same defect up to four times with one fix between them.

    Three things are judged, and all three are answerable from the response
    alone: whether the header parses at all, whether a browser reads it on this
    response, and whether each URL is one reports can be delivered to. Whether
    anything is listening at the other end is an active question and is not
    asked here.

    None is a security defect -- a report that is never collected costs
    information, not protection, and there is no way for an attacker to reach
    the site or its users through one -- so all of them are notes.
    """
    findings = []
    for name, parse, invalid, ineffective, undeliverable_code in REPORTING_DEFINERS:
        pairs = parse(present)
        if pairs is None:
            findings.append(Finding(name, invalid))
            continue
        if not pairs:
            continue
        if not _reporting_endpoints_apply(secure, host):
            findings.append(Finding(name, ineffective))
            continue
        undeliverable = sorted(
            {group for group, url in pairs if url is not None and not _delivers(url)}
        )
        if undeliverable:
            findings.append(
                Finding(name, undeliverable_code, {"endpoints": undeliverable})
            )
    return findings


def _reporting_endpoint_names(present):
    """The group names this response defines, or None if it cannot tell.

    Syntactic on purpose. Whether a browser will deliver to the URL behind a
    name is a defect in the *definition*, which _analyze_reporting_endpoints
    reports against the header that wrote it; a policy that names a group
    someone did define has done nothing wrong and is not told otherwise.

    Both spellings of the Reporting API count. None means a Report-To header is
    present and could not be read, and no caller may report an undefined group
    on that basis.
    """
    endpoints = _reporting_endpoints(present)
    legacy = _report_to_names(present)
    if endpoints is None or legacy is None:
        # A header that will not parse defines nothing, but the defect is its
        # own -- see _analyze_reporting_endpoints -- and no policy that named
        # one of its groups is told it named something imaginary.
        return None
    return {name for name, _url in endpoints} | legacy


def _analyze_ip_reporting(present):
    """Reporting groups Integrity-Policy names that nothing defines.

    The endpoints directive carries group names, not URLs; the URLs live in a
    Reporting-Endpoints header. Name a group that header does not define and
    the policy still blocks, but every violation it catches goes nowhere -- and
    a violation report is the whole reason to deploy this before enforcing it.

    Only the enforcing header is read. The report-only spelling is left alone
    on principle, even though the same defect there is arguably worse.
    """
    value = _sole_value(present, "Integrity-Policy")
    if value is None:
        return []
    policy = parse_integrity_policy(value)
    if not policy:
        return []
    # A policy that blocks nothing catches no violation, so it has none to
    # deliver and where it would have sent them decides nothing -- the same
    # answer _analyze_ip gives before reading any other directive. Style-only
    # counts as blocking nothing while no engine honours that destination.
    destinations = policy.get("blocked-destinations", [])
    if not any(name in IP_BLOCKING_DESTINATIONS for name in destinations):
        return []
    wanted = policy.get("endpoints", [])
    if not wanted:
        return []
    defined = _reporting_endpoint_names(present)
    if defined is None:
        return []
    undefined = [name for name in wanted if name not in defined]
    if not undefined:
        return []
    return [
        Finding("Integrity-Policy", "ip-endpoints-undefined", {"endpoints": undefined})
    ]


# The headers that name a reporting group the way Integrity-Policy names one,
# and the code each raises when nothing defines it. CSP spells it as a
# directive; COOP and COEP as a parameter of a structured field item.
REPORT_TO_HEADERS = (
    ("Content-Security-Policy", "csp-report-to-undefined"),
    ("Cross-Origin-Opener-Policy", "coop-report-to-undefined"),
    ("Cross-Origin-Embedder-Policy", "coep-report-to-undefined"),
)


def _csp_report_to_groups(present):
    """Every reporting group the response's CSPs name.

    A browser enforces every policy a response carries and each carries its own
    report-to, so a group undefined for one policy is that policy's violations
    going nowhere whatever a sibling says. That makes this "any policy", the
    same way a syntax defect belongs to the text of one policy -- unlike a
    weakness, which has to be in all of them to survive the intersection.
    """
    groups = []
    for value in _lookup_all(present, "Content-Security-Policy"):
        groups.extend(parse_csp(value).get("report-to", []))
    return groups


def _applies(name, value):
    """Whether a policy is one a browser will act on at all.

    A header that opted into nothing blocks nothing, so it has nothing to
    report, so where its reports would have gone decides nothing -- and saying
    otherwise renders a sentence that is plainly false ("the policy applies and
    every report it would have sent is discarded", of a policy that applies
    nothing). An unrecognised value belongs here too, because both engines fall
    back to the inert default rather than to the value the operator meant.
    """
    bare = _bare_item(value)
    if name == "Cross-Origin-Opener-Policy":
        return bare in COOP_VALUES
    if name == "Cross-Origin-Embedder-Policy":
        return bare in ("require-corp", "credentialless")
    return True


def _analyze_report_to_groups(present):
    """Reporting groups CSP, COOP and COEP name that nothing defines.

    The same defect _analyze_ip_reporting reports for Integrity-Policy, and the
    same consequence: the header still does its job -- the policy enforces, the
    document is isolated -- and every violation it notices is discarded. A
    reporting endpoint that never receives anything is indistinguishable from
    one that has nothing to report, which is the failure mode worth naming.

    Only the enforcing spellings are read, following the same principle
    _analyze_ip_reporting does.
    """
    defined = _reporting_endpoint_names(present)
    if defined is None:
        return []
    findings = []
    for name, code in REPORT_TO_HEADERS:
        if name == "Content-Security-Policy":
            wanted = _csp_report_to_groups(present)
        else:
            value = _sole_value(present, name)
            if value is None or not _applies(name, value):
                continue
            group = _item_parameter(value, "report-to")
            wanted = [group] if group else []
        undefined = sorted({group for group in wanted if group not in defined})
        if undefined:
            findings.append(Finding(name, code, {"groups": undefined}))
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
    findings.extend(_analyze_ip_reporting(present))
    findings.extend(_analyze_report_to_groups(present))
    findings.extend(_analyze_reporting_endpoints(present, secure, host))
    findings.extend(_analyze_report_only(present))
    findings.extend(_analyze_duplicates(present))
    findings.extend(_analyze_preload(present, host))
    # A repeated header can raise the same defect twice, and a defect is the pair
    # of a header and what is wrong with it: the second occurrence adds nothing.
    # Two *different* headers sharing a code stay, because they are two findings.
    seen = set()
    unique = [f for f in findings if not (identity(f) in seen or seen.add(identity(f)))]
    return _suppress_redundant(unique, present)


def inventory(present):
    """What the response carries, before anything is judged about it.

    Four tables, and the split between them is the point: `security` and
    `missing` are two halves of one question -- with the one exception of
    REPORTING_HEADERS, which is inventoried when present and never reported
    absent, because configuring no reporting is not a defect -- `deprecated`
    names headers whose
    values are analysed elsewhere, and `information` and `caching` name headers
    whose values are never analysed at all -- only a human can say whether a
    particular `Server` banner is a leak.

    Nothing here is withheld because of what it contains, which is why there is
    no `secure` argument. A plaintext response is still missing HSTS and this
    says so; whether that absence is a *finding* is a judgment, and judgments
    are analyze_all's business.
    """
    present = _normalize(present)
    return {
        "security": _filter_headers(
            present, SECURITY_HEADERS + REPORTING_HEADERS + CORS_HEADERS
        ),
        "missing": [name for name in SECURITY_HEADERS if name.lower() not in present],
        "deprecated": _filter_headers(present, DEPRECATED_HEADERS),
        "information": _filter_headers(present, INFORMATION_HEADERS),
        "caching": _filter_headers(present, CACHE_HEADERS),
    }
