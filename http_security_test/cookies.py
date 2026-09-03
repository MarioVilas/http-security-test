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

"""Set-Cookie: the cookies a response sets, and what is wrong with them.

One header is many subjects here. `Set-Cookie` may legally repeat and each
value is an unrelated cookie, so a finding names one of them in `data` and the
same code fires once per cookie -- which is what `identity()` was widened to
allow.

Parsing follows draft-ietf-httpbis-rfc6265bis 5.2 literally and never fails:
the inventory reports what the response sent, and the findings report what a
browser does with it. A value carrying a control character is still a cookie
here; it is `cookie-control-character` that says the browser discards it.
"""

import collections
import datetime
import email.utils
import fnmatch
import re

from .findings import Finding

# One cookie as the wire carried it. `attributes` is the lowercased attribute
# mapping with flags mapping to None -- the convention hsts._parse_directives()
# already uses -- and holds EVERY attribute, recognised or not. `raw` is the
# header value verbatim, because a parsed model is lossy about attribute order,
# casing and repeats and the inventory promises what the response carried.
Cookie = collections.namedtuple("Cookie", "name value attributes raw")


def parse_set_cookie(value):
    """One `Set-Cookie` value as a Cookie. Never returns None.

    Returning None for a value a browser discards was the obvious alternative
    and it makes the inventory lie: a cookie the server really sent would
    vanish, indistinguishable from a response that sent none.
    """
    head, _, unparsed = value.partition(";")
    name, found, cookie_value = head.partition("=")
    if not found:
        # rfc6265bis 5.2 step 3: no '=' means an empty name and the whole
        # string as the value.
        name, cookie_value = "", head
    attributes = {}
    for chunk in unparsed.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        key, has_value, attribute_value = chunk.partition("=")
        key = key.strip().lower()
        if not key:
            continue
        attributes[key] = attribute_value.strip() if has_value else None
    return Cookie(name.strip(), cookie_value.strip(), attributes, value)


def parse_cookies(present):
    """Every cookie the response set, in the order the header carried them.

    A tuple rather than a mapping: one response may set the same name twice and
    a mapping would silently drop one.
    """
    return tuple(parse_set_cookie(v) for v in present.get("set-cookie", ()))


# Everything from here to CSRF_FRAGMENTS is a hand-formatted table, fenced
# because `ruff format` would put every entry on its own line and bury the
# category comments the tables depend on to be readable at all -- the comments
# are what say why a name is on a list, which is the only thing that makes an
# entry auditable. tests/test_cookies.py and tests/test_headers.py fence
# themselves whole for the same reason; this is the narrower version, so the
# code below the fence stays formattable.
# fmt: off

# The attribute names browsers recognise: Chromium's nine
# (net/cookies/parsed_cookie.cc:62-70), a superset of Firefox's eight
# (netwerk/cookie/CookieParser.cpp:306-315). NOT rfc6265bis's list, which omits
# `priority` -- Chrome-proprietary, never standardised, and sent by Google's own
# cookies, so reporting it would fire on some of the most visited responses on
# the web. Firefox ignoring it is why it is recognised rather than reported: a
# value this package cannot fault Chrome for reading is not a defect anywhere.
KNOWN_ATTRIBUTES = frozenset([
    "path", "domain", "expires", "max-age", "secure", "httponly",
    "samesite", "partitioned", "priority",
])

# The three attributes whose misspelling fails OPEN. A misspelled Expires or
# Max-Age makes the cookie session-scoped, a misspelled Path narrows it to the
# request directory, a misspelled Domain makes it host-only: all leave the
# cookie MORE restricted, so rating one an error would assert a defect that
# does not exist.
TYPO_SENSITIVE_ATTRIBUTES = ("secure", "httponly", "samesite")

# The canonical spelling of each typo-sensitive attribute, for the one place a
# finding quotes one back at the reader: `data["suspected"]` names the
# attribute the author MEANT to write, and nobody writes `httponly`.
# `data["attribute"]` stays lowercased in contrast, because that is what the
# response actually sent, as the parser read it -- one key is this package's
# inference, the other is the wire.
_ATTRIBUTE_SPELLING = {
    "secure": "Secure",
    "httponly": "HttpOnly",
    "samesite": "SameSite",
}

# The canonical spelling of each prefix, for a message that reads the way the
# author wrote it. Keyed by the lowercased form the matcher uses.
_PREFIX_SPELLING = {
    "__secure-": "__Secure-",
    "__http-": "__Http-",
    "__host-": "__Host-",
    "__host-http-": "__Host-Http-",
}

# Longest-prefix-first: `__Host-Http-` must be tested before `__Host-`, which
# it starts with. Both engines order their tables this way and both carry a
# comment saying why -- a naive startswith("__Host-") classifies
# `__Host-Http-sid` as `__Host-` and then fails to require HttpOnly, a false
# negative that looks like a pass. Matching is case-INSENSITIVE (rfc6265bis
# 5.4, normative for UAs); cookie NAMES stay case-sensitive.
COOKIE_PREFIXES = ("__host-http-", "__secure-", "__host-", "__http-")

# What each prefix requires. All four build on __Secure-, and __Host-Http- is
# the conjunction of the two below it: a lattice, not a chain, so __Host- does
# NOT imply HttpOnly.
PREFIX_REQUIREMENTS = {
    "__secure-": ("secure",),
    "__http-": ("secure", "httponly"),
    "__host-": ("secure", "path", "domain"),
    "__host-http-": ("secure", "httponly", "path", "domain"),
}

# Names that raise a hardening finding above its floor. Every entry is the
# default session cookie of software deployed by parties other than its vendor
# -- the axis is not framework-versus-vendor but whether the name can appear on
# a host the vendor does not control. Completeness is an explicit non-goal:
# selfh.st catalogues ~1500 self-hosted applications, misses cost a `note`
# rather than silence, and the list is bounded by reach. See the spec.
SESSION_NAMES = frozenset([
    # frameworks and runtimes
    "phpsessid", "jsessionid", "asp.net_sessionid", "aspsessionid",
    "cfid", "cftoken", "cgisessid", "sessionid", "session_id", "_session_id",
    "_rails_session", "laravel_session", "ci_session", "connect.sid",
    "express_sid", "rack.session", "play_session",
    # identity servers
    "keycloak_session", "auth_session_id", "auth_session_id_legacy",
    # transparent generic names: absent from Open-Cookie-Database's 2266 rows
    # and semantically unambiguous. `token` FAILS that test -- Adform uses it.
    "sid", "sessid", "jwt",
    # self-hosted applications
    "plesksessid", "phpmyadmin", "zenid", "siteserver", "whostmgrsession",
    "xf_session", "grafana_session", "i_like_gitea", "_redmine_session",
    "_mastodon_session", "mmauthtoken", "nc_session_id", "oc_sessionpassphrase",
    # persistent authentication tokens
    "remember_user_token", "xf_tfa_trust", "gitea_incredible", "nc_token",
])

# Anchored glob patterns, `*` only. A pattern must be anchored at both ends or
# be a prefix containing a literal that identifies one piece of software. A
# pattern anchored at NEITHER end is forbidden: `*session*` is expressible and
# must never be written -- measured at 65% precision for `*_session`, 50% for
# `*_sess` and `*sessid`, because the analytics industry names visit-tracking
# cookies exactly as authentication cookies are named.
SESSION_PATTERNS = (
    "wordpress_logged_in_*",
    "wp_woocommerce_session_*",
    "cpsession*",
    "phpbb3_*_sid",          # the prefix is randomised at install
)

# Names that emit NO hardening finding: set by infrastructure, carrying a
# routing or bot-detection identifier rather than a user credential.
# Membership -- the stricter of the two bars, because a wrong entry here
# silences a finding absolutely: vendor-specific, and the attribution on disk.
INFRASTRUCTURE_NAMES = frozenset([
    "awsalb", "awsalbcors", "awsalbtg", "awsalbtgcors", "awselb", "awselbcors",
    "arraffinity", "arraffinitysamesite", "__cflb", "__cf_bm",
    "ak_bmsc", "bm_sv", "_abck",
])

INFRASTRUCTURE_PATTERNS = (
    "bigipserver*", "nsc_*", "incap_ses_*", "visid_incap_*",
)

# A CSRF token cookie without HttpOnly is a CORRECT configuration: the
# cookie-to-header pattern requires JavaScript to read it. OWASP's CSRF
# cheat sheet writes the counter-example as literal sample code, and OpenID
# Connect Session Management 1.0 says the same of the OP state cookie. The
# exemption is not about CSRF specifically -- it is about cookies whose own
# specification requires script access.
CSRF_FRAGMENTS = ("csrf", "xsrf")

# fmt: on


def strip_prefix(name):
    """`name` with any cookie-name prefix removed, longest first.

    `__Secure-PHPSESSID` is a literal Open-Cookie-Database entry, so the idiom
    occurs and an exact match against the undecorated name would miss it.
    """
    lowered = name.lower()
    for prefix in COOKIE_PREFIXES:
        if lowered.startswith(prefix):
            return name[len(prefix) :]
    return name


def _matches(name, names, patterns):
    """Whether a lowercased name is in `names` or matches one of `patterns`."""
    lowered = name.lower()
    if lowered in names:
        return True
    return any(fnmatch.fnmatchcase(lowered, pattern) for pattern in patterns)


def is_session_name(name):
    """Whether the name is a known session or authentication cookie name."""
    return _matches(strip_prefix(name), SESSION_NAMES, SESSION_PATTERNS)


def is_infrastructure_name(name):
    """Whether the name is a known routing or bot-detection cookie name."""
    return _matches(name, INFRASTRUCTURE_NAMES, INFRASTRUCTURE_PATTERNS)


def osa_distance(a, b):
    """Optimal String Alignment distance -- Damerau restricted to adjacent swaps.

    Not Levenshtein, and this is measured rather than chosen: of 21 realistic
    cookie-attribute typos, 8 are OSA 1 and Levenshtein 2, every one a
    transposition -- `secrue`, `secuer`, `httponyl`, `httpolny`, `smaesite`,
    `expries`, `domian`, `paht`. A plain-Levenshtein threshold of 1 misses
    about 40% of real typos, including the likeliest misspelling of the most
    important attribute. Restricting to adjacent swaps costs nothing: typos in
    an eight-character token are adjacent.
    """
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[-1][-1]


def suspected_attribute(name, absent_from):
    """The security attribute `name` is probably a misspelling of, or None.

    Two guards, and the second keeps the first honest. Only the three
    attributes whose misspelling fails open are considered, and only when the
    real attribute is absent from this cookie -- `Secure; Secrue` has the
    protection, so the typo cost nothing.
    """
    if name in KNOWN_ATTRIBUTES:
        return None
    for attribute in TYPO_SENSITIVE_ATTRIBUTES:
        if attribute in absent_from and osa_distance(name, attribute) <= 1:
            return attribute
    return None


def cookie_as_dict(cookie):
    """One cookie as plain data for the inventory.

    Derived keys are always present -- None for an absent value attribute,
    False for an absent flag, since a flag's absence is known rather than
    unknown. `raw` rides along because a parsed model is lossy about attribute
    order, casing, repeats and anything unrecognised, and the inventory
    promises what the response carried.

    `judged` records whether hardening findings were considered for this
    cookie at all, so a suppression is auditable rather than invisible: a
    reader who wonders why an infrastructure cookie has no finding despite
    lacking Secure can see the tool decided rather than missed it.

    The value is carried in full. This package does not redact -- principle 2,
    and redaction before anything reaches a report is the caller's business.
    """
    attributes = cookie.attributes
    return {
        "name": cookie.name,
        "value": cookie.value,
        "secure": "secure" in attributes,
        "httponly": "httponly" in attributes,
        "samesite": attributes.get("samesite"),
        "path": attributes.get("path"),
        "domain": attributes.get("domain"),
        "expires": attributes.get("expires"),
        "max_age": attributes.get("max-age"),
        "partitioned": "partitioned" in attributes,
        "judged": not is_infrastructure_name(cookie.name),
        "raw": cookie.raw,
    }


def cookie_inventory(present):
    """Every cookie the response set, as plain data, in header order."""
    return [cookie_as_dict(c) for c in parse_cookies(present)]


# rfc6265bis 5.2 step 1: a set-cookie-string containing any of these is
# ignored entirely. HTAB (%x09) is excluded, so it is NOT in the class.
_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")

# An obs-folded continuation line, unfolded to the single SP both engines
# reduce it to before any header value -- cookies included -- is parsed:
# Chromium's HttpUtil::AssembleRawHeaders (net/http/http_util.cc:813-815) and
# Firefox's nsHttpTransaction::ParseLineSegment (:2177-2190). `raw` carries
# whatever parse_raw_headers() handed back, and that function does not unfold
# -- it is shared by every other analyser, so this module unfolds its own copy
# rather than changing what every sibling reads.
_OBS_FOLD = re.compile(r"\r?\n[ \t]+")

# rfc6265bis 5.2 step 5.
MAX_NAME_VALUE_OCTETS = 4096

# rfc6265bis algorithm [11]. Anything else sets enforcement to "Default",
# which is Lax in Chrome and no restriction at all in Firefox and Safari
# release -- so an unrecognised value is not a synonym for None.
SAMESITE_VALUES = frozenset(["none", "lax", "strict"])


def _octets(text):
    """The octet count of `text` on the wire.

    Header values are latin-1 in this package -- see CLAUDE.md -- so that is
    the encoding to measure, matching what parse_raw_headers() decodes with.
    utf-8 is a fallback only, for a caller that hands over text latin-1 cannot
    represent at all (already-decoded, non-latin-1 text built by hand rather
    than parsed off the wire).
    """
    try:
        return len(text.encode("latin-1"))
    except UnicodeEncodeError:
        return len(text.encode("utf-8"))


def _prefix_of(name):
    """The cookie-name prefix `name` carries, longest first, or None."""
    lowered = name.lower()
    for prefix in COOKIE_PREFIXES:
        if lowered.startswith(prefix):
            return prefix
    return None


def _unmet_prefix_requirements(cookie, prefix, trustworthy, host):
    """Which of a prefix's requirements this cookie fails to meet."""
    attributes = cookie.attributes
    unmet = []
    for requirement in PREFIX_REQUIREMENTS[prefix]:
        if requirement == "secure":
            if "secure" not in attributes or not trustworthy:
                unmet.append("secure")
        elif requirement == "httponly":
            if "httponly" not in attributes:
                unmet.append("httponly")
        elif requirement == "path":
            if attributes.get("path") != "/":
                unmet.append("path")
        elif requirement == "domain":
            domain = attributes.get("domain")
            # Chromium tolerates Domain when the host is an IP literal equal
            # to it (cookie_util.cc:120); refusing that would be a false
            # positive on a configuration Chrome accepts.
            if domain and not (host and domain == host and _is_ip_literal(host)):
                unmet.append("domain")
    return unmet


def _is_ip_literal(host):
    """Whether `host` is an IP literal rather than a domain name.

    Both spellings of an IPv6 literal count. `exchange.host()` is
    `urlsplit().hostname`, which strips the brackets, so testing only the
    bracketed form left this branch dead for every caller the analyser
    actually has -- the same assumption `response._is_loopback` had. A colon
    is what separates the two cases: a port is already off by the time a
    hostname exists, so a name carrying one is an IPv6 literal.
    """
    octets = host.split(".")
    if len(octets) == 4 and all(o.isdigit() for o in octets):
        return True
    if host.startswith("[") and host.endswith("]"):
        return True
    return ":" in host


def _domain_matches(domain, host):
    """Whether a Domain attribute could apply to this host.

    Suffix comparison only. Whether the domain is over-BROAD needs a public
    suffix list and is deliberately out of scope; whether it matches at all
    does not.
    """
    domain = domain.lstrip(".").lower()
    host = host.lower()
    return host == domain or host.endswith("." + domain)


def _analyze_one(cookie, trustworthy, host):
    """Tier 1: what a browser does with this cookie that the server did not ask for."""
    findings = []
    attributes = cookie.attributes
    secure = "secure" in attributes
    name = cookie.name

    if _CONTROL.search(_OBS_FOLD.sub(" ", cookie.raw)):
        findings.append(Finding("Set-Cookie", "cookie-control-character", {"cookie": name}))

    octets = _octets(name) + _octets(cookie.value)
    if octets > MAX_NAME_VALUE_OCTETS:
        findings.append(Finding("Set-Cookie", "cookie-oversized", {"cookie": name, "octets": octets}))

    if "samesite" in attributes:
        samesite = attributes["samesite"]
        if samesite is None:
            # A bare flag -- `Set-Cookie: a=b; SameSite` with no `=` at all --
            # degrades to Default exactly as an unrecognised value does
            # (rfc6265bis algorithm [11]); only the wire spelling differs, so
            # it is the same code with no `value` key rather than a second
            # code. Absent-beats-empty, and here it is load-bearing: a
            # placeholder value read back as `SameSite=(none)` quoted the
            # reader something the response never wrote.
            findings.append(Finding("Set-Cookie", "cookie-samesite-invalid", {"cookie": name}))
        elif samesite.lower() not in SAMESITE_VALUES:
            findings.append(Finding("Set-Cookie", "cookie-samesite-invalid", {"cookie": name, "value": samesite}))
        elif samesite.lower() == "none" and not secure:
            findings.append(Finding("Set-Cookie", "cookie-samesite-none-insecure", {"cookie": name}))

    if secure and not trustworthy:
        findings.append(Finding("Set-Cookie", "cookie-secure-over-plaintext", {"cookie": name}))

    if "partitioned" in attributes and not secure:
        findings.append(Finding("Set-Cookie", "cookie-partitioned-insecure", {"cookie": name}))

    prefix = _prefix_of(name)
    if prefix is not None:
        unmet = _unmet_prefix_requirements(cookie, prefix, trustworthy, host)
        if unmet:
            findings.append(
                Finding(
                    "Set-Cookie",
                    "cookie-prefix-violated",
                    {"cookie": name, "prefix": _PREFIX_SPELLING[prefix], "unmet": unmet},
                )
            )

    if not name:
        # No further stripping needed here: parse_set_cookie() already
        # strips the value (Python's str.strip(), a superset of SP/HTAB), so
        # by the time a Cookie exists its value carries no leading whitespace
        # to trim a second time.
        hidden = _prefix_of(cookie.value)
        if hidden is not None:
            findings.append(
                Finding("Set-Cookie", "cookie-hidden-prefix", {"cookie": name, "prefix": _PREFIX_SPELLING[hidden]})
            )

    domain = attributes.get("domain")
    if domain and host and not _domain_matches(domain, host):
        findings.append(
            Finding("Set-Cookie", "cookie-domain-mismatch", {"cookie": name, "domain": domain, "host": host})
        )

    absent = {a for a in TYPO_SENSITIVE_ATTRIBUTES if a not in attributes}
    for written in attributes:
        if written in KNOWN_ATTRIBUTES:
            continue
        data = {"cookie": name, "attribute": written}
        suspected = suspected_attribute(written, absent_from=absent)
        if suspected is not None:
            # Absent-beats-empty: no near match, no key. The canonical
            # spelling, not the lowercased matcher key -- see
            # _ATTRIBUTE_SPELLING.
            data["suspected"] = _ATTRIBUTE_SPELLING[suspected]
        findings.append(Finding("Set-Cookie", "cookie-unknown-attribute", data))

    return findings


# Which evidence escalates which attribute, and to what. A misspelling is the
# only signal that reaches `error`, and it outranks the rest: every other row
# infers whether the cookie MATTERS, while a misspelling establishes what the
# author INTENDED and did not get, which is principle 3's error verbatim.
# HttpOnly's `csrf` cell is the row that would otherwise be a bug -- see
# test_a_csrf_cookie_is_never_escalated_for_httponly.
_HARDENING = {
    # attribute: (code, may a csrf-named cookie escalate?)
    "secure": ("cookie-no-secure", True),
    "httponly": ("cookie-no-httponly", False),
    "samesite": ("cookie-no-samesite", True),
}


def evidence_for(cookie, attribute):
    """The signals that raise a hardening finding on `attribute` for `cookie`.

    Returned worst-first, so the level is the first entry's. `typo:` entries
    reach `error`; everything else reaches `warning`; empty stays at the floor.

    `attribute` is always one of `_HARDENING`'s three keys in this module;
    `.get(..., (None, True))` below means an attribute outside that set is
    simply treated as escalatable rather than raising `KeyError` on a
    csrf/xsrf-named cookie, since a public function should not crash on a
    caller passing a fourth attribute name.

    The csrf exemption -- `_HARDENING[attribute][1]` being `False`, which
    today is only HttpOnly's row -- DOMINATES every inference signal below it,
    not just the plain name match that decides whether it applies at all.
    `prefix` and `session-name` only guess that the cookie matters; OWASP's
    CSRF cheat sheet recommends exactly the `__Host-`/`__Secure-` prefixed
    form for this cookie and says at lines 114 and 605
    (Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) that it is
    deliberately not HttpOnly -- so letting `prefix` re-escalate it, or a
    session-name pattern the csrf-named cookie happens to also match,
    would reintroduce the exact false positive the name-based exemption
    exists to prevent. A misspelling still escalates regardless: that
    establishes what the author INTENDED, not a guess about importance.
    """
    name = cookie.name
    evidence = []
    for written in cookie.attributes:
        suspected = suspected_attribute(written, absent_from={attribute})
        if suspected == attribute:
            evidence.append("typo:%s" % attribute)
            break
    lowered = name.lower()
    is_csrf = any(fragment in lowered for fragment in CSRF_FRAGMENTS)
    may_escalate = _HARDENING.get(attribute, (None, True))[1]
    if is_csrf and not may_escalate:
        return evidence
    if is_session_name(name):
        evidence.append("session-name")
    if _prefix_of(name) is not None:
        evidence.append("prefix")
    if attribute != "httponly" and "httponly" in cookie.attributes:
        evidence.append("httponly-set")
    if is_csrf and may_escalate:
        evidence.append("csrf-name")
    return evidence


def _matters(cookie):
    """The signals that say a cookie is worth caring about, attribute-free.

    `evidence_for()` answers two questions at once: *did the author intend a
    protection they did not get* (`typo:`, `httponly-set`) and *does this
    cookie matter* (everything else). `cookie-samesite-none`,
    `cookie-persistent` and `cookie-domain-broad` can only ask the second one:
    nothing was misspelled and nothing was forgotten, because the response
    asked for cross-site sending, an expiry or a parent domain deliberately in
    each case.

    Those three used to get their answer by calling
    `evidence_for(cookie, "secure")` -- or `"samesite"` for the first -- and
    filtering the other question's signals back out. That returned the right
    list for the wrong reason, and left a reader tracing why domain breadth
    consults the `Secure` row with no answer, because there is none: the
    attribute was a borrowed call site, not a decision. The signals below are
    exactly what survived that filter, in the same order.

    `httponly-set` is deliberately absent rather than filtered. Including it
    inverted the ladder: adding `HttpOnly` to `_ga=x; Domain=.example.com;
    Max-Age=63072000; Secure; SameSite=Lax` raised two unrelated notes to
    warnings, so hardening a cookie made the tool louder about it. Here it
    cannot come back by accident, because nothing reads an attribute at all.
    """
    name = cookie.name
    evidence = []
    if is_session_name(name):
        evidence.append("session-name")
    if _prefix_of(name) is not None:
        evidence.append("prefix")
    if any(fragment in name.lower() for fragment in CSRF_FRAGMENTS):
        evidence.append("csrf-name")
    return evidence


def _level_from(evidence):
    if not evidence:
        return "note"
    if evidence[0].startswith("typo:"):
        return "error"
    return "warning"


# The Expires cutoff a response that sent no readable Date falls back to.
# One day past the epoch, not the epoch itself: rfc6265bis expresses an
# immediate deletion as "the earliest representable date", and what servers
# actually write for that is `Thu, 01 Jan 1970 00:00:00 GMT`, the epoch
# exactly, so the cutoff sits one day later rather than exactly on it. It
# recognises a deliberate deletion and nothing else -- an ordinary past date
# needs the response's own Date to be judged against, which is what
# `_exempts_persistence` prefers whenever there is one.
_DELETION_CUTOFF = datetime.datetime(1970, 1, 2, tzinfo=datetime.timezone.utc)


def _delta_seconds(value):
    """`value` as rfc6265bis's delta-seconds, or None if it is not one.

    Algorithm [8] is `[ "-" ] 1*DIGIT`, and anything else means "ignore the
    cookie-av" -- the attribute never reaches the storage model at all, so
    Expires decides instead. `int()` is looser than that grammar in ways that
    matter here: it accepts underscores (`Max-Age=1_000` is 1000 to Python and
    an ignored av to every browser) and a leading `+`. DIGIT is ASCII, so
    `isascii()` guards against `int()` accepting other scripts' digits and
    against `isdigit()` accepting superscripts it cannot convert. Surrounding
    whitespace is not on that list only because `parse_set_cookie()` has
    already stripped it, as rfc6265bis 5.2 requires.
    """
    digits = value.removeprefix("-")
    if not (digits.isascii() and digits.isdigit()):
        return None
    return int(value)


def _response_date(present):
    """The response's own Date as an aware datetime, or None.

    A repeated Date whose values disagree yields None, for the reason
    `response._sole_value()` gives: no specification says which wins, so
    nothing can be earned from it.
    """
    values = present.get("date") or ()
    unique = {value.strip() for value in values}
    if len(unique) != 1:
        return None
    try:
        when = email.utils.parsedate_to_datetime(unique.pop())
    except (TypeError, ValueError, OverflowError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return when


def _exempts_persistence(attributes, date=None):
    """Whether Max-Age/Expires undercut persistence rather than confirm it.

    Two attributes, and Max-Age wins outright when it parses: RFC 6265 4.1.2.2
    says so in as many words -- "If a cookie has both the Max-Age and the
    Expires attribute, the Max-Age attribute has precedence" -- so a valid
    Max-Age decides alone and `Max-Age=100; Expires=Thu, 01 Jan 1970` is
    persistent, as it is in every browser. A Max-Age that is NOT valid
    delta-seconds is not a deletion either -- algorithm [8] says to ignore the
    cookie-av, so `Max-Age=abc; Expires=<future>` falls through to a future
    Expires and is persistent too. Only `delta-seconds <= 0` asks for
    immediate deletion.

    `date` is the response's own `Date` header, and it is what an Expires is
    compared against. This stays clock-free in the sense that matters:
    `cookie-persistent` must not depend on when the tool happened to run, and
    `Date` is a fact carried *in the response*, so an archived report analysed
    a year later reaches the same verdict. Without it the only clock-free
    cutoff is the epoch, and that misses the canonical ASP.NET Framework
    delete -- `Expires = DateTime.Now.AddDays(-1)` with no Max-Age, which is
    an ordinary past date rather than 1970 and read as persistence. PHP,
    Django, Rails, Express and Tomcat all write `Max-Age=0` or an epoch
    Expires and escaped that; ASP.NET does not. The 1970 cutoff remains the
    fallback for a response that sent no readable Date.

    An Expires no browser can parse sets no expiry at all, so it is not
    persistence either -- exempt, but for that reason rather than deletion.
    The same goes for reaching the end with no usable Expires: the caller only
    asks about a cookie carrying one of the two attributes, so arriving here
    with `expires` unusable means the Max-Age was the ignored av and nothing
    is left to set an expiry. `Max-Age=abc` alone, and the bare flag spellings
    `Max-Age` and `Expires` with no `=` at all, all land there.
    """
    max_age = attributes.get("max-age")
    if max_age is not None:
        seconds = _delta_seconds(max_age)
        if seconds is not None:
            return seconds <= 0
    expires = attributes.get("expires")
    if expires is None:
        return True
    try:
        when = email.utils.parsedate_to_datetime(expires)
    except (TypeError, ValueError, OverflowError):
        return True
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return when <= (date or _DELETION_CUTOFF)


def _hardening_findings(cookie, host, date=None):
    """Tier 2: gaps that are only defects on a cookie that matters."""
    if is_infrastructure_name(cookie.name):
        # Unconditional within tier 2. The cookie is still fully visible in
        # inventory.cookies, marked `judged: false`, so nothing is hidden.
        return []
    findings = []
    attributes = cookie.attributes
    secure = "secure" in attributes
    for attribute, (code, _) in _HARDENING.items():
        if attribute in attributes:
            continue
        evidence = evidence_for(cookie, attribute)
        findings.append(
            Finding("Set-Cookie", code, {"cookie": cookie.name, "evidence": evidence}, _level_from(evidence))
        )

    # Gated on Secure: once cookie-samesite-none-insecure has already said
    # Chrome and Firefox reject the cookie outright, a tier-2 fact about what
    # a cross-site-sent cookie "does" would contradict tier 1's own verdict on
    # the same response. Safari's part of the story -- it sends the cookie
    # cross-site in cleartext regardless -- is already in that tier-1 message.
    samesite = attributes.get("samesite")
    if samesite is not None and samesite.lower() == "none" and secure:
        evidence = _matters(cookie)
        findings.append(
            Finding(
                "Set-Cookie",
                "cookie-samesite-none",
                {"cookie": cookie.name, "evidence": evidence},
                _level_from(evidence),
            )
        )

    if ("expires" in attributes or "max-age" in attributes) and not _exempts_persistence(attributes, date):
        evidence = _matters(cookie)
        findings.append(
            Finding(
                "Set-Cookie", "cookie-persistent", {"cookie": cookie.name, "evidence": evidence}, _level_from(evidence)
            )
        )

    # Gated on the domain actually matching the host, reusing the same
    # `_domain_matches` tier 1 already computes cookie-domain-mismatch from:
    # once that finding has said browsers reject the cookie outright, a
    # tier-2 fact about the subdomains it would have widened to is
    # meaningless for the same response.
    domain = attributes.get("domain")
    if domain and host and _domain_matches(domain, host):
        evidence = _matters(cookie)
        findings.append(
            Finding(
                "Set-Cookie",
                "cookie-domain-broad",
                {"cookie": cookie.name, "domain": domain, "evidence": evidence},
                _level_from(evidence),
            )
        )
    return findings


def analyze_cookies(present, trustworthy, host):
    """Every cookie finding for one response.

    The response's own `Date` is read here rather than passed in, so no
    signature changed for it: `present` already carries it, and it is what
    `cookie-persistent` compares an `Expires` against -- see
    `_exempts_persistence`.

    `trustworthy` is the caller's answer to "was this response from a
    potentially-trustworthy origin" -- https, or a loopback host. It is passed
    in rather than derived because the loopback predicate lives in
    `response.py`, which imports this module: deriving it here would be a
    cycle. Both engines carve loopback out (Chromium
    ProvisionalAccessScheme, cookie_util.cc:709), so testing the scheme alone
    would fire on every developer running against http://localhost.
    """
    findings = []
    date = _response_date(present)
    for cookie in parse_cookies(present):
        findings.extend(_analyze_one(cookie, trustworthy, host))
        findings.extend(_hardening_findings(cookie, host, date))
    return findings
