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

"""HTTP security header analysis.

Reports what is wrong with a header value: each finding carries a stable code,
a message, and a rating chosen to line up with SARIF levels. Findings are facts,
and so are the header tables -- which headers exist and what a value means is
knowledge. What a badly configured header is worth to a particular site is not,
so a consumer is free to remap the ratings or ignore them entirely.
"""

import collections
import email.parser

try:
    import hstspreload
except ImportError:
    hstspreload = None

Finding = collections.namedtuple("Finding", "header code message")

# Fetch directives fall back to default-src when they are absent.
# https://www.w3.org/TR/CSP3/#directives-fetch
FETCH_DIRECTIVES = frozenset(
    [
        "child-src",
        "connect-src",
        "default-src",
        "font-src",
        "frame-src",
        "img-src",
        "manifest-src",
        "media-src",
        "object-src",
        "prefetch-src",
        "script-src",
        "script-src-attr",
        "script-src-elem",
        "style-src",
        "style-src-attr",
        "style-src-elem",
        "worker-src",
    ]
)

# 180 days, the floor recommended for a policy that is meant to stick.
HSTS_MIN_MAX_AGE = 15552000

# The HSTS preload list will not accept a domain below one year, and requires
# includeSubDomains alongside it. https://hstspreload.org/
HSTS_PRELOAD_MIN_MAX_AGE = 31536000

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
# COOP values that sever the opener relationship. noopener-allow-popups cuts the
# document's own opener while still letting it open popups that keep theirs,
# which is what a page doing OAuth-style popup flows needs; it ships in Chromium
# and Safari but not Firefox, where an unrecognised value falls back to
# unsafe-none. Only same-origin earns crossOriginIsolated -- see _seeks_isolation.
COOP_VALUES = frozenset(
    ["same-origin", "same-origin-allow-popups", "noopener-allow-popups"]
)
COEP_VALUES = frozenset(["unsafe-none", "require-corp", "credentialless"])
CORP_VALUES = frozenset(["same-site", "same-origin", "cross-origin"])

# The header does not grant cross-domain access itself; it decides how much
# authority a cross-domain policy file is allowed to have. These are the values
# Adobe's specification defines, none-this-response being header-only.
XPCDP_VALUES = frozenset(
    [
        "all",
        "by-content-type",
        "by-ftp-filename",
        "master-only",
        "none",
        "none-this-response",
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

# Security headers that are obsolete: their absence is the desired state, so
# they are never reported missing, only reported on when a response carries one.
DEPRECATED_HEADERS = (
    "Expect-CT",
    "Feature-Policy",
    "P3P",
    "Public-Key-Pins",
    "Public-Key-Pins-Report-Only",
    "X-Content-Security-Policy",
    "X-Download-Options",
    "X-Permitted-Cross-Domain-Policies",
    "X-WebKit-CSP",
    "X-XSS-Protection",
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


def parse_headers(pairs):
    """The mapping analyze_all wants, from (name, value) pairs off the wire.

    Build it with this rather than by hand. A dict comprehension over the same
    pairs -- the obvious thing to write -- keeps only the last value of a
    repeated header, and repeated headers are not a corner case: a browser
    enforces every Content-Security-Policy a response carries, so dropping one
    inverts the verdict on the rest.

    `http.client`'s getheaders() returns exactly the pairs this expects.
    """
    present = {}
    for name, value in pairs:
        present.setdefault(name.strip().lower(), []).append(value)
    return present


def parse_raw_headers(raw):
    """The same mapping, from a raw header block as captured off the wire.

    Accepts bytes or text, with or without a leading status or request line.
    """
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("latin-1")
    block = raw.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    first, newline, rest = block.partition("\n")
    if newline and ":" not in first:
        block = rest  # a status or request line, not a header
    return parse_headers(email.parser.Parser().parsestr(block).items())


def parse_csp(value):
    """Parse a CSP header into an ordered {directive: [source, ...]} mapping.

    Directive names are lowercased. Source expressions keep their case, because
    host sources are case-sensitive in their path component. Repeated
    directives are ignored after the first, which is what the spec requires of
    user agents.
    """
    directives = {}
    for chunk in value.split(";"):
        parts = chunk.split()
        if not parts:
            continue
        name = parts[0].lower()
        if name in directives:
            continue
        directives[name] = parts[1:]
    return directives


def _sources(directives, name):
    """Effective sources for a fetch directive, honouring the default-src fallback.

    Returns None when the directive is neither set nor inherited.
    """
    if name in directives:
        return directives[name]
    if name in FETCH_DIRECTIVES and "default-src" in directives:
        return directives["default-src"]
    return None


def _has_keyword(sources, keyword):
    return sources is not None and any(s.lower() == keyword for s in sources)


# Quoted source expressions that make a browser ignore 'unsafe-inline' in the
# same source list.
# https://www.w3.org/TR/CSP3/#allow-all-inline
NONCE_HASH_PREFIXES = ("nonce-", "sha256-", "sha384-", "sha512-")


def _ignores_unsafe_inline(sources, script=False):
    """Whether something in this source list makes 'unsafe-inline' inert.

    A nonce-source or a hash-source does, in that same list, which is why
    serving both is the documented way to keep older browsers working while
    modern ones enforce the nonce. Only a quoted expression counts: unquoted,
    `nonce-abc` is a host source and silences nothing.

    'strict-dynamic' does too, but only for script: it is defined to make the
    allowlist and 'unsafe-inline' be ignored, and it has no meaning in a style
    list.
    """
    if sources is None:
        return False
    for source in sources:
        if source[:1] != "'":
            continue
        keyword = source[1:].lower()
        if keyword.startswith(NONCE_HASH_PREFIXES):
            return True
        if script and keyword.startswith("strict-dynamic"):
            return True
    return False


# The list a browser consults is not always the directive you asked about: -elem
# and -attr fall back to their base directive, which falls back to default-src.
# Inline <script> and inline event handlers are governed by different ones, and
# either is an injection surface.
# https://www.w3.org/TR/CSP3/#directive-fallback-list
CSP_FALLBACKS = {
    "script-src": ("script-src", "default-src"),
    "script-src-elem": ("script-src-elem", "script-src", "default-src"),
    "script-src-attr": ("script-src-attr", "script-src", "default-src"),
    "style-src-elem": ("style-src-elem", "style-src", "default-src"),
    "style-src-attr": ("style-src-attr", "style-src", "default-src"),
    "object-src": ("object-src", "default-src"),
    # base-uri is not a fetch directive and inherits from nothing
    "base-uri": ("base-uri",),
}

# Every directive the standard defines. A name outside this set is one browsers
# ignore; a name *inside* it appearing as a source value is a missing semicolon.
CSP_DIRECTIVES = frozenset(
    [
        "base-uri",
        "block-all-mixed-content",
        "child-src",
        "connect-src",
        "default-src",
        "disown-opener",
        "font-src",
        "form-action",
        "frame-ancestors",
        "frame-src",
        "img-src",
        "manifest-src",
        "media-src",
        "navigate-to",
        "object-src",
        "plugin-types",
        "prefetch-src",
        "reflected-xss",
        "referrer",
        "report-to",
        "report-uri",
        "require-sri-for",
        "require-trusted-types-for",
        "sandbox",
        "script-src",
        "script-src-attr",
        "script-src-elem",
        "style-src",
        "style-src-attr",
        "style-src-elem",
        "trusted-types",
        "upgrade-insecure-requests",
        "webrtc",
        "worker-src",
    ]
)

# Directives whose values are source expressions. The rest -- sandbox,
# reflected-xss, trusted-types, report-to -- take bare tokens of their own, so
# keyword syntax does not apply to them.
CSP_SOURCE_DIRECTIVES = FETCH_DIRECTIVES | frozenset(
    ["base-uri", "form-action", "frame-ancestors", "navigate-to"]
)

# Directives dropped from the standard: browsers parse them and do nothing.
CSP_DEPRECATED_DIRECTIVES = frozenset(
    ["disown-opener", "plugin-types", "reflected-xss", "referrer"]
)

# Where a source expression decides whether injected script gets to run.
CSP_XSS_DIRECTIVES = (
    "script-src",
    "script-src-attr",
    "script-src-elem",
    "object-src",
    "base-uri",
)

# A bare scheme in one of those lists lets every host reachable over it supply
# script, which is barely narrower than no policy at all.
CSP_XSS_SCHEMES = frozenset(["data:", "http:", "https:"])

# Quoted source expressions the standard defines.
CSP_KEYWORDS = frozenset(
    [
        "'allow-duplicates'",
        "'block'",
        "'inline-speculation-rules'",
        "'none'",
        "'report-sample'",
        "'script'",
        "'self'",
        "'strict-dynamic'",
        "'unsafe-eval'",
        "'unsafe-hashed-attributes'",
        "'unsafe-hashes'",
        "'unsafe-inline'",
        "'wasm-eval'",
        "'wasm-unsafe-eval'",
    ]
)
CSP_KEYWORDS_UNQUOTED = frozenset(k.strip("'") for k in CSP_KEYWORDS)

# A nonce is per-response secret: too short or outside base64 and it is
# guessable, which hands an injected script the one token the policy trusts.
CSP_MIN_NONCE_LENGTH = 8
CSP_NONCE_CHARSET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-="
)


def _csp_host(source):
    """The host part of a source expression, without scheme, port or path."""
    host = source.rsplit("//", 1)[-1].split("/")[0]
    if host.startswith("["):  # bracketed IPv6 literal
        return host[: host.find("]") + 1]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _looks_like_ip(host):
    if host.startswith("[") or host.count(":") > 1:
        return True
    octets = host.split(".")
    return len(octets) == 4 and all(o.isdigit() for o in octets)


def _analyze_syntax(directives):
    """Findings about a policy that does not say what it appears to say.

    These are the defects that survive review precisely because the header looks
    right: a browser reads it, discards the broken part, and enforces the rest
    without complaint.
    """
    findings = []

    # A directive name sitting in a value list means a semicolon was forgotten,
    # which silently demotes that directive to a hostname nobody will ever serve.
    stray = sorted(
        {
            source.lower()
            for sources in directives.values()
            for source in sources
            if source.lower() in CSP_DIRECTIVES
        }
    )
    if stray:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-missing-semicolon",
                "present but lists %s as a source value, so a semicolon is "
                "missing and that directive is not in force at all"
                % ", ".join(stray),
            )
        )

    unknown = sorted(name for name in directives if name not in CSP_DIRECTIVES)
    if unknown:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-unknown-directive",
                "present but sets %s, which no browser recognises, so that part "
                "of the policy does nothing" % ", ".join(unknown),
            )
        )

    obsolete = sorted(name for name in directives if name in CSP_DEPRECATED_DIRECTIVES)
    if obsolete:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-deprecated-directive",
                "present but sets %s, which was dropped from the standard and is "
                "parsed and ignored" % ", ".join(obsolete),
            )
        )

    # Only source lists take source expressions. sandbox, reflected-xss and the
    # Trusted Types directives take bare tokens of their own, where an unquoted
    # `block` or `allow` is exactly right.
    invalid = sorted(
        {
            source
            for name, sources in directives.items()
            if name in CSP_SOURCE_DIRECTIVES
            for source in sources
            if _is_invalid_keyword(source)
        }
    )
    if invalid:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-invalid-keyword",
                "present but lists %s, which is read as a hostname rather than "
                "the keyword it resembles" % ", ".join(invalid),
            )
        )

    weak = sorted(
        {
            source
            for sources in directives.values()
            for source in sources
            if _is_weak_nonce(source)
        }
    )
    if weak:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-nonce-weak",
                "present but its nonce %s is guessable: nonces need at least %d "
                "base64 characters and a fresh value per response"
                % (", ".join(weak), CSP_MIN_NONCE_LENGTH),
            )
        )

    return findings


def _is_invalid_keyword(source):
    """Whether a source expression is a keyword a browser will not read as one."""
    lowered = source.lower()
    if lowered in CSP_KEYWORDS_UNQUOTED or lowered.startswith(NONCE_HASH_PREFIXES):
        return True  # the quotes were forgotten
    if source[:1] != "'":
        return False
    return not (lowered in CSP_KEYWORDS or lowered[1:].startswith(NONCE_HASH_PREFIXES))


def _is_weak_nonce(source):
    lowered = source.lower()
    if not (lowered.startswith("'nonce-") and lowered.endswith("'")):
        return False
    nonce = source[len("'nonce-") : -1]
    return len(nonce) < CSP_MIN_NONCE_LENGTH or not set(nonce) <= CSP_NONCE_CHARSET


def _analyze_csp(value):
    findings = []
    directives = parse_csp(value)

    # Inline scripts and inline styles are separate defects with separate
    # consequences, so they are separate findings: a policy that nonces its
    # scripts and allows inline CSS still stops script injection cold.
    def _inline_offenders(surfaces, script):
        """The directives that leave these inline surfaces unrestricted.

        Names the directive a browser actually consults, which may not be the
        one the surface is called after.
        """
        offenders = set()
        for surface in surfaces:
            for name in CSP_FALLBACKS[surface]:
                if name not in directives:
                    continue
                sources = directives[name]
                if _has_keyword(sources, "'unsafe-inline'") and not _ignores_unsafe_inline(
                    sources, script
                ):
                    offenders.add(name)
                break
        return sorted(offenders)

    inline_script = _inline_offenders(("script-src-elem", "script-src-attr"), script=True)
    if inline_script:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-unsafe-inline",
                "present but allows unsafe-inline in %s, defeating most of the "
                "cross-site scripting protection a policy provides"
                % ", ".join(inline_script),
            )
        )

    inline_style = _inline_offenders(("style-src-elem", "style-src-attr"), script=False)
    if inline_style:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-unsafe-inline-style",
                "present but allows unsafe-inline in %s, so injected CSS can "
                "redress the interface and, where the policy allows an outbound "
                "source, read page data through selector-driven requests; it "
                "cannot run script" % ", ".join(inline_style),
            )
        )

    if _has_keyword(_sources(directives, "script-src"), "'unsafe-eval'"):
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-unsafe-eval",
                "present but allows unsafe-eval in script-src, permitting "
                "strings to be executed as code",
            )
        )

    if "default-src" not in directives and "script-src" not in directives:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-no-default-src",
                "present but sets neither default-src nor script-src, so script "
                "loading is left unrestricted",
            )
        )

    wildcarded = sorted(
        name
        for name, sources in directives.items()
        if name in FETCH_DIRECTIVES and any(s == "*" for s in sources)
    )
    if wildcarded:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-wildcard",
                "present but uses a wildcard source (*) in %s, allowing content "
                "from any origin" % ", ".join(wildcarded),
            )
        )

    frame_ancestors = directives.get("frame-ancestors")
    if frame_ancestors is None:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-no-frame-ancestors",
                "present but sets no frame-ancestors directive, so the page can "
                "be framed by any origin",
            )
        )
    elif "*" in frame_ancestors:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-frame-ancestors-wildcard",
                "present but sets frame-ancestors to *, so the page can be framed "
                "by any origin, exactly as if the directive were absent",
            )
        )

    if "object-src" not in directives and "default-src" not in directives:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-no-object-src",
                "present but sets neither object-src nor default-src, so plugin "
                "content is left unrestricted",
            )
        )

    if "base-uri" not in directives:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-no-base-uri",
                "present but sets no base-uri directive, so an injected <base> "
                "tag can redirect every relative URL on the page",
            )
        )

    # A bare scheme where script comes from is barely narrower than no policy:
    # every host reachable over it qualifies.
    schemed = set()
    for name in CSP_XSS_DIRECTIVES:
        for candidate in CSP_FALLBACKS[name]:
            if candidate not in directives:
                continue
            sources = directives[candidate]
            # 'strict-dynamic' makes the allowlist inert, and pairing it with a
            # scheme is the documented fallback for browsers that lack it.
            if not (name.startswith("script-") and _ignores_unsafe_inline(sources, True)):
                schemed.update(
                    (candidate, source.lower())
                    for source in sources
                    if source.lower() in CSP_XSS_SCHEMES
                )
            break
    if schemed:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-plain-scheme",
                "present but allows the bare scheme %s, so anything served over "
                "it counts as an allowed source: every host on the web for "
                "http: and https:, any attacker-authored payload for data:"
                % ", ".join(
                    "%s in %s" % (scheme, name) for name, scheme in sorted(schemed)
                ),
            )
        )

    insecure = sorted(
        {
            source
            for sources in directives.values()
            for source in sources
            if source.lower().startswith("http://")
        }
    )
    if insecure:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-http-source",
                "present but allows %s over plaintext HTTP, which anyone on the "
                "path can replace" % ", ".join(insecure),
            )
        )

    addresses = sorted(
        {
            _csp_host(source)
            for sources in directives.values()
            for source in sources
            if source[:1] != "'" and _looks_like_ip(_csp_host(source))
        }
    )
    if addresses:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-ip-source",
                "present but allows the IP address %s, which browsers do not "
                "match against and which usually means a development entry "
                "reached production" % ", ".join(addresses),
            )
        )

    findings.extend(_analyze_syntax(directives))

    return findings


def _parse_directives(value):
    """Parse a semicolon-separated `key[=value]` header into a lowercased mapping.

    Valueless directives map to None. Values are unquoted.
    """
    directives = {}
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        key, sep, val = chunk.partition("=")
        directives[key.strip().lower()] = val.strip().strip('"') if sep else None
    return directives


def _analyze_hsts(value):
    directives = _parse_directives(value)

    if directives.get("max-age") is None:
        return [
            Finding(
                "Strict-Transport-Security",
                "hsts-malformed",
                "present but specifies no max-age, so browsers ignore the policy "
                "entirely",
            )
        ]
    try:
        max_age = int(directives["max-age"])
    except ValueError:
        return [
            Finding(
                "Strict-Transport-Security",
                "hsts-malformed",
                "present but its max-age is not a number (%s), so browsers ignore "
                "the policy entirely" % directives["max-age"],
            )
        ]

    findings = []
    if max_age == 0:
        findings.append(
            Finding(
                "Strict-Transport-Security",
                "hsts-max-age-zero",
                "present but set to max-age=0, which tells browsers to forget the "
                "policy and permits plaintext connections again",
            )
        )
    elif max_age < HSTS_MIN_MAX_AGE:
        findings.append(
            Finding(
                "Strict-Transport-Security",
                "hsts-max-age-short",
                "present but its max-age is only %d seconds, below the "
                "recommended minimum of %d (six months)" % (max_age, HSTS_MIN_MAX_AGE),
            )
        )

    if "includesubdomains" not in directives:
        findings.append(
            Finding(
                "Strict-Transport-Security",
                "hsts-no-include-subdomains",
                "present but does not set includeSubDomains, leaving subdomains "
                "reachable over plaintext HTTP",
            )
        )

    # The preload directive is a submission to a list browsers ship, and the
    # list has entry requirements. Failing them means the token does nothing
    # while the operator believes the domain is preloaded.
    if "preload" in directives:
        unmet = []
        if "includesubdomains" not in directives:
            unmet.append("includeSubDomains")
        if max_age < HSTS_PRELOAD_MIN_MAX_AGE:
            unmet.append(
                "a max-age of at least %d (one year) rather than %d"
                % (HSTS_PRELOAD_MIN_MAX_AGE, max_age)
            )
        if unmet:
            findings.append(
                Finding(
                    "Strict-Transport-Security",
                    "hsts-preload-ineffective",
                    "present with preload, but the preload list requires %s, so "
                    "the domain would not be accepted" % " and ".join(unmet),
                )
            )

    return findings


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


def parse_permissions_policy(value):
    """Parse a Permissions-Policy header into a {feature: [allowlist item, ...]} mapping.

    Feature names are lowercased; allowlist items keep their case, because
    origins are compared as written. An empty allowlist `()` yields [], and `*`
    yields ["*"]. Repeated features keep the last one, which is what the
    structured field syntax the header is built on requires of parsers.
    Chunks that are not `feature=allowlist` are skipped: call analyze() to learn
    that the header is malformed.
    """
    policy = {}
    for chunk in value.split(","):
        name, sep, allowlist = chunk.partition("=")
        name = name.strip().lower()
        if not sep or not name:
            continue
        allowlist = allowlist.strip()
        if allowlist.startswith("(") and allowlist.endswith(")"):
            allowlist = allowlist[1:-1]
        policy[name] = [item.strip('"') for item in allowlist.split()]
    return policy


def _analyze_pp(value):
    stripped = value.strip()

    # Structured field parsing is all-or-nothing: one unparseable member and the
    # browser drops the whole header, so a syntax error is never partial.
    items = [chunk.strip() for chunk in stripped.split(",")]
    malformed = [item for item in items if item and "=" not in item]
    if malformed:
        # Feature-Policy, the predecessor, separated features with semicolons
        # and quoted its allowlist keywords. That spelling still turns up in
        # Permissions-Policy headers, where it parses as nothing at all.
        if ";" in stripped or "'" in stripped:
            return [
                Finding(
                    "Permissions-Policy",
                    "pp-legacy-syntax",
                    "present but written in the older Feature-Policy syntax (%s), "
                    "which browsers cannot parse, so the whole header is ignored"
                    % stripped,
                )
            ]
        return [
            Finding(
                "Permissions-Policy",
                "pp-invalid",
                "present but %s is not a feature=allowlist pair, so browsers "
                "ignore the whole header" % malformed[0],
            )
        ]

    policy = parse_permissions_policy(stripped)
    if not policy:
        return [
            Finding(
                "Permissions-Policy",
                "pp-empty",
                "present but sets no feature, so it restricts nothing",
            )
        ]

    wildcarded = sorted(name for name, allowlist in policy.items() if "*" in allowlist)
    if wildcarded:
        return [
            Finding(
                "Permissions-Policy",
                "pp-wildcard",
                "present but allows %s in every origin (*), including third party "
                "frames the page embeds" % ", ".join(wildcarded),
            )
        ]

    return []


def _bare_item(value):
    """The token of a structured field item, without its parameters.

    COOP, COEP and CORP are structured field items: a token optionally followed
    by `; name=value` parameters. The reporting integration uses one of those to
    name a report group -- `same-origin; report-to="coop"` selects exactly the
    policy `same-origin` does.
    """
    return value.split(";")[0].strip().lower()


def _analyze_coop(value):
    # Browsers fall back to unsafe-none for unrecognised values, so an invalid
    # value and an explicit unsafe-none are the same defect.
    if _bare_item(value) not in COOP_VALUES:
        return [
            Finding(
                "Cross-Origin-Opener-Policy",
                "coop-unsafe-none",
                "present but effectively unsafe-none (%s), which provides no "
                "cross-origin isolation" % value.strip(),
            )
        ]
    return []


def _analyze_coep(value):
    bare = _bare_item(value)
    if bare not in COEP_VALUES:
        return [
            Finding(
                "Cross-Origin-Embedder-Policy",
                "coep-invalid",
                "present but has an unrecognised value (%s); expected unsafe-none, "
                "require-corp or credentialless" % value.strip(),
            )
        ]
    # unsafe-none is the state a document is already in without the header, so
    # setting it explicitly opts into nothing.
    if bare == "unsafe-none":
        return [
            Finding(
                "Cross-Origin-Embedder-Policy",
                "coep-unsafe-none",
                "present but set to unsafe-none, which is the default and embeds "
                "cross-origin resources without requiring them to opt in",
            )
        ]
    return []


def _analyze_corp(value):
    bare = _bare_item(value)
    if bare not in CORP_VALUES:
        return [
            Finding(
                "Cross-Origin-Resource-Policy",
                "corp-invalid",
                "present but has an unrecognised value (%s); expected same-site, "
                "same-origin or cross-origin" % value.strip(),
            )
        ]
    # cross-origin permits exactly what no header at all permits.
    if bare == "cross-origin":
        return [
            Finding(
                "Cross-Origin-Resource-Policy",
                "corp-cross-origin",
                "present but set to cross-origin, so it keeps no ordinary "
                "embedder out; that is a deliberate opt-in for resources meant "
                "to stay loadable by cross-origin isolated pages, and not a "
                "restriction",
            )
        ]
    return []


def _analyze_acao(value):
    origin = value.strip()
    if origin.lower() == "null":
        return [
            Finding(
                "Access-Control-Allow-Origin",
                "acao-null",
                "present but set to null, which any sandboxed iframe or data: "
                "URL can send as its Origin, so any page can read the response",
            )
        ]
    # The header carries one origin or the wildcard. A list is rejected outright,
    # which fails closed, but it also means the CORS the operator configured is
    # not happening at all.
    if "," in origin or len(origin.split()) > 1:
        return [
            Finding(
                "Access-Control-Allow-Origin",
                "acao-multiple-origins",
                "present but lists more than one origin (%s), which the header "
                "does not allow, so browsers reject it and no cross-origin read "
                "succeeds" % origin,
            )
        ]
    if origin == "*":
        return [
            Finding(
                "Access-Control-Allow-Origin",
                "acao-wildcard",
                "present and set to *, so any origin may read the response; "
                "that is deliberate for public assets and a leak for anything "
                "user-specific",
            )
        ]
    return []


def _analyze_ect(value):
    # No need to parse the actual policy since no browser uses it anyway.
    return [
        Finding("Expect-CT", "ect-deprecated", "present but deprecated since June 2021")
    ]


def parse_feature_policy(value):
    """Parse a Feature-Policy header into a {feature: [allowlist item, ...]} mapping.

    The predecessor syntax: features separated by semicolons, each followed by a
    space-separated allowlist. Feature names are lowercased and allowlist items
    are unquoted, so the result compares directly against
    parse_permissions_policy(). Repeated features keep the last, as there too.
    """
    policy = {}
    for chunk in value.split(";"):
        parts = chunk.split()
        if not parts:
            continue
        policy[parts[0].lower()] = [item.strip("'\"") for item in parts[1:]]
    return policy


def _allowlist(items):
    """An allowlist in the form the two syntaxes agree on.

    Feature-Policy spells "no origins" as 'none'; Permissions-Policy spells it
    as an empty list. They mean the same thing and must compare equal.
    """
    lowered = sorted(item.lower() for item in items)
    return [] if lowered == ["none"] else lowered


def _analyze_fp(value):
    # Superseded rather than dead: Chromium still enforces Feature-Policy, so a
    # page sending only this one is protected there and nowhere else. The
    # syntaxes differ, which is why pp-legacy-syntax exists for the reverse
    # mistake of writing this spelling under the new name.
    findings = [
        Finding(
            "Feature-Policy",
            "fp-deprecated",
            "present but superseded by Permissions-Policy, which uses a "
            "different syntax; only Chromium still honours this header",
        )
    ]

    policy = parse_feature_policy(value)
    if not policy:
        findings.append(
            Finding(
                "Feature-Policy",
                "fp-empty",
                "present but sets no feature, so it restricts nothing",
            )
        )
        return findings

    wildcarded = sorted(name for name, allow in policy.items() if "*" in allow)
    if wildcarded:
        findings.append(
            Finding(
                "Feature-Policy",
                "fp-wildcard",
                "present but allows %s in every origin (*), including third "
                "party frames the page embeds" % ", ".join(wildcarded),
            )
        )

    return findings


def _analyze_p3p(value):
    # Only Internet Explorer ever read P3P, to decide whether to accept third
    # party cookies, and the W3C abandoned the spec. Its compact policy is not
    # worth parsing: a large share of deployments were deliberate nonsense sent
    # to make IE relent, and nothing has consumed either kind since IE retired.
    return [
        Finding(
            "P3P",
            "p3p-deprecated",
            "present but P3P was only ever read by Internet Explorer, which is "
            "retired, and the specification was abandoned",
        )
    ]


def _analyze_xdo(value):
    return [
        Finding(
            "X-Download-Options",
            "xdo-deprecated",
            "present but only Internet Explorer read it, to stop a download "
            "being opened in the site's own origin; no current browser does",
        )
    ]


def _analyze_hpkp(value):
    return [
        Finding(
            "Public-Key-Pins",
            "hpkp-deprecated",
            "present but every browser has removed key pinning, so the pins "
            "bind nothing; it was withdrawn because a mistake could lock users "
            "out of a site for the lifetime of the policy",
        )
    ]


def _analyze_hpkp_report_only(value):
    return [
        Finding(
            "Public-Key-Pins-Report-Only",
            "hpkp-ro-deprecated",
            "present but every browser has removed key pinning, so nothing is "
            "measured and nothing is reported",
        )
    ]


def _analyze_xcsp(value):
    return [
        Finding(
            "X-Content-Security-Policy",
            "xcsp-deprecated",
            "present but no browser has read this header since Firefox 23; if "
            "it is the only policy sent, the page has none",
        )
    ]


def _analyze_xwkcsp(value):
    return [
        Finding(
            "X-WebKit-CSP",
            "xwkcsp-deprecated",
            "present but no browser has read this header since Chrome 25; if "
            "it is the only policy sent, the page has none",
        )
    ]


def _analyze_xpcdp(value):
    normalized = value.strip().lower()

    # none-this-response withholds the policy file from this one response, which
    # is the same answer as none for the response being analyzed.
    if normalized in ("none", "none-this-response"):
        return [
            Finding(
                "X-Permitted-Cross-Domain-Policies",
                "xpcdp-deprecated",
                "present but permits no cross-domain policy file, which is the "
                "restrictive setting; only Flash and Acrobat clients ever read it",
            )
        ]

    if normalized == "all":
        return [
            Finding(
                "X-Permitted-Cross-Domain-Policies",
                "xpcdp-all",
                "present but set to all, so any file on the server can serve as a "
                "cross-domain policy, including whatever a user can upload",
            )
        ]

    # The remaining values narrow which files count as a policy without saying
    # what those files permit, so the answer is in crossdomain.xml, not here.
    if normalized in XPCDP_VALUES:
        return [
            Finding(
                "X-Permitted-Cross-Domain-Policies",
                "xpcdp-policy-file",
                "present and set to %s, which leaves cross-domain access to the "
                "policy file; check crossdomain.xml" % normalized,
            )
        ]

    return [
        Finding(
            "X-Permitted-Cross-Domain-Policies",
            "xpcdp-invalid",
            "present but has an unrecognised value (%s), so clients fall back to "
            "their default policy" % value.strip(),
        )
    ]


def _analyze_xxp(value):
    normalized = value.strip().lower().replace(" ", "")
    if normalized == "0":
        return [Finding("X-XSS-Protection", "xxp-deprecated", "present but disabled")]
    elif normalized == "1":
        return [
            Finding(
                "X-XSS-Protection",
                "xxp-enabled",
                "present and enabled, which in some cases can create XSS vulnerabilities in otherwise safe websites",
            )
        ]
    elif normalized == "1;mode=block":
        return [
            Finding(
                "X-XSS-Protection",
                "xxp-blocked",
                "present and enabled in blocked mode, which may lead to side channel attacks on iframe embeddable websites",
            )
        ]
    return [
        Finding(
            "X-XSS-Protection",
            "xxp-invalid",
            "present but has an unrecognised value (%s), expected '0', '1' or '1; mode=block'"
            % value.strip(),
        )
    ]


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


# A syntax defect belongs to the text of one policy, so any occurrence counts.
# Everything else describes what a policy permits, and a browser enforces every
# policy a response carries -- a resource must satisfy all of them -- so the
# effective policy is their intersection and a weakness has to be in every one.
CSP_SYNTAX_CODES = frozenset(
    [
        "csp-deprecated-directive",
        "csp-http-source",
        "csp-invalid-keyword",
        "csp-ip-source",
        "csp-missing-semicolon",
        "csp-nonce-weak",
        "csp-unknown-directive",
    ]
)


def _analyze_csp_all(policies):
    """Findings for every Content-Security-Policy the response carries.

    One policy is the ordinary case and answers for itself. Several are enforced
    together, so reporting each in isolation would call a directive missing that
    a sibling policy sets -- which is worse than saying nothing.
    """
    if len(policies) == 1:
        return _analyze_csp(policies[0])
    per_policy = [{f.code: f for f in _analyze_csp(policy)} for policy in policies]
    findings = []
    for codes in per_policy:
        for code, finding in codes.items():
            if any(finding.code == seen.code for seen in findings):
                continue
            if code in CSP_SYNTAX_CODES or all(code in other for other in per_policy):
                findings.append(finding)
    return findings


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


# How bad each finding is. A consumer is free to ignore these and apply its own
# model -- for most sites a badly configured header is a low-risk issue whatever
# it says here -- but they are SARIF levels, so they can be adopted directly.
# An error means the header does not deliver the protection its presence
# implies: browsers ignore it, or it permits the very thing it exists to stop.
# A warning means it protects, but a hardening directive is missing. A note is
# a fact with no defect.
FINDING_SEVERITY = {
    "acao-credentials-wildcard": "error",
    "acao-multiple-origins": "error",
    "acao-null": "error",
    "coep-invalid": "error",
    "corp-invalid": "error",
    "csp-invalid-keyword": "error",
    "csp-missing-semicolon": "error",
    "csp-plain-scheme": "error",
    "csp-frame-ancestors-wildcard": "error",
    "csp-no-default-src": "error",
    "csp-unsafe-eval": "error",
    "csp-unsafe-inline": "error",
    "csp-wildcard": "error",
    "hsts-malformed": "error",
    "hsts-max-age-zero": "error",
    "hsts-missing": "error",
    "hsts-preload-ineffective": "error",
    "hsts-not-preloaded": "error",
    "pp-invalid": "error",
    "pp-legacy-syntax": "error",
    "rp-invalid": "error",
    "rp-unsafe-url": "error",
    "xcto-invalid": "error",
    "xfo-deprecated": "error",
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
    "hsts-no-include-subdomains": "warning",
    "pp-empty": "warning",
    "pp-wildcard": "warning",
    "rp-missing": "warning",
    "xcto-missing": "warning",
    "xfo-missing": "warning",
    "coep-missing": "note",
    "coep-unsafe-none": "note",
    "csp-deprecated-directive": "note",
    "csp-ip-source": "note",
    "fp-deprecated": "note",
    "hpkp-deprecated": "note",
    "hpkp-ro-deprecated": "note",
    "xcsp-deprecated": "note",
    "xwkcsp-deprecated": "note",
    "fp-conflicts": "note",
    "p3p-deprecated": "note",
    "xdo-deprecated": "note",
    "acao-wildcard": "note",
    "coep-ro-unenforced": "note",
    "coop-ro-unenforced": "note",
    "csp-ro-unenforced": "note",
    "ect-deprecated": "note",
    "pp-missing": "note",
    "xpcdp-deprecated": "note",
    "xpcdp-policy-file": "note",
    "xxp-deprecated": "note",
}

# Worst first; also the order findings are printed in.
SEVERITIES = ("error", "warning", "note")


def severity(code):
    """How bad a finding is. Unknown codes are warnings, never crashes."""
    return FINDING_SEVERITY.get(code, "warning")


def order_findings(findings):
    """Worst first, so a header's headline problem reads first."""
    return sorted(findings, key=lambda f: SEVERITIES.index(severity(f.code)))


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


def _normalize(present):
    """`present` keyed by stripped, lowercased names, every value in a list.

    Header names are case-insensitive, so two spellings are one header. A value
    may be given as a string or as a list of them: a caller with one value per
    header -- the ordinary case -- passes the mapping it already has, and one
    holding a repeated header passes its values without having to choose.
    """
    normalized = {}
    for name, value in present.items():
        values = [value] if isinstance(value, str) else list(value)
        normalized.setdefault(name.strip().lower(), []).extend(values)
    return normalized


def _lookup(present, name):
    """The first value of `name`, or None when the response does not carry it.

    Every header this is asked about carries one value; where a response repeats
    one anyway, the first is what a browser's own single-value lookup returns.
    """
    values = present.get(name.lower())
    return values[0] if values else None


def _lookup_all(present, name):
    """Every value of `name`, in the order the response carried them."""
    return present.get(name.lower(), [])


def _sole_value(present, name):
    """The value of `name` when the response is unambiguous about it.

    None when the header is absent, and None when it was sent more than once
    with values that disagree: no specification says which of those a client
    honours, so the response cannot be relied on to mean either.
    """
    values = present.get(name.lower(), [])
    distinct = {value.strip() for value in values}
    return values[0] if len(distinct) == 1 else None


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


def _seeks_isolation(present):
    """Whether COOP asks for cross-origin isolation.

    Only same-origin does: same-origin-allow-popups deliberately lets popups it
    opens keep their opener, which is why a browser will not set
    crossOriginIsolated for it.
    """
    value = _sole_value(present, "Cross-Origin-Opener-Policy")
    return value is not None and _bare_item(value) == "same-origin"


def _grants_isolation(present):
    """Whether COEP holds up its half of cross-origin isolation."""
    value = _sole_value(present, "Cross-Origin-Embedder-Policy")
    return value is not None and _bare_item(value) in ("require-corp", "credentialless")


def _analyze_isolation(present):
    """Findings about the COOP/COEP pair that neither header shows alone.

    Cross-origin isolation needs both halves. A COEP that opts in while COOP
    does not is a cost with no benefit: the page pays for subresources that must
    opt in, and still gets no crossOriginIsolated.
    """
    if _grants_isolation(present) and not _seeks_isolation(present):
        return [
            Finding(
                "Cross-Origin-Embedder-Policy",
                "coep-no-isolation",
                "present and opting in, but Cross-Origin-Opener-Policy is not "
                "same-origin, so crossOriginIsolated stays false and the "
                "SharedArrayBuffer-class APIs remain unavailable; expected for a "
                "document meant to be embedded, since COOP is inert in a frame",
            )
        ]
    return []


def _shares_credentials_with_everyone(present):
    """Whether the response asks for the one CORS pairing browsers refuse."""
    acao = _sole_value(present, "Access-Control-Allow-Origin")
    acac = _sole_value(present, "Access-Control-Allow-Credentials")
    return (
        acao is not None
        and acac is not None
        and acao.strip() == "*"
        and acac.strip().lower() == "true"
    )


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


def _analyze_cors(present):
    """Findings about the CORS pair that neither header shows alone."""
    if not _shares_credentials_with_everyone(present):
        return []
    return [
        Finding(
            "Access-Control-Allow-Origin",
            "acao-credentials-wildcard",
            "present as * alongside Access-Control-Allow-Credentials: true, a "
            "combination browsers refuse outright, so every credentialed "
            "cross-origin request fails",
        )
    ]


def _analyze_policy_overlap(present):
    """Features both policy headers set, and set differently.

    Only Chromium reads either header, so there is no split between browsers
    here -- but there are two sources of truth for one policy, and which one
    wins is an implementation detail rather than something to depend on.
    """
    old = _lookup(present, "Feature-Policy")
    new = _lookup(present, "Permissions-Policy")
    if old is None or new is None:
        return []
    old_policy = parse_feature_policy(old)
    new_policy = parse_permissions_policy(new)
    disagree = sorted(
        name
        for name, allow in old_policy.items()
        if name in new_policy and _allowlist(allow) != _allowlist(new_policy[name])
    )
    if not disagree:
        return []
    return [
        Finding(
            "Feature-Policy",
            "fp-conflicts",
            "present alongside Permissions-Policy, and the two disagree about "
            "%s; which one applies is an implementation detail, so the policy "
            "should be stated once" % ", ".join(disagree),
        )
    ]


def _analyze_preload(present, host):
    """Whether a domain claiming preload is on the list browsers actually ship.

    The requirements check in _analyze_hsts catches a submission that would be
    rejected; this catches one that was never made, or has since been removed.
    Answers only when the optional hstspreload package is installed.
    """
    if hstspreload is None or not host:
        return []
    value = _lookup(present, "Strict-Transport-Security")
    if value is None or "preload" not in _parse_directives(value):
        return []
    if hstspreload.in_hsts_preload(host):
        return []
    return [
        Finding(
            "Strict-Transport-Security",
            "hsts-not-preloaded",
            "present with preload, but %s is not on the list browsers ship, so "
            "the very first visit is still unprotected" % host,
        )
    ]


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


def _single_or_list(values):
    """One value as itself, several as a list.

    A header is normally sent once, and a caller should not have to unwrap a
    list to read it; a repeated one keeps every value, because that is what the
    response said and a browser acts on all of them.
    """
    return values[0] if len(values) == 1 else list(values)


def _filter_headers(present, wanted):
    # Normalised here too: these are public entry points, and a caller has no
    # reason to know that analyze_all happens to do it for the other path.
    present = _normalize(present)
    filtered = {}
    for name in wanted:
        values = present.get(name.lower())
        if values:
            filtered[name] = _single_or_list(values)
    return filtered


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
