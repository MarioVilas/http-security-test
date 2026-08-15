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

"""Content-Security-Policy.

The largest analysis here by some way, and self-contained: a policy is parsed
and judged on its own terms, and the only thing it needs from elsewhere is
somewhere to put a finding.
"""

from .findings import Finding

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
                {"directives": stray},
            )
        )

    unknown = sorted(name for name in directives if name not in CSP_DIRECTIVES)
    if unknown:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-unknown-directive",
                {"directives": unknown},
            )
        )

    obsolete = sorted(name for name in directives if name in CSP_DEPRECATED_DIRECTIVES)
    if obsolete:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-deprecated-directive",
                {"directives": obsolete},
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
                "Content-Security-Policy", "csp-invalid-keyword", {"sources": invalid}
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
                {"nonces": weak, "minimum": CSP_MIN_NONCE_LENGTH},
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
                if _has_keyword(
                    sources, "'unsafe-inline'"
                ) and not _ignores_unsafe_inline(sources, script):
                    offenders.add(name)
                break
        return sorted(offenders)

    inline_script = _inline_offenders(
        ("script-src-elem", "script-src-attr"), script=True
    )
    if inline_script:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-unsafe-inline",
                {"directives": inline_script},
            )
        )

    inline_style = _inline_offenders(("style-src-elem", "style-src-attr"), script=False)
    if inline_style:
        findings.append(
            Finding(
                "Content-Security-Policy",
                "csp-unsafe-inline-style",
                {"directives": inline_style},
            )
        )

    if _has_keyword(_sources(directives, "script-src"), "'unsafe-eval'"):
        findings.append(Finding("Content-Security-Policy", "csp-unsafe-eval"))

    if "default-src" not in directives and "script-src" not in directives:
        findings.append(Finding("Content-Security-Policy", "csp-no-default-src"))

    wildcarded = sorted(
        name
        for name, sources in directives.items()
        if name in FETCH_DIRECTIVES and any(s == "*" for s in sources)
    )
    if wildcarded:
        findings.append(
            Finding(
                "Content-Security-Policy", "csp-wildcard", {"directives": wildcarded}
            )
        )

    frame_ancestors = directives.get("frame-ancestors")
    if frame_ancestors is None:
        findings.append(Finding("Content-Security-Policy", "csp-no-frame-ancestors"))
    elif "*" in frame_ancestors:
        findings.append(
            Finding("Content-Security-Policy", "csp-frame-ancestors-wildcard")
        )

    if "object-src" not in directives and "default-src" not in directives:
        findings.append(Finding("Content-Security-Policy", "csp-no-object-src"))

    if "base-uri" not in directives:
        findings.append(Finding("Content-Security-Policy", "csp-no-base-uri"))

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
            if not (
                name.startswith("script-") and _ignores_unsafe_inline(sources, True)
            ):
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
                {
                    "schemes": [
                        {"directive": name, "scheme": scheme}
                        for name, scheme in sorted(schemed)
                    ]
                },
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
            Finding("Content-Security-Policy", "csp-http-source", {"sources": insecure})
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
                "Content-Security-Policy", "csp-ip-source", {"addresses": addresses}
            )
        )

    findings.extend(_analyze_syntax(directives))

    return findings


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
