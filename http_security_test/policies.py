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

"""Permissions-Policy and the Feature-Policy it replaced.

Both delegate browser features to origins, in syntaxes that look nothing alike,
and only Chromium reads either as an HTTP header -- so the older one decides
something only when it stands alone.
"""

from .findings import Finding
from .message import _lookup


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
                Finding("Permissions-Policy", "pp-legacy-syntax", {"value": stripped})
            ]
        return [Finding("Permissions-Policy", "pp-invalid", {"item": malformed[0]})]

    policy = parse_permissions_policy(stripped)
    if not policy:
        return [Finding("Permissions-Policy", "pp-empty")]

    wildcarded = sorted(name for name, allowlist in policy.items() if "*" in allowlist)
    if wildcarded:
        return [Finding("Permissions-Policy", "pp-wildcard", {"features": wildcarded})]

    return []


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
    findings = [Finding("Feature-Policy", "fp-deprecated")]

    policy = parse_feature_policy(value)
    if not policy:
        findings.append(Finding("Feature-Policy", "fp-empty"))
        return findings

    wildcarded = sorted(name for name, allow in policy.items() if "*" in allow)
    if wildcarded:
        findings.append(
            Finding("Feature-Policy", "fp-wildcard", {"features": wildcarded})
        )

    return findings


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
    return [Finding("Feature-Policy", "fp-conflicts", {"features": disagree})]
