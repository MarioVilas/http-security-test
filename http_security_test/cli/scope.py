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

"""Where the tool is allowed to wander.

One concept, not two: a list of host patterns. An earlier draft had a
`--follow {none,host,subdomain,any}` enum beside this and every value of it
turned out to be a pattern.

A pattern is an exact hostname, `*.example.com`, or bare `*`. Matching is on
the hostname only -- never scheme or port -- so an https-to-http redirect on
one host stays in scope, and whether that downgrade is a *finding* is the
analyser's business rather than this guard's.

`*.example.com` does not match `example.com`, and does match at any depth.
That is decided on composability: keeping the wildcard and the apex disjoint
gives two orthogonal primitives, so "subdomains but not the apex" -- a real
engagement shape -- has a spelling at all. Deriving scope from label counts
instead was rejected; see DECISION R-1 in the spec for the measurement.
"""

import os


def matches(pattern, hostname):
    """Whether one pattern admits one hostname."""
    pattern = (pattern or "").strip().lower().rstrip(".")
    hostname = (hostname or "").strip().lower().rstrip(".")
    if not hostname or not pattern:
        return False
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        # The leading star is dropped, not the dot: endswith(".example.com")
        # admits a.b.example.com and refuses both example.com and
        # notexample.com, which a bare suffix test would not.
        return hostname.endswith(pattern[1:])
    return hostname == pattern


def allows(patterns, hostname):
    """Whether any pattern admits this hostname."""
    return any(matches(pattern, hostname) for pattern in patterns)


def derive(hosts):
    """The default scope: every target host and everything under it."""
    patterns = []
    for name in hosts:
        if not name:
            continue
        for pattern in (name, "*." + name):
            if pattern not in patterns:
                patterns.append(pattern)
    return tuple(patterns)


def resolve(explicit, target_hosts):
    """The scope in force.

    An explicit --scope replaces the derived default, with one exception: every
    target's own host stays in scope regardless. You typed it, so hitting it is
    in scope by construction -- and without the exception, naming an unrelated
    domain would silently forbid a redirect back to your own target.
    """
    if not explicit:
        return derive(target_hosts)
    patterns = list(explicit)
    for name in target_hosts:
        if name and name not in patterns:
            patterns.append(name)
    return tuple(patterns)


def banner(patterns, derived):
    """The line printed before the first request, so the guard is auditable."""
    return "scope: %s%s" % (
        ", ".join(patterns) or "(empty)",
        "  (derived from targets)" if derived else "",
    )


def looks_shell_expanded(patterns):
    """Patterns naming a real file -- the shell probably ate an unquoted glob.

    A warning about argv, not an analysis judgement: unquoted `*.example.com`
    expands silently when a matching file happens to sit in the working
    directory, which makes the bug appear on some machines and not others.
    """
    return [pattern for pattern in patterns if os.path.exists(pattern)]
