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

"""Strict-Transport-Security.

Whether a site is reachable over plaintext at all, and for how long that answer
sticks. The preload list is the one question a response cannot answer about
itself, so this is also the only module with a third-party dependency -- an
optional one: without it that single claim goes unchecked and nothing else
changes.
"""

from .findings import Finding
from .message import _lookup

try:
    import hstspreload
except ImportError:
    hstspreload = None


HSTS_MIN_MAX_AGE = 15552000


# The HSTS preload list will not accept a domain below one year, and requires
# includeSubDomains alongside it. https://hstspreload.org/
HSTS_PRELOAD_MIN_MAX_AGE = 31536000


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
