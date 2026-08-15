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

"""Headers that are obsolete.

Their absence is the desired state, so none is ever reported missing. Most are
inert in every current browser; the ones that still do something are the reason
this file is not simply a list of names.
"""

from .findings import Finding

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


# Security headers that are obsolete: their absence is the desired state, so
# they are never reported missing, only reported on when a response carries one.
DEPRECATED_HEADERS = (
    "Expect-CT",
    "Feature-Policy",
    "P3P",
    "Public-Key-Pins",
    "Public-Key-Pins-Report-Only",
    "X-Content-Security-Policy",
    "X-DNS-Prefetch-Control",
    "X-Download-Options",
    "X-Permitted-Cross-Domain-Policies",
    "X-WebKit-CSP",
    "X-XSS-Protection",
)


def _analyze_ect(value):
    # No need to parse the actual policy since no browser uses it anyway.
    return [Finding("Expect-CT", "ect-deprecated")]


def _analyze_p3p(value):
    # Only Internet Explorer ever read P3P, to decide whether to accept third
    # party cookies, and the W3C abandoned the spec. Its compact policy is not
    # worth parsing: a large share of deployments were deliberate nonsense sent
    # to make IE relent, and nothing has consumed either kind since IE retired.
    return [Finding("P3P", "p3p-deprecated")]


def _analyze_xdo(value):
    return [Finding("X-Download-Options", "xdo-deprecated")]


def _analyze_xdpc(value):
    # The odd one in this file: never standardised rather than withdrawn, which
    # is why the code does not end in -deprecated. It is here because the table
    # is what "do not reach for this" is spelled as, and because its absence is
    # the desired state for the same reason as the rest -- there is nothing to
    # report missing when only one browser reads it.
    #
    # Both values earn the same note. `on` asks for the behaviour browsers have
    # anyway, and `off` is a real measure in the one engine that honours it, so
    # neither is a defect and neither is a policy. OWASP recommends sending it;
    # that recommendation is not contradicted here, only qualified.
    return [Finding("X-DNS-Prefetch-Control", "xdpc-nonstandard")]


def _analyze_hpkp(value):
    return [Finding("Public-Key-Pins", "hpkp-deprecated")]


def _analyze_hpkp_report_only(value):
    return [Finding("Public-Key-Pins-Report-Only", "hpkp-ro-deprecated")]


def _analyze_xcsp(value):
    return [Finding("X-Content-Security-Policy", "xcsp-deprecated")]


def _analyze_xwkcsp(value):
    return [Finding("X-WebKit-CSP", "xwkcsp-deprecated")]


def _analyze_xpcdp(value):
    normalized = value.strip().lower()

    # none-this-response withholds the policy file from this one response, which
    # is the same answer as none for the response being analyzed.
    if normalized in ("none", "none-this-response"):
        return [Finding("X-Permitted-Cross-Domain-Policies", "xpcdp-deprecated")]

    if normalized == "all":
        return [Finding("X-Permitted-Cross-Domain-Policies", "xpcdp-all")]

    # The remaining values narrow which files count as a policy without saying
    # what those files permit, so the answer is in crossdomain.xml, not here.
    if normalized in XPCDP_VALUES:
        return [
            Finding(
                "X-Permitted-Cross-Domain-Policies",
                "xpcdp-policy-file",
                {"value": normalized},
            )
        ]

    return [
        Finding(
            "X-Permitted-Cross-Domain-Policies",
            "xpcdp-invalid",
            {"value": value.strip()},
        )
    ]


def _analyze_xxp(value):
    normalized = value.strip().lower().replace(" ", "")
    if normalized == "0":
        return [Finding("X-XSS-Protection", "xxp-deprecated")]
    elif normalized == "1":
        return [Finding("X-XSS-Protection", "xxp-enabled")]
    elif normalized == "1;mode=block":
        return [Finding("X-XSS-Protection", "xxp-blocked")]
    return [Finding("X-XSS-Protection", "xxp-invalid", {"value": value.strip()})]
