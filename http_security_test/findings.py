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

"""Findings and how bad they are.

A finding is a fact about a header: a stable code, a message, and a rating. The
ratings are SARIF levels, so a consumer can adopt them directly, remap them, or
ignore them and apply its own model -- what a badly configured header is worth
to a particular site is not something this package can know.
"""

import collections

Finding = collections.namedtuple("Finding", "header code message")


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
    "csd-unquoted": "error",
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
    "csd-empty": "warning",
    "csd-unknown-type": "warning",
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
