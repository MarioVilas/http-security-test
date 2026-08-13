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

"""Who may reach into this document, and what it may embed.

COOP, COEP and CORP work as a set: cross-origin isolation needs two of them
agreeing, so each is judged in the light of the others. CORS lives here too --
Access-Control-Allow-Origin answers the same question from the other side.
"""

from .findings import Finding
from .message import _sole_value

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
