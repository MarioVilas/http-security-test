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

import copy
import os
import pathlib

from http_security_test import cookies
from http_security_test.cli import outcome, text

SNAPSHOT = pathlib.Path(__file__).parent / "cli_terminal_snapshot.txt"

FINDINGS = [
    {
        "header": "Content-Security-Policy",
        "code": "csp-missing",
        "level": "warning",
        "data": {},
        "message": "missing",
        "consequences": ["xss"],
    },
    {
        "header": "Access-Control-Allow-Origin",
        "code": "acao-null",
        "level": "error",
        "data": {"origin": "null"},
        "message": "permits the null origin",
        "consequences": ["cors-data-theft"],
    },
    {
        # Deliberately keeps no consequences: xdpc-nonstandard really maps to
        # (), so this is the negative case rather than an oversight.
        "header": "X-DNS-Prefetch-Control",
        "code": "xdpc-nonstandard",
        "level": "note",
        "data": {},
        "message": "never standardised",
        "consequences": [],
    },
]

DOCUMENT = {
    "schema": 1,
    "tool": {"name": "http-security-test", "version": "0.1.0"},
    "run": {"started": "2026-08-21T12:09:03Z", "finished": "2026-08-21T12:09:07Z"},
    "results": [
        {
            "outcome": "ok",
            "target": "example.com",
            "source": {
                "kind": "live",
                "url": "https://www.example.com/",
                "status": 200,
                "reason": "OK",
                "hops": [
                    {
                        "from": "http://example.com/",
                        "code": 301,
                        "to": "https://example.com/",
                        "followed": True,
                    },
                    {
                        "from": "https://example.com/",
                        "code": 302,
                        "to": "https://login.example.net/",
                        "followed": False,
                        "refused": "scope",
                    },
                ],
            },
            "report": {
                "response": {
                    "findings": FINDINGS,
                    "inventory": {
                        "security": {"Strict-Transport-Security": "max-age=31536000"},
                        "missing": ["Content-Security-Policy"],
                        "deprecated": {},
                        "information": {"Server": "nginx"},
                        "caching": {},
                    },
                }
            },
        },
        {
            "outcome": "failed",
            "target": "down.example.com",
            "failure": {"kind": "dns", "message": "Name or service not known"},
        },
    ],
}


def _document_with_cookies(rows):
    """The module's DOCUMENT with a cookies inventory spliced in."""
    document = copy.deepcopy(DOCUMENT)
    document["results"][0]["report"]["response"]["inventory"]["cookies"] = rows
    return document


def test_the_cookies_table_renders_one_line_per_cookie():
    rows = [
        cookies.cookie_as_dict(
            cookies.parse_set_cookie("sid=abc; Secure; HttpOnly; SameSite=Strict")
        ),
        cookies.cookie_as_dict(cookies.parse_set_cookie("lang=en")),
    ]
    out = text.render(_document_with_cookies(rows))
    assert "cookies:" in out
    assert "sid" in out and "lang" in out


def test_an_unjudged_cookie_says_so():
    rows = [cookies.cookie_as_dict(cookies.parse_set_cookie("AWSALB=x"))]
    out = text.render(_document_with_cookies(rows))
    assert "not judged" in out


def test_no_cookies_table_when_the_response_sets_none():
    assert "cookies:" not in text.render(_document_with_cookies([]))


def test_the_terminal_never_prints_a_cookie_value():
    # The JSON carries values in full and deliberately -- this package does
    # not redact, and redaction before anything reaches a report is the
    # consumer's job. The TERMINAL is a summary, so a value there is noise.
    # This test exists because every other cookie assertion in this file is a
    # substring presence check, and all of them keep passing if a future edit
    # appends row["value"] to the flags list in _inventory_lines.
    rows = [
        cookies.cookie_as_dict(cookies.parse_set_cookie(
            "sid=UNIQUE-SENTINEL-VALUE-9f3a; Secure; HttpOnly; SameSite=Strict"
        )),
        cookies.cookie_as_dict(
            cookies.parse_set_cookie("AWSALB=SENTINEL-ROUTING-7b21")
        ),
    ]
    out = text.render(_document_with_cookies(rows))
    # the names and attributes are wanted...
    assert "sid" in out and "AWSALB" in out
    assert "SameSite=Strict" in out
    # ...the values are not, judged or unjudged
    assert "UNIQUE-SENTINEL-VALUE-9f3a" not in out
    assert "SENTINEL-ROUTING-7b21" not in out


def test_render_returns_a_string_ending_in_a_newline():
    out = text.render(DOCUMENT)
    assert isinstance(out, str)
    assert out.endswith("\n")


def test_plain_render_has_no_escape_sequences():
    assert "\033" not in text.render(DOCUMENT)


def test_colour_paints_only_when_asked():
    assert "\033" in text.render(DOCUMENT, color=True)


def test_a_refused_hop_prints_its_reason():
    out = text.render(DOCUMENT)
    assert "login.example.net" in out
    assert "refused: scope" in out


def test_a_failed_target_prints_its_kind():
    out = text.render(DOCUMENT)
    assert "down.example.com" in out
    assert "dns" in out


def test_quiet_drops_the_inventories_but_keeps_findings():
    out = text.render(DOCUMENT, quiet=True)
    assert "permits the null origin" in out
    assert "findings" in out
    assert "information:" not in out
    assert "Server: nginx" not in out
    assert "missing:" not in out


def test_codes_annotates_each_finding_with_its_code_and_data():
    out = text.render(DOCUMENT, codes=True)
    assert "acao-null" in out
    assert '{"origin": "null"}' in out


def test_a_finding_line_names_its_consequences():
    out = text.render(DOCUMENT)
    assert "[xss]" in out
    assert "[cors-data-theft]" in out


def test_a_finding_with_no_consequence_gets_no_brackets():
    line = next(
        l for l in text.render(DOCUMENT).splitlines() if "X-DNS-Prefetch-Control" in l
    )
    assert "[" not in line


def test_a_finding_missing_the_key_entirely_still_renders():
    # A caller on the old schema, or a hand-built document. .get() not [].
    stale = {"header": "X-Frame-Options", "code": "xfo-missing",
             "level": "warning", "data": {}, "message": "missing"}
    assert "X-Frame-Options" in "\n".join(text._finding_lines(
        {"response": {"findings": [stale]}}, False, False, "note"))


def test_min_level_filters_the_terminal():
    out = text.render(DOCUMENT, min_level="error")
    assert "permits the null origin" in out
    assert "never standardised" not in out


def test_min_level_note_shows_everything():
    out = text.render(DOCUMENT, min_level="note")
    assert "never standardised" in out


def test_more_than_one_result_gets_a_summary():
    out = text.render(DOCUMENT)
    assert "summary" in out
    assert "1 dns" in out


def test_a_single_result_gets_no_summary():
    single = dict(DOCUMENT, results=DOCUMENT["results"][:1])
    assert "summary" not in text.render(single)


def test_the_summary_orders_failure_kinds_by_failure_kinds_not_alphabetically():
    # outcome.FAILURE_KINDS is (dns, refused, timeout, reset, tls, protocol,
    # other) -- timeout precedes reset there but follows it alphabetically,
    # so this pair is the one that tells sorted() apart from the declared
    # table.
    assert outcome.FAILURE_KINDS.index("timeout") < outcome.FAILURE_KINDS.index(
        "reset"
    )
    document = {
        "schema": 1,
        "tool": {"name": "http-security-test", "version": "0.1.0"},
        "run": {"started": "2026-08-21T12:00:00Z", "finished": "2026-08-21T12:00:01Z"},
        "results": [
            {
                "outcome": "failed",
                "target": "reset.example.com",
                "failure": {"kind": "reset", "message": "connection reset"},
            },
            {
                "outcome": "failed",
                "target": "timeout.example.com",
                "failure": {"kind": "timeout", "message": "timed out"},
            },
        ],
    }
    out = text.render(document)
    summary = next(
        line for line in out.splitlines() if line.strip().startswith("failures:")
    )
    assert summary.index("timeout") < summary.index("reset")


def test_render_is_deterministic():
    assert text.render(DOCUMENT) == text.render(DOCUMENT)


def test_cli_snapshot_matches():
    """Prose nothing else reads, so an edit here is invisible without a pin.

    Regenerate deliberately and read the diff:
        UPDATE_CLI_SNAPSHOT=1 python -m pytest tests/ -k cli_snapshot
    """
    produced = text.render(DOCUMENT, codes=True)
    if os.environ.get("UPDATE_CLI_SNAPSHOT"):
        SNAPSHOT.write_text(produced, encoding="utf-8")
    assert SNAPSHOT.read_text(encoding="utf-8") == produced


# --- final review, M2 and M3: the cookies table's two wrong renderings ------

def test_a_nameless_cookie_gets_the_same_placeholder_the_catalog_gives_it():
    # An empty name is legal (rfc6265bis 5.2 step 3). Task 6 gave it a
    # readable subject in catalog.py; the inventory renderer never got the
    # same fix and printed 28 blanks where a name belongs.
    rows = [cookies.cookie_as_dict(cookies.parse_set_cookie("=__Host-sid=x"))]
    out = text.render(_document_with_cookies(rows))
    assert "a nameless cookie" in out
    assert "\n                               " not in out


def test_a_cookie_with_only_non_security_attributes_is_not_called_bare():
    # `flags` inspects five attributes, so Path and Expires render as "no
    # attributes" -- factually wrong, and it hid the persistence on exactly
    # the infrastructure cookies whose findings are suppressed.
    rows = [
        cookies.cookie_as_dict(cookies.parse_set_cookie(
            "AWSALB=x; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT"
        ))
    ]
    out = text.render(_document_with_cookies(rows))
    assert "no security attributes" in out
    assert "no attributes\n" not in out
