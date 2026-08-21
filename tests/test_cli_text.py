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

import os
import pathlib

from http_security_test.cli import exchange, text

SNAPSHOT = pathlib.Path(__file__).parent / "cli_terminal_snapshot.txt"

FINDINGS = [
    {
        "header": "Content-Security-Policy",
        "code": "csp-missing",
        "level": "warning",
        "data": {},
        "message": "missing",
    },
    {
        "header": "Access-Control-Allow-Origin",
        "code": "acao-null",
        "level": "error",
        "data": {"origin": "null"},
        "message": "permits the null origin",
    },
    {
        "header": "X-DNS-Prefetch-Control",
        "code": "xdpc-nonstandard",
        "level": "note",
        "data": {},
        "message": "never standardised",
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
    # exchange.FAILURE_KINDS is (dns, refused, timeout, reset, tls, protocol,
    # other) -- timeout precedes reset there but follows it alphabetically,
    # so this pair is the one that tells sorted() apart from the declared
    # table.
    assert exchange.FAILURE_KINDS.index("timeout") < exchange.FAILURE_KINDS.index(
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
