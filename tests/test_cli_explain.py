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

import re

import pytest

from http_security_test import FINDING_SEVERITY, MESSAGES
from http_security_test.cli import main


def test_explain_one_code_prints_its_level_and_template(capsys):
    assert main(["explain", "csp-unsafe-inline"]) == 0
    out = capsys.readouterr().out
    assert "csp-unsafe-inline" in out
    assert FINDING_SEVERITY["csp-unsafe-inline"] in out
    assert MESSAGES["csp-unsafe-inline"] in out


def test_explain_with_no_arguments_lists_every_code(capsys):
    # Each code's block is no longer exactly one line -- consequences and
    # reference links can add more -- so the invariant worth pinning is the
    # head line of each block: one per code, no more, no fewer.
    assert main(["explain"]) == 0
    out = capsys.readouterr().out
    listed = re.findall(r"^(\S+)\s+(?:error|warning|note)\s", out, re.MULTILINE)
    assert listed == sorted(FINDING_SEVERITY)
    for code in FINDING_SEVERITY:
        assert code in out


def test_explain_lists_codes_in_a_stable_order(capsys):
    main(["explain"])
    first = capsys.readouterr().out
    main(["explain"])
    assert capsys.readouterr().out == first


def test_explain_an_unknown_code_is_a_usage_error(capsys):
    assert main(["explain", "no-such-code"]) == 2
    assert "no-such-code" in capsys.readouterr().err


def test_explain_reports_unknown_codes_and_still_prints_known_ones(capsys):
    assert main(["explain", "csp-unsafe-inline", "no-such-code"]) == 2
    captured = capsys.readouterr()
    assert "csp-unsafe-inline" in captured.out
    assert "no-such-code" in captured.err


def test_explain_names_the_owning_header(capsys):
    """The header must be in the head line, not merely somewhere in the output.

    A prior version of this test asserted "Content-Security-Policy" in out,
    which the MDN URL printed later in the entry
    (.../Headers/Content-Security-Policy) also satisfies -- so deleting the
    header from the head line's format string entirely still passed. Anchor
    the assertion to the head line itself: code, level, header, in that order,
    nothing after the header but whitespace.
    """
    main(["explain", "csp-unsafe-inline"])
    out = capsys.readouterr().out
    assert re.search(
        r"^csp-unsafe-inline\s+error\s+Content-Security-Policy\s*$", out, re.MULTILINE
    )


def test_explain_lists_consequences_and_urls(capsys):
    main(["explain", "csp-unsafe-inline"])
    out = capsys.readouterr().out
    assert "xss" in out
    assert "https://cwe.mitre.org/data/definitions/79.html" in out
    assert "developer.mozilla.org" in out


def test_explain_says_nothing_about_consequences_when_there_are_none(capsys):
    main(["explain", "rt-invalid"])
    out = capsys.readouterr().out
    assert "consequences" not in out


def test_a_bare_target_is_a_usage_error_that_names_the_verb(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["example.com"])
    assert caught.value.code == 2
    assert "hst scan example.com" in capsys.readouterr().err


def test_an_unknown_verb_that_is_not_a_host_gets_the_ordinary_message(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["frobnicate"])
    assert caught.value.code == 2
    assert "did you mean" not in capsys.readouterr().err


def test_version_is_reported(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0
    assert capsys.readouterr().out.strip()
