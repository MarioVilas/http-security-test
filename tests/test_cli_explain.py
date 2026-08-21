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
    assert main(["explain"]) == 0
    out = capsys.readouterr().out
    assert len(out.strip().splitlines()) == len(FINDING_SEVERITY)
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
