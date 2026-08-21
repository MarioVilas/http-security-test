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

from http_security_test.cli import scope

MATCH_CASES = [
    # (pattern, hostname, expected)
    ("*", "anything.example", True),
    ("*", "", False),
    ("example.com", "example.com", True),
    ("example.com", "www.example.com", False),
    ("*.example.com", "www.example.com", True),
    ("*.example.com", "a.b.example.com", True),
    # The apex is deliberately NOT matched by the wildcard: keeping them
    # disjoint is what gives "subdomains but not the apex" a spelling.
    ("*.example.com", "example.com", False),
    # A bare suffix test would wrongly admit these two.
    ("*.example.com", "notexample.com", False),
    ("*.example.com", "evilexample.com", False),
    ("EXAMPLE.com", "example.COM", True),
    ("example.com.", "example.com", True),
    ("example.com", "example.com.", True),
    ("example.com", "", False),
    ("example.com", None, False),
]


@pytest.mark.parametrize("pattern,hostname,expected", MATCH_CASES)
def test_matches(pattern, hostname, expected):
    assert scope.matches(pattern, hostname) is expected


def test_derive_gives_each_target_its_apex_and_its_subdomains():
    assert scope.derive(["example.com"]) == ("example.com", "*.example.com")


def test_derive_deduplicates_and_keeps_order():
    assert scope.derive(["b.test", "a.test", "b.test"]) == (
        "b.test",
        "*.b.test",
        "a.test",
        "*.a.test",
    )


def test_the_derived_default_refuses_a_sibling_public_suffix():
    # DECISION R-1: this is the case a label-counting sibling rule would have
    # allowed, across 195 ccTLDs. The whole ruling rests on it staying refused.
    patterns = scope.derive(["example.co.uk"])
    assert scope.allows(patterns, "www.example.co.uk") is True
    assert scope.allows(patterns, "evil.co.uk") is False


def test_an_explicit_scope_replaces_the_derived_default():
    patterns = scope.resolve(["*.partner.test"], ["example.com"])
    assert scope.allows(patterns, "api.partner.test") is True
    assert scope.allows(patterns, "www.example.com") is False


def test_a_target_host_stays_in_scope_even_when_scope_is_explicit():
    # Without this exception, --scope '*.partner.test' would silently forbid a
    # redirect back to the host you actually asked to scan.
    patterns = scope.resolve(["*.partner.test"], ["example.com"])
    assert scope.allows(patterns, "example.com") is True


def test_scope_is_a_union_across_targets():
    patterns = scope.resolve([], ["a.test", "b.test"])
    assert scope.allows(patterns, "b.test") is True
    assert scope.allows(patterns, "www.b.test") is True


def test_star_is_how_you_follow_anything():
    assert scope.allows(scope.resolve(["*"], ["a.test"]), "elsewhere.example")


def test_banner_says_when_the_scope_was_derived():
    assert "derived from targets" in scope.banner(("a.test",), True)
    assert "derived from targets" not in scope.banner(("a.test",), False)


def test_a_pattern_that_names_a_real_file_is_flagged(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "www.example.com").write_text("")
    assert scope.looks_shell_expanded(["www.example.com"]) == ["www.example.com"]
    assert scope.looks_shell_expanded(["*.example.com"]) == []
