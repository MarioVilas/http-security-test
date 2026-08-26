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

from http_security_test.cli import outcome


def test_a_hop_defaults_to_followed_with_no_reason():
    hop = outcome.Hop("http://a/", 301, "https://a/")
    assert hop.followed is True
    assert hop.refused is None


def test_a_refused_hop_carries_its_reason():
    hop = outcome.Hop("https://a/", 302, "https://b/", False, "scope")
    assert (hop.followed, hop.refused) == (False, "scope")


def test_a_failure_names_the_target_and_the_kind():
    bad = outcome.Failure("a.example", "dns", "Name or service not known")
    assert bad.kind in outcome.FAILURE_KINDS
