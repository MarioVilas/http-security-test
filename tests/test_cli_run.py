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

import datetime

from http_security_test.cli import exchange, run

REPORT = {"response": {"findings": [], "inventory": {"security": {}, "missing": []}}}


def _exchange(**kwargs):
    fields = {
        "kind": "live",
        "target": "example.com",
        "url": "https://www.example.com/",
        "status": 200,
        "reason": "OK",
        "headers": {},
    }
    fields.update(kwargs)
    return exchange.Exchange(**fields)


def test_timestamp_is_utc_with_a_trailing_z():
    moment = datetime.datetime(2026, 8, 21, 12, 9, 3, tzinfo=datetime.timezone.utc)
    assert run.timestamp(moment) == "2026-08-21T12:09:03Z"


def test_an_analysed_result_quotes_the_library_document_verbatim():
    result = run.analysed(_exchange(), REPORT)
    assert result["report"] is REPORT
    assert "url" not in result["report"]


def test_an_analysed_result_names_the_target_the_operator_typed():
    result = run.analysed(_exchange(target="example.com"), REPORT)
    assert result["target"] == "example.com"
    assert result["source"]["url"] == "https://www.example.com/"


def test_the_source_carries_a_kind_discriminator():
    assert run.analysed(_exchange(), REPORT)["source"]["kind"] == "live"


def test_hops_serialise_with_wire_names():
    hops = (exchange.Hop("http://a/", 301, "https://a/"),)
    source = run.analysed(_exchange(hops=hops), REPORT)["source"]
    assert source["hops"] == [
        {"from": "http://a/", "code": 301, "to": "https://a/", "followed": True}
    ]


def test_a_refused_hop_records_why():
    hops = (exchange.Hop("https://a/", 302, "https://b/", False, "scope"),)
    hop = run.analysed(_exchange(hops=hops), REPORT)["source"]["hops"][0]
    assert hop["followed"] is False
    assert hop["refused"] == "scope"


def test_hops_are_present_even_when_empty():
    # Derived content is always there; only passthrough is conditional.
    assert run.analysed(_exchange(), REPORT)["source"]["hops"] == []


def test_a_failed_result_carries_the_kind_and_no_report():
    bad = exchange.Failure("down.example", "dns", "Name or service not known")
    result = run.failed(bad)
    assert result["outcome"] == "failed"
    assert result["failure"] == {"kind": "dns", "message": "Name or service not known"}
    assert "report" not in result


def test_failures_and_successes_share_one_results_list():
    document = run.run_document(
        [
            run.analysed(_exchange(), REPORT),
            run.failed(exchange.Failure("down.example", "dns", "nope")),
        ],
        "2026-08-21T12:09:03Z",
        "2026-08-21T12:09:07Z",
    )
    assert [r["outcome"] for r in document["results"]] == ["ok", "failed"]


def test_the_document_is_versioned_and_names_the_tool():
    document = run.run_document([], "a", "b")
    assert document["schema"] == run.SCHEMA_VERSION
    assert document["tool"]["name"] == "http-security-test"
    assert document["tool"]["version"]
    assert document["run"] == {"started": "a", "finished": "b"}


def test_the_document_is_json_serialisable_without_an_encoder():
    import json

    hops = (exchange.Hop("https://a/", 302, "https://b/", False, "scope"),)
    document = run.run_document(
        [run.analysed(_exchange(hops=hops), REPORT)], "a", "b"
    )
    assert json.loads(json.dumps(document)) == document
