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

import io
import json

import pytest

from http_security_test.cli import writers

RESOLVE_CASES = [
    ("json:out.json", ("json", "out.json")),
    ("text:notes.txt", ("text", "notes.txt")),
    ("json:-", ("json", "-")),
    ("report.json", ("json", "report.json")),
    ("notes.txt", ("text", "notes.txt")),
    ("notes.text", ("text", "notes.text")),
    ("REPORT.JSON", ("json", "REPORT.JSON")),
    # The Windows case: C is not a format name, so the colon is not a separator
    # and the extension decides.
    (r"C:\evidence\out.json", ("json", r"C:\evidence\out.json")),
    ("json:C:\\evidence\\out.json", ("json", "C:\\evidence\\out.json")),
    # An unrecognized head is a path, not an error: the same rule that keeps
    # `C:\out.json` safe applies here too, and no syntactic test can tell a
    # mistyped format prefix apart from a bare filename that contains a
    # colon -- `nope:out.json` and `note:doc.json` are structurally identical
    # despite one looking like a typo and the other looking deliberate.
    ("nope:out.json", ("json", "nope:out.json")),
    ("note:doc.json", ("json", "note:doc.json")),
    ("/home/user/my:file.json", ("json", "/home/user/my:file.json")),
    ("./weird:name.txt", ("text", "./weird:name.txt")),
]


@pytest.mark.parametrize("spec,expected", RESOLVE_CASES)
def test_resolve(spec, expected):
    assert writers.resolve(spec) == expected


@pytest.mark.parametrize("spec", ["-", "out", "out.csv", "json:", "nope:out"])
def test_unresolvable_specs_are_usage_errors(spec):
    with pytest.raises(writers.UsageError):
        writers.resolve(spec)


@pytest.mark.parametrize("spec", ["sarif:out.sarif", "out.sarif", "out.ndjson"])
def test_reserved_formats_say_not_implemented_rather_than_invalid(spec):
    with pytest.raises(writers.UsageError) as caught:
        writers.resolve(spec)
    assert "not implemented" in str(caught.value)


def test_the_format_tables_agree():
    # FORMATS, RESERVED, EXTENSIONS and _WRITERS must all name the same
    # formats. Forgetting one when promoting sarif from RESERVED to FORMATS
    # would make write() raise KeyError mid -oA, after .txt is already on
    # disk -- this is what makes that KeyError unreachable while the tables
    # agree.
    assert set(writers._WRITERS) == set(writers.FORMATS)
    for name, fmt in writers.FORMATS.items():
        assert writers.EXTENSIONS.get(fmt.extension) == name
    for name, extension in writers.RESERVED.items():
        assert writers.EXTENSIONS.get(extension) == name


def test_no_single_letter_format_name():
    # This invariant is what makes `C:\out.json` unambiguous. A one-letter
    # format would make the drive letter look like a format prefix.
    for name in writers.KNOWN:
        assert len(name) > 1, "%r would make a Windows drive letter ambiguous" % name


def test_all_outputs_covers_every_implemented_format_in_a_stable_order():
    assert writers.all_outputs("run") == [("text", "run.txt"), ("json", "run.json")]
    assert writers.all_outputs("run") == writers.all_outputs("run")


def test_all_outputs_omits_reserved_formats():
    paths = [path for _, path in writers.all_outputs("run")]
    assert not any(path.endswith(".sarif") for path in paths)


def test_json_writer_emits_the_document_unchanged():
    document = {"schema": 1, "results": []}
    stream = io.StringIO()
    writers.write("json", document, stream)
    assert json.loads(stream.getvalue()) == document


def test_text_writer_never_emits_colour():
    document = {
        "results": [
            {
                "outcome": "failed",
                "target": "a.test",
                "failure": {"kind": "dns", "message": "nope"},
            }
        ]
    }
    stream = io.StringIO()
    writers.write("text", document, stream)
    assert "\033" not in stream.getvalue()
