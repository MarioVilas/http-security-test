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

"""Where output goes and in what shape.

The terminal always shows the run; `-o` writes files. Several formats can be
written from one run, which is why the pipeline materialises one plain-data
document and renders it repeatedly rather than letting a renderer walk live
objects.
"""

import collections
import json
import os

from . import text


class UsageError(Exception):
    """A command line the tool cannot act on. main() turns this into exit 2."""


Format = collections.namedtuple("Format", "name extension")

# INVARIANT: no single-letter format name, ever. resolve() treats the text
# before the first colon as a format when it names one, so a one-letter name
# would make `-o C:\out.json` ambiguous on Windows.
#
# Insertion order is the order -oA writes files in, and it is contractual.
FORMATS = collections.OrderedDict(
    [
        ("text", Format("text", ".txt")),
        ("json", Format("json", ".json")),
    ]
)

# Named so a user gets "not implemented yet" rather than "invalid choice".
RESERVED = {"sarif": ".sarif", "ndjson": ".ndjson"}

KNOWN = tuple(FORMATS) + tuple(sorted(RESERVED))

EXTENSIONS = {
    ".txt": "text",
    ".text": "text",
    ".json": "json",
    ".sarif": "sarif",
    ".ndjson": "ndjson",
}


def resolve(spec):
    """(format, path) for one -o argument.

    Two ways to say it, tried in order: an explicit `FORMAT:PATH`, or a path
    whose extension names a format. The explicit form only fires when the text
    before the first colon really is a format name, which is what keeps
    `C:\\out.json` working.
    """
    head, separator, rest = spec.partition(":")
    if separator and head.lower() in KNOWN:
        name, path = head.lower(), rest
    else:
        # An unrecognized head is a path, not a mistake: the same rule that
        # keeps `C:\out.json` safe applies to `nope:out.json`, and no
        # syntactic test can tell a mistyped format prefix apart from a bare
        # filename that happens to contain a colon.
        name, path = EXTENSIONS.get(os.path.splitext(spec)[1].lower()), spec
    if name is None:
        raise UsageError(
            "cannot tell what format %r should be: write FORMAT:PATH (one of %s) "
            "or give the file a known extension (%s)"
            % (spec, ", ".join(FORMATS), ", ".join(sorted(EXTENSIONS)))
        )
    if not path:
        raise UsageError("no path in %r" % spec)
    if name in RESERVED:
        raise UsageError("the %s output format is not implemented yet" % name)
    return name, path


def all_outputs(prefix):
    """Every implemented format, for -oA."""
    return [(fmt.name, prefix + fmt.extension) for fmt in FORMATS.values()]


def _write_json(document, stream):
    json.dump(document, stream, indent=2)
    stream.write("\n")


def _write_text(document, stream):
    # A file is evidence, so it is the complete rendering: no colour, no
    # --min-level floor, inventories and codes included. Terminal flags shape
    # the terminal only.
    stream.write(text.render(document, color=False, quiet=False, codes=True))


_WRITERS = {"json": _write_json, "text": _write_text}


def write(name, document, stream):
    """Render the document to an open stream in the named format."""
    _WRITERS[name](document, stream)
