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

"""The run document as text, for a terminal or for a `-o text:` file.

Returns a string rather than printing, so both callers share one path.

This module is the only place `--min-level` is applied, which is what keeps the
promise that files are complete: the terminal passes the operator's floor, and
the file writer always passes the lowest. Colour is likewise a terminal
property and never reaches a file.
"""

import collections
import json

from . import exchange, meta

# The library's SEVERITIES, reversed, so a floor is an index comparison.
# Lives in meta.py so options.py and commands.py can reach it without
# importing this renderer; re-exported here under the same name because
# every reference in this module predates the move.
LEVELS = meta.LEVELS

COLORS = {"error": "\033[31m", "warning": "\033[33m", "note": "\033[36m"}
RESET = "\033[0m"
BOLD = "\033[1m"

TABLES = ("security", "deprecated", "information", "caching")


def _paint(body, level, color):
    if not color:
        return body
    return "%s%s%s" % (COLORS.get(level, ""), body, RESET)


def _counted(counts):
    return ", ".join(
        "%d %s" % (counts[level], level) for level in reversed(LEVELS) if counts[level]
    )


def _header_lines(result, color):
    head = "=== %s ===" % result["target"]
    return [BOLD + head + RESET if color else head]


def _source_lines(source):
    lines = [
        "    %s %s   %s"
        % (source.get("status", ""), source.get("reason", ""), source["url"])
    ]
    for hop in source.get("hops", []):
        arrow = "->" if hop["followed"] else "-X"
        line = "    %s %s %s %s" % (hop["from"], hop["code"], arrow, hop["to"])
        if not hop["followed"]:
            line += "   (refused: %s)" % hop.get("refused", "scope")
        lines.append(line)
    return lines


def _finding_lines(report, color, codes, min_level):
    floor = LEVELS.index(min_level)
    findings = [
        f for f in report["response"]["findings"] if LEVELS.index(f["level"]) >= floor
    ]
    if not findings:
        return ["findings: none", ""]
    counts = collections.Counter(f["level"] for f in findings)
    lines = ["findings (%s):" % _counted(counts)]
    for finding in findings:
        # Padded before it is painted: %-8s counts the escape bytes as content,
        # so colouring first collapses the column to nothing.
        level = _paint("%-8s" % finding["level"], finding["level"], color)
        lines.append(
            "  %s %-34s %s"
            % (level, finding["header"], finding.get("message", finding["code"]))
        )
        if codes:
            lines.append(
                "           %s %s"
                % (finding["code"], json.dumps(finding.get("data", {})))
            )
    lines.append("")
    return lines


def _inventory_lines(report):
    lines = []
    inventory = report["response"].get("inventory", {})
    for table in TABLES:
        entries = inventory.get(table) or {}
        if not entries:
            continue
        lines.append("%s:" % table)
        for name, value in entries.items():
            for one in [value] if isinstance(value, str) else value:
                lines.append("  %s: %s" % (name, one))
        lines.append("")
    if inventory.get("missing"):
        lines.append("missing:")
        lines.extend("  %s" % name for name in inventory["missing"])
        lines.append("")
    return lines


def _summary_lines(document):
    results = document["results"]
    if len(results) < 2:
        return []
    counts = collections.Counter()
    failures = collections.Counter()
    for result in results:
        if result["outcome"] == "failed":
            failures[result["failure"]["kind"]] += 1
            continue
        for finding in result["report"]["response"]["findings"]:
            counts[finding["level"]] += 1
    lines = ["=== summary ===", "    %d results" % len(results)]
    if counts:
        lines.append("    findings: %s" % _counted(counts))
    if failures:
        # By exchange.FAILURE_KINDS, matching the counts above ordered by
        # severity -- not sorted(), which does not agree with that table
        # (e.g. "reset" would sort before "timeout" though the table has it
        # the other way round) and made the declared order a dead letter.
        lines.append(
            "    failures: %s"
            % ", ".join(
                "%d %s" % (failures[kind], kind)
                for kind in exchange.FAILURE_KINDS
                if failures[kind]
            )
        )
    lines.append("")
    return lines


def render(document, color=False, quiet=False, codes=False, min_level="note"):
    """The run document as text."""
    lines = []
    for result in document["results"]:
        lines.extend(_header_lines(result, color))
        if result["outcome"] == "failed":
            failure = result["failure"]
            lines.append("    %s: %s" % (failure["kind"], failure["message"]))
            lines.append("")
            continue
        lines.extend(_source_lines(result["source"]))
        lines.append("")
        lines.extend(_finding_lines(result["report"], color, codes, min_level))
        if not quiet:
            lines.extend(_inventory_lines(result["report"]))
    lines.extend(_summary_lines(document))
    return "\n".join(lines) + "\n"
