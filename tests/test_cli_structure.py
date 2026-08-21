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

import ast
import pathlib
import subprocess
import sys

import http_security_test
from http_security_test import SEVERITIES
from http_security_test.cli import meta, options

PACKAGE = pathlib.Path(http_security_test.__file__).parent


def _imports_cli(path):
    """True if this module imports the cli subpackage, however spelled."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == "cli":
                return True
            if node.module is None and any(a.name == "cli" for a in node.names):
                return True
        elif isinstance(node, ast.Import):
            if any(a.name.split(".")[0] == "cli" for a in node.names):
                return True
    return False


def test_no_analyser_module_imports_the_cli():
    # The library's identity is that it never fetches. That survives only while
    # the dependency runs one way, so it is pinned rather than trusted.
    offenders = [p.name for p in sorted(PACKAGE.glob("*.py")) if _imports_cli(p)]
    assert offenders == []


def test_importing_the_library_does_not_import_the_cli():
    # A subprocess, because this session has already imported everything.
    probe = "import http_security_test, sys; print('http_security_test.cli' in sys.modules)"
    done = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert done.stdout.strip() == "False"


def test_the_console_entry_point_resolves():
    # pyproject points both scripts at this callable; a rename would break the
    # installed binary without breaking any other test.
    from http_security_test.cli import main

    assert callable(main)


def test_meta_levels_is_the_librarys_own_table_reversed():
    # text.LEVELS used to restate the library's SEVERITIES by hand, reversed
    # and unpinned -- nothing asserted the two agreed. meta.LEVELS must be
    # genuinely derived from SEVERITIES (a copy that had drifted would still
    # satisfy a set() comparison alone), so this checks both the membership
    # and the ascending order the index-comparison callers depend on.
    assert set(meta.LEVELS) == set(SEVERITIES)
    assert meta.LEVELS == tuple(reversed(SEVERITIES))
    # Ascending by severity: note is least severe, error the most.
    assert meta.LEVELS.index("note") < meta.LEVELS.index("warning") < meta.LEVELS.index(
        "error"
    )


def test_misplaced_target_examines_only_argv_zero():
    # misplaced_target() runs in main() BEFORE parse_args, so argparse has
    # not spoken yet and is not there to police what a pre-verb flag's value
    # means. The earlier implementation scanned past leading flags looking
    # for the first non-flag token, so a flag value containing a dot --
    # `--proxy http://127.0.0.1:8080` -- was mistaken for the stray host
    # argument and produced "did you mean: hst scan http://127.0.0.1:8080".
    # Only argv[0] may be examined: that is the one case the feature exists
    # for (`hst example.com`).
    assert (
        options.misplaced_target(["--proxy", "http://127.0.0.1:8080", "scan", "a.com"])
        is None
    )
    assert options.misplaced_target(["-o", "report.json", "scan", "x.com"]) is None


def test_the_draft_fetcher_is_gone():
    # scan.py was the throwaway `hst scan` replaces. Keeping both means two
    # answers to the same question and one of them rots. Anchored to this
    # file, not to the package, so it cannot pass vacuously against an
    # installed wheel.
    assert not (pathlib.Path(__file__).parent.parent / "scan.py").exists()
