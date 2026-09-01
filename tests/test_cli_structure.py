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

# Lowest first. A module may import its own layer and anything below it.
LAYERS = ("core", "adaptors", "formats", "cli")

CORE = (
    "findings",
    "catalog",
    "message",
    "references",
    "csp",
    "hsts",
    "isolation",
    "policies",
    "legacy",
    "response",
    "reporting",
    "exchange",
)


def _layer_of(name):
    if name in CORE:
        return "core"
    return name if name in LAYERS else "core"


def _self_head(dotted):
    """The first path component after this package's own name.

    `import http_security_test.cli` and `from http_security_test.cli import
    x` both carry `http_security_test.cli` as the dotted name being
    resolved; this pulls out `cli`, the part _layer_of() knows how to
    classify. None for a dotted name that does not name this package at all
    (any stdlib or third-party import) -- that is not this package's own
    layering to police, and _layer_of()'s own fallback treats it as "core"
    wherever it is asked about, which can never trigger a violation since
    core is the lowest layer.
    """
    parts = dotted.split(".")
    if len(parts) > 1 and parts[0] == http_security_test.__name__:
        return parts[1]
    return None


def _imported_layers(path):
    """The layers this module imports from, by first path component.

    Catches both relative imports (`from .cli import x`, `from . import
    cli`) and absolute ones that spell the package name out
    (`import http_security_test.cli`, `from http_security_test.cli import
    x`, `from http_security_test import cli`). A test that only inspected
    `node.level` would miss every absolute form -- exactly the gap that let
    a single-name grep stand in for this rule before "adaptors" existed as a
    second layer worth naming.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                # from .foo import bar / from . import foo
                head = (node.module or "").split(".")[0]
                if head:
                    found.add(_layer_of(head))
                else:
                    found.update(_layer_of(a.name) for a in node.names)
            elif node.module:
                # from http_security_test.foo import bar
                head = _self_head(node.module)
                if head:
                    found.add(_layer_of(head))
                elif node.module == http_security_test.__name__:
                    # from http_security_test import foo
                    found.update(_layer_of(a.name) for a in node.names)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                # import http_security_test.foo
                head = _self_head(alias.name)
                if head:
                    found.add(_layer_of(head))
    return found


def _imports_cli(path):
    """True if this module imports the cli subpackage, however spelled.

    A narrow wrapper around _imported_layers() rather than its own AST walk,
    so there is exactly one place that decides what an import "means" for
    layering purposes -- a second, independently-written detector is how the
    absolute-import gap this module's history records got missed the first
    time.
    """
    return "cli" in _imported_layers(path)


def test_no_analyser_module_imports_the_cli():
    # A narrower echo of test_imports_only_ever_run_downhill, kept because it
    # names the exact invariant CLAUDE.md's opening paragraph states in
    # isolation: nothing outside cli/ may import cli, whether the importer
    # lives in core or in adaptors, and however the import is spelled.
    offenders = [p.name for p in sorted(PACKAGE.glob("*.py")) if _imports_cli(p)]
    assert offenders == []


def test_imports_only_ever_run_downhill():
    # Replaces the single-name check above with the rule it was an instance
    # of. It now also catches a format parser reaching into adaptors, or an
    # adaptor reaching into cli, which the single-name check could not see
    # because neither existed as a layer when it was written.
    offenders = []
    for path in sorted(PACKAGE.glob("*.py")):
        if path.stem == "__init__":
            continue
        mine = LAYERS.index(_layer_of(path.stem))
        for other in _imported_layers(path):
            if LAYERS.index(other) > mine:
                offenders.append("%s -> %s" % (path.name, other))
    assert offenders == []


def test_importing_the_library_does_not_import_the_adaptors_or_the_cli():
    # __init__ exports the core only, which is what keeps the base import
    # cheap and dependency-free. A subprocess, because this session has
    # already imported everything.
    probe = (
        "import http_security_test, sys; "
        "print(sorted(m for m in ('http_security_test.cli', "
        "'http_security_test.adaptors') if m in sys.modules))"
    )
    done = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=True)
    assert done.stdout.strip() == "[]"


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
    assert meta.LEVELS.index("note") < meta.LEVELS.index("warning") < meta.LEVELS.index("error")


def test_misplaced_target_examines_only_argv_zero():
    # misplaced_target() runs in main() BEFORE parse_args, so argparse has
    # not spoken yet and is not there to police what a pre-verb flag's value
    # means. The earlier implementation scanned past leading flags looking
    # for the first non-flag token, so a flag value containing a dot --
    # `--proxy http://127.0.0.1:8080` -- was mistaken for the stray host
    # argument and produced "did you mean: hst scan http://127.0.0.1:8080".
    # Only argv[0] may be examined: that is the one case the feature exists
    # for (`hst example.com`).
    assert options.misplaced_target(["--proxy", "http://127.0.0.1:8080", "scan", "a.com"]) is None
    assert options.misplaced_target(["-o", "report.json", "scan", "x.com"]) is None


def test_the_draft_fetcher_is_gone():
    # scan.py was the throwaway `hst scan` replaces. Keeping both means two
    # answers to the same question and one of them rots. Anchored to this
    # file, not to the package, so it cannot pass vacuously against an
    # installed wheel.
    assert not (pathlib.Path(__file__).parent.parent / "scan.py").exists()
