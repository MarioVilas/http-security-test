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

"""Command-line interface for the analysis engine.

Imports the analyser and is imported by nothing: `import http_security_test`
still pulls in no network code, and the library still never fetches anything.
A test pins that direction.
"""

import sys

from . import options


def main(argv=None):
    """Parse argv, run the verb, return the exit code.

    Returns rather than exits so the whole CLI is testable in-process. argparse
    still raises SystemExit(2) on a usage error, which is the contract.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = options.build_parser()
    hint = options.misplaced_target(argv)
    if hint:
        parser.error(hint)  # exits 2, which is the contract for a usage error
    args = parser.parse_args(argv)
    return args.run(args)
