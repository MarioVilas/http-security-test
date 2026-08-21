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

"""Who this tool says it is.

A shared leaf: `options` needs the version for `--version` and for the default
User-Agent, `run` needs it for the document's `tool` block, and neither should
have to import the other to get it.
"""

from .. import SEVERITIES

TOOL_NAME = "http-security-test"

# The library's own severity table, reversed so a floor is a plain index
# comparison ("at least this severe" becomes "index >= floor", which only
# holds ascending). Deriving it from SEVERITIES rather than restating the
# tuple is what keeps the CLI's vocabulary from drifting out of step with the
# library's: text.py and commands.py both compare finding levels against this
# table, and a copy that silently disagreed with SEVERITIES would raise
# ValueError -- a traceback rather than a wrong number -- the day the library
# grows a fourth level.
LEVELS = tuple(reversed(SEVERITIES))


def tool_version():
    """The installed distribution's version, or a marker when running from source.

    Read from the installed metadata rather than duplicated in a `__version__`,
    so `pyproject.toml` stays the one place the number lives.
    """
    try:
        import importlib.metadata

        return importlib.metadata.version(TOOL_NAME)
    except Exception:
        return "0+source"


USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) %s/%s" % (TOOL_NAME, tool_version())
