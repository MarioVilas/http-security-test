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

"""What the CLI's own run produced, as distinct from what crossed the wire.

`Hop`'s `followed` and `refused` are --scope outcomes: what this tool chose to
do, not facts about HTTP. Its `origin`, `code` and `destination` ARE wire facts
and are derivable from a list of exchanges, which is why the analyser needs no
hop type of its own to gain chain analysis later.

cli/exchange.py is gone. It used to hold url, status, reason, headers and the
raw blobs, which are message facts and now live in the analyser's own
`Exchange`, built by `cli/live.py`. What is left once a message's own facts
move there is `Run`: the facts about the *fetch* rather than about the
message it produced -- which target was asked for, what kind of source
answered, and the redirect chain it took to get there. `cli/run.py`'s
`analysed()` reads `kind`, `target`, `url`, `status`, `reason` and `hops` off
whatever it is handed; a `Run` supplies exactly those names.
"""

import collections

Hop = collections.namedtuple("Hop", "origin code destination followed refused", defaults=(True, None))

Failure = collections.namedtuple("Failure", "target kind message")

# Observable failure kinds. Not "retryable": that is a prediction, and only the
# kind is a fact. A calling tool reads these and decides for itself.
FAILURE_KINDS = ("dns", "refused", "timeout", "reset", "tls", "protocol", "other")

# `url`, `status` and `reason` duplicate what the analyser's Response often
# already implies, but a source may answer with no representation at all (a
# redirect refused before follow, a HEAD with an empty body) and the run still
# happened -- these are facts about the fetch, kept apart from facts about the
# message so run.analysed() has something to read even when there is no
# message worth analysing.
Run = collections.namedtuple("Run", "kind target url status reason hops", defaults=((),))
