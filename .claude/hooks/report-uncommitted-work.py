#!/usr/bin/env python3

"""Tell a starting session which uncommitted changes are not its own.

A SessionStart hook. At session start this session has edited nothing, so every
uncommitted change in the tree belongs to somebody else -- the human, or one of
the other agents working against this same checkout. That makes the warning a
fact derived from the tree rather than a claim anybody had to remember to file,
which is the whole point:

  * it cannot go stale, because it is recomputed every time;
  * it needs no cleanup, so a crashed session leaves nothing behind;
  * it needs no cooperation from the other sessions.

An earlier design had each session declare the files it intended to touch. That
was dropped: a session cannot know its own blast radius up front (this one began
as one analyser and ended up in seven files), a shared declarations file is
itself a concurrent-write hotspot, and a killed session's declaration would
never be removed.

Silent when the tree is clean, so it costs a starting session nothing to read.
"""

import json
import os
import subprocess
import sys

# Enough to see the shape of what somebody else is doing without burying the
# rest of the session-start context.
MAX_LISTED = 20


PREAMBLE = """This working tree already carried uncommitted changes before this session \
started, so none of them are yours:

{listing}
Sessions run in parallel against one shared checkout, and the human keeps their \
own work here too. Treat every path above as someone else's until you learn \
otherwise:

- Prefer Edit over Write. Edit fails loudly on a file that moved under you; a \
Write can bury it.
- Never overwrite one of these from the shell -- `sed -i`, `> file`, `cp` or \
`mv` onto it. Those skip the read-state check that Edit and Write do, which is \
where the tools' protection actually lives.
- Never revert one to make your own change apply. See CLAUDE.md: no git command \
that discards working-tree content, for any reason, including undoing your own \
edit."""


def _porcelain(project_dir):
    """Every uncommitted path, or None when git cannot answer."""
    try:
        finished = subprocess.run(
            ["git", "-C", project_dir, "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,  # a non-zero exit is an answer here, not an error
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if finished.returncode != 0:
        return None  # not a repository, or git is unwell; either way, say nothing
    return [line for line in finished.stdout.splitlines() if line.strip()]


def main():
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    changes = _porcelain(project_dir)
    if not changes:
        return 0  # clean tree, or no answer: nothing worth saying

    shown = changes[:MAX_LISTED]
    listing = "".join("  %s\n" % line for line in shown)
    if len(changes) > MAX_LISTED:
        listing += "  ...and %d more\n" % (len(changes) - MAX_LISTED)

    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": PREAMBLE.format(listing=listing),
            }
        },
        sys.stdout,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
