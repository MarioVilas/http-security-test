#!/usr/bin/env python3

"""Refuse any git command that could destroy work, in any checkout.

A PreToolUse hook on Bash. It reads the hook payload on stdin and denies the
call when the command runs git as anything other than a reader.

Why an allowlist rather than a list of dangerous verbs: the rule this enforces
is "protect uncommitted work", and the command that broke it -- `git checkout --
<path>` -- changes no git state at all, so a denylist written around "commands
that write git state" missed it. A verb nobody thought about is far more likely
to be destructive than to be a reader, so the unknown case fails closed and says
how to widen the list.

Sessions run in parallel against one working tree, so an uncommitted edit may
belong to another agent, and `git checkout -- <path>` over never-staged content
is unrecoverable: it never entered the object database, so no blob survives.
That is what makes this worth a hook rather than a paragraph.
"""

import json
import re
import shlex
import sys

# git verbs that only read. Everything else is denied, including verbs that are
# harmless in isolation, because being wrong in that direction costs a retry and
# being wrong in the other direction costs somebody's afternoon.
READ_ONLY = frozenset(
    [
        "annotate",
        "archive",
        "blame",
        "cat-file",
        "check-attr",
        "check-ignore",
        "check-mailmap",
        "check-ref-format",
        "count-objects",
        "describe",
        "diff",
        "diff-files",
        "diff-index",
        "diff-tree",
        "difftool",
        "for-each-ref",
        "get-tar-commit-id",
        "grep",
        "help",
        "log",
        "ls-files",
        "ls-remote",
        "ls-tree",
        "merge-base",
        "name-rev",
        "rev-list",
        "rev-parse",
        "shortlog",
        "show",
        "show-branch",
        "show-index",
        "show-ref",
        "status",
        "var",
        "verify-commit",
        "verify-pack",
        "verify-tag",
        "version",
        "whatchanged",
    ]
)


# Verbs that read with one set of arguments and write with another, as
# (accepted tokens, every argument must be one of them, the bare form only
# lists).
#
# The third field is not decoration. `git branch` and `git tag` with no
# arguments list what exists, but **`git stash` with no arguments stashes
# everything** -- it is the one verb here whose bare form is the destructive
# one, and it is the command that flattened a human's staged changes once.
#
# The second field separates two shapes. `git branch -v foo` creates a branch
# called foo, so for branch and tag *every* argument has to be a listing flag.
# `git config --get user.email` has to carry the key it is reading, so there
# only the first argument decides.
CONDITIONAL = {
    "branch": (
        frozenset(["--list", "-l", "-a", "-r", "-v", "-vv", "--show-current"]),
        True,
        True,
    ),
    "tag": (frozenset(["--list", "-l", "-n"]), True, True),
    "config": (
        frozenset(["--get", "--get-all", "--get-regexp", "--list", "-l"]),
        False,
        True,
    ),
    "remote": (frozenset(["-v", "--verbose", "show"]), False, True),
    "worktree": (frozenset(["list"]), False, True),
    "stash": (frozenset(["list", "show"]), False, False),
}


# Global options that take a value, so the token after them is not the verb.
OPTIONS_WITH_VALUE = frozenset(["-C", "-c", "--git-dir", "--work-tree", "--namespace"])


DENIAL = """Blocked: `{command}` runs `git {verb}`, which is not a read-only git command.

CLAUDE.md forbids this. Other agents may be editing this working tree right now,
and `git checkout -- <path>`, `restore`, `reset` and `clean` destroy uncommitted
changes with no way to recover them -- content that was never staged never
entered the object database, so there is no blob to find.

To restore a file you broke on purpose (mutation testing), back it up outside the
repo first and copy it back:

    cp module.py "$SCRATCH/"      # ...mutate, run the suite...
    cp "$SCRATCH/module.py" module.py

Reading git is fine: {readers} and more.

If this verb really is read-only, add it to READ_ONLY in
.claude/hooks/block-destructive-git.py rather than working around the hook."""


def _segments(command):
    """The command split on the shell operators that start a new command."""
    return re.split(r"&&|\|\||[;|&\n]", command)


def _tokens(segment):
    """Best-effort argv for one segment.

    shlex raises on an unbalanced quote, which a legitimate command can carry in
    a subshell this crude split has cut in half. Falling back to a whitespace
    split keeps the check running; it can only ever see fewer git verbs, never
    invent one.
    """
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _git_call(tokens):
    """(verb, arguments) for the git command this segment runs, or None.

    The arguments come back sliced by position rather than looked up by name: a
    global option's *value* can equal the verb (`git -C log log`), and finding
    the verb by string search would then slice from the wrong token.
    """
    index = 0
    # env assignments and `env`/`command`/`sudo` style prefixes
    while index < len(tokens) and re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]
    ):
        index += 1
    if index >= len(tokens):
        return None
    # `/usr/bin/git` and `git` are the same program
    if tokens[index].rsplit("/", 1)[-1] != "git":
        return None
    index += 1
    while index < len(tokens):
        token = tokens[index]
        if token in OPTIONS_WITH_VALUE:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token, tokens[index + 1 :]
    return None  # bare `git`, which prints usage


def _allowed(verb, arguments):
    if verb in READ_ONLY:
        return True
    entry = CONDITIONAL.get(verb)
    if entry is None:
        return False
    accepted, every_argument, bare_lists = entry
    if not arguments:
        return bare_lists
    if every_argument:
        return all(argument in accepted for argument in arguments)
    return arguments[0] in accepted


def main():
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0  # not our payload to judge
    command = (payload.get("tool_input") or {}).get("command") or ""

    for segment in _segments(command):
        call = _git_call(_tokens(segment))
        if call is None:
            continue
        verb, arguments = call
        if _allowed(verb, arguments):
            continue
        reason = DENIAL.format(
            command=command.strip(),
            verb=verb,
            readers="git show, log, diff, status, archive, rev-parse",
        )
        json.dump(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            },
            sys.stdout,
        )
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
