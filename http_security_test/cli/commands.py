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

"""One function per verb. Glue only -- the work lives in the modules it calls."""

import sys

from .. import FINDING_SEVERITY, MESSAGES, report
from ..hsts import hstspreload
from . import exchange, live, meta, run, scope, text, writers


def do_explain(args):
    """Print each named code's level and message template, or all of them.

    Deliberately does not print which header a code belongs to: there is no
    runtime code-to-header mapping, and inventing one here would duplicate
    knowledge the analysers own. See the spec's "A code-to-header table".
    """
    wanted = list(args.code) if args.code else sorted(FINDING_SEVERITY)
    unknown = [code for code in wanted if code not in FINDING_SEVERITY]
    for code in wanted:
        if code in FINDING_SEVERITY:
            print("%-34s %-8s %s" % (code, FINDING_SEVERITY[code], MESSAGES[code]))
    for code in unknown:
        print("%s: no such code" % code, file=sys.stderr)
    return 2 if unknown else 0


def _targets(raw):
    """Targets as absolute URLs, expanding '-' into stdin lines."""
    collected = []
    for item in raw:
        if item == "-":
            collected.extend(line.strip() for line in sys.stdin if line.strip())
        else:
            collected.append(item)
    # https, never a silent downgrade to plaintext: this is a security tool.
    return [t if "://" in t else "https://" + t for t in collected]


def _color(mode):
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty()


def _exit_code(document, fail_on):
    """0 clean, 1 findings at the floor, 3 a target could not be reached."""
    if any(result["outcome"] == "failed" for result in document["results"]):
        return 3  # 3 beats 1: an incomplete answer is the more serious fact
    if fail_on == "never":
        return 0
    floor = meta.LEVELS.index(fail_on)
    for result in document["results"]:
        for finding in result["report"]["response"]["findings"]:
            if meta.LEVELS.index(finding["level"]) >= floor:
                return 1
    return 0


def _rate_limited(item):
    """A note for 429 and 503, or None.

    The one retry signal that is a fact rather than a prediction: RFC 9110
    defines both statuses as "try later" and Retry-After as when. Echoing it
    guesses nothing, unlike sniffing a response for a WAF interstitial, which
    this tool deliberately does not do.
    """
    if item.status not in (429, 503):
        return None
    values = item.headers.get("retry-after") or []
    when = "; Retry-After: %s" % values[0] if values else ""
    return "%s: HTTP %s -- the server is asking you to come back later%s" % (
        item.target,
        item.status,
        when,
    )


def _outputs(args):
    """Every (format, path) this run writes. Raises writers.UsageError."""
    targets = [writers.resolve(spec) for spec in args.output]
    if args.output_all:
        targets.extend(writers.all_outputs(args.output_all))
    if args.json:
        targets.append(("json", "-"))
    return targets


def do_scan(args, source=None):
    """Fetch each target, analyse it, render the run."""
    source = source or live.fetch

    try:
        outputs = _outputs(args)
    except writers.UsageError as error:
        print("error: %s" % error, file=sys.stderr)
        return 2

    targets = _targets(args.url)
    patterns = scope.resolve(args.scope, [exchange.host(t) for t in targets])
    # The one line of output that appears whether or not anything is found,
    # and what makes the guard auditable rather than mysterious -- so it is
    # ungated by `show` and always goes to stderr, same as the diagnostics
    # below it: with -j (or any -o ...:-) there is otherwise no record
    # anywhere of what the guard was, only that some hop was refused "scope".
    print(scope.banner(patterns, not args.scope), file=sys.stderr)
    for stray in scope.looks_shell_expanded(args.scope):
        print(
            "warning: --scope %s names a file -- quote the pattern so the shell "
            "does not expand it" % stray,
            file=sys.stderr,
        )
    if hstspreload is None:
        print(
            "note: hstspreload is not installed, so hsts-not-preloaded cannot fire",
            file=sys.stderr,
        )

    # Machine output on stdout and a human report on stdout cannot coexist.
    show = not any(path == "-" for _, path in outputs)

    options = live.Options(
        method=args.method,
        headers=args.header,
        user_agent=args.user_agent,
        timeout=args.timeout,
        insecure=args.insecure,
        proxy=args.proxy,
        no_redirect=args.no_redirect,
        max_redirects=args.max_redirects,
        patterns=patterns,
        raw=args.raw,
    )

    started = run.timestamp()
    results = []
    for target in targets:
        for item in source(target, options):
            if isinstance(item, exchange.Failure):
                print(
                    "%s: %s: %s" % (item.target, item.kind, item.message),
                    file=sys.stderr,
                )
                results.append(run.failed(item))
                continue
            note = _rate_limited(item)
            if note:
                print(note, file=sys.stderr)
            # secure and host come from THIS response's URL, not the typed
            # target: on a redirect chain the plaintext leg must be analysed
            # with secure=False, and the last leg may have another hostname.
            results.append(
                run.analysed(
                    item,
                    report(
                        item.headers,
                        secure=exchange.secure(item.url),
                        host=exchange.host(item.url),
                        raw=item.raw_response,
                        request_raw=item.raw_request,
                    ),
                )
            )
    document = run.run_document(results, started, run.timestamp())

    if show:
        sys.stdout.write(
            text.render(
                document,
                color=_color(args.color),
                quiet=args.quiet,
                codes=args.codes,
                min_level=args.min_level,
            )
        )
    # The terminal report is already written by this point, so the run's
    # results are not lost even when every file below fails to write. One bad
    # path must not cost the others, so a write failure is recorded and the
    # loop continues rather than aborting -- otherwise -oA could half-write
    # its evidence set on the first unwritable prefix.
    write_failed = False
    for name, path in outputs:
        if path == "-":
            writers.write(name, document, sys.stdout)
        else:
            try:
                with open(path, "w", encoding="utf-8") as stream:
                    writers.write(name, document, stream)
            except OSError as error:
                print("error: could not write %s: %s" % (path, error), file=sys.stderr)
                write_failed = True

    if write_failed:
        return 3  # an incomplete answer, not the code --fail-on owns
    return _exit_code(document, args.fail_on)
