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

import email.message
import io
import json
import sys

from http_security_test import parse_headers
from http_security_test.cli import commands, exchange, options


def parse(argv):
    return options.build_parser().parse_args(argv)


def headers(pairs):
    message = email.message.Message()
    for name, value in pairs:
        message.add_header(name, value)
    return parse_headers(message.items())


# Fixtures verified 2026-08-21 against the analyser at 357 tests passing.
# HARDENED yields notes only; WARNS adds exactly one warning (rp-missing) and
# still no error; adding `Access-Control-Allow-Origin: null` adds one error
# (acao-null). Do NOT use a bare `Server: nginx` response as a warning-only
# fixture -- over https it raises hsts-missing, which is an error.
HARDENED = [
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy",
     "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
]
WARNS = [pair for pair in HARDENED if pair[0] != "Referrer-Policy"]
ERRORS = WARNS + [("Access-Control-Allow-Origin", "null")]


def ok(target, url=None, status=200, pairs=None, hops=()):
    # Every caller passes a full URL as `target` (do_scan's own _targets()
    # always produces one), so the old `"https://%s/" % target` fallback
    # built "https://https://a.test//" and exchange.host() of THAT returns
    # "https" -- not the intended hostname. host= is one of exactly two facts
    # only the source can supply, and it drives the HSTS preload lookup, so a
    # malformed default silently untested that path in every fixture that
    # relies on it.
    return exchange.Exchange(
        kind="live",
        target=target,
        url=url or (target if "://" in target else "https://%s/" % target),
        status=status,
        reason="OK",
        headers=headers(HARDENED if pairs is None else pairs),
        hops=hops,
    )


def source_of(*items):
    """A fake input source: hands back whatever it was built with, per target."""
    by_target = {}
    for item in items:
        by_target.setdefault(item.target, []).append(item)

    def source(target, _options):
        return tuple(by_target.get(target, ()))

    return source


def test_a_clean_run_exits_zero(capsys):
    code = commands.do_scan(
        parse(["scan", "https://a.test/"]), source=source_of(ok("https://a.test/"))
    )
    assert code == 0
    assert "a.test" in capsys.readouterr().out


def test_findings_alone_do_not_change_the_exit_code(capsys):
    # A pentester with `set -e` must not have the script die because a site has
    # findings -- even error-level ones. CI opts in with --fail-on.
    item = ok("https://a.test/", pairs=ERRORS)
    code = commands.do_scan(parse(["scan", "https://a.test/"]), source=source_of(item))
    capsys.readouterr()
    assert code == 0


def test_fail_on_error_exits_one_when_an_error_finding_is_present(capsys):
    item = ok("https://a.test/", pairs=ERRORS)
    code = commands.do_scan(
        parse(["scan", "--fail-on", "error", "https://a.test/"]), source=source_of(item)
    )
    capsys.readouterr()
    assert code == 1


def test_fail_on_error_exits_zero_when_only_warnings_are_present(capsys):
    item = ok("https://a.test/", pairs=WARNS)
    code = commands.do_scan(
        parse(["scan", "--fail-on", "error", "https://a.test/"]),
        source=source_of(item),
    )
    capsys.readouterr()
    assert code == 0


def test_a_failed_target_exits_three(capsys):
    def source(target, _options):
        return (exchange.Failure(target, "dns", "no such host"),)

    code = commands.do_scan(parse(["scan", "https://nope.test/"]), source=source)
    assert code == 3
    assert "dns" in capsys.readouterr().err


def test_an_operational_failure_beats_a_finding(capsys):
    # 3 beats 1: a partial run is a more serious fact than a finding, because
    # it means the answer is incomplete.
    bad = ok("https://a.test/", pairs=ERRORS)

    def source(target, _options):
        if target == "https://a.test/":
            return (bad,)
        return (exchange.Failure(target, "timeout", "timed out"),)

    code = commands.do_scan(
        parse(["scan", "--fail-on", "error", "https://a.test/", "https://b.test/"]),
        source=source,
    )
    capsys.readouterr()
    assert code == 3


def test_the_scope_banner_prints_before_anything_else(capsys):
    # The scope line is diagnostic, not report: it goes to stderr, ungated by
    # whether the terminal report itself is shown, per the spec's "diagnostics,
    # the preload note and per-target failures all go to stderr."
    commands.do_scan(
        parse(["scan", "https://a.test/"]), source=source_of(ok("https://a.test/"))
    )
    first = capsys.readouterr().err.splitlines()[0]
    assert first.startswith("scope:")
    assert "derived from targets" in first


def test_an_explicit_scope_is_not_labelled_derived(capsys):
    commands.do_scan(
        parse(["scan", "--scope", "a.test", "https://a.test/"]),
        source=source_of(ok("https://a.test/")),
    )
    assert "derived from targets" not in capsys.readouterr().err


def test_json_to_stdout_suppresses_the_terminal_report(capsys):
    commands.do_scan(
        parse(["scan", "-j", "https://a.test/"]), source=source_of(ok("https://a.test/"))
    )
    out = capsys.readouterr().out
    document = json.loads(out)  # the whole of stdout must be one JSON document
    assert document["schema"] == 1
    assert "scope:" not in out
    assert "===" not in out


def test_the_scope_banner_still_prints_with_j(capsys):
    # -j is exactly the mode where nothing else records what the guard was:
    # the run document carries no scope record, and the banner used to be
    # gated by the same `show` flag that -j turns off. It must survive on
    # stderr while stdout stays one parseable JSON document.
    commands.do_scan(
        parse(["scan", "-j", "https://a.test/"]), source=source_of(ok("https://a.test/"))
    )
    captured = capsys.readouterr()
    assert captured.err.splitlines()[0].startswith("scope:")
    document = json.loads(captured.out)
    assert document["schema"] == 1


def test_output_files_are_written_and_the_terminal_still_prints(tmp_path, capsys):
    path = tmp_path / "evidence.json"
    commands.do_scan(
        parse(["scan", "-o", "json:%s" % path, "https://a.test/"]),
        source=source_of(ok("https://a.test/")),
    )
    captured = capsys.readouterr()
    assert "scope:" in captured.err
    assert "===" in captured.out  # the terminal report itself still shows
    assert json.loads(path.read_text(encoding="utf-8"))["schema"] == 1


def test_output_all_writes_every_implemented_format(tmp_path, capsys):
    prefix = tmp_path / "run"
    commands.do_scan(
        parse(["scan", "-oA", str(prefix), "https://a.test/"]),
        source=source_of(ok("https://a.test/")),
    )
    capsys.readouterr()
    assert (tmp_path / "run.json").exists()
    assert (tmp_path / "run.txt").exists()


def test_oA_without_a_space_degrades_to_a_loud_usage_error(capsys):
    # argparse reads `-oArun` as `-o Arun`; format resolution then rejects it.
    # Loud, not silent, which is the acceptable outcome -- pinned so it stays so.
    code = commands.do_scan(
        parse(["scan", "-oArun", "https://a.test/"]), source=source_of(ok("https://a.test/"))
    )
    assert code == 2
    assert "Arun" in capsys.readouterr().err


def test_min_level_filters_the_terminal_but_not_the_file(tmp_path, capsys):
    path = tmp_path / "evidence.json"
    commands.do_scan(
        parse(
            [
                "scan", "--min-level", "error", "-q",
                "-o", "json:%s" % path, "https://a.test/",
            ]
        ),
        source=source_of(ok("https://a.test/", pairs=WARNS)),
    )
    terminal = capsys.readouterr().out
    document = json.loads(path.read_text(encoding="utf-8"))
    findings = document["results"][0]["report"]["response"]["findings"]
    # The evidence file is complete; the terminal is filtered. `-q` drops the
    # inventories, so this assertion is about the findings list alone -- the
    # `missing` table legitimately names Referrer-Policy either way, which is
    # what the companion test below pins.
    assert any(f["code"] == "rp-missing" for f in findings)
    assert "Referrer-Policy" not in terminal


def test_min_level_never_filters_an_inventory(capsys):
    # Inventories are facts, findings are judgments, and nothing is withheld
    # from an inventory because of what it contains. So a header that
    # --min-level suppresses from the findings list must still appear in the
    # `missing` table.
    commands.do_scan(
        parse(["scan", "--min-level", "error", "https://a.test/"]),
        source=source_of(ok("https://a.test/", pairs=WARNS)),
    )
    terminal = capsys.readouterr().out
    assert "missing:" in terminal
    assert "Referrer-Policy" in terminal


def test_a_bare_host_target_becomes_https(capsys):
    seen = []

    def source(target, _options):
        seen.append(target)
        return (ok(target),)

    commands.do_scan(parse(["scan", "a.test"]), source=source)
    capsys.readouterr()
    assert seen == ["https://a.test"]


def test_the_plaintext_leg_is_analysed_as_insecure(capsys):
    # secure comes from this response's URL, not the typed target: HSTS
    # findings must stay suppressed on an http leg.
    item = ok("http://a.test/", url="http://a.test/", pairs=[("Server", "nginx")])
    # Over https this same response raises hsts-missing; over http it must not.
    commands.do_scan(parse(["scan", "-j", "http://a.test/"]), source=source_of(item))
    document = json.loads(capsys.readouterr().out)
    codes = [f["code"] for f in document["results"][0]["report"]["response"]["findings"]]
    assert "hsts-missing" not in codes


def test_a_scope_pattern_naming_a_file_is_warned_about(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.test").write_text("")
    commands.do_scan(
        parse(["scan", "--scope", "a.test", "https://a.test/"]),
        source=source_of(ok("https://a.test/")),
    )
    assert "quote" in capsys.readouterr().err


def test_a_dash_target_reads_targets_from_stdin(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("a.test\n\nb.test\n"))
    seen = []

    def source(target, _options):
        seen.append(target)
        return (ok(target),)

    commands.do_scan(parse(["scan", "-"]), source=source)
    capsys.readouterr()
    assert seen == ["https://a.test", "https://b.test"]


def test_a_rate_limited_response_echoes_retry_after(capsys):
    item = ok(
        "https://a.test/",
        status=429,
        pairs=HARDENED + [("Retry-After", "120")],
    )
    commands.do_scan(parse(["scan", "https://a.test/"]), source=source_of(item))
    err = capsys.readouterr().err
    assert "429" in err
    assert "Retry-After: 120" in err


def test_an_ordinary_response_says_nothing_about_retrying(capsys):
    commands.do_scan(
        parse(["scan", "https://a.test/"]), source=source_of(ok("https://a.test/"))
    )
    assert "Retry-After" not in capsys.readouterr().err


def test_an_unwritable_output_path_exits_three_with_a_message(tmp_path, capsys):
    path = tmp_path / "nonexistent-dir" / "x.json"  # parent dir does not exist
    code = commands.do_scan(
        parse(["scan", "-o", "json:%s" % path, "https://a.test/"]),
        source=source_of(ok("https://a.test/")),
    )
    assert code == 3
    err = capsys.readouterr().err
    assert "error: could not write" in err
    assert str(path) in err


def test_output_all_at_an_unwritable_prefix_exits_three(tmp_path, capsys):
    prefix = tmp_path / "nonexistent-dir" / "run"
    code = commands.do_scan(
        parse(["scan", "-oA", str(prefix), "https://a.test/"]),
        source=source_of(ok("https://a.test/")),
    )
    assert code == 3
    err = capsys.readouterr().err
    assert "error: could not write" in err
    # Both formats are attempted -- one bad path must not cost the other.
    assert str(prefix) + ".txt" in err
    assert str(prefix) + ".json" in err


def test_the_ok_fixture_builds_a_well_formed_url_not_a_doubled_scheme(capsys):
    # Regression pin for the fixture bug: the old default built
    # "https://https://a.test//" from a `target` that was already a full URL,
    # and exchange.host() of that malformed URL returns "https", not "a.test".
    commands.do_scan(
        parse(["scan", "-j", "https://a.test/"]), source=source_of(ok("https://a.test/"))
    )
    document = json.loads(capsys.readouterr().out)
    assert document["results"][0]["source"]["url"] == "https://a.test/"


def test_host_reaches_report_as_the_true_hostname(monkeypatch, capsys):
    # host= is one of exactly two facts only the source can supply, and it
    # drives the HSTS preload lookup -- so this pins that do_scan derives it
    # from the response's own URL correctly, rather than from a malformed one.
    captured = {}
    real_report = commands.report

    def spy(headers, **kwargs):
        captured.update(kwargs)
        return real_report(headers, **kwargs)

    monkeypatch.setattr(commands, "report", spy)
    commands.do_scan(
        parse(["scan", "https://a.test/"]), source=source_of(ok("https://a.test/"))
    )
    capsys.readouterr()
    assert captured["host"] == "a.test"


def test_the_scope_in_force_reaches_the_fetcher(capsys):
    seen = {}

    def source(target, options):
        seen["patterns"] = options.patterns
        return (ok(target),)

    commands.do_scan(parse(["scan", "https://a.test/"]), source=source)
    capsys.readouterr()
    assert seen["patterns"] == ("a.test", "*.a.test")
