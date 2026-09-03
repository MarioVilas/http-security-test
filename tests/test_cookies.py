#!/usr/bin/python3
# fmt: off

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

import pytest

from http_security_test import catalog, cookies


def test_a_simple_cookie():
    c = cookies.parse_set_cookie("sid=abc123; Path=/; Secure; HttpOnly")
    assert c.name == "sid"
    assert c.value == "abc123"
    assert c.attributes == {"path": "/", "secure": None, "httponly": None}
    assert c.raw == "sid=abc123; Path=/; Secure; HttpOnly"


def test_the_value_is_split_at_the_FIRST_equals():
    # rfc6265bis 5.2 step 3. A base64 value ends in '=' padding and a JWT has
    # none, but either way only the first '=' separates name from value.
    c = cookies.parse_set_cookie("t=YWJj=; Path=/")
    assert (c.name, c.value) == ("t", "YWJj=")


def test_a_nameless_cookie_puts_everything_in_the_value():
    # rfc6265bis 5.2 step 3: no '=' means the name is empty and the value is
    # the whole name-value-pair. This is what makes the hidden-prefix defect
    # reachable at all.
    c = cookies.parse_set_cookie("=__Host-sid=x; Path=/")
    assert c.name == ""
    assert c.value == "__Host-sid=x"


def test_a_bare_token_with_no_equals_at_all():
    c = cookies.parse_set_cookie("justavalue")
    assert (c.name, c.value) == ("", "justavalue")


def test_surrounding_whitespace_is_stripped_from_name_and_value():
    c = cookies.parse_set_cookie("  sid  =  abc  ; Path = /x ")
    assert (c.name, c.value) == ("sid", "abc")
    assert c.attributes["path"] == "/x"


def test_attribute_names_are_lowercased_and_flags_map_to_None():
    c = cookies.parse_set_cookie("a=b; SECURE; HttpOnly; SameSite=Lax")
    assert c.attributes == {"secure": None, "httponly": None, "samesite": "Lax"}


def test_an_attribute_value_keeps_its_case():
    # SameSite is matched case-insensitively by browsers, but the parser
    # records what was sent; the analysis lowercases when it compares.
    assert cookies.parse_set_cookie("a=b; SameSite=STRICT").attributes["samesite"] == "STRICT"


def test_unrecognised_attributes_are_kept_not_dropped():
    # Both engines ignore them. This package reports them, so the parser must
    # not throw them away: the parser records, the analysis judges.
    c = cookies.parse_set_cookie("a=b; Version=1; Port=\"80\"; Secrue")
    assert c.attributes["version"] == "1"
    assert c.attributes["port"] == '"80"'
    assert "secrue" in c.attributes


def test_a_repeated_attribute_keeps_the_last():
    # No specification defines this; last-wins matches both engines' parsers.
    assert cookies.parse_set_cookie("a=b; Path=/x; Path=/y").attributes["path"] == "/y"


def test_empty_and_whitespace_only_attributes_are_skipped():
    c = cookies.parse_set_cookie("a=b; ; Secure;  ; HttpOnly")
    assert c.attributes == {"secure": None, "httponly": None}


def test_parse_cookies_reads_every_value_of_a_repeated_header():
    present = {"set-cookie": ["a=1", "b=2", "c=3"]}
    assert [c.name for c in cookies.parse_cookies(present)] == ["a", "b", "c"]


def test_parse_cookies_is_empty_when_the_header_is_absent():
    assert cookies.parse_cookies({"content-type": ["text/html"]}) == ()


def test_the_same_name_twice_is_two_cookies():
    # A dict keyed by name would drop one. This is why the inventory is a list.
    present = {"set-cookie": ["sid=1; Path=/a", "sid=2; Path=/b"]}
    parsed = cookies.parse_cookies(present)
    assert len(parsed) == 2
    assert [c.attributes["path"] for c in parsed] == ["/a", "/b"]


# The remaining two cases came from checking this parser against an
# independent corpus: security/cryptoparser's test/httpx/test_header.py,
# TestHttpHeaderFieldValueSetCookie (around line 806). Both agreed with this
# parser; they are added because neither shape above already covered them.


def test_a_cookie_with_no_attributes_at_all():
    # cryptoparser's _header_minimal_bytes: b'name=value', with every
    # attribute absent. Confirms the empty tail after the name=value pair
    # parses to an empty attributes dict rather than raising or adding a
    # spurious entry.
    c = cookies.parse_set_cookie("name=value")
    assert (c.name, c.value) == ("name", "value")
    assert c.attributes == {}


def test_an_attribute_value_containing_a_comma_is_not_split_there():
    # cryptoparser's _header_full_bytes pairs an Expires date -- which
    # contains its own comma ("Thu, 01 Jan 1970 00:00:00 GMT") -- with the
    # rest of the attributes. This is the CLAUDE.md-documented trap in
    # miniature: a comma inside one field must not be mistaken for a
    # separator. Here the separator is ';', not ',', so the date survives
    # intact.
    c = cookies.parse_set_cookie(
        "name=value; expires=Thu, 01 Jan 1970 00:00:00 GMT; max-age=1; "
        "Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax"
    )
    assert (c.name, c.value) == ("name", "value")
    assert c.attributes == {
        "expires": "Thu, 01 Jan 1970 00:00:00 GMT",
        "max-age": "1",
        "domain": "example.com",
        "path": "/",
        "secure": None,
        "httponly": None,
        "samesite": "Lax",
    }


# --- the typo metric ------------------------------------------------------
# Damerau/OSA, not Levenshtein. Measured during design: of 21 realistic typos,
# 8 are OSA 1 and Levenshtein 2, every one a transposition. A plain-Levenshtein
# threshold of 1 misses roughly 40% of real typos, including the likeliest
# misspelling of the most important attribute.

@pytest.mark.parametrize("typo,expected", [
    ("secrue", "secure"),        # transposition: OSA 1, Levenshtein 2
    ("secuer", "secure"),        # transposition
    ("httponyl", "httponly"),    # transposition
    ("httpolny", "httponly"),    # transposition
    ("smaesite", "samesite"),    # transposition
    ("expries", "expires"),      # transposition
    ("domian", "domain"),        # transposition
    ("paht", "path"),            # transposition
    ("secue", "secure"),         # deletion
    ("htponly", "httponly"),     # deletion
    ("samesit", "samesite"),     # deletion
    ("maxage", "max-age"),       # deletion
])
def test_osa_finds_the_intended_attribute_at_distance_one(typo, expected):
    assert cookies.osa_distance(typo, expected) == 1


@pytest.mark.parametrize("typo", ["secrue", "secuer", "httponyl", "httpolny",
                                  "smaesite", "expries", "domian", "paht"])
def test_the_transposition_cases_are_levenshtein_two(typo):
    # This is the test that makes the metric choice load-bearing. Swap the
    # implementation to plain Levenshtein and the parametrized test above
    # fails on exactly these eight.
    nearest = min(cookies.KNOWN_ATTRIBUTES, key=lambda k: cookies.osa_distance(typo, k))
    assert cookies.osa_distance(typo, nearest) == 1
    assert _levenshtein(typo, nearest) == 2


def _levenshtein(a, b):
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1,
                             rows[i - 1][j - 1] + cost)
    return rows[-1][-1]


@pytest.mark.parametrize("real", ["version", "comment", "commenturl", "discard",
                                  "port", "sameparty"])
def test_no_real_attribute_name_collides_at_threshold_one(real):
    # Probed during design against every cookie attribute that has ever
    # existed and is not in KNOWN_ATTRIBUTES: the nearest is 3 away.
    nearest = min(cookies.KNOWN_ATTRIBUTES, key=lambda k: cookies.osa_distance(real, k))
    assert cookies.osa_distance(real, nearest) >= 3


# --- which attributes are recognised -------------------------------------

def test_every_spelling_table_covers_the_keys_it_is_indexed_by():
    # Both spelling tables are indexed with a bare subscript at their one call
    # site -- `_ATTRIBUTE_SPELLING[suspected]` and `_PREFIX_SPELLING[prefix]`
    # -- so a key added to the table they mirror without a spelling lands as a
    # KeyError inside an analyser, on whichever cookie happens to trigger it.
    # Safe today because both indexes can only be reached with a value that
    # came out of the mirrored table; pinned because that is an argument about
    # the current call sites, not about the tables.
    assert set(cookies._ATTRIBUTE_SPELLING) == set(cookies.TYPO_SENSITIVE_ATTRIBUTES)
    assert set(cookies._PREFIX_SPELLING) == set(cookies.COOKIE_PREFIXES)


def test_the_recognised_set_is_the_browser_union():
    # Chromium parsed_cookie.cc:62-70 -- a superset of Firefox's eight. The
    # extra is `priority`: Chrome-proprietary, never standardised, and sent by
    # Google's own cookies, so an rfc6265bis-derived set would fire on some of
    # the most visited responses on the web.
    assert cookies.KNOWN_ATTRIBUTES == frozenset([
        "path", "domain", "expires", "max-age", "secure", "httponly",
        "samesite", "partitioned", "priority",
    ])


# --- suspected typos, with both guards -----------------------------------

def test_a_typo_of_a_security_flag_is_suspected_when_the_flag_is_absent():
    assert cookies.suspected_attribute("secrue", absent_from={"secure"}) == "secure"


def test_a_typo_is_not_suspected_when_the_real_attribute_is_present():
    # `Secure; Secrue` has the protection; the typo cost nothing.
    assert cookies.suspected_attribute("secrue", absent_from=set()) is None


@pytest.mark.parametrize("typo", ["expries", "domian", "maxage", "paht", "prioriy"])
def test_a_typo_of_a_fail_safe_attribute_is_never_suspected(typo):
    # A misspelled Expires or Max-Age makes the cookie session-scoped; a
    # misspelled Path narrows it to the request directory; a misspelled Domain
    # makes it host-only. All leave the cookie MORE restricted, so escalating
    # would assert a defect that does not exist.
    assert cookies.suspected_attribute(
        typo, absent_from={"expires", "max-age", "domain", "path", "priority"}
    ) is None


def test_an_unrelated_name_is_not_suspected():
    assert cookies.suspected_attribute("version", absent_from={"secure"}) is None


# --- prefix stripping and glob matching ----------------------------------

@pytest.mark.parametrize("name,stripped", [
    ("__Secure-PHPSESSID", "PHPSESSID"),    # a literal Open-Cookie-Database entry
    ("__Host-Http-sid", "sid"),             # longest-prefix-first
    ("__Host-sid", "sid"),
    ("__Http-sid", "sid"),
    ("__SECURE-sid", "sid"),                # matching is case-insensitive
    ("plain", "plain"),
])
def test_strip_prefix(name, stripped):
    assert cookies.strip_prefix(name) == stripped


@pytest.mark.parametrize("name", ["PHPSESSID", "phpsessid", "__Secure-PHPSESSID",
                                   "JSESSIONID", "sessid", "jwt", "rack.session",
                                   "PLAY_SESSION", "i_like_gitea", "grafana_session"])
def test_session_names_match_case_insensitively_after_prefix_stripping(name):
    assert cookies.is_session_name(name)


@pytest.mark.parametrize("name", [
    "wordpress_logged_in_a1b2c3",     # prefix pattern
    "wp_woocommerce_session_deadbeef",
    "cpsession12345",
    "phpbb3_n7fab_sid",               # anchored at BOTH ends
])
def test_session_patterns_match(name):
    assert cookies.is_session_name(name)


@pytest.mark.parametrize("name", [
    "lang", "_ga", "_gid", "_fbp",
    "_hjSessionUser_1234",       # contains "Session" and must NOT match
    "taboola_session_id",        # analytics; a *_session rule would mis-rate it
    "matomo_sessid",             # analytics; a *sessid suffix rule would too
    "mage-cache-sessid",         # a Magento CACHE marker
    "ai_session",                # Azure Application Insights
    "token",                     # fails the negative-oracle test: Adform uses it
    "_sid",                      # a bare fragment must never match
])
def test_non_session_names_do_not_match(name):
    assert not cookies.is_session_name(name)


@pytest.mark.parametrize("name", ["AWSALB", "awsalb", "__cf_bm", "ak_bmsc", "_abck",
                                   "BIGipServerpool_web", "NSC_abc",
                                   "incap_ses_123_456", "visid_incap_789"])
def test_infrastructure_names_match(name):
    assert cookies.is_infrastructure_name(name)


@pytest.mark.parametrize("name", ["SERVERID", "cf_clearance", "TS01abc",
                                   "bbcpsessionhash", "phpsessid"])
def test_rejected_infrastructure_candidates_do_not_match(name):
    # SERVERID: a generic English word, the only entry a real application might
    # plausibly choose. cf_clearance: a bearer token, so a credential. TS01:
    # TS-prefixed cookies are F5 ASM as well as Wix. bbcpsessionhash CONTAINS
    # cpsession without STARTING with it -- the fragment/prefix distinction in
    # one example.
    assert not cookies.is_infrastructure_name(name)


def test_cookie_as_dict_shape():
    c = cookies.parse_set_cookie(
        "sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict")
    assert cookies.cookie_as_dict(c) == {
        "name": "sid", "value": "abc123",
        "secure": True, "httponly": True, "samesite": "Strict",
        "path": "/", "domain": None, "expires": None, "max_age": None,
        "partitioned": False, "judged": True,
        "raw": "sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict",
    }


def test_every_key_is_present_even_when_nothing_is_set():
    row = cookies.cookie_as_dict(cookies.parse_set_cookie("a=b"))
    assert set(row) == {"name", "value", "secure", "httponly", "samesite",
                        "path", "domain", "expires", "max_age",
                        "partitioned", "judged", "raw"}


def test_flags_are_false_not_null_when_absent():
    # The attribute is a flag, so absent is False rather than unknown.
    row = cookies.cookie_as_dict(cookies.parse_set_cookie("a=b"))
    assert row["secure"] is False
    assert row["httponly"] is False
    assert row["partitioned"] is False
    assert row["samesite"] is None      # a value, so absent really is unknown


def test_an_infrastructure_cookie_is_marked_unjudged():
    row = cookies.cookie_as_dict(cookies.parse_set_cookie("AWSALB=x"))
    assert row["judged"] is False


def test_max_age_is_reported_under_an_underscored_key():
    # The wire spells it max-age; JSON keys in this schema use underscores.
    row = cookies.cookie_as_dict(cookies.parse_set_cookie("a=b; Max-Age=60"))
    assert row["max_age"] == "60"


def test_the_value_is_carried_in_full():
    # This package does not redact. It is a working tool for a pentester, and
    # redaction before anything reaches a client report is the consumer's job.
    row = cookies.cookie_as_dict(cookies.parse_set_cookie("sid=live-token-here"))
    assert row["value"] == "live-token-here"


def _analyze(value, trustworthy=True, host="example.com", date=None):
    present = {"set-cookie": [value] if isinstance(value, str) else list(value)}
    if date is not None:
        present["date"] = [date] if isinstance(date, str) else list(date)
    return cookies.analyze_cookies(present, trustworthy, host)


def _codes(value, **kw):
    return sorted(f.code for f in _analyze(value, **kw))


def test_samesite_none_without_secure():
    # layered-cookies step 12: the cookie is rejected. BCD
    # SameSite.none_requires_secure: Chrome 80 / Firefox 131 / Safari false.
    assert "cookie-samesite-none-insecure" in _codes("a=b; SameSite=None")
    assert "cookie-samesite-none-insecure" not in _codes("a=b; SameSite=None; Secure")


def test_secure_over_plaintext():
    # Chromium adds EXCLUDE_SECURE_ONLY and does not store the cookie at all
    # (net/cookies/cookie_base.cc:124); Firefox refuses to send it
    # (netwerk/cookie/CookieService.cpp:1038).
    assert "cookie-secure-over-plaintext" in _codes("a=b; Secure", trustworthy=False)
    assert "cookie-secure-over-plaintext" not in _codes("a=b; Secure", trustworthy=True)


@pytest.mark.parametrize("value,unmet", [
    ("__Secure-sid=x", ["secure"]),
    ("__Host-sid=x; Secure", ["path"]),
    ("__Host-sid=x; Secure; Path=/; Domain=example.com", ["domain"]),
    ("__Http-sid=x; Secure", ["httponly"]),
    ("__Host-Http-sid=x; Secure; Path=/", ["httponly"]),
])
def test_prefix_violations(value, unmet):
    findings = [f for f in _analyze(value) if f.code == "cookie-prefix-violated"]
    assert len(findings) == 1
    assert findings[0].data["unmet"] == unmet


def test_host_http_is_matched_before_host():
    # A naive startswith("__Host-") classifies this as __Host- and then never
    # requires HttpOnly -- a false negative that looks like a pass.
    findings = [f for f in _analyze("__Host-Http-sid=x; Secure; Path=/")
                if f.code == "cookie-prefix-violated"]
    assert findings[0].data["prefix"] == "__Host-Http-"


def test_prefix_matching_is_case_insensitive():
    # rfc6265bis 5.4 is normative for UAs, and both engines apply it.
    assert "cookie-prefix-violated" in _codes("__SECURE-sid=x")


def test_a_satisfied_prefix_raises_nothing():
    # Scoped to the prefix code deliberately: Task 6 adds hardening findings
    # to this same cookie (no HttpOnly, no SameSite), so an `== []` assertion
    # here would be true now and false two tasks later.
    assert "cookie-prefix-violated" not in _codes("__Host-sid=x; Secure; Path=/")


def test_host_prefix_tolerates_domain_on_an_ip_literal_host():
    # Chromium HasValidHostPrefixAttributes (cookie_util.cc:120). Refusing it
    # would be a false positive on a configuration Chrome accepts.
    assert "cookie-prefix-violated" not in _codes(
        "__Host-sid=x; Secure; Path=/; Domain=127.0.0.1", host="127.0.0.1")


@pytest.mark.parametrize("host", ["[::1]", "::1", "2001:db8::1"])
def test_host_prefix_tolerates_domain_on_an_ipv6_literal_host(host):
    # The same Chromium tolerance, for the spelling analyze() actually passes:
    # exchange.host() is urlsplit().hostname, brackets stripped, so testing
    # only `host.startswith("[")` left this branch dead (final review, C1).
    assert "cookie-prefix-violated" not in _codes(
        "__Host-sid=x; Secure; Path=/; Domain=%s" % host, host=host)


def test_a_domain_name_is_not_an_ip_literal():
    # The guard the colon test needs: a Domain on a real hostname is still a
    # __Host- violation, brackets or no brackets.
    assert "cookie-prefix-violated" in _codes(
        "__Host-sid=x; Secure; Path=/; Domain=example.com", host="example.com")


def test_hidden_prefix_in_the_value_of_a_nameless_cookie():
    # layered-cookies step 17; Chromium HasHiddenPrefixName
    # (cookie_util.cc:796). Something downstream re-parses `=__Host-sid=x` as a
    # __Host-sid cookie that never met the rules.
    findings = [f for f in _analyze("=__Host-sid=x") if f.code == "cookie-hidden-prefix"]
    assert findings[0].data["prefix"] == "__Host-"


def test_hidden_prefix_trims_leading_whitespace_and_ignores_case():
    assert "cookie-hidden-prefix" in _codes("=  __host-sid=x")


def test_a_named_cookie_whose_value_looks_prefixed_is_not_a_hidden_prefix():
    # HasHiddenPrefixName fires only when the NAME is empty.
    assert "cookie-hidden-prefix" not in _codes("a=__Host-sid=x")


@pytest.mark.parametrize("bad", ["a=b\x00c", "a=b\x01c", "a=b\x1fc", "a=b\x7fc"])
def test_control_characters_discard_the_header(bad):
    # rfc6265bis 5.2 step 1: CTLs excluding HTAB abort the whole algorithm.
    assert "cookie-control-character" in _codes(bad)


def test_horizontal_tab_is_not_a_control_character_here():
    assert "cookie-control-character" not in _codes("a=b\tc")


def test_an_oversized_cookie_is_discarded():
    # rfc6265bis 5.2 step 5: name + value over 4096 octets.
    findings = [f for f in _analyze("a=" + "x" * 4096) if f.code == "cookie-oversized"]
    assert findings[0].data["octets"] == 4097


def test_a_cookie_at_the_limit_is_not_oversized():
    assert "cookie-oversized" not in _codes("a=" + "x" * 4095)


def test_an_invalid_samesite_value_falls_back_to_default():
    # rfc6265bis algorithm [11]: an unrecognised value sets enforcement to
    # Default, NOT None. Chrome's Default is Lax; Firefox's and Safari's
    # release default is no restriction at all, so the strongest protection
    # was asked for and none was received in two engines.
    findings = [f for f in _analyze("a=b; SameSite=Strictt; Secure")
                if f.code == "cookie-samesite-invalid"]
    assert findings[0].data["value"] == "Strictt"


@pytest.mark.parametrize("value", ["None", "none", "Lax", "LAX", "Strict", "strict"])
def test_valid_samesite_values_are_case_insensitive(value):
    assert "cookie-samesite-invalid" not in _codes(
        "a=b; SameSite=%s; Secure" % value)


def test_partitioned_without_secure():
    # Chromium IsCookiePartitionedValid.
    assert "cookie-partitioned-insecure" in _codes("a=b; Partitioned")
    assert "cookie-partitioned-insecure" not in _codes("a=b; Partitioned; Secure")


def test_a_domain_that_is_not_a_suffix_of_the_host_is_rejected():
    findings = [f for f in _analyze("a=b; Domain=evil.example", host="www.example.com")
                if f.code == "cookie-domain-mismatch"]
    assert findings[0].data["domain"] == "evil.example"


@pytest.mark.parametrize("domain", ["example.com", ".example.com", "www.example.com"])
def test_a_domain_that_is_a_suffix_is_accepted(domain):
    assert "cookie-domain-mismatch" not in _codes(
        "a=b; Domain=%s" % domain, host="www.example.com")


def test_domain_mismatch_is_silent_when_the_host_is_unknown():
    # Unknown is not evidence of a mismatch.
    assert "cookie-domain-mismatch" not in _codes("a=b; Domain=x.example", host=None)


def test_tier_one_fires_on_an_infrastructure_cookie():
    # Not a sensitivity judgement: the browser throws the cookie away, which
    # breaks session affinity. A correctness statement about the response.
    assert "cookie-samesite-none-insecure" in _codes("AWSALB=x; SameSite=None")


def test_two_cookies_missing_the_same_thing_are_two_findings():
    # The assertion identity() was widened for, and which nothing exercised
    # before this feature.
    findings = [f for f in _analyze(["a=1; SameSite=None", "b=2; SameSite=None"])
                if f.code == "cookie-samesite-none-insecure"]
    assert len(findings) == 2
    assert {f.data["cookie"] for f in findings} == {"a", "b"}


# ---------------------------------------------------------------------------
# Fix report follow-ups (code review on the initial Task 5 landing)
# ---------------------------------------------------------------------------


def test_an_obs_folded_set_cookie_does_not_raise_control_character():
    # Both engines unfold a continuation line before parsing any header value,
    # cookies included -- Chromium's HttpUtil::AssembleRawHeaders
    # (net/http/http_util.cc:813-815) and Firefox's
    # nsHttpTransaction::ParseLineSegment (:2177-2190) -- so the CR/LF here
    # never reaches the cookie a browser actually sets. parse_raw_headers()
    # does not unfold (it is shared by every other analyser), so this is
    # cookies.py's own unfolding, exercised directly on the raw value.
    assert "cookie-control-character" not in _codes("a=b;\r\n Path=/")


def test_a_control_character_in_an_attribute_also_discards_the_header():
    # Pins that the WHOLE raw set-cookie-string is searched, not just the
    # value -- a check that would stay green even if _CONTROL only looked at
    # cookie.value, since every other case in this file puts the CTL there.
    assert "cookie-control-character" in _codes("a=b; Path=/\x01")


def test_a_non_ascii_value_at_the_limit_is_not_oversized():
    # Latin-1 is one octet per character for "e"-acute (0xE9): the old
    # utf-8 encode counted two octets per character here and overcounted
    # every non-ASCII cookie toward a false cookie-oversized.
    assert "cookie-oversized" not in _codes("a=" + "\xe9" * 4095)


def test_a_non_ascii_value_just_over_the_limit_is_oversized():
    findings = [f for f in _analyze("a=" + "\xe9" * 4096)
                if f.code == "cookie-oversized"]
    assert findings[0].data["octets"] == 4097


def test_a_bare_samesite_flag_is_invalid():
    # `Set-Cookie: a=b; SameSite` (no `=` at all) degrades to Default exactly
    # as `SameSite=Strictt` does (rfc6265bis algorithm [11]); previously only
    # the `=`-bearing spelling of the same defect was reported.
    findings = [f for f in _analyze("a=b; SameSite")
                if f.code == "cookie-samesite-invalid"]
    assert len(findings) == 1
    # No `value` key at all, and the message says so in words rather than
    # quoting back a placeholder the response never wrote (final review, M4).
    assert "value" not in findings[0].data
    rendered = catalog.describe(findings[0])
    assert "sets SameSite as a flag with no value" in rendered
    assert "(none)" not in rendered


def test_a_bare_samesite_flag_is_not_also_reported_as_none():
    # Mutually exclusive with cookie-samesite-none-insecure: a flag with no
    # value is not the SameSite=None value, so it must not double-report.
    assert "cookie-samesite-none-insecure" not in _codes("a=b; SameSite")


def _find(value, code, **kw):
    hits = [f for f in _analyze(value, **kw) if f.code == code]
    assert len(hits) == 1, "expected exactly one %s, got %d" % (code, len(hits))
    return hits[0]


# --- the floor: everything is reported, nothing is claimed ----------------

@pytest.mark.parametrize("code", ["cookie-no-secure", "cookie-no-httponly",
                                   "cookie-no-samesite"])
def test_an_ordinary_cookie_reports_every_gap_at_the_floor(code):
    # Reporting everything is the design: noise is a risk asserted where there
    # is none, not a fact reported. `lang=en` gets notes, not warnings.
    finding = _find("lang=en; Secure", code) if code != "cookie-no-secure" \
        else _find("lang=en", code)
    assert finding.level == "note"


def test_a_well_configured_cookie_reports_nothing():
    assert _codes("sid=x; Secure; HttpOnly; SameSite=Strict; Path=/") == []


# --- escalation ----------------------------------------------------------

@pytest.mark.parametrize("name", ["PHPSESSID", "jsessionid", "__Secure-PHPSESSID",
                                   "wordpress_logged_in_abc", "phpbb3_n7fab_sid",
                                   "grafana_session", "jwt"])
def test_a_known_session_name_escalates_to_warning(name):
    finding = _find("%s=x; Secure; SameSite=Lax" % name, "cookie-no-httponly")
    assert finding.level == "warning"
    assert "session-name" in finding.data["evidence"]


def test_a_prefix_escalates_the_OTHER_attributes():
    # A prefix does not escalate the attribute it names: __Secure- without
    # Secure is cookie-prefix-violated, tier 1, not a hardening gap.
    finding = _find("__Secure-x=y; Secure; SameSite=Lax", "cookie-no-httponly")
    assert finding.level == "warning"
    assert "prefix" in finding.data["evidence"]


def test_httponly_already_set_escalates_secure_and_samesite():
    finding = _find("x=y; HttpOnly; Secure", "cookie-no-samesite")
    assert finding.level == "warning"
    assert "httponly-set" in finding.data["evidence"]


def test_a_misspelling_escalates_to_error_and_outranks_everything():
    # The only signal that establishes INTENT rather than guessing importance.
    finding = _find("x=y; Secrue; SameSite=Lax", "cookie-no-secure")
    assert finding.level == "error"
    assert "typo:secure" in finding.data["evidence"]


def test_matters_is_evidence_for_without_the_intent_signals():
    # `_matters()` replaced three call sites that asked
    # `evidence_for(cookie, "secure")` -- or "samesite" -- and filtered the
    # intent signals back out. The list was right; the attribute was a
    # borrowed call site rather than a decision, so a reader tracing why
    # domain breadth consulted the Secure row found no answer.
    #
    # Pinned as one test over a cross-product rather than a parametrize:
    # 105 test functions for a single property would outnumber the tests for
    # the sixteen codes. The assertion names the failing cookie itself.
    names = ["lang", "sid", "PHPSESSID", "__Host-sid", "__Secure-sid",
             "csrf_token", "XSRF-TOKEN", "__Host-csrf", "AWSALB", "_ga",
             "remember_user_token", "wordpress_logged_in_abc", "", "nc_token",
             "grafana_session"]
    attrs = ["", "; Secure", "; HttpOnly", "; Secure; HttpOnly", "; Secrue",
             "; HtppOnly; Secure",
             "; Max-Age=99999; Domain=example.com; Secure; HttpOnly"]
    for name in names:
        for attr in attrs:
            value = "%s=x%s" % (name, attr)
            cookie = cookies.parse_set_cookie(value)
            for attribute in ("secure", "samesite"):
                # Either attribute's evidence, once the OTHER question's
                # signals are removed, is what _matters() must return. Both
                # directions, because either was a plausible spelling of the
                # old code.
                intent_free = [
                    e for e in cookies.evidence_for(cookie, attribute)
                    if not e.startswith("typo:") and e != "httponly-set"
                ]
                assert cookies._matters(cookie) == intent_free, (
                    "%r via %s: %r != %r"
                    % (value, attribute, cookies._matters(cookie), intent_free)
                )


def test_matters_reads_no_attribute_at_all():
    # The structural claim, separate from the equivalence above: two cookies
    # with the same name and completely different attributes must get the same
    # answer, because "does this cookie matter" is a question about the name.
    bare = cookies.parse_set_cookie("PHPSESSID=x")
    loaded = cookies.parse_set_cookie(
        "PHPSESSID=x; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=1; Domain=example.com")
    assert cookies._matters(bare) == cookies._matters(loaded) == ["session-name"]


def test_an_unescalated_finding_carries_empty_evidence():
    # Always present, [] included, the same rule as `data` itself.
    assert _find("lang=en; Secure; SameSite=Lax", "cookie-no-httponly").data["evidence"] == []


# --- the CSRF exemption, which would otherwise be a bug ------------------

@pytest.mark.parametrize("name", ["XSRF-TOKEN", "csrf_token", "xf_csrf"])
def test_a_csrf_cookie_is_never_escalated_for_httponly(name):
    # A CSRF token cookie without HttpOnly is a CORRECT configuration: the
    # cookie-to-header pattern requires JavaScript to read it. OWASP's CSRF
    # cheat sheet writes exactly this as sample code, and OIDC Session
    # Management says the same of the OP state cookie. Escalating it would be
    # a false positive on a correct configuration -- principle 4's worst case.
    assert _find("%s=x; Secure; SameSite=Lax" % name, "cookie-no-httponly").level == "note"


@pytest.mark.parametrize("name", ["XSRF-TOKEN", "csrf_token"])
def test_a_csrf_cookie_IS_escalated_for_secure_and_samesite(name):
    assert _find("%s=x; SameSite=Lax" % name, "cookie-no-secure").level == "warning"


# --- the three facts that are only findings once laddered ----------------

def test_samesite_none_is_reported():
    assert _find("x=y; SameSite=None; Secure", "cookie-samesite-none").level == "note"
    assert _find("PHPSESSID=y; SameSite=None; Secure; HttpOnly",
                 "cookie-samesite-none").level == "warning"


@pytest.mark.parametrize("value", ["x=y; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure",
                                    "x=y; Max-Age=86400; Secure"])
def test_a_persistent_cookie_is_reported(value):
    assert _find(value, "cookie-persistent").level == "note"


def test_a_session_lifetime_cookie_is_not_persistent():
    assert "cookie-persistent" not in _codes("x=y; Secure")


def test_a_domain_scoped_cookie_is_reported_but_never_judged_broad():
    # Whether a Domain is over-BROAD needs a public suffix list, and the
    # ruling is PSL-or-nothing. That it widens the cookie to subdomains is a
    # fact needing no PSL.
    finding = _find("x=y; Domain=example.com; Secure", "cookie-domain-broad",
                    host="www.example.com")
    assert finding.data["domain"] == "example.com"


def test_no_domain_attribute_is_not_broad():
    assert "cookie-domain-broad" not in _codes("x=y; Secure")


# --- suppression --------------------------------------------------------

@pytest.mark.parametrize("name", ["AWSALB", "BIGipServerpool_web", "__cf_bm",
                                   "incap_ses_1_2"])
def test_an_infrastructure_cookie_raises_no_hardening_finding(name):
    assert _codes("%s=x" % name) == []


def test_suppression_is_unconditional_within_tier_two():
    # An earlier draft cancelled suppression whenever an escalation signal
    # fired. That was incoherent: the list is a corroborated assertion that a
    # cookie is not a credential, and "HttpOnly is set" is a guess about
    # sensitivity. A guess must not override an assertion.
    assert _codes("__cf_bm=x; HttpOnly") == []


# --- fix round: the CSRF exemption must dominate inference, not just the
# name match (Task 6 review, CRITICAL) -------------------------------------

@pytest.mark.parametrize("value", [
    "__Host-csrf=t; Secure; Path=/",
    "__Secure-XSRF-TOKEN=t; Secure",
    "phpbb3_csrf_sid=t; Secure; SameSite=Lax",
])
def test_the_csrf_exemption_dominates_prefix_and_session_name_for_httponly(value):
    # The exemption has to beat every INFERENCE signal, not just the plain
    # name match that decides whether it applies: OWASP's CSRF cheat sheet
    # recommends exactly the __Host-/__Secure- prefixed form for this cookie
    # (Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md:494-514) and says
    # at :114/:605 it is deliberately not HttpOnly. Letting `prefix` or a
    # session-name pattern re-escalate it -- `phpbb3_csrf_sid` matches
    # `phpbb3_*_sid` -- would reintroduce the exact false positive the
    # name-based exemption exists to prevent.
    finding = _find(value, "cookie-no-httponly")
    assert finding.level == "note"
    assert finding.data["evidence"] == []


@pytest.mark.parametrize("name", ["__Host-csrf", "__Secure-XSRF-TOKEN", "phpbb3_csrf_sid"])
def test_the_csrf_exemption_still_lets_secure_escalate_on_the_same_names(name):
    # The dominance is scoped to HttpOnly's row -- Secure's row still reads
    # `prefix`/`session-name` normally for the very same cookie names.
    assert _find("%s=t; SameSite=Lax" % name, "cookie-no-secure").level == "warning"


# --- fix round: evidence ordering is load-bearing and must be pinned
# (Task 6 review, IMPORTANT 2) ----------------------------------------------

def test_a_misspelling_outranks_a_second_signal_on_the_same_cookie():
    # A single-signal typo case cannot tell "worst-first" from "sorted": both
    # orderings put the lone entry at [0]. PHPSESSID also being a known
    # session name is what makes the ordering actually load-bearing --
    # sorted() puts "session-name" before "typo:secure" alphabetically and
    # would silently drop this to a warning.
    finding = _find("PHPSESSID=x; Secrue", "cookie-no-secure")
    assert finding.level == "error"
    assert finding.data["evidence"][0].startswith("typo:")


# --- fix round: cookie-persistent must not fire on a deletion
# (Task 6 review, IMPORTANT 3) ----------------------------------------------

@pytest.mark.parametrize("value", [
    "x=y; Max-Age=0; Secure",
    "x=y; Max-Age=-1; Secure",
    "x=y; Max-Age=abc; Secure",
    "x=y; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure",
])
def test_a_deletion_is_never_reported_as_persistent(value):
    # rfc6265bis: only `delta-seconds <= 0` asks for immediate deletion. An
    # unparseable Max-Age is not a deletion at all -- algorithm [8] ignores
    # the cookie-av -- and `Max-Age=abc` alone is exempt for the other
    # reason: with the av ignored and no Expires beside it, nothing sets an
    # expiry, so the cookie is session-scoped. The loudest instance of the
    # original bug was PHPSESSID/sessionid-shaped logout responses, since
    # those names are also on the escalation list -- the most common CORRECT
    # case on the web.
    assert "cookie-persistent" not in _codes(value)


def test_a_genuinely_persistent_cookie_still_fires():
    assert "cookie-persistent" in _codes("x=y; Max-Age=86400; Secure")


# --- fix round: tier 2 must not contradict tier 1 on the same response
# (Task 6 review, IMPORTANT 4) -----------------------------------------------

def test_samesite_none_without_secure_is_rejected_not_hardened():
    # Chrome/Firefox reject SameSite=None without Secure outright
    # (cookie-samesite-none-insecure, tier 1); a tier-2 fact about what a
    # cross-site-sent cookie "does" would contradict that on the same
    # response.
    codes = _codes("a=b; SameSite=None")
    assert "cookie-samesite-none-insecure" in codes
    assert "cookie-samesite-none" not in codes


def test_samesite_none_with_secure_is_still_hardened():
    assert "cookie-samesite-none" in _codes("a=b; SameSite=None; Secure")


def test_a_mismatched_domain_is_rejected_not_hardened():
    # Domain=evil.example on a www.example.com response is rejected outright
    # by browsers (cookie-domain-mismatch, tier 1); tier 2's "every subdomain
    # receives it" is meaningless for a cookie that was never set.
    codes = _codes("a=b; Domain=evil.example", host="www.example.com")
    assert "cookie-domain-mismatch" in codes
    assert "cookie-domain-broad" not in codes


def test_a_matching_domain_is_still_hardened():
    assert "cookie-domain-broad" in _codes("a=b; Domain=example.com; Secure",
                                           host="www.example.com")


# --- cookie-unknown-attribute ------------------------------------------------

def test_an_unrecognised_attribute_is_reported():
    finding = _find("a=b; Secure; HttpOnly; SameSite=Lax; Version=1",
                    "cookie-unknown-attribute")
    assert finding.data["attribute"] == "version"
    assert "suspected" not in finding.data
    assert finding.level is None            # fixed at its default, never escalated


def test_the_suspected_correction_is_carried_when_there_is_one():
    finding = _find("a=b; HttpOnly; SameSite=Lax; Secrue",
                    "cookie-unknown-attribute")
    assert finding.data["suspected"] == "Secure"


@pytest.mark.parametrize("typo,spelling", [
    ("Secrue", "Secure"), ("Httponyl", "HttpOnly"), ("Smaesite", "SameSite"),
])
def test_the_suspected_correction_is_spelled_canonically(typo, spelling):
    # `suspected` names the attribute the author MEANT to write, and nobody
    # writes `httponly`. The written name in `attribute` stays lowercased,
    # because that is the wire as the parser read it -- one key is this
    # package's inference, the other is what arrived (final review, M5).
    finding = _find("a=b; %s" % typo, "cookie-unknown-attribute")
    assert finding.data["suspected"] == spelling
    assert finding.data["attribute"] == typo.lower()


def test_no_correction_is_suspected_when_the_real_attribute_is_also_present():
    # `Secure; Secrue` has the protection already -- the typo cost nothing --
    # so absent_from must be computed from THIS cookie's own attributes, not
    # from the closed KNOWN_ATTRIBUTES set the misspelling is tested against.
    finding = _find("a=b; Secure; HttpOnly; SameSite=Lax; Secrue",
                    "cookie-unknown-attribute")
    assert "suspected" not in finding.data


@pytest.mark.parametrize("attribute", ["path", "domain", "expires", "max-age",
                                        "secure", "httponly", "samesite",
                                        "partitioned", "priority"])
def test_no_recognised_attribute_is_reported(attribute):
    # priority is the one that matters: Chrome-proprietary and never
    # standardised, but Google sends it, so an rfc6265bis-derived set would
    # fire on some of the most visited responses on the web.
    value = "a=b; Secure; HttpOnly; SameSite=Lax; %s=1" % attribute
    assert "cookie-unknown-attribute" not in _codes(value)


def test_it_is_reported_on_an_infrastructure_cookie():
    # Never suppressed: what the response sent is a fact independent of
    # whether the cookie carries a credential, and legacy cruft like
    # Version=1 is likeliest on exactly these.
    assert "cookie-unknown-attribute" in _codes("AWSALB=x; Version=1")


def test_each_unrecognised_attribute_is_its_own_finding():
    findings = [f for f in _analyze("a=b; Secure; HttpOnly; SameSite=Lax; "
                                     "Version=1; Port=80")
                if f.code == "cookie-unknown-attribute"]
    assert {f.data["attribute"] for f in findings} == {"version", "port"}


@pytest.mark.parametrize("real", ["version", "comment", "commenturl",
                                   "discard", "port", "sameparty"])
def test_a_real_legacy_attribute_gets_no_suspected_correction(real):
    finding = _find("a=b; Secure; HttpOnly; SameSite=Lax; %s=1" % real,
                    "cookie-unknown-attribute")
    assert "suspected" not in finding.data


# --- final review, I1: httponly-set does not apply to the last three codes -
# Adding a hardening attribute must never make the tool louder. `httponly-set`
# means "the author hardened one flag and forgot another", and for these three
# nothing was forgotten -- the response asked for cross-site sending, an
# expiry, or a parent domain deliberately.

@pytest.mark.parametrize("value,code", [
    ("x=y; Domain=example.com; Secure", "cookie-domain-broad"),
    ("x=y; Max-Age=63072000; Secure", "cookie-persistent"),
    ("x=y; SameSite=None; Secure", "cookie-samesite-none"),
])
def test_adding_httponly_does_not_raise_the_other_three(value, code):
    assert _find(value, code, host="www.example.com").level == "note"
    hardened = _find("%s; HttpOnly" % value, code, host="www.example.com")
    assert hardened.level == "note"
    assert "httponly-set" not in hardened.data["evidence"]


def test_a_hardened_analytics_cookie_stays_at_the_floor():
    # The whole reported case: adding HttpOnly to `_ga` raised two unrelated
    # notes to warnings, so hardening a cookie made the tool complain more.
    value = ("_ga=x; Domain=.example.com; Max-Age=63072000; Secure; "
             "HttpOnly; SameSite=Lax")
    findings = _analyze(value, host="www.example.com")
    assert {f.code for f in findings} == {"cookie-persistent",
                                          "cookie-domain-broad"}
    assert all(f.level == "note" for f in findings)


def test_a_session_name_still_escalates_the_same_three():
    # The discrimination the ladder exists for: dropping httponly-set must not
    # flatten the ladder, only the row that did not apply.
    value = ("remember_user_token=x; Domain=.example.com; Max-Age=63072000; "
             "Secure; HttpOnly")
    for code in ("cookie-persistent", "cookie-domain-broad"):
        finding = _find(value, code, host="www.example.com")
        assert finding.level == "warning"
        assert finding.data["evidence"] == ["session-name"]


# --- final review, revised ruling: Expires is compared against the response's
# own Date, and an invalid Max-Age is av-ignored rather than a deletion -------

_ASPNET = ("ASP.NET_SessionId=; expires=Sat, 30 Aug 2025 12:00:00 GMT; "
           "secure; HttpOnly; SameSite=Lax")


def test_a_past_expires_is_a_deletion_when_the_response_dates_itself():
    # The canonical ASP.NET Framework delete is Expires = Now.AddDays(-1) with
    # no Max-Age -- an ordinary past date, not 1970, so the epoch cutoff read
    # it as persistence and escalated it, since asp.net_sessionid is on the
    # session-name list. `Date` is a fact IN the response, so this stays
    # clock-free: an archived report reaches the same verdict a year later.
    assert "cookie-persistent" not in _codes(
        _ASPNET, date="Sun, 31 Aug 2025 12:00:00 GMT")


def test_a_future_expires_is_still_persistent_beside_a_date():
    assert "cookie-persistent" in _codes(
        "x=y; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure",
        date="Sun, 31 Aug 2025 12:00:00 GMT")


def test_without_a_date_the_epoch_cutoff_is_all_there_is():
    # Stated so the residual is a recorded limit rather than a surprise: with
    # no Date to compare against, a past-but-not-epoch Expires still reads as
    # persistent.
    assert "cookie-persistent" in _codes(_ASPNET)


@pytest.mark.parametrize("date", [
    "not a date",
    ["Sun, 31 Aug 2025 12:00:00 GMT", "Mon, 01 Sep 2025 12:00:00 GMT"],
])
def test_an_unusable_date_falls_back_to_the_epoch_cutoff(date):
    # A Date nothing can be read from, and a repeated Date whose values
    # disagree -- no specification says which of those wins, so nothing can be
    # earned from it (response._sole_value's reasoning).
    assert "cookie-persistent" in _codes(_ASPNET, date=date)


def test_an_ignored_max_age_falls_through_to_expires():
    # rfc6265bis algorithm [8]: an invalid Max-Age means "ignore the
    # cookie-av", NOT an immediate deletion. So a future Expires beside it
    # still makes the cookie persistent -- previously silent.
    assert "cookie-persistent" in _codes(
        "x=y; Max-Age=abc; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure")


def test_a_valid_max_age_decides_alone():
    # The storage model reads Expires only in the ABSENCE of a Max-Age, so a
    # positive Max-Age beside an epoch Expires is persistent in every browser
    # -- previously silent.
    assert "cookie-persistent" in _codes(
        "x=y; Max-Age=100; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure")


@pytest.mark.parametrize("max_age", ["1_000", "+100", "1e3", "١٢٣", "²"])
def test_max_age_is_validated_against_digits_not_int(max_age):
    # int() is looser than `[ "-" ] 1*DIGIT`: it takes underscores, a leading
    # plus and other scripts' digits, every one of which a browser ignores as
    # an invalid av. (Surrounding whitespace is not on this list because
    # parse_set_cookie already strips it, as rfc6265bis 5.2 requires.) With no
    # Expires beside it, nothing sets an expiry at all, so the cookie is
    # session-scoped.
    assert "cookie-persistent" not in _codes("x=y; Max-Age=%s; Secure" % max_age)


@pytest.mark.parametrize("value", ["x=y; Max-Age; Secure", "x=y; Expires; Secure"])
def test_a_bare_lifetime_flag_sets_no_expiry(value):
    # The extreme form of the same rule: `Max-Age` and `Expires` written as
    # flags carry no value to parse, so no expiry is set and the cookie is not
    # persistent.
    assert "cookie-persistent" not in _codes(value)
