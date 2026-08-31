# Cookie Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse `Set-Cookie` and analyse it — a parsed cookie inventory plus sixteen finding codes, with severity able to vary per finding.

**Architecture:** A new core module `cookies.py` (stdlib only) holds the parser, the name-classification tables and the analysis; `response.py` calls it in two places. `Finding` grows a fourth field so one code can be rated differently per finding, which is what lets the same defect be a `note` on `lang=en` and a `warning` on `phpsessid` without minting two codes.

**Tech Stack:** Python standard library only. pytest. No new dependencies — the package has none at runtime and must keep none.

**Spec:** `docs/designs/2026-08-30-cookie-analysis.md` — read it before Task 1. The plan argues from the spec; where they disagree, the spec wins and the plan is wrong.

## Global Constraints

- **No agent runs any git command that writes state or discards working-tree content.** No `add`, `commit`, `stash`, `push`, `checkout -- <path>`, `restore`, `reset --hard`, `clean`. The human owns the git workflow entirely. Tasks end with a **Checkpoint** naming what is ready; the human commits. To restore a file broken on purpose during mutation testing, copy it out to `$SCRATCH` first and copy it back — never reach for git.
- **Standard library only** in `http_security_test/`. The sole third-party import in the package is the optional `hstspreload` in `hsts.py`; do not add a second.
- **`cookies.py` is `core`.** It may import `findings` and `message`. It must NOT import `response`, `catalog`, `adaptors` or `cli`. `response.py` imports `cookies.py`, so the reverse is a cycle. `test_imports_only_ever_run_downhill` enforces the layer rule.
- **No analyser imports `catalog.py`.** Analysers emit `(header, code, data)` and hold no prose. A test reads the syntax of every `Finding()` call to keep it that way.
- **Every emittable code needs four table entries in the same task that makes it emittable**: `FINDING_SEVERITY`, `CODE_HEADER`, `CODE_CONSEQUENCES` (in `findings.py`) and `MESSAGES` (in `catalog.py`). Four bijection tests go red otherwise, so a task that adds a code and defers its tables leaves the suite failing.
- **`tests/test_headers.py` has a hard severity census** in `test_severity_values_match_the_documented_policy`. Its current value is `{"error": 39, "warning": 26, "note": 37}`. Each code-adding task states the new value; update it in that task.
- **Run `ruff check` before every checkpoint. Do not run `ruff format`** — the human formats.
- **Mutation-test every new guard.** Break it, confirm a test fails, restore from `$SCRATCH`. A test that passes both ways is worse than none.
- Cookie names are **case-sensitive identifiers**; prefix and list *matching* is **case-insensitive**. Both, at once, everywhere.

---

### Task 1: Per-finding severity

`FINDING_SEVERITY` becomes a code's *default* rather than its only rating. Nothing cookie-specific; the rest of the plan depends on it.

**Files:**
- Modify: `http_security_test/findings.py` (the `Finding` namedtuple ~line 34; add `level_of` and `ESCALATABLE` near `severity` ~line 520)
- Modify: `http_security_test/reporting.py:140`
- Modify: `http_security_test/findings.py:531` (`order_findings`)
- Modify: `http_security_test/__init__.py` (export `level_of`)
- Test: `tests/test_headers.py`, `tests/test_reporting.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Finding(header, code, data=None, level=None)`; `level_of(finding) -> str`; `ESCALATABLE: frozenset[str]`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_headers.py`, near the other severity tests (after `test_severity_values_match_the_documented_policy`):

```python
def test_a_finding_without_a_level_uses_its_code_default():
    finding = headers.Finding("Strict-Transport-Security", "hsts-missing")
    assert headers.level_of(finding) == "error"


def test_a_finding_can_carry_its_own_level():
    finding = headers.Finding("Set-Cookie", "hsts-missing", {}, "note")
    assert headers.level_of(finding) == "note"
    # The table is untouched: the override is per finding, not per code.
    assert headers.severity("hsts-missing") == "error"


def test_identity_ignores_the_level():
    # Two findings that differ only in level are the same finding. The level is
    # always derived from `data`, so this can only happen by mistake.
    a = headers.Finding("Set-Cookie", "hsts-missing", {"cookie": "sid"}, "note")
    b = headers.Finding("Set-Cookie", "hsts-missing", {"cookie": "sid"}, "error")
    assert headers.identity(a) == headers.identity(b)


def test_every_escalatable_code_is_a_real_code():
    assert headers.ESCALATABLE <= set(headers.FINDING_SEVERITY)


def test_every_level_a_finding_carries_is_a_real_severity():
    # A typo'd level would sort wrong and render wrong, and nothing else would
    # notice: order_findings does SEVERITIES.index(...), which raises, and
    # --min-level compares an index. This is the guard for the whole corpus.
    for present, url in COOKIE_CASES:
        for finding in headers.analyze(_ex(present, url=url)):
            assert headers.level_of(finding) in headers.SEVERITIES
```

`COOKIE_CASES` does not exist until Task 5. Write this test now but mark it
`@pytest.mark.skip(reason="COOKIE_CASES lands in Task 5")`, and remove the
skip in Task 5 Step 7 when the corpus is added. Writing it now is what stops
it being forgotten; skipping it is what keeps the suite green in between.

In `tests/test_reporting.py`:

```python
def test_the_report_writes_a_findings_own_level():
    finding = headers.Finding("Set-Cookie", "hsts-missing", {}, "note")
    assert headers.finding_as_dict(finding, message=False)["level"] == "note"
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -m pytest tests/test_headers.py -k "level_of or carry_its_own_level or identity_ignores or escalatable" tests/test_reporting.py -k "own_level" -v`
Expected: FAIL — `AttributeError: module 'http_security_test' has no attribute 'level_of'`, and `TypeError` on the four-argument `Finding`.

- [ ] **Step 3: Widen `Finding` and add the resolver**

In `findings.py`, replace the `Finding` definition (keep the comment above it, extend it):

```python
# A finding is a header, a stable code, the values that made it true, and
# optionally its own level. `level=None` means "use FINDING_SEVERITY", which is
# the code's default and not its only possible rating: one defect can be worth
# more on one cookie than on another, and that is a rating rather than a
# different fact. This is SARIF's shape -- `result.level` overrides
# `rule.defaultConfiguration.level` -- and the report schema was already on
# this side of the line, denormalising `level` onto every finding.
Finding = collections.namedtuple("Finding", "header code data level",
                                defaults=(None, None))
```

`identity()` needs no change: it reads `header`, `code` and `data` only. Leave it alone and add to its docstring:

```python
    The level is deliberately not part of it. A level is always derived from
    `data`, so two findings with the same identity cannot disagree about it.
```

After `def severity(code):`, add:

```python
# Codes whose level can be raised above their default by evidence in `data`.
# `hst explain` reads this so it can say the level it prints is a floor.
ESCALATABLE = frozenset()


def level_of(finding):
    """A finding's level: its own if it carries one, else its code's default.

    `severity()` answers about a *code* and stays the public spelling of that
    question. This answers about a *finding*, which is what a renderer wants.
    """
    return finding.level or severity(finding.code)
```

- [ ] **Step 4: Route the two consumers through it**

`findings.py:531`, in `order_findings`:

```python
    return sorted(findings, key=lambda f: SEVERITIES.index(level_of(f)))
```

`reporting.py:140`, in `finding_as_dict`:

```python
        "level": level_of(finding),
```

and change its import from `severity` to `level_of` (`severity` is no longer used there — check with `grep -n severity http_security_test/reporting.py` and remove it from the import list if unused, or `ruff check` will flag it).

`__init__.py`: add `level_of` to the `from .findings import (...)` block and to `__all__`, both alphabetically.

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest tests/ -q && ruff check`
Expected: all pass. 613 tests plus the five added here.

- [ ] **Step 6: Mutation-test the resolver**

```bash
SCRATCH=/tmp/cookie-plan && mkdir -p "$SCRATCH"
cp http_security_test/findings.py "$SCRATCH/"
# Mutate: make level_of ignore the override.
#   return severity(finding.code)
python -m pytest tests/ -q          # must FAIL: two tests above
cp "$SCRATCH/findings.py" http_security_test/findings.py
python -m pytest tests/ -q          # green again
```

Expected: the mutation fails `test_a_finding_can_carry_its_own_level` and `test_the_report_writes_a_findings_own_level`. If it passes, the tests are not pinning the behaviour — fix them before continuing.

- [ ] **Step 7: Checkpoint**

Ready to commit: `findings.py`, `reporting.py`, `__init__.py`, `tests/test_headers.py`, `tests/test_reporting.py`. Suggested message: `feat: allow a finding to carry its own severity level`. **Do not run git** — tell the human it is ready.

---

### Task 2: The `Set-Cookie` parser

Parsing only. No findings, no tables, no analysis.

**Files:**
- Create: `http_security_test/cookies.py`
- Test: `tests/test_cookies.py` (new)

**Interfaces:**
- Consumes: `Finding` from Task 1 (imported but not yet used); `message` for nothing yet.
- Produces: `Cookie = namedtuple("Cookie", "name value attributes raw")`; `parse_set_cookie(value) -> Cookie`; `parse_cookies(present) -> tuple[Cookie, ...]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_cookies.py`. Copy the GPL notice header from `tests/test_headers.py` verbatim first (every source file in this project carries it).

```python
import pytest

from http_security_test import cookies


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
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -m pytest tests/test_cookies.py -v`
Expected: FAIL at import — `ImportError: cannot import name 'cookies'`.

- [ ] **Step 3: Write the module**

Create `http_security_test/cookies.py`. Start with the GPL notice header copied verbatim from `http_security_test/hsts.py`, then:

```python
"""Set-Cookie: the cookies a response sets, and what is wrong with them.

One header is many subjects here. `Set-Cookie` may legally repeat and each
value is an unrelated cookie, so a finding names one of them in `data` and the
same code fires once per cookie -- which is what `identity()` was widened to
allow.

Parsing follows draft-ietf-httpbis-rfc6265bis 5.2 literally and never fails:
the inventory reports what the response sent, and the findings report what a
browser does with it. A value carrying a control character is still a cookie
here; it is `cookie-control-character` that says the browser discards it.
"""

import collections

from .findings import Finding

# One cookie as the wire carried it. `attributes` is the lowercased attribute
# mapping with flags mapping to None -- the convention hsts._parse_directives()
# already uses -- and holds EVERY attribute, recognised or not. `raw` is the
# header value verbatim, because a parsed model is lossy about attribute order,
# casing and repeats and the inventory promises what the response carried.
Cookie = collections.namedtuple("Cookie", "name value attributes raw")


def parse_set_cookie(value):
    """One `Set-Cookie` value as a Cookie. Never returns None.

    Returning None for a value a browser discards was the obvious alternative
    and it makes the inventory lie: a cookie the server really sent would
    vanish, indistinguishable from a response that sent none.
    """
    head, _, unparsed = value.partition(";")
    name, found, cookie_value = head.partition("=")
    if not found:
        # rfc6265bis 5.2 step 3: no '=' means an empty name and the whole
        # string as the value.
        name, cookie_value = "", head
    attributes = {}
    for chunk in unparsed.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        key, has_value, attribute_value = chunk.partition("=")
        key = key.strip().lower()
        if not key:
            continue
        attributes[key] = attribute_value.strip() if has_value else None
    return Cookie(name.strip(), cookie_value.strip(), attributes, value)


def parse_cookies(present):
    """Every cookie the response set, in the order the header carried them.

    A tuple rather than a mapping: one response may set the same name twice and
    a mapping would silently drop one.
    """
    return tuple(parse_set_cookie(v) for v in present.get("set-cookie", ()))
```

- [ ] **Step 4: Run the tests**

Run: `python -m pytest tests/test_cookies.py -v && ruff check`
Expected: all 13 PASS. `ruff check` will flag `Finding` as imported and unused — that is expected at this stage; add `# noqa: F401` with the comment `# used from Task 5 onward` if it blocks, and remove the noqa in Task 5.

- [ ] **Step 5: Check the parser against an independent corpus**

`security/cryptoparser`'s `test/httpx/test_header.py` is 1143 lines of real
header values with their expected parses — the only per-header parse corpus on
disk that is not this package's own, so it is a free source of awkward inputs.
Read only; do not copy it, and note it implements **none** of the four cookie
prefixes, so it is a source of parse cases and not of rules.

```bash
grep -n -i 'set.cookie' /home/crapula/ref/security/cryptoparser/test/httpx/test_header.py | head -40
```

For each distinct `Set-Cookie` value it exercises, run it through
`parse_set_cookie` and confirm the name, value and attributes come out as that
test expects. Add any value that disagrees, or that this plan's tests do not
already cover, as a case in `tests/test_cookies.py` with a comment naming
where it came from. If everything agrees, add nothing and say so at the
checkpoint — a corpus that finds no bug is still evidence.

**Do not run any git command in `/home/crapula/ref`.** That tree is read-only:
the human maintains it with their own tooling.

- [ ] **Step 6: Verify the layer rule still holds**

Run: `python -m pytest tests/test_cli_structure.py -v`
Expected: PASS. `cookies.py` imports only `collections` and `.findings`, both at or below its layer.

- [ ] **Step 7: Checkpoint**

Ready to commit: `http_security_test/cookies.py`, `tests/test_cookies.py`. Suggested message: `feat: parse Set-Cookie per rfc6265bis 5.2`.

---

### Task 3: Name classification and the typo metric

Pure functions and tables. Still no findings.

**Files:**
- Modify: `http_security_test/cookies.py`
- Test: `tests/test_cookies.py`

**Interfaces:**
- Consumes: `Cookie` from Task 2.
- Produces, all module-level in `cookies.py`:
  - Tables: `KNOWN_ATTRIBUTES`, `TYPO_SENSITIVE_ATTRIBUTES`, `COOKIE_PREFIXES`, `_PREFIX_SPELLING`, `PREFIX_REQUIREMENTS`, `SESSION_NAMES`, `SESSION_PATTERNS`, `INFRASTRUCTURE_NAMES`, `INFRASTRUCTURE_PATTERNS`, `CSRF_FRAGMENTS`.
  - Public: `strip_prefix(name) -> str`; `is_session_name(name) -> bool`; `is_infrastructure_name(name) -> bool`; `osa_distance(a, b) -> int`; `suspected_attribute(name, absent_from) -> str | None`.
  - Private: `_matches(name, names, patterns) -> bool`. Task 5 and Task 6 call the public four and `PREFIX_REQUIREMENTS`; nothing outside this module calls `_matches`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cookies.py`:

```python
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
                                   "incap_ses_123_456", "visid_incap_789",
                                   "whostmgrsession"])
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
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -m pytest tests/test_cookies.py -k "osa or recognised or suspected or strip_prefix or session_name or infrastructure" -v`
Expected: FAIL — `AttributeError: module ... has no attribute 'osa_distance'`.

- [ ] **Step 3: Add the tables**

Append to `cookies.py`:

```python
# The attribute names browsers recognise: Chromium's nine
# (net/cookies/parsed_cookie.cc:62-70), a superset of Firefox's eight
# (netwerk/cookie/CookieParser.cpp:306-315). NOT rfc6265bis's list, which omits
# `priority` -- Chrome-proprietary, never standardised, and sent by Google's own
# cookies, so reporting it would fire on some of the most visited responses on
# the web. Firefox ignoring it is why it is recognised rather than reported: a
# value this package cannot fault Chrome for reading is not a defect anywhere.
KNOWN_ATTRIBUTES = frozenset([
    "path", "domain", "expires", "max-age", "secure", "httponly",
    "samesite", "partitioned", "priority",
])

# The three attributes whose misspelling fails OPEN. A misspelled Expires or
# Max-Age makes the cookie session-scoped, a misspelled Path narrows it to the
# request directory, a misspelled Domain makes it host-only: all leave the
# cookie MORE restricted, so rating one an error would assert a defect that
# does not exist.
TYPO_SENSITIVE_ATTRIBUTES = ("secure", "httponly", "samesite")

# The canonical spelling of each prefix, for a message that reads the way the
# author wrote it. Keyed by the lowercased form the matcher uses.
_PREFIX_SPELLING = {
    "__secure-": "__Secure-",
    "__http-": "__Http-",
    "__host-": "__Host-",
    "__host-http-": "__Host-Http-",
}

# Longest-prefix-first: `__Host-Http-` must be tested before `__Host-`, which
# it starts with. Both engines order their tables this way and both carry a
# comment saying why -- a naive startswith("__Host-") classifies
# `__Host-Http-sid` as `__Host-` and then fails to require HttpOnly, a false
# negative that looks like a pass. Matching is case-INSENSITIVE (rfc6265bis
# 5.4, normative for UAs); cookie NAMES stay case-sensitive.
COOKIE_PREFIXES = ("__host-http-", "__secure-", "__host-", "__http-")

# What each prefix requires. All four build on __Secure-, and __Host-Http- is
# the conjunction of the two below it: a lattice, not a chain, so __Host- does
# NOT imply HttpOnly.
PREFIX_REQUIREMENTS = {
    "__secure-": ("secure",),
    "__http-": ("secure", "httponly"),
    "__host-": ("secure", "path", "domain"),
    "__host-http-": ("secure", "httponly", "path", "domain"),
}

# Names that raise a hardening finding above its floor. Every entry is the
# default session cookie of software deployed by parties other than its vendor
# -- the axis is not framework-versus-vendor but whether the name can appear on
# a host the vendor does not control. Completeness is an explicit non-goal:
# selfh.st catalogues ~1500 self-hosted applications, misses cost a `note`
# rather than silence, and the list is bounded by reach. See the spec.
SESSION_NAMES = frozenset([
    # frameworks and runtimes
    "phpsessid", "jsessionid", "asp.net_sessionid", "aspsessionid",
    "cfid", "cftoken", "cgisessid", "sessionid", "session_id", "_session_id",
    "_rails_session", "laravel_session", "ci_session", "connect.sid",
    "express_sid", "rack.session", "play_session",
    # identity servers
    "keycloak_session", "auth_session_id", "auth_session_id_legacy",
    # transparent generic names: absent from Open-Cookie-Database's 2266 rows
    # and semantically unambiguous. `token` FAILS that test -- Adform uses it.
    "sid", "sessid", "jwt",
    # self-hosted applications
    "plesksessid", "phpmyadmin", "zenid", "siteserver", "whostmgrsession",
    "xf_session", "grafana_session", "i_like_gitea", "_redmine_session",
    "_mastodon_session", "mmauthtoken", "nc_session_id", "oc_sessionpassphrase",
    # persistent authentication tokens
    "remember_user_token", "xf_tfa_trust", "gitea_incredible", "nc_token",
])

# Anchored glob patterns, `*` only. A pattern must be anchored at both ends or
# be a prefix containing a literal that identifies one piece of software. A
# pattern anchored at NEITHER end is forbidden: `*session*` is expressible and
# must never be written -- measured at 65% precision for `*_session`, 50% for
# `*_sess` and `*sessid`, because the analytics industry names visit-tracking
# cookies exactly as authentication cookies are named.
SESSION_PATTERNS = (
    "wordpress_logged_in_*",
    "wp_woocommerce_session_*",
    "cpsession*",
    "phpbb3_*_sid",          # the prefix is randomised at install
)

# Names that emit NO hardening finding: set by infrastructure, carrying a
# routing or bot-detection identifier rather than a user credential.
# Membership -- the stricter of the two bars, because a wrong entry here
# silences a finding absolutely: vendor-specific, and the attribution on disk.
INFRASTRUCTURE_NAMES = frozenset([
    "awsalb", "awsalbcors", "awsalbtg", "awsalbtgcors", "awselb", "awselbcors",
    "arraffinity", "arraffinitysamesite", "__cflb", "__cf_bm",
    "ak_bmsc", "bm_sv", "_abck",
])

INFRASTRUCTURE_PATTERNS = (
    "bigipserver*", "nsc_*", "incap_ses_*", "visid_incap_*",
)

# A CSRF token cookie without HttpOnly is a CORRECT configuration: the
# cookie-to-header pattern requires JavaScript to read it. OWASP's CSRF
# cheat sheet writes the counter-example as literal sample code, and OpenID
# Connect Session Management 1.0 says the same of the OP state cookie. The
# exemption is not about CSRF specifically -- it is about cookies whose own
# specification requires script access.
CSRF_FRAGMENTS = ("csrf", "xsrf")
```

- [ ] **Step 4: Add the functions**

```python
def strip_prefix(name):
    """`name` with any cookie-name prefix removed, longest first.

    `__Secure-PHPSESSID` is a literal Open-Cookie-Database entry, so the idiom
    occurs and an exact match against the undecorated name would miss it.
    """
    lowered = name.lower()
    for prefix in COOKIE_PREFIXES:
        if lowered.startswith(prefix):
            return name[len(prefix):]
    return name


def _matches(name, names, patterns):
    """Whether a lowercased name is in `names` or matches one of `patterns`."""
    lowered = name.lower()
    if lowered in names:
        return True
    return any(fnmatch.fnmatchcase(lowered, pattern) for pattern in patterns)


def is_session_name(name):
    """Whether the name is a known session or authentication cookie name."""
    return _matches(strip_prefix(name), SESSION_NAMES, SESSION_PATTERNS)


def is_infrastructure_name(name):
    """Whether the name is a known routing or bot-detection cookie name."""
    return _matches(name, INFRASTRUCTURE_NAMES, INFRASTRUCTURE_PATTERNS)


def osa_distance(a, b):
    """Optimal String Alignment distance -- Damerau restricted to adjacent swaps.

    Not Levenshtein, and this is measured rather than chosen: of 21 realistic
    cookie-attribute typos, 8 are OSA 1 and Levenshtein 2, every one a
    transposition -- `secrue`, `secuer`, `httponyl`, `httpolny`, `smaesite`,
    `expries`, `domian`, `paht`. A plain-Levenshtein threshold of 1 misses
    about 40% of real typos, including the likeliest misspelling of the most
    important attribute. Restricting to adjacent swaps costs nothing: typos in
    an eight-character token are adjacent.
    """
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
            if (i > 1 and j > 1
                    and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]):
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[-1][-1]


def suspected_attribute(name, absent_from):
    """The security attribute `name` is probably a misspelling of, or None.

    Two guards, and the second keeps the first honest. Only the three
    attributes whose misspelling fails open are considered, and only when the
    real attribute is absent from this cookie -- `Secure; Secrue` has the
    protection, so the typo cost nothing.
    """
    if name in KNOWN_ATTRIBUTES:
        return None
    for attribute in TYPO_SENSITIVE_ATTRIBUTES:
        if attribute in absent_from and osa_distance(name, attribute) <= 1:
            return attribute
    return None
```

Add `import fnmatch` to the module's imports, above `import collections` (alphabetical).

- [ ] **Step 5: Run the tests**

Run: `python -m pytest tests/test_cookies.py -v && ruff check`
Expected: all PASS.

- [ ] **Step 6: Mutation-test the metric — this is the important one**

```bash
cp http_security_test/cookies.py "$SCRATCH/"
# Mutate: delete the transposition branch in osa_distance (the `if i > 1 and
# j > 1 ...` block), making it plain Levenshtein.
python -m pytest tests/test_cookies.py -q
```
Expected: FAIL on the eight transposition cases. **If it passes, stop** — the metric is not pinned and a future refactor can silently break it. Restore with `cp "$SCRATCH/cookies.py" http_security_test/cookies.py`.

Then mutate `SESSION_PATTERNS` to add `"*session*"` and confirm `test_non_session_names_do_not_match` fails on `_hjSessionUser_1234`, `taboola_session_id` and `ai_session`. Restore.

- [ ] **Step 7: Checkpoint**

Ready to commit: `http_security_test/cookies.py`, `tests/test_cookies.py`. Suggested message: `feat: cookie name classification and typo metric`.

---

### Task 4: The `inventory.cookies` table

**Files:**
- Modify: `http_security_test/cookies.py`
- Modify: `http_security_test/response.py` (`inventory()`, ~line 1195; its docstring says "Five tables")
- Modify: `http_security_test/__init__.py`
- Test: `tests/test_cookies.py`, `tests/test_headers.py`, `tests/test_reporting.py`

**Interfaces:**
- Consumes: `parse_cookies`, `is_infrastructure_name` from Tasks 2–3.
- Produces: `cookie_as_dict(cookie) -> dict`; `inventory()` gains a `"cookies"` key holding `list[dict]`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cookies.py`:

```python
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
```

In `tests/test_headers.py`, near the other inventory tests:

```python
def test_the_inventory_has_a_cookies_table():
    present = {"Set-Cookie": ["sid=1; Secure", "lang=en"]}
    table = headers.inventory(_ex(present))["cookies"]
    assert [row["name"] for row in table] == ["sid", "lang"]
    assert table[0]["secure"] is True


def test_the_cookies_table_is_empty_when_the_response_sets_none():
    assert headers.inventory(_ex({}))["cookies"] == []


def test_the_cookies_table_keeps_both_of_a_repeated_name():
    present = {"Set-Cookie": ["sid=1; Path=/a", "sid=2; Path=/b"]}
    table = headers.inventory(_ex(present))["cookies"]
    assert [row["path"] for row in table] == ["/a", "/b"]
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -m pytest tests/test_cookies.py -k "as_dict or every_key or flags_are or unjudged or max_age or in_full" tests/test_headers.py -k "cookies_table" -v`
Expected: FAIL — no `cookie_as_dict`, and `KeyError: 'cookies'`.

- [ ] **Step 3: Add `cookie_as_dict`**

Append to `cookies.py`:

```python
def cookie_as_dict(cookie):
    """One cookie as plain data for the inventory.

    Derived keys are always present -- None for an absent value attribute,
    False for an absent flag, since a flag's absence is known rather than
    unknown. `raw` rides along because a parsed model is lossy about attribute
    order, casing, repeats and anything unrecognised, and the inventory
    promises what the response carried.

    `judged` records whether hardening findings were considered for this
    cookie at all, so a suppression is auditable rather than invisible: a
    reader who wonders why an infrastructure cookie has no finding despite
    lacking Secure can see the tool decided rather than missed it.

    The value is carried in full. This package does not redact -- principle 2,
    and redaction before anything reaches a report is the caller's business.
    """
    attributes = cookie.attributes
    return {
        "name": cookie.name,
        "value": cookie.value,
        "secure": "secure" in attributes,
        "httponly": "httponly" in attributes,
        "samesite": attributes.get("samesite"),
        "path": attributes.get("path"),
        "domain": attributes.get("domain"),
        "expires": attributes.get("expires"),
        "max_age": attributes.get("max-age"),
        "partitioned": "partitioned" in attributes,
        "judged": not is_infrastructure_name(cookie.name),
        "raw": cookie.raw,
    }


def cookie_inventory(present):
    """Every cookie the response set, as plain data, in header order."""
    return [cookie_as_dict(c) for c in parse_cookies(present)]
```

- [ ] **Step 4: Wire it into `inventory()`**

In `response.py`, add `from . import cookies` to the imports (alphabetical among the relative imports), and add the key at the end of the returned dict in `inventory()`:

```python
        "caching": _filter_headers(present, CACHE_HEADERS),
        "cookies": cookies.cookie_inventory(present),
    }
```

Update `inventory()`'s docstring: change "Five tables, and the split between them is the point." to "Six tables, and the split between them is the point." and add a paragraph before the `Content-Type` one:

```
    `cookies` is the sixth and the only one that is a list of parsed objects
    rather than a header-name mapping. `Set-Cookie` may legally repeat and each
    value is an unrelated cookie, so a mapping keyed by name would drop one of
    two cookies sharing a name. It deliberately does NOT also appear under
    `security`: the parsed rows carry `raw` already, and the same content in
    two places is what the `references` design rejected.
```

In `__init__.py`, nothing new is exported — `inventory` already is. Confirm with `grep -n '"inventory"' http_security_test/__init__.py`.

- [ ] **Step 5: Run the suite**

Run: `python -m pytest tests/ -q && ruff check`
Expected: all pass. If `tests/test_reporting.py` asserts an exact set of inventory keys, update it to include `cookies` — search with `grep -n "caching" tests/test_reporting.py tests/test_headers.py`.

- [ ] **Step 6: Verify a well-configured cookie is visible**

Run:
```bash
python -c "
from http_security_test import Exchange, Request, Response, report
import json
ex = Exchange(Request.from_parts(url='https://example.com/'),
              Response.from_parts(status=200, headers=[
                  ('Set-Cookie', '__Host-sid=x; Path=/; Secure; HttpOnly; SameSite=Strict')]))
print(json.dumps(report(ex)['response']['inventory']['cookies'], indent=2))"
```
Expected: one row, every key present, `judged: true`. This is the case the table exists for — a correct cookie raises no finding, and without the inventory it would leave no trace in the report at all.

- [ ] **Step 7: Checkpoint**

Ready to commit: `cookies.py`, `response.py`, the two test files. Suggested message: `feat: inventory the cookies a response sets`.

---

### Task 5: Tier 1 — the nine codes where a browser rejects or degrades the cookie

All `error`, all fixed-rating, all firing on every cookie including infrastructure ones. Adds the two consequence slugs, because these codes reference them.

**Files:**
- Modify: `http_security_test/cookies.py`
- Modify: `http_security_test/findings.py` (`FINDING_SEVERITY`, `CODE_HEADER`, `CODE_CONSEQUENCES`)
- Modify: `http_security_test/catalog.py` (`MESSAGES`, `CONSEQUENCES`)
- Modify: `http_security_test/references.py` (`_MDN`)
- Modify: `http_security_test/response.py` (`analyze()`)
- Test: `tests/test_cookies.py`, `tests/test_headers.py`

**Interfaces:**
- Consumes: everything from Tasks 2–4.
- Produces: `analyze_cookies(present, trustworthy, host) -> list[Finding]`.

- [ ] **Step 1: Add the two consequence slugs first**

In `catalog.py`, add to `CONSEQUENCES` (alphabetically among the existing eight):

```python
    "session-theft": Consequence(
        "Session token theft",
        ("CWE-1004", "CAPEC-31"),
        "An attacker could obtain the cookie carrying this session and act as "
        "the user without their credentials. Whether the cookie carries a "
        "session is not determined here.",
    ),
    "csrf": Consequence(
        "Cross-site request forgery",
        ("CWE-352", "CAPEC-62"),
        "Another site could cause the browser to make an authenticated "
        "request to this origin using the user's own cookies. Whether the "
        "application has a state-changing endpoint that would accept one is "
        "not determined here.",
    ),
```

Both closing sentences follow the house rule: a hint about potential risk, never a claim it is reachable. CAPEC ids were chosen by cross-reference to the CWE, not by name match.

- [ ] **Step 2: Write the failing tests**

Append to `tests/test_cookies.py`. `_analyze` is a helper defined here:

```python
def _analyze(value, trustworthy=True, host="example.com"):
    present = {"set-cookie": [value] if isinstance(value, str) else list(value)}
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
    assert _codes("__Host-sid=x; Secure; Path=/") == []


def test_host_prefix_tolerates_domain_on_an_ip_literal_host():
    # Chromium HasValidHostPrefixAttributes (cookie_util.cc:120). Refusing it
    # would be a false positive on a configuration Chrome accepts.
    assert "cookie-prefix-violated" not in _codes(
        "__Host-sid=x; Secure; Path=/; Domain=127.0.0.1", host="127.0.0.1")


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
```

- [ ] **Step 3: Run them to verify they fail**

Run: `python -m pytest tests/test_cookies.py -v`
Expected: FAIL — no `analyze_cookies`.

- [ ] **Step 4: Implement `analyze_cookies` and its tier-1 rules**

Append to `cookies.py`. Add `import re` to the imports.

```python
# rfc6265bis 5.2 step 1: a set-cookie-string containing any of these is
# ignored entirely. HTAB (%x09) is excluded, so it is NOT in the class.
_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")

# rfc6265bis 5.2 step 5.
MAX_NAME_VALUE_OCTETS = 4096

# rfc6265bis algorithm [11]. Anything else sets enforcement to "Default",
# which is Lax in Chrome and no restriction at all in Firefox and Safari
# release -- so an unrecognised value is not a synonym for None.
SAMESITE_VALUES = frozenset(["none", "lax", "strict"])


def _octets(text):
    return len(text.encode("utf-8", "surrogateescape"))


def _prefix_of(name):
    """The cookie-name prefix `name` carries, longest first, or None."""
    lowered = name.lower()
    for prefix in COOKIE_PREFIXES:
        if lowered.startswith(prefix):
            return prefix
    return None


def _unmet_prefix_requirements(cookie, prefix, trustworthy, host):
    """Which of a prefix's requirements this cookie fails to meet."""
    attributes = cookie.attributes
    unmet = []
    for requirement in PREFIX_REQUIREMENTS[prefix]:
        if requirement == "secure":
            if "secure" not in attributes or not trustworthy:
                unmet.append("secure")
        elif requirement == "httponly":
            if "httponly" not in attributes:
                unmet.append("httponly")
        elif requirement == "path":
            if attributes.get("path") != "/":
                unmet.append("path")
        elif requirement == "domain":
            domain = attributes.get("domain")
            # Chromium tolerates Domain when the host is an IP literal equal
            # to it (cookie_util.cc:120); refusing that would be a false
            # positive on a configuration Chrome accepts.
            if domain and not (host and domain == host and _is_ip_literal(host)):
                unmet.append("domain")
    return unmet


def _is_ip_literal(host):
    octets = host.split(".")
    if len(octets) == 4 and all(o.isdigit() for o in octets):
        return True
    return host.startswith("[") and host.endswith("]")


def _domain_matches(domain, host):
    """Whether a Domain attribute could apply to this host.

    Suffix comparison only. Whether the domain is over-BROAD needs a public
    suffix list and is deliberately out of scope; whether it matches at all
    does not.
    """
    domain = domain.lstrip(".").lower()
    host = host.lower()
    return host == domain or host.endswith("." + domain)


def _analyze_one(cookie, trustworthy, host):
    """Tier 1: what a browser does with this cookie that the server did not ask for."""
    findings = []
    attributes = cookie.attributes
    secure = "secure" in attributes
    name = cookie.name

    if _CONTROL.search(cookie.raw):
        findings.append(Finding("Set-Cookie", "cookie-control-character",
                                {"cookie": name}))

    octets = _octets(name) + _octets(cookie.value)
    if octets > MAX_NAME_VALUE_OCTETS:
        findings.append(Finding("Set-Cookie", "cookie-oversized",
                                {"cookie": name, "octets": octets}))

    samesite = attributes.get("samesite")
    if samesite is not None and samesite.lower() not in SAMESITE_VALUES:
        findings.append(Finding("Set-Cookie", "cookie-samesite-invalid",
                                {"cookie": name, "value": samesite}))
    elif samesite is not None and samesite.lower() == "none" and not secure:
        findings.append(Finding("Set-Cookie", "cookie-samesite-none-insecure",
                                {"cookie": name}))

    if secure and not trustworthy:
        findings.append(Finding("Set-Cookie", "cookie-secure-over-plaintext",
                                {"cookie": name}))

    if "partitioned" in attributes and not secure:
        findings.append(Finding("Set-Cookie", "cookie-partitioned-insecure",
                                {"cookie": name}))

    prefix = _prefix_of(name)
    if prefix is not None:
        unmet = _unmet_prefix_requirements(cookie, prefix, trustworthy, host)
        if unmet:
            findings.append(Finding("Set-Cookie", "cookie-prefix-violated",
                                    {"cookie": name,
                                     "prefix": _PREFIX_SPELLING[prefix],
                                     "unmet": unmet}))

    if not name:
        hidden = _prefix_of(cookie.value.lstrip(" \t"))
        if hidden is not None:
            findings.append(Finding("Set-Cookie", "cookie-hidden-prefix",
                                    {"cookie": name,
                                     "prefix": _PREFIX_SPELLING[hidden]}))

    domain = attributes.get("domain")
    if domain and host and not _domain_matches(domain, host):
        findings.append(Finding("Set-Cookie", "cookie-domain-mismatch",
                                {"cookie": name, "domain": domain, "host": host}))

    return findings


def analyze_cookies(present, trustworthy, host):
    """Every cookie finding for one response.

    `trustworthy` is the caller's answer to "was this response from a
    potentially-trustworthy origin" -- https, or a loopback host. It is passed
    in rather than derived because the loopback predicate lives in
    `response.py`, which imports this module: deriving it here would be a
    cycle. Both engines carve loopback out (Chromium
    ProvisionalAccessScheme, cookie_util.cc:709), so testing the scheme alone
    would fire on every developer running against http://localhost.
    """
    findings = []
    for cookie in parse_cookies(present):
        findings.extend(_analyze_one(cookie, trustworthy, host))
    return findings
```

- [ ] **Step 5: Add the table entries**

`findings.py` — `FINDING_SEVERITY`, in the `error` block:

```python
    "cookie-control-character": "error",
    "cookie-domain-mismatch": "error",
    "cookie-hidden-prefix": "error",
    "cookie-oversized": "error",
    "cookie-partitioned-insecure": "error",
    "cookie-prefix-violated": "error",
    "cookie-samesite-invalid": "error",
    "cookie-samesite-none-insecure": "error",
    "cookie-secure-over-plaintext": "error",
```

`CODE_HEADER` — a new `# -- Set-Cookie` block, alphabetically between `Report-To` and `Strict-Transport-Security`; all nine map to `"Set-Cookie"`.

`CODE_CONSEQUENCES`:

```python
    # -- Set-Cookie. The empty ones fail closed: a discarded cookie and a
    # rejected Partitioned attribute both leave a feature absent rather than
    # anything over-shared.
    "cookie-control-character": (),
    "cookie-domain-mismatch": ("session-theft",),
    "cookie-hidden-prefix": ("session-theft",),
    "cookie-oversized": (),
    "cookie-partitioned-insecure": (),
    "cookie-prefix-violated": ("session-theft",),
    "cookie-samesite-invalid": ("csrf",),
    "cookie-samesite-none-insecure": ("csrf", "mitm"),
    "cookie-secure-over-plaintext": ("mitm", "session-theft"),
```

`catalog.py` — `MESSAGES`, a new `# -- Set-Cookie` section. Every template names the cookie, and must read correctly however the finding is rated:

```python
    "cookie-control-character": (
        "{cookie} contains a control character, so browsers discard the whole "
        "Set-Cookie header and the cookie is never set"
    ),
    "cookie-oversized": (
        "{cookie} has a name and value totalling {octets} octets, over the "
        "4096-octet limit, so browsers discard it entirely"
    ),
    "cookie-samesite-invalid": (
        "{cookie} sets SameSite={value}, which no browser recognises, so it "
        "falls back to the default -- Lax in Chrome, and no cross-site "
        "restriction at all in Firefox and Safari"
    ),
    "cookie-samesite-none-insecure": (
        "{cookie} sets SameSite=None without Secure, so Chrome and Firefox "
        "reject the cookie outright and Safari sends it cross-site in "
        "cleartext"
    ),
    "cookie-secure-over-plaintext": (
        "{cookie} is marked Secure on a response that did not arrive over a "
        "trustworthy origin, so the cookie is not stored at all"
    ),
    "cookie-partitioned-insecure": (
        "{cookie} sets Partitioned without Secure, so the partitioning "
        "attribute is rejected"
    ),
    "cookie-prefix-violated": (
        "{cookie} carries the {prefix} prefix but does not meet its "
        "requirements ({unmet}), so browsers reject the cookie"
    ),
    "cookie-hidden-prefix": (
        "a nameless cookie carries a value beginning {prefix}, which browsers "
        "reject and anything re-parsing it would read as a prefixed cookie "
        "that never met the prefix rules"
    ),
    "cookie-domain-mismatch": (
        "{cookie} sets Domain={domain}, which is not {host} nor a parent of "
        "it, so browsers reject the cookie"
    ),
```

`references.py` — add `"Set-Cookie",` to `_MDN`, alphabetically after `"Reporting-Endpoints"`.

- [ ] **Step 6: Call it from `analyze()`**

In `response.py`'s `analyze()`, after `findings.extend(_analyze_preload(present, host))`:

```python
    # Loopback counts as trustworthy: both engines carve it out, so testing
    # the scheme alone would fire on every developer running against
    # http://localhost. `secure` is None when the scheme was unreadable, and
    # unknown is not plaintext -- treat it as trustworthy so nothing is
    # asserted on input nobody supplied.
    trustworthy = secure is not False or bool(host and _is_loopback(host))
    findings.extend(cookies.analyze_cookies(present, trustworthy, host))
```

- [ ] **Step 7: Extend the test corpus and the census**

In `tests/test_headers.py`, add a cookie corpus above `_every_code_headers_can_emit` and fold it in:

```python
# Cookie findings cannot go in ANALYZER_CASES: _analyze_header takes a value,
# and cookie rules need the request scheme and host as well.
COOKIE_CASES = [
    ({"Set-Cookie": ["a=b; SameSite=None"]}, "https://example.com/"),
    ({"Set-Cookie": ["a=b; Secure"]}, "http://example.com/"),
    ({"Set-Cookie": ["__Secure-sid=x"]}, "https://example.com/"),
    ({"Set-Cookie": ["=__Host-sid=x"]}, "https://example.com/"),
    ({"Set-Cookie": ["a=b\x00c"]}, "https://example.com/"),
    ({"Set-Cookie": ["a=" + "x" * 4096]}, "https://example.com/"),
    ({"Set-Cookie": ["a=b; SameSite=Strictt; Secure"]}, "https://example.com/"),
    ({"Set-Cookie": ["a=b; Partitioned"]}, "https://example.com/"),
    ({"Set-Cookie": ["a=b; Domain=evil.example"]}, "https://www.example.com/"),
]
```

and inside `_every_code_headers_can_emit()`:

```python
    for present, url in COOKIE_CASES:
        codes |= {f.code for f in headers.analyze(_ex(present, url=url))}
```

Update the census in `test_severity_values_match_the_documented_policy`:

```python
    assert counts == {"error": 48, "warning": 26, "note": 37}
```

- [ ] **Step 8: Regenerate the message snapshot and read the diff**

Run:
```bash
UPDATE_MESSAGE_SNAPSHOT=1 python -m pytest tests/ -k snapshot
git diff --stat tests/rendered_messages.txt
git diff tests/rendered_messages.txt
```
Expected: nine added lines and no changes to existing ones. **Read every added sentence.** A template naming `{sources}` beside data carrying `directives` renders as a crash or as nonsense, and this snapshot is the only thing that shows it. `git diff` is read-only and permitted.

- [ ] **Step 9: Run everything**

Run: `python -m pytest tests/ -q && ruff check`
Expected: all pass.

- [ ] **Step 10: Mutation-test two guards**

```bash
cp http_security_test/cookies.py "$SCRATCH/"
# Mutate 1: reorder COOKIE_PREFIXES so "__host-" precedes "__host-http-".
python -m pytest tests/test_cookies.py -q   # must FAIL: test_host_http_is_matched_before_host
cp "$SCRATCH/cookies.py" http_security_test/cookies.py
# Mutate 2: include \x09 in the _CONTROL class.
python -m pytest tests/test_cookies.py -q   # must FAIL: test_horizontal_tab_is_not_a_control_character_here
cp "$SCRATCH/cookies.py" http_security_test/cookies.py
```

- [ ] **Step 11: Checkpoint**

Ready to commit: `cookies.py`, `findings.py`, `catalog.py`, `references.py`, `response.py`, `tests/test_cookies.py`, `tests/test_headers.py`, `tests/rendered_messages.txt`. Suggested message: `feat: report cookies a browser rejects or degrades`.

---

### Task 6: Tier 2 — six laddered hardening codes, and suppression

**Files:**
- Modify: `http_security_test/cookies.py`
- Modify: `http_security_test/findings.py`
- Modify: `http_security_test/catalog.py`
- Test: `tests/test_cookies.py`, `tests/test_headers.py`

**Interfaces:**
- Consumes: Tasks 2–5.
- Produces: `evidence_for(cookie, attribute) -> list[str]`; six new codes.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cookies.py`:

```python
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
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -m pytest tests/test_cookies.py -v`
Expected: FAIL — the six codes are not emitted.

- [ ] **Step 3: Implement the ladder**

Append to `cookies.py`:

```python
# Which evidence escalates which attribute, and to what. A misspelling is the
# only signal that reaches `error`, and it outranks the rest: every other row
# infers whether the cookie MATTERS, while a misspelling establishes what the
# author INTENDED and did not get, which is principle 3's error verbatim.
# HttpOnly's `csrf` cell is the row that would otherwise be a bug -- see
# test_a_csrf_cookie_is_never_escalated_for_httponly.
_HARDENING = {
    # attribute: (code, may a csrf-named cookie escalate?)
    "secure": ("cookie-no-secure", True),
    "httponly": ("cookie-no-httponly", False),
    "samesite": ("cookie-no-samesite", True),
}


def evidence_for(cookie, attribute):
    """The signals that raise a hardening finding on `attribute` for `cookie`.

    Returned worst-first, so the level is the first entry's. `typo:` entries
    reach `error`; everything else reaches `warning`; empty stays at the floor.
    """
    name = cookie.name
    evidence = []
    suspected = None
    for written in cookie.attributes:
        suspected = suspected_attribute(written, absent_from={attribute})
        if suspected == attribute:
            evidence.append("typo:%s" % attribute)
            break
    if is_session_name(name):
        evidence.append("session-name")
    if _prefix_of(name) is not None:
        evidence.append("prefix")
    if attribute != "httponly" and "httponly" in cookie.attributes:
        evidence.append("httponly-set")
    lowered = name.lower()
    if any(fragment in lowered for fragment in CSRF_FRAGMENTS):
        if _HARDENING[attribute][1]:
            evidence.append("csrf-name")
    return evidence


def _level_from(evidence):
    if not evidence:
        return "note"
    if evidence[0].startswith("typo:"):
        return "error"
    return "warning"


def _hardening_findings(cookie):
    """Tier 2: gaps that are only defects on a cookie that matters."""
    if is_infrastructure_name(cookie.name):
        # Unconditional within tier 2. The cookie is still fully visible in
        # inventory.cookies, marked `judged: false`, so nothing is hidden.
        return []
    findings = []
    attributes = cookie.attributes
    for attribute, (code, _) in _HARDENING.items():
        if attribute in attributes:
            continue
        evidence = evidence_for(cookie, attribute)
        findings.append(Finding("Set-Cookie", code,
                                {"cookie": cookie.name, "evidence": evidence},
                                _level_from(evidence)))

    samesite = attributes.get("samesite")
    if samesite is not None and samesite.lower() == "none":
        evidence = [e for e in evidence_for(cookie, "samesite")
                    if not e.startswith("typo:")]
        findings.append(Finding("Set-Cookie", "cookie-samesite-none",
                                {"cookie": cookie.name, "evidence": evidence},
                                _level_from(evidence)))

    if "expires" in attributes or "max-age" in attributes:
        evidence = [e for e in evidence_for(cookie, "secure")
                    if not e.startswith("typo:")]
        findings.append(Finding("Set-Cookie", "cookie-persistent",
                                {"cookie": cookie.name, "evidence": evidence},
                                _level_from(evidence)))

    domain = attributes.get("domain")
    if domain:
        evidence = [e for e in evidence_for(cookie, "secure")
                    if not e.startswith("typo:")]
        findings.append(Finding("Set-Cookie", "cookie-domain-broad",
                                {"cookie": cookie.name, "domain": domain,
                                 "evidence": evidence},
                                _level_from(evidence)))
    return findings
```

and in `analyze_cookies`, after `findings.extend(_analyze_one(...))`:

```python
        findings.extend(_hardening_findings(cookie))
```

- [ ] **Step 4: Add the table entries**

`findings.py` — `FINDING_SEVERITY`, in the `note` block (these are *defaults*, i.e. the floor):

```python
    "cookie-domain-broad": "note",
    "cookie-no-httponly": "note",
    "cookie-no-samesite": "note",
    "cookie-no-secure": "note",
    "cookie-persistent": "note",
    "cookie-samesite-none": "note",
```

and populate `ESCALATABLE`, replacing the empty frozenset from Task 1:

```python
ESCALATABLE = frozenset([
    "cookie-domain-broad",
    "cookie-no-httponly",
    "cookie-no-samesite",
    "cookie-no-secure",
    "cookie-persistent",
    "cookie-samesite-none",
])
```

`CODE_HEADER` — all six to `"Set-Cookie"`.

`CODE_CONSEQUENCES`:

```python
    "cookie-domain-broad": ("session-theft",),
    "cookie-no-httponly": ("session-theft",),
    "cookie-no-samesite": ("csrf",),
    "cookie-no-secure": ("mitm", "session-theft"),
    "cookie-persistent": ("session-theft", "cache-exposure"),
    "cookie-samesite-none": ("csrf",),
```

`catalog.py` — six templates. Each must read correctly at every level it can carry:

```python
    "cookie-no-secure": (
        "{cookie} has no Secure attribute, so the browser will send it over "
        "plaintext HTTP to this host"
    ),
    "cookie-no-httponly": (
        "{cookie} has no HttpOnly attribute, so scripts running in the page "
        "can read it"
    ),
    "cookie-no-samesite": (
        "{cookie} has no SameSite attribute; Chrome defaults it to Lax, while "
        "Firefox and Safari send it on cross-site requests"
    ),
    "cookie-samesite-none": (
        "{cookie} sets SameSite=None, so it is sent on cross-site requests to "
        "this host by design"
    ),
    "cookie-persistent": (
        "{cookie} sets an expiry, so it is written to disk and outlives the "
        "browser session"
    ),
    "cookie-domain-broad": (
        "{cookie} sets Domain={domain}, so every subdomain of it receives the "
        "cookie"
    ),
```

- [ ] **Step 5: Extend the corpus and update the census**

Add to `COOKIE_CASES` in `tests/test_headers.py`:

```python
    ({"Set-Cookie": ["lang=en"]}, "https://example.com/"),
    ({"Set-Cookie": ["x=y; SameSite=None; Secure"]}, "https://example.com/"),
    ({"Set-Cookie": ["x=y; Max-Age=60; Secure"]}, "https://example.com/"),
    ({"Set-Cookie": ["x=y; Domain=example.com; Secure"]}, "https://www.example.com/"),
```

Census: `assert counts == {"error": 48, "warning": 26, "note": 43}`

- [ ] **Step 6: Regenerate the snapshot and read the diff**

Run:
```bash
UPDATE_MESSAGE_SNAPSHOT=1 python -m pytest tests/ -k snapshot
git diff tests/rendered_messages.txt
```
Expected: six added lines. Read them.

- [ ] **Step 7: Run everything**

Run: `python -m pytest tests/ -q && ruff check`

- [ ] **Step 8: Mutation-test the ladder — a suite that only counts findings passes either way**

```bash
cp http_security_test/cookies.py "$SCRATCH/"
# Mutate 1: make _level_from always return "note".
python -m pytest tests/test_cookies.py -q   # must FAIL: every escalation test
cp "$SCRATCH/cookies.py" http_security_test/cookies.py
# Mutate 2: let a csrf-named cookie escalate HttpOnly (flip the False to True).
python -m pytest tests/test_cookies.py -q   # must FAIL: the csrf exemption test
cp "$SCRATCH/cookies.py" http_security_test/cookies.py
# Mutate 3: remove one INFRASTRUCTURE_NAMES entry, say "awsalb".
python -m pytest tests/test_cookies.py -q   # must FAIL: the suppression test
cp "$SCRATCH/cookies.py" http_security_test/cookies.py
```

- [ ] **Step 9: Checkpoint**

Ready to commit: `cookies.py`, `findings.py`, `catalog.py`, both test files, the snapshot. Suggested message: `feat: rate cookie hardening gaps by evidence`.

---

### Task 7: `cookie-unknown-attribute`

**Files:**
- Modify: `http_security_test/cookies.py`
- Modify: `http_security_test/findings.py`, `http_security_test/catalog.py`
- Test: `tests/test_cookies.py`, `tests/test_headers.py`

**Interfaces:**
- Consumes: `KNOWN_ATTRIBUTES`, `suspected_attribute` from Task 3.
- Produces: one code, fixed `note`, consequences `()`.

- [ ] **Step 1: Write the failing tests**

```python
def test_an_unrecognised_attribute_is_reported():
    finding = _find("a=b; Secure; HttpOnly; SameSite=Lax; Version=1",
                    "cookie-unknown-attribute")
    assert finding.data["attribute"] == "version"
    assert "suspected" not in finding.data
    assert finding.level is None            # fixed at its default, never escalated


def test_the_suspected_correction_is_carried_when_there_is_one():
    finding = _find("a=b; HttpOnly; SameSite=Lax; Secrue",
                    "cookie-unknown-attribute")
    assert finding.data["suspected"] == "secure"


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
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -m pytest tests/test_cookies.py -k unknown_attribute -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

In `cookies.py`, add to `_analyze_one` before `return findings`:

```python
    absent = {a for a in TYPO_SENSITIVE_ATTRIBUTES if a not in attributes}
    for written in attributes:
        if written in KNOWN_ATTRIBUTES:
            continue
        data = {"cookie": name, "attribute": written}
        suspected = suspected_attribute(written, absent_from=absent)
        if suspected is not None:
            # Absent-beats-empty: no near match, no key.
            data["suspected"] = suspected
        findings.append(Finding("Set-Cookie", "cookie-unknown-attribute", data))
```

This sits in `_analyze_one` rather than `_hardening_findings` because it must not be suppressed.

- [ ] **Step 4: Add the table entries**

`FINDING_SEVERITY`: `"cookie-unknown-attribute": "note",`
`CODE_HEADER`: `"Set-Cookie"`.
`CODE_CONSEQUENCES`:

```python
    # Empty because the note asserts no defect. Where a misspelling does cause
    # one, the consequences are carried by the absence finding it escalates,
    # which already holds exactly the right slugs.
    "cookie-unknown-attribute": (),
```

`catalog.py` — one template, and it must read correctly with and without `suspected`, so it goes in `_DISPLAY`:

```python
def _unknown_attribute(data):
    suspected = data.get("suspected")
    return {
        "cookie": data["cookie"],
        "attribute": data["attribute"],
        "detail": (", which may be a misspelling of %s" % suspected) if suspected else "",
    }
```

registered as `"cookie-unknown-attribute": _unknown_attribute,` in `_DISPLAY`, with:

```python
    "cookie-unknown-attribute": (
        "{cookie} sets the attribute {attribute}, which no browser "
        "recognises{detail}"
    ),
```

- [ ] **Step 5: Extend the corpus and update the census**

Add to `COOKIE_CASES`: `({"Set-Cookie": ["a=b; Secure; HttpOnly; SameSite=Lax; Version=1"]}, "https://example.com/")`

Census: `assert counts == {"error": 48, "warning": 26, "note": 44}`

- [ ] **Step 6: Regenerate the snapshot, read the diff, run everything**

```bash
UPDATE_MESSAGE_SNAPSHOT=1 python -m pytest tests/ -k snapshot
git diff tests/rendered_messages.txt
python -m pytest tests/ -q && ruff check
```
Expected: one added line, rendering both with and without the suspected clause. If only one form appears, add a corpus case for the other.

- [ ] **Step 7: Mutation-test the two guards**

```bash
cp http_security_test/cookies.py "$SCRATCH/"
# Mutate 1: drop "priority" from KNOWN_ATTRIBUTES.
python -m pytest tests/test_cookies.py -q   # must FAIL: the parametrized recognised test
cp "$SCRATCH/cookies.py" http_security_test/cookies.py
# Mutate 2: pass absent_from=set(KNOWN_ATTRIBUTES) so the second guard is inert.
python -m pytest tests/test_cookies.py -q   # must FAIL: the fail-safe-attribute tests
cp "$SCRATCH/cookies.py" http_security_test/cookies.py
```

- [ ] **Step 8: Checkpoint**

Suggested message: `feat: report unrecognised and misspelled cookie attributes`.

---

### Task 8: CLI rendering and documentation

**Files:**
- Modify: `http_security_test/cli/text.py` (`_inventory_lines`, ~line 106)
- Modify: `http_security_test/cli/commands.py` (`do_explain`, ~line 47)
- Modify: `CLAUDE.md`
- Test: `tests/test_cli_text.py`, `tests/test_cli_explain.py`, `tests/cli_terminal_snapshot.txt`

**Interfaces:**
- Consumes: `inventory()["cookies"]`, `ESCALATABLE`.
- Produces: nothing further.

- [ ] **Step 1: Write the failing tests**

In `tests/test_cli_text.py`:

```python
def test_the_cookies_table_renders_one_line_per_cookie():
    document = _document_with_headers([
        ("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Strict"),
        ("Set-Cookie", "lang=en"),
    ])
    out = text.render(document)
    assert "cookies:" in out
    assert "sid" in out and "lang" in out


def test_an_unjudged_cookie_says_so():
    document = _document_with_headers([("Set-Cookie", "AWSALB=x")])
    assert "not judged" in text.render(document)


def test_no_cookies_table_when_the_response_sets_none():
    assert "cookies:" not in text.render(_document_with_headers([]))
```

(Reuse whatever helper `tests/test_cli_text.py` already has for building a document; check with `grep -n "^def _" tests/test_cli_text.py` and follow it rather than inventing a second one.)

In `tests/test_cli_explain.py`:

```python
def test_an_escalatable_code_says_its_level_is_a_floor():
    out = _explain("cookie-no-httponly")
    assert "note" in out
    assert "may escalate" in out


def test_a_fixed_code_does_not():
    assert "may escalate" not in _explain("hsts-missing")
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -m pytest tests/test_cli_text.py tests/test_cli_explain.py -v`
Expected: FAIL.

- [ ] **Step 3: Render the cookies table**

In `cli/text.py`, `_inventory_lines` loops over `TABLES` assuming `{name: value}`. Cookies are a list of dicts, so they need their own block. Add after the `TABLES` loop and before the `missing` block:

```python
    rows = inventory.get("cookies") or []
    if rows:
        lines.append("cookies:")
        for row in rows:
            flags = [k for k in ("secure", "httponly", "partitioned") if row[k]]
            if row["samesite"]:
                flags.append("SameSite=%s" % row["samesite"])
            if row["domain"]:
                flags.append("Domain=%s" % row["domain"])
            detail = "; ".join(flags) if flags else "no attributes"
            if not row["judged"]:
                detail += "   (not judged: infrastructure cookie)"
            lines.append("  %-28s %s" % (row["name"], detail))
        lines.append("")
```

The value is deliberately not printed: the terminal report is a summary and the value is in the JSON. Do NOT add a redaction switch — this package does not redact, and `--raw` is a size control, not a privacy one.

- [ ] **Step 4: Mark escalatable codes in `explain`**

In `cli/commands.py`, add `ESCALATABLE` to the `from ..findings import` block (alphabetically) and change the level line:

```python
        level = FINDING_SEVERITY[code]
        if code in ESCALATABLE:
            level += "*"
        print("%-34s %-9s %s" % (code, level, header or "(response)"))
        if code in ESCALATABLE:
            print("(* a floor: this level may escalate on evidence in the finding)")
```

- [ ] **Step 5: Regenerate the terminal snapshot and read the diff**

Run:
```bash
python -m pytest tests/test_cli_text.py -q
git diff tests/cli_terminal_snapshot.txt
```
If `tests/cli_terminal_snapshot.txt` is generated by an env var like the message snapshot, use the same mechanism — check with `grep -rn "cli_terminal_snapshot" tests/`. Read the diff; the column widths in `explain` changed, so alignment shifts are expected and anything else is not.

- [ ] **Step 6: Reserve `--ignore-cookie`**

The spec reserves it on the evidence that ZAP's operators want to own this
list. Reserved-and-documented is a real state in this CLI — see the `read`
verb, `--probe` and `writers.RESERVED` — so it needs an entry rather than a
comment.

In `cli/options.py`, add to the `scan` parser beside the other reserved flags:

```python
    scan.add_argument(
        "--ignore-cookie", metavar="NAME", action="append", default=[],
        help="not implemented yet: suppress hardening findings for a cookie name",
    )
```

In `cli/commands.py`'s `do_scan`, beside the existing reserved-flag guard
(find it with `grep -n "not implemented" http_security_test/cli/commands.py`
and follow the same shape), refuse it rather than accepting it silently — a
flag that parses and does nothing is worse than one that says so.

Add a test in `tests/test_cli_scan.py` asserting the flag exits 2 with a
message naming it, matching whatever the existing reserved-flag tests assert.

- [ ] **Step 7: Update CLAUDE.md**

Six edits, each a fact that is now wrong:

1. **Layout** — add `cookies.py   Set-Cookie: the parser, the name tables, the analysis` to the module list, and add it to the `core` line of the layering block.
2. **Status** — analyser code count `102` → `118`; the severity census `(39 error / 26 warning / 37 note)` → `(48 error / 26 warning / 44 note)`; consequence slugs `Eight` → `Ten`; `references.py` resolves `40 headers` → `41 headers`; core modules `12` → `13`; test count from the final `pytest` run.
3. **The output schema** — `inventory` gains `"cookies": []`; note it is the sixth key and the only list of parsed objects.
4. **Parked, with intent to do** — delete the whole `**`Set-Cookie` analysis**` item; it is done. Leave the two cache items, and update the cache/cookie item's opening: its stated blocker ("land it with the cookie parser") is now satisfied, so restate the remaining blocker as the `caching`-table contract.
5. **Design principles** — principle 1 needs a sentence: a rating is a code's *default* and a finding may carry its own, which is SARIF's `result.level`.
6. **Invariants the test suite pins** — the `identity()` bullet says "two cookies each missing `Secure` will be two more" in the future tense. It is now exercised; change the tense and name the test.

- [ ] **Step 8: Final verification**

```bash
python -m pytest tests/ -q
ruff check
python -c "import http_security_test, sys; assert 'http_security_test.cli' not in sys.modules"
```
Expected: all pass. Record the final test count for CLAUDE.md.

- [ ] **Step 9: End-to-end check against a real-shaped response**

```bash
python -m http_security_test.cli scan --help >/dev/null && echo "cli ok"
python -c "
from http_security_test import Exchange, Request, Response, report
import json
ex = Exchange(
    Request.from_parts(url='https://example.com/'),
    Response.from_parts(status=200, headers=[
        ('Set-Cookie', 'PHPSESSID=abc; Path=/'),
        ('Set-Cookie', 'AWSALB=x; SameSite=None'),
        ('Set-Cookie', '__Host-csrf=t; Secure; Path=/'),
        ('Set-Cookie', 'lang=en; Secrue'),
    ]))
r = report(ex)
for f in r['response']['findings']:
    print('%-8s %-32s %s' % (f['level'], f['code'], f['data']))
print()
print(json.dumps(r['response']['inventory']['cookies'], indent=1))"
```

Expected, and check each: `PHPSESSID` escalates to `warning` for all three gaps; `AWSALB` raises `cookie-samesite-none-insecure` (tier 1, unsuppressed) and **no** hardening findings, and is `judged: false`; `__Host-csrf` raises `cookie-no-httponly` at `note` because of the CSRF exemption, and no prefix violation; `lang=en` raises `cookie-unknown-attribute` naming `secrue` with `suspected: secure`, and `cookie-no-secure` at **error**.

- [ ] **Step 10: Checkpoint**

Ready to commit: `cli/text.py`, `cli/commands.py`, `cli/options.py`, `CLAUDE.md`, the CLI tests and snapshot. Suggested message: `feat: render cookies in the CLI report`.

---

## Notes for the executor

- **The spec is the authority.** Where this plan and `docs/designs/2026-08-30-cookie-analysis.md` disagree, the spec wins — the CLI contract was built the same way and the plan was corrected in five places during that build.
- **Do not add a redaction option anywhere.** Cookie values are carried in full, deliberately. `--raw` controls output size, not privacy.
- **Do not derive the cookie inventory from findings.** A correctly configured cookie emits nothing and would vanish.
- **Do not widen a pattern to a fragment.** `*session*` and `*_sid` are forbidden by policy; the precision figures are in the spec.
