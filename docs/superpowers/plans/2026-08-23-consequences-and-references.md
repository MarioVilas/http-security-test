# Consequences, taxonomy references and CODE_HEADER — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every finding a declared owning header, a list of consequence slugs naming the risk its misconfiguration creates, and a per-response block of resolvable documentation and taxonomy identifiers.

**Architecture:** Three new code-keyed tables in `findings.py` (`CODE_HEADER`, `CODE_CONSEQUENCES`, `CODE_TAXONOMY`), one prose table in `catalog.py` (`CONSEQUENCES`), and one new leaf module `references.py` holding URL derivation. `reporting.py` joins them into the report; `cli/text.py` and `cli/commands.py` render them. No analyser is touched and no verdict moves.

**Tech Stack:** Python 3, standard library only, pytest, `ruff check`. No new dependencies.

**Spec:** `docs/designs/2026-08-23-consequences-and-references.md`

## Global Constraints

- **Standard library only.** No new runtime dependency, not even an optional one.
- **No test may touch the network.** Not for URL validation, not ever.
- **No test may depend on `/home/crapula/ref` or `tmp/`.** Those are used by one-off generator steps whose *output* is committed; the suite must pass on a clean clone.
- **GPL-3.0-or-later notice** at the top of every new source file, copied verbatim from `http_security_test/findings.py:1-18`.
- **`ruff check` stays clean.** Do not run `ruff format`; the human owns formatting.
- **Never run a git command that writes. Leave your work uncommitted.** A `PreToolUse` hook denies every git verb outside a read-only allowlist and it will stop you — that is the repository's rule, working as designed, not a misconfiguration to route around. `add`, `commit`, `push`, `stash`, `branch`, `merge`, `rebase`, `checkout -- <path>`, `restore`, `reset`, `clean`: all denied. Reading is always fine (`show`, `log`, `diff`, `status`, `rev-parse`). The controller snapshots your files for review after each task, and the human owns every commit in this repository.
- **To restore a file you broke on purpose** — the mutation-test steps below require exactly this — copy it back from a backup made outside the repo. **Never reach for git to undo your own edit.** Other agents may be working in this tree; `git checkout -- <path>` over their never-staged changes is unrecoverable, because content that was never staged never entered the object database and no blob survives.
- **The tree accumulates.** Nothing is committed between tasks, so by Task 6 the working tree carries every earlier task's changes. Never infer "what I changed" from `git status` or `git diff` — they show the whole run. Report the files *you* touched, from your own record.

```bash
SCRATCH=$(mktemp -d); cp module.py "$SCRATCH/"   # ...mutate, run the suite...
cp "$SCRATCH/module.py" module.py
```

- **Tables are tuples, never sets.** A set literal reorders output per process and breaks determinism.
- **Analysers must not import `catalog.py` or `references.py`.** A test walks the AST to enforce the `cli` direction; keep the same discipline here.
- **Consequence slugs are the eight in the spec and no others:** `xss`, `clickjacking`, `mitm`, `data-disclosure`, `cors-data-theft`, `cache-exposure`, `cross-origin-leak`, `permission-abuse`.

## File Structure

| file                                 | responsibility               | change                                                                    |
| ------------------------------------ | ---------------------------- | ------------------------------------------------------------------------- |
| `http_security_test/findings.py`     | code-keyed policy tables     | add `CODE_HEADER`, `CODE_CONSEQUENCES`, `CODE_TAXONOMY`, `consequences()` |
| `http_security_test/catalog.py`      | all prose                    | add `Consequence`, `CONSEQUENCES`                                         |
| `http_security_test/references.py`   | **new leaf** — external URLs | `HEADER_DOCS`, `header_url()`, `taxonomy_url()`                           |
| `http_security_test/reporting.py`    | plain-data report            | `consequences` per finding, `references` block                            |
| `http_security_test/__init__.py`     | public API                   | export the new names                                                      |
| `http_security_test/cli/text.py`     | terminal render              | append `[slug, slug]` to a finding line                                   |
| `http_security_test/cli/commands.py` | `explain` verb               | print header, consequences, URLs                                          |
| `tests/test_headers.py`              | analyser + catalog tests     | new sections for each table                                               |
| `tests/test_references.py`           | **new**                      | URL derivation                                                            |
| `tests/test_cli_explain.py`          | `explain` output             | extend                                                                    |
| `tests/cli_terminal_snapshot.txt`    | pinned terminal output       | regenerate                                                                |

Dependency direction after this work — still acyclic, `references` a leaf:

```
findings, message, catalog, references  ->  (nothing)
reporting  ->  response, findings, catalog, references
```

______________________________________________________________________

### Task 1: `CODE_HEADER`

Closes the parked "public code-to-header table" item. Self-contained: no schema change, no other table depends on it. Ships alone if the rest slips.

**Files:**

- Modify: `http_security_test/findings.py` (after `FINDING_SEVERITY`)
- Modify: `http_security_test/__init__.py`
- Modify: `tests/test_headers.py` (replace `test_each_code_belongs_to_exactly_one_header` at line 777)

**Interfaces:**

- Produces: `CODE_HEADER: dict[str, str | None]` — every emittable code to its canonical header name, `None` for `duplicate-headers`.

- [ ] **Step 1: Generate the table**

The spec forbids typing this list by hand — an earlier hand-assembled header set was wrong. Derive it:

```bash
python3 - <<'PYEOF' > /tmp/code_header.txt
import sys, collections
sys.path.insert(0, "tests")
import tests.test_headers as T
owners = {}
for f in T._every_finding_headers_can_emit():
    owners.setdefault(f.code, set()).add(f.header)
byhdr = collections.defaultdict(list)
for c, s in owners.items():
    byhdr[None if c == "duplicate-headers" else sorted(s)[0]].append(c)
print("CODE_HEADER = {")
print("    # duplicate-headers is about the response, not any one header: any")
print("    # header may be repeated, so a code-keyed view cannot name an owner.")
print('    "duplicate-headers": None,')
for h in sorted(k for k in byhdr if k):
    print("    # -- %s" % h)
    for c in sorted(byhdr[h]):
        print('    "%s": "%s",' % (c, h))
print("}")
PYEOF
wc -l /tmp/code_header.txt   # expect 141
head -8 /tmp/code_header.txt
```

Expected first entries:

```python
CODE_HEADER = {
    # duplicate-headers is about the response, not any one header: any
    # header may be repeated, so a code-keyed view cannot name an owner.
    "duplicate-headers": None,
    # -- Access-Control-Allow-Credentials
    "acac-ineffective": "Access-Control-Allow-Credentials",
```

- [ ] **Step 2: Write the failing tests**

Add to `tests/test_headers.py`, replacing the existing `test_each_code_belongs_to_exactly_one_header` (line 777). The old test could only prove the corpus was self-consistent; these prove the package agrees with it.

```python
def test_every_emittable_code_declares_a_header():
    assert _every_code_headers_can_emit() <= set(headers.CODE_HEADER)


def test_no_header_is_declared_for_a_code_that_cannot_be_emitted():
    assert set(headers.CODE_HEADER) <= _every_code_headers_can_emit()


def test_the_declared_header_is_the_header_the_finding_carries():
    """The upgrade over the old test.

    The old one asked only whether the corpus disagreed with itself. This asks
    whether the declared table matches what analysis actually emits, which is
    the failure a moved code would cause. Compared case-insensitively because
    duplicate-headers findings carry a lowercased name -- see the exemption
    below, which is about the *code*, not the casing.
    """
    for finding in _every_finding_headers_can_emit():
        if finding.code == "duplicate-headers":
            continue  # any header may repeat; the code names no single owner
        declared = headers.CODE_HEADER[finding.code]
        assert declared is not None, finding.code
        assert declared.lower() == finding.header.lower(), finding.code


def test_duplicate_headers_declares_no_header():
    # None rather than absence, so the table stays total over codes and the
    # two bijection tests above cannot pass by skipping it.
    assert "duplicate-headers" in headers.CODE_HEADER
    assert headers.CODE_HEADER["duplicate-headers"] is None
```

- [ ] **Step 3: Run them to verify they fail**

```bash
python -m pytest tests/test_headers.py -k "declare or declared or duplicate_headers_declares" -v
```

Expected: FAIL, `AttributeError: module 'http_security_test' has no attribute 'CODE_HEADER'`.

- [ ] **Step 4: Add the table**

Paste `/tmp/code_header.txt` into `http_security_test/findings.py` immediately after the `FINDING_SEVERITY` dict closes, preceded by this comment:

```python
# Which header a code belongs to, declared rather than inferred. The prefix of a
# code is a mnemonic and not a lookup -- `re-` is Reporting-Endpoints and `rp-`
# is Referrer-Policy -- so a consumer that wants the owning header has no way to
# ask without this. `explain` is the first caller and a SARIF writer's rules[]
# will be the second. None means the response rather than any one header.
```

- [ ] **Step 5: Export it**

In `http_security_test/__init__.py`, add `CODE_HEADER` to the `from .findings import (...)` block and to `__all__`, both in alphabetical position (before `FINDING_SEVERITY` in the import, first in `__all__`).

- [ ] **Step 6: Run the full suite**

```bash
python -m pytest tests/ -q && ruff check
```

Expected: **515 passing** — the baseline is 512, one test is removed and four added — and ruff clean.

- [ ] **Step 7: Mutation-test the new guard**

A test that passes both ways is worse than none. Back the file up outside the repo first — never use git to undo this.

```bash
SCRATCH=$(mktemp -d)
cp http_security_test/findings.py "$SCRATCH/"
sed -i 's/"csp-unsafe-inline": "Content-Security-Policy"/"csp-unsafe-inline": "X-Frame-Options"/' http_security_test/findings.py
python -m pytest tests/test_headers.py -k declared -q   # expect FAIL
cp "$SCRATCH/findings.py" http_security_test/findings.py
python -m pytest tests/test_headers.py -k declared -q   # expect PASS
```

- [ ] **Step 8: Report, do not commit**

**Do not run any git command that writes.** A PreToolUse hook denies
`add` and `commit` outright and will stop you; that is the repository's
rule, not a misconfiguration, so do not work around it. Leave every change
in the working tree. The controller snapshots your files for review and the
human owns every commit.

Write your report to the report file named in your dispatch, listing the
files you touched, the commands you ran and their output. Return the short
status contract only.

______________________________________________________________________

### Task 2: `references.py`

**Files:**

- Create: `http_security_test/references.py`
- Create: `tests/test_references.py`
- Modify: `http_security_test/__init__.py`

**Interfaces:**

- Consumes: nothing.

- Produces:

  - `HEADER_DOCS: dict[str, str]` — canonical header name to documentation URL.
  - `header_url(name: str) -> str | None` — case-insensitive lookup.
  - `taxonomy_url(identifier: str) -> str | None` — `"CWE-79"` / `"CAPEC-63"` to a MITRE URL, `None` for an unrecognised scheme.

- [ ] **Step 1: Generate the three source collections**

One-off, needs `/home/crapula/ref`. The *output* is committed; the suite never re-runs this.

```bash
python3 - <<'PYEOF'
import sys, json, os, glob
sys.path.insert(0, "tests")
import tests.test_headers as T
from http_security_test.response import (SECURITY_HEADERS, REPORTING_HEADERS,
                                         CORS_HEADERS, DEPRECATED_HEADERS, CACHE_HEADERS)
# The set is derived: every header a finding names, plus every header an
# inventory carries. Hand-listing it is what made the spec's first draft wrong.
allh = sorted(({f.header for f in T._every_finding_headers_can_emit()} - {"x-frame-options"})
              | set(SECURITY_HEADERS) | set(REPORTING_HEADERS) | set(CORS_HEADERS)
              | set(DEPRECATED_HEADERS) | set(CACHE_HEADERS))
mdn = {}
for p in glob.glob("/home/crapula/ref/documentation/browser-compat-data/http/headers/*.json"):
    for n, b in json.load(open(p)).get("http", {}).get("headers", {}).items():
        u = b.get("__compat", {}).get("mdn_url")
        if u:
            mdn[n] = u
PAT = "https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/%s"
SPEC = ("Public-Key-Pins", "Public-Key-Pins-Report-Only", "P3P")
M = [h for h in allh if mdn.get(h) == PAT % h]
D = [h for h in allh if h not in M and h not in SPEC]
assert all(os.path.exists("/home/crapula/ref/documentation/http.dev/" + h.lower()) for h in D), D
print("total %d  _MDN %d  _SPEC %d  _HTTP_DEV %d" % (len(allh), len(M), len(SPEC), len(D)))
for label, names in (("_MDN", M), ("_HTTP_DEV", D)):
    print("\n%s = (" % label)
    for h in names:
        print('    "%s",' % h)
    print(")")
PYEOF
```

Expected: `total 40  _MDN 30  _SPEC 3  _HTTP_DEV 7`, and the assert passes (every non-MDN header has an http.dev page).

- [ ] **Step 2: Write the failing tests**

Create `tests/test_references.py` with the GPL notice from `findings.py:1-18`, then:

```python
import http_security_test as headers
from http_security_test import references


def test_an_mdn_header_resolves_to_the_mdn_pattern():
    assert references.header_url("Content-Security-Policy") == (
        "https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/"
        "Content-Security-Policy"
    )


def test_a_header_mdn_does_not_document_falls_back_to_http_dev():
    assert references.header_url("X-WebKit-CSP") == "https://http.dev/x-webkit-csp"


def test_a_header_with_a_permanent_spec_prefers_it_over_http_dev():
    # RFC and W3C /TR/ URLs are permanent by their publishers' written policy,
    # which http.dev does not have. That ordering is the whole design.
    assert references.header_url("Public-Key-Pins") == (
        "https://www.rfc-editor.org/rfc/rfc7469"
    )
    assert references.header_url("P3P") == "https://www.w3.org/TR/P3P"


def test_lookup_is_case_insensitive():
    # duplicate-headers findings carry a lowercased name; a case-sensitive
    # lookup would silently produce None for them.
    assert references.header_url("x-frame-options") == references.header_url(
        "X-Frame-Options"
    )


def test_an_unknown_header_resolves_to_none():
    # Coverage is 40/40 today, which is exactly what makes this branch look
    # like dead code. A header added later would be in no source at all.
    assert references.header_url("X-Not-A-Real-Header") is None


def test_every_header_a_finding_can_name_resolves():
    for code, header in headers.CODE_HEADER.items():
        if header is None:
            continue
        assert references.header_url(header) is not None, code


def test_taxonomy_urls():
    assert references.taxonomy_url("CWE-79") == (
        "https://cwe.mitre.org/data/definitions/79.html"
    )
    assert references.taxonomy_url("CAPEC-63") == (
        "https://capec.mitre.org/data/definitions/63.html"
    )


def test_an_unrecognised_taxonomy_scheme_resolves_to_none():
    assert references.taxonomy_url("TID-319") is None
    assert references.taxonomy_url("nonsense") is None


def test_every_url_is_https_and_has_no_whitespace():
    # Shape only. Nothing here fetches anything, in this test or any other.
    for url in list(references.HEADER_DOCS.values()) + [
        references.taxonomy_url("CWE-79"),
        references.taxonomy_url("CAPEC-63"),
    ]:
        assert url.startswith("https://")
        assert url == url.strip()
        assert " " not in url
```

- [ ] **Step 3: Run to verify failure**

```bash
python -m pytest tests/test_references.py -v
```

Expected: FAIL, `ModuleNotFoundError: No module named 'http_security_test.references'`.

- [ ] **Step 4: Write the module**

`http_security_test/references.py`, GPL notice first, then:

```python
"""Where to read more, as URLs derived from names this package already has.

Nothing here is fetched and nothing here is curated beyond three entries. A
header name and a CWE identifier both resolve to a stable URL by pattern, which
is why the report carries identifiers rather than links: a name does not rot.

Resolution is ordered by the publisher's permanence policy, not by how official
the source sounds. The IETF and W3C keep published documents in perpetuity; MDN
redirects a page when a header is superseded, which is exactly how Feature-Policy
disappeared; http.dev states no policy at all and is the last resort.
"""

_MDN_PATTERN = "https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/%s"
_HTTP_DEV_PATTERN = "https://http.dev/%s"

# Paste _MDN and _HTTP_DEV from the Step 1 generator here, as tuples.
_MDN = (...)
_HTTP_DEV = (...)

# The only curated URLs in the package. Permanent by their publishers' written
# policy, which is what earns them the exception -- do NOT read three entries as
# licence to add a fourth because the table is still short. The distinction is
# permanence, not brevity.
_SPEC = {
    "Public-Key-Pins": "https://www.rfc-editor.org/rfc/rfc7469",
    "Public-Key-Pins-Report-Only": "https://www.rfc-editor.org/rfc/rfc7469",
    "P3P": "https://www.w3.org/TR/P3P",
}

# One positive name-to-URL table, built once. Positive rather than a pair of
# "headers MDN lacks" exclusion sets, and the direction is the point: an
# exclusion set lets an unrecognised header fall through to the MDN pattern and
# emit a URL that 404s, so it fails OPEN exactly when it is most out of date.
HEADER_DOCS = {}
HEADER_DOCS.update({name: _MDN_PATTERN % name for name in _MDN})
HEADER_DOCS.update({name: _HTTP_DEV_PATTERN % name.lower() for name in _HTTP_DEV})
HEADER_DOCS.update(_SPEC)

_LOWER = {name.lower(): url for name, url in HEADER_DOCS.items()}

_TAXONOMY = {
    "CWE": "https://cwe.mitre.org/data/definitions/%s.html",
    "CAPEC": "https://capec.mitre.org/data/definitions/%s.html",
}


def header_url(name):
    """Where to read about a header, or None.

    Case-insensitive because a duplicate-headers finding carries the lowercased
    name it read out of the header mapping, unlike every other finding.
    """
    return _LOWER.get(name.lower())


def taxonomy_url(identifier):
    """Where to read about a taxonomy entry, or None for an unknown scheme.

    Identifiers are self-prefixing -- CWE-79, CAPEC-63 -- which is why the
    report can carry one flat list and adding a taxonomy needs no schema change.
    """
    scheme, _, number = identifier.partition("-")
    if not number.isdigit() or scheme not in _TAXONOMY:
        return None
    return _TAXONOMY[scheme] % number
```

- [ ] **Step 5: Run to verify they pass**

```bash
python -m pytest tests/test_references.py -v
```

Expected: 9 passing.

- [ ] **Step 6: Export**

In `__init__.py`, add `from .references import HEADER_DOCS, header_url, taxonomy_url` and the three names to `__all__` in alphabetical position.

- [ ] **Step 7: Mutation-test the `None` branch**

The branch nothing currently reaches is the one most likely to be wrong.

```bash
SCRATCH=$(mktemp -d)
cp http_security_test/references.py "$SCRATCH/"
sed -i 's/return _LOWER.get(name.lower())/return _LOWER.get(name.lower(), "")/' http_security_test/references.py
python -m pytest tests/test_references.py -q   # expect FAIL on the None test
cp "$SCRATCH/references.py" http_security_test/references.py
python -m pytest tests/test_references.py -q   # expect PASS
```

- [ ] **Step 8: Report, do not commit**

**Do not run any git command that writes.** A PreToolUse hook denies
`add` and `commit` outright and will stop you; that is the repository's
rule, not a misconfiguration, so do not work around it. Leave every change
in the working tree. The controller snapshots your files for review and the
human owns every commit.

Write your report to the report file named in your dispatch, listing the
files you touched, the commands you ran and their output. Return the short
status contract only.

______________________________________________________________________

### Task 3: The consequence tables, empty

Scaffolding and the invariants, with no mappings yet. Splitting this from the mappings means the bijection tests exist and fail *before* 102 policy decisions land, so each mapping task has a gate.

**Files:**

- Modify: `http_security_test/catalog.py`
- Modify: `http_security_test/findings.py`
- Modify: `http_security_test/__init__.py`
- Modify: `tests/test_headers.py`

**Interfaces:**

- Produces:

  - `catalog.Consequence` — `namedtuple("Consequence", "name taxonomy text")`, `taxonomy` a tuple of identifiers.
  - `catalog.CONSEQUENCES: dict[str, Consequence]` — eight slugs.
  - `findings.CODE_CONSEQUENCES: dict[str, tuple[str, ...]]` — every code to its slugs, `()` for none.
  - `findings.consequences(code) -> tuple[str, ...]`.

- [ ] **Step 1: Add `CONSEQUENCES` to `catalog.py`**

At the end of the file, after `describe()`. Every `text` says the risk is possible, not present — that wording is the contract with the reader and is pinned by a test in Task 7.

```python
# What a misconfiguration could lead to. A hint about potential risk, never a
# claim that the risk is reachable: whether an injected script exists, whether
# the page is worth framing, whether anything sensitive is in the URL, are all
# facts about an application that a response header cannot report. The wording
# of every entry says so, because a consumer will paste it into a ticket.
#
# The slug is the contract and the taxonomy identifier is an attribute of it.
# That is not a preference: CWE 4.20 has no weakness for MIME sniffing, for
# XS-Leaks, or written for permission delegation, so a CWE-keyed vocabulary
# would have had entries with no identifier or a forced one.
Consequence = collections.namedtuple("Consequence", "name taxonomy text")

CONSEQUENCES = {
    "xss": Consequence(
        "Cross-site scripting",
        ("CWE-79", "CAPEC-63"),
        "Script an attacker controls could run in this origin, with the same "
        "access to cookies, storage and the DOM as the site's own code. "
        "Whether an injection point exists is not determined here.",
    ),
    "clickjacking": Consequence(
        "Clickjacking",
        ("CWE-1021", "CAPEC-103"),
        "The page could be framed by another site and overlaid, so a user "
        "clicking what they see acts on what they do not. Whether the page "
        "has an action worth stealing is not determined here.",
    ),
    "mitm": Consequence(
        "Network interception",
        ("CWE-319", "CAPEC-117"),
        "A request could be carried in cleartext where someone on the path "
        "can read or alter it, session cookies included. Whether an attacker "
        "is on the path is not determined here.",
    ),
    "data-disclosure": Consequence(
        "Sensitive data sent to third parties",
        ("CWE-200",),
        "The browser could hand data to a third party as part of ordinary "
        "browsing -- a URL carrying a token, for instance. Whether anything "
        "sensitive travels that way is not determined here.",
    ),
    "cors-data-theft": Consequence(
        "Cross-origin data theft",
        ("CWE-942",),
        "Another origin could read this response, including anything in it "
        "specific to the logged-in user. Whether the response carries "
        "user-specific content is not determined here.",
    ),
    "cache-exposure": Consequence(
        "Sensitive data left in the browser",
        ("CWE-525", "CAPEC-204"),
        "Data could remain in the browser after it should have been cleared, "
        "readable by the next person using the device. Whether anything "
        "sensitive was stored is not determined here.",
    ),
    "cross-origin-leak": Consequence(
        "Cross-origin state or resource leak",
        ("CAPEC-663",),
        "A page the user visits could measure something about this origin "
        "that the same-origin policy is meant to hide, using the user's own "
        "session. Whether anything measurable is worth learning is not "
        "determined here.",
    ),
    "permission-abuse": Consequence(
        "Powerful browser feature left available",
        ("CWE-732",),
        "A powerful capability such as the camera, microphone or location "
        "could be reachable by the page or by a third party it embeds. "
        "Whether anything embedded would use it is not determined here.",
    ),
}
```

`catalog.py` currently has **no imports at all** — verified. Add a single `import collections` on its own line immediately after the module docstring's closing `"""` and before the blank line preceding `MESSAGES`.

- [ ] **Step 2: Add the empty table and accessor to `findings.py`**

After `CODE_HEADER`:

```python
# What each code's misconfiguration could lead to. Empty is a result and not an
# omission: a reporting failure costs the operator information and withholds no
# protection, and most CORS defects fail closed -- the preflight fails, nothing
# is over-shared -- so those carry nothing. The ratings and this table are
# independent axes on purpose: acao-credentials-wildcard is an error with no
# consequence, and acao-wildcard is a note with a real one.
CODE_CONSEQUENCES = {}


def consequences(code):
    """The consequence slugs for a code, worst-case first in table order."""
    return CODE_CONSEQUENCES.get(code, ())
```

- [ ] **Step 3: Write the failing invariant tests**

Add a new section to `tests/test_headers.py` after the message-catalog block:

```python
# ---------------------------------------------------------------------------
# Consequences
# ---------------------------------------------------------------------------
# Two tables and three invariants. The severities and the message templates are
# both bijections with the emittable codes; these are held to the same standard,
# because a code with no entry would silently report no risk at all.


def test_every_emittable_code_declares_consequences():
    assert _every_code_headers_can_emit() <= set(headers.CODE_CONSEQUENCES)


def test_no_consequences_are_declared_for_a_code_that_cannot_be_emitted():
    assert set(headers.CODE_CONSEQUENCES) <= _every_code_headers_can_emit()


def test_every_slug_a_code_names_is_defined():
    named = {s for slugs in headers.CODE_CONSEQUENCES.values() for s in slugs}
    assert named <= set(headers.CONSEQUENCES)


def test_every_defined_slug_is_named_by_some_code():
    # Without this the vocabulary could grow entries nothing ever emits, which
    # is how a catalogue rots: the table looks maintained and half of it is dead.
    named = {s for slugs in headers.CODE_CONSEQUENCES.values() for s in slugs}
    assert set(headers.CONSEQUENCES) <= named


def test_consequences_are_tuples_not_sets():
    # A set literal reorders per process and makes output nondeterministic.
    for code, slugs in headers.CODE_CONSEQUENCES.items():
        assert isinstance(slugs, tuple), code
    for slug, entry in headers.CONSEQUENCES.items():
        assert isinstance(entry.taxonomy, tuple), slug


def test_every_taxonomy_identifier_resolves():
    for slug, entry in headers.CONSEQUENCES.items():
        for identifier in entry.taxonomy:
            assert references.taxonomy_url(identifier) is not None, (slug, identifier)
```

Add `from http_security_test import references` to the imports at `tests/test_headers.py:28`.

- [ ] **Step 4: Run to verify they fail**

```bash
python -m pytest tests/test_headers.py -k "consequence or slug" -v
```

Expected: `test_every_emittable_code_declares_consequences` FAILS (the table is empty), `test_every_defined_slug_is_named_by_some_code` FAILS (nothing names them). The other four pass vacuously — that is expected and is why Tasks 4-6 exist.

- [ ] **Step 5: Export**

In `__init__.py`, add `CONSEQUENCES` and `Consequence` to the `from .catalog import` line, `CODE_CONSEQUENCES` and `consequences` to the `from .findings import` block, and all four to `__all__` in alphabetical position.

- [ ] **Step 6: Report, do not commit**

**Do not run any git command that writes.** A PreToolUse hook denies
`add` and `commit` outright and will stop you; that is the repository's
rule, not a misconfiguration, so do not work around it. Leave every change
in the working tree. The controller snapshots your files for review and the
human owns every commit.

Write your report to the report file named in your dispatch, listing the
files you touched, the commands you ran and their output. Return the short
status contract only.

______________________________________________________________________

### Task 4: Map the classic five

CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy — the families where nearly every code carries a consequence.

**Files:**

- Modify: `http_security_test/findings.py` (`CODE_CONSEQUENCES`)

**Interfaces:**

- Consumes: `CODE_CONSEQUENCES` from Task 3.

- [ ] **Step 1: Add the mappings**

```python
CODE_CONSEQUENCES = {
    # -- Content-Security-Policy
    "csp-deprecated-directive": (),      # parsed and ignored; nothing was lost
    "csp-frame-ancestors-wildcard": ("clickjacking",),
    "csp-http-source": ("mitm", "xss"),  # a plaintext script source is swappable
    "csp-invalid-keyword": ("xss",),
    "csp-ip-source": (),                 # browsers do not match it; a dev leftover
    "csp-missing": ("xss",),
    "csp-missing-semicolon": ("xss",),
    "csp-no-base-uri": ("xss",),
    "csp-no-default-src": ("xss",),
    "csp-no-frame-ancestors": ("clickjacking",),
    "csp-no-object-src": ("xss",),
    "csp-nonce-weak": ("xss",),
    "csp-plain-scheme": ("xss",),
    "csp-report-to-undefined": (),       # reporting: the operator loses a report
    "csp-ro-unenforced": (),             # report-only content decides nothing
    "csp-unknown-directive": (),         # what it meant to do is unknowable
    "csp-unsafe-eval": ("xss",),
    "csp-unsafe-inline": ("xss",),
    # Not xss: the message is explicit that injected CSS cannot run script. It
    # can redress the interface and read page data through selector-driven
    # requests, which is those two slugs exactly.
    "csp-unsafe-inline-style": ("clickjacking", "data-disclosure"),
    "csp-wildcard": ("xss",),
    # -- Strict-Transport-Security
    "hsts-malformed": ("mitm",),
    "hsts-max-age-short": ("mitm",),
    "hsts-max-age-zero": ("mitm",),
    "hsts-missing": ("mitm",),
    "hsts-no-include-subdomains": ("mitm",),
    "hsts-not-preloaded": ("mitm",),
    "hsts-preload-ineffective": ("mitm",),
    # -- X-Frame-Options
    "xfo-allow-from": ("clickjacking",),
    "xfo-invalid": ("clickjacking",),
    "xfo-missing": ("clickjacking",),
    # -- X-Content-Type-Options
    # CAPEC names this exactly -- CAPEC-209 "XSS Using MIME Type Mismatch" --
    # which is why there is no separate mime-confusion slug. The overlay in
    # Task 7 attaches that id to the code.
    "xcto-invalid": ("xss",),
    "xcto-missing": ("xss",),
    # -- Referrer-Policy
    "rp-invalid": ("data-disclosure",),
    "rp-missing": ("data-disclosure",),
    "rp-unsafe-url": ("data-disclosure",),
}
```

- [ ] **Step 2: Run the suite**

```bash
python -m pytest tests/test_headers.py -k "consequence or slug" -v
```

Expected: `test_every_emittable_code_declares_consequences` still FAILS (67 codes unmapped), `test_every_slug_a_code_names_is_defined` PASSES, `test_every_defined_slug_is_named_by_some_code` still FAILS (four slugs unnamed).

- [ ] **Step 3: Report, do not commit**

**Do not run any git command that writes.** A PreToolUse hook denies
`add` and `commit` outright and will stop you; that is the repository's
rule, not a misconfiguration, so do not work around it. Leave every change
in the working tree. The controller snapshots your files for review and the
human owns every commit.

Write your report to the report file named in your dispatch, listing the
files you touched, the commands you ran and their output. Return the short
status contract only.

______________________________________________________________________

### Task 5: Map the cross-origin story

CORS, the isolation family, Clear-Site-Data, X-Permitted-Cross-Domain-Policies, X-XSS-Protection. **This is the task with the surprising result** — read the codes' messages before accepting the mappings.

**Files:**

- Modify: `http_security_test/findings.py` (`CODE_CONSEQUENCES`)

- [ ] **Step 1: Add the mappings**

```python
    # -- Access-Control-* : seven of nine carry nothing, and that is the result.
    # Read the messages: these describe a response that FAILS CLOSED. "the
    # preflight fails", "no cross-origin read succeeds", "browsers refuse
    # outright". They are availability and interop defects, not exposure -- the
    # same reading CLAUDE.md already applies to ACAH: *. Only the two below
    # widen access to anybody.
    "acac-ineffective": (),
    "acah-credentials-wildcard": (),
    "acam-credentials-wildcard": (),
    "acam-forbidden-method": (),
    "aceh-credentials-wildcard": (),
    "acma-invalid": (),
    "acao-credentials-wildcard": (),
    "acao-invalid-origin": (),
    "acao-multiple-origins": (),
    "acao-null": ("cors-data-theft",),   # any sandboxed frame can send Origin: null
    "acao-wildcard": ("cors-data-theft",),
    # -- Cross-Origin-Embedder-Policy
    "coep-invalid": ("cross-origin-leak",),
    "coep-missing": ("cross-origin-leak",),
    # Loss of function, not of protection: the message is about
    # crossOriginIsolated staying false and SharedArrayBuffer being unavailable.
    "coep-no-isolation": (),
    "coep-report-to-undefined": (),
    "coep-ro-unenforced": (),
    "coep-unsafe-none": ("cross-origin-leak",),
    # -- Cross-Origin-Opener-Policy
    "coop-missing": ("cross-origin-leak",),
    "coop-report-to-undefined": (),
    "coop-ro-unenforced": (),
    "coop-unsafe-none": ("cross-origin-leak",),
    # -- Cross-Origin-Resource-Policy
    "corp-cross-origin": ("cross-origin-leak",),
    "corp-invalid": ("cross-origin-leak",),
    "corp-missing": ("cross-origin-leak",),
    # -- Clear-Site-Data: every one of these is a logout that does not clear.
    "csd-empty": ("cache-exposure",),
    "csd-unknown-type": ("cache-exposure",),
    "csd-unquoted": ("cache-exposure",),
    # -- X-Permitted-Cross-Domain-Policies. CWE-942 is literally "Permissive
    # Cross-domain Security Policy with Untrusted Domains", written for this.
    "xpcdp-all": ("cors-data-theft",),
    "xpcdp-deprecated": (),              # the restrictive setting; no defect
    "xpcdp-invalid": ("cors-data-theft",),
    "xpcdp-policy-file": ("cors-data-theft",),
    # -- X-XSS-Protection
    "xxp-blocked": ("cross-origin-leak",),  # the message names a side channel
    "xxp-deprecated": (),                   # "present but disabled" is correct
    "xxp-enabled": ("xss",),                # the auditor introduced XSS
    "xxp-invalid": (),                      # falls back to a default that is inert
```

- [ ] **Step 2: Run**

```bash
python -m pytest tests/test_headers.py -k "consequence or slug" -v
```

Expected: the two bijection tests still FAIL (31 codes unmapped, `permission-abuse` still unnamed).

- [ ] **Step 3: Report, do not commit**

**Do not run any git command that writes.** A PreToolUse hook denies
`add` and `commit` outright and will stop you; that is the repository's
rule, not a misconfiguration, so do not work around it. Leave every change
in the working tree. The controller snapshots your files for review and the
human owns every commit.

Write your report to the report file named in your dispatch, listing the
files you touched, the commands you ran and their output. Return the short
status contract only.

______________________________________________________________________

### Task 6: Map the rest, and every empty

Permissions-Policy, Feature-Policy, Integrity-Policy, the reporting family, the legacy headers, `Content-Type`, `duplicate-headers`. Completing this makes both bijection tests pass.

**Files:**

- Modify: `http_security_test/findings.py` (`CODE_CONSEQUENCES`)

- [ ] **Step 1: Add the mappings**

```python
    # -- Permissions-Policy / Feature-Policy
    "pp-empty": ("permission-abuse",),
    "pp-invalid": ("permission-abuse",),        # whole header ignored
    "pp-legacy-syntax": ("permission-abuse",),  # whole header ignored
    "pp-missing": ("permission-abuse",),
    "pp-wildcard": ("permission-abuse",),
    "fp-conflicts": (),                         # says which header wins, not a risk
    "fp-deprecated": (),
    "fp-empty": ("permission-abuse",),
    "fp-wildcard": ("permission-abuse",),
    # -- Integrity-Policy. Its job is to refuse subresources with no integrity
    # metadata, so a policy that enforces nothing leaves a compromised CDN
    # script running in the page.
    "ip-endpoints-undefined": (),               # reporting only
    "ip-invalid": ("xss",),
    "ip-no-blocked-destinations": ("xss",),
    "ip-ro-unenforced": (),
    "ip-sources-without-inline": ("xss",),
    "ip-style-unsupported": (),                 # no engine implements it either way
    "ip-unknown-destination": ("xss",),
    # -- Reporting. The whole family carries nothing, which is the same
    # reasoning that rates it all `note`: a reporting failure costs the
    # operator information and withholds no browser protection.
    "re-endpoint-undeliverable": (),
    "re-ineffective": (),
    "re-invalid": (),
    "rt-endpoint-undeliverable": (),
    "rt-ineffective": (),
    "rt-invalid": (),
    # -- Legacy CSP aliases: if one of these is the only policy sent, the page
    # has no policy at all.
    "xcsp-deprecated": ("xss",),
    "xwkcsp-deprecated": ("xss",),
    # -- Everything else that withholds no protection.
    "ct-no-charset": (),        # the message says outright: not a defect
    "ect-deprecated": (),
    "hpkp-deprecated": (),      # browsers removed pinning; the pins bind nothing
    "hpkp-ro-deprecated": (),
    "p3p-deprecated": (),
    "xdo-deprecated": (),
    "xdpc-nonstandard": (),     # `on` is the default everywhere it works
    # Ambiguity rather than a named risk: which value wins is client-specific,
    # so what it costs depends on which header repeated and cannot be said here.
    "duplicate-headers": (),
}
```

- [ ] **Step 2: Run the whole suite**

```bash
python -m pytest tests/ -q && ruff check
```

Expected: all pass. Confirm the split:

```bash
python3 -c "
from http_security_test import CODE_CONSEQUENCES as C
n = sum(1 for v in C.values() if v)
print('%d codes with a consequence, %d with none, %d total' % (n, len(C)-n, len(C)))
"
```

Expected: `61 codes with a consequence, 41 with none, 102 total`.

(An earlier draft of this line said 60/42. That was an arithmetic slip in
the plan's own hand-count -- Cross-Origin-Embedder-Policy contributes three
non-empty codes, not two. The mappings above are correct; the summary was
not. Verified against the built table on 2026-08-23.)

- [ ] **Step 3: Mutation-test the bijections**

```bash
SCRATCH=$(mktemp -d)
cp http_security_test/findings.py "$SCRATCH/"
sed -i '/"rp-unsafe-url": ("data-disclosure",),/d' http_security_test/findings.py
python -m pytest tests/test_headers.py -k consequence -q   # expect FAIL
cp "$SCRATCH/findings.py" http_security_test/findings.py
sed -i 's/"cache-exposure": Consequence(/"unused-slug": Consequence(/' http_security_test/catalog.py
python -m pytest tests/test_headers.py -k slug -q          # expect FAIL both directions
# The tree carries every prior task's uncommitted work, so a dirty-file
# check proves nothing here. Restore with the inverse sed below.
cp "$SCRATCH/findings.py" http_security_test/findings.py
```

Restore `catalog.py` by reverting the `sed` with the inverse substitution, not with git.

- [ ] **Step 4: Report, do not commit**

**Do not run any git command that writes.** A PreToolUse hook denies
`add` and `commit` outright and will stop you; that is the repository's
rule, not a misconfiguration, so do not work around it. Leave every change
in the working tree. The controller snapshots your files for review and the
human owns every commit.

Write your report to the report file named in your dispatch, listing the
files you touched, the commands you ran and their output. Return the short
status contract only.

______________________________________________________________________

### Task 7: The `CODE_TAXONOMY` overlay

**Files:**

- Modify: `http_security_test/findings.py`
- Modify: `tests/test_headers.py`

**Interfaces:**

- Produces: `CODE_TAXONOMY: dict[str, tuple[str, ...]]` — **sparse**; `taxonomy(code)` returns the union of the code's slugs' identifiers and this overlay.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_overlay_adds_to_a_slug_rather_than_replacing_it():
    # Union, never replace. Adding precision must not delete the general
    # classification: CAPEC-209 is a Detailed pattern beneath CAPEC-63.
    ids = headers.taxonomy("xcto-missing")
    assert "CAPEC-209" in ids
    assert "CWE-79" in ids and "CAPEC-63" in ids


def test_a_code_with_no_overlay_entry_inherits_its_slugs():
    assert headers.taxonomy("csp-unsafe-inline") == ("CAPEC-63", "CWE-79")


def test_a_code_with_no_consequence_has_no_taxonomy():
    assert headers.taxonomy("rt-invalid") == ()


def test_taxonomy_is_sorted_by_scheme_then_numeric_id():
    # Not lexically, or CWE-1021 sorts before CWE-79.
    assert headers.taxonomy("xfo-missing") == ("CAPEC-103", "CAPEC-222", "CWE-1021")


def test_the_overlay_is_partial_and_only_checked_one_way():
    """The one deliberately non-bijective table in the package.

    An absent entry means "no better id was found", not "none exists", so
    completeness is not a property it claims. Do not make this symmetrical by
    minting 102 curated entries to satisfy a test.
    """
    assert set(headers.CODE_TAXONOMY) <= _every_code_headers_can_emit()
    for code, ids in headers.CODE_TAXONOMY.items():
        assert isinstance(ids, tuple), code
        for identifier in ids:
            assert references.taxonomy_url(identifier) is not None, (code, identifier)
```

- [ ] **Step 2: Run to verify failure**

```bash
python -m pytest tests/test_headers.py -k "overlay or taxonomy or inherits" -v
```

Expected: FAIL, no attribute `CODE_TAXONOMY`.

- [ ] **Step 3: Implement**

In `findings.py`, after `CODE_CONSEQUENCES`:

```python
# A sparse overlay: a specific published entry, where one describes a code
# better than its slug's general classification does. Most codes have no entry
# and simply inherit. This is the one table in the package that is NOT a
# bijection with the emittable codes, and that is deliberate -- an absent entry
# means "no better id was found", never "none exists".
CODE_TAXONOMY = {
    # CAPEC-209 "XSS Using MIME Type Mismatch" is the exact mechanism.
    "xcto-invalid": ("CAPEC-209",),
    "xcto-missing": ("CAPEC-209",),
    # CAPEC-102 "Session Sidejacking" is the specific loss, where the slug's
    # CAPEC-117 "Interception" is the Meta-level parent.
    "hsts-malformed": ("CAPEC-102",),
    "hsts-max-age-zero": ("CAPEC-102",),
    "hsts-missing": ("CAPEC-102",),
    # CAPEC-222 "iFrame Overlay" joins CWE-1021 and names the delivery.
    "xfo-allow-from": ("CAPEC-222",),
    "xfo-invalid": ("CAPEC-222",),
    "xfo-missing": ("CAPEC-222",),
    "csp-frame-ancestors-wildcard": ("CAPEC-222",),
    "csp-no-frame-ancestors": ("CAPEC-222",),
}


def _identifier_sort_key(identifier):
    # By scheme then NUMERIC id. Lexically, CWE-1021 sorts before CWE-79.
    scheme, _, number = identifier.partition("-")
    return (scheme, int(number))


def taxonomy(code):
    """Every taxonomy identifier for a code: its slugs' union the overlay's."""
    from .catalog import CONSEQUENCES

    ids = {i for s in consequences(code) for i in CONSEQUENCES[s].taxonomy}
    ids.update(CODE_TAXONOMY.get(code, ()))
    return tuple(sorted(ids, key=_identifier_sort_key))
```

The `catalog` import is function-local **on purpose**: `findings.py` is a leaf that `catalog.py` must be free to import, and a module-level import here would make that a cycle.

- [ ] **Step 4: Run**

```bash
python -m pytest tests/test_headers.py -k "overlay or taxonomy or inherits" -v && ruff check
```

Expected: 5 passing, ruff clean.

- [ ] **Step 5: Export, then report**

Add `CODE_TAXONOMY` and `taxonomy` to `__init__.py` imports and `__all__`.

**Do not run any git command that writes.** A PreToolUse hook denies
`add` and `commit` outright and will stop you; that is the repository's
rule, not a misconfiguration, so do not work around it. Leave every change
in the working tree. The controller snapshots your files for review and the
human owns every commit.

Write your report to the report file named in your dispatch, listing the
files you touched, the commands you ran and their output. Return the short
status contract only.

______________________________________________________________________

### Task 8: The report schema

**Files:**

- Modify: `http_security_test/reporting.py`
- Modify: `tests/test_headers.py`

**Interfaces:**

- Consumes: `consequences()`, `taxonomy()`, `CODE_HEADER`, `references.header_url`.

- Produces: `finding_as_dict()` gains `consequences`; `report()` gains `response["references"]` = `{"headers": [...], "taxonomy": [...]}`.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_finding_carries_its_consequences():
    present = headers.parse_headers([("Content-Security-Policy", "script-src 'unsafe-inline'")])
    doc = headers.report(present)
    row = next(f for f in doc["response"]["findings"] if f["code"] == "csp-unsafe-inline")
    assert row["consequences"] == ["xss"]


def test_consequences_are_always_present_even_when_empty():
    # The `data` rule: content this package derived is always there, so a
    # consumer never has to test for the key.
    present = headers.parse_headers([("Report-To", "not json")])
    doc = headers.report(present)
    row = next(f for f in doc["response"]["findings"] if f["code"] == "rt-invalid")
    assert row["consequences"] == []


def test_the_references_block_collects_headers_and_taxonomy():
    present = headers.parse_headers([("X-Frame-Options", "ALLOWALL")])
    block = headers.report(present)["response"]["references"]
    assert "X-Frame-Options" in block["headers"]
    assert "CWE-1021" in block["taxonomy"]
    assert "CAPEC-222" in block["taxonomy"]


def test_the_references_block_is_deduped_and_sorted_numerically():
    present = headers.parse_headers([("X-Frame-Options", "ALLOWALL")])
    block = headers.report(present)["response"]["references"]
    assert block["headers"] == sorted(set(block["headers"]))
    # CWE-1021 after CWE-79: by scheme then numeric id, not lexically.
    cwes = [i for i in block["taxonomy"] if i.startswith("CWE-")]
    assert cwes == sorted(cwes, key=lambda i: int(i.split("-")[1]))


def test_the_references_headers_are_canonical_not_lowercased():
    # duplicate-headers findings carry a lowercased name; the block must
    # canonicalise or header_url() resolves nothing for them.
    present = headers.parse_headers(
        [("X-Frame-Options", "DENY"), ("X-Frame-Options", "SAMEORIGIN")]
    )
    block = headers.report(present)["response"]["references"]
    assert "x-frame-options" not in block["headers"]
    assert "X-Frame-Options" in block["headers"]


def test_references_is_fed_by_findings_only():
    # A response with nothing wrong reads as "no reading needed".
    clean = headers.parse_headers(
        [("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")]
    )
    block = headers.report(clean)["response"]["references"]
    assert isinstance(block["headers"], list)
    assert isinstance(block["taxonomy"], list)
```

- [ ] **Step 2: Run to verify failure**

```bash
python -m pytest tests/test_headers.py -k "consequences or references_block or references_is or references_headers" -v
```

Expected: FAIL with `KeyError: 'consequences'` and `KeyError: 'references'`.

- [ ] **Step 3: Implement**

In `reporting.py`, add `from . import references` and `from .findings import consequences, order_findings, severity, taxonomy, CODE_HEADER` to the imports, then:

```python
def finding_as_dict(finding, message=True):
    row = {
        "header": finding.header,
        "code": finding.code,
        "level": severity(finding.code),
        "data": dict(finding.data or {}),
        # Always present, [] included, so a consumer never tests for the key.
        # A hint about potential risk, never a claim the risk is reachable.
        "consequences": list(consequences(finding.code)),
    }
    if message:
        row["message"] = catalog.describe(finding)
    return row


def _references(findings):
    """The reading list for one response: identifiers, never URLs.

    Fed by findings only -- a header appears because something was said about
    it. Header names come from CODE_HEADER rather than from the finding,
    because a duplicate-headers finding carries the lowercased name it read out
    of the mapping and every other finding carries canonical casing.
    """
    names, ids = set(), set()
    for finding in findings:
        declared = CODE_HEADER.get(finding.code)
        if declared is not None:
            names.add(declared)
        ids.update(taxonomy(finding.code))
    return {
        "headers": sorted(names),
        # By scheme then NUMERIC id: lexically, CWE-1021 sorts before CWE-79.
        "taxonomy": sorted(ids, key=_identifier_sort_key),
    }
```

`_identifier_sort_key` is private to `findings.py` but imported here by name rather than reached through a module alias, so that the one place defining "scheme then numeric id" stays the only place. Add it to the `from .findings import` list alongside `consequences`, `taxonomy` and `CODE_HEADER`.

Then in `report()`, after the `response` dict is built and before the `raw` block:

```python
    response = {
        "findings": [finding_as_dict(f, message=message) for f in findings],
        "inventory": inventory(present),
        "references": _references(findings),
    }
```

- [ ] **Step 4: Run**

```bash
python -m pytest tests/ -q && ruff check
```

Expected: all pass.

- [ ] **Step 5: Update the module docstring**

`reporting.py`'s docstring shows the schema. Add the two new keys to the example block and one paragraph:

```
The `references` block is the reading list for this response, as identifiers
rather than links: a header name and a CWE identifier both resolve to a stable
URL by pattern, and a name does not rot. `references.header_url()` and
`taxonomy_url()` resolve them. It is fed by findings only, so a response with
nothing wrong carries two empty lists.
```

- [ ] **Step 6: Report, do not commit**

**Do not run any git command that writes.** A PreToolUse hook denies
`add` and `commit` outright and will stop you; that is the repository's
rule, not a misconfiguration, so do not work around it. Leave every change
in the working tree. The controller snapshots your files for review and the
human owns every commit.

Write your report to the report file named in your dispatch, listing the
files you touched, the commands you ran and their output. Return the short
status contract only.

______________________________________________________________________

### Task 9: Terminal and `explain`

**Files:**

- Modify: `http_security_test/cli/text.py:87-99`

- Modify: `http_security_test/cli/commands.py:26-40`

- Modify: `tests/test_cli_text.py`, `tests/test_cli_explain.py`

- Regenerate: `tests/cli_terminal_snapshot.txt`

- [ ] **Step 1: Write the failing tests**

`tests/test_cli_text.py` builds its input by hand: a module-level `FINDINGS` list at line 26 feeding a `DOCUMENT` dict at line 50. It is **not** produced by `report()`, so the renderer sees exactly what the fixture says.

That matters twice. First, `text.py` will read `finding.get("consequences")`, so the fixture as it stands renders unchanged and **the snapshot would not move at all** — the feature would look tested and be untested. Second, it gives a free negative case. Extend `FINDINGS` (line 26) so two entries carry consequences and one carries none:

```python
FINDINGS = [
    {
        "header": "Content-Security-Policy",
        "code": "csp-missing",
        "level": "warning",
        "data": {},
        "message": "missing",
        "consequences": ["xss"],
    },
    {
        "header": "Access-Control-Allow-Origin",
        "code": "acao-null",
        "level": "error",
        "data": {"origin": "null"},
        "message": "permits the null origin",
        "consequences": ["cors-data-theft"],
    },
    {
        # Deliberately keeps no consequences: xdpc-nonstandard really maps to
        # (), so this is the negative case rather than an oversight.
        "header": "X-DNS-Prefetch-Control",
        "code": "xdpc-nonstandard",
        "level": "note",
        "data": {},
        "message": "never standardised",
        "consequences": [],
    },
]
```

Then add:

```python
def test_a_finding_line_names_its_consequences():
    out = text.render(DOCUMENT)
    assert "[xss]" in out
    assert "[cors-data-theft]" in out


def test_a_finding_with_no_consequence_gets_no_brackets():
    line = next(
        l for l in text.render(DOCUMENT).splitlines() if "X-DNS-Prefetch-Control" in l
    )
    assert "[" not in line


def test_a_finding_missing_the_key_entirely_still_renders():
    # A caller on the old schema, or a hand-built document. .get() not [].
    stale = {"header": "X-Frame-Options", "code": "xfo-missing",
             "level": "warning", "data": {}, "message": "missing"}
    assert "X-Frame-Options" in "\n".join(text._finding_lines(
        {"response": {"findings": [stale]}}, False, False, "note"))
```

In `tests/test_cli_explain.py`:

```python
def test_explain_names_the_owning_header(capsys):
    main(["explain", "csp-unsafe-inline"])
    assert "Content-Security-Policy" in capsys.readouterr().out


def test_explain_lists_consequences_and_urls(capsys):
    main(["explain", "csp-unsafe-inline"])
    out = capsys.readouterr().out
    assert "xss" in out
    assert "https://cwe.mitre.org/data/definitions/79.html" in out
    assert "developer.mozilla.org" in out


def test_explain_says_nothing_about_consequences_when_there_are_none(capsys):
    main(["explain", "rt-invalid"])
    out = capsys.readouterr().out
    assert "consequences" not in out
```

- [ ] **Step 2: Run to verify failure**

```bash
python -m pytest tests/test_cli_text.py tests/test_cli_explain.py -v
```

- [ ] **Step 3: Implement the terminal line**

In `cli/text.py`, replace the append at lines 91-94:

```python
        # Consequences ride on the message line rather than a line of their
        # own: "what could this lead to" is what a reader runs a scan for, and
        # the slugs are short enough not to crowd it.
        slugs = finding.get("consequences") or []
        suffix = "  [%s]" % ", ".join(slugs) if slugs else ""
        lines.append(
            "  %s %-34s %s%s"
            % (level, finding["header"], finding.get("message", finding["code"]), suffix)
        )
```

- [ ] **Step 4: Implement `explain`**

Replace `do_explain` in `cli/commands.py`:

```python
def do_explain(args):
    """Print each named code's header, level, template, consequences and links."""
    wanted = list(args.code) if args.code else sorted(FINDING_SEVERITY)
    unknown = [code for code in wanted if code not in FINDING_SEVERITY]
    for code in wanted:
        if code not in FINDING_SEVERITY:
            continue
        header = CODE_HEADER[code]
        print("%-34s %-8s %s" % (code, FINDING_SEVERITY[code], header or "(response)"))
        print(MESSAGES[code])
        slugs = consequences(code)
        if slugs:
            print()
            for slug in slugs:
                entry = CONSEQUENCES[slug]
                print("consequences: %s -- %s" % (slug, entry.name))
                print("              %s" % entry.text)
        links = []
        if header:
            links.append(references.header_url(header))
        links.extend(references.taxonomy_url(i) for i in taxonomy(code))
        for link in [link for link in links if link]:
            print("  %s" % link)
        print()
    for code in unknown:
        print("%s: no such code" % code, file=sys.stderr)
    return 2 if unknown else 0
```

Add to the imports at `cli/commands.py:22`:

```python
from .. import (
    CODE_HEADER,
    CONSEQUENCES,
    FINDING_SEVERITY,
    MESSAGES,
    consequences,
    references,
    report,
    taxonomy,
)
```

- [ ] **Step 5: Run and regenerate the snapshot**

```bash
python -m pytest tests/test_cli_text.py tests/test_cli_explain.py -v
UPDATE_CLI_SNAPSHOT=1 python -m pytest tests/ -k cli_snapshot
git diff tests/cli_terminal_snapshot.txt
```

The variable is `UPDATE_CLI_SNAPSHOT` and the selector is `-k cli_snapshot` — verified at `tests/test_cli_text.py:204-209`. Note this is a *different* snapshot from the analyser's, which uses `UPDATE_MESSAGE_SNAPSHOT` and `-k snapshot`; that one must **not** move, since no message text changes in this work.

**Read the diff before keeping it.** Exactly two lines should change, each gaining a trailing `  [xss]` or `  [cors-data-theft]`; the X-DNS-Prefetch-Control line must be untouched. If the diff is empty, the fixture edit in Step 1 did not land and the feature is untested.

- [ ] **Step 6: Full suite**

```bash
python -m pytest tests/ -q && ruff check
```

- [ ] **Step 7: Report, do not commit**

**Do not run any git command that writes.** A PreToolUse hook denies
`add` and `commit` outright and will stop you; that is the repository's
rule, not a misconfiguration, so do not work around it. Leave every change
in the working tree. The controller snapshots your files for review and the
human owns every commit.

Write your report to the report file named in your dispatch, listing the
files you touched, the commands you ran and their output. Return the short
status contract only.

______________________________________________________________________

### Task 10: Documentation

**Files:**

- Modify: `CLAUDE.md`

- [ ] **Step 1: Update the Layout section**

Add `references.py` to the module list after `catalog.py`:

```
references.py  header and taxonomy URLs -- the only module holding a link
```

And to the dependency block:

```
findings, message, catalog, references  ->  (nothing)
```

- [ ] **Step 2: Update the output schema section**

Add `consequences` and `references` to the example JSON, and one paragraph of rationale drawn from spec §4 — identifiers rather than URLs, one key rather than scattered, fed by findings only, sorted by scheme then numeric id.

- [ ] **Step 3: Record the three facts that cost a corpus query**

Under "Deliberately decided":

- CWE 4.20 has no weakness for MIME sniffing or XS-Leaks, and none written for permission delegation. Do not re-propose CWE ids as the consequence vocabulary.

- A Pillar-level CWE is not a fallback: CWE-693 and CWE-284 are true of every finding here, so filling a gap with one makes it mean "unclassified".

- Pick a CAPEC id by its CWE cross-reference, not by its name. Keyword matching was wrong three times in a dozen.

- CWE's cookie coverage is rich — 1004, 1275, 614, 315, 539, 565, 784 — and maps onto the parked `Set-Cookie` prefix work.

- [ ] **Step 4: Move the closed parked item**

Delete the "A public code-to-header table" entry from "Parked, with intent to do" and note in the Status section that `CODE_HEADER` now exists and that `test_the_declared_header_is_the_header_the_finding_carries` is what makes it stronger than the test it replaced.

- [ ] **Step 5: Update Status counts**

```bash
python -m pytest tests/ -q 2>&1 | tail -2
```

Update the test count and add: 102 codes each with a rating, a message template, a declared header and a consequence tuple; 8 consequence slugs; `references.py` resolving 40 headers.

- [ ] **Step 6: Report, do not commit**

**Do not run any git command that writes.** A PreToolUse hook denies
`add` and `commit` outright and will stop you; that is the repository's
rule, not a misconfiguration, so do not work around it. Leave every change
in the working tree. The controller snapshots your files for review and the
human owns every commit.

Write your report to the report file named in your dispatch, listing the
files you touched, the commands you ran and their output. Return the short
status contract only.

______________________________________________________________________

## Self-Review

**Spec coverage.** §1 `CODE_HEADER` → Task 1. §2 vocabulary → Task 3 (table) + Tasks 4-6 (mappings). §3 taxonomies → Task 3's `CONSEQUENCES.taxonomy` + Task 7's overlay. §4 schema → Task 8. §5 `references.py` → Task 2. §6 terminal and `explain` → Task 9. §7 invariants → tests in Tasks 1, 2, 3, 7, 8. §8 order of work → Tasks 1-10, with the spec's steps 5 and 6 swapped so the overlay lands before the schema that serialises it. §9 CLAUDE.md → Task 10.

**Known gaps, both deliberate.** The spec's §6 `explain` mockup wraps the message across lines; the real renderer prints one line per finding, so Task 9 follows the code rather than the mockup. And the spec's parked **hygiene axis** has no task: it is a sibling field to `consequences`, not a ninth slug, and it waits for the inverted interesting-headers work where `Server` and `X-Powered-By` banners give it evidence. If a reviewer asks why `hpkp-deprecated` and `rt-invalid` carry `()` when both plainly indicate a neglected server, that is the answer — the signal is real and belongs on the other axis.

**Type consistency.** `consequences(code) -> tuple[str, ...]` and `taxonomy(code) -> tuple[str, ...]` are used with those names in Tasks 3, 7, 8 and 9. `CONSEQUENCES[slug].taxonomy` is a tuple in Tasks 3 and 7. `header_url` / `taxonomy_url` return `str | None` and every caller filters `None` (Task 9 Step 4). `_identifier_sort_key` is defined in Task 7 and imported by name in Task 8.
