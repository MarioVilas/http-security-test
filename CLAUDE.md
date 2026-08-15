# http-security-test

An HTTP security header **analysis engine**. Library only — there is deliberately
no CLI. It began as a fork of `shcheck` and outgrew it; the fork's tool has been
deleted and only the analyzer survives.

GPL-3.0-or-later. Every source file carries the notice.

## Layout

```
findings.py    Finding, FINDING_SEVERITY, SEVERITIES, severity(), order_findings()
message.py     the header mapping model: parse_headers, parse_raw_headers, lookups
csp.py         Content-Security-Policy                      (largest module)
hsts.py        Strict-Transport-Security + the ONLY third-party dependency
isolation.py   COOP / COEP / CORP / CORS
policies.py    Permissions-Policy + Feature-Policy
legacy.py      the obsolete headers
response.py    tables, registry, cross-header rules, analyze_all, orphan headers
__init__.py    public API
```

Dependencies run one way and there are no cycles:

```
findings, message  ->  (nothing)
csp, hsts, isolation, legacy, policies  ->  findings [, message]
response  ->  all of the above
```

**The boundary that matters:** a family module answers *"what is wrong with this
header"* — a value in, findings out, no knowledge of siblings. `response.py`
answers *"what is wrong with this response"* — which headers should have been
there, what the ones present mean together, what a sibling has made moot. Cross-
header rules cannot be split by family; they belong in `response.py`.

`message.py` is the HTTP **message** model, not the response model. A request
carries headers the same way, so a future `request.py` shares it.

`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
`Clear-Site-Data` and `Integrity-Policy` live in `response.py` because they have
no family. That is the resting point, not a half-measure — a module each would
be overkill.

## Design principles

These were expensive to arrive at. Do not quietly reverse them.

1. **Findings are facts; ratings are policy — but published.** A finding is
   `(header, code, message)`. The ratings are SARIF levels (`error` / `warning` /
   `note`) so a consumer can adopt, remap, or ignore them.
2. **Inventories are facts, findings are judgments.** Nothing is withheld from an
   inventory because of what it contains. HSTS appears in a `missing` inventory on
   a plaintext target; the *finding* is what `secure=False` suppresses.
3. **Severity rule.** `error` = the header does not deliver the protection its
   presence implies (browsers ignore it, or it permits the very thing it exists to
   stop). `warning` = it protects, but a hardening directive is missing. `note` =
   a fact with no defect.
4. **A false positive on a correct configuration is the worst outcome.** This
   project exists because the tool it forked called `default-src 'self'` unsafe by
   substring match. Two Criticals found in review were the same bug in new
   clothes (`require-corp; report-to="…"` read as invalid; the nonce +
   `'unsafe-inline'` idiom flagged as XSS). Assume the next one is too.
5. **Only an effective header earns a suppression.** An `X-Frame-Options`
   browsers ignore protects nothing, and neither does `frame-ancestors *`.
6. **What a non-enforcing header permits decides nothing.** Report-only content
   is never analyzed; Feature-Policy's content is ignored once Permissions-Policy
   is present; `coep-missing` is excused unless COOP asks for isolation.
7. **Code naming.** `<prefix>-deprecated` means "present, legacy, no defect".
   Known exception: `xfo-deprecated` (ALLOW-FROM) is rated `error` — a real
   defect. Renaming it to `xfo-allow-from` is still open and free until the codes
   have consumers. The table and the code name are independent: membership of
   `DEPRECATED_HEADERS` says "do not reach for this", the suffix says what is
   wrong with it. `xdpc-nonstandard` is in that table without a `-deprecated`
   code because X-DNS-Prefetch-Control was never standardised in the first
   place, and calling that deprecated would be false.

## Invariants the test suite pins

Breaking one of these silently is easy; each has a test, and each has been
mutation-verified.

- Every emittable code has a rating, **and** every rated code is emittable. The
  corpus in `tests/` is what makes that checkable — a new code needs a case there
  or the completeness tests pass vacuously.
- A code belongs to exactly one header. **Exception:** `duplicate-headers`, which
  is about the response; it is explicitly exempted in that test.
- Findings are deduped by `(header, code)`, never by `code` alone.
- Output order is deterministic: the tables are tuples, not sets. A set literal
  here reorders output per process.

## The header mapping (easy to get wrong)

`present` maps a lowercased name to a **list** of values. `analyze_all` accepts a
plain string per header too, so the ordinary caller is unaffected.

Build it with `parse_headers(pairs)` or `parse_raw_headers(raw)` — never with a
dict comprehension. Verified stdlib behaviour:

| access | value |
|---|---|
| `getheaders()` | both pairs, duplicates intact |
| `Message["name"]` | the **first** |
| `{k: v for k, v in pairs}` | the **last** |

Repeated headers are not a corner case. **Repeated CSP is enforced
conjunctively**: a coverage gap fires only if *no* policy closes it, a weakness
only if *every* policy permits it, and a syntax defect if *any* policy has it —
that split is `CSP_SYNTAX_CODES`. Getting this wrong inverts the verdict.

`REPEATABLE_HEADERS` (CSP, CSP-Report-Only, Set-Cookie) may legally repeat;
anything else repeated raises `duplicate-headers`. `_sole_value()` returns `None`
for a header repeated with values that disagree — no specification says which
wins, so no suppression can be earned from it.

## Working practices that paid off

- **Verify, don't assert.** Several confident claims this project ran on turned
  out false under test — including mine and the human's. Check stdlib behaviour
  with a constructed response; check browser support against the local caniuse
  checkout; check a "this is unused" hunch by grepping call sites.
- **Mutation-test new guards.** Break the code, confirm the test fails, restore.
  A test that passes both ways is worse than none.
- **Refactors get behavioural equivalence checks.** `git show HEAD:<file>` into
  `/tmp`, run a corpus through old and new, diff the `(header, code)` sets. Both
  module splits were verified this way at 335 and 168 cases, zero mismatches.
- **Scripted edits fail silently, twice bitten.** `str.replace` with an
  indentation-prefixed pattern also matches deeper indentation (a 4-space tuple
  entry matched a 12-space constructor argument and corrupted a `Finding`). And an
  anchor edited earlier in the session no-ops without complaint. Assert the anchor
  exists and is unique before replacing.

## Human's preferences

- **Never commit.** The human owns the git workflow entirely — no `git add`,
  `commit`, `stash`, or anything that changes git state. An agent ran `git stash`
  once and flattened their staged changes.
- **They run `ruff format`.** Keep `ruff check` clean; do not reformat.
- **Ask, with options and a recommendation,** on policy and design calls
  (severity, schema, scope). They engage closely and will push back with evidence
  when a premise is wrong — that has repeatedly been the right call.

## Deliberately decided (do not re-litigate without new information)

- **Not analyzed:** `Document-Policy` (no closed value set, no delegation axis, no
  concrete configuration points of its own); `X-Content-Security-Policy` /
  `X-WebKit-CSP` contents (no browser reads them, so content decides nothing).
- **Not embedded:** csp-evaluator's 171-entry JSONP/Angular bypass lists — high
  catch rate, but curated data that ages, and the module has no upkeep burden
  today. The data-free checks from it *were* ported.
- `noopener-allow-popups` is accepted as a valid COOP value (caniuse: ~84%,
  Chromium and Safari; Firefox absent).
- `HSTS_MIN_MAX_AGE = 15552000` (180 days), chosen over the 6-month figure because
  Shodan shows 180 days is what sites actually send.
- `info` was renamed `note` throughout, including theme keys, to match SARIF.
- **`X-DNS-Prefetch-Control` is inventoried, never a gap.** It is in
  `DEPRECATED_HEADERS` and emits one `note`, `xdpc-nonstandard`. No finding can
  do better: OWASP's own browser testing (their issue #201) found DNS
  prefetching is a Chromium behaviour and only Chrome acts on the header at all,
  the local caniuse checkout has no feature entry for it, and `on` asks for the
  default. So `off` is a real measure in one engine, `on` is a no-op, and
  neither is a defect. Note that OWASP's `headers_add.json` *recommends* sending
  it — the note qualifies that, it does not contradict it.
- **`blocked-destinations=(style)` is treated as blocking nothing.** Chrome and
  Safari do not implement it and Firefox only behind
  `security.integrity_policy.stylesheet.enabled` (MDN BCD, matching OWASP's
  hand-testing). This is browser-support data with a shelf life: recheck it
  before trusting `IP_BLOCKING_DESTINATIONS`, and a style-only policy stops
  being inert the day an engine ships it.
- **Integrity-Policy's `endpoints` is unreliable in Firefox** — it enforces the
  blocking from 145 but ignores the directive and logs violations to the console
  instead (caniuse renders Firefox partial for exactly this; global support
  ~81.6%). Deliberately *not* a code: it would fire on every correct policy that
  asks for reports. `ip-endpoints-undefined` is the finding worth having.

## Parked, with intent to do

- **`Set-Cookie` analysis** — `Secure`, `HttpOnly`, `SameSite=None` without
  `Secure`, and the `__Host-` / `__Secure-` prefix rules. The mapping already
  supports repeated headers, so the blocker is gone; findings will need to
  identify *which* cookie.
- **The cache/cookie cross-header quirk — land it *with* the cookie parser, not
  before.** RFC 9111 §7.3: "the Set-Cookie response header field does not inhibit
  caching; a cacheable response with a Set-Cookie header field can be (and often
  is) used to satisfy subsequent requests to caches." So `Cache-Control: public`
  or `s-maxage` beside a `Set-Cookie` lets a shared cache hand one visitor's
  cookie to the next. Tempting to write as a two-header rule today — don't. **No
  header says a cookie is a session cookie.** On a `lang=en` this is not a
  finding at all, and shipping it standalone means guessing. `HttpOnly`,
  `SameSite`, and the `__Host-` / `__Secure-` prefixes are the signals that make
  it worth reporting, and they only exist once the cookie parser does.
- **`Pragma: no-cache` with nothing enforcing it** — same parcel, same reason: it
  is the other half of "does the analyzer judge cache values at all", and
  `find_cache_headers()` currently promises it does not. One code,
  `pragma-ineffective`, `error`, cross-header, in `response.py`. It fires only
  when no `Cache-Control` prevents storage. **Not a `DEPRECATED_HEADERS` entry**
  even though RFC 9111 §5.4 does say "this specification deprecates Pragma": that
  tuple means obsolete *security* headers whose absence is desired, and a
  `pragma-deprecated` note would fire on OWASP's own recommended pairing of
  `Cache-Control: no-store, max-age=0` with `Pragma: no-cache`. What makes the
  narrow case judgeable at all is that intent is visible — a *missing*
  `Cache-Control` says nothing about what the author wanted, a *present* `Pragma:
  no-cache` says exactly what they wanted, and §5.4 says they did not get it:
  "the meaning of `Pragma: no-cache` in responses was never specified".
- **Active checks** — Origin reflection is the highest-value CORS test and needs a
  second request with a forged `Origin`. Tool work, not analysis.
- **Inverted "interesting headers"** — report anything not on a *boring* list,
  rather than only known-interesting names. The human wants to compile their own
  list, behind its own switch.
- **`request.py`** — request parsing/analysis, sharing `message.py`.

## Reference material on disk

Read for ideas and reference, never copy.

- `./tmp/caniuse` — browser support, authoritative for "is this value worth accepting"
- `./tmp/csp-evaluator` — CSP evaluator from Google written in Node.js
- `./tmp/hstspreload` — Python library that maps Chromium's preload list
- `./tmp/header-issue-reporter` — Burp plugin, read for ideas only
- `./tmp/headers-analyzer` — Burp plugin, read for ideas only
- `./tmp/shcheck` — Tool that inspired the development of this one
- `./tmp/shcheck-fork` — Fork of the previous tool with some minor improvements
- `./tmp/www-project-secure-headers/` — OWASP Secure Headers documentation.
  `mainsite/01_headers.md` is the per-header reference; `ci/headers_add.json` and
  `ci/headers_remove.json` are machine-readable and CI-regenerated from the tables
  in `mainsite/03_best_practices.md`, so read those two rather than the prose.
  Several sections carry *browser tests they ran themselves* — worth more than the
  recommendations around them

## Status

85 codes (34 error / 27 warning / 24 note). 235 tests, 87 test functions, all
passing; `ruff check` clean. `pyproject.toml` is a placeholder — hatchling, no
README yet, `hstspreload` declared as the optional `[preload]` extra.
