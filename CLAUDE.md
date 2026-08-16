# http-security-test

An HTTP security header **analysis engine**. Library only — there is deliberately
no CLI. It began as a fork of `shcheck` and outgrew it; the fork's tool has been
deleted and only the analyzer survives.

GPL-3.0-or-later. Every source file carries the notice.

## Layout

```
findings.py    Finding, identity(), FINDING_SEVERITY, SEVERITIES, severity(), order_findings()
catalog.py     MESSAGES + describe(): every sentence the package can produce
message.py     the header mapping model: parse_headers, parse_raw_headers, lookups
csp.py         Content-Security-Policy                      (largest module)
hsts.py        Strict-Transport-Security + the ONLY third-party dependency
isolation.py   COOP / COEP / CORP / CORS
policies.py    Permissions-Policy + Feature-Policy
legacy.py      the obsolete headers
response.py    tables, registry, cross-header rules, analyze_all, inventory, orphans
reporting.py   report(): findings + inventories as plain data, ready for JSON
__init__.py    public API
```

Dependencies run one way and there are no cycles:

```
findings, message, catalog  ->  (nothing)
csp, hsts, isolation, legacy, policies  ->  findings [, message]
response   ->  all of the above except catalog
reporting  ->  response, findings, catalog
```

`catalog.py` is a leaf on purpose and **no analyser may import it**. The
analysers emit `(header, code, data)` and hold no prose; only `reporting.py` and
a consumer calling `describe()` turn that into a sentence. A test reads the
syntax of every `Finding()` call to keep it that way -- prose in a comment or a
docstring is ordinary English and fine, a sentence passed as `data` is not.

Two naming rules, both learned the hard way in one session: a module and an
exported callable must not share a name (`from .message import ...` sets
`http_security_test.message` to the submodule and silently clobbers a function
of that name -- which is why the renderer is `describe()` and not `message()`),
and `catalog.py` is not called `messages.py` because one character from
`message.py` is not a distinction.

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
   `(header, code, data)`. The ratings are SARIF levels (`error` / `warning` /
   `note`) so a consumer can adopt, remap, or ignore them, and the wording is
   split off the same way: a template belongs to the rule and the values belong
   to the result, which is SARIF's `messageStrings` + `arguments` in all but
   name. `data` is the contract; the sentence is a convenience.
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
7. **Code naming.** `<prefix>-deprecated` means "present, legacy, no defect",
   and there is no longer an exception: `xfo-deprecated` was renamed
   `xfo-allow-from` once the schema made codes an external contract, because it
   is rated `error` and a `-deprecated` suffix understated a value no browser
   honours. A code names the defect, not the age of the thing. The table and the
   code name are independent: membership of
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
- Findings are deduped by `identity()` — `(header, code, data)` — never by
  `code` alone and no longer by `(header, code)` either. The pair was right only
  while a finding carried prose: two `X-Frame-Options` values that are both
  invalid are two facts, and two cookies each missing `Secure` will be two more.
  A repeated header with *identical* values still reports once, because the data
  is identical too.
- Every emittable code has a message template **and** every template's code is
  emittable — the same bijection the severities have, checked the same way.
  Separately, every finding the corpus can produce is rendered, because a
  template naming `{sources}` beside data carrying `directives` is invisible
  until someone asks for the sentence.
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

## The output schema

`report(present, secure=True, host=None, message=True, raw=None,
request_raw=None)` is the whole analysis of one exchange as plain data —
strings, numbers, lists, dicts, no encoder needed:

```json
{
  "response": {
    "findings": [
      {"header": "Clear-Site-Data", "code": "csd-unquoted", "level": "error",
       "data": {"members": ["cookies"]}, "message": "present but cookies is not…"}
    ],
    "inventory": {
      "security": {}, "missing": [], "deprecated": {}, "information": {},
      "caching": {}
    },
    "raw": "<base64>"
  },
  "request": {"raw": "<base64>"}
}
```

Decisions inside that shape, each of which had an alternative:

- **A list of findings, not `{severity: [code]}`.** The old tool's schema grouped
  codes under a severity, which is lossless only while a code identifies one
  header and cannot repeat. Neither holds: `duplicate-headers` names several
  headers today, and per-cookie findings will repeat within one header.
- **Nested by message, not flat.** Not only for the parked `request.py`:
  `Cache-Control` is *both* a request and a response header, so a bare `header`
  field could not say which one a finding meant once requests are analysed.
  `request` grows `findings` and `inventory` when that lands and nothing else
  moves. **A finding about the exchange goes under `response`** — origin
  reflection is a defect in what the response did, with the forged `Origin` in
  `data`. Do not add a top-level `findings` for those; it would be empty in
  every ordinary report and force consumers to merge two lists forever.
- **No URL key.** A response does not know where it came from. A tool that
  fetched several wraps as many of these as it fetched — that is a fact about
  the run, not about any response.
- **`level` is denormalised.** It is derivable from `code`, and written out
  anyway, because the common reader wants to sort by severity without also
  carrying `FINDING_SEVERITY`.
- **`data` is always present, `{}` included**, so a consumer never tests for the
  key. `message` can be dropped entirely with `message=False`.
- **`inventory()` takes no `secure`.** Principle 2: nothing is withheld from an
  inventory. HSTS is missing on a plaintext response and the inventory says so.
- **Absent beats empty for passthrough.** No blob, no `raw` key; nothing known
  about the request, no `request` key. The rule that reconciles this with `data`
  always being `{}`: content this package *derived* is always present, content
  it was merely *given* is present only if it was given.

The `raw` blobs are optional and this package never fetches anything, so they
are whatever the caller hands over. Two things decided about them:

- **The library does the base64**, from bytes or text, text encoded latin-1 to
  match what `parse_raw_headers()` decodes with. One encoding decision in one
  place — the alternative was accepting a ready-encoded string, which leaves
  nothing enforcing whether it is base64 of UTF-8 or of latin-1, and that bug
  stays invisible until a non-ASCII `Server` banner turns up. Base64 at all
  because header values are latin-1: `Server: café-server` is not valid UTF-8
  and a JSON string cannot carry it losslessly.
- **A blob makes a report reproducible.** `raw` is exactly what
  `parse_raw_headers()` accepts, so an archived report can be re-analysed by a
  later version and the findings diffed. That is the real argument for carrying
  it, more than provenance.
- **They carry credentials.** A raw response head normally includes `Set-Cookie`
  with a live session token; a raw request includes `Cookie` and
  `Authorization`. Nothing here can police it, and reports get pasted into
  tickets and dashboards. Passing only the header block, redacting, or passing
  nothing is the caller's call — the docstring makes sure it is a call and not
  an accident.

The three `find_*` functions are gone; `inventory()` replaces them and adds the
`missing` list, which every consumer previously rebuilt by hand. Deriving those
inventories from findings does **not** work and the temptation is real: the 91
information headers and the 5 caching headers emit no findings at all by design,
and `missing` deliberately differs from the `-missing` findings wherever a
suppression applies.

## Working practices that paid off

- **Verify, don't assert.** Several confident claims this project ran on turned
  out false under test — including mine and the human's. Check stdlib behaviour
  with a constructed response; check a "this is unused" hunch by grepping call
  sites; check browser support against **MDN BCD first** (`caniuse` alone
  cannot answer most header questions — see the reference section), and check
  what sites really send against OWASP's 250 000-domain corpus instead of
  recalling a figure. One rationale here was already wrong on exactly this
  point and stood for weeks because nothing on disk could contradict it; now
  something can.
- **Mutation-test new guards.** Break the code, confirm the test fails, restore.
  A test that passes both ways is worse than none. This has paid for itself
  twice; most recently a guard returning `None` instead of `""` survived every
  mutation because the only caller tested truthiness, which is dead code
  pretending to be a decision.
- **The wording is pinned too.** `tests/rendered_messages.txt` holds every
  distinct sentence the package can produce, and a companion test asserts it
  covers every rated code so it cannot pass vacuously. `catalog.py` is prose
  nothing else reads, so an accidental edit there changes what a consumer sees
  while every other test stays green. Regenerate deliberately and read the diff:

  ```sh
  UPDATE_MESSAGE_SNAPSHOT=1 python -m pytest tests/ -k snapshot
  ```
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
- `noopener-allow-popups` is accepted as a valid COOP value. MDN BCD:
  Chrome 131, Safari 18.4, Firefox `false` (and `webview_android` `false`).
  The "~84 %" this used to cite came off caniuse.com, which renders BCD; the
  versions above are the on-disk fact and the ones to recheck.
- `HSTS_MIN_MAX_AGE = 15552000` (180 days), chosen over the 6-month figure
  because it is what sites actually send. Now measured rather than recalled:
  of the 55 349 `Strict-Transport-Security` values carrying a `max-age` in
  OWASP's 250 000-domain corpus (`subprojects/data/data.db`, see the reference
  section), **86.1 % are ≥ 180 days**, so this threshold contradicts 13.9 % of
  live deployments where a 1-year threshold would contradict 26.4 %. 1 105
  send `max-age=0`. Re-run the query there before moving the constant.
- `info` was renamed `note` throughout, including theme keys, to match SARIF.
- **From the OWASP cheat sheet, and settled — do not re-propose from it:**
  `X-Robots-Tag` is inventory at most, never a finding (not browser-enforced,
  and whether you want `noindex` depends on content nobody here sees); the
  secure-download `Content-Disposition` advice needs to know the resource is
  user-supplied, which headers cannot say; and the FLoC section
  (`interest-cohort=()`) is stale — Google cancelled FLoC in 2022.
- **`Content-Type` is analysed for exactly one thing**, the charset parameter on
  `text/html`, rated `note`. Real-world impact is negligible now (the injection
  needed UTF-7, and `<meta charset>` satisfies it invisibly), but tools still
  flag it, so the fact is reported without the noise a warning would make.
  Absence of the header is not reported at all: `analyze_all` sees no status
  line and a 204 or 304 carries no representation.
- **`X-DNS-Prefetch-Control` is inventoried, never a gap.** It is in
  `DEPRECATED_HEADERS` and emits one `note`, `xdpc-nonstandard`. No finding can
  do better: MDN BCD has it as Chrome 1 and Firefox 2 with no partial or pref
  caveat on either, Safari never, and `on` asks for the default everywhere it
  works — in Firefox both `network.dns.disablePrefetch` and
  `network.dns.disablePrefetchFromHTTPS` default to `false`. So `off` is a real
  measure in two engines, `on` is a no-op, and neither is a defect. BCD also
  records `standard_track: false, deprecated: false`, which is exactly what
  `xdpc-nonstandard` names and why it carries no `-deprecated` suffix. Note
  that OWASP's `headers_add.json` *recommends* sending it — the note qualifies
  that, it does not contradict it.
  **Rationale corrected 2026-08-16, conclusion unchanged.** This used to read
  "only Chrome acts on the header at all", from OWASP's hand-testing in their
  issue #201, plus "the local caniuse checkout has no feature entry for it".
  BCD contradicts the first and supersedes the second. Nothing in the code
  moved, because the verdict never depended on how many engines honour it —
  only on `on` being the default in all of them. If you find issue #201 again,
  this is the paragraph that already accounts for it.
- **`blocked-destinations=(style)` is treated as blocking nothing.** Chrome and
  Safari do not implement it and Firefox only behind
  `security.integrity_policy.stylesheet.enabled` (MDN BCD, matching OWASP's
  hand-testing). This is browser-support data with a shelf life: recheck it
  before trusting `IP_BLOCKING_DESTINATIONS`, and a style-only policy stops
  being inert the day an engine ships it. Rechecking is one file —
  the `blocked-destinations_style` node of
  `documentation/browser-compat-data/http/headers/Integrity-Policy.json`.
  Verified still true 2026-08-16: Chrome `false`, Safari `false`, Firefox 142
  pref-gated, against `blocked-destinations_script` at Chrome 138 /
  Firefox 145 / Safari 26.
- **Integrity-Policy's `endpoints` is unreliable in Firefox** — it enforces the
  blocking from 145 but ignores the directive and logs violations to the
  console instead. MDN BCD carries this as `partial_implementation: true` on
  Firefox with the note "Reporting `endpoints` are ignored (violations are
  logged to console)"; the "~81.6 % global support" figure came off
  caniuse.com, which renders BCD and is not the same as the caniuse checkout.
  Deliberately *not* a code: it would fire on every correct policy that asks
  for reports. `ip-endpoints-undefined` is the finding worth having.

## Parked, with intent to do

- **`Set-Cookie` analysis** — `Secure`, `HttpOnly`, `SameSite=None` without
  `Secure`, and the `__Host-` / `__Secure-` prefix rules. Both blockers are now
  gone: the mapping supports repeated headers, and `identity()` means a code can
  fire more than once against one header without the second being deduped away.
  Put the cookie's name in `data` so two cookies are two findings.
  Scope note from MDN BCD's `http/headers/Set-Cookie.json`, which breaks the
  header down by attribute and is the place to settle this before writing
  codes: there is now a **third** name prefix in the wild,
  `__Host-Http-` (BCD node `http_host-http_prefixes`, Chrome 140, Firefox 143,
  Safari `false`; Firefox 142 shipped it briefly as `__HostHttp-`). The two the
  item was written around are `host_secure_prefixes`, Chrome 49 / Firefox 50 /
  Safari 13 — universally supported, so a prefix violation is a real defect
  everywhere. `Partitioned` (CHIPS) is Chrome 114 / Firefox 141 / Safari 26.2
  and is *not* a security defect either way. Read the spec for `__Host-Http-`
  before rating it; BCD gives support, not semantics.
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
  **Neither of these two can be sized from OWASP's corpus**, and the check is
  not worth repeating: it collects 17 header names and `set-cookie` and
  `pragma` are not among them, so how often the pairings actually occur is
  unmeasurable from disk. What *is* there is 101 728 domains' worth of raw
  `cache-control` values — enough to write and sanity-check the "no
  `Cache-Control` prevents storage" condition against real directives rather
  than invented ones.
- **Active checks** — Origin reflection is the highest-value CORS test and needs a
  second request with a forged `Origin`. Tool work, not analysis.
- **Inverted "interesting headers"** — report anything not on a *boring* list,
  rather than only known-interesting names. The human wants to compile their own
  list, behind its own switch.
- **`request.py`** — request parsing/analysis, sharing `message.py`.
- **The schema is not finished.** The shape in "The output schema" is settled;
  what surrounds it is not. Open: a version field (needed *because* the `raw`
  blobs invite archiving reports — a stored report from today and one from a
  later shape are indistinguishable, and this is cheap now and awkward once
  reports exist); how several results travel together, which the old tool did by
  keying on URL and which should not come back that way; and whether run
  metadata — tool name and version — belongs in the document at all. Decide
  these together, before release, since all three change the top level.

## Reference material on disk

For reading and analysis only, do not copy. They live at
`/home/crapula/ref/<category>/<repo>`, the subdirectory naming the kind of
material: `documentation`, `security`, `burp`, `cookie_security`,
`web_browsers`, `web_servers`, `web_app_servers`, `operating_systems`. All
third-party, all read-only — no write operations, ever. All are git checkouts
except `web_browsers/lynx2.9.3`, which is an unpacked tarball, so `git log` /
`git show` are available for history on the rest.

**This section is a whitelist, not a sample.** What is named below was surveyed
once and verified rather than assumed, and is the whole of what this project
cares about; the closing subsection says what to do with everything else. Sizes
matter — `web_browsers/WebKit` is 6.4 GB, `operating_systems/nt5src` is 7.1 GB
and `burp/http-request-smuggler` is 154 MB — so scope every `grep` to a
subdirectory.

### Primary — reach for these first

**`documentation/www-project-secure-headers`** — the OWASP Secure Headers
Project, upstream of most of this package's header set and of several settled
rulings above.

- `mainsite/01_headers.md` and `mainsite/03_best_practices.md` — the header
  list and the recommended values. `03_best_practices.md` is the **source of
  truth**; the two JSONs below are generated from its tables by CI.
- `ci/headers_add.json` — 13 headers with OWASP's recommended values.
- `ci/headers_remove.json` — **87 information-leakage header names** OWASP says
  to strip (`X-Powered-By`, `X-AspNet-Version`, the Envoy/Datadog/B3 tracing
  set, …). This is the closest thing on disk to prior art for the parked
  *inverted "interesting headers"* switch.
- `mainsite/02_browser_support.md` — one caniuse URL per header. Note how many
  are `mdn-*` URLs; see the caniuse caveat below before trusting the checkout
  to answer them.
- `mainsite/04_technical_resources.md` — the other tools in this space.
- `mainsite/07_statistics.md` — the published prevalence charts, **PNG images
  only**, so useless to read programmatically. Use the database instead:
- `subprojects/data/data.db` — **the real-world corpus, and the most valuable
  single file in `/home/crapula/ref`.** 79 MB of SQLite, fetched by hand from
  the project's GitHub Release assets (CI generates it, local generation does
  not work). One table and it holds raw *values*, not just counts:

  ```sql
  CREATE TABLE stats (id integer PRIMARY KEY, domain text,
                      http_header_name text, http_header_value text);
  ```

  684 485 rows over **250 000 domains** — the Majestic top-1M prefix, with
  `input.csv` beside it as the domain list. Three things to know before
  quoting a number from it:
  - **Only the 17 headers OSHP tracks** appear (`cache-control`,
    `x-frame-options`, `x-content-type-options`, `referrer-policy`,
    `strict-transport-security`, `content-security-policy`, the three
    `cross-origin-*`, `permissions-policy`, `x-xss-protection`,
    `x-permitted-cross-domain-policies`, `content-security-policy-report-only`,
    `x-dns-prefetch-control`, `expect-ct`, `public-key-pins`,
    `clear-site-data`). It is **not** a corpus for the "interesting headers"
    work — no `Server`, no `X-Powered-By`, no `Set-Cookie`.
  - A domain with no security header at all still gets one row, with
    `http_header_name IS NULL`. That is 110 982 of the 250 000; the other
    139 018 have at least one. Filter `http_header_name IS NOT NULL` or every
    ratio comes out wrong.
  - The path is `subprojects/data/`, one level above the
    `subprojects/statistics/data/` that `scripts/*.py` reads as `../data`.
    Irrelevant for querying it directly; it means the repo's own scripts will
    not find it.

  This is the first thing on disk that can settle a threshold empirically.
  Worked example — the `HSTS_MIN_MAX_AGE` question, over the 55 349 HSTS
  values carrying a `max-age`: 86.1 % are ≥ 180 days, so the current threshold
  contradicts 13.9 % of live deployments, while a 1-year threshold would
  contradict 26.4 % (and 1 105 send `max-age=0`). Prefer this over recalling a
  figure from Shodan or a blog.
- `subprojects/validator/tests_suite.yml` — a Venom suite asserting OSHP
  conformance against a live site. Useful as an independent opinion to diff
  verdicts against.
- The repo carries its own `CLAUDE.md`, including strict GenAI rules. Those
  govern *contributing there*, not reading it from here.

**`documentation/browser-compat-data`** and **`documentation/caniuse`** —
browser support, in two halves that answer different questions. Use them
together; using one alone is how a wrong support claim gets made.

- **MDN BCD (`browser-compat-data`) says *whether*.** `http/headers/` holds one
  JSON per header, 160 of them, named exactly as the header is
  (`Integrity-Policy.json`, `Cross-Origin-Opener-Policy.json`,
  `Set-Cookie.json`, `X-DNS-Prefetch-Control.json`, …). Sub-keys carry
  *per-directive and per-value* support, which is the granularity this package
  reasons at and which caniuse does not have. A support entry can say
  `version_added: false`, `partial_implementation: true` with a `notes` string,
  or `flags: [{type: preference, name: …}]` for pref-gated — all three
  distinctions matter here. `"mirror"` means "same as the parent engine's
  browser", not "unknown".
- **caniuse says *how much*.** `data.json` / `features-json/` carry only
  caniuse's own 554 features and **no `mdn-*` entries** — anything caniuse.com
  shows as `mdn-http_headers_*` is BCD rendered on their site, not data in this
  checkout. What is here natively: `contentsecuritypolicy`,
  `contentsecuritypolicy2`, `stricttransportsecurity`, `x-frame-options`,
  `referrer-policy`, `permissions-policy`, `feature-policy`, `document-policy`,
  `upgradeinsecurerequests`, `cors`, `same-site-cookie-attribute`,
  `subresource-integrity`, with `usage_perc_y` / `usage_perc_a` per feature
  (`x-frame-options` is 0.28 % `y` + 96.41 % `a`, the whole deprecation story
  in two numbers).
- **To recompute a global support percentage for a header BCD covers but
  caniuse does not** — the "~81.6 %" sort of figure — join BCD's
  `version_added` against `caniuse/region-usage-json/alt-ww.json`, which is
  worldwide usage share per browser per version (its `total` is 96.44, not 100,
  so normalise or say "of tracked traffic").

Three rulings in "Deliberately decided" were re-verified against BCD and all
three hold exactly as written — `Integrity-Policy` is
`partial_implementation` in Firefox 145 with the note "Reporting `endpoints`
are ignored (violations are logged to console)";
`blocked-destinations_style` is `false` in Chrome and Safari and Firefox 142
behind `security.integrity_policy.stylesheet.enabled`; COOP
`noopener-allow-popups` is Chrome 131 / Safari 18.4 / Firefox `false`. Recheck
them there, not from memory.

**`documentation/rfc-library`** — the full RFC/STD/BCP/FYI archive as plain
text, laid out `rfc/NNNNN-NNNNN/rfcNNNN.txt`, with `indexes/rfc-index.txt` to
search by title. The ones this package reasons from: **9110** (HTTP
semantics), **9111** (caching — §5.4 on `Pragma`, §7.3 on `Set-Cookie` and
shared caches, both quoted in the parked items), **6797** (HSTS), **6265**
(cookies), **7034** (`X-Frame-Options`).

**`web_browsers/firefox`** and **`web_browsers/WebKit`** — ground truth for
*"does a browser actually honour this"*, which principle 5 and every
deprecation ruling turn on. Two engines only; there is no Chromium checkout,
so a Chromium claim still needs an external source.

- Firefox: `dom/security/nsCSPParser.cpp`, `dom/security/nsCSPUtils.cpp`,
  `security/manager/ssl/nsSiteSecurityService.cpp` (HSTS),
  `dom/security/featurepolicy/`, `dom/security/IntegrityPolicy.cpp`, and
  `modules/libpref/init/StaticPrefList.yaml` for what is behind a pref.
- WebKit: `Source/WebCore/page/csp/ContentSecurityPolicy*.cpp`,
  `Source/WebCore/loader/CrossOriginOpenerPolicy.cpp`,
  `Source/WebCore/loader/CrossOriginEmbedderPolicy.h`.
- Both browser-support claims in "Deliberately decided" were re-verified
  against these checkouts: `security.integrity_policy.stylesheet.enabled` is
  real (`StaticPrefList.yaml:19276`, beside `security.integrity_policy.enabled`
  at 19271), and `noopener-allow-popups` is parsed in WebKit
  (`CrossOriginOpenerPolicy.cpp:237`) and appears nowhere in Firefox. This is
  the cheap way to recheck them when the shelf life runs out.

**`security/csp-evaluator`** — the source of the ported CSP checks.
`checks/security_checks.ts`, `checks/strictcsp_checks.ts` and
`checks/parser_checks.ts` are the checks themselves;
`allowlist_bypasses/{jsonp,angular,flash}.ts` is the curated data deliberately
*not* embedded here.

**`security/hstspreload`** — the source of the declared `[preload]` extra, so
the behaviour of the only third-party dependency is readable. One public
function, `in_hsts_preload(host)`; the list is a packed `hstspreload.bin`
rebuilt monthly from Chromium's `transport_security_state_static.json`.

**`security/humble`** — rfc-st/humble, the closest peer to this package on disk
and the one to diff verdicts against. `humble.py` is 5 648 lines, but the part
worth reading is the data beside it, because it is a catalogue in the same
sense `catalog.py` is:

- `additional/insecure.txt` — **158 defect names over 93 distinct headers**,
  each written `Header: Defect` (`Access-Control-Allow-Origin: Unsafe Values`,
  `Cache-Control: No Valid Directives`). This package has 86 codes over far
  fewer headers, so that file is a ready-made gap list. Read it for candidates,
  not as a specification, and rate anything taken from it by principle 3.
- `additional/missing.txt` — the 14 headers humble reports as absent, against
  this package's `missing` inventory.
- `additional/security.txt` — the 62 names it treats as security-relevant at
  all: its answer to the scoping question the `Layout` section answers here.
- `additional/fingerprint.txt` — **1 287 vendor/product banner headers**, each
  annotated with what it identifies (`$WSEP (IBM WebSphere Application
  Server)`, `Akamai-Cache-Status (Akamai Edge)`). Fifteen times the size of
  OWASP's 87-name `headers_remove.json`, and the best prior art on disk for the
  parked *inverted "interesting headers"* switch.
- `l10n/details.txt` (and its `_es` twin) — its prose catalogue, the analogue of
  `catalog.py`, for how another tool words the same findings.

MIT-licensed, which changes nothing here: the read-only rule above is about
scope, not licence.

**`security/shcheck`** and **`security/shcheck-fork`** — this package's own
provenance, now checkable instead of recalled. `security/shcheck` is santoru's
upstream at v1.7; `security/shcheck-fork` is `MarioVilas/shcheck`, the fork this
package grew out of and whose tool was deleted. `git log` in either settles what
the original did or what the fork changed — including the `default-src 'self'`
substring bug that principle 4 is named after.

**`documentation/known-http-header-db`** — 271 headers in one JSON
(`src/db.json` pretty-printed, `dist/db.json` the same content minified),
aggregated from MDN, the IANA http-fields registry and Wikipedia. Per header:
`type` (request/response), description, `syntax`, `directives[]` with a
description each, `specifications[]` with RFC links, and `status` (`permanent`,
…). The fastest way to answer *"is this a real header, what does it take, which
RFC"* for a name nobody here has met. **Do not quote its
`browserCompatibility`** — it is a
scraped MDN *rendering*, carrying `"Yes"` and `"?"` where versions belong;
`documentation/browser-compat-data` is the machine-readable original and the
only one of the two that records flags, partial implementations and
`version_added: false`.

### Secondary — for specific parked work

- **`Set-Cookie` analysis.** Jetty's
  `jetty-core/jetty-http/src/main/java/org/eclipse/jetty/http/HttpCookieStore.java`
  implements the `__Host-` / `__Secure-` prefix rules, with
  `HttpCookieStoreTest.java` beside it; Tomcat's
  `java/org/apache/tomcat/util/http/Rfc6265CookieProcessor.java` plus
  `SameSiteCookies.java` and `test/…/TestCookieProcessorGeneration.java` are
  the serialization ground truth; `werkzeug/tests/test_http.py` has prefix
  tests in Python. Read these three when the cookie parser lands, not before.
- **`Set-Cookie` analysis, the analyser side.** `security/securityheaders`
  (koenbuyens) is the only Python `Set-Cookie` *checker* on disk and is
  decomposed the way this package is — `checkers/<header>/` beside
  `models/<header>/`, with `checkers/setcookie/` holding `notsecure.py`,
  `nothttponly.py` and `requiressecurity.py`, and `models/setcookie/` parsing
  `SameSite` as a directive. Read it for the decomposition, and read
  `requiressecurity.py` as a **warning**: it lowercases the cookie name and
  then tests `startswith('__Secure')` / `startswith('__Host')`, so both prefix
  branches are unreachable, and it falls back to guessing from `'session' in
  name` / `'csrf' in name` — the guess the parked cache/cookie item refuses to
  make. Two failure modes to avoid in one 15-line file; the prefixes are
  case-**sensitive**, which is what makes the lowercasing wrong rather than
  merely redundant. `burp/burp-samesite-reporter` is 326 lines of Java that
  classifies each cookie as `SameSite` missing / `None` / other and carries its
  reasoning in the issue prose.
- **`documentation/Open-Cookie-Database`** — 2 264 cookies as CSV and JSON,
  keyed by name, each with platform, category (Functional / Personalization /
  Analytics / Marketing / Security), retention period and a `Wildcard match`
  flag (`_gac_1234` matches wildcard `_ga`). This is the nearest thing on disk
  to the oracle the parked cache/cookie quirk says does not exist — with two
  caveats that probably sink it: the categories are *privacy* purposes, not
  "is this a session token", and it is curated data that ages, which is the
  objection that kept csp-evaluator's bypass lists out. `burp/CookieMonster`
  vendors it and implements the wildcard rule, if the semantics are ever
  needed.
- **Prior art on defaults.** Tomcat's
  `java/org/apache/catalina/filters/HttpHeaderSecurityFilter.java` (HSTS
  max-age, XFO, XCTO defaults) and `CorsFilter.java`; Jetty's
  `CrossOriginFilter.java` in each `jetty-ee*/…/servlets/`.
- **Boring-list prior art**, for the inverted "interesting headers" switch:
  wpscan's `app/models/headers.rb` has a hand-curated 27-entry `known_headers`
  list feeding `app/finders/interesting_findings/headers.rb` — a working
  implementation of exactly that design. `burp/HeadersAnalyzer` carries a
  91-entry `BoringHeaders.txt`, the same design again and the largest hand-
  curated *boring* list here; humble's 1 287-entry `fingerprint.txt` above is
  the largest *interesting* one. `lighttpd1.4/src/http_header.h` is a third,
  written from the server's side.
- **`security/testssl.sh`** — `run_security_headers()` (~line 3580) is the
  baseline to beat, not a source of checks: it enumerates headers and rates
  *presence* only, and the comment near line 3641 says so outright ("I am not
  testing for the correctness or anything stupid yet, e.g. `X-Frame-Options:
  allowall`"). That sentence is this package's reason to exist.
  `burp/Headers` and `burp/HeaderGuardian-Burpsuite-Pro-Extension` are the same
  baseline in miniature and in Python: hand-curated presence lists with an
  on/off flag per entry (`security_headers.txt` 10 entries, `cookie_flags.txt`
  7, `dangerous_headers.txt` 2, `potentially_dangerous_headers.txt` 3), plus a
  user-editable `thresholds.txt` giving the count at which each list flags a
  host. Both are small enough to read in a sitting and neither judges a value.
- **`security/badssl.com`** — `domains/upgrade/{hsts,preloaded-hsts,upgrade}.conf`
  define live, publicly reachable hosts with known-good HSTS, preload and
  `upgrade-insecure-requests` values. The only end-to-end fixture source on
  disk, for whenever a fetcher exists.
- **HPACK / QPACK static tables** — `nginx/src/http/v2/ngx_http_v2_table.c` and
  `src/http/v3/ngx_http_v3_table.c`, `lighttpd1.4/src/ls-hpack/lshpack.c`,
  `libmicrohttpd2/src/mhd2/h2/hpack/`. They enumerate canonical **lowercase**
  header names, which is the wire-level justification for `message.py`
  lowercasing rather than a convenience.
- **`security/Security-Headers-Validator`** — one module per header under
  `headers/`, and the only tool on disk carrying `pragma.py` *and*
  `cache_control.py`, so it is the one independent opinion available on both
  parked cache items before writing `pragma-ineffective`.
- **CSP allowlist-bypass corpora, still not embedded.** `burp/csp-auditor` has
  `csp-auditor-core/src/main/resources/resources/data/csp_host_user_content.txt`
  and `csp_host_vulnerable_js.txt` — a second curated list beside
  csp-evaluator's and split along the same two axes, loaded by
  `model/WeakCdnHost.java`. `burp/CSP-Bypass` has a readable standalone
  `csp_parser.py` but a `csp_known_bypasses.py` holding exactly one domain, so
  it is no substitute for either. The **Not embedded** ruling covers all of
  them; nothing here changes the upkeep argument.
- **`burp/Additional_CORS_Checks`** — Kotlin, and the prior art for the parked
  active origin-reflection check: it re-issues a request with a forged `Origin`
  and reports arbitrary-origin and `null`-origin reflection (`doc/*.png` shows
  what it claims). Tool-side work, exactly as that item says.

### Everything else — assume it is not interesting

`/home/crapula/ref` holds far more than the whitelist above: ~19 GB of
operating-system source, a dozen application servers, seven cookie tools and
two dozen Burp extensions of which only the eight named above touch a header
value or a cookie flag. **Nothing outside this section is relevant unless the
human says so.** Do not survey it, do not grep it speculatively, and do not
re-derive that it is uninteresting — that was done once, and the cost of doing
it again is the reason this paragraph exists.

Only the negatives that would otherwise look promising are kept:

- **There is no Chromium checkout.** Firefox and WebKit are the only engines
  readable here, so a Chromium claim still needs BCD or an external source.
- **`operating_systems/*`** — nothing about HTTP security headers.
  `busybox/networking/httpd.c` and `Windows-Server-2003/inetsrv/iis` (IIS 6)
  predate every header analysed here; at most they explain where a few
  `Server:` and `X-Powered-By` banners originate.
- **The remaining servers** — `httpd`, `caddy`, `heliod`, `Zope`, `daphne`,
  `gunicorn`, `hypercorn`, `twisted`, `uvicorn`, `uwsgi`, `glassfish*` — pass
  configured headers through and originate no analysis logic. One exception:
  `hiawatha/src/send.c` emits HSTS itself rather than by configuration.
- **The remaining `burp/` and `cookie_security/` repos** — JWT tooling, WAF
  fingerprinting and cookie *decryption*, HAR/Nessus/sitemap import, request
  smuggling, nuclei and semgrep bridges, and GDPR consent scanners. Burp
  plumbing and privacy-compliance tools; none analyses a header value or a
  cookie flag.

## Status

86 codes (34 error / 27 warning / 25 note), each with a rating and a message
template, and every rendered sentence pinned by a snapshot. 269 tests, 111 test
functions, all passing; `ruff check` clean. `pyproject.toml` is a placeholder — hatchling, no
README yet, `hstspreload` declared as the optional `[preload]` extra.
