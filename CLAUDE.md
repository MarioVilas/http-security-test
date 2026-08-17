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

`Reporting-Endpoints` and `Report-To` live there for the opposite reason: they
*are* a family, and every other member of it is a header analysed elsewhere.
Five headers name a reporting group — CSP, COOP, COEP, Integrity-Policy and
Document-Isolation-Policy when it lands — while only these two define one, so
every question about reporting is a cross-header question by construction.

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
- **`security` and `missing` are two halves of one question, with one
  exception.** `REPORTING_HEADERS` (`Report-To`, `Reporting-Endpoints`) is
  inventoried under `security` when present and is **never** reported absent,
  because a response that configures no reporting is the ordinary state of the
  web rather than a gap. This is why they are not in `SECURITY_HEADERS`: that
  tuple is read three times — for `security`, for `missing`, and by
  `_report_missing()` — and only the first is wanted here. Adding a header
  there to get it inventoried mints an `<initials>-missing` code that fires on
  nearly every site; the bijection tests catch it, but the design should not
  need saving by them.
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
- **Never maintain `/home/crapula/ref`.** The human has their own tooling for
  that whole tree — no syncing, fetching, updating, pruning or cleanup, and no
  state-changing git command in any checkout under it. Read it; that is all. The
  reference section repeats this where the sync sources are recorded.
- **They run `ruff format`.** Keep `ruff check` clean; do not reformat.
- **Ask, with options and a recommendation,** on policy and design calls
  (severity, schema, scope). They engage closely and will push back with evidence
  when a premise is wrong — that has repeatedly been the right call.

## Deliberately decided (do not re-litigate without new information)

- **The whole reporting family is rated `note`**, `ip-endpoints-undefined`
  included, which was re-rated down from `warning` on 2026-08-17. A reporting
  failure costs the operator information and nothing else: no browser
  protection is withheld by it, and there is no path through it for an attacker
  to reach the site or its users. What makes it worth reporting at all is that
  the operator plainly intended the reports to arrive — which is a `note`'s job
  exactly, a fact with no defect in protection. Apply this to any reporting
  code added later rather than rating it on how broken the configuration looks.
- **A defect in an endpoint's *definition* belongs to the header that defined
  it.** One endpoint URL nothing can be delivered to is one fact however many
  policies name that group, so it is a finding on `Reporting-Endpoints` or
  `Report-To` and the referencing policies stay quiet. Consequently
  `_reporting_endpoint_names()` is **syntactic**: a policy naming a group that
  something did define has done nothing wrong, and only a group nobody names at
  all earns `<prefix>-report-to-undefined`. The reverse split — folding
  deliverability into the group lookup — was implemented first and produces the
  same defect up to four times with one fix between them.
- **`Report-To` is deprecated but still honoured, and reading only
  `Reporting-Endpoints` is a false positive.** BCD says `deprecated: true,
  standard_track: false` (Chrome 70 / Firefox 149 / Safari never), and both
  engines nonetheless parse it and act on it: Chromium wires it up at
  `net/reporting/reporting_service.cc:250`, Firefox at
  `dom/reporting/ReportingHeader.cpp:211`. A response defining its groups only
  this way is configured correctly — the norm, in fact, in cloaked.pl's 2021
  survey, where `Report-To` appears 50 times and `Reporting-Endpoints` not
  once. **The general lesson, which is the reason this entry is here:** BCD's
  `deprecated` flag means "do not reach for this", never "browsers ignore it".
  That is a different trap from the `features.cc` one below, and it bites in
  the opposite direction — there a value is parsed but not honoured, here a
  header is disowned but still honoured.
- **Endpoint *existence* is out of scope; endpoint *syntax* is not.** Whether
  anything answers at a reporting URL needs a request, so it waits for the
  active checks. Whether the header parses at all, whether a browser reads it
  on this response, and whether each URL is one reports can be delivered to are
  all answerable from the response alone, and all three are checked. Note the
  parse question is real rather than pedantic: structured field dictionary keys
  are lower-case by grammar (RFC 9651 `key = ( lcalpha / "*" ) *( lcalpha /
  DIGIT / "_" / "-" / "." / "*" )`), and **both engines drop the entire header**
  when the dictionary will not parse — Firefox `SFV::ParseDict(...); if
  (!dict.IsValid()) return 0;`, Chromium `ParseDictionary` returning `nullopt`
  — so one capital letter costs every group the header meant to define.
- **The engines disagree about loopback reporting endpoints, and the spec sides
  with Firefox.** Reporting API step 5.3 (`w3c/webref`
  `ed/algorithms/reporting-1.json`) says "If endpoint url's origin is not
  **potentially trustworthy**, then continue"; Firefox implements exactly that,
  Chromium requires `SchemeIsCryptographic()` and so rejects
  `http://localhost`. `_delivers()` therefore fires only on what *both* reject.
  If Chromium relaxes toward the spec the predicate can widen; the reverse is
  not on the cards.
- **Not analyzed:** `Document-Policy` (no closed value set, no delegation axis, no
  concrete configuration points of its own); `X-Content-Security-Policy` /
  `X-WebKit-CSP` contents (no browser reads them, so content decides nothing).
- **Not analyzed: CSP Embedded Enforcement**, i.e. `Allow-CSP-From` (response)
  and `Sec-Required-CSP` (request). Decided 2026-08-17 with the spec source in
  front of us at `w3c/webappsec-cspee` and the implementation confirmed —
  Chromium's `ParseAllowCSPFromHeader()`
  (`services/network/public/cpp/content_security_policy/`
  `content_security_policy.cc:1404`) takes `*` or a single origin and rejects
  anything else, and `content/browser/renderer_host/cspee_histogram_browsertest`
  `.cc` exists, so this is live in Chrome. It is nonetheless out of scope, for
  reasons that are about the *value set*, not obscurity:
  - **`Allow-CSP-From: *` is not a defect.** CSPEE only lets an embedder
    *tighten* — the embedded document must return a policy that subsumes the
    required one or the frame is blocked — so a wildcard grants an embedder no
    power to weaken anything. Rating it would be principle 4 all over again.
  - That leaves exactly one judgeable case, a value that is neither `*` nor a
    valid origin. One narrow `error` code, on a header **absent from both MDN
    BCD and OWASP's 17 tracked names**, so its prevalence cannot be measured
    from the corpus at all. Not worth a code today.
  - Reopen it if BCD gains an entry, or if a second engine ships it — the spec
    checkout is on disk, so the recheck is cheap. Do not re-survey the repo.
- **Not embedded:** csp-evaluator's 171-entry JSONP/Angular bypass lists — high
  catch rate, but curated data that ages, and the module has no upkeep burden
  today. The data-free checks from it *were* ported.
- `noopener-allow-popups` is accepted as a valid COOP value. MDN BCD:
  Chrome 131, Safari 18.4, Firefox `false` (and `webview_android` `false`).
  The "~84 %" this used to cite came off caniuse.com, which renders BCD; the
  versions above are the on-disk fact and the ones to recheck.
  **Confirmed in Chromium source 2026-08-17**, which matters because the parser
  gates the value on a feature flag —
  `cross_origin_opener_policy_parser.cc:66` accepts it only when
  `features::kCoopNoopenerAllowPopups` is enabled, and that flag is
  `FEATURE_ENABLED_BY_DEFAULT` at `features.cc:89`. So BCD's "Chrome 131" is
  right and the guard is a launched-feature remnant. Worth knowing as a pattern:
  in Chromium a value being *parsed* is not the same as it being *honoured*, and
  `features.cc` is where the difference lives.
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
  Firefox 145 / Safari 26. **Chromium source agrees, and more strongly than BCD
  can** (2026-08-17): `integrity_policy_parser.cc:36` accepts
  `blocked-destinations=script` and `sources=inline` and pushes every other
  token onto `parsing_errors` as "not supported". That is a closed value set in
  code, not an absence of support inferred from a table, so
  `IP_BLOCKING_DESTINATIONS` is on firm ground until that `if` grows a branch.
- **Integrity-Policy's `endpoints` is unreliable in Firefox** — it enforces the
  blocking from 145 but ignores the directive and logs violations to the
  console instead. MDN BCD carries this as `partial_implementation: true` on
  Firefox with the note "Reporting `endpoints` are ignored (violations are
  logged to console)"; the "~81.6 % global support" figure came off
  caniuse.com, which renders BCD and is not the same as the caniuse checkout.
  Deliberately *not* a code: it would fire on every correct policy that asks
  for reports. `ip-endpoints-undefined` is the finding worth having.

## Parked, with intent to do

- **Reporting groups named by a *report-only* policy** — `csp-ro-`, `coop-ro-`,
  `coep-ro-` and `ip-ro-` equivalents of the `-report-to-undefined` codes.
  Deliberately not shipped, and the reason is not principle 6: an author
  running a policy in report-only mode *knows* it is not enforcing and is
  precisely the person who wants to hear that its plumbing is broken. It is
  that in most responses this is noise, and the one audience it serves is
  someone deliberately trialling a policy — which is a switch on a tool, not a
  default of the analysis engine. Revisit with the CLI, not before.
- **`Set-Cookie` analysis** — `Secure`, `HttpOnly`, `SameSite=None` without
  `Secure`, and the `__Host-` / `__Secure-` prefix rules. Both blockers are now
  gone: the mapping supports repeated headers, and `identity()` means a code can
  fire more than once against one header without the second being deduped away.
  Put the cookie's name in `data` so two cookies are two findings.

  **The prefix rules are settled — from the specs *and* from source, which
  agree — and there are four of them, not the two this item was written
  around.** Chromium's `net/cookies/cookie_util.cc`, Firefox's
  `netwerk/cookie/CookiePrefixes.cpp` and the draft text all match exactly;
  read the Firefox file first, it is 102 lines. All four build on `__Secure-`,
  and `__Host-Http-` is the conjunction of the two below it — it is a lattice,
  not a chain, so `__Host-` does *not* imply `HttpOnly`:

  | prefix | requires |
  |---|---|
  | `__Secure-` | `Secure`, on a secure origin |
  | `__Http-` | `Secure` + `HttpOnly` |
  | `__Host-` | `Secure` + `Path=/` + **no** `Domain` |
  | `__Host-Http-` | `Secure` + `HttpOnly` + `Path=/` + no `Domain` |

  Three things that will bite an implementation, all verified rather than
  assumed:
  - **Match longest-prefix-first.** Both engines order their prefix tables so
    `__Host-Http-` is tested before `__Host-`, and both carry a comment saying
    why. A naive `name.startswith('__Host-')` classifies `__Host-Http-sid` as
    `__Host-` and then fails to require `HttpOnly` — a false negative that
    looks like a pass.
  - **Matching is case-INSENSITIVE**, which contradicts the obvious reading of
    the spec. Chromium's `GetCookiePrefix()` uses
    `base::CompareCase::INSENSITIVE_ASCII`; Firefox uses
    `nsCaseInsensitiveCStringComparator` and explains the discrepancy in a
    comment: RFC 6265bis §5.4 requires UAs to match case-insensitively even
    though §4.1.3 describes the prefixes with "case-sensitive match" wording,
    because that wording is about server-side semantics, not UA enforcement.
    So `__SECURE-sid` must be held to the `__Secure-` rules. Firefox's comment
    gives the reason: otherwise a server that compares names case-insensitively
    would accept a miscapitalised prefix without the guarantees it implies.
  - **A prefix hiding in the *value* of a nameless cookie is its own defect.**
    Chromium's `HasHiddenPrefixName()` fires only when the name is empty
    (`canonical_cookie.cc:397` and `:701`) and the cookie is then excluded
    outright with `EXCLUDE_INVALID_PREFIX`. The case it stops is
    `Set-Cookie: =__Host-sid=x`, which something downstream re-parses as a
    `__Host-sid` cookie that never met the rules. Note this one matches the
    prefix case-insensitively too, and after trimming leading SP/HTAB.

  BCD is still the source for *which engine and which version*, in
  `http/headers/Set-Cookie.json`: `host_secure_prefixes` is Chrome 49 /
  Firefox 50 / Safari 13, so violating those two is a real defect everywhere;
  `http_host-http_prefixes` is Chrome 140 / Firefox 143 / Safari `false`
  (Firefox 142 shipped it briefly as `__HostHttp-`). **Look `__Http-` up there
  before rating it** — it is in both engines' source but its BCD versions have
  not been checked here, and a prefix Safari ignores cannot be rated the same
  way as one it enforces. `Partitioned` (CHIPS) is Chrome 114 / Firefox 141 /
  Safari 26.2 and is *not* a security defect either way.

  **Where the specs are, and it is two drafts, not one.** No published RFC
  carries these rules — `rfc6265.txt` does not contain `__Secure-` anywhere and
  the RFC index lists no HTTP cookie RFC after 6265, so `documentation/`
  `rfc-library` cannot answer this and is not at fault for it. Verified against
  the draft text 2026-08-17:
  - `__Secure-` and `__Host-` are `draft-ietf-httpbis-rfc6265bis` §4.1.3.1 and
    §4.1.3.2. Current revision is **-22** (2025-12-01); the URL in Chromium's
    `net/cookies/cookie_constants.h:391` cites **-13**, so treat any section
    number copied out of browser source as needing a re-check.
  - `__Http-` and `__Host-Http-` are **not in 6265bis at all** — zero
    occurrences in -22, whose §4.1.3 has only the two subsections. They are
    `draft-ietf-httpbis-layered-cookies` §4.1.3.3 and §4.1.3.4, currently
    **-02** (2026-05-22). Firefox's comments attribute all four to
    "RFC 6265bis §4.1.3", which is loose; do not copy that attribution.
  - The case-insensitivity requirement is normative and lives in 6265bis
    **§5.4**: "UAs MUST match the prefix string case-insensitively", explicitly
    differing from the servers' §4.1.3 framing. Both engines apply it to all
    four prefixes.
  - **Cookie names themselves stay case-sensitive** (§5.4's own example):
    `__Secure-foo` and `__secure-foo` are two distinct cookies that both have to
    satisfy the `__Secure-` rules. That matters for keying — the cookie name in
    `data` is a case-sensitive identifier even though the prefix test is not.

  Neither draft is in `rfc-library`'s tracked tree; if they are on disk they are
  under its `mirror/`, which the human maintains — do not fetch them. And WebKit
  is no help here — its only prefix code is the curl backend.

  **Both drafts are readable on disk after all, in `w3c/webref`** (found
  2026-08-17; this paragraph used to end "work from the browser sources and say
  the draft was not available"). Reffy crawls them, so
  `ed/algorithms/rfc6265bis.json` and `ed/algorithms/layered-cookies.json` carry
  the numbered steps verbatim, with `ed/headings/` and `ed/ids/` beside them.
  What that settled, and what it did not:
  - The section numbers above are **confirmed independently**: 6265bis §4.1.3
    has exactly the two subsections, layered-cookies has §4.1.3.3 `__Http-` and
    §4.1.3.4 `__Host-Http-`, and 6265bis §5.4 is titled "Cookie Name Prefixes".
  - layered-cookies' *Store a Cookie* has all four prefixes at steps 13–16 and
    the hidden-prefix-in-value rule at step 17, every one of them matching on
    the name "byte-lowercased", with an inline note giving the same reason
    Firefox's comment does — "to protect servers that process these values in a
    case-insensitive manner".
  - **The spec's structure is four independent guard clauses, not the browsers'
    longest-prefix-first table.** `__Host-Http-sid` trips step 14 (starts with
    `__host-`) *and* step 16, so the conjunction falls out of both firing. The
    longest-prefix-first warning above is about implementations that match once
    against a prefix table, and it still stands — it is just not what the draft
    says.
  - **Not everything is extractable.** These are plain RFC HTML with no Bikeshed
    markup, so there are no `dfns/` files for either: "Host-prefix compatible"
    and "Http-prefix compatible" are defined in §4.1.3 prose that webref does
    not carry, and only their anchors show up in `ids/`. Read them from
    `netwerk/cookie/CookiePrefixes.cpp`, which is the plan anyway.
  - **Revision drift.** Reffy crawls the editor's copy at `httpwg.org/`
    `http-extensions/`, not a numbered revision, so the extract can be ahead of
    the -22 / -02 cited above. It is the current text, not a pinned one.
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
material: `documentation`, `security`, `burp`, `cookie_security`, `w3c`,
`web_browsers`, `web_servers`, `web_app_servers`, `operating_systems`. All
git checkouts except `web_browsers/lynx2.9.3`, which is an unpacked tarball, so
`git log` / `git show` are available for history on the rest.

**Read, and nothing else. The human maintains this tree with their own tooling
and an agent does no maintenance on it — ever.** That means no writes, and also
no `rsync`, no fetching or updating a checkout, no pruning, no cleanup of files
that look stray, and no git command that changes state anywhere under
`/home/crapula/ref`. Sizes, staleness and what is or is not mirrored are not
problems to fix here; if something needed is missing, say so and stop. Where a
sync source is documented below it is recorded so the *fact* is checkable, not
as a task to run.

**This section is a whitelist, not a sample.** What is named below was surveyed
once and verified rather than assumed, and is the whole of what this project
cares about; the closing subsection says what to do with everything else. Sizes
matter, and they grow with every fetch, so re-measure rather than trust these:
`web_browsers/chromium` is **70 GB** (64 GB of it `.git`, so `git log` is cheap
and a tree-wide `grep` is not), `web_browsers/WebKit` is 19 GB,
`web_browsers/firefox` is 11 GB, `operating_systems/nt5src` is 9.1 GB,
`w3c/webref` is 1.4 GB (1.1 GB of it `.git`; the data is `ed/`, 186 MB)
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

**`documentation/rfc-library`** — the RFC/BCP/STD/FYI/IEN archive as plain text,
laid out `rfc/NNNNN-NNNNN/rfcNNNN.txt`, with `indexes/rfc-index.txt` to search
by title. Complete for what it covers: 9 810 RFC texts, every published RFC that
has one, verified against the index. The ones this package reasons from:
**9110** (HTTP semantics), **9111** (caching — §5.4 on `Pragma`, §7.3 on
`Set-Cookie` and shared caches, both quoted in the parked items), **6797**
(HSTS), **6265** (cookies), **7034** (`X-Frame-Options`).

**It mirrors the published series only — no Internet-Drafts, by design.** A
scope decision of the mirror, not a defective checkout: `scripts/update.sh`
rsyncs `rfcs-text-only` and `rfcs-pdf-all` from `rsync://ftp.rfc-editor.org`,
and that server offers **eight modules, none of which carries drafts** (asked
directly, 2026-08-17; its `prerelease/` is approved-but-unpublished RFCs, a
different thing). The consequence that matters here: the `Set-Cookie` prefix
rules are in no RFC at all, so **6265 is not the authority for the prefixes** —
do not cite it for one.

Internet-Drafts, when they are here, are under **`mirror/`** — human-maintained,
gitignored in that repo alongside `pdf/` and `dist/`, and **not an agent's to
create, sync or tidy** (see the rule at the top of this section; untracked files
there are expected, not a mess). Read whatever is in it, and if the draft you
need is absent, say so rather than fetching it. Provenance, recorded once so the
claim is checkable: drafts come from the IETF, `rsync://rsync.ietf.org`, module
`internet-drafts` (currently active, 9 356 files / 795 MB, or 3 366 files /
199 MB text-only) or `id-archive` (active *and* expired, every revision). Not
from the RFC Editor, and no scrape of `datatracker.ietf.org` is involved — it
renders the same documents.

Two standing facts about draft coverage, which are about *analysis*, not upkeep:

- **Only the cookie prefixes need a draft at all.** `draft-ietf-httpbis-`
  `rfc6265bis` and `draft-ietf-httpbis-layered-cookies` — every other header
  here resolves to a published RFC already on disk.
- **No IETF mirror closes the real spec gap.** Counting `specifications[]` links
  in `known-http-header-db` across the ~20 headers this package analyses, the
  IETF links are all *published RFC* pages, while **9 point at WHATWG**
  (`html.spec.whatwg.org`, `fetch.spec.whatwg.org`) and **8 at W3C**
  (`w3c.github.io`, `w3.org`) — CSP, Permissions-Policy, COOP/COEP,
  Clear-Site-Data, `nosniff`. Those are living standards in neither IETF module,
  so for them the browser sources remain the on-disk authority.

**`web_browsers/chromium`**, **`web_browsers/firefox`** and
**`web_browsers/WebKit`** — ground truth for *"does a browser actually honour
this"*, which principle 5 and every deprecation ruling turn on. **All three
engines are now readable**, so a support claim no longer has to rest on BCD
alone; BCD says *whether it shipped*, the source says *what it actually does
with the value*, and the second question is the one this package reasons about.

- Chromium: nearly everything is under `services/network/public/cpp/` —
  `content_security_policy/` (`csp_source_list.cc` is the one to read),
  `cross_origin_opener_policy_parser.cc`,
  `cross_origin_embedder_policy_parser.cc`, `cross_origin_resource_policy.cc`,
  `integrity_policy_parser.cc`, `x_frame_options_parser.cc`, and
  `parsed_headers.cc` as the index of what the network service parses at all.
  Cookies are `net/cookies/cookie_util.cc` (the prefix rules) and
  `canonical_cookie.cc`; HSTS is `net/http/transport_security_state.cc`.
  Feature flags gate a lot of this — `services/network/public/cpp/features.cc`
  says whether a parsed value is actually live, and
  `base::FEATURE_ENABLED_BY_DEFAULT` there is what turns "parsed" into
  "honoured".
- Two Chromium files are data, not code, and both are assets in their own
  right: `services/network/public/cpp/permissions_policy/`
  `permissions_policy_features.json5` is the authoritative registry of the
  **210** Permissions-Policy features Chromium knows, each with its wire name
  (`permissions_policy_name: "ch-ua"`) and its `feature_default` — the closed
  value set `policies.py` otherwise has to hand-maintain. And
  `net/http/transport_security_state_static.json` is 10.5 MB of **the HSTS
  preload list itself**, which is what `security/hstspreload`'s packed
  `hstspreload.bin` is generated from, so a preload claim can now be checked
  against the source rather than the binary.
- Firefox: `dom/security/nsCSPParser.cpp`, `dom/security/nsCSPUtils.cpp`,
  `security/manager/ssl/nsSiteSecurityService.cpp` (HSTS),
  `dom/security/featurepolicy/`, `dom/security/IntegrityPolicy.cpp`,
  `netwerk/cookie/CookiePrefixes.cpp` (102 lines, and the best-commented
  account of the prefix rules on disk — it cites the RFC section per prefix),
  and `modules/libpref/init/StaticPrefList.yaml` for what is behind a pref.
- WebKit: `Source/WebCore/page/csp/ContentSecurityPolicy*.cpp`,
  `Source/WebCore/loader/CrossOriginOpenerPolicy.cpp`,
  `Source/WebCore/loader/CrossOriginEmbedderPolicy.h`. **WebKit cannot answer
  cookie questions.** The only prefix logic in the tree is
  `Source/WebCore/platform/network/curl/CookieJarDB.cpp:492`, the curl backend
  used by the non-Apple ports; Safari goes through CFNetwork, which is not open
  source and not in this checkout. Take Safari cookie behaviour from BCD.
- Three browser-support claims in "Deliberately decided" were re-verified
  against these checkouts and all hold:
  `security.integrity_policy.stylesheet.enabled` is real
  (`StaticPrefList.yaml:19276`, beside `security.integrity_policy.enabled` at
  19271); `noopener-allow-popups` is
  parsed in WebKit (`CrossOriginOpenerPolicy.cpp:237`), parsed in Chromium
  (`cross_origin_opener_policy_parser.cc:66`) behind a flag that is
  `FEATURE_ENABLED_BY_DEFAULT` (`features.cc:89`), and appears nowhere in
  Firefox; and Chromium's `integrity_policy_parser.cc:36` accepts
  `blocked-destinations=script` and nothing else, pushing anything else onto
  `parsing_errors`. This is the cheap way to recheck them when the shelf life
  runs out.

**`security/csp-evaluator`** — the source of the ported CSP checks.
`checks/security_checks.ts`, `checks/strictcsp_checks.ts` and
`checks/parser_checks.ts` are the checks themselves;
`allowlist_bypasses/{jsonp,angular,flash}.ts` is the curated data deliberately
*not* embedded here.

**`security/hstspreload`** — the source of the declared `[preload]` extra, so
the behaviour of the only third-party dependency is readable. One public
function, `in_hsts_preload(host)`; the list is a packed `hstspreload.bin`
rebuilt monthly from Chromium's `transport_security_state_static.json` — which
is now on disk too, at `web_browsers/chromium/net/http/`, so the packed list and
its source can be compared.

**`security/humble`** — rfc-st/humble, the closest peer to this package on disk
and the one to diff verdicts against. `humble.py` is 5 648 lines, but the part
worth reading is the data beside it, because it is a catalogue in the same
sense `catalog.py` is:

- `additional/insecure.txt` — **158 defect names over 93 distinct headers**,
  each written `Header: Defect` (`Access-Control-Allow-Origin: Unsafe Values`,
  `Cache-Control: No Valid Directives`). This package has 96 codes over far
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

**`w3c/webref`** — mechanically extracted content of **752 crawled web specs**,
and the answer to the spec gap this section otherwise records as unclosable:
the WHATWG and W3C living standards are in no IETF mirror, and this is them, in
JSON. Generated by Reffy, regenerated upstream every 6 hours. Surveyed
2026-08-17.

- **`ed/dfns/` is a registry of headers defined by living standards.** Filtering
  on `type == "http-header"` yields **77 headers across 19 specs**, each with
  its `linkingText`, its exact anchor `href`, and the `heading` it sits under —
  CSP and CSP-Report-Only from `CSP3`, COOP/COEP and their report-only twins,
  XFO and `Origin-Agent-Cluster` from `html`, the eight `Access-Control-*`,
  `X-Content-Type-Options` and CORP from `fetch`, `Clear-Site-Data`,
  `Permissions-Policy`, the four `Sec-Fetch-*`, and the Document-Policy family.
  **The type filter is not complete and must not be used alone**: authors who
  wrote a plain `<dfn>` get `type: "dfn"`, which is how `Referrer-Policy`
  (`dfns/referrer-policy.json`) and every `Integrity-Policy` term
  (`dfns/sri-2.json`) escape it. Grep `linkingText` as well.
- **`ed/algorithms/` is the normative text**, 58 MB of it: each algorithm as a
  name, an `href`, and a nested `steps[]` tree whose `html` carries the actual
  numbered prose with every cross-reference resolved to an absolute URL. This is
  the closest thing on disk to reading the spec, and it is greppable.
- Worked example, and it moved a ruling: `algorithms/sri-2.json` holds
  *processing an integrity policy*, which confirms `blocked-destinations` is the
  closed set `{script, style}` at spec level — matching Chromium's parser — and
  adds a fact the browser source does not state as plainly, that **an absent
  `sources` key means `inline`** ("If `dictionary["sources"]` does not exist *or*
  if its value contains `inline`, append `inline`"). A policy with an explicitly
  empty `sources` therefore blocks nothing.
- **RFCs are crawled too but yield less.** `rfc6797` (HSTS) and `rfc7034` (XFO)
  get `headings/` and `ids/` only — plain RFC HTML has no Bikeshed markup, so
  there are no dfns and no algorithms. For those, `rfc-library` remains the
  source.
- This checkout is the `main` branch — **raw** extracts, explicitly carrying no
  validity guarantee. The `curated` branch is the patched one; the difference
  bites on IDL and CSS, which this project does not read. Extraction artefacts
  do exist in what it does read: `html`'s XFO dfn is filed under a
  `speculative-loading.html` href because heading attribution drifts across
  HTML's multipage split. Trust the `linkingText`, sanity-check the `href`.

**`w3c/browser-specs`** — the 804-entry curated spec list that decides what
`webref` crawls, and independently useful as a **spec liveness oracle**:
`standing` is `good` (735) / `discontinued` (61) / `pending` (8), with
`obsoletedBy`, `formerNames`, `organization` and both nightly and release URLs
per entry. Facts read off it 2026-08-17, each of which bears on a ruling here:
`document-policy` is in **good** standing, so "not analyzed" is a scope call and
not a dead-spec call; **`feature-policy` is absent entirely** — not
discontinued, not present, the list simply does not carry it, which is a
stronger statement about it than `DEPRECATED_HEADERS` makes; there is no
`integrity-policy` entry because Integrity-Policy is defined inside `sri-2`;
`partitioned-cookies` is **discontinued**; and `rfc7230`–`rfc7235` are marked
obsoleted by `rfc9110`/`rfc9111`/`rfc9112`, which is a cheap way to check an RFC
citation has not gone stale.

**`w3c/web-features`** — the WebDX Baseline catalogue, 1 189 features as
`features/<id>.yml` (hand-written: `name`, `description`, `spec`, `caniuse`,
`compat_features` as BCD keys) beside `features/<id>.yml.dist` (generated:
`baseline: high|low|false`, `baseline_low_date`, `baseline_high_date`, and the
minimum version per browser). It is **a rollup of BCD, not a rival to it** —
use it for the one-line "is this widely available" answer (`hsts` is
`baseline: high` since 2018-01-29, `csp` since 2019-02-02) and go to BCD the
moment the question is per-directive or per-value.

- Its real asset here is the **`discouraged:`** key: `reason`, `alternatives`,
  an optional `removal_date`, and `according_to` — a **URL to the decision
  itself**. That is the citation `DEPRECATED_HEADERS` entries otherwise have to
  be argued from prose. Of the 50 discouraged features exactly one is a header:
  `feature-policy`, "superseded by permissions policy", cited to
  `w3c/webappsec-permissions-policy` PR #379.
- **Coverage is partial and the gaps are ours.** It references 115 headers, but
  there is no feature for `X-Frame-Options`, `X-Content-Type-Options`, COOP,
  `X-XSS-Protection`, `Expect-CT` or `Public-Key-Pins` — it curates what web
  developers are told to *use*, so obsolete and defensive-only headers fall
  outside it. Do not read an absence here as an absence of support.

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
  make. Two failure modes to avoid in one 15-line file. Note *why* the first one
  is a bug, because this was recorded wrongly here once: lowercasing the name is
  not itself the error — browsers match these prefixes case-insensitively (see
  the parked `Set-Cookie` item) — the error is comparing the lowered name
  against a mixed-case literal, which can never match. Lower both sides.
  `burp/burp-samesite-reporter` is 326 lines of Java that
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

`/home/crapula/ref` holds far more than the whitelist above: 35 GB of
operating-system source, a dozen application servers, seven cookie tools and
two dozen Burp extensions of which only the eight named above touch a header
value or a cookie flag. **Nothing outside this section is relevant unless the
human says so.** Do not survey it, do not grep it speculatively, and do not
re-derive that it is uninteresting — that was done once, and the cost of doing
it again is the reason this paragraph exists.

Only the negatives that would otherwise look promising are kept:

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

96 codes (35 error / 26 warning / 35 note), each with a rating and a message
template, and every rendered sentence pinned by a snapshot. 324 tests, 153 test
functions, all passing; `ruff check` clean. `pyproject.toml` is a placeholder — hatchling, no
README yet, `hstspreload` declared as the optional `[preload]` extra.
