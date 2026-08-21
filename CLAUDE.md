# http-security-test

An HTTP security header **analysis engine**, plus a command-line tool over it.
It began as a fork of `shcheck` and outgrew it; the fork's tool was deleted and
only the analyser survived, until `hst` was written against the analyser rather
than tangled into it.

**The engine is still library-only in the sense that matters: it never fetches
anything.** Every network call lives in `cli/live.py`, `import
http_security_test` pulls in no fetching code of ours, and a test pins that
nothing outside `cli/` names `cli`. Do not relax that direction — it is what
lets the analyser be embedded in a Burp extension, a CI job or a notebook
without dragging a tool along.

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

cli/           the `hst` tool -- the only code here that opens a socket
  __init__.py    main(argv) -> int: parse, dispatch, exit codes
  meta.py        TOOL_NAME, tool_version(), USER_AGENT, LEVELS
  options.py     the entire argparse contract, one file to read the CLI
  commands.py    do_scan(), do_explain(): glue, one function per verb
  exchange.py    Exchange, Hop, Failure: what crosses the input seam
  scope.py       host patterns -- where a redirect may wander
  live.py        the live source: urllib, redirects, TLS, proxy
  run.py         run_document(): results -> the JSON run envelope
  text.py        render(): the human-readable report
  writers.py     format table, -o resolution, the writers
```

`cli/` is flat for the same reason the analyser is. `sources/` and `formats/`
directories become worth having at three implementations each; today they would
be ceremony. When the HAR parser lands, `har.py` sits beside `live.py`.

Dependencies run one way and there are no cycles:

```
findings, message, catalog  ->  (nothing)
csp, hsts, isolation, legacy, policies  ->  findings [, message]
response   ->  all of the above except catalog
reporting  ->  response, findings, catalog

cli.exchange, cli.scope  ->  (nothing)
cli.meta     ->  SEVERITIES, from the public API
cli.run      ->  cli.meta
cli.text     ->  cli.exchange, cli.meta
cli.writers  ->  cli.text
cli.live     ->  cli.exchange, cli.scope, parse_headers
cli.commands ->  all of the above + report(), FINDING_SEVERITY, MESSAGES, hsts
cli.options  ->  cli.commands, cli.meta
cli.__init__ ->  cli.options
```

`cli.meta` holds `LEVELS = tuple(reversed(SEVERITIES))` rather than restating
the severity vocabulary, which is why `options` needs no import of the renderer
just to spell `--min-level`'s choices — and why adding a level upstream cannot
silently desynchronise the two.

**Nothing outside `cli/` may import `cli`**, and a test asserts it by walking
the AST of every analyser module. That single grep is what keeps the claim in
the opening paragraph true.

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
`message.py` is not a distinction. The rule bit again in `cli/`: the fetch
module is `live.py` exporting `fetch()` rather than `fetch.py`, and the envelope
module exports `run_document()` rather than `run()`.

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
   `'unsafe-inline'` idiom flagged as XSS). Assume the next one is too. This is
   not an amateur failure mode: PortSwigger shipped the same bug and then
   **archived** it — `documentation/BChecks`
   `archived/Content-Security-Policy.bcheck` decides everything by substring
   containment and carries a comment recording a false positive it had already
   had to patch out. See that entry in the reference section.
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
- **`security` and `missing` are two halves of one question, with two
  exceptions.** `REPORTING_HEADERS` (`Report-To`, `Reporting-Endpoints`) and
  `CORS_HEADERS` (the six response-side `Access-Control-*`) are inventoried
  under `security` when present and are **never** reported absent, because a
  response that configures no reporting — or shares nothing across origins — is
  the ordinary state of the web rather than a gap. This is why they are not in
  `SECURITY_HEADERS`: that
  tuple is read three times — for `security`, for `missing`, and by
  `_report_missing()` — and only the first is wanted here. Adding a header
  there to get it inventoried mints an `<initials>-missing` code that fires on
  nearly every site; the bijection tests catch it, but the design should not
  need saving by them. The CORS table was added on 2026-08-21 and closed a
  plain oversight: `Access-Control-Allow-Origin` had findings but appeared in
  no inventory at all, so a response sharing itself with credentials to an
  arbitrary origin showed five empty tables.
- **Absent beats empty for passthrough.** No blob, no `raw` key; nothing known
  about the request, no `request` key. The rule that reconciles this with `data`
  always being `{}`: content this package *derived* is always present, content
  it was merely *given* is present only if it was given.

The `raw` blobs are optional and the analyser never fetches anything, so they
are whatever the caller hands over — `cli/live.py` is what supplies them for a
live scan, and it does so only under `--raw`. Two things decided about them:

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

## The CLI

`hst`, added 2026-08-21. `docs/designs/2026-08-21-cli-contract.md` is the
contract and the full reasoning; this is the part worth carrying in your head.

```sh
hst scan https://example.com          # the 95% case
hst scan -oA evidence example.com     # nmap-style: terminal AND files
hst scan -j example.com | jq .        # machine output on stdout
hst explain csp-unsafe-inline         # what a code means
```

Two console scripts, `hst` and `http-security-test`, both at
`http_security_test.cli:main`. **Standard library only** — `pip install
http-security-test` gives a working tool with no dependencies, and there is
deliberately no `[cli]` extra, because an extra that installs nothing
misrepresents the package.

**Verb-first, and the bare form is deliberately a usage error.** `hst
example.com` exits 2 with `did you mean: hst scan example.com`. A flat,
curl-shaped CLI was considered and rejected: every file-input format on the
roadmap has a flag set disjoint from `scan`'s — no `-k`, no `-H`, but filters a
single fetch has no use for — and retrofitting verbs onto a flat tool breaks
every invocation anyone has written down.

**nmap's output model, and it is not only ergonomics.** The terminal always
shows the run; `-o FORMAT:PATH` (repeatable) and `-oA PREFIX` write files. With
several simultaneous outputs the pipeline is *forced* to materialise one
plain-data run document and render it N times, rather than letting a renderer
walk live objects — the same discipline `reporting.py` imposes on the analyser,
and the reason a SARIF writer will be a pure function over data that already
exists. Corollaries: colour is a terminal property and never reaches a file,
and **`--min-level` filters the terminal only** so evidence files stay complete.

**Exit codes are frozen.** 0 ran clean; 1 findings at or above `--fail-on`;
2 usage error (argparse's own, which we do not fight); 3 a target could not be
reached. **Findings never make the exit nonzero by default** — a pentester with
`set -e` must not have a loop die because a site is missing CSP, and CI opts in
with `--fail-on`. **3 beats 1**, because an incomplete answer is the more
serious fact: a gate reporting "clean" after failing to reach half its targets
is worse than useless.

**Failure kinds, not retryability.** `dns`, `refused`, `timeout`, `reset`,
`tls`, `protocol`, `other`, from one exception-to-tag mapping. "Retryable" is a
prediction; the kind is a fact, and a calling tool predicts for itself. Note
`classify()` returns `None` for an `HTTPError`: a WAF's 403 is a response whose
headers are worth analysing, not a failure. Two live-tested details that will
otherwise be "tidied" wrong — urllib wraps only what `h.request()` raises, so
`BadStatusLine` and `RemoteDisconnected` arrive **bare** while connect-phase
errors arrive inside `URLError`; and `RemoteDisconnected` subclasses both
`ConnectionResetError` and `BadStatusLine`, so the reset branch catches it and a
separate branch would be dead code.

### The run envelope, and the three schema questions it answers

```json
{"schema": 1,
 "tool": {"name": "http-security-test", "version": "0.1.0"},
 "run": {"started": "...", "finished": "..."},
 "results": [{"outcome": "ok", "target": "example.com",
              "source": {"kind": "live", "url": "...", "status": 200,
                         "reason": "OK", "hops": [...]},
              "report": { ...verbatim from report()... }},
             {"outcome": "failed", "target": "...",
              "failure": {"kind": "dns", "message": "..."}}]}
```

**`report` holds what `report()` returned, unmutated.** Run facts live in the
sibling `source` key. That is what lets *"a response does not know where it came
from"* stay literally true instead of being worked around, and it keeps the two
contracts separable: `schema` versions the wrapper, `tool.version` versions the
contents. The throwaway `scan.py` used to splice `result["url"] = final` into
the document and label it "not part of the schema"; that hack is gone.

**`source.kind` is the discriminator, and it is where the next input format
slots in.** A HAR result reads `{"kind": "har", "file": ..., "entry": 12, ...}`
in the same slot. This is the cheap form of extensibility: **the polymorphism
lives in the document, not in the call graph**, which is why there is no source
registry and should not be one until a second source exists.

The three questions CLAUDE.md used to park under *"The schema is not finished"*
are answered, and answered **without touching the library**:

- **A version field:** `schema`, an integer, owned by the envelope. A version is
  a property of a *serialised artifact*; `report()` returns a dict, and the CLI
  is what writes files that outlive the process.
- **Run metadata:** yes, tool name and version, because reproducibility is the
  stated reason `raw` exists. Without it, a finding that vanished between two
  archived reports is ambiguous — the site was fixed, or a rule changed.
- **How several results travel:** a list, never a URL-keyed map. Keying by URL
  was already rejected and is independently wrong here, since one target can
  yield several results and the same URL can be scanned twice in one run.

Deliberately absent: **the command line**, because it carries `-H
'Authorization: …'` and proxy credentials, and redacting means guessing at
secrets. The precise provenance record already exists — `--raw` gives the actual
request head, with its credential warning attached. One documented footgun beats
two, one of them fuzzy.

### Scope is declared, never derived — and this generalises

`--follow {none,host,subdomain,any}` was designed and then deleted: every value
of it turned out to be a host pattern. What ships is `-n/--no-redirect` plus
`--scope PATTERN` (repeatable), defaulting to `{H, *.H}` for each target host
and **printed to stderr before the first request** so the guard is auditable.
`*.example.com` does not match the apex and does match at any depth — decided on
composability, because keeping them disjoint is what gives "subdomains but not
the apex" a spelling at all.

**A derived "sibling" rule was proposed and killed by measurement.** From
`example.co.uk` a label-counting rule derives `co.uk` and would admit
`evil.co.uk`. Chromium's PSL (`net/base/registry_controlled_domains/`
`effective_tld_names.dat`, read 2026-08-21): **6934 ICANN rules, 5470 of them
multi-label, 3367 two-label suffixes across 195 ccTLDs** — a second level is the
norm for country TLDs, not an exception, and `.in` carries `5g.in`/`6g.in`, so
the pattern is still growing. Three approximations were tried and all fail: a
two-label floor misses `.co.uk`; refusing a two-label parent under a two-letter
TLD then breaks `.de`, `.io`, `.fr` and most of Europe; and a shared-suffix test
cannot distinguish `www.example.co.uk -> shop.example.co.uk` from
`example.co.uk -> evil.co.uk`. **Sibling scoping is PSL-or-nothing**, and
vendoring a PSL is the csp-evaluator objection again (curated data that ages,
failing *open* when stale).

**The precedent is wider than one flag.** Any "same site" notion this tool grows
— CORS origin checks, cookie `Domain` analysis, `__Host-` reasoning — hits the
same wall. And nothing here is called **same-site**: that term has a precise
PSL-backed meaning in RFC 6265bis and Fetch, and attaching it to a looser rule
would be exactly the borrowed-term sloppiness this document warns about
elsewhere.

### `-o` resolution, and the bug that is easy to reintroduce

Given one `-o` argument: if it contains a colon **and the text before the first
colon is a known format name**, that is the format and the rest is the path;
otherwise the whole argument is a path and its extension decides; otherwise a
usage error naming both fixes. **Invariant: no single-letter format name,
ever** — that is what makes `-o C:\out.json` unambiguous on Windows, and a
future `-o c:report.csv` would break it silently.

An "obvious" third branch — error on a format-shaped head that names nothing —
was written, shipped and reverted in one session. It rejects `note:doc.json`, an
ordinary relative filename, and **no syntactic rule can separate that from
`nope:out.json`**; the two are structurally identical. So a mistyped format
prefix with a valid extension writes a file of that literal name, which is
principle 4 applied to argv: refusing a legitimate input is worse than accepting
an odd one, and the odd one is loud anyway.


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

## Human's preferences and standing rules

The first two are not preferences. They are data-loss rules, and both have been
broken by an agent that had read the section and filed it under taste.

- **Never destroy uncommitted work; never write to git.** The human owns the git
  workflow entirely. Two families of command, and the second is the trap:
  - **Writing git state:** `add`, `commit`, `stash`, `push`, `merge`, `rebase`,
    `tag`, `branch`, `worktree add`. An agent ran `git stash` once and flattened
    the human's staged changes.
  - **Discarding working-tree content:** `checkout -- <path>`, `restore`,
    `reset --hard`, `clean`. **These change no git state at all** — no ref
    moves, no index entry changes, nothing enters the object database — which is
    exactly why the older wording, "anything that changes git state", did not
    stop an agent running `git checkout -- <file>` inside a mutation-test
    harness on 2026-08-21 and reverting its own uncommitted work in two files.
    Protect the *work*, not the *state*: git is only one route to losing it.

  **Assume other agents are editing this tree right now.** Sessions run in
  parallel against one working tree — on the day above, `ListAgents` showed two
  other live sessions on this repo and `git worktree list` showed a single
  checkout, so the file the harness reverted could as easily have been someone
  else's. There is no way to tell whose an uncommitted edit is from inside a
  session, and no way to ask before the command lands. The recovery odds are not
  symmetric either: `git stash` at least leaves something in `git stash list`,
  while `git checkout -- <path>` over never-staged changes is **unrecoverable**,
  because that content never entered the object database and there is no blob to
  recover.

  **Reading git is fine, and the practices above require it:** `git show`,
  `git log`, `git diff`, `git status` and `git archive` write nothing, and the
  behavioural-equivalence check depends on them.

  **To restore a file broken on purpose** — mutation testing asks for exactly
  this, so the need is real and the doc used to leave it unanswered — back the
  file up outside the repo and copy it back:

  ```sh
  cp module.py "$SCRATCH/"      # ...mutate, run the suite...
  cp "$SCRATCH/module.py" module.py
  ```

  Reaching for git to undo your own edit is the mistake. The backup is one line
  and it cannot reach anyone else's work. A `PreToolUse` hook in
  `.claude/settings.json` blocks the discarding commands outright, because a
  rule that lives only in prose is read by exactly the agents that were going
  to follow it anyway.
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
- **Origin reflection cannot be detected from one exchange, and this is the
  fact the passive CORS work turns on.** Settled 2026-08-21. A server whose
  allowlist is exactly `{https://app.example.com}`, answering a request from
  that origin, emits byte-for-byte what a reflect-anything server emits.
  Nothing in a response distinguishes a correct allowlist from a broken one, so
  any check that calls an echoed origin "reflection" is principle 4 in new
  clothes. What closes the gap is **one bit the caller holds and the response
  does not**: whether the request's `Origin` was one the caller forged.
  `burp/Additional_CORS_Checks` works exactly this way — `CorsHelper.kt:62`
  sends nine forged origins (arbitrary, `http://` downgrade, `null`, prefix,
  suffix, subdomain, substring, underscore, unescaped-dot) and
  `CorsIssue.kt:84` decides severity purely on *did my origin come back* ×
  *was `ACAC: true` set*. When request analysis lands, take the bit as an
  argument; do not try to infer it from `host`, because partner APIs and CDNs
  legitimately allowlist unrelated origins.
- **Not analyzed: `Vary: Origin`.** Decided 2026-08-21, against MDN's advice
  and against humble, which flags it — so this is a deliberate divergence from
  peers rather than an omission. The cache-poisoning story does not survive
  being worked through: a shared cache handing origin A's
  `ACAO: https://a.example` to origin B only makes B's CORS check fail, and the
  reverse direction fails too, so it is closed in both. The exploitable version
  needs the response *content* to differ per origin, which no header can say —
  the same wall the parked cache/cookie item hit. Note also that `Vary` appears
  nowhere in Fetch: this is an RFC 9111 §4.1 cache-key question, not a
  browser-CORS one, so a finding here would be about correctness, not
  protection. Re-propose only with a concrete attack that does not need
  origin-varying content.
- **Not analyzed: `Access-Control-Allow-Private-Network`** — no MDN BCD entry,
  so by the same reasoning as the CSPEE ruling its prevalence cannot be
  measured and its support cannot be checked. Reopen if BCD gains one.
- **`ACAH: *` not covering `Authorization` is an interop bug, not a security
  one.** Fetch makes `Authorization` a CORS non-wildcard request-header name,
  but BCD's `Access-Control-Allow-Headers.authorization_not_covered_by_wildcard`
  is Firefox 115 / Chrome `false` / Safari `false` — only Firefox implements
  it. A finding here would say "your request fails in one engine", which is not
  what this package rates. Left alone deliberately.
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
  default of the analysis engine. The CLI now exists and reserves the switch as
  `--include-report-only`, documented and unimplemented; that is the hook, and
  the codes are still the work.
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
  second request with a forged `Origin`. Tool work, not analysis. The CLI
  reserves `--probe LIST` for it, on `scan` rather than as its own verb,
  because a probe run must produce the *same* document shape as a passive one —
  a separate verb would invite a second shape and then every consumer needs two
  parsers forever. An explicit list rather than a bare boolean, because a tool
  that fires unusual traffic at someone's server should make you name what you
  are firing.
- **Inverted "interesting headers"** — report anything not on a *boring* list,
  rather than only known-interesting names. The human wants to compile their own
  list, behind its own switch; the CLI reserves `--unknown-headers` for it.
- **`request.py`** — request parsing/analysis, sharing `message.py`.
- **~~The schema is not finished~~ — ANSWERED 2026-08-21 by the CLI's run
  envelope**, and answered without touching this library. A version field, run
  metadata, and how several results travel together are all properties of the
  *serialised artifact*, and `report()` returns a dict — so they belong to the
  thing that writes files. See "The run envelope" under **The CLI**. One
  consequence to know: a consumer calling `report()` directly and dumping it to
  JSON has built its own artifact and owns its versioning; this package does not
  stamp one into the dict.
- **`--all-hops`, blocked on the analyser.** The CLI can analyse every hop of a
  redirect chain and the envelope is specified for it, but it is reserved rather
  than shipped, because a bare 301 currently produces **six warnings** —
  `csp-missing`, `coop-missing`, `corp-missing`, `rp-missing`, `xcto-missing`,
  `xfo-missing` — on a response that carries no representation for any of them
  to protect. Measured, not guessed. That is principle 4, once per hop. The
  cause is structural and already recorded: `analyze_all` sees no status line,
  which is the same reason absent `Content-Type` is not reported. Closing it
  means an optional status on `analyze_all()` — most naturally as part of the
  TODO item *"change api to expect full request/response pairs first"*, which
  brings the status line along with everything else. Note HSTS is correctly
  *absent* from that list: on the https legs of a chain a redirect is precisely
  where HSTS matters, so per-hop analysis is genuinely valuable and it is only
  the representation-scoped headers that misfire.
- **A public code-to-header table.** `explain` wants to say which header a code
  belongs to and has no way to ask: the invariant is stated here and pinned by
  `test_each_code_belongs_to_exactly_one_header`, but the mapping exists only
  inside that test, reconstructed by running the corpus. Two fakes were rejected
  — a table in `cli/` duplicates knowledge the analysers own and rots the first
  time a code moves, and deriving the header from the code's prefix is a guess
  dressed as a lookup. A declared `CODE_HEADER` would also make that test
  stronger: today it can only prove the corpus is self-consistent, not that the
  package agrees with it. Second consumer waiting: SARIF's `rules[]` wants a
  rule's owning component.
- **File input for the CLI** — `read` verb, Burp XML, HAR, SAZ, WCAT. The seam
  is designed and the payload shape fixed (`cli/exchange.py`), deliberately with
  no registry: every one of those formats is a multi-exchange container carrying
  both request and response, so a source yields an *iterable* and one live
  target yields a tuple of one. Getting the payload right was the commitment;
  the registry is a few lines whenever the second source lands.

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
  `Cache-Control: No Valid Directives`). This package has 102 codes over far
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

**`security/cryptolyzer`** — the closest *architectural* cousin on disk, and
easy to miss because its README sells it as a TLS/SSH/DNSSEC analyzer. Surveyed
2026-08-21. `docs/features.rst:250-281` lists an HTTP header feature set
overlapping this package's almost exactly — CSP and CSP-Report-Only, HSTS, XFO,
XCTO, X-XSS-Protection, Referrer-Policy, Expect-CT, Set-Cookie, NEL, Server,
Content-Type, and the five caching headers. Two things make it worth reading:

- **It draws the inventory/judgement line where principle 2 draws it, and it
  drew it independently.** `cryptolyzer/httpx/headers.py` is 55 lines and its
  whole job is `'Check which response headers are sent by the server(s)'` — an
  inventory, no findings. Its `httpx/content.py` is the other half and needs
  the response *body* (it walks tags for SRI attributes and mixed content),
  which is the same wall this package's out-of-scope rulings keep hitting.
- **The parse layer is a separate repository**, `security/cryptoparser`, which
  has its own entry below. Note that `submodules/cryptoparser` *inside this
  checkout* is an empty gitlink and always will be — `pull.sh` does not do
  submodules, which is why the sibling clone exists. Read the sibling; the
  empty directory is not a problem to solve.

**`security/cryptoparser`** — cryptolyzer's parse layer, cloned separately
2026-08-21 so `pull.sh` maintains it. `cryptoparser/httpx/header.py` is
**2 028 lines and the most complete typed model of HTTP header *values* on
disk**: `attrs` classes, one per header and one per directive, each with
`_parse()` and `compose()` so every header round-trips. The nearest thing to a
rival design for `message.py` plus the family modules, and the closest
available answer to "what would this package look like if the value model were
the product rather than the findings".

- **Coverage is 22 headers, and lopsided against this package's.** Age,
  Cache-Control, Content-Type, CSP, CSP-Report-Only, Date, ETag, Expect-CT,
  Expect-Staple, Expires, Last-Modified, NEL, Pragma, Public-Key-Pinning,
  Server, Set-Cookie, Referrer-Policy, HSTS, X-Content-Security-Policy, XCTO,
  XFO, X-XSS-Protection. Wider on caching and on the obsolete set, **narrower
  on everything modern** — no COOP, COEP or CORP, no Permissions-Policy, no
  Clear-Site-Data, no Integrity-Policy, no reporting headers, no
  `Access-Control-*`. Read it for the modelling, not for coverage.
- **Do not copy its header-name table.** One entry is simply wrong:
  `:1644` registers `code='public-key-pinning'` /
  `normalized_name='Public-Key-Pinning'`, and the string `Public-Key-Pins` —
  the name RFC 7469 actually defines, and the one OWASP's corpus tracks —
  appears **zero times in the file**, so that parser can never match the header
  on the wire. Worth knowing for its own sake and as a warning: a round-trip
  `_parse()`/`compose()` test cannot catch this, because both directions read
  the same wrong constant. That is the "passes both ways" failure the working
  practices above describe, sitting in production code.
- **`Set-Cookie` is parsed, the prefixes are not.** `HttpHeaderFieldValueSetCookie`
  (`:1399`) carries `name`, `value`, `expires`, `max_age`, `domain`, `path`,
  `secure`, `http_only`, `same_site`, split across two layers: the value class
  takes `name=value` and delegates the rest to
  `HttpHeaderFieldValueSetCookieParams`, a semicolon-separated field set. Its
  `SameSite` is a `StringEnumCaseInsensitiveParsable`, matching the
  case-insensitivity the parked item verified. But `__Host-`, `__Secure-`,
  `__Http-`, `__Host-Http-` and `Partitioned` appear **zero times in the file**
  — so this is a parse model to borrow from and **not** a source for the four
  prefix rules, which stay this package's own work off
  `CookiePrefixes.cpp` and `cookie_util.cc`.
- **Its XFO value set is `{DENY, SAMEORIGIN}` case-insensitive, with
  `ALLOW-FROM` absent from the file entirely.** An independent parser that
  simply does not admit the value, which is corroboration for rating
  `xfo-allow-from` an `error` rather than a deprecation note.
- **CSP is modelled as a closed grammar, not strings.** Nonce, hash, scheme,
  host and keyword are five distinct parsable source types
  (`ContentSecurityPolicySourceHash`, `…Nonce`, `…Scheme`, `…Host`,
  `…Keyword`), with the keyword set closed at nine (`'none'`,
  `'report-sample'`, `'self'`, `'strict-dynamic'`, `'unsafe-allow-redirects'`,
  `'unsafe-eval'`, `'unsafe-hashes'`, `'unsafe-inline'`, `'wasm-unsafe-eval'`).
  A source-list type that cannot represent an unparsed string is the structural
  answer to principle 4's substring bug — worth reading before the next CSP
  change, whether or not the model is adopted.
- **`test/httpx/test_header.py` is 1 143 lines of real header values** with
  their expected parses. The only per-header parse corpus on disk that is not
  this package's own `tests/`, so it is a free source of awkward inputs to
  check `message.py` and the family parsers against.

**`documentation/BChecks`** — PortSwigger's official BCheck library, a
declarative scan-check DSL (`metadata:` / `define:` / `given response then`).
Surveyed 2026-08-21. Its value here is mostly evidentiary:

- `archived/Content-Security-Policy.bcheck` is **principle 4's failure mode
  shipped by a major vendor and then archived by them**. Every decision is
  substring containment against the whole header block — `" *" in
  {to_lower(latest.response.headers)}`, `" 'unsafe-inline'"` flagged with no
  nonce or `strict-dynamic` awareness — and `report-uri` and
  `block-all-mixed-content` are listed among its "insecure values". It even
  carries the epitaph: *"the deprecated `referrer` value was removed from
  insecure_value due to causing false positives from the Referrer-Policy
  header"*. Cite this when someone proposes a substring check.
- `other/Cookie-SameSite-Disabled.bcheck`, `other/tokens/`
  `cookie-cached-on-disk.bcheck` and
  `other/corsCredentialedRequestsMisconfiguration.bcheck` are small independent
  opinions for the parked cookie work and the CORS rulings.

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

**`documentation/http.dev`** — **not a git repository**, and the first thing to
know about it. It is an unpacked HTML scrape of http.dev, like
`web_browsers/lynx2.9.3` is an unpacked tarball, so `pull.sh` reports it
`skipped (not a git repository)` and any `git` command run *inside* it walks up
and answers about the git-mirror repo at the root of `/home/crapula/ref` —
which looks alarmingly like a mirror pointing at the wrong origin, and is not.
Surveyed 2026-08-21. 506 files, no extensions: 138 status-code pages and 365
non-numeric ones, mostly one per header name with a few topic pages
(`caching`, `authentication`). Two uses and one trap:

- **The broadest header-name list on disk** — 365 against
  `known-http-header-db`'s 271 — which makes it the best candidate corpus for
  the parked inverted *"interesting headers"* switch. It is HTML, so strip tags
  before using it as data.
- Readable prose per header when orientation is wanted on something nobody here
  has met.
- **Never cite it for browser support.** Its "Baseline: Widely available"
  banners are rendered from web-features/webstatus.dev, so it is BCD at second
  hand — the same trap this section already records for caniuse.com, one step
  further removed.

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
  `cookie_security/cookie-security-analyzer` (added to the survey 2026-08-21)
  is the one peer with an explicit **severity ladder** for cookies: a Chrome
  MV3 extension rating each one `SAFE` / `LOW RISK` / `MEDIUM RISK` /
  `HIGH RISK` in `src/popup.ts` from `secure`, `httpOnly`, `sameSite` and
  third-party status — `pageIsSecure && !secure`, `sameSite` unspecified, and
  `sameSite === "None" && !secure` are its three rules. Read it for the ladder,
  and note what it cannot do: it reads `chrome.cookies`, not `Set-Cookie`, so
  the prefixes are invisible to it and it implements **none** of the four. That
  blind spot is the argument for parsing the wire header rather than a cookie
  store, and it is why this repo is worth naming despite sitting in a directory
  the "Everything else" section otherwise writes off.
  For the **parse** side rather than the rules, `security/cryptoparser`'s
  `HttpHeaderFieldValueSetCookie` is the typed Python model to compare against
  — see its entry above, including the warning that it implements none of the
  four prefixes.
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
  `cache_control.py`, so it is the one independent *opinion* available on both
  parked cache items before writing `pragma-ineffective`. For the parse side,
  `security/cryptoparser` models both — a `Cache-Control` response class with
  `max-age`, `s-maxage`, `no-cache`, `no-store`, `must-revalidate`,
  `proxy-revalidate`, `public`, `private` and `no-transform` as typed
  directives, and `Pragma` as a header in its own right — which is the closed
  directive set the "no `Cache-Control` prevents storage" condition has to be
  written against.
- **CSP allowlist-bypass corpora, still not embedded.** `burp/csp-auditor` has
  `csp-auditor-core/src/main/resources/resources/data/csp_host_user_content.txt`
  and `csp_host_vulnerable_js.txt` — a second curated list beside
  csp-evaluator's and split along the same two axes, loaded by
  `model/WeakCdnHost.java`. `burp/CSP-Bypass` has a readable standalone
  `csp_parser.py` but a `csp_known_bypasses.py` holding exactly one domain, so
  it is no substitute for either. The **Not embedded** ruling covers all of
  them; nothing here changes the upkeep argument.
- **`burp/burp-javascript-security-extension`** — the only peer on disk that
  ties CSP to subresource integrity, and it is instructive for being wrong
  twice over. `src/main/java/burp/BurpExtender.java:135` is
  `if (!response.contains("Content-Security-Policy: require-sri-for script;"))`
  — an exact-substring test, trailing semicolon included, so it fires on every
  correct policy that omits the `;`, capitalises differently, or orders its
  directives another way. That is principle 4's failure mode inverted: the
  shcheck bug was a match too loose, this is a match too tight, and both
  produce a finding on a correct configuration. Second, the directive it asks
  for is dead — **MDN BCD carries no `require-sri-for` key at all** under
  `http/headers/Content-Security-Policy.json` (verified 2026-08-21), the same
  absence that decided the CSPEE and `Access-Control-Allow-Private-Network`
  rulings. `Integrity-Policy` is the live mechanism for this and is already
  analysed here. Do not port this check.
- **`burp/Additional_CORS_Checks`** — Kotlin, and the prior art for the parked
  active origin-reflection check: it re-issues a request with a forged `Origin`
  and reports arbitrary-origin and `null`-origin reflection (`doc/*.png` shows
  what it claims). Tool-side work, exactly as that item says.
- **`burp/t0xodiles-cors-check`** — the *second* implementation of that same
  check, found 2026-08-21, and the reason the CORS ruling can be called
  corroborated rather than reasoned: it decides on exactly the same bit
  (`ACAO` equal to the origin it sent), from a different author, in a codebase
  last touched 2026-05-31 where `Additional_CORS_Checks` stopped in 2022. It
  adds one axis the other lacks —
  `src/main/kotlin/TrustedDomainValidationBypassCheck.kt` carries **24
  hand-written allowlist-regex bypass patterns**, 23 of them distinct — one is
  listed twice and two more are commented out. They are the trusted domain and
  the attacker domain joined by each of eighteen punctuation characters (`_`,
  `-`, `,`, `;`, `!`, `'`, `(`, `)`, `*`, `&`, `+`, `=`, `~`, `$`, `{`, `}`, a
  backtick and a double quote) or by a bare dot, plus the concatenations
  `trusted.comweb-attacker.com`, `web-attacker.com.trusted.com`,
  `anythingtrusted.com` and `strusted.com` — each tried as both `http://` and
  `https://`. `TrustedDomainCheck.kt` bootstraps from a domain it has
  *observed* to be trusted, then enumerates subdomains of it. Take the pattern
  list from here when the active checks land; take the severity rule
  (reflection × `ACAC: true`) from `Additional_CORS_Checks`.
- **`burp/additional-scanner-checks`** — small, from 2018, and worth an entry
  only because it corroborates two decisions this package otherwise made alone.
  Its BApp description lists *"Multiple occurrences of the checked headers"* as
  a check in its own right, for HSTS and X-XSS-Protection — `duplicate-headers`
  by another name. And `Burp-MissingScannerChecks.py:316` reaches the
  `identity()` conclusion independently: *"it is assumed that multiple
  `X-Content-Type-Options: nosniff` headers can't cause confusion at browser
  side because they all have the same meaning"*, which is this package's "a
  repeated header with identical values still reports once" in someone else's
  words. It also demonstrates the failure `_sole_value()` exists to avoid —
  `:120` carries `# TODO: multiple max-age directives cause confusion!` on its
  HSTS regex, unresolved.
- **The Burp extension-development kit**, if a Burp front-end for this library
  is ever wanted: `documentation/burp-extensions-montoya-api` is the current
  API (`documentation/burp-extender-api` is the same thing deprecated, by
  upstream's own README), with `documentation/`
  `burp-extensions-montoya-api-examples` — whose `customscanchecks/` is the
  relevant one — plus `documentation/extension-template-project` as a
  ready-made Gradle skeleton and `burp/example-scanner-checks` as the
  three-language version. Packaging material, not analysis material; noted so
  it is not rediscovered as though it were.

### Everything else — assume it is not interesting

`/home/crapula/ref` holds far more than the whitelist above: **153 repositories
and unpacked trees across ten categories**, of which 35 GB is operating-system
source, a dozen are application servers, seven are cookie tools and **80 are
Burp extensions** — and only the dozen or so named above touch a header value
or a cookie flag. **Nothing outside this section is relevant unless the human
says so.** Do not survey it, do not grep it speculatively, and do not re-derive
that it is uninteresting — that was done once, and the cost of doing it again is
the reason this paragraph exists.

**How far the negative reaches, because the tree grows.** Everything present on
**2026-08-21** was surveyed, superseding an earlier pass that had seen only 83
repositories — which is why this paragraph used to say "two dozen Burp
extensions" and was wrong by 55 of them. So the blanket negative is good for
what was on disk that day and **claims nothing about anything added since**. It
went stale silently once and will again; a dated survey is the honest form.

To tell what is new, compare directory mtimes against the survey date: the
clones surveyed then are stamped 2026-08-12 to 2026-08-21, so anything later is
an addition. Treat it as a hint rather than proof — a directory is restamped
whenever a top-level entry appears or disappears, so an upstream that added a
file will look new. **Do not look for a manifest.** A `research.tsv` may or may
not be sitting at the root of `/home/crapula/ref`; it was written once to
exercise `export.sh`, it is not maintained and is expected to be deleted, and
reading it as an inventory would under-report the tree by 70 repositories. When
the mtime is ambiguous, ask rather than re-survey 153 repositories.

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
  smuggling, nuclei and semgrep bridges, GDPR consent scanners, 403/429 and WAF
  bypass helpers, GraphQL and OpenAPI tooling, AI assistants, and PortSwigger's
  own example extensions. Burp plumbing and privacy-compliance tools; none
  analyses a header value or a cookie flag. Four that look like exceptions and
  are not, checked 2026-08-21 so they are not re-opened: `burp/identity-crisis`
  diffs responses across **request** `User-Agent` values;
  `burp/BurpSuite_CookieReflection` and `burp/sri-check` both need the response
  **body** (a cookie echoed into it, an `integrity` attribute on a tag);
  `burp/http-terminator` is request smuggling, already out of scope. Two data
  files were weighed for the parked inverted *"interesting headers"* switch and
  lost to humble's 1 287-name `fingerprint.txt`: `burp/waf-detect`'s 64-row
  `resources/WafFingerprints.csv` (which does have a `HEADER_ONLY` column and
  header-anchored regexes such as `^Server: AkamaiGHost` and
  `^Set-Cookie: ak_bmsc=`) and the 114-regex `match-rules.tab` shared by
  `burp/software-version-reporter` and
  `burp/burp-suite-software-version-checks` — the latter is the only one that
  extracts a *version* out of a value rather than just naming the product, so
  revisit it if the switch ever wants that. And `cookie_security/`
  `sentry-watchdog`'s `known_cookies.json` is not a cookie database: it is the
  cookies observed on Sentry's own marketing sites, keyed `name/domain`.
- **`security/nmap-nse-vulnerability-scripts`** — named only because the name
  promises far more than it holds. It is NCC's three unrelated NSE scripts
  (Lexmark, PJL, SMTP), **not** the nmap NSE corpus, so
  `http-security-headers.nse` is not here and this is not the independent
  opinion it looks like. Same for `security/retire.js` (JS library CVEs),
  `security/IIS-ShortName-Scanner`, `security/cloud_ip_ranges`,
  `security/nsdp-discover` and `vulnerable/research-labs` — the last is three
  PortSwigger research labs (token signing, PDF rendering, control-character
  injection), none header-related, though the `vulnerable/` category is where
  an end-to-end fixture would live if one ever appears, beside
  `security/badssl.com`.
- **`documentation/xss-cheatsheet-data` and `documentation/url-cheatsheet-data`**
  — PortSwigger's cheat-sheet corpora as JSON. Payload data for injection and
  SSRF testing; nothing about response headers.

## Status

**Analyser:** 102 codes (39 error / 26 warning / 37 note), each with a rating and
a message template, and every rendered sentence pinned by a snapshot.

**CLI:** `hst` ships the `scan` and `explain` verbs over 10 modules in `cli/`,
standard library only. Reserved and documented but not implemented: the `read`
verb and its file parsers, `--probe`, `--all-hops`, `--include-report-only`,
`--unknown-headers`, `--retry`, scope exclusions, `-d/--data`, and the `sarif`
and `ndjson` output formats — the last two are *named* in `writers.RESERVED` so
a user gets "not implemented yet" rather than "invalid choice", which is the
whole of their implementation.

**Tests:** 512 passing across 274 test functions, 108 of them CLI. `ruff check`
clean. No test touches the network, with one deliberate exception: the redirect-
limit test binds a loopback `http.server` on an ephemeral port, because urllib's
own redirect bookkeeping cannot be tested any other way.

`pyproject.toml` declares two console scripts (`hst` and `http-security-test`,
both `http_security_test.cli:main`) and `hstspreload` as the optional
`[preload]` extra. No runtime dependencies. Still no README.

The CLI was built 2026-08-21 against
`docs/designs/2026-08-21-cli-contract.md`; `docs/superpowers/plans/`
`2026-08-21-cli-tool.md` is the implementation plan, corrected in five places
during the build where it disagreed with the spec or with reality.
