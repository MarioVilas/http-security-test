# The CLI contract

Design notes for the command-line tool. Agreed in session on 2026-08-21;
**nothing here is implemented yet.**

The library has deliberately had no CLI and never fetches anything. Neither of
those facts changes. What changes is that a `cli` subpackage is added beside the
analyser, importing it and never imported by it, so that `import
http_security_test` still pulls in no network code and the analysis engine still
answers only "what is wrong with this response".

`scan.py` at the repository root is the throwaway fetcher this replaces. It
should be deleted when `hst scan` exists.

## Why now, and why the CLI is the thing that closes the schema

Three questions in CLAUDE.md's *"The schema is not finished"* cannot be answered
from inside a library that analyses one exchange at a time — a version field,
how several results travel together, and whether run metadata belongs in the
document. All three need a consumer that produces more than one result.

`scan.py` already gropes at the third and gets it wrong on purpose:

```python
result["url"] = final  # not part of the schema; a fact about the run
```

That line is a design question the library correctly refused, punted to a tool
that did not exist. This document answers it, and answers it **without touching
the library** — see *The run document*.

## Scope

**Implemented in v1:** the `scan` verb (live fetch of one or more URLs, analysis,
output), the `explain` verb, the nmap-style output model, the run document, exit
codes, failure classification.

**Designed here, not built:** the `read` verb and its file sources (Burp XML,
HAR, SAZ, WCAT), `--probe` (active tests), `--all-hops`, `--include-report-only`,
`--unknown-headers`, `--retry`, the `sarif` and `ndjson` output formats.
Reserved names are recorded so that adding them later is additive.

**Out of scope entirely:** anything that changes the analyser. This document was
written while a second agent was working in `response.py` and friends, and it
touches no analyser module. One finding *for* the analyser is recorded at the
end under *Handed to the analyser*.

## Where the code lives

```
http_security_test/
    ...analyser modules, untouched...
    cli/
        __init__.py    main(argv) -> int : parse, dispatch, exit codes
        options.py     the entire argparse contract -- one file to read the CLI
        commands.py    do_scan(), do_explain() : glue, one function per verb
        exchange.py    Exchange, Hop, Failure -- what crosses the input seam
        live.py        the live-fetch source (urllib, redirects, TLS, proxy)
        run.py         run_document() : results -> the JSON run envelope
        text.py        render() : the human-readable report
        writers.py     format registry: extension + writer per format
```

Flat, no subdirectories, mirroring the analyser — which is also flat. `sources/`
and `formats/` become worth having at three implementations each; today they
would be ceremony. When the HAR parser lands, `har.py` sits beside `live.py`;
when SARIF lands, `sarif.py` sits beside `text.py`. Module names *are* the source
and format names, so the eventual directory move is mechanical.

Two of CLAUDE.md's naming rules are already applied and are the reason for some
of these names. **A module and an exported callable must not share a name** —
which is why the source module is `live.py` exporting `fetch()` rather than
`fetch.py`, and why `run.py` exports `run_document()` rather than `run()`. That
is the same trap that turned the renderer into `describe()`.

**The dependency rule, and it gets a test:** `cli/*` imports the analyser's
public API; nothing outside `cli/` names `cli`. That single grep is what keeps
the library's identity — it still never fetches, and it still has no CLI in any
sense that matters. Pinned the same way the corpus test pins that no analyser
imports `catalog`.

## Packaging

```toml
[project.scripts]
hst = "http_security_test.cli:main"
http-security-test = "http_security_test.cli:main"
```

Both names. `hst` is the one people type; the long form exists because a
two-letter binary is a bad thing to squat silently, and because it is
self-documenting in a script someone else reads. Checked against Kali on
2026-08-21: no current tool called `hst`.

**Stdlib only** — `urllib`, `ssl`, `json`, `argparse`. So `pip install
http-security-test` yields a working tool with zero dependencies, and `[preload]`
remains the only extra. There is deliberately **no `[cli]` extra**: an extra that
installs nothing is a lie about the shape of the package.

`requires-python = ">=3.9"` is unchanged and constrains the implementation.

## The verbs

The CLI is verb-first, git-shaped. `hst example.com` is a usage error.

**`scan`** — fetch and analyse. The 95% case and the bulk of this document.

**`explain`** — with arguments, print what a code means: its level and its
message template. With no arguments, list all 102. About 25 lines over
`MESSAGES` and `FINDING_SEVERITY`.

**It does not print the header the code belongs to, and cannot.** There is no
runtime code-to-header mapping: `test_each_code_belongs_to_exactly_one_header`
derives ownership by running the corpus, which is test data the package does
not ship. Two ways to fake it were rejected — a table in `cli/` would duplicate
knowledge the analysers own and rot the first time a code moves, and deriving
the header from the code's prefix (`csp-`, `xfo-`) is a guess dressed as a
lookup. Recorded under *Handed to the analyser* instead. Listing therefore
groups by code prefix, which is a lexical sort and claims nothing.

It earns its place in v1 for three reasons beyond being useful at a terminal.
It is the natural companion to machine output — a reader who gets
`csd-unquoted` in a JSON file wants the sentence. It is a **second independent
consumer of `catalog.py`**, which is what proves `describe()`'s
template-from-data split is an interface rather than an internal convention;
today the only readers are `reporting.py` and the snapshot test. And it subsumes
a `codes`/`list` verb, so that is one fewer name to reserve.

`explain` is terminal-only in v1. Reserved: machine output for it, because a
dump of every code with its level and template is exactly the input SARIF's
`rules[]` and `messageStrings` need, and that is the cheapest possible route to
the SARIF writer.

**Reserved, and absent from `--help` rather than stubbed:**

- **`read`** — the file sources. A verb rather than a `scan` flag because its
  flag set is disjoint: no `-k`, no `-H`, no `--timeout`, but filters (`--host`,
  `--status`) that a single fetch has no use for. This is the payoff of the
  verb-first shape.
- **`--probe LIST` on `scan`** — active tests are a *depth modifier*, not a
  different noun: same analysis, same output document, more requests. Putting
  them on `scan` is load-bearing, because a separate `probe` verb would invite a
  separate output shape and then every consumer needs two parsers forever. An
  explicit list rather than a bare boolean, because a tool that fires unusual
  traffic at someone's server should make you name what you are firing.

A stubbed verb that always errors is noise. Intent lives here.

### The error a returning user will hit

`hst example.com` produces argparse's own message, which is adequate but not
directive:

```
hst: error: argument verb: invalid choice: 'example.com' (choose from 'scan', 'explain')
```

If the invalid verb contains a dot or `://`, append `did you mean: hst scan
example.com`. Roughly six lines in `main()` before dispatch, careful not to
intercept `--help` or `--version`.

## `scan` — the flag surface

Positional: `URL...`, one or more. A bare host gets `https://` prepended; the
tool never silently downgrades to plaintext. `-` as a target reads targets from
stdin, one per line.

| Flag | Default | vs. `scan.py` |
|---|---|---|
| `-H, --header 'Name: value'` | — | unchanged, repeatable |
| `-A, --user-agent` | tool UA | unchanged |
| `-X, --method` | `GET` | unchanged; help text corrected — the draft says "GET or HEAD" but accepts anything, and should keep accepting anything |
| `-t, --timeout SECONDS` | `15` | unchanged |
| `-k, --insecure` | off | unchanged |
| `--proxy URL` | — | **new** |
| `-n, --no-redirect` | off | unchanged |
| `--scope PATTERN` | derived from targets | **new**, repeatable; quote the wildcard |
| `--max-redirects N` | `10` | **new**; `_Chain` must also pin urllib's own `max_redirections` and `max_repeats` to it — see below |
| `-o, --output FORMAT:PATH` | — | **new**, repeatable; replaces `-j` as the general mechanism |
| `-oA, --output-all PREFIX` | — | **new** |
| `-j, --json` | off | kept as sugar for `-o json:-`, and so suppresses the terminal report |
| `--color {auto,always,never}` | `auto` | **new**; the draft hard-codes `isatty`, which loses colour through `less -R` |
| `-q, --quiet` | off | unchanged — findings only, no inventories |
| `-c, --codes` | off | unchanged — annotate each finding with its code and `data` |
| `--min-level {note,warning,error}` | `note` | **new**, terminal only |
| `--fail-on {never,note,warning,error}` | `never` | **new** |
| `--raw` | off | unchanged, scary help text intact |

Reserved on `scan`: `--all-hops`, `--probe LIST`, scope exclusions,
`--include-report-only`,
`--unknown-headers`, `--retry N`.

Four of those need their reasoning rather than a table row.

**`--proxy` is not optional for the primary use case.** A pentest workstation
runs everything through Burp; a tool that cannot be pointed at
`http://127.0.0.1:8080` gets used once and then replaced by `curl | hst`.
`urllib.request.ProxyHandler` covers it in about five lines.

**`-j` survives as an alias and not as the mechanism.** Boolean format flags do
not compose: with SARIF on the TODO list and NDJSON implied by bulk sweeps,
`-j --sarif` is a contradiction the parser has to police, while `-o sarif:x` is
a value. One documented alias for the single most common non-default invocation
is acceptable; two mechanisms would not be.

**`--min-level` and `--fail-on` look like one flag and are deliberately two.**
One controls what you read, the other what the shell concludes. Collapsed, a CI
job that fails on errors could no longer print the warnings beside them.

**`--min-level` filters the terminal only; files are always complete.** That is
the nmap split — terminal for monitoring, files for evidence — and it removes
the footgun where a filtered document archives as though it were whole. It is
also why no record of the filter appears in the run document: the document is
never filtered.

### Verified non-issues, recorded so nobody "fixes" them

`action="append"` with `default=[]` does **not** leak across parses; argparse
copies the default on each call (`_copy_items`). Verified 2026-08-21 on Python
3.12.3 with three successive `parse_args` calls. `scan.py`'s current spelling is
fine and needs no change.

## Redirects and scope

Following redirects is the default. The alternative — not following by default —
is simpler and worse, on this project's own principle 4. The two most common
real redirects are `http://x` → `https://x` and `x` → `www.x`; a tool whose
default answer is *"this bare 301 has no CSP, no HSTS and no X-Frame-Options"*
is emitting false positives against a correctly configured site while saying
nothing at all about the application. That is the `default-src 'self'` substring
bug wearing a different hat.

Where the tool is allowed to wander is one concept, not two: a **scope**, given
as a list of host patterns. There is no `--follow` mode enum; an earlier draft
had one and every value of it turned out to be a pattern.

| Instead of a mode | Write |
|---|---|
| don't follow at all | `-n` / `--no-redirect` |
| the same host only | `--scope example.com` |
| host and subdomains | the default — type nothing |
| follow anything | `--scope '*'` |

A **pattern** is an exact hostname (`example.com`) or a wildcard
(`*.example.com`, or bare `*`). Patterns match the **hostname only** — never
scheme or port, compared lowercased — so `https://x` → `http://x` stays in
scope, and whether that downgrade is a *finding* remains the analyser's
business rather than the scope guard's.

Three rules, each pinned because ambiguity here is expensive:

- **`*.example.com` does not match `example.com`,** and it matches at any
  depth, so `a.b.example.com` is in. The apex exclusion is decided on
  **composability**, not on DNS precedent — we already diverge from DNS by
  matching multiple labels. Keeping the wildcard and the apex disjoint gives two
  orthogonal primitives, so "subdomains but not the apex" has a spelling, which
  is a real engagement shape when the marketing site is out of scope. If the
  wildcard swallowed the apex, that case could not be expressed at all. The
  common case pays nothing, because the derived default supplies both.
- **The default, when no `--scope` is given, is `{H, *.H}` for every target
  host `H`** — and it is **printed before the first request**:

  ```
  scope: example.com, *.example.com  (derived from targets)
  ```

  That line is the affordance the mode enum could not offer: the guard's
  decision is visible up front rather than inferred from a refusal later.
- **An explicit `--scope` replaces the derived default, but every target's own
  host stays in scope regardless.** One rule and one exception, and the
  exception earns its keep: without it, `--scope '*.partner.com'` to allow an
  SSO hop would silently forbid `example.com` → `www.example.com`, which is
  the class of surprise the feature exists to prevent. You typed the target;
  hitting it is in scope by construction.

**Scope is a union across all targets.** `hst scan a.com b.com` derives
`{a.com, *.a.com, b.com, *.b.com}`, so an `a.com` → `b.com` redirect is
followed. This is deliberate and differs from the mode draft, which would have
refused it: both hosts are things the operator typed.

### urllib's own redirect ceilings must be pinned to ours

*Found 2026-08-21 by the final review, against a loopback server.*
`HTTPRedirectHandler` carries `max_redirections = 10` and `max_repeats = 4`, and
CPython calls `redirect_request()` **first** and only then applies them — so our
limit wins below 10 and urllib's wins at or above it. Three consequences, and
the middle one is the default invocation:

- `--max-redirects` above 10 silently does nothing.
- `max_repeats = 4` fires on any two-URL loop after ~9 hops, under the limit the
  operator set.
- When either fires, urllib raises `HTTPError` carrying the 3xx, the fetcher
  treats it as a response, and **no refusal is recorded** — indistinguishable
  from a site that genuinely answered 302. Worse, `HTTPError.reason` is the
  message, so a three-line English sentence with embedded newlines lands in
  `source.reason` in the evidence file.

`_Chain.__init__` therefore sets `self.max_redirections = self.max_repeats =
limit`. Our own check then always fires first and records a proper
`max-redirects` refusal hop. This does hand loop protection entirely to
`_Chain.limit` — which is correct, because it bounds total hops regardless of
loop topology: `len(self.hops)` upper-bounds both of urllib's counters.

### The quoting hazard

`--scope *.example.com` unquoted is expanded by the shell if any matching file
exists in the working directory, and the tool then silently receives filenames
as scope patterns. Verified 2026-08-21 in bash: with `www.example.com` and
`api.example.com` present in the cwd, `*.example.com` expands to both; with an
empty cwd it stays literal, which is worse, because it means the bug only
appears on some machines.

Mitigation is one line: **if a `--scope` value names an existing filesystem
entry, warn** that the shell probably expanded a glob and that the pattern
wants quoting. This is a UX warning about argv, not an analysis judgement, so
it is not the kind of guessing this project refuses elsewhere. Help text
carries the quotes in its example.

A refused redirect is loud on stderr *and* recorded as a hop with `followed:
false` and a `refused` reason. "The target tried to bounce us to
`login.example.net`" is a fact worth keeping in an evidence file; a scope guard
that silently stops is a mystery, and one that logs what it blocked is data.

### DECISION R-1 — sibling scoping — RESOLVED: `--scope`, no `sibling` mode

Proposed during design: a `--follow sibling` that admits hosts sharing the
target's immediate parent, so `www.example.com` reaches `shop.example.com`. The
derivation is "drop the leftmost label", and the worry was a small list of
historical oddities like `.co.uk`.

**Measured instead of recalled.** From Chromium's copy of the Public Suffix List
(`net/base/registry_controlled_domains/effective_tld_names.dat`, read
2026-08-21):

```
ICANN section rules:        6934
  of which multi-label:     5470  (78.9%)
ccTLDs with 2-label suffixes: 195
total such suffixes:        3367
  .uk : 10   .au : 17   .jp : 103   .nz : 16   .za : 18
  .br : 146  .in : 43   .kr : 33    .cn : 44   .pl : 153
```

A second level is the norm for country TLDs, not an exception, across 195 of
them. Nor is the pattern purely historical: `.in` carries `5g.in`, `6g.in`,
`ai.in` and `bank.in`.

The failure this causes is not cosmetic. From `example.co.uk` the derived parent
is `co.uk`, which admits `evil.co.uk` — an out-of-scope host reached during an
engagement, which is the exact thing the guard exists to prevent. And typing the
bare registrable domain is the *normal* invocation, so the hole is on the common
path for those 195 TLDs.

No safe approximation exists:

- **Floor at two labels** stops `example.com` → `com` but not `example.co.uk` →
  `co.uk`.
- **Refuse a two-label parent under a two-letter TLD** fixes `.co.uk` and then
  refuses siblings on `.de`, `.io`, `.fr`, `.nl`, `.ai` and every other flat
  ccTLD — trading an unsafe failure for a wrong one across most of Europe.
- **Require a shared suffix of ≥2 labels** does not discriminate:
  `www.example.co.uk` → `shop.example.co.uk` and `example.co.uk` →
  `evil.co.uk` are the same shape unless you already know `co.uk` is a suffix.

Sibling scoping is therefore PSL-or-nothing. **Resolved: declared `--scope`
patterns, and no derived sibling rule.** `www.example.com` reaches
`shop.example.com` by `--scope '*.example.com'`, which is exact. It is exact, needs no data and no dependency, and is less
typing than documenting the caveat would be. It does not reintroduce the hassle
the mode was meant to avoid, because the derived default still asks for
nothing — `--scope` is reached for only in the case that needed a decision.

Rejected alternatives, with reasons that should survive a re-proposal:

- **Vendoring a mini-list.** The numbers above say it would not be mini, and the
  existing ruling against csp-evaluator's curated bypass lists applies verbatim:
  curated data that ages. The failure direction is also wrong — a stale list
  means an unknown suffix derives a too-permissive parent, so it fails open.
- **`--follow sibling` behind an optional `[scope]` extra** using a real PSL
  library, mirroring `[preload]`/`hstspreload`. Clean precedent and still
  available later, but it buys a dependency for something `--scope` already does
  precisely. Reopen only if `--scope` proves annoying in practice.

**This precedent is wider than one flag.** Any "same site" notion this tool grows
— CORS origin checks, cookie `Domain` analysis, `__Host-` reasoning — hits the
same wall. Scope is *declared*, not *derived*.

### A naming trap avoided

Nothing here is called **same-site**, and nothing later should be. The term has
a precise, PSL-backed meaning in RFC 6265bis and Fetch, both of which this
project reasons from elsewhere; attaching it to a looser rule would be exactly
the borrowed-term sloppiness CLAUDE.md calls out. The pattern syntax states its
own rule and needs no label — which is a third argument for data over a mode
enum, since an enum has to name each value and each name is a chance to borrow
the wrong one.

## Exit codes

A frozen contract.

| Code | Meaning |
|---|---|
| `0` | Ran to completion; nothing met `--fail-on`. |
| `1` | Findings at or above `--fail-on`. Reachable only when `--fail-on` is given. |
| `2` | Usage error. |
| `3` | Operational failure: at least one target could not be fetched. |

`2` is argparse's own convention and we do not fight it — verified 2026-08-21,
`ArgumentParser.error()` exits 2.

**Findings never make the exit nonzero by default.** A pentester with `set -e`
in a loop does not want the script to die because a site is missing CSP; CI opts
in with `--fail-on error`. One contract, both audiences, no mode flag.

**Precedence: 3 beats 1.** A partial run is a more serious fact than a finding,
because it means the answer is incomplete. A CI gate reporting "clean" after
failing to reach half its targets is worse than useless.

Failure *kinds* are deliberately not encoded in the exit integer — one number
cannot describe a run of many targets. They live in the output, where a calling
tool can read them and decide whether to retry.

## Output

nmap's model. **The terminal always shows what is happening**, and `-o` writes
files. A pentester wants the terminal to monitor the run and the files as
evidence or as input to the next tool; piping the only output to a file gives up
the first to get the second.

This also fixes an internal layering question: with several simultaneous outputs
you are forced to materialise **one plain-data run document and render it N
times**, rather than letting a renderer walk live objects. The terminal renderer
and the `text` file writer are then the same code, and the SARIF writer later is
a pure function over data that already exists.

### Resolving `-o`

Format names are a closed set. Given one `-o` argument:

1. If it contains a colon **and the text before the first colon is a known
   format name**, that is the format and the remainder is the path.
2. Otherwise the whole argument is a path, and the format comes from its
   lowercased extension.
3. If neither resolves, usage error naming both fixes.

`-o C:\out.json` is therefore safe: `C` is not a format name, so rule 1 does not
fire and rule 2 reads `.json`.

**Invariant: no single-letter format name, ever.** That is what makes rule 1
Windows-safe, and a future `-o c:report.csv` would break it silently. Write it
into the format table's comment.

| Format | Extension | Status |
|---|---|---|
| `text` | `.txt`, also accepts `.text` | v1 |
| `json` | `.json` | v1 |
| `sarif` | `.sarif` | reserved |
| `ndjson` | `.ndjson` | reserved |

A reserved format is rejected with "not implemented yet", not "invalid choice" —
a two-line difference that tells a user the feature is coming rather than that
they misremembered.

`-` as a path means stdout. **If any output target is stdout, the terminal
report is suppressed**; you asked for machine output on the terminal and cannot
have both interleaved. `-o -` alone is an error: stdout has no extension to
infer from, so it must be spelled `-o json:-` (or `-j`).

`-oA PREFIX` writes every *implemented* format: `PREFIX.txt` and `PREFIX.json`,
later `PREFIX.sarif`. Files are overwritten rather than refused — these get
re-run constantly, and nmap made the same call.

Colour is purely a terminal property. File output is never coloured, so no
escape sequences leak into evidence, and `--color` never interacts with format
selection.

## The run document

```json
{
  "schema": 1,
  "tool": {"name": "http-security-test", "version": "0.1.0"},
  "run": {"started": "2026-08-21T12:09:03Z", "finished": "2026-08-21T12:09:07Z"},
  "results": [
    {
      "outcome": "ok",
      "target": "example.com",
      "source": {
        "kind": "live",
        "url": "https://www.example.com/",
        "status": 200,
        "reason": "OK",
        "hops": [
          {"from": "http://example.com/", "code": 301,
           "to": "https://example.com/", "followed": true},
          {"from": "https://example.com/", "code": 302,
           "to": "https://login.example.net/", "followed": false,
           "refused": "scope"}
        ]
      },
      "report": {
        "response": {"findings": [], "inventory": {}}
      }
    },
    {
      "outcome": "failed",
      "target": "down.example.com",
      "failure": {"kind": "dns", "message": "Name or service not known"}
    }
  ]
}
```

### Key by key

**`report` is the library's document, quoted verbatim and never mutated.** This
is the structural move the rest depends on. It lets CLAUDE.md's *"No URL key — a
response does not know where it came from"* stay literally true rather than be
worked around; `scan.py`'s `result["url"] = final` disappears. It also means an
archived report lifts straight back out for a diff against a fresh `report()`
with no unwrapping — which is the stated reason the `raw` blobs are carried at
all.

**`source` carries a `kind` discriminator**, and that is the file-input seam
appearing in the data. A HAR result reads `{"kind": "har", "file":
"capture.har", "entry": 12, "url": ..., "status": 200}` — same slot, different
facts, nothing restructured. This is why it is not called `exchange` or `http`.
It is also the cheap form of extensibility: **the polymorphism lives in the
document, not in the call graph**, so a new source adds a `kind` value and a
module and nothing existing has to know.

**Failures live in `results`, not a parallel list.** A consumer diffing two runs
must see that a target was attempted and did not answer; two lists mean two
loops and one of them eventually gets forgotten. `outcome` discriminates and
`report`/`failure` are mutually exclusive.

**Results are ordered, and the order is part of the contract** — targets in the
order given, and within a target, hop order. Same reasoning as *"the tables are
tuples, not sets"*: an unspecified order reorders output per process.

### The three parked schema questions

**A version field: `schema`, an integer, owned by the envelope and not by the
library's document.** A version is a property of a *serialised artifact*;
`report()` returns a Python dict, and the CLI is what writes files that outlive
the process. It increments only on a breaking change, and consumers ignore keys
they do not know. The practical bonus is that this closes the question **without
touching the library**, which matters while another agent is working in it. A
consumer who serialises `report()` directly has built their own artifact and
owns its versioning.

**Run metadata: yes — tool name and version.** Reproducibility is the stated
reason `raw` exists, and without a version a finding that vanished between two
archived reports is ambiguous: the site was fixed, or a rule changed. It is the
cheapest field in the document.

**Several results travel as a list, never a URL-keyed map.** Keying by URL was
already rejected in CLAUDE.md and is independently wrong here: `--all-hops`
makes one target yield several results, and the same URL can legitimately be
scanned twice in one run.

### `--all-hops`, specified though reserved

With `--all-hops`, each analysed hop is its own result. For
`http://example.com` → 301 → `https://example.com` → 302 →
`https://www.example.com` (200):

```json
"results": [
  {"outcome": "ok", "target": "example.com",
   "source": {"kind": "live", "url": "http://example.com/",
              "status": 301, "reason": "Moved Permanently", "hops": ["...chain..."]},
   "report": {"response": {}}},

  {"outcome": "ok", "target": "example.com",
   "source": {"kind": "live", "url": "https://example.com/",
              "status": 302, "reason": "Found", "hops": ["...same chain..."]},
   "report": {"response": {}}},

  {"outcome": "ok", "target": "example.com",
   "source": {"kind": "live", "url": "https://www.example.com/",
              "status": 200, "reason": "OK", "hops": ["...same chain..."]},
   "report": {"response": {}}}
]
```

Four things that are load-bearing:

- **`target` is identical on all three** — it is the string the user typed, and
  it is the grouping key. The per-hop URL is `source.url`.
- **`hops` repeats identically on every result, and the redundancy is required.**
  NDJSON is reserved, and an NDJSON line that needs a sibling line to be
  understood is a broken format. Self-containment is the constraint; a
  three-entry chain is a rounding error beside a findings list.
- **`secure` and `host` are derived per hop, not per target.** The first result
  is analysed with `secure=False`, so HSTS findings are correctly suppressed on
  the plaintext leg; the last with `host="www.example.com"`, a different preload
  lookup than `example.com`. An implementation that took the scheme from the
  typed target and applied it to every hop would be wrong in both directions.
  Neither key appears in the document, because `source.url` carries both.
- **No `final: true` marker.** Considered and dropped: ordering is already
  contractual, and in the default case there is one result per target, so the
  key would be dead weight on the common path. Last-per-`target` is a two-line
  groupby.

### Deliberately absent

**The command line.** Tempting for provenance, and it carries `-H 'Authorization:
Bearer …'` and `--proxy http://user:pass@…`. Redacting means pattern-guessing at
secrets, which is the class of guess this codebase rejects — see the critique of
`securityheaders`' `'session' in name`. The precise provenance record already
exists: `--raw` gives the actual request head with an explicit credential
warning attached. One documented footgun beats two, one of them fuzzy. The same
argument covers `-X`, `-H` and `--user-agent`, all of which change what comes
back and none of which is recorded outside `--raw`.

**Any record of `--min-level`,** because it filters the terminal only.

## Failure classification

"Retryable" is not observable — it is a prediction. The failure's *kind* is
observable, and it is what a calling tool needs in order to make the prediction
itself.

| Kind | Raised by |
|---|---|
| `dns` | `socket.gaierror` |
| `refused` | `ConnectionRefusedError` |
| `timeout` | `TimeoutError`, `socket.timeout` |
| `reset` | `ConnectionResetError`, `http.client.RemoteDisconnected` |
| `tls` | `ssl.SSLCertVerificationError` and other `ssl.SSLError` |
| `protocol` | malformed status line, `http.client` parse errors |
| `other` | anything else |

One exception-to-tag mapping, no flag surface, and it turns *"4840 targets
failed"* into *"800 dns, 40 timeout"*, which is a different conclusion. It is
also the input a future `--retry N` would consult.

Two related notes:

**A WAF ban is not an operational failure.** A Cloudflare 403 is a successful
fetch and gets analysed, correctly. The real risk is subtler — the headers
analysed are the WAF's, not the application's — and the tool deliberately does
**not** try to detect that. Sniffing for interstitials means heuristics like
`'cloudflare' in server`, which is the guess this codebase refuses. Instead the
status and final URL are shown prominently enough that a human reading `403`
draws their own conclusion.

**One retry signal is factual rather than predicted.** `429` and `503` with
`Retry-After` are *specified* as retry-later, so echoing that on stderr guesses
nothing. That covers the honest half of the rate-limit case.

## The input seam

No registry, no ABC, no entry points in v1. What is fixed now is **what crosses
the boundary**, because a wrong payload shape is the refactor and a missing
registry is a few lines whenever the second source lands.

Every named future format — Burp XML, HAR, SAZ, WCAT — is a **multi-exchange
container carrying both request and response**. Two consequences, both free now:

- **A source yields an iterable**, never a single item. One live target yields a
  one-element iterable. If the fetcher returned a bare result and the HAR reader
  returned a list, there would be two shapes to unify badly.
- **An exchange carries both heads plus the facts only the source knows** — the
  final URL, and from it `secure` and `host`. Those are exactly the three
  arguments `report()` cannot derive, and exactly what all four formats can
  supply.

Matching the analyser's style — `collections.namedtuple`, not dataclasses:

```python
Hop = namedtuple(
    "Hop", "origin code destination followed refused", defaults=(True, None)
)

Exchange = namedtuple(
    "Exchange",
    "kind target url status reason headers hops raw_response raw_request",
    defaults=((), None, None),
)

Failure = namedtuple("Failure", "target kind message")
```

A source yields `Exchange` or `Failure` items. `Failure` is yielded rather than
raised so that one unreadable HAR entry does not abandon the rest of the file;
for the live source, a target produces one or the other.

`headers` is the mapping from `parse_headers()`, so the seam speaks the
library's vocabulary and `commands.py` does no translation.

`Hop` deliberately does **not** use the wire names: a hop serialises to
`{"from": ..., "to": ...}`, which reads best in JSON, but `from` is a Python
keyword and cannot be a field. `origin`/`destination` in code, `from`/`to` in
the document, mapped in `run.py` — and `destination` rather than `target`
because `Exchange.target` already means the string the user typed, and one word
meaning two things in adjacent structures is how a bug gets written.

**One constraint recorded for later:** `urllib` normalises what it sends and
cannot emit a malformed request. Active tests eventually need to — duplicate
headers, odd methods, a forged `Origin`. That does not justify an abstraction
today, since the second client cannot be named, but it is why `live.py` is one
module behind a narrow function: swapping it should be a file, not surgery.

## Terminal output

Unchanged in spirit from `scan.py`: a block per result with a status line, the
redirect chain, findings, then inventories unless `-q`. Four additions.

- **The scope line prints before the first request**, derived or explicit, and
  it goes to **stderr**. It is the one piece of output that appears whether or
  not anything is found, and it is what makes the guard auditable rather than
  mysterious — which is exactly why it cannot be gated on the terminal report.
  *Corrected 2026-08-21 during implementation:* it was first written to stdout
  behind the same `show` gate as the report, so `-j` printed no scope line at
  all — the one mode where nothing else records the guard, since the run
  document deliberately carries no scope. This section's own rule settles it:
  diagnostics go to stderr.
- Refused hops print with their reason.
- A run of more than one target ends with a summary: counts by level, and
  failures by kind. About ten lines, and it is the bulk-sweep affordance.
- The missing-`hstspreload` note stays on stderr.

Only the report goes to stdout; diagnostics, the preload note and per-target
failures all go to stderr. A per-target failure prints, the run continues, and
the operational-failure flag is remembered for the exit code.

## Testing

No test touches the network, with one deliberate exception.

**The exception, added 2026-08-21:** the redirect-limit test binds a loopback
`http.server.HTTPServer` on `("127.0.0.1", 0)` — ephemeral port, daemon thread,
torn down in a `finally`. It is hermetic: no external traffic, no DNS, no
dependency on the internet. It exists because `_Chain` has to override urllib's
own `max_redirections` (10) and `max_repeats` (4), and that interaction lives in
urllib's redirect bookkeeping rather than in our handler, so a unit test on
`redirect_request()` cannot see it. Do not use a loopback server for anything
else.

- **`main(argv)` returns an int and does not call `sys.exit`** (argparse aside),
  so the whole CLI is testable in-process.
- **`live.py` is the only module that fetches**, behind one function, so every
  other test injects a fake source yielding `Exchange` items.
- **The run document is plain data**, so it gets golden-file tests in the style
  of `tests/rendered_messages.txt`, including a case with a refused hop and one
  with a failure.
- **Terminal rendering gets a snapshot** for the same reason the message catalog
  does: it is prose that nothing else reads, so an accidental edit changes what
  a user sees while every other test stays green.
- **Table-driven unit tests** for the two pure predicates that will otherwise
  rot: `-o` resolution (including `C:\out.json`, `report.json`, `json:-`, `-`,
  and a reserved format) and scope matching (apex vs `*.` at several depths,
  case folding, the derived default, the target-always-in-scope exception, and
  `example.co.uk` → `evil.co.uk` **refused under the derived default**, which
  is the behaviour DECISION R-1 relies on).
- **Exit codes get a case each**, including the 3-beats-1 precedence.
- **One structural test**: nothing outside `cli/` imports `cli`.
- **Mutation-test the scope predicate and the `-o` resolver** before calling
  them done, per the project's standing practice. A test that passes both ways
  is worse than none.

## Handed to the analyser

Not a CLI change, recorded here because the CLI is what makes it cost something.

Run against an ordinary 301 head (`Location`, `Server`, `Content-Length: 0`,
`Strict-Transport-Security`), on 2026-08-21 at 357 tests passing:

```
findings on a bare 301: 7
  warning  Content-Security-Policy        csp-missing
  warning  Cross-Origin-Opener-Policy     coop-missing
  warning  Cross-Origin-Resource-Policy   corp-missing
  warning  Referrer-Policy                rp-missing
  warning  X-Content-Type-Options         xcto-missing
  warning  X-Frame-Options                xfo-missing
  note     Permissions-Policy             pp-missing
```

Six warnings on a response carrying no representation for any of them to
protect. That is principle 4, and under `--all-hops` it fires once per redirect
hop.

The cause is structural and already known: `analyze_all` sees no status line,
which is the reason CLAUDE.md gives for not reporting an absent `Content-Type`
("a 204 or 304 carries no representation"). The same argument extends to
`-missing` findings on any 3xx.

Note HSTS is *absent* from that list and should be — on the https legs of a
chain, a redirect is precisely where HSTS matters. So per-hop analysis is
genuinely valuable; it is the representation-scoped headers that misfire.

### A code-to-header table

`explain` wants to say which header a code belongs to and has no way to ask.
CLAUDE.md already states the invariant — *"a code belongs to exactly one
header"*, `duplicate-headers` excepted — and a test pins it, but the mapping
exists only inside that test, reconstructed by running the corpus.

A public `CODE_HEADER` dict would make `explain` complete, and it has a second
consumer waiting: SARIF's `rules[]` wants a rule's owning component, and the
reserved machine output for `explain` is the cheapest route to the SARIF
writer. It would also let the existing invariant test assert against a declared
table rather than a derived one, which is the stronger form of that test —
today the test can only prove the corpus is self-consistent, not that the
package agrees with it.

Not attempted here: it is an analyser change, and this document changes no
analyser module.

**This is why `--all-hops` is reserved rather than shipped.** It becomes a small
follow-up once the analyser can see the status — most naturally as part of the
TODO item *"change api to expect full request/response pairs first"*, which
brings the status line along with everything else. The CLI must not paper over
it by filtering findings itself: which findings apply to which response is
analysis policy, and it belongs on the other side of the boundary.

## What is not being done

- **No plugin discovery.** No entry points, no ABC, no registry until the second
  source exists. The payload shape is the commitment; the machinery is a few
  lines later.
- **No PSL, vendored or depended on.** DECISION R-1.
- **No automatic retry.** Classification only. Repeat traffic at an engagement
  target should be something you asked for, and the kinds are in the output so a
  calling tool can decide.
- **No WAF or interstitial detection.** Heuristic, and this project does not
  guess.
- **No scope exclusions (`!blog.example.com`) in v1.** The obvious next ask,
  and deliberately deferred: it is one more syntax rule, and `--scope
  example.com` already spells the coarse version of "the apex but not the
  subdomains". Reserved.
- **No request-body support (`-d`/`--data`) in v1.** It drags in content-type
  handling for a case that is rare when analysing response headers. Reserved.
- **No `--all-hops` in v1.** See *Handed to the analyser*.
- **No changes to any analyser module, to the library's document shape, or to
  CLAUDE.md** in the work this document specifies. CLAUDE.md's *"Library only —
  there is deliberately no CLI"* will need revising once this lands, but that
  edit waits until the concurrent analyser work is finished.
