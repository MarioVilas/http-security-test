# SARIF output

2026-09-10. Status: design agreed, not implemented.

A third output format for `hst scan`, promoted from `writers.RESERVED`. It is a
projection of the run document onto SARIF 2.1.0 and adds no analysis. One
enabling change comes first (`--raw` stops deciding what the document records),
and one field joins the run envelope (`source.method`).

Everything here was checked against the OASIS schema and the specification
text, both fetched during the design; every section number below is from
SARIF 2.1.0 errata01. Where the two disagree with what this project assumed,
the specification wins and the assumption is recorded as corrected.

## What lands

- **`cli/sarif.py`** — `log(document) -> dict`, a pure function over the run
  document, rendered by a new writer in `writers.py`.
- **`sarif` promoted out of `RESERVED`** into `FORMATS`, after `json`, so
  `-oA` writes `.txt`, `.json`, `.sarif` in that order.
- **Capture decoupled from emission** — `cli/live.py` always builds the raw
  heads; `--raw` decides only whether a writer emits them. This is what makes
  the header projection available without `--raw`, and it makes the
  implementation agree with the flag's own help text ("include the base64 raw
  blobs").
- **`source.method`** on the run envelope, so a SARIF `webRequest` can say
  which method was used.

## What does not, and why

- **No rule prose.** `shortDescription`, `fullDescription` and `help` stay
  absent on all rules. The long-form descriptions parked in
  `2026-08-23-consequences-and-references.md` were parked "to land with the
  SARIF writer", and that pairing is dissolved here: they are rule-level,
  value-free prose, while `result.message.text` is per-finding and needs the
  values, so nothing about writing them later constrains what ships now. The
  parked item is re-scoped as its own catalog task.
- **No `messageStrings` / `arguments`.** See *Rejected alternatives*.
- **No spec-native taxonomies.** CWE and CAPEC identifiers travel as
  `properties.tags`.
- **No `partialFingerprints`.** See *Rejected alternatives*.
- **No inventories.** The SARIF file carries findings and wire provenance; the
  `json` writer stays the complete record, and `-oA` writes both. A
  *placement* decision rather than a rejection — see *Forward compatibility*
  for the two routes that stay open.
- **No `result.kind`.** It would erase the rating — see *The kind trap*.
- **No GitHub-shaped locations.** No result claims a file that was never
  analysed.

## Verified specification facts

These are the load-bearing ones. Each was checked rather than recalled, and
three of them contradicted an assumption this project held.

- **`result` requires only `message`** (§3.27.11). `locations` is optional, so
  a header finding with no file does not have to invent one.
- **SARIF placeholders are positional** (§3.11.5): `placeholder = "{", index, "}"`,
  zero-based into `message.arguments`, and literal braces must be doubled. This
  package's templates are `str.format` *named* fields, so CLAUDE.md's claim that
  they are "SARIF's `messageStrings` + `arguments` in all but name" is true
  structurally and **false literally**. The claim is worth keeping; the word "literally" is not.
- **`message.arguments` is `items: {type: string}`.** A list-valued field
  (`{"directives": ["script-src", "style-src"]}`) can only cross as a joined
  string, which a consumer must then guess apart — the `HTTPHeaderDict`
  comma-join hazard, in a format we control. `propertyBag` is
  `additionalProperties: true`, so `data` crosses it structurally unchanged.
  **`arguments` is a display channel, not a data channel.**
- **`rules[]` is a catalog, not a log** (§3.19.23): each descriptor describes a
  rule "supported by the tool component", and ids need not be unique. Emitting
  every code every run is the spec's own reading.
- **`webRequest` / `webResponse` exist** with `protocol`, `version`, `target`,
  `method`, `statusCode`, `reasonPhrase`, `headers`, and are cacheable at
  `run.webRequests` / `run.webResponses` with `index` references.
- **`webRequest.headers` and `webResponse.headers` are
  `{"type": "object", "additionalProperties": {"type": "string"}}`** — one
  string per name. See *The header projection*.
- **`run.timestamp()` is already conformant.** The date-time grammar makes
  fractional seconds optional, and `2016-02-08T16:08:25Z` is one of the
  spec's own examples.

### The kind trap

`level` is where this project's ratings came from, but `kind` is a **different
field asking a different question**, and the two are not parallel
vocabularies:

- `kind` — what happened when the rule was evaluated: `fail`, `pass`, `open`,
  `review`, `notApplicable`, `informational`.
- `level` — how severe the problem found is: `error`, `warning`, `note`,
  `none`.

They interlock. §3.27.9: if `level` is anything but `"none"` and `kind` is
present, `kind` "SHALL have the value `"fail"`". §3.27.10: if `kind` is
anything but `"fail"`, `level` "SHALL have the value `"none"`". So
`kind: "informational"` is not a synonym for `level: "note"` -- it is
mutually exclusive with carrying a level at all, and choosing it erases the
rating.

The temptation is real rather than silly, because the glosses cut across
principle 3. SARIF's `informational` is "a purely informational result that
does not indicate the presence of a problem", which is almost word for word
principle 3's "a fact with no defect", while SARIF's `note` is "a minor
problem **or an opportunity to improve the code**". Two things decide it
anyway:

- That escape clause. "An opportunity to improve" covers most of what this
  package rates `note` -- `pp-missing`, `cookie-no-samesite`,
  `xdpc-nonstandard`, whose improvement is removal -- so `note` is the
  intended use and not a distortion.
- **Two artifacts from one run would contradict each other.** The `json` file
  publishes `level: "note"` for a finding; SARIF would publish `level: "none"`
  for the same one, and a CI consumer reading SARIF levels would see nothing
  found while `hst` exited 1 under `--fail-on note`.

**`kind` stays absent everywhere** (it defaults to `fail`) and `level` carries
the published vocabulary. Emitting `informational` for *some* note codes is
worse still: sorting the 45 into facts and minor problems is a new per-code
axis, and this package already has a name for that shape -- the parked hygiene
axis -- which does not get invented inside an output writer.

The deeper reason to leave it alone: SARIF splits "is this a problem" from
"how bad is it" across two fields, while this package's three levels merge
both into one. Adopting a vocabulary is not adopting the model behind it.

### Forward compatibility: the kind axis stays available

v1 never emits `kind`, so every result is a `fail` carrying a real level. That
is a starting point and not a rejection of the two-variable model, because at
least four plausible features want it, and each wants a *different* kind:

- **`informational`** (with `level: "none"`) — the inventories as results,
  which would make the SARIF file a superset of the `json` document instead of
  a subset, and is therefore the one route to SARIF-to-`json` conversion. The
  other open route is the cached `webResponse` property bag, left empty here.
  "Interesting" headers, if they ever land, are the same feature wearing a
  moustache: they belong to an inventory, not to a finding of their own.
- **`pass`** — "evaluated, and no problem was found": a header that is
  *correctly* configured. More precise than `informational` for that case, and
  it needs no new rule ids, since it pairs with the existing codes
  (`hsts-missing` evaluated, and passed).
- **`notApplicable`** — "not evaluated, because it does not apply to the
  analysis target". This is what the suppressions already compute and then
  throw away: HSTS on a plaintext target (principle 2), a header a sibling has
  made moot (principle 6), a coverage code excused by
  `REPRESENTATION_HEADERS` on a bare redirect. No output records *why* a
  finding did not fire.
- **`open`** — "insufficient information to decide whether a problem exists",
  which is the passive-CORS ruling almost verbatim: origin reflection cannot be
  decided from one exchange.

Two cheap rules keep the door open:

- **The rules array is a floor** (above). A test asserting
  `len(rules) == len(FINDING_SEVERITY)` would encode an exhaustiveness claim
  nobody meant; assert containment instead.
- **Nothing in v1 keys off "every result is a problem."** Level filtering,
  index references and the header projection are all indifferent to `kind`,
  and `--fail-on` reads the run envelope rather than the SARIF file, so a
  later `level: "none"` result cannot desync the exit code from what the file
  says.

## Task 1: capture stops depending on an output flag

`cli/live.py` builds the raw heads only `if options.raw`, which lets an output
flag decide what the *document* knows rather than what a file contains. Three
facts make the change safe and worth doing on its own merits:

- `--raw`'s help already says "**include** the base64 raw blobs". The
  implementation is what disagrees with the documented contract.
- **Nothing in the analysis path reads `Response.raw`.** (`adaptors.py` reads
  *requests'* unrelated `.raw`; `cookies.py` reads a cookie's own raw string.)
  So unconditional capture cannot move a finding. `live.py` already asserts
  the same principle in a comment: re-parsing the blob "would let `--raw`
  change the analysis".
- `text.py` renders no blobs at all, so the filter surface is two writers.

Therefore: `live.py` always captures, and `writers.write(name, document, stream, blobs=True)` gains the policy, honoured by `json` and `sarif`.
The filter must live **in** the writers rather than before them, because the
SARIF header projection is derived from a head it then does not emit.

Costs, both accepted: roughly 1-4 KB per target held in memory on bulk sweeps,
and request-side headers become visible by default through the projection.
Response-side already are — measured, with no blob present at all, the
`cookies` inventory carries a session cookie's `value` and its full `raw`
`Set-Cookie` string. Consistent with the standing position that this is a
pentester's tool that does not redact and that `--raw` is a size control.

## The document mapping

`$schema` is the OASIS URL for this exact revision, `version` is `"2.1.0"`,
and one invocation produces one `runs[0]`. The canonical OASIS URL is
preferred over a schemastore mirror on the permanence criterion
`references.py` already applies: OASIS keeps published documents.

### Driver and rules

```json
{"tool": {"driver": {
   "name": "http-security-test", "version": "...", "semanticVersion": "...",
   "informationUri": "https://github.com/MarioVilas/http-security-test",
   "rules": [
     {"id": "csp-unsafe-inline",
      "defaultConfiguration": {"level": "error"},
      "helpUri": "https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Content-Security-Policy",
      "properties": {"tags": ["external/cwe/cwe-079", "external/capec/capec-063"],
                     "header": "Content-Security-Policy",
                     "consequences": ["xss"]}},
     {"id": "cookie-no-secure", "defaultConfiguration": {"level": "note"},
      "properties": {"tags": ["external/cwe/cwe-614"], "header": "Set-Cookie",
                     "consequences": ["mitm"], "escalatable": true}}],
   "notifications": [{"id": "dns"}, {"id": "refused"}, {"id": "timeout"},
                     {"id": "reset"}, {"id": "tls"}, {"id": "protocol"},
                     {"id": "other"}]}}}
```

Every code in `FINDING_SEVERITY`, in `sorted()` order — the order `explain`
with no arguments prints. **Counts are derived, never written down**: the
table held 118 codes when this design started and 119 by the time it was
finished.

That is a **floor, not an inventory of the array**: every finding code appears,
and the array is not promised to contain only finding codes. See *Forward
compatibility*.

- `helpUri` from `references.header_url(CODE_HEADER[code])`, absent where the
  header does not resolve. Absent beats empty.
- `properties.tags` in the recognisable `external/cwe/cwe-079` form (padded to
  three digits, so `external/cwe/cwe-1021` for the long ones), with
  `external/capec/capec-063` extending the same shape. **The only claim in this
  document not checked against a primary source**: the padding follows a
  convention attributed to CodeQL-produced SARIF, and no such file was read.
  Confirm it against a real one before implementing, or drop the padding --
  nothing in SARIF requires either form. An external
  identifier's value is that another tool can match it, which is what earns
  the convention over the spec's taxonomy machinery.
- `properties.escalatable` for `ESCALATABLE` codes, because
  `defaultConfiguration.level` cannot express "a floor, not a verdict", and a
  consumer recomputing from the default would read every laddered cookie
  finding a rung too quiet.
- `notifications[]` declares the seven `FAILURE_KINDS` so a failed target's
  notification carries a resolvable `descriptor`. No authored prose: a
  notification's `message.text` is the failure string urllib produced.

`invocations[0]` carries `startTimeUtc`, `endTimeUtc`, `executionSuccessful`
(false when any target failed) and `toolExecutionNotifications`. **No
`exitCode`**: it is computed after the writers run, and `executionSuccessful`
carries the fact that matters.

### Results

```json
{"ruleId": "csp-unsafe-inline", "ruleIndex": 17, "level": "error",
 "message": {"text": "Content-Security-Policy: present but allows unsafe-inline in script-src, style-src, defeating most of ..."},
 "analysisTarget": {"uri": "https://example.com"},
 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://www.example.com/"}}}],
 "webRequest": {"index": 0}, "webResponse": {"index": 0},
 "properties": {"header": "Content-Security-Policy",
                "data": {"directives": ["script-src", "style-src"]},
                "consequences": ["xss"]}}
```

One result per finding per target. `level` is the finding's own level as the
envelope already denormalised it, so an escalated finding keeps its rung.

`message.text` is `describe()`'s sentence with the header as its subject,
because `describe()` returns a *continuation* ("present but allows...") that
the terminal renders beside a header column and SARIF has no column for. The
subject is the finding's own `header` field, matching `text.py` — and correct
for `duplicate-headers`, where `CODE_HEADER` is `None` and the finding's
lowercased name is what actually repeated.

`analysisTarget` is the target as given; `locations[0]` is the final URL after
redirects. That is the distinction those two fields are defined for, and it
lets one result record both what was asked for and what answered.

`ruleIndex` beside `ruleId` is redundancy the spec allows and worth paying: an
array index instead of a scan of 119 descriptors, with the id keeping the file
readable by hand.

### Provenance, cached once per target

```json
"webRequests":  [{"target": "https://www.example.com/", "method": "GET",
                  "properties": {"kind": "live",
                                 "hops": [{"from": "...", "code": 301, "to": "...", "followed": true}],
                                 "raw": "<base64>", "fidelity": "reconstructed"}}],
"webResponses": [{"statusCode": 200, "reasonPhrase": "OK",
                  "headers": {"Content-Security-Policy": "default-src 'self', script-src 'none'",
                              "Set-Cookie": "sessionid=...", "Set-Cookie [2]": "lang=en"},
                  "properties": {"raw": "<base64>", "fidelity": "reconstructed"}}]
```

The run-level caches exist for exactly this: the redirect chain and `source.kind`
are facts about one fetch, so they are stored once and referenced by index,
rather than repeated on every finding as the run envelope deliberately does for
NDJSON's sake. `raw` and `fidelity` appear only under `--raw`.

`protocol` and `version` are omitted: the document does not carry the HTTP
version, urllib only ever reports 1.0 or 1.1, and `raw` already carries the
status line.

### The header projection

The spec field cannot represent a repeated header — one string per name — and
that is a defect in the format, not in the response. The format inherited a
library's lossy header model (`dict`, `NameValueCollection`) rather than the
wire's, which is the same inheritance `adaptors.from_requests()` refuses. Two
independent signs it was never used: the specification contains **zero
examples** populating `headers` across 36 mentions of `webResponse` (checked),
and existing producers are reported to clobber duplicates (not verified here).

So the field is treated as **a projection for consumers, never a record**.
It is emitted on **every** run, because task 1 makes the head always available;
the base64 blobs beside it remain gated on `--raw`. The two are separate axes:
`--raw` decides whether the bytes are in the file, the rule below decides how
the map is shaped.

The rule is one line of HTTP:

> **Fold every repeated header with `", "`; `[n]`-suffix `Set-Cookie` alone.**

RFC 9110 §5.2 defines a repeated field's combined value as exactly that
comma-concatenation, and §5.3 lets a recipient fold "without changing the
semantics of the message" ("For consistency, use comma SP"). The grammar
restriction in §5.3 binds *senders*, not recipients — conflating the two was
an error made and corrected during this design. §5.3's own Note names
`Set-Cookie` as the exception recipients must special-case, and it is the only
one: `path-value` admits a comma (RFC 6265 §4.1.1), so rewriting `Expires` into
`Max-Age` would not make folding safe, and would change the bytes
`cookie-oversized`, `cookie-control-character` and `cookie-persistent` are
computed from. `Set-Cookie2` folds — RFC 2965 quotes its attribute values and
has no unquoted dates, which is why Chromium omits it from
`IsNonCoalescingHeader()`.

The suffix separator is a space and brackets rather than `#`, because
`field-name = token` and `tchar` **includes** `#` (RFC 9110 §5.6.2): a
`Set-Cookie#2` key is a syntactically valid field name and therefore ambiguous
with a real header, while `Set-Cookie [2]` cannot collide with anything legal.
The first occurrence keeps the plain name so a naive `headers["Set-Cookie"]`
returns a true value rather than nothing.

Folding CSP is provably faithful **as of `3ef0eda`** and was not before it:
`split_policies()` now reads a value as the `serialized-policy-list` CSP3
defines, so two policies on two lines and the same two folded onto one line
produce identical findings — including the awkward case of a comma inside a
`report-uri`, where a browser splits the unfolded header identically.

## What has no home, and why that is fine

| envelope content                                                 | destination | reason                                                                                             |
| ---------------------------------------------------------------- | ----------- | -------------------------------------------------------------------------------------------------- |
| `references`                                                     | omitted     | reconstructible: `headers` from per-rule `helpUri`, `taxonomy` from per-rule tags                  |
| `inventory`                                                      | omitted     | SARIF is the findings interchange; `json` is the complete record and `-oA` writes both             |
| envelope `schema: 1`                                             | omitted     | `tool.driver.version` versions the producer; a SARIF file is its own artifact with its own version |
| `artifacts[]`, `columnKind`, `taxonomies[]`, `automationDetails` | omitted     | no files, no regions, tags chosen over taxonomies, no automation identity to claim                 |

## Testing

1. **SARIF snapshot** — `tests/cli_sarif_snapshot.json`, the device
   `cli_terminal_snapshot.txt` already uses, regenerated deliberately behind an
   environment variable so the diff gets read.
2. **Cross-process determinism** — the same document rendered under two
   `PYTHONHASHSEED` values, byte-equal. Measured during design: the existing
   `json` writer is already stable across five seeds, because sets are used
   internally and always `sorted()` on the way out. Unlike an in-process double
   render, this test can actually fail.
3. **Header round-trip** — decode the projection back to pairs and assert it
   reproduces the original header list, duplicates and order intact. This is
   what makes "lossless" a claim rather than an intention.
4. **All-formats blob-leak guard** — every registered format rendered with
   `blobs=False`, asserting the base64 appears in none. Covers `ndjson` the day
   it lands.
5. **Byte-identical `json` without `--raw`** — the regression guard for task 1.
6. `tests/test_cli_writers.py` inverts in three places: the reserved-format
   parametrization, the comment predicting this promotion, and the `-oA`
   assertion that no `.sarif` path appears.

Mutation-check 3 and 4 per the working practice: break the suffixing, confirm
the round-trip fails, restore from a scratch copy rather than from git.

No schema validation in the suite. Structural assertions test what was
decided; validating against a vendored 112 KB schema would test what the
format permits, at the cost of a test-only dependency and vendored data.

## Rejected alternatives

- **Positional `messageStrings` + `arguments`.** Mechanically feasible — parse
  field names in first-appearance order, rewrite to indices, take values from
  `_DISPLAY[code](data)` — and rejected because it buys nothing: both forms
  render the same sentence, `arguments` is strings-only so it is *lossier* than
  the `data` beside it, and the only consumer that would benefit is a
  localiser that does not exist. It would also need a new catalog API returning
  a template rather than a finished sentence. Note the index bookkeeping is a
  live trap: the header occupies argument 0, so template fields start at 1, and
  getting it wrong silently renumbers every placeholder.
- **Spec-native taxonomies** (`taxonomies[]` + `taxa[]` + `relationships[]`).
  A taxonomy is a whole `toolComponent` wanting a version, a release date, a
  GUID and one descriptor per CWE carrying MITRE's own wording — curated prose
  that ages, and identity we would be inventing. It also mixes two different
  things: the consequence slug is the vocabulary and a taxonomy id is an
  attribute of it, never a peer.
- **Consequence slugs as a tool-defined taxonomy.** Same error in the other
  direction. A slug selects prose; it is not a classification for export. It
  travels in `rule.properties.consequences`.
- **`partialFingerprints`.** Cross-run diffing is already served by
  re-analysing an archived `raw` blob, nothing being targeted consumes them,
  and the data they would hash is not uniformly stable — `csp-nonce-weak`
  carries the nonce itself, which changes every response. Additive later if a
  consumer ever wants them.
- **A `headers` map with duplicate JSON keys.** RFC 8259 says names SHOULD be
  unique; Python's `json` silently keeps the last, and the Microsoft SARIF SDK
  is *reported* to throw (not verified here). The one option that can cost a
  consumer the findings as well as the headers.
- **Emitting `headers` only when no header repeats.** Never lies, but two or
  more `Set-Cookie` is the ordinary state of a real site, so the field would be
  absent from most files — poor coverage for a field whose only purpose is
  best effort.
- **Growing the envelope with a full header pair list.** Would make the
  projection complete independently of capture, but duplicates the blob's
  content in parsed form and grows every `json` file for every user. Task 1
  achieves the same end without new schema.

## Closed during this design

The question "can N headers become one?" surfaced a defect unrelated to
output: `hst` read a legal comma-separated policy list as one malformed
policy, producing an `error`-rated `csp-invalid-keyword` on Google's real
`forms.gle` header and on Pinterest across ~15 ccTLDs — 65 of the CSP-carrying
domains in OWASP's corpus, 0.15%. Principle 4's exact failure mode. **Fixed
independently in `3ef0eda`**, which is also what makes the CSP fold above
faithful. Recorded here because the route to it is reusable: implementing an
external format is a cheap audit, since the format's field list is an
independent opinion about what a scan record should contain.
