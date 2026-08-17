# Two additions: reporting-group cross-checks and non-origin ACAO

Design notes for the two items accepted from the 2026-08-16 source review.

**Revision 2, 2026-08-17.** All four decisions are now answered — see the
**RESOLVED** notes on each. A Chromium checkout arrived overnight and every
ground-truth claim below has been re-verified against a third engine; two
details changed and one conclusion reversed, all marked *Chromium* in place.

**Revision 3, 2026-08-17.** W3C spec extracts (`/home/crapula/ref/w3c/webref`,
`browser-specs`) arrived and settled three things this document had reasoned
about from implementations alone. Five changes since revision 2:

- **A false positive was found and fixed.** `Report-To` — the Reporting API's
  older spelling — also defines groups, and **both engines still honour it**
  (Chromium `net/reporting/reporting_service.cc:250`, Firefox
  `dom/reporting/ReportingHeader.cpp:211`). Reading only `Reporting-Endpoints`
  meant a response defining its groups the old way was told they were
  undefined. That is not a hypothetical shape: in cloaked.pl's 2021 survey
  `Report-To` appears 50 times and `Reporting-Endpoints` not once.
- **The undeliverable-endpoint defect moved to the header that defines it.**
  One bad endpoint URL is one fact however many policies name the group, so it
  is a finding on `Reporting-Endpoints`, not on each of up to four referencing
  headers. `_reporting_endpoint_names()` is therefore purely syntactic again —
  the reverse of DECISION A-1's original resolution, for a better reason.
- **The whole reporting family is rated `note`.** A report that is never
  collected costs the operator information, not protection, and gives an
  attacker no way to reach the site or its users. This re-rates
  `ip-endpoints-undefined` from `warning`, which is a change to settled
  behaviour.
- **The "policy applies nothing" gate** now covers all four headers, including
  `Integrity-Policy`, whose sentence claimed violations were "caught and never
  delivered" for a policy that can catch none.
- **`REPORTING_HEADERS` landed** as designed at the end of this document.

Totals at revision 3: 35 error / 26 warning / 31 note, 315 tests.

**Revision 4, 2026-08-17.** The scope line for reporting was drawn where it
belongs: *whether an endpoint answers* is an active question and waits for the
probe work, but *whether the definition is well formed* is answerable from the
response and is now checked — for both definers, because deprecated is not
unhonoured.

- **`Report-To` is analysed, not merely read.** It gets the same three
  judgements `Reporting-Endpoints` has: `rt-invalid` (the value is not the JSON
  the header is defined as carrying), `rt-ineffective` (plaintext response),
  and `rt-endpoint-undeliverable` (a URL browsers will not deliver to, checked
  with the same predicate because Chromium runs Report-To's endpoints through
  the very same `ProcessEndpointURLString`).
- **`re-invalid`** covers the case this document previously left open as "low
  priority". Structured field dictionary keys are lower-case by grammar
  (RFC 9651 §3.2), and **both engines drop the entire header** when the
  dictionary will not parse — Firefox `SFV::ParseDict(...); if
  (!dict.IsValid()) return 0;`, Chromium `ParseDictionary` returning `nullopt`.
  So `CSP-EP="https://…"` costs every group the header meant to define, and the
  policies naming those groups are not blamed for it.
- **Both definers are inventoried and neither is ever reported missing**, so
  `REPORTING_HEADERS` is now `("Report-To", "Reporting-Endpoints")`.

Totals: **35 error / 26 warning / 35 note** over 96 codes, 324 tests, 153 test
functions. `ruff check` clean; every guard added in this revision was
mutation-verified, including one that would silently drop `Report-To` back out
of the inventory.

**Items A and B are implemented.** At revision 2 that was 299 tests passing;
see the revision 3 note above for the current figures. `ruff check` is clean, and
every new guard was mutation-verified — three mutations survived the first pass
and each exposed a genuinely untested branch (`_item_parameter` reading any
parameter rather than `report-to`, the 127.0.0.0/8 half of the loopback rule,
and the CSP any-policy loop), so three tests were added and all three mutations
then died. A behavioural-equivalence run over 1344 generated responses changed
1008 verdicts and **removed or altered nothing**: every difference is purely one
of the four new codes being added.

Four codes landed — `acao-invalid-origin` (`error`), and
`csp-report-to-undefined` / `coop-report-to-undefined` /
`coep-report-to-undefined` (`warning`). Totals moved from 34/27/25 to
**35 error / 30 warning / 25 note**. The only thing still open is the
inventory mechanism at the end of this document.

Status of the six items that came out of that review:

| # | Item | Disposition |
|---|---|---|
| 1 | `Reporting-Endpoints` cross-check for CSP / COOP / COEP | **accepted** — item A below |
| 2 | Endpoint URL the browser discards | **folded into A** — see DECISION A-1; it is not a separate feature |
| 3 | `Access-Control-Allow-Origin` that is not a serialized origin | **accepted** — item B below |
| 4 | `Connection` naming an end-to-end header | dropped |
| 5 | `Document-Isolation-Policy` | parked — item C below, and Chromium changed *why* |
| 6 | `Origin-Agent-Cluster`, `Report-To` | dropped (not security) |

---

## Item A — a reporting group nothing defines

### What already exists

`response.py` has exactly this rule for one header. `_analyze_ip_reporting()`
reads `Integrity-Policy`, pulls its `endpoints` directive, and compares the
group names against those defined by `Reporting-Endpoints`; any name that is
not defined produces `ip-endpoints-undefined`, rated `warning`. The lookup
helper is `_reporting_endpoint_names()`.

The docstring already states the rationale in general terms:

> The endpoints directive carries group names, not URLs; the URLs live in a
> Reporting-Endpoints header. Name a group that header does not define and
> the policy still blocks, but every violation it catches goes nowhere -- and
> a violation report is the whole reason to deploy this before enforcing it.

Nothing in that reasoning is specific to `Integrity-Policy`. Three other
headers name a reporting group the same way and get no such check:

- `Content-Security-Policy`, via the `report-to` directive
- `Cross-Origin-Opener-Policy`, via the `report-to` structured-field parameter
- `Cross-Origin-Embedder-Policy`, via the same parameter

`isolation.py` already parses those parameters off — `_bare_item()` splits on
`;` and its docstring names the reporting integration explicitly — it simply
never checks the group.

### Vulnerable samples

Each of these is a complete response head, and each reports **clean today**.
Verified by running them through `report()` at HEAD; the recorded output is
what the package actually produced, not a prediction.

**A1 — CSP violation reports go nowhere.** There is no `Reporting-Endpoints`
header at all, so the group `csp-endpoint` is undefined. The policy still
enforces; every violation it detects is discarded.

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=63072000; includeSubDomains
Content-Security-Policy: default-src 'self'; base-uri 'none'; frame-ancestors 'none'; report-to csp-endpoint
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Permissions-Policy: geolocation=()
```

Today: **no findings.** Wanted: `csp-report-to-undefined`.

**A2 — COOP and COEP report nowhere.** Same defect, both isolation headers.

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=63072000; includeSubDomains
Content-Security-Policy: default-src 'self'; base-uri 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Cross-Origin-Opener-Policy: same-origin; report-to="coop-endpoint"
Cross-Origin-Embedder-Policy: require-corp; report-to="coep-endpoint"
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: geolocation=()
```

Today: **no findings.** Wanted: `coop-report-to-undefined`,
`coep-report-to-undefined`.

**A3 — the group is defined, and the browser discards it anyway.** This is the
sample that decides DECISION A-1. The name matches on both sides, so a
name-only check stays silent, but the endpoint is not a potentially trustworthy
URL and the browser never registers it.

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=63072000; includeSubDomains
Reporting-Endpoints: csp-endpoint="http://reports.example.com/csp"
Content-Security-Policy: default-src 'self'; base-uri 'none'; frame-ancestors 'none'; report-to csp-endpoint
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Permissions-Policy: geolocation=()
```

Today: **no findings**, and it would still be no findings under a name-only
implementation of item A.

*Revision 3:* this sample is now `re-endpoint-undeliverable`, a `note` on
`Reporting-Endpoints` — the header that wrote the bad URL — rather than a
warning on the CSP that named the group. The CSP did nothing wrong: it named a
group that something did define.

**A4 — correct, and must stay silent.** The regression guard for all of the
above. Identical to A3 with one character changed.

```http
Reporting-Endpoints: csp-endpoint="https://reports.example.com/csp"
Content-Security-Policy: default-src 'self'; base-uri 'none'; frame-ancestors 'none'; report-to csp-endpoint
```

Today: no findings. Wanted: no findings.

### Ground truth for A3

Firefox parses `Reporting-Endpoints` in `dom/reporting/ReportingHeader.cpp`.
At line 325, inside the per-item loop:

```cpp
if (!nsMixedContentBlocker::IsPotentiallyTrustworthyOrigin(endpointURL)) {
  continue;
}

++itemsParsed;
aOnParsedItemCallback(NS_ConvertUTF8toUTF16(key), std::move(endpointURL));
```

The `continue` happens *before* the callback that registers the name, so a
discarded endpoint does not merely fail to receive reports — its group name is
never defined at all. From the browser's point of view A3 is exactly A1.

**Chromium agrees on the outcome and is stricter about the rule.**
`net/reporting/reporting_header_parser.cc`, in `ProcessEndpointURLString()`,
which the `Reporting-Endpoints` path reaches through `ProcessEndpoint()` at
line 223:

```cpp
if (IsAbsolutePath(endpoint_url_string)) {
  endpoint_url_out = header_origin.GetURL().Resolve(endpoint_url_string);
} else {
  endpoint_url_out = GURL(endpoint_url_string);
}
if (!endpoint_url_out.is_valid())
  return false;
if (!endpoint_url_out.SchemeIsCryptographic())
  return false;
```

Three traps that any implementation has to respect. The first is where the two
engines genuinely disagree, and it is the reason the predicate below is
narrower than either engine's own rule:

- **The engines differ on loopback.** Firefox accepts any *potentially
  trustworthy* origin, which includes `http://localhost` and `http://127.0.0.1`.
  Chromium requires `SchemeIsCryptographic()`, which is HTTPS/WSS only and
  rejects loopback over plain HTTP. So `csp-endpoint="http://localhost:9000"`
  delivers reports in Firefox and silently does not in Chrome. Neither "not
  HTTPS" nor "not potentially trustworthy" is safe to use on its own: the
  first is a false positive against Firefox, the second lets Chromium's
  behaviour go unreported. **Fire only on what both engines reject** — an
  absolute URL with a non-cryptographic scheme whose host is not loopback.
- **Relative URLs are resolved, not rejected**, in both engines — `NS_NewURI(...,
  baseURL)` in Firefox, `header_origin.GetURL().Resolve(...)` in Chromium. So
  `csp-endpoint="/reports"` is a perfectly good endpoint and must never fire.
- **Chromium discards the whole header on one bad member.**
  `ParseReportingEndpoints()` returns `std::nullopt` — dropping *every* group,
  not just the offending one — if any dictionary member is an inner list or a
  non-string. Firefox `continue`s past the bad member and keeps the rest. This
  is not something to report on directly, but it means a syntactically broken
  `Reporting-Endpoints` can undefine groups that look perfectly well-defined in
  the text, so the analyser must never claim a group *is* defined more
  confidently than this.

`Reporting-Endpoints` support, from MDN BCD (`http/headers/Reporting-Endpoints.json`,
checkout `ba5f572f7`, 2026-08-14): Chrome 96, Firefox 130, Safari 16.4. This is
not a fringe header, and the three referencing headers are all older and more
widely deployed than the one that already has the check.

### DECISION A-1 — what counts as "defined" — RESOLVED: Option 1

> **Resolved 2026-08-17: Option 1**, fold the check into the lookup. The
> Chromium evidence above narrows *how*: the predicate fires only on what both
> engines reject, so a loopback endpoint over plain HTTP is left alone.
>
> **Superseded in revision 3 by something closer to Option 3.** The deciding
> argument for Option 1 was that a name-only check "answers whether the author
> wrote the same string twice", and that still holds — but it does not follow
> that the *referencing* header owns the defect. An endpoint URL nothing can
> be delivered to is one fact about the definition, and blaming each policy
> that named the group reports it up to four times with a single fix between
> them. So: the lookup is syntactic, and `Reporting-Endpoints` answers for its
> own URLs via `re-endpoint-undeliverable`. Option 3's objection — that the two
> findings "never connect" — is answered by the group still counting as
> defined, so exactly one of them fires.
>
> The Reporting API spec also arbitrates the loopback question the engines
> disagreed on: `ed/algorithms/reporting-1.json` step 5.3 says "If endpoint
> url's origin is **not potentially trustworthy**, then continue", so Firefox
> is conformant and Chromium's `SchemeIsCryptographic()` is stricter than
> required. The predicate is unchanged — it still fires only on what both
> reject — but the direction of any future revisit is now known: if Chromium
> relaxes toward the spec the predicate can widen, and the reverse is not on
> the cards.

The question the samples force: does `_reporting_endpoint_names()` return every
name that appears in the header, or only the names a browser would register?

**Option 1 — fold it into the lookup (recommended).**
`_reporting_endpoint_names()` skips entries whose URL is an absolute URL that
is not potentially trustworthy. One predicate, no new code, no new severity,
and all four findings — the three new ones and the existing
`ip-endpoints-undefined` — become correct together. A3 then produces
`csp-report-to-undefined`.

The cost is prose. The current sentence for `ip-endpoints-undefined` reads
"…which no Reporting-Endpoints header defines…", and under this option that is
not quite true of A3: a header does define the name, badly. The wording needs a
pass — something closer to "…which no Reporting-Endpoints header usefully
defines…" — and `tests/rendered_messages.txt` regenerates. That is a small,
deliberate diff, but it touches an existing message, so it deserves to be read
rather than rubber-stamped.

**Option 2 — name-only matching, park the URL question.** Ships item A with a
known blind spot: A3 stays silent forever. Smallest diff, no prose change. The
blind spot is real but narrow, and it is the option that matches last night's
"park it for research" instinct.

**Option 3 — a separate code on `Reporting-Endpoints` itself.** Say
`re-insecure-endpoint`, firing whether or not anything references the group.
Cleanest ownership and the clearest sentence, but the group still counts as
defined, so A3 produces a finding about the endpoint and *no* finding about the
CSP that is silently broken. The two facts never connect, which is the outcome
with the least explanatory value.

**Recommendation: Option 1.** The argument that moved me is that this is not an
extra feature bolted onto item A — it is item A being correct. A name-only
check answers "did the author write the same string twice", which is a typo
detector; a browser-accurate check answers "will these reports arrive", which
is the thing the finding claims. The one-character difference between A3 and A4
producing identical output is hard to defend once it is written down.

### DECISION A-2 — the report-only spellings — RESOLVED: parked

> **Resolved 2026-08-17: parked, Option 1.** Enforcing headers only. The
> reasoning that settled it is not the one below and is worth recording,
> because it disposes of the tension rather than deferring it: in most
> responses a report-only finding is noise, and the one case where it is not —
> an administrator deliberately trialling a policy before enforcing it — is
> someone who *knows* the policy is not enforcing and wants to be told about
> its plumbing. That is a switch on a tool, not a default of the analysis
> engine. It may return as an optional feature; it is not a priority.

`_analyze_ip_reporting()` reads only the enforcing header, and says so:

> Only the enforcing header is read. The report-only spelling is left alone
> on principle, even though the same defect there is arguably worse.

That is principle 6, and the parenthetical concedes the tension. It is sharper
for the three new headers than it was for `Integrity-Policy`, because a
`Content-Security-Policy-Report-Only` whose reporting group is undefined does
not merely lose its reports — it does *nothing whatsoever*. Enforcement is not
its job; delivery is its only job.

There is a distinction available that would resolve this without reopening
principle 6. That principle says non-enforcing **content** decides nothing —
"what a non-enforcing header permits" is the phrase. A reporting group is not
content and does not describe what the policy permits; it is the delivery
plumbing. The package already treats report-only headers as having analysable
properties that are not content: `csp-ro-unenforced` fires on the presence of
`Content-Security-Policy-Report-Only` without an enforcing sibling.

**Option 1 — enforcing headers only (recommended for this change).** Matches
the `Integrity-Policy` precedent exactly. Three codes.

**Option 2 — extend to the report-only spellings too.** Four more codes
(`csp-ro-`, `coop-ro-`, `coep-ro-`, and `ip-ro-` for symmetry), and a paragraph
in CLAUDE.md drawing the content/plumbing line explicitly.

**Recommendation: Option 1 now, Option 2 as its own decision.** Not because the
argument for Option 2 is weak — I think it is the stronger argument on the
merits — but because bundling a refinement of principle 6 into a symmetry fix
means neither gets judged on its own evidence. If Option 2 is taken it should
also cover `Integrity-Policy`, which makes it a change to a settled ruling
rather than an extension of this one.

### Design

**Location: `response.py`.** These are cross-header rules — a CSP alone cannot
say whether a group is defined — and the boundary in CLAUDE.md puts those in
`response.py` regardless of family. This also means the CSP check does not pass
through `_analyze_csp_all()`, so its repeated-header semantics are decided here
rather than inherited.

**Codes.** One per header, because a code belongs to exactly one header and
`duplicate-headers` is the only exemption:

| Code | Header | Level |
|---|---|---|
| `csp-report-to-undefined` | `Content-Security-Policy` | `note` |
| `coop-report-to-undefined` | `Cross-Origin-Opener-Policy` | `note` |
| `coep-report-to-undefined` | `Cross-Origin-Embedder-Policy` | `note` |
| `re-endpoint-undeliverable` | `Reporting-Endpoints` | `note` |
| `re-ineffective` | `Reporting-Endpoints` | `note` |

Nothing here is `error`, because nothing is ignored by the browser and nothing
is permitted that should not be. Revision 2 rated the first three `warning`, on
the `ip-endpoints-undefined` precedent; **revision 3 rates the whole family
`note` and moves `ip-endpoints-undefined` down to join them.** The reasoning
that settled it is worth keeping: a reporting failure costs the operator
information and nothing else — no browser protection is withheld by it, and
there is no path through it for an attacker to reach the site or its users.
What makes it worth saying at all is that the operator plainly intended the
reports to arrive, which is a `note`'s job exactly: a fact with no defect in
protection.

**Data.** `{"groups": [...]}`, a sorted list, matching the shape
`ip-endpoints-undefined` uses for `{"endpoints": [...]}`. A list rather than a
scalar for two reasons: CSP's `report-to` is written as one token by the spec
but appears with several in the wild, and the list keeps one finding per header
rather than one per group. The template must name `{groups}` — a template naming
a key the data does not carry is invisible until someone asks for the sentence,
and there is a test for exactly that.

**Repeated CSP.** Each policy carries its own `report-to`, so a group named by
one policy and undefined is that policy's reports going nowhere, whatever its
siblings say. That is "any policy", the same reasoning `CSP_SYNTAX_CODES` gives
for its members: a syntax defect belongs to the text of one policy. The
implementation takes the union of undefined groups across all policies and
emits one finding. Note this must be written explicitly — the rule lives in
`response.py` and does not inherit the conjunctive merge in `csp.py`.

**Repeated COOP/COEP.** Use `_sole_value()`. A header repeated with values that
disagree returns `None` and emits nothing, because no specification says which
one wins.

**A policy that applies nothing is not asked about reporting.** Added in
revision 3 across all four headers: COEP `unsafe-none` blocks nothing, so it
reports nothing, and the sentence "the policy applies and every report it would
have sent is discarded" was false of it. An unrecognised value counts the same,
because both engines fall back to the inert default rather than to what the
operator meant. `_analyze_ip` had this discipline already — its comment reads
"once the policy enforces nothing, what its other directives say decides
nothing either" — while `_analyze_ip_reporting` did not; now they agree, and
`integrity-policy: endpoints=(ep)` no longer claims violations are caught.

**Message templates**, modelled on the existing one:

```text
csp-report-to-undefined   present and reports violations to {groups}, which no
                          Reporting-Endpoints header defines, so violations are
                          detected and never delivered
```

with the wording adjusted per DECISION A-1 if Option 1 is taken.

### Two pre-existing defects in `_reporting_endpoint_names()`

Both found while probing this; both currently harmless, both become
load-bearing once three more findings depend on the helper.

**A comma inside a quoted URL invents a group.** The helper splits the value on
`,` and then partitions each chunk on `=`. Verified:

```text
'csp-endpoint="https://r.example.com/csp?a=1,b=2"'  ->  {'csp-endpoint', 'b'}
```

The phantom group `b` can only ever *over*-define names, so the effect is a
false negative: a policy that genuinely reports to a group named `b` would be
excused. Narrow, but it is the wrong direction of error for a helper that four
findings consult. The fix is to split on commas outside quoted strings.

**Structured-field keys are lowercase by definition.** `CSP-EP="…"` is not a
valid dictionary key, and the helper accepts it. Low priority; noted so it is
not rediscovered.

Recommendation: fix the comma case as part of this work, leave the key case.

**Done:** the comma case is fixed — `_split_dictionary()` splits on commas
outside quoted strings, with a test and a killed mutation. The lowercase-key
case is deliberately still open and is the only thing in this document left
unaddressed on purpose.

---

## Item B — an ACAO value that is not a serialized origin

### The gap

`_analyze_acao()` in `isolation.py` handles three shapes — `null`, a list, and
`*` — and then falls through to `return []`. Everything else is accepted in
silence, including values that no browser can ever match. Verified at HEAD:

```text
'*.example.com'                                -> (nothing)
'https://*.example.com'                        -> (nothing)
'https://example.com/'                         -> (nothing)
'https://Example.com'                          -> (nothing)
'example.com'                                  -> (nothing)
'https://example.com'                          -> (nothing)   correct
'*'                                            -> acao-wildcard
'null'                                         -> acao-null
'https://a.example.com https://b.example.com'  -> acao-multiple-origins
```

The first two are values the cloaked.pl survey observed in the wild
(`*.vporn\.com` and `*.imgimg.com` in its sample of roughly 1600 sites).

### Ground truth

Both engines on disk compare the header against the request's serialized origin
as a byte string. There is no parsing, no wildcard expansion, and no case
folding anywhere in either path.

All three engines compare bytes. Chromium is the most informative of the three,
because it does not stop at "no match" — it sorts the failure into named error
classes, and one of them is precisely the finding proposed here.

Chromium, `services/network/public/cpp/cors/cors.cc`, in `CheckAccess()`:

```cpp
} else if (*allow_origin_header != origin.Serialize()) {
  // ...
  // Does not allow to have multiple origins in the allow origin header.
  if (allow_origin_header->find_first_of(" ,") != std::string::npos) {
    return base::unexpected(CorsErrorStatus(
        mojom::CorsError::kMultipleAllowOriginValues, *allow_origin_header));
  }
  // Check valid "null" first since GURL assumes it as invalid.
  if (*allow_origin_header == "null") { /* kAllowOriginMismatch */ }

  GURL header_origin(*allow_origin_header);
  if (!header_origin.is_valid()) {
    return base::unexpected(CorsErrorStatus(
        mojom::CorsError::kInvalidAllowOriginValue, *allow_origin_header));
  }
```

`kInvalidAllowOriginValue` is `acao-invalid-origin` under another name, and
Chromium's own unit test for it uses the value `"invalid.origin"` — sample B2
below, exactly. The `find_first_of(" ,")` test also confirms that the existing
`acao-multiple-origins` is checking the right two separators.

Firefox, `netwerk/protocol/http/nsCORSListenerProxy.cpp:811`:

```cpp
mOriginHeaderPrincipal->GetWebExposedOriginSerialization(origin);

if (!allowedOriginHeader.Equals(origin)) {
```

WebKit, `Source/WebCore/loader/CrossOriginAccessControl.cpp`, in
`passesAccessControlCheck()`:

```cpp
String securityOriginString = securityOrigin.toString();
if (accessControlOriginString != securityOriginString) {
```

So the complete set of values that can ever match is: `*` (when credentials are
not in use), `null`, and one serialized origin — `scheme "://" host [ ":" port ]`
with an ASCII-lowercase scheme and host, no trailing slash, no path, no query,
no fragment, no userinfo. Anything else fails for every possible request.

### Vulnerable samples (ACAO)

**B1 — a subdomain wildcard, which CORS has never supported.**

```http
HTTP/1.1 200 OK
Content-Type: application/json
Access-Control-Allow-Origin: https://*.example.com
Access-Control-Allow-Credentials: true
```

Today: no findings. Wanted: `acao-invalid-origin`.

**B2 — a bare hostname with no scheme.**

```http
Access-Control-Allow-Origin: example.com
```

**B3 — a trailing slash, the most common single-character version.**

```http
Access-Control-Allow-Origin: https://example.com/
```

**B4 — correct, and must stay silent.**

```http
Access-Control-Allow-Origin: https://app.example.com:8443
```

### Why this is worth reporting even though it fails closed

An invalid ACAO never permits more than a valid one; the browser rejects the
exchange. Strictly, it is a functional defect rather than a hole. Two arguments
for reporting it anyway:

1. It is the same failure mode as `acao-multiple-origins`, which is already
   rated `error` and whose comment says the quiet part: "A list is rejected
   outright, which fails closed, but it also means the CORS the operator
   configured is not happening at all." Reporting one and not the other is an
   accident of which shape happened to be implemented.
2. It is a leading indicator of the real vulnerability. A developer who writes
   `https://*.example.com`, finds CORS broken, and needs it working by Friday
   very often "fixes" it by reflecting the `Origin` header back — which is the
   origin-reflection defect the parked active check exists to catch. The
   invalid value is the state just before that.

### DECISION B-1 — severity — RESOLVED: `error`

> **Resolved 2026-08-17: `error`**, consistent with `acao-multiple-origins`.
> Chromium's taxonomy independently supports treating the two as siblings: it
> reaches `kInvalidAllowOriginValue` and `kMultipleAllowOriginValues` from the
> same branch, three lines apart, for the same reason.

**Option 1 — `error` (recommended).** Consistency with
`acao-multiple-origins`, which is `error` today for an identical failure mode.

**Option 2 — `warning`.** Arguably the better fit for principle 3 as written,
since that principle defines `error` in terms of protection not being delivered
and a permission header does not protect anything.

**Recommendation: Option 1**, with a caveat worth a minute of your time: if
`warning` is the right reading of principle 3 here, then `acao-multiple-origins`
is mis-rated today and the fix is to move both, not to split them. I would
rather have the two consistent at `error` than consistent-by-accident.

### DECISION B-2 — how strict the predicate should be — RESOLVED: core + case

> **Resolved 2026-08-17: the conservative core, plus the case check.** Chromium
> settles the one clause that was resting on inference. `url/url_canon_host.cc`
> gives `'*'` a lookup value of `0` (line 93), which marks it an invalid host
> character and fails canonicalisation, so `https://*.example.com` is an
> invalid `GURL` and Chromium classifies it as `kInvalidAllowOriginValue`. The
> comment at line 21 notes asterisks are "still non-compliant to the URL
> Standard", i.e. this is deliberate. Both of the values cloaked.pl observed in
> the wild land in Chromium's invalid bucket.
>
> One nuance that does **not** change the predicate: Chromium's *taxonomy* is
> narrower than ours. A trailing slash, a path, a query or userinfo all make a
> perfectly valid `GURL`, so Chromium calls those `kAllowOriginMismatch` rather
> than invalid. They still never match, because `origin.Serialize()` never
> contains any of them — which is the right question to ask, and the one this
> predicate asks. Our bucket is a superset of Chromium's on purpose.

Principle 4 says a false positive on a correct configuration is the worst
outcome, so the predicate should fire only on values that *cannot* be a
serialized origin, never on values that merely look unusual.

**The conservative core (recommended).** After stripping, and after the
existing `null`, list and `*` branches, fire when any of these holds:

- no `://` in the value
- a `*` anywhere in it
- a `/` after the `://` — this catches the trailing slash and any path
- a `?` or `#`
- an `@` (userinfo)

Deliberately *not* included: any restriction on the scheme, because
`moz-extension://`, `chrome-extension://` and friends are valid serialized
origins and appear in real CORS configurations; and any attempt to validate the
host, because IDN and punycode are a bog and the failure mode of getting it
wrong is a false positive on a working site.

**The optional extra — flag a non-lowercase scheme or host.** `https://Example.com`
never matches, deterministically, because both engines compare bytes and the
request origin is always lowercase-serialized. It is a true positive with
certainty. It is listed separately because it is a different kind of check —
normalization rather than structure — and because it is the one that would
most embarrass us if some engine turned out to fold case after all. **All three
engines compare bytes and none folds case**, so this is now settled rather than
inferred from two.

*Revision 3 retires the hedge entirely.* The byte comparison is normative, not
a shared implementation habit: Fetch's CORS check, step 4
(`ed/algorithms/fetch.json`), reads "If the result of **byte-serializing a
request origin** with request is not origin, then return failure." No
conformant engine can fold case, so there is nothing left to be embarrassed
by. Step 1 of the same algorithm also explains the sibling code: it *gets*
`Access-Control-Allow-Origin` from the header list, and getting joins repeated
fields with `", "`, which is why a repeated ACAO lands in Chromium's
`kMultipleAllowOriginValues` bucket rather than anywhere else.

**Recommendation:** conservative core now; take the case check too if you
agree the two-engine evidence is enough, since it is three lines and one test.

### Design (ACAO)

One branch in `_analyze_acao()` in `isolation.py`, before the final
`return []`. This stays a single-header rule — it needs no sibling — so it does
not move to `response.py`.

| Code | Header | Level | Data |
|---|---|---|---|
| `acao-invalid-origin` | `Access-Control-Allow-Origin` | `error` (B-1) | `{"value": "<as sent>"}` |

`{"value": ...}` matches what `acao-multiple-origins` already carries.

Draft message: "present but {value} is not a serialized origin, so no browser
can match it and every cross-origin request is rejected".

---

## Item C — `Document-Isolation-Policy`, parked as a watch item

Not to be implemented. Recorded so the next person does not re-derive it.

DIP grants cross-origin isolation on its own, without COEP. The package's
`coep-missing` suppression only excuses a missing COEP when COOP does not ask
for isolation, so a document isolated by DIP gets a warning it does not
deserve. Verified at HEAD:

```text
COOP: same-origin
Document-Isolation-Policy: isolate-and-require-corp
   ->  coep-missing
```

Revision 1 of this document called that a false positive and parked it for want
of evidence. **Chromium supplies the evidence, and it reverses the conclusion:
the suppression should not be written, and now for a reason rather than for a
lack of one.**

DIP is real, shipped, and live in Chrome.
`services/network/public/cpp/document_isolation_policy_parser.cc` parses both
`document-isolation-policy` and `document-isolation-policy-report-only` as
structured-field items, accepting exactly `isolate-and-require-corp` and
`isolate-and-credentialless` and treating everything else as `kNone`, with an
optional `report-to` string parameter. It is not merely parsed, either — the
distinction CLAUDE.md warns about — since `features.cc:349` reads
`BASE_FEATURE(kDocumentIsolationPolicy, base::FEATURE_ENABLED_BY_DEFAULT)`.

And it is Chrome's alone:

- **No MDN BCD entry at all** — no `Document-Isolation-Policy.json` in
  `documentation/browser-compat-data/http/headers/` at checkout `ba5f572f7`
  (2026-08-14).
- **Nothing in Firefox** — no hit for `Document-Isolation-Policy` or
  `DocumentIsolationPolicy` under `dom/security` or `netwerk/protocol/http`.
- **Nothing in WebKit** — no hit under `Source/WebCore/loader`.

That is what settles it. On a response carrying COOP `same-origin` and DIP but
no COEP, Chrome grants cross-origin isolation and Firefox and Safari do not —
they ignore DIP entirely and see a document that asked for isolation and did
not get it. `coep-missing` is therefore **correct in two engines out of three**,
and suppressing it would trade a warning that is right for most users against
one that is wrong for some. Principle 5 already decides this: only an effective
header earns a suppression, and a header one engine honours is not effective in
the sense that principle means.

**Recheck trigger:** DIP shipping in a second engine — a
`Document-Isolation-Policy.json` in BCD is the cheap way to notice. At that
point the balance inverts and it becomes a suppression in
`_suppress_redundant()` beside the existing COOP/COEP logic, plus — note — a
fourth `report-to` group to cross-check under item A, since the Chromium parser
above already accepts one.

---

## Testing

Standard for this project, plus the two things that have paid for themselves:

- **Corpus first.** Every new code needs a case in `tests/`, or the
  completeness tests — every emittable code has a rating and a template, and
  every rated code is emittable — pass vacuously.
- **Mutation-test each new guard.** Break it, confirm the test fails, restore.
  Specifically worth mutating: the trustworthiness predicate if DECISION A-1
  takes Option 1 (a guard that returns the wrong empty value survives every
  mutation when the only caller tests truthiness — that has happened here
  before), and each clause of the ACAO predicate independently, since a
  five-clause `or` passes its test with four clauses dead.
- **A4 and B4 are the point.** The negative cases are load-bearing; a version
  of this that fires on A4 is worse than not shipping it.
- **Behavioural equivalence for the ACAO change.** `git show HEAD:http_security_test/isolation.py`
  into the scratchpad, run the corpus through both, diff the `(header, code)`
  sets. The only difference should be the new code on the new cases.
- **Regenerate the snapshot deliberately and read the diff**, especially under
  DECISION A-1 Option 1, which edits an existing sentence:

  ```sh
  UPDATE_MESSAGE_SNAPSHOT=1 python -m pytest tests/ -k snapshot
  ```

## Open question, minor — RESOLVED: inventory it

`Reporting-Endpoints` currently appears in no inventory bucket — a response
carrying it reports empty `security`, `information`, `deprecated` and
`caching`. After item A the analyzer reads it, which makes its absence from
every inventory odd.

**Resolved 2026-08-17: add it — but not to `SECURITY_HEADERS`, and the
mechanism is a small open question.**

The obvious move is wrong, and it is worth writing down why. `SECURITY_HEADERS`
is read in three places, not one:

- `inventory()["security"]` — the headers present. *Wanted.*
- `inventory()["missing"]` — the headers absent. **Not wanted.**
- `_report_missing()` — which emits `<tag>-missing` for each absent entry.
  **Definitely not wanted.**

A response that configures no reporting is the ordinary state of the web, so
the third would fire `re-missing` on nearly every site analysed — a false
positive on a correct configuration, principle 4, from a one-line table edit.
(The test suite would in fact catch it, since `_missing_tag()` would mint the
code `re-missing`, which has no rating and no template and would fail the
bijection tests. That is the suite working as designed, but the design should
not need saving by it.)

So the header needs to reach the `security` inventory without reaching the
other two consumers, and the tidy way to do that is a separate table:

```python
# Security-relevant headers that are inventoried but never reported missing:
# their absence is the ordinary state of the web, not a gap.
REPORTING_HEADERS = ("Reporting-Endpoints",)
```

`inventory()["security"]` then filters on `SECURITY_HEADERS + REPORTING_HEADERS`
while `missing` and `_report_missing()` keep reading `SECURITY_HEADERS` alone.

The cost is that `inventory()`'s own docstring currently says "`security` and
`missing` are two halves of one question", and this makes that three-quarters
true.

**Resolved 2026-08-17 and implemented:** the separate table, with the docstring
amended to name the exception rather than leave it implicit. A fifth inventory
key was rejected because it changes the top level of the output schema, which
is parked pending the version-field question.

## What is not being done

- **`Connection` naming an end-to-end header** (RFC 9110 §7.6.1, "a sender MUST
  NOT send a connection option corresponding to a field that is intended for
  all recipients"). Dropped as too far-fetched.
- **`Origin-Agent-Cluster`** — Chrome 90 / Firefox 138 / Safari preview, and
  explicitly not a security feature; it is an agent-clustering hint.
- **`Report-To`** — BCD `deprecated: true, standard_track: false`, superseded
  by `Reporting-Endpoints`. Reporting infrastructure, not a security header.
