# Consequence codes, taxonomy references, and the code-to-header table

2026-08-23. Status: design agreed, not implemented.

Three additions to what a finding carries, and one parked item closed to make
them possible. Everything here is *derived* data with an external contract; no
analyser changes and no verdict moves.

## What lands

- **`CODE_HEADER`** — the declared code-to-header table, parked since the CLI
  landed. `explain` needs it and cannot fake it.
- **A consequence vocabulary** — eight slugs naming the risk a misconfiguration
  creates, each anchored where an honest published id exists.
- **`consequences` on every finding**, and a **`references` block per response**
  carrying resolvable identifiers rather than URLs.
- **`references.py`** — URL derivation, a new leaf.

## What does not, and why

- **Long-form markdown descriptions.** Parked, to land with the SARIF writer,
  where `fullDescription` / `help.markdown` is the field they belong in. The
  short message is SARIF's `messageStrings` and takes `arguments`; a long
  description belongs to the *rule* and takes none. Splitting them across two
  releases costs nothing because they are different SARIF fields.
- **Curated per-code links** (a Tenable plugin page for `duplicate-headers`,
  vendor write-ups, cheat sheets). This is curated data that ages, which is the
  argument that kept csp-evaluator's bypass lists out. Revisit alongside any
  other decision to take on curation.
- **ATT&CK and EMB3D ids.** Measured, not assumed — see below.
- **CVE.** Not parked, dropped. A CVE names a flaw in a specific product
  version. A misconfigured header has none, and attaching one would be false
  precision of exactly the kind principle 4 exists to stop.
- **An operational-neglect signal.** Parked as a *second axis*, not as a ninth
  slug — see below.

### Parked: the hygiene axis

A finding can say something about the *operator* rather than about an attacker:
a header no browser has read since 2018 that nobody removed, a `Report-To` whose
JSON does not parse, an RFC 1918 address left in a production CSP. None of that
is risk, and all of it is evidence that nobody is tending the server — which is
its own finding to a pentester, because the box that nobody tends is the box
that gets owned three years later.

The concept is legitimate and has a precedent in CWE's own prose: **CWE-477
*Use of Obsolete Function*** describes itself as *"The code uses deprecated or
obsolete functions, **which suggests that the code has not been actively
reviewed or maintained**."* Same inference, different altitude.

It is nonetheless **not** a consequence slug, for one reason that survived
scrutiny and one that did not.

- **It did not fail the CWE-693 test**, which was the expected objection.
  Framed narrowly — *the operator wrote something that does not do what they
  evidently intended* — it discriminates well: false for the deliberate opt-ins
  (`acao-wildcard`, `corp-cross-origin`, whose messages say as much), false for
  competent-but-constrained configurations (`csp-unsafe-inline` is usually a
  legacy application, not neglect), true for `rt-invalid`, `hpkp-deprecated`
  and `csp-ip-source`. It would turn "this finding has no consequence" into
  "no consequence, *for a reason*", which is more than `()` says.
- **It is a different axis, and that is disqualifying for a slug.** Every
  consequence answers *what could an attacker achieve*. This answers *what does
  this tell me about the operator*. In one list, `["xss", "stale-config"]`
  conflates a capability with an inference, and every consumer triaging by risk
  must filter one out forever. The right shape is a sibling field — `signals`
  beside `consequences` — never another value in this one.

**Why it waits.** The strong evidence is not in the headers analysed here. A
missing semicolon is weak; `Server: Apache/2.2.15` and `X-Powered-By: PHP/5.3`
are not. Those belong to the parked inverted *"interesting headers"* switch,
where the material already surveyed for it lives — humble's 1 287-name
`fingerprint.txt`, and `burp/burp-suite-software-version-checks`' 114-regex
`match-rules.tab`, already recorded in CLAUDE.md as "the only one that extracts
a *version* out of a value rather than just naming the product, so revisit it
if the switch ever wants that". It wants that. Land the two together.

Until then it is computable by a consumer and worth nothing more: a response
whose findings all carry `consequences: []` is misconfigured and not dangerous,
which is one line over data this design already produces.

**Consequence of parking the long text: no new CLI flag.** Identifiers are
cheap enough to emit unconditionally, so there is no verbosity switch, no
which-outputs-get-the-extra-fields question, and no terminal-versus-file split.

## 1. `CODE_HEADER`, in `findings.py`

```python
CODE_HEADER = {
    "csp-unsafe-inline": "Content-Security-Policy",
    "duplicate-headers": None,   # the response, not a header
    ...
}
```

**Not `catalog.py`**, which holds prose and nothing else. **Not `cli/`**, which
would duplicate knowledge the analysers own and rot the first time a code moves
— that was the objection when the table was parked. It goes beside
`FINDING_SEVERITY`, which is the same shape: a declared, code-keyed policy
table pinned in both directions by test.

`duplicate-headers` maps to `None` rather than being omitted, so the table stays
**total** over codes and earns the same bijection the severities have. This
upgrades `test_each_code_belongs_to_exactly_one_header` from *"the corpus is
self-consistent"* to *"the package agrees with the corpus"*: it can now catch a
code whose declared header and emitted header disagree, which today nothing can.

**A live wrinkle, verified rather than assumed.** `_duplicated()` reads names
straight out of the lowercased `present` mapping, so a duplicate-header finding
carries `Finding("x-frame-options", "duplicate-headers")` while every other
finding carries canonical casing — and it is pinned that way at
`tests/rendered_messages.txt:81`. Any name-to-URL resolution must therefore be
case-insensitive, or it silently produces a dead link. Canonicalising through
the package's own header tables is what the `references` block does, and it is
the reason that block is not a one-line comprehension a consumer could do.

## 2. The consequence vocabulary

Eight slugs. Deliberately coarse: this is a **hint about potential risk, not a
detection**, so a slug names a class of harm rather than claiming one is
reachable. The rendered sentence for each says so in as many words.

| slug | CWE | CAPEC |
|---|---|---|
| `xss` | CWE-79 | CAPEC-63 |
| `clickjacking` | CWE-1021 | CAPEC-103 |
| `mitm` | CWE-319 | CAPEC-117 |
| `data-disclosure` | CWE-200 | — |
| `cors-data-theft` | CWE-942 | — |
| `cache-exposure` | CWE-525 | CAPEC-204 |
| `cross-origin-leak` | — | CAPEC-663 |
| `permission-abuse` | CWE-732 | — |

Exact names, read from `tmp/cwec_v4.20.xml` and
`ref/documentation/cti/capec/2.1/stix-capec.json` on 2026-08-23:

- CWE-79 *Improper Neutralization of Input During Web Page Generation
  ('Cross-site Scripting')* — Base, Stable
- CWE-1021 *Improper Restriction of Rendered UI Layers or Frames* — Base
- CWE-319 *Cleartext Transmission of Sensitive Information* — Base
- CWE-200 *Exposure of Sensitive Information to an Unauthorized Actor* — Class
- CWE-942 *Permissive Cross-domain Security Policy with Untrusted Domains* —
  Variant
- CWE-525 *Use of Web Browser Cache Containing Sensitive Information* — Variant
- CWE-732 *Incorrect Permission Assignment for Critical Resource* — Class
- CAPEC-63 *Cross-Site Scripting (XSS)* — Standard
- CAPEC-103 *Clickjacking* — Standard
- CAPEC-117 *Interception* — Meta
- CAPEC-204 *Lifting Sensitive Data Embedded in Cache* — Detailed
- CAPEC-663 *Exploitation of Transient Instruction Execution* — Standard

### The rule that shrank the vocabulary

It started at eleven slugs and lost three to one rule: **the consequence of an
ineffective protection is the thing that protection existed to stop.**

- `mime-confusion` dropped; `xcto-missing` maps to `xss` directly. CAPEC's own
  catalogue agrees — CAPEC-209 is named *XSS Using MIME Type Mismatch*.
- `policy-bypass` dropped; `xcsp-deprecated` maps to `xss`, `xfo-allow-from` to
  `clickjacking`. A slug meaning "see the finding" is not a consequence.
- `session-hijack` folded into `mitm`, which is the actual mechanism by which a
  missing HSTS costs you a session.

`csrf` waits for the cookie parser. No response header alone gets you there.

### `data-disclosure` versus `cross-origin-leak`

Both would read as "information going somewhere it shouldn't", which is why the
first is **not** called `info-leak`. They are disjoint in attacker model, in
direction of travel, and in remedy:

- **`data-disclosure`** — the site sends data outward during ordinary use. No
  attacker page is involved; the recipient is a third party the page already
  talks to. Population today is the Referrer-Policy family.
- **`cross-origin-leak`** — an attacker's document in the victim's browser
  measures something about your origin that the same-origin policy should have
  hidden, using the victim's ambient session. Population is COOP / COEP / CORP.

**The question that separates them: does the attack require the victim to visit
an attacker-controlled page?** Always yes for the second, never for the first.
Nothing set on Referrer-Policy helps the isolation family, or the reverse.

### Empty is a result

The whole reporting family, `hpkp-deprecated`, and most of the 37 notes carry
`()`. That is the vocabulary working: browsers removed key pinning entirely, and
a reporting failure costs the operator information and withholds no protection —
the same reasoning that rates them `note`.

`csd-empty` and `csd-unquoted` map to `cache-exposure`, not `data-disclosure`: a
logout that fails to clear the browser leaves data for the next person at that
machine. Enumerating each slug's actual members is what caught this; reasoning
from the slug name alone did not.

## 3. Which taxonomies, and the measurements behind the answer

Each of the four answers a different question, and only two ask ours: CWE is
*what is weak*, CAPEC is *how it is attacked*, ATT&CK is *what a campaign does*,
EMB3D is *what threatens a device*. A misconfigured header is a weakness with a
known attack, no campaign and no device.

Measured on 2026-08-23 so nobody re-derives it:

- **CWE 4.20 has 969 weaknesses and thin browser-side coverage.** There is **no
  weakness for MIME sniffing at all** — zero hits across "MIME",
  "Content-Type" and "sniff". None for XS-Leaks. Nothing named for permission
  *delegation* either — every permission CWE is written around filesystem and
  OS permissions, and CWE-732 is usable only because its Class-level wording
  happens to be resource-agnostic while its examples are not.
  **This is the measurement behind making the slug the contract and the
  taxonomy id an optional attribute.** Had CWE ids *been* the vocabulary, a
  quarter of the entries would have had no code, or a forced one.
- **ATT&CK contributes nothing.** Zero hits for clickjacking or anything
  cross-origin across 4 822 enterprise objects; its 51 "permission" techniques
  are Windows registry keys and Android device-admin.
- **EMB3D contributes nothing, though it looks like it does.** It has exactly
  six web-ish threats of ~70 (TID-226, 313, 319, 321, 324, 325), and TID-319
  *is* Cross Site Scripting. Reading it settles the matter and argues the
  opposite of what its existence suggests: the threat is *"the **device** does
  not properly restrict … web-based requests"*, evidenced by CVE-2018-14784 on
  a NetComm LTE router and CVE-2014-2246 on a Siemens S7-1500 PLC. Tagging a
  generic web scan with it would assert the target is an embedded device.
  **A taxonomy having an entry for your concept is not the same as it being
  about your concept.**

### When a broader id is honest, and when it is filler

The gaps invite a generic id — CWE-693 *Protection Mechanism Failure* was
proposed for `permission-abuse` on the reasoning that it is not ideal but beats
nothing. It does not, and the reason generalises.

CWE-693 is a Pillar with 26 direct children whose description is *"The product
does not use or incorrectly uses a protection mechanism that provides sufficient
defense against directed attacks against the product."* That is principle 3's
definition of an `error` almost word for word — it is true of **every finding
this package emits**. Attached to the one slug that lacked something better, it
would stop meaning what it says and start meaning *"unclassified"*: a consumer
filtering on CWE-693 would get exactly the slug we failed to classify and miss
`xss`, `clickjacking` and `mitm`, which are equally protection-mechanism
failures.

**The test.** A broader id is honest when it would still be chosen if a narrower
one existed. It is filler when it is *equally true of the slugs that already have
specific ids* — at that point it carries no information and inverts into a
marker for the gaps. CWE-693 and CWE-284 *Improper Access Control* both fail
this on all eight slugs.

What the gap actually wanted was a longer look, not a weaker id. **CWE-732
*Incorrect Permission Assignment for Critical Resource*** (Class): *"The product
specifies permissions for a security-critical resource in a way that allows that
resource to be read or modified by unintended actors."* A policy saying
`camera=*` does precisely that. It passes the test — it is not true of `xss`,
`mitm`, `clickjacking` or `cache-exposure` — and its parent CWE-668 makes the
vocabulary more coherent, since `data-disclosure` (CWE-200) and
`permission-abuse` (CWE-732) then both descend from *Exposure of Resource to
Wrong Sphere*, one being information and the other a capability. Rejected on the
way: CWE-269 *Improper Privilege Management* (vaguer about the resource) and
CWE-250 *Execution with Unnecessary Privileges* (the product's own privilege
level, not delegation).

`cross-origin-leak` keeps no CWE, for the reason in the next section.

### Four ids that look right and are wrong

Each was found by keyword and killed by reading. Record them so they are not
re-proposed:

- **CWE-693 *Protection Mechanism Failure***, for any gap — see above.

- **CWE-293 *Using Referer Field for Authentication*** is the only referrer CWE
  and points the wrong way: it is the *server trusting* `Referer`, not a page
  leaking one. `data-disclosure` takes CWE-200.
- **CWE-668 *Exposure of Resource to Wrong Sphere*** reads like the missing
  `cross-origin-leak` id — CWE's "control sphere" is nearly an origin. But
  **CWE-200 is a direct `ChildOf` CWE-668**, so pairing them would put our
  narrower concept on the parent class and our broader one on the child,
  asserting a containment we do not mean. Better a gap than a backwards id.
- **CAPEC-468 *Generic Cross-Browser Cross-Domain Theft*** reads like
  `cors-data-theft` and is CSS-injection data theft. The join settles it:
  **zero CAPEC patterns reference CWE-942.**

One disagreement is knowingly kept: CAPEC-204 is chosen for `cache-exposure` on
its description ("examines a target application's cache, or a browser cache")
even though it cross-references CWE-524, the parent, rather than CWE-525. The
CWE stays 525 because it names the browser cache specifically.

**Method note.** Picking an id by keyword match produced a wrong answer three
times out of about a dozen. The reliable join is CAPEC's own
`external_references` — filter `source_name == "cwe"` and ask which patterns
cross-reference the CWE already chosen. That is how CAPEC-103 was confirmed for
`clickjacking` and how CAPEC-468 was eliminated. Use it before trusting a name.

### Taxonomy ids hang off slugs, and *may* also hang off codes

Two tables, and the second is deliberately **sparse**:

- `CONSEQUENCES[slug].taxonomy` — the general classification. Total: every slug
  has one, possibly empty.
- `CODE_TAXONOMY[code]` — an **optional overlay**, present only where a specific
  published entry describes that code better than its slug's does. Most codes
  have no entry and simply inherit.

**Union, never replace.** `xcto-missing` yields CWE-79 and CAPEC-63 *and*
CAPEC-209 — not CAPEC-209 alone. Adding precision must not delete the general
classification, and the hierarchy is built for this: CAPEC-209 is a `Detailed`
pattern beneath CAPEC-63 `Standard`.

Verified starting entries, so the overlay is not an empty dict pretending to be
a design:

| code | id | why it beats the slug's |
|---|---|---|
| `xcto-missing` | CAPEC-209 | *XSS Using MIME Type Mismatch* — the exact mechanism |
| `hsts-missing`, `hsts-malformed` | CAPEC-102 | *Session Sidejacking* — the specific loss, not generic interception |
| `xfo-*`, `csp-frame-ancestors-*` | CAPEC-222 | *iFrame Overlay*, joins CWE-1021 |

**What this costs, stated so it is not later "fixed".** A sparse table cannot be
a bijection, unlike `CODE_HEADER`, `FINDING_SEVERITY` and `MESSAGES` beside it.
Its test runs one direction only: every id well-formed, every key an emittable
code. Nothing can prove the overlay is *complete*, because completeness is not a
property it claims — an absent entry means "no better id was found", not "none
exists". Do not convert it to a total table to make the test symmetrical; that
would mint 102 curated entries to satisfy a test rather than a reader.

## 4. Schema

```json
"response": {
  "findings": [
    {"header": "Content-Security-Policy", "code": "csp-unsafe-inline",
     "level": "error", "data": {"directives": ["script-src"]},
     "message": "present but allows unsafe-inline in script-src, …",
     "consequences": ["xss"]}
  ],
  "inventory": { },
  "references": {
    "headers": ["Content-Security-Policy", "X-Frame-Options"],
    "taxonomy": ["CAPEC-63", "CAPEC-103", "CWE-79", "CWE-1021"]
  }
}
```

Decisions inside that shape, each with an alternative that was considered:

- **Identifiers, not URLs.** A header name and a CWE id do not rot, and both
  resolve to a stable URL by pattern. Storing five URLs per header was the
  first design and it is curated data that ages — the objection that parks the
  vendor links. This is the same distinction the project draws everywhere:
  content it *derives* versus content it was *given*.
- **One `references` key, not references scattered through `findings[]` and the
  inventories.** Scattering puts the same MDN entry in six places and forces
  every consumer to merge six lists forever — the argument that already killed
  a top-level `findings` key.
- **`consequences` is per finding and always present, `[]` included**, so a
  consumer never tests for the key. That is the `data` rule.
- **`references` is per response, not per run.** One result cut out of a
  multi-target run stays self-contained.
- **Fed by findings only.** A header appears because something was said about
  it, `-missing` codes included. A response with nothing wrong gets two empty
  lists, which reads as "no reading needed". The alternative — every analysed
  header the response sent, so a flawless CSP still yields its link — was
  considered and rejected as the less predictable rule.
- **`taxonomy` rather than a `cwe` key, because the ids are self-prefixing.**
  `CWE-79`, `CAPEC-63`, and any future `TID-319` identify their own scheme, so
  unparking a taxonomy adds entries to an existing list instead of restructuring
  the schema — the same reasoning that made `source.kind` beat a source
  registry. Adding CAPEC after this design was first drafted cost zero schema
  change, which is the argument demonstrating itself.
- **Sorted by scheme then *numeric* id, deduped.** Not lexically, or `CWE-1021`
  sorts before `CWE-79`. This needs a comment at the sort or it will be tidied
  back.
- **`headers` is canonicalised** through the package's header tables, which is
  what stops `duplicate-headers`' lowercase producing a dead link.

## 5. `references.py`, a new leaf

```
message, catalog, references  ->  (nothing)
findings   ->  catalog (lazily, inside taxonomy(); catalog imports nothing, so
                this is not a cycle -- the import is deferred to keep catalog
                free to import findings later)
reporting  ->  response, findings, catalog
cli.commands  ->  ... + CODE_HEADER, CONSEQUENCES, consequences, references, taxonomy
```

**Corrected 2026-08-24.** This block originally read `findings, message,
catalog, references -> (nothing)`, filing `findings.py` as a leaf outright. It
is not one: `taxonomy()` imports `catalog` -- lazily, and with a comment that
(also wrongly) called a module-scope import a cycle. It would not have been
one either, since `catalog.py` imports nothing from this package; the real
reason for the lazy import is to keep `catalog.py` free to import `findings.py`
later. Both the code comment and this block were fixed in the same pass.

**`reporting.py` does not import `references`, and that is the point.** An
earlier draft of this block said it did — written before the decision below that
the report carries identifiers and never URLs, and left stale when that decision
landed. Nothing in the analyser resolves a link. `references.py` has exactly one
consumer, `cli/commands.py`, which resolves on demand for a human reader.

Exports `header_url(name)`, `taxonomy_url(id)`, and `HEADER_DOCS` — one
**positive** name-to-URL table, with an unknown name resolving to `None`. It is
built once at import from three small collections, so a reader sees the sources
of truth rather than 37 hand-written URLs:

```python
_MDN      = (...)   # 30 names, URL from the MDN pattern
_HTTP_DEV = (...)   #  7 names, URL from lower(name)
_SPEC     = {...}   #  3 names -> a literal permanent URL
```

**The header set is derived, not hand-listed.** It is the union of every header
a finding can name and every header an inventory carries — **40** today: 35 from
findings, 5 more (`Cache-Control`, `ETag`, `Expires`, `Last-Modified`, `Pragma`)
that only ever appear in an inventory. An earlier draft of this document counted
37 by assembling the set by hand from the canonical tuples, and silently omitted
the report-only siblings. Rebuild it by running the corpus, the way
`tests/test_headers.py` builds its code set, and never by typing out a list.

Positive, not a pair of "headers MDN lacks" exclusion sets, and the direction
matters: an exclusion set makes an unrecognised header fall through to the MDN
pattern and emit a URL that 404s, so the table **fails open** exactly when it is
most out of date. A positive table fails closed, and it makes the `None` branch
reachable by any header added later rather than only by a test fixture.

Separate from `catalog.py` so that module's "only prose lives here" claim stays
literally true, and because URLs have a different lifecycle from sentences.
`catalog.py` says *`xss` is CWE-79*; `references.py` says *CWE-79 lives at this
URL*.

**MDN derivation, measured against BCD on 2026-08-23.** Of the **40 headers**
above, **30 have an MDN page and all 30 sit at exactly**

```
https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/<Canonical-Name>
```

with **zero exceptions**, checked against `__compat.mdn_url` in
`ref/documentation/browser-compat-data/http/headers/`. The other **ten have no
MDN page at all**:

`Cross-Origin-Embedder-Policy-Report-Only`,
`Cross-Origin-Opener-Policy-Report-Only`, `Feature-Policy`, `P3P`,
`Public-Key-Pins`, `Public-Key-Pins-Report-Only`, `X-Content-Security-Policy`,
`X-Download-Options`, `X-Permitted-Cross-Domain-Policies`, `X-WebKit-CSP`.

All but the two report-only siblings are obsolete or never standardised, and
`Feature-Policy`'s absence
independently corroborates the existing note that `w3c/browser-specs` does not
carry it either.

**Resolution order is by publisher permanence policy, then documentation
quality.** That ordering is the whole design here, and it is not the same as
"official beats unofficial": the IETF and W3C both keep published documents in
perpetuity by written policy, MDN explicitly *redirects* a page when a header is
superseded, and http.dev states no policy at all. MDN's redirect-on-deprecation
is not hypothetical — it is exactly how `Feature-Policy` disappeared.

**Three of the ten have an official permanent source**, verified on disk in
`known-http-header-db`'s `specifications[]` and `rfc-library`:

| header | source |
|---|---|
| `Public-Key-Pins` | RFC 7469, `status: permanent` in the db |
| `Public-Key-Pins-Report-Only` | RFC 7469, same document |
| `P3P` | `https://www.w3.org/TR/P3P`, a W3C Recommendation nothing supersedes |

**Seven have no official source.** Two are the COOP and COEP report-only
siblings, documented by neither MDN nor a spec of their own. `X-Content-Security-Policy` and
`X-WebKit-CSP` sit in the db with an empty `specifications[]` — vendor prefixes,
never specified. `X-Download-Options` and `X-Permitted-Cross-Domain-Policies`
are absent from all 271 entries. And `Feature-Policy`'s only listed
specification is now *Permissions Policy* — so an aggregator built from MDN,
IANA and Wikipedia has overwritten it too, alongside MDN removing the page and
`w3c.github.io/webappsec-feature-policy/` redirecting to the permissions-policy
draft. Three independent sources have replaced it rather than archived it, which
makes `Feature-Policy` the **strongest** case for a non-official historical
source, not the weakest.

Those three entries are **curated URLs, the thing this design otherwise
refuses**, and the exception is deliberate: three links to rfc-editor.org and
w3.org, durable by their publishers' written policy, are a different risk class
from the vendor links parked at the top of this document. The distinction to
preserve is *permanence policy*, not *low count* — do not read this as licence
to add a fourth link because the table is still short.

**http.dev covers the remaining seven, and the sources turn out to be exactly
complementary.** Measured against `ref/documentation/http.dev` the same day:
**38 of the 40 resolve at `https://http.dev/<lower(name)>`**, the only misses
being `Integrity-Policy` and `Integrity-Policy-Report-Only` — both of which MDN
documents. All ten of the headers above are covered, with real pages of
62-66 KB rather than stubs. So MDN first, then a permanent spec, then http.dev,
and the union is **40/40 today**.

Three things about that:

- **Keep the `None` return anyway.** Complete coverage *today* invites deleting
  the branch as dead code; a header added tomorrow would be in neither source.
  The `None` path needs a test driven by a synthetic name, or it is a guard
  nothing exercises — the failure mode already recorded in the working
  practices, where a `None`-versus-`""` guard survived every mutation because
  its only caller tested truthiness.
- **Fallback, not both.** MDN is the better page for the 29, and a second
  general-reference link per header works against the reason identifiers beat
  URLs here: a short reading list that does not rot.
- **A noted exposure, decided rather than missed.** http.dev has no institution
  behind it, so its rot risk is higher than MDN's — acceptable, because after
  the three official sources above the fallback set is seven headers that no
  standards body documents. And its pages carry "Baseline"
  banners rendered from web-features, which is BCD at second hand and which
  this project already refuses to cite for browser support. Linking the page as
  a *reference* does not breach that rule, but it does point a reader at
  support claims made here from BCD directly. For seven headers whose support
  answer is "legacy or never", that is the cheapest such exposure available.

`taxonomy_url()`: `https://cwe.mitre.org/data/definitions/<n>.html` and
`https://capec.mitre.org/data/definitions/<n>.html`. Note CAPEC's own STIX
records the CWE URL as `http://`; use `https://`.

## 6. Terminal and `explain`

Findings gain a trailing bracketed slug list. "What could this lead to" is what
a reader runs the scan for, and slugs are short enough not to crowd the line.

```
  error   Content-Security-Policy
          present but allows unsafe-inline in script-src, defeating most of
          the cross-site scripting protection a policy provides
          [xss]
```

`explain` finally earns its keep, and is the reason `CODE_HEADER` is in scope:

```
$ hst explain csp-unsafe-inline
csp-unsafe-inline   error   Content-Security-Policy
present but allows unsafe-inline in {directives}, defeating most of the
cross-site scripting protection a policy provides

consequences: xss -- Cross-site scripting (CWE-79, CAPEC-63)
              Injected script could run in this origin. Whether it can is not
              determined here; this names the risk the setting creates.

  https://developer.mozilla.org/docs/Web/HTTP/Reference/Headers/Content-Security-Policy
  https://cwe.mitre.org/data/definitions/79.html
  https://capec.mitre.org/data/definitions/63.html
```

## 7. Invariants to pin

- `CODE_HEADER` is a bijection with the emittable codes, both directions.
- `CODE_CONSEQUENCES` likewise; a code with no consequence maps to `()`, never
  to absence.
- Every slug a code names is defined in `CONSEQUENCES`, and every defined slug
  is named by at least one code — the same both-directions check the severities
  and message templates have, so neither table can rot silently.
- `CODE_TAXONOMY` is the one deliberately partial table: one direction only, as
  set out above.
- For every corpus finding, the declared header equals the emitted header,
  compared case-insensitively; `duplicate-headers` exempt.
- URL helpers: shape only — `https`, parses, MDN before http.dev, and `None`
  for a name neither source covers, exercised with a synthetic name since no
  real header currently reaches it. **No fetching, in any test, ever.**
- The BCD agreement above is a **one-off verification recorded here, not a
  test**: the suite must not depend on `/home/crapula/ref` existing. Re-run it
  by hand if MDN restructures.
- `tests/cli_terminal_snapshot.txt` and `tests/rendered_messages.txt` regenerate
  deliberately, and the diff gets read.

## 8. Order of work

1. `CODE_HEADER` + its tests. Self-contained, closes a parked item, no schema
   change. Ships alone if the rest slips.
2. `references.py` + helpers + shape tests.
3. `Consequence` namedtuple, `CONSEQUENCES` in `catalog.py`, empty
   `CODE_CONSEQUENCES` in `findings.py`, bijection tests failing.
4. Map all 102 codes; tests go green.
5. `CODE_TAXONOMY` overlay, seeded with the verified entries above and whatever
   a pass over CAPEC per header family turns up.
6. `reporting.py`: `consequences` per finding, the `references` block.
7. `cli/text.py` rendering; regenerate the terminal snapshot.
8. `cli/commands.py`: `explain`.
9. `__init__.py` exports; CLAUDE.md.

## 9. For CLAUDE.md when this lands

Three facts cost a corpus query each and should not be re-derived:

- **CWE 4.20 has no weakness for MIME sniffing or XS-Leaks**, and none written
  for permission delegation. Do not re-propose CWE ids as the consequence
  vocabulary.
- **A Pillar-level CWE is not a fallback.** CWE-693 and CWE-284 are true of
  every finding here, so using one to fill a gap makes it mean "unclassified".
  The test is in the design doc.
- **CWE's cookie coverage is unusually rich** — 1004 (`HttpOnly`), 1275
  (`SameSite`), 614 (`Secure`), 315, 539, 565, 784 — which maps almost
  one-to-one onto the parked `Set-Cookie` prefix work.
- **Pick a CAPEC id by its CWE cross-reference, not by its name.** Keyword
  matching was wrong three times in a dozen here.

Also worth recording: the CWE corpus lives at `tmp/cwec_v4.20.xml`, gitignored
at `.gitignore:32` and outside `/home/crapula/ref` because no reliable upstream
repository of CWE was found. CAPEC is in the corpus proper, at
`ref/documentation/cti/capec/2.1/stix-capec.json`.
