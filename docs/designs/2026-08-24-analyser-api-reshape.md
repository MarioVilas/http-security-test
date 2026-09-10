# The analyser API reshape

Design notes for the input contract. Agreed in session on 2026-08-24;
**nothing here is implemented yet.**

This answers the TODO line *"change api to expect full request/response pairs
first, break down for just response, just headers, etc."* It replaces the
current entry points outright — there is no compatibility shim and none is
wanted. What does not change: the analyser still never fetches anything, still
carries no runtime dependency, and still answers only *"what is wrong with this
exchange"*.

The note it answers is older than the package's own maturity. `analyze_all` was
shaped around what shcheck's fetcher happened to be holding, and every input
added since has arrived as another parameter — `secure`, then `host`, then
`raw`, then `request_raw`. The subject of the analysis was never named, so
there was nowhere to put anything.

## What is wrong with the shape today

Five defects, one cause.

**1. `secure` and `host` are crumbs of a URL the caller already has.**
`cli/exchange.py` exists partly to derive them (`secure(url)`, `host(url)`), and
every file source on the roadmap — Burp XML, HAR, SAZ, WCAT — would have
re-implemented the same two derivations.

**2. `secure=True` is a policy default wearing a fact's clothes.** A caller who
omits it is told the response arrived over TLS. The HSTS suppression that
principle 2 rests on then silently stops applying. A package whose first
principle is *findings are facts* should not default a fact to the flattering
value.

**3. There is nowhere to put the status line.** This is the recorded cause of
`--all-hops` being blocked: a bare 301 emits six `-missing` warnings for headers
that protect a representation it does not carry, and an absent `Content-Type`
is not reported at all. Both are principle 4 firing because
`analyze_all(present, secure, host)` has no parameter that could hold a status.

**4. There is nowhere to take the one bit that closes the CORS gap.** The
2026-08-21 ruling says origin reflection is undetectable from a response and
what closes it is *"one bit the caller holds"* — whether the request's `Origin`
was forged — *"take the bit as an argument"*. There is no argument to take it
as.

**5. Four entry points, three normalisations.** `analyze_all` and `inventory`
each `_normalize(present)` independently and `report` calls both, so the
ordinary path normalises the same mapping twice.

## Scope

**In:** the input contract, the value types, the byte parser, the adaptors, the
fidelity field, the package layering, and the deletion of the old entry points.

**Out, deliberately, and each is unblocked by this work rather than done by
it:**

- Request *analysis*. `request.findings` and `request.inventory` stay parked;
  the request is carried and used only where it changes a response verdict.
- `<meta http-equiv>` parsing. Complex enough to be its own session; see
  *Meta-derived headers* below for the representation decided in advance.
- The three finding families this opens — protocol hygiene (HTTP/2 forbidding
  connection-specific headers), verb/preflight coherence, and TRACE/XST.
- `Content-Length` / `Transfer-Encoding` conflicts. That is request smuggling,
  `burp/http-request-smuggler`'s subject, and not a header question.
- Chain-level analysis. See *Hops and chains*.

Splitting this way is not timidity. The reshape is a refactor with a 555-test
suite holding it steady; each of the items above is a new corpus, new codes and
a new bijection to close. Landing them together means a failing test cannot say
which half broke.

## The shape

One entry point per output form, taking one argument.

```python
analyze(exchange)   -> [Finding, ...]      # objects
inventory(exchange) -> dict                # the five tables
report(exchange, message=True) -> dict     # plain data, as today's report()
```

`analyze_all(present, secure, host)`, `analyze(name, value)`, `inventory(present)`
and `report(present, secure, host, message, raw, request_raw)` are **deleted**.
`analyze(name, value)` becomes `_analyze_header(name, value)`, private, since
its only stated reason to be public was unit testing. `inventory()` remains
public but takes an `Exchange`.

### No decomposed entry points

The TODO says *"break down for just response, just headers, etc."* That
decomposition is real and it is preserved — but it lives **in the data as
optional fields**, not in the call graph as three functions.

This is the CLI's own precedent one layer down. `source.kind` was designed so
that *"the polymorphism lives in the document, not in the call graph, which is
why there is no source registry and should not be one until a second source
exists."* Three functions differing only in which fields are `None` would be
that registry by another name.

The rule that makes the degradation honest:

> **A missing input disables the checks that need it. It never defaults them.**

Today `secure=True` defaults it. That inversion is the actual design content of
the TODO note.

## The types

Three, all frozen, all in the analyser.

```python
Request:
    url        str            required
    method     str | None
    version    str | None     wire token: "HTTP/1.1", "HTTP/2"
    headers    ((str, str), ...)   ordered pairs, duplicates intact
    body       bytes | None
    raw        bytes | None
    fidelity   str | None

Response:
    status     int | None
    reason     str | None     absent for HTTP/2 by protocol
    version    str | None
    headers    ((str, str), ...)
    body       bytes | None
    raw        bytes | None
    fidelity   str | None

Exchange:
    request    Request
    response   Response
    timestamp  str | None          not on the wire
    connection Connection | None   host / ip / port / scheme actually used
```

### Why an `Exchange` type, reversing an earlier recommendation

Two loose arguments were recommended during the session, on the grounds that a
type should arrive with the rules that need it — the same argument that keeps
`exchange.py` unbuilt.

That was wrong, and the reason is data rather than rules. The **timestamp and
the connection info belong to neither message**. A request does not carry when
it was sent; `Date` is the server's clock and it is a response header. The
hostname, IP and port actually connected to are deliberately separate from
`Host:`, because a `Host:` header can be forged and Burp and mitmproxy both
model them apart for exactly that reason. Two loose arguments have nowhere to
put either fact, so the type is needed now even though the exchange-level
*rules* are all parked.

`Connection` is a nested type rather than four fields on `Exchange` so that
"we know nothing about the connection" is one `None` rather than four.

### Required and optional

> **Required = what is always knowable if you have a response at all.
> Optional = what is genuinely sometimes absent.**

`url` is required. You cannot possess a response without having requested a
URL, so a caller who cannot supply one is telling us something is wrong. Every
other field is optional, including `status` and `headers`, because a redacted
or truncated capture may genuinely lack them.

The cost, stated so it is a decision: **"just headers, no URL" ceases to be
expressible.** A middleware checking headers it is about to emit must write
`Request(url="https://example.invalid/")`. That is correct — it forces the
scheme to be *stated* rather than defaulted, which is the whole point of
defect 2 above.

### Headers are ordered pairs, not a mapping

The type stores `((name, value), ...)` exactly as received. The `present`
mapping the family analysers consume is **derived on demand**, not stored.

Storing pairs preserves three things a mapping loses: the order of *different*
header names, the interleaving of repeated ones, and enough information to
reproduce the head. `parse_headers()` becomes internal machinery rather than
the front door.

### Why the URL cannot come from the bytes

An HTTP/1.x request line is origin-form — `GET /login HTTP/1.1` — and the
authority comes from `Host:`. **Nothing in either says `http` or `https`.** That
is precisely what `secure` was, and it decides HSTS suppression,
`Reporting-Endpoints` applicability and the preload lookup.

Three routes out, of which only one is general: HTTP/2 and /3 carry `:scheme`
and `:authority` as pseudo-headers, but Burp's h2 export writes 1.1 syntax with
an ordinary `Host:` and an `HTTP/2` version token, so the pseudo-headers cannot
be relied on. Absolute-form request targets carry the scheme but are a proxy
form nobody captures. So the URL rides alongside, always, regardless of version.

Verified independently: **urllib3's response object cannot say where it came
from.** It has no `.request`, and `.url` is `/probe` — path only. CLAUDE.md's
*"a response does not know where it came from"* is literally true of at least
one real library.

### `urllib.parse` is used, and is lossy in our direction

Use it. Hand-rolling a URL parser is worse, and `response.py` already
hand-rolls one in `_delivers()` with `partition("://")`.

But it destroys exactly the data a security tool cares about. `urlsplit` strips
ASCII CR, LF and TAB from **anywhere** in the URL — the bpo-43882 /
CVE-2022-0391 hardening. Measured:

```
in  'https://example.com/x\r\nSet-Cookie: evil=1'
out  path='/xSet-Cookie: evil=1'     # CRLF gone, payload text kept
in  'https://exam\rple.com/'
out  hostname='example.com'          # clean host reported for dirty input
```

`geturl()` does not round-trip in either case, and nothing raises. The guard is
one comparison: **if the URL differs from itself with `\r\n\t` removed, keep
that as a fact** rather than trusting the parse. Whether it becomes a finding is
a later question; losing it silently is not acceptable now.

Everything else checked out: `.hostname` lowercases (only there), a trailing
root-zone dot is preserved in `netloc`, IPv6 brackets are handled, `.port`
raises on a bad value, and `https://example.com\@evil.com/` resolves to
`evil.com`, which is what browsers do.

Note that `urllib.parse` is pure string manipulation and `urllib.request` is
the fetcher. Importing the former in the analyser does not touch the
never-fetches rule — but CLAUDE.md should say so, because the next reader will
see `import urllib.parse` in the analyser and call it a breach.

## Constructors

```python
Response.from_bytes(data, *, fidelity=...)
Response.from_parts(status=..., reason=..., version=..., headers=..., body=...)
Request.from_bytes(data, url=..., *, fidelity=...)
Request.from_parts(url=..., method=..., version=..., headers=..., body=...)
```

`from_bytes` is **primary**, not a convenience. It is what makes a
byte-oriented source supportable at all, and it is the only way to handle a
library whose structured model is wrong — see scapy under *Adaptors*.

### What the byte parser must do

It is now a **parser of hostile input**, which this package currently is not.
Leniency stops being a style preference: a strict parser that raises on a
malformed response refuses to analyse exactly the response most worth
analysing, which is principle 4 in a new location.

- **Never raise on garbage.** Parse what is parseable, leave the rest `None`.
  Malformations become findings in a later pass, not exceptions now.
- **Accept `HTTP/2` in a 1.1-shaped start line.** Every capture tool writes
  this. Burp's own export, verified from a real project dump, is
  `POST /events/bulk/... HTTP/2` with `Host:` rather than `:authority`, and
  the response is `HTTP/2 202 Accepted` — a **synthesised reason phrase**,
  since RFC 9113 carries only `:status`. Rejecting this as malformed would
  refuse the most common real input there is.
- **Accept CRLF and bare LF**, and record which was seen if it is cheap.
- **Preserve duplicates and order.** This is the whole reason the pairs form
  exists.
- **Take the body as whatever follows the blank line**, with no decoding. The
  charset is itself a finding subject, so decoding here would apply a rule the
  package is simultaneously judging.

## Fidelity

The analyser is unopinionated about whether raw bytes are stored, and the CLI
decides. What the analyser **does** owe the consumer is an honest statement of
what the bytes are.

| value           | meaning                                            | examples                                                                                         |
| --------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `capture`       | the bytes as they crossed the wire                 | Burp base64 export, pycurl header lines, scapy, a pcap                                           |
| `reconstructed` | reassembled from a parsed model                    | mitmproxy `assemble_response()`, h11 `send()`, our own `from_parts()`, **every HTTP/2 exchange** |
| `redacted`      | a reconstruction known to have had content removed | the sample Burp HTML scanner report                                                              |
| absent          | nothing available                                  | anything built from a live library object                                                        |

Per **message**, not per exchange: pycurl can hand over a captured response
beside a reconstructed request.

### Fidelity is `source × protocol version`

Measured on the four libraries that can produce message bytes:

| library   | mechanism                                                                         | fidelity                                                                                       |
| --------- | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| pycurl    | `HEADERFUNCTION` — raw header lines, status line included, duplicates intact      | a genuine capture                                                                              |
| scapy     | `raw(pkt)` — byte-identical round trip, reason phrase, casing and order preserved | faithful                                                                                       |
| mitmproxy | `http1.assemble_response()`                                                       | reconstruction — *injects* lowercased `content-length`                                         |
| h11       | `Connection.send()`                                                               | reconstruction — emits `HTTP/1.1 200 \r\n`, **reason phrase dropped**, header names lowercased |

And the version half: **an HTTP/2 exchange can never be a true wire capture in
text form.** The start line does not exist on the wire and someone has to
invent it — Burp invents `Accepted`, and no tool can do better. So an h2
message is `reconstructed` however good its source.

### Reconstruction is never presented as capture

Built from a live object, `raw` is **absent** — never reassembled from parts.
`headers.as_bytes()` round-trips cleanly on well-formed input but silently
repairs obs-folds and odd whitespace, and presenting a normalisation as
captured evidence is worse than admitting there is none. This is *absent beats
empty* doing its job.

### Truncation demotes fidelity

If the CLI keeps only the `<head>` of an HTML response, those bytes are no
longer a capture — the head may be intact but what is stored is not what
crossed the wire. A truncating caller either withholds `raw` or declares the
demotion. Recorded here because it is the first real use of the field.

## Adaptors

`adaptors.py`, analyser-side, **third-party free** — every adaptor reads
attributes and imports nothing, so it adds no dependency and is mockable in
tests without installing anything.

They are a **convenience, not a requirement**. A caller who wants to control
loading, streaming or truncation constructs the types directly. The adaptor is
syntactic sugar for the case where our decisions are acceptable.

### Head-only: adaptors never touch the body

Forced, not chosen. `aiohttp.ClientResponse.read` and `.text` are coroutines,
so a synchronous adaptor **cannot** read an aiohttp body. If one supported
library structurally forbids it, "adaptors read the body" was never a uniform
design.

And where it is possible it is harmful: reading `requests`' `.content` on a
`stream=True` response materialises the whole body silently. It does not break
the caller — `iter_content()` still yields, replayed from the buffer — it
**defeats** them. They asked for streaming and got a full buffer with no error
to notice.

So an adaptor yields status, version, headers, method and URL. The body is
always the caller's explicit act, and the adaptor holds no resource policy at
all.

### The survey that decided which adaptors are worth shipping

Measured against a loopback server returning duplicate CSP and duplicate
`Set-Cookie`, except `werkzeug` and `starlette`, whose header types were
exercised on constructed pairs rather than a fetch.

| library                            | duplicate-preserving accessor  | `d[name]` returns |
| ---------------------------------- | ------------------------------ | ----------------- |
| stdlib `HTTPMessage`               | `.get_all()`, `.items()`       | first             |
| urllib3 `HTTPHeaderDict`           | `.getlist()`, `.items()`       | comma-joined      |
| aiohttp `CIMultiDict`              | `.getall()`, `.items()`        | first             |
| werkzeug `Headers`                 | `.get_all()`, `.items()`       | first             |
| starlette `Headers`                | `.getlist()`, `.items()`       | first             |
| httpx `Headers`                    | `.get_list()`                  | first             |
| tornado                            | `.get_list()`                  | first             |
| curl_cffi                          | `.get_list()`                  | first             |
| geventhttpclient                   | `.items()`                     | first             |
| **requests `CaseInsensitiveDict`** | **none — lost**                | comma-joined      |
| **niquests**                       | `.raw.headers`, or `.oheaders` | comma-joined      |
| **httplib2 `Response`**            | **none — a `dict` subclass**   | comma-joined      |
| **scapy**                          | **none — named fields**        | **last**          |

Five spellings for one operation, and four distinct wrong answers for the
naive one. **Comma-joined is a fourth row for CLAUDE.md's header-mapping
table**, and the nastiest of them, because unlike *first* and *last* it is
lossy in a way that still looks like a header value:

```
'a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT, b=2; Path=/'
   split on ',' -> 3 pieces for 2 cookies
```

`Expires` dates contain commas. That is the parked `Set-Cookie` work broken
before it is written, through a path nobody would see fail.

### No introspection dispatch

`requests.Response.headers` and `httpx.Response.headers` are both spelled
`.headers` and both dict-like, and one of them destroys data. A dispatch keyed
on attribute names picks the destroying one. A "try `get_all`, then `getlist`,
then `getall`, else `.items()`" chain — the obvious duck-typing shape — falls
all the way through to `.items()` for `requests`, silently, because
`CaseInsensitiveDict` has none of the three.

Named constructors only. The caller states which contract they are handing
over and we never guess.

### An adaptor's real job is normalisation

Not attribute lookup. The version field alone is encoded five ways:

| library                                       | value                           | means                                                               |
| --------------------------------------------- | ------------------------------- | ------------------------------------------------------------------- |
| httpx, geventhttpclient, mitmproxy            | `'HTTP/1.1'`                    | wire token                                                          |
| stdlib, requests, niquests, urllib3, httplib2 | `11`                            | int                                                                 |
| aiohttp                                       | `HttpVersion(major=1, minor=1)` | namedtuple                                                          |
| **pycurl, curl_cffi**                         | **`2`**                         | **HTTP/1.1** — `CurlHttpVersion.V1_1 == 2`, `V2_0 == 3`, `V3 == 30` |
| tornado                                       | *absent*                        | —                                                                   |

libcurl's `2` reads as "HTTP/2" and is not. That is the trap an adaptor exists
to own, and it is libcurl's rather than curl_cffi's — pycurl reports it too.

### Which ship

**Ship:** `requests`, `niquests`, `httpx`, `aiohttp`, `urllib3`, `http.client`,
`tornado`, `curl_cffi`, `pycurl`, `geventhttpclient`, `mitmproxy`, `scapy`.
Also the server-side header types where the same normalisation applies —
`werkzeug`, `starlette` — for a framework checking a response it is about to
emit.

Two adaptors carry knowledge that is the whole of their value:

- **`from_requests` / `from_niquests` must read `.raw.headers`**, never
  `.headers`. Five lines whose entire point is knowing which of two attributes
  to touch.
- **`from_scapy` must ignore the library's model entirely** — take `raw(pkt)`
  and hand it to `from_bytes()`. scapy is the exact inverse of every other
  library: flawless bytes, last-wins fields. Without `from_bytes()` there is no
  way to support it except by consuming a model we have proved wrong.

**Do not ship: `httplib2`.** Its `Response` is a `dict` subclass; duplicates
are comma-joined with no accessor and no underlying object. The data is
destroyed before we could see it. Its absence is documented with that reason so
it reads as a deliberate exclusion rather than an oversight.

`mechanize`, `treq`, `aiosonic`, `asks`, `grequests`, `MechanicalSoup` are
wrappers; survey each while writing its adaptor, since the only question about
them is which underlying object they expose.

## Package layering

```
core        findings, catalog, message, references, csp, hsts, isolation,
            policies, legacy, response, reporting     -> stdlib only
adaptors    live library objects -> core types        -> imports core; third-party free
formats     Burp XML, HAR, SAZ, WCAT                  -> imports core; extras allowed
cli         argv, orchestration, writers, live.py     -> imports all of the above
```

The invariant gets **stronger**. Today it is a single-name check — nothing
outside `cli/` may import `cli`, one AST walk. It becomes a direction rule:
*each layer may import only from layers below it*, which catches things the
current test cannot, such as a format parser reaching into `adaptors`.

**`__init__` exports the core only.** `import http_security_test` currently
gives everything but the CLI; after this it gives the core, and `adaptors` and
`formats` are explicit imports. That is what keeps the base import cheap and
dependency-free, and it is a behaviour change worth calling out rather than
discovering.

### `live.py` stays in `cli/`

The one carve-out, and the reason is the claim the project rests on. CLAUDE.md's
headline is *"it never fetches anything"* — unconditional. Promote `live` to a
peer subpackage and the strongest honest phrasing becomes *"it will not fetch
unless you import the part that does."* The technical guarantee survives;
the sentence a Burp extension author reads while auditing what they are
embedding does not.

`live.py` is also this project's opinionated implementation for its own CLI —
one library, one set of decisions. A library consumer who wants to fetch uses
their own client plus an adaptor, which is the better path anyway.

### `formats/` is decided now and built later

Zero implementations today, four planned. By the project's own
three-implementations rule the directory has not earned itself, so the
**decision** is recorded and the first parser lands there rather than in
`cli/` — the same reserve-the-decision-not-the-code pattern as `--probe`.

This reverses an earlier conclusion in the session, and the reversal is the
point. With only two homes, "a Burp export is a tool artifact — `burpVersion`,
`exportTime`, per-item `comment`, most of it never on a wire" argued for
`cli/` by elimination. A third home makes the category honest: `formats/` is
neither the analyser nor the tool, it is *readers of other tools' stored
traffic*, which is exactly what those parsers are.

Three facts for whoever writes them:

- **Third-party dependencies are acceptable here**, behind extras, and should
  be declared with the `[preload]` comment's discipline — what you lose, not
  what breaks.
- **Parsers take a file object and yield exchanges lazily**, never a path and
  never bytes. `cli/commands.py` opens the file. `cli/exchange.py` already
  commits to this: *"a source yields an **iterable** of these, never a single
  one."*
- **The formats do not stream equally.** Burp XML does —
  `iterparse(fh, events=("end",))` plus `elem.clear()` per `<item>`, verified
  on a real export, and it works off `io.BytesIO` so tests need no disk.
  Constant memory follows from `elem.clear()` rather than having been
  measured on a large file. SAZ does, being a ZIP. **HAR does not**: `json` exposes only
  `decode` and `raw_decode`, so the format that looks easiest is the one that
  forces a choice — load it all, hand-roll a `raw_decode` scanner over
  `entries`, or take a dependency. That is the hinge that makes `formats/`
  worth having.

Stdlib parses Burp's export today, incidentally: `xml.etree.ElementTree` reads
both the cdata and base64 forms including the DOCTYPE, and does not resolve
external entities. Internal entity expansion does work, so billion-laughs is
theoretically live; against a file the operator chose to open, that does not
justify a dependency. Prefer the base64 form when both are offered — Burp's own
DOCTYPE comment says the cdata form preserves NULL bytes *"even though this
strictly breaks the XML syntax"*.

## What moves out of `cli/exchange.py`

`Exchange(kind, target, url, status, reason, headers, hops, raw_response, raw_request)` is a mixture of two things, and it is a mixture because the
analyser had nowhere to put its half.

| field                                         | goes to      | why                                           |
| --------------------------------------------- | ------------ | --------------------------------------------- |
| `url`, `status`, `reason`, `headers`, `raw_*` | **analyser** | message facts                                 |
| `kind`, `target`, `hops`                      | **CLI**      | run facts; they feed `source` in the envelope |
| `Failure`, `FAILURE_KINDS`                    | **CLI**      | run facts                                     |

The rule, which is the documented output rule applied to the input:

> The analyser owns the shape of what it **consumes**, what it **returns**, and
> its own **accuracy**. The CLI owns the shape of what it **writes to disk**.

`secure()` and `host()` are **deleted**. They exist for no reason except to
crumble a URL on the analyser's behalf.

### Hops and chains

`Hop(origin, code, destination, followed, refused)` splits along the same line.
`origin`, `code` and `destination` are wire facts and all three are *derivable
from a list of exchanges* — `request.url`, `response.status`, and `Location`
resolved against the former. `followed` and `refused` are `--scope` outcomes:
what the tool chose to do, run facts by construction.

So `Hop` stays in the CLI and no chain type is added. The analyser needs
nothing new to gain chain analysis later — only an ordered list of exchanges,
which it will already have, plus the chain *rules*, which are the real work and
are parked. Forward-compatibility cost: zero, because `Response.status` and
`Request.url` are already in.

## Output

`report()` returns the shape it returns today, with one addition and one
subtraction.

**Added:** each message's `fidelity`, beside its `raw`. A consumer re-analysing
an archived report needs to know whether re-parsing those bytes reproduces the
findings — `capture` yes, `reconstructed` approximately, `redacted` no.

**Unchanged and worth restating:** there is still no URL key. A response does
not know where it came from; run facts live in the envelope's `source`. Taking
a URL as *input* does not violate that rule, which is about what a report
claims to know about itself.

**The credential warning stays.** It is not a redaction feature and never was —
it reads *"Nothing here can police it… Passing only the header block,
redacting, or passing nothing, is the caller's call"*, which is the correct
position. Redaction is a requirement of pentest *reports*, not of pentest
*work files*; Burp redacts nothing. What was wrong was an inference drawn from
that note during the session, that redaction and analysis must be separable
inputs. Dropped.

## Meta-derived headers

Not implemented in this pass. The representation is decided now so the shape
does not break when it lands.

**`Response.meta`, a sibling mapping to `headers`**, analysed separately and
reconciled by a cross-header rule in `response.py`. Family analysers keep their
contract — value in, findings out, no knowledge of provenance — and `headers`
keeps meaning exactly what it means today.

Merging meta into `headers` at parse time was rejected: it is lossy in the
direction of the finding you wanted. A meta CSP carrying `frame-ancestors` is a
real defect, and merging drops the evidence for it — principle 4 inverted,
manufacturing false negatives.

Provenance belongs in `data` as `{"origin": "meta"}`, so `identity()` does the
right thing for free: a header CSP and a meta CSP both carrying `unsafe-inline`
become two findings, which is correct, because they are two places to edit.

Two closed value sets make this cheap, both verified:

- **HTML defines exactly seven `http-equiv` states** (`w3c/webref`
  `ed/dfns/html.json`, under *Pragma directives*): `content-language`,
  `content-type`, `default-style`, `refresh`, `set-cookie`, `x-ua-compatible`,
  `content-security-policy`. So `<meta http-equiv="X-Frame-Options">` is not a
  header that behaves differently — it is **not a header at all**, and neither
  are HSTS, COOP or CORP. (`Referrer-Policy` enters by a different door,
  `<meta name="referrer">`.)
- **Four CSP directives are ignored in meta.** Chromium
  `services/network/public/cpp/content_security_policy/`
  `content_security_policy.cc:214`, `SupportedInMeta()` returns false for
  `frame-ancestors`, `report-uri`, `sandbox` and `treat-as-public-address`, and
  true for everything else, emitting *"ignored when delivered via a `<meta>`
  element"* into `parsing_errors`.

Two things not verified and to pin down when it lands: whether HTML's
`set-cookie` pragma state is defined-but-inert, and whether Firefox's
equivalent of `SupportedInMeta` matches Chromium's four.

## Open question for review

**Does the status line get *used* in this pass, or only carried?**

Scope says shape-only, and by that reading `status` is a field nothing reads —
which is the same thing as the `body` field turned down earlier in the session,
and inconsistent with the rule we adopted.

The argument for using it is that this one is not a feature waiting on a field,
it is a **measured bug**: a bare 301 emits six `-missing` warnings today, and
the fix is a suppression rule in `response.py` rather than new codes or a new
corpus. Leaving it out means knowingly shipping a false positive we have
already measured, on the very pass that removes the reason it existed.

Recommendation: **use it**, as the single behavioural exception, and keep
`--all-hops` itself parked.

## What was measured rather than recalled

So a later reader can re-check rather than re-derive:

- HTTP/1.x carries no scheme; urllib3's response has no `.request` and its
  `.url` is path-only.
- `urlsplit` strips CR/LF/TAB anywhere in a URL and `geturl()` does not
  round-trip.
- Duplicate-header behaviour across 13 header containers, against a loopback
  server; `requests`, `niquests`, `httplib2` and `scapy` lose them by four
  different mechanisms.
- Version encodings across 12 libraries; `CurlHttpVersion.V1_1 == 2`.
- `aiohttp.ClientResponse.read`/`.text` are coroutines; `requests` `.content`
  on `stream=True` buffers without breaking `iter_content()`.
- Byte-production fidelity for pycurl, scapy, mitmproxy and h11.
- Burp's export: both forms decode byte-identically, 22 CRLFs, no bare LF;
  request line `POST /... HTTP/2`; response line `HTTP/2 202 Accepted` with a
  synthesised reason phrase. That dump also carries
  `Access-Control-Allow-Methods` and `Access-Control-Max-Age` on a
  **non-preflight** POST response — a live specimen of the verb gap, since
  Fetch consults `Access-Control-Allow-Methods` in exactly one algorithm,
  *CORS-preflight fetch* (`w3c/webref` `ed/algorithms/fetch.json`).
- RFC 9113 §8.2.2: `Connection`, `Proxy-Connection`, `Keep-Alive`,
  `Transfer-Encoding` and `Upgrade` in an HTTP/2 message *"MUST be treated as
  malformed"*, with `TE` restricted to `trailers`.
- `xml.etree.ElementTree` parses both Burp export forms and does not resolve
  external entities; `iterparse` streams from a file object and from
  `io.BytesIO`; `json` has no incremental API.
