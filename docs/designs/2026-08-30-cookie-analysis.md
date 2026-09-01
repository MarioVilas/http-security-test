# Cookie analysis

`Set-Cookie` parsing and analysis: a new core family module, a sixth inventory
table, sixteen codes, and one change to the finding type that the rest of the
package has been ready for since `identity()` was widened.

This closes the **`Set-Cookie` analysis** item parked in CLAUDE.md. It
deliberately does *not* close the two cache items parked alongside it; see
**Scope**.

Nothing here needs the network, a body, or a second request. Every rule is
decidable from one response plus the request URL that produced it.

## Why cookies do not fit the shape as it stands

Three things about `Set-Cookie` break assumptions the other twenty-odd headers
share, and all three were anticipated rather than discovered.

**One header is many subjects.** `Set-Cookie` is in `REPEATABLE_HEADERS`, and
unlike repeated CSP -- where the policies compose into one verdict -- repeated
`Set-Cookie` is N unrelated cookies. A finding is about one of them, so the same
code fires more than once against one header. `identity()` was widened from
`(header, code)` to `(header, code, data)` for exactly this case, with the
comment naming it: *"two cookies each missing `Secure` will be two more"*.
Nothing in the package exercises that today. This is the feature that collects.

**The rules need a fact the value does not carry.** Every cookie-prefix rule is
gated on the response having come from a trustworthy origin, so a value-in
findings-out analyzer cannot answer them. There is precedent and it is not a
concession: `hsts._analyze_preload(present, host)` and
`response._analyze_reporting_endpoints(present, secure, host)` already take
exchange facts, because the question is not answerable otherwise.

**The judgement is not uniform across cookies.** Every other header in this
package means one thing wherever it appears. A missing `HttpOnly` on a session
token is a real defect and the same absence on `lang=en` is nothing, and no
header says which is which. That is the whole design problem, and it is
addressed in **Rating** rather than dodged.

## Scope

In:

- Parsing `Set-Cookie` per rfc6265bis 5.2, exactly.
- A parsed cookie model in `inventory()`.
- Sixteen finding codes: nine where the browser rejects or degrades the
  cookie, six hardening gaps, one about attribute names.
- Per-finding severity, replacing the assumption that a code has exactly one.
- Two new consequence slugs.

Out, each for a stated reason:

- **The request `Cookie` header.** It needs `request.py` and the `request`
  half of the report schema, both parked. Nothing here forecloses it.
- **The cache/cookie cross-header rule** (RFC 9111 7.3) and
  **`pragma-ineffective`**. CLAUDE.md says to land the first *with* the cookie
  parser, and the signals it needs do arrive here. It is still deferred,
  because judging "does any `Cache-Control` prevent storage" means reading
  cache *values*, and `inventory()`'s docstring currently promises the
  `caching` table means **never analysed**. Breaking that promise is a
  decision about the caching contract, and it should be made when caching is
  the subject rather than as a rider on a cookie change. Both remain parked,
  together, and the trigger CLAUDE.md records is unchanged.
- **Judging whether a `Domain` is over-broad.** Requires a public suffix list.
  CLAUDE.md's ruling is PSL-or-nothing. A `Domain` that is not a suffix of the
  request host is still reported, because that needs no PSL.
- **Cookie value entropy, or guessing what a value contains.** Out of reach of
  a header analyser and squarely principle 4.

## The module

`cookies.py`, in `core`: standard library only, imports `findings` and
`message`, imported by `response.py`. No new layer; `test_imports_only_ever_
run_downhill` is unaffected.

```python
Cookie = collections.namedtuple("Cookie", "name value attributes raw")

parse_set_cookie(value) -> Cookie        # never None; see below
parse_cookies(present)  -> tuple[Cookie] # over present["set-cookie"], in order
analyze_cookies(present, trustworthy, host) -> [Finding]
```

`response.analyze()` gains one `findings.extend(...)` call beside the existing
seven. `response.inventory()` gains one key. `response.py` grows by about four
lines; it is 1237 already and none of this belongs in it.

### `parse_set_cookie` never returns `None`

The obvious alternative -- return `None` for a value the browser discards
entirely -- was rejected. It makes the inventory lie: a cookie the server
really did send would vanish from `inventory.cookies`, and a reader could not
tell it from a response that never sent one. That is principle 2, and it is
the same oversight that put `Integrity-Policy` into an inventory on
2026-08-24.

So parsing is total. The inventory reports **what the response sent**; the
findings report **what a browser does with it**. A `Set-Cookie` carrying a
control character appears in the inventory in full and raises
`cookie-control-character` saying it is discarded.

### Parsing follows rfc6265bis 5.2 literally

Read from `w3c/webref` `ed/algorithms/rfc6265bis.json`, algorithms [5] and
[6]:

1. Split the set-cookie-string at the first `;`. Everything before is the
   name-value-pair, everything after is unparsed-attributes.
2. Split the name-value-pair at the **first** `=`. If there is no `=`, the
   name is empty and the value is the whole string. (This is what makes
   `cookie-hidden-prefix` reachable.)
3. Strip leading and trailing WSP from both.
4. For each attribute: discard the `;`, take up to the next `;`, split at the
   first `=`, strip WSP, lowercase the attribute name.
5. Unrecognised attribute names are kept, not dropped. The spec says a UA
   ignores them and both engines do; this package **reports** them, which is
   `cookie-unknown-attribute` below.

`attributes` on the `Cookie` is the lowercased mapping, with valueless
attributes mapping to `None`, which is the same convention
`hsts._parse_directives()` already uses. Every attribute the header carried is
in it, recognised or not: the parser records, the analysis judges.

**No regex over a joined header, ever.** `mapping()` keeps `set-cookie` as a
list of values because it is in `REPEATABLE_HEADERS`, so the parser is handed
the real values and never sees a join. This matters because the nearest peer
gets it wrong: `humble.py:5388` reads `headers_l.get("set-cookie")` -- the
comma-joined string -- and re-splits it at `:1437`, so two cookies where one
carries an `Expires` date yield three fragments, the date's internal comma
being indistinguishable from the join. CLAUDE.md documents that trap for
`requests`' `CaseInsensitiveDict`; this is the feature that would have hit it.

## The inventory table

`inventory()` gains a sixth key, `cookies`, a **list** in response order:

```json
{"name": "sid", "value": "abc123",
 "secure": true, "httponly": true, "samesite": "Strict",
 "path": "/", "domain": null, "expires": null, "max_age": null,
 "partitioned": false, "judged": true,
 "raw": "sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"}
```

Decisions inside that shape:

- **A list, not a name-keyed map.** One response may set the same cookie name
  twice, and a map would silently drop one -- the same reason the run envelope
  carries a list of results rather than a URL-keyed map.
- **Derived keys are always present**, `null` for an absent attribute, matching
  `data`'s always-present rule. `secure`, `httponly` and `partitioned` are
  booleans and are never `null`: the attribute is a flag, so absent is `false`
  rather than unknown.
- **`raw` per cookie**, verbatim. The other five inventory tables map a name to
  the value as sent and are lossless by construction; a parsed model is lossy.
  Attribute order, casing, repeated attributes and anything unrecognised are
  recoverable only from the source line, and `inventory()` promises "what the
  response carries, before anything is judged about it".
- **`judged`** is `false` when the suppression list applies, and `true`
  otherwise. It makes a suppression auditable rather than invisible: a reader
  who wonders why `BIGipServerpool_web` has no finding despite lacking `Secure`
  can see that the tool decided, rather than missed it. This is principle 1
  -- ratings are policy, but published -- applied to the decision not to rate.
- **The value is carried in full.** This package does not redact. It is a
  working tool for a pentester, not a generator of client deliverables, and
  redaction before anything reaches a report is the consumer's business.
  Principle 2 says nothing is withheld from an inventory because of what it
  contains, and a cookie value is the sharpest case of that rule, not an
  exception to it.

`Set-Cookie` does **not** join `PRESENT_ONLY_HEADERS`, so it does not also
appear in `inventory.security`. The parsed table carries the raw line already
and the same content in two places is what the `references` design rejected.

## Per-finding severity

`Finding` grows a fourth field:

```python
Finding = collections.namedtuple("Finding", "header code data level",
                                 defaults=(None, None))
```

`level=None` means "use the table". `FINDING_SEVERITY` stops being a code's
only rating and becomes its **default**.

```python
def level_of(finding):
    """The finding's own level, or its code's default."""
    return finding.level or severity(finding.code)
```

`order_findings()` (`findings.py:531`) and `reporting.finding_as_dict()`
(`reporting.py:140`) switch to `level_of`. Those are the only two consumers of
`severity(finding.code)` in the package; everything else that touches
`FINDING_SEVERITY` treats it as a table about codes. `severity(code)` stays
public and unchanged. `identity()` ignores `level`, which stays coherent
because the level is always derived from `data`.

**Why not two codes per tier**, which needs no change at all: because
`cookie-no-httponly` and a hypothetical `cookie-sensitive-no-httponly` are not
two defects. They are one defect the tool weighs differently, and principle 1
says the fact is the finding while the rating is policy. Encoding a policy
distinction as a code distinction puts it on the wrong side of that line, and
doubles the code count for each attribute that wants it.

**This is SARIF's own shape**, which the ratings already follow. `result.level`
is a first-class property that overrides `rule.defaultConfiguration.level`. The
schema is already on this side of the line too: `report()` denormalises `level`
onto every finding, and the CLI's `--min-level` filters on `finding["level"]`
out of the document, not on the code. Only the producer was per-code.

`hst explain` prints the default. Codes whose level can be raised are listed in
a new `ESCALATABLE` frozenset in `findings.py` and print as `note (may
escalate)`, so the verb does not quietly misreport.

## Findings

### Tier 1 -- the browser rejects or degrades the cookie

Nine codes, all `error`, all fixed-rating, all firing on **every** cookie
including suppressed ones. None of these is a judgement about sensitivity: each
says the response asked for something it did not get, which is principle 3's
definition of `error` and is true whatever the cookie holds.

| code | fires when |
|---|---|
| `cookie-samesite-none-insecure` | `SameSite=None` without `Secure` |
| `cookie-secure-over-plaintext` | `Secure` set from a non-trustworthy origin |
| `cookie-prefix-violated` | a name prefix whose requirements are unmet |
| `cookie-hidden-prefix` | nameless cookie whose value starts with a prefix |
| `cookie-control-character` | a CTL character; the header is discarded |
| `cookie-oversized` | name + value over 4096 octets; discarded |
| `cookie-samesite-invalid` | a `SameSite` value that is not None/Lax/Strict |
| `cookie-partitioned-insecure` | `Partitioned` without `Secure` |
| `cookie-domain-mismatch` | `Domain` is not a suffix of the request host |

`data` carries the cookie name in every case, plus what the code needs:
`cookie-prefix-violated` carries `{"prefix": "__Host-", "unmet":
["path", "domain"]}`, `cookie-oversized` carries `{"octets": 5142}`,
`cookie-samesite-invalid` carries `{"value": "Strictt"}` -- with no `value` key
at all for the bare-flag spelling `SameSite` with no `=`, since there is
nothing to quote back and a placeholder read as `SameSite=(none)`, telling the
reader the response wrote something it did not.

Four of the nine deserve their reasoning recorded:

**`cookie-secure-over-plaintext` is an error, not a note.** The instinct is
that a `Secure` cookie on a plaintext response is merely pointless. It is
worse: Chromium adds `EXCLUDE_SECURE_ONLY` and the cookie is not stored at all
(`net/cookies/cookie_base.cc:124`), and Firefox refuses to send it
(`netwerk/cookie/CookieService.cpp:1038`). The server believes it set a cookie
and did not.

**"Trustworthy", not "https".** Both engines carve out loopback:
Chromium's `ProvisionalAccessScheme` (`net/cookies/cookie_util.cc:709`) returns
`kTrustworthy` for localhost. `response.py` already implements this predicate
as `_is_loopback()` for reporting endpoints; reuse it rather than testing the
scheme. Testing `https` alone would fire on every developer running against
`http://localhost`, which is principle 4.

**`cookie-samesite-invalid` is an error.** An unrecognised value does not fall
back to `None`; rfc6265bis algorithm [11] sets enforcement to `Default`. In
Chrome `Default` is Lax, which is close to the intent. In Firefox and Safari
release it is no restriction at all, because BCD's
`SameSite.Lax_default` is Chrome 80 / Firefox 69 behind a flag / Safari
`false`. So `SameSite=Strictt` asks for the strongest protection and receives
none in two engines: the header does not deliver the protection its presence
implies.

**`cookie-hidden-prefix` is not a curiosity.** layered-cookies step 17 rejects
a nameless cookie whose value, byte-lowercased, starts with a prefix.
Chromium implements it as `HasHiddenPrefixName`
(`net/cookies/cookie_util.cc:796`), matching case-insensitively after trimming
leading SP/HTAB. The case it stops is `Set-Cookie: =__Host-sid=x`, which
something downstream re-parses as a `__Host-sid` cookie that never met the
rules.

### The four prefixes

`__Secure-`, `__Http-`, `__Host-`, `__Host-Http-`. All four build on
`__Secure-`, and `__Host-Http-` is the conjunction of the two below it: a
lattice, not a chain, so `__Host-` does **not** imply `HttpOnly`.

| prefix | requires |
|---|---|
| `__Secure-` | `Secure`, on a trustworthy origin |
| `__Http-` | `Secure` + `HttpOnly` |
| `__Host-` | `Secure` + `Path=/` + no `Domain` |
| `__Host-Http-` | `Secure` + `HttpOnly` + `Path=/` + no `Domain` |

Three implementation traps, each verified rather than assumed:

- **Match longest-prefix-first.** Both engines order their tables so
  `__Host-Http-` is tested before `__Host-`, and both carry a comment saying
  why (Firefox `netwerk/cookie/CookiePrefixes.cpp`; Chromium
  `net/cookies/cookie_util.cc:342`). A naive `startswith("__Host-")`
  classifies `__Host-Http-sid` as `__Host-` and then fails to require
  `HttpOnly` -- a false negative that looks like a pass.
- **Matching is case-INSENSITIVE**, contradicting the obvious reading of the
  spec. Chromium uses `CompareCase::INSENSITIVE_ASCII`
  (`cookie_util.cc:788`); Firefox uses `nsCaseInsensitiveCStringComparator`
  and explains it in a comment. rfc6265bis 5.4 requires it of UAs even though
  4.1.3 describes the prefixes with case-sensitive wording, because that
  wording is about server-side semantics. `__SECURE-sid` is held to the
  `__Secure-` rules.
- **Cookie names themselves stay case-sensitive.** `__Secure-foo` and
  `__secure-foo` are two distinct cookies that both satisfy the prefix rules.
  The name in `data` is a case-sensitive identifier even though the prefix
  test is not.

One Chromium wrinkle Firefox lacks: `__Host-` tolerates a `Domain` attribute
when the host is an IP literal equal to it
(`HasValidHostPrefixAttributes`, `cookie_util.cc:120`). Implemented, because
refusing it would be a false positive on a configuration Chrome accepts.

Ratings note: `http_host-http_prefixes` is Chrome 140 / Firefox 143 / Safari
`false` (BCD), against `host_secure_prefixes` at Chrome 49 / Firefox 50 /
Safari 13. A `__Http-` violation is therefore not enforced everywhere, which
is *why* it still rates `error`: in Safari the cookie is stored without the
guarantee its name advertises, which is the same defect from the other side.

### Attribute names -- one code, never suppressed

`cookie-unknown-attribute`, fixed `note`, consequences `()`. Fires once per
attribute name the browsers do not recognise, carrying
`{"cookie": name, "attribute": "secrue", "suspected": "Secure"}`, with
`suspected` absent when there is no near match. The two keys are cased
differently on purpose: `attribute` is the wire as the parser read it, which
lowercases attribute names, while `suspected` names the attribute the author
MEANT to write and is spelled canonically -- "a misspelling of httponly" reads
wrong for a name nobody writes that way.

**The recognised set is the browser union, not the spec's list.** Nine names,
being Chromium's (`net/cookies/parsed_cookie.cc:62-70`) which is a superset of
Firefox's eight (`netwerk/cookie/CookieParser.cpp:306-315`):

```
path  domain  expires  max-age  secure  httponly  samesite  partitioned
priority
```

`priority` is the one that matters for this choice. It is Chrome-proprietary
and was never standardised, so an rfc6265bis-derived set would omit it -- and
Google sends it on its own cookies, so the note would fire on some of the most
visited responses on the web. Firefox ignores it, which is *why* it is on the
recognised list rather than reported: a header this package cannot fault
Chrome for reading is not a defect anywhere.

**Not suppressed for infrastructure cookies.** What the response sent is a
fact independent of whether the cookie carries a credential, and a legacy
attribute is likeliest exactly on a vendor cookie -- a `Version=1; Port="80"`
survives in a load balancer's output long after nothing reads it. Same
reasoning that keeps tier 1 unsuppressed: this is a correctness statement, not
a sensitivity judgement.

**It stays a `note` even when it is a typo**, because the note asserts no
defect -- it says a name was not recognised, which is true whatever a future
spec does. The defect, when there is one, is reported by the *absence* finding
the typo explains, and the typo is what raises that finding to `error`; see
the ladder. That split is why this code needs no consequence slugs and why it
does not need three variants to carry the right ones.

**Future-proofing, stated plainly**, because it is the obvious objection: a
new attribute lands and this fires on a correct configuration. It costs a
`note` and the note remains literally true -- the analyser does not recognise
the name. Staleness here produces noise, never a wrong claim, which is the
test CLAUDE.md applies when it admits `INFORMATION_HEADERS` and refuses
csp-evaluator's bypass lists. The dead RFC 2965 set --
`Version`, `Comment`, `CommentURL`, `Discard`, `Port` -- makes it earn its
keep on day one, and feeds the parked hygiene axis directly.

### Tier 2 -- hardening, laddered

Six codes. Floor `note`, raised to `warning` when the response gives evidence
the cookie matters, and to `error` on a misspelled attribute. Suppressed
entirely for the infrastructure names below.

`cookie-no-secure` `cookie-no-httponly` `cookie-no-samesite`
`cookie-samesite-none` `cookie-persistent` `cookie-domain-broad`

The last three are not restatements of inventory fields once laddered. A
*session* cookie deliberately sent cross-site, written to disk, or scoped to a
parent domain where any subdomain takeover reaches it, is each a real finding;
the same three facts on `lang=en` are not. That is exactly what the ladder is
for, so they cost no mechanism beyond the three they share.

**`cookie-persistent` excludes deletion, and does so without reading a
clock.** `Max-Age` with `delta-seconds <= 0`, and an `Expires` at or before the
response's own `Date`, both ask a browser to discard the cookie immediately,
which is the opposite of what this code reports. A Django-style logout response
-- `sessionid=""; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure;
SameSite=Lax` -- is not "written to disk and outlives the session"; it is the
mechanism by which the session ends, and because `sessionid` is also on the
escalation list, the loudest instance of getting this wrong would have landed
on the single most common *correct* case on the web.

**The `Expires` cutoff is the response's own `Date`, falling back to
1970-01-02 when the response sent none.** That is still clock-free in the sense
the rule exists to protect: the verdict must not depend on when the tool
happened to run, and `Date` is a fact carried *in the response*, so an archived
report re-analysed a year later reaches the same verdict. The epoch alone was
the first design and it misses the canonical ASP.NET Framework delete --
`Expires = DateTime.Now.AddDays(-1)` with no `Max-Age`, an ordinary past date
rather than 1970, read as persistence and then escalated because
`asp.net_sessionid` is on the escalation list. PHP, Django, Rails, Express and
Tomcat all write `Max-Age=0` or an epoch `Expires` and escaped that; ASP.NET
does not. With no readable `Date` the residual stands and is a recorded limit.

**`Max-Age` is `[ "-" ] 1*DIGIT` or it is not a `Max-Age` at all.** rfc6265bis
algorithm [8] says an invalid `delta-seconds` means *"ignore the cookie-av"* --
not a deletion, which is what an earlier draft of this section claimed. So
`Max-Age=abc; Expires=<future>` falls through to the `Expires` and is
persistent, exactly as it is in every browser, and `Max-Age=1_000` is an
ignored av rather than 1000 seconds (`int()` is looser than the grammar:
underscores, a leading `+`, other scripts' digits). When the `Max-Age` *is*
valid it decides alone -- so `Max-Age=100; Expires=Thu, 01 Jan 1970` is
persistent too. Both halves are verified rather than recalled: the parse rule
is `w3c/webref`'s `ed/algorithms/rfc6265bis.json` algorithm [8] ("If the
remainder of attribute-value contains a non-DIGIT character, ignore the
cookie-av"), and the precedence is RFC 6265 4.1.2.2 verbatim -- "If a cookie
has both the Max-Age and the Expires attribute, the Max-Age attribute has
precedence and controls the expiration date of the cookie." The webref extract
of the *storage model* agrees, but reading it takes one trick worth recording:
the `Otherwise ... Expires` branch is **not** a sibling entry in that step's
`steps` array, it hangs off the same step's **`additional`** key, with its own
nested `steps` beneath it. A walker that recurses only through `steps` sees the
`Max-Age` branch and concludes the `Expires` one is missing. It is not missing.
An earlier draft of this paragraph called it an extraction artefact and was
wrong; the general lesson is that reffy models an "Otherwise" as an
`additional` block rather than as another step, so any traversal of
`ed/algorithms/` has to follow both keys.

An `Expires` a browser cannot parse at all is excluded, because it sets no
expiry and so is not persistence either; the same goes for a cookie whose only
lifetime attribute was the ignored `Max-Age`, or for either attribute written
as a bare flag with no value.

**Two of the three are gated on tier 1's own verdict, and the claim is
narrow: a tier-2 finding is suppressed where tier 1 has already made the same
*attribute-level* claim moot.** Exactly two pairs are gated --
`cookie-samesite-none` behind `cookie-samesite-none-insecure`, and
`cookie-domain-broad` behind `cookie-domain-mismatch` -- and no more should be.
Tier 1 and tier 2 findings about one cookie co-occur freely otherwise, and
correctly: `cookie-control-character`, `cookie-oversized`,
`cookie-prefix-violated` and `cookie-domain-mismatch` all sit beside tier-2
`warning`s, because hardening advice *survives* fixing tier 1. An operator who
repairs the prefix still has no `HttpOnly`, and gating that away would hide
the second half of the work. `cookie-samesite-none` fires only when `Secure` is also
present. Without it, `cookie-samesite-none-insecure` (tier 1) has already said
Chrome and Firefox reject the cookie outright, and "sent on cross-site
requests to this host by design" would contradict a finding on the same
response saying the cookie is never sent at all -- Safari's part of the story
is already carried in that tier-1 message. `cookie-domain-broad` fires only
when the `Domain` actually matches the host. Without that,
`cookie-domain-mismatch` (tier 1) has already said browsers reject the
cookie, and "every subdomain of it receives the cookie" is meaningless for a
cookie that was never set. Both reuse the same boolean tier 1 already
computes rather than restating the logic. `cookie-persistent` has no tier-1
counterpart to contradict, so it is gated differently -- excluded from firing
on deletion, above, rather than gated on a sibling finding.

`data` is `{"cookie": name, "evidence": [...]}`, where `evidence` is the list
of signals that fired, empty at the floor. Deriving the level from `data` is
what keeps `identity()` coherent: two findings that dedupe to one cannot
disagree about their level, because the level is a function of what they
deduped on.

## Rating

### Why the ladder exists at all

Every peer on disk hits the same wall and three of four take the same way out
-- guessing from the cookie's name whether it holds a session. `humble` flags
every cookie lacking `Secure` **or** `HttpOnly` (`humble.py:1451`), so `lang=en`
and `_ga` are findings. `securityheaders` gates its checks on
`'session' in name or 'csrf' in name`, in a function whose two prefix branches
are dead code because it lowercases the name and compares against
`'__Secure'` (`checkers/setcookie/requiressecurity.py`).
`cookie-security-analyzer` scores a `SENSITIVE_NAME_PATTERN` (`src/popup.ts`).

This package reports the fact either way and uses the heuristic only for the
**rating**. That is the whole difference: a name guess that gates a finding
causes false positives, and a name guess that weights a reported fact can only
mis-weight it. Noise is a risk assigned where there is none, not a fact
reported.

ZAP reaches the same place from the other direction: its five cookie passive
rules apply no heuristic at all, flag every cookie, and leave false positives
to a user-editable ignore list
(`CookieUtils.getCookieIgnoreList`, `CookieSecureFlagScanRule.java:89`), empty
by default.

### The escalation list: exact names and specific prefixes, no fragments

Escalate when the lowercased name, **after stripping any cookie-name prefix**,
matches one of these exactly, or begins with one of the two prefixes:

```
frameworks and runtimes
  phpsessid  jsessionid  asp.net_sessionid  aspsessionid  cfid  cftoken
  cgisessid  sessionid  session_id  _session_id  _rails_session
  laravel_session  ci_session  connect.sid  express_sid  rack.session
  play_session

identity servers
  keycloak_session  auth_session_id  auth_session_id_legacy

transparent generic names
  sid  sessid  jwt

self-hosted applications
  plesksessid  phpmyadmin  zenid  siteserver  whostmgrsession  xf_session
  grafana_session  i_like_gitea  _redmine_session  _mastodon_session
  mmauthtoken  nc_session_id  oc_sessionpassphrase

persistent authentication tokens
  remember_user_token  xf_tfa_trust  gitea_incredible  nc_token

patterns
  wordpress_logged_in_*   wp_woocommerce_session_*   cpsession*
  phpbb3_*_sid
```

**Entries are anchored glob patterns, `*` only.** An exact name is a pattern
with no wildcard, a prefix is `foo*`, and phpBB needs both ends:
its cookies are `<prefix>_<name>` where the prefix is randomised at install
(`phpbb3_n7fab_sid`), so the session cookie is `phpbb3_*_sid`. One mechanism
covers all three shapes and subsumes the prefix matching the suppression list
already uses; no `?` or character classes, which would be a footgun for no
gain.

**The anchoring policy is what keeps the mechanism from becoming the rule this
design rejected.** A pattern must be anchored at both ends, or be a prefix
containing a literal that identifies one piece of software. A pattern anchored
at *neither* end is forbidden -- `*session*` is expressible and must never be
written, because it is the substring rule measured at 29% wrong below.
`*_sid` alone is forbidden for the same reason. Coverage for phpBB is
therefore defaults-only, since an administrator may change the prefix in the
control panel; that is accepted rather than worked around.

Prefix-stripping first, because `__Secure-PHPSESSID` is a literal
Open-Cookie-Database entry: the idiom occurs, and an exact match against the
undecorated name would miss it. Such a cookie escalates via the prefix signal
anyway, so this is belt-and-braces rather than load-bearing.

Sources: ZAP's `HttpSessionsParam.DEFAULT_TOKENS`
(`HttpSessionsParam.java:55`), OWASP's Session Management Cheat Sheet
(`Session_Management_Cheat_Sheet.md:31`), Wappalyzer's cookie fingerprints,
Open-Cookie-Database. They age well for a structural reason: the name is
load-bearing, so changing it breaks existing sessions and upgrades.

**cPanel and WHM are included on the Plesk rationale, with the name form
unverified.** Neither `cpsession` nor `whostmgrsession` appears in any on-disk
source -- Open-Cookie-Database has neither, and CRS's six `cpanel` hits are
filesystem paths in LFI wordlists, not cookies -- so both come from
external evidence only. `cpsession` is written as a prefix because whether the
real name is exactly that or carries a token suffix could not be confirmed,
and a prefix covers both readings safely: the name is distinctive, and
vBulletin's `bbcpsessionhash` *contains* it without *starting* with it, which
is the fragment-versus-prefix distinction in one example.

**XenForo is included on disk evidence, not the firewall claim.** OCD carries
`xf_session` (Functional) and `xf_tfa_trust`, a two-factor trust token that
belongs to the persistent-authentication category. The suggestion that CRS
ships XenForo-specific rules is not corroborated here: XenForo appears in
`coreruleset` only in `CHANGES.md`, because CRS 4 moved application exclusions
into separate plugin repositories that are not on disk. The entry stands on
OCD alone, which the escalation bar permits.

**Membership: the name must be deployable on hosts its vendor does not
control.** That is the axis, not framework-versus-vendor. Only two properties
matter -- *stability*, because the name cannot change without breaking
deployments, and *reach*, how many independent hosts can emit it -- and on
both, `PLESKSESSID` scores like `PHPSESSID` and nothing like a single
company's SaaS cookie. Plesk is vendor-specific and installed on tens of
thousands of servers the vendor has never touched. So frameworks and
self-hosted applications are in; a cookie only ever seen on one vendor's own
domains is out, because a tester scanning that vendor does not need a list to
recognise its session cookie. `sessionid` earns its place because Django uses
it, not because Instagram does.

**The criterion does NOT bound the list, and an earlier draft claimed it did.**
That claim -- "the population is on the order of twenty to thirty and moves
slowly" -- is false. `selfh.st/apps` catalogues on the order of 1500
self-hosted applications and grows, and "deployable on hosts its vendor does
not control" admits every one of them. The criterion constrains *quality*; it
says nothing about *quantity*. Recorded because the error shaped two rounds of
this design.

**Completeness is an explicit non-goal.** A sampling of roughly twenty
popular self-hosted applications produced: a handful of fixed distinctive
names, several that derive the name from an instance id or configuration and
are unmatchable by any static list (Sonarr and Radarr from the instance name,
Nextcloud's ordinary session from the instance id, Gitea and phpBB from
config), and several that use names too generic to match. That distribution
will not improve with more sampling. The list is a triage convenience whose
misses cost a `note`, so it is bounded by judgement about reach and stops
being extended when the marginal entry stops mattering -- not by a rule that
promises to be exhaustive.

**Reproducibility was traded away deliberately.** Entries attested only by an
on-disk source can be re-derived by re-running the sweep queries recorded in
**Verified, with sources**. These cannot, and rest on external documentation
read during review: `cpsession*`, `whostmgrsession`, `grafana_session`,
`i_like_gitea`, `gitea_incredible`, `express_sid`, `nc_token`,
`nc_session_id`, `oc_sessionpassphrase`, `_redmine_session`,
`_mastodon_session`, `mmauthtoken`, `zenid`, `siteserver`, `sessid`, `jwt`.
The alternative -- requiring on-disk attestation, which would have made the
whole list re-derivable from a checkout -- was considered and declined in
favour of coverage. The consequence to know: verifying this list means reading
vendor documentation, not running a query.

**Err tight, because omission costs a `note` and not silence.** A session
cookie whose name is not here still raises `cookie-no-httponly`; it is rated
at the floor rather than escalated. The list is a triage convenience, not a
gate on detection -- which is the payoff of reporting everything and rating by
heuristic. The stakes are asymmetrically low in both directions: a missing
entry under-rates, a wrong entry over-rates, and neither hides nor invents a
finding. A sixty-name list would buy very little over this one and cost review
forever.

**Open-Cookie-Database is authoritative for *existence* only.** Its
`Category` is a *privacy purpose*, not a judgement about session tokens:
`sessionid` is filed under Instagram / **Marketing** and is Instagram's real
auth cookie and Django's default, and `sid` is Google / **Marketing** and is a
Google auth cookie. Its `Platform` is "where observed", not "who defines it":
`connect.sid` is attributed to **Zendesk** when it is Express/connect's
default. Never filter it by category or trust its attribution. CLAUDE.md
already carries this caveat; it fires on two of the strongest entries here.

**The two lists have different membership bars, because they fail in opposite
directions.** An earlier draft applied one bar -- "two or more independent
sources on disk" -- to both, which was wrong twice: it is too weak for the
suppression list and it measures the wrong thing for this one.

- **Escalation (this list): evidence that the name is really used as a session
  identifier.** A second curated list is one form of evidence; a live site
  observed sending it is a better one. A wrong entry here can only mis-rate a
  finding that is reported either way, so the bar is real-world use, not a
  source count.
- **Suppression: the stricter bar**, stated in that section. A wrong entry
  there silences a finding absolutely, so an on-disk vendor attribution is
  required and a generic name is refused outright.

**`zenid` and `siteserver` are on the list, and an earlier draft dropped them
as "dead platforms" without checking.** Both are live: Zen Cart ships today
(Wappalyzer carries it; WhatWeb ships `zen-cart.rb`) and `zenid` is its
session cookie, and both names were found on live sites' cookie-policy pages
during review. Neither appears in Open-Cookie-Database, which is why a
source-count bar excluded them and why that bar was the problem. Recorded
because the error is instructive: "dead platform" is a claim about the world,
and there was nothing on disk supporting it.

**`viewstate` stays off, and now for a reason rather than an assumption.**
ZAP's own codebase classifies it as POST data --
`ScannerParam.java:336` registers `__VIEWSTATE` with
`NameValuePair.TYPE_POST_DATA`. That is the key to the whole list:
`DEFAULT_TOKENS` is not a list of *cookie* names, it is session token names
ZAP looks for across cookies **and** parameters, so `viewstate` belongs in it
and not here. ASP.NET puts ViewState in a hidden form field; emitting it as a
cookie needs custom application code. It is also absent from
Open-Cookie-Database, and its provenance is a six-name batch commit with no
rationale (`8f7573bc4`, 2012-02-18: `siteserver`, `cfid`, `sessid`, `sid`,
`viewstate`, `zenid`). No live example was found.

**Open-Cookie-Database is the negative oracle, and that is the test a generic
name must pass.** It is a poor guide to what *is* a session cookie -- wrong
category, wrong attribution -- but 2266 rows dominated by trackers is exactly
the corpus for the question *"would matching this name mis-rate something?"*.
So a transparent generic name is admitted when it is **absent from that corpus
and semantically unambiguous**. `sessid` passes, and so does `jwt` -- which
appears nowhere in the file, not even as a substring, while a cookie named
`jwt` is a bearer token and the highest-value escalation available. `token`
**fails**: Adform uses it, so it is excluded despite being just as
transparent. That is the rule with two passes and one documented failure,
rather than a judgement call per name.

**`sessid` is kept on absence of harm rather than on provenance**, which is
worth saying plainly rather than dressing up. No framework defaults to it. Its trail is a Roundcube cookie renamed away in
2007, a 2011 SonicWall appliance exploit, and live sites that are probably
custom applications. What justifies keeping it is measurable: the exact name
appears in **none of Open-Cookie-Database's 2266 rows**, so in a corpus
dominated by trackers, nothing uses it -- exact-matching it cannot mis-rate a
known tracker, and real applications demonstrably do use it as a session id.
If it is ever dropped, this is the paragraph that says what would have to
change: a tracker adopting the exact name.

**Exact names and specific prefixes; never a generic fragment.** The
distinction is not exact-versus-fuzzy -- the suppression list matches
`BIGipServer` and `NSC_` as prefixes, and Open-Cookie-Database encodes the
same distinction in its own `Wildcard match` column. A prefix like
`wordpress_logged_in_` identifies one piece of software; a fragment like
`session` or `-sessid` identifies nothing. The prefix entries are not
optional: WordPress's session cookie is `wordpress_logged_in_<hash>`, and it
is plausibly the most common session cookie on the internet, so exact
matching alone would miss the single highest-reach name there is.

**Every fragment rule was measured, and all of them fail.** Of the 8 names
*ending* in `sessid`, **4 are not session tokens** -- `CPSessID` and `SISessID`
(Qualtrics), `matomo_sessid` (Matomo), and `mage-cache-sessid`, a Magento
cache marker. Of the 26 ending in `_session` -- the most promising anchoring,
since the underscore looks like a word boundary -- **9 are not**, judged by
hand: `ai_session` (Azure Application Insights), `_parsely_session`,
`rl_session` (Rudderstack), `sbjs_session`, `_Brochure_session`, the RD
Station pair and the CookieYes pair. That is **65% precision**. `*_sess` is
50%.

**The reason is structural, not a threshold to tune.** The analytics industry
names *visit*-tracking cookies exactly as authentication cookies are named,
because it is genuinely tracking something it calls a session. No name shape
separates "logged-in session" from "this visitor's browsing session" -- the
two senses share the word. Pattern matching on session-ish shapes is
therefore closed off permanently, and the individual names are the only thing
that works.

An earlier draft reported this as "29% wrong" using Open-Cookie-Database's
`Category` field as the discriminator. That measurement was taken with a
broken instrument: the same field mislabels real session cookies as Marketing
(`sessionid` is Instagram's auth cookie, `sid` is Google's). The hand-judged
figures above are the real ones, and they are worse. The conclusion did not
change; the number did.

That same suffix probe is how `CGISESSID` was found -- Perl's `CGI::Session`,
a framework default that every other source here had missed. The measurement
that rejected the rule paid for itself by surfacing the gap.

An earlier draft paired a substring rule with a de-escalation list of known
analytics cookies to cancel the over-matches. Exact matching removes the
over-matches, so that list is not needed: `_ga` and `_hjSessionUser_1234` sit
at the floor because nothing lifted them, not because something pushed them
back. One less table to keep current.

### The signals are per attribute

Three rungs -- `note`, `warning`, `error` -- which cost nothing now that a
level is per finding.

| signal | `Secure` | `HttpOnly` | `SameSite` | to |
|---|---|---|---|---|
| a misspelling of this attribute | escalate | escalate | escalate | `error` |
| canonical session name | escalate | escalate | escalate | `warning` |
| `__Secure-`/`__Host-`/`__Http-` prefix | escalate | escalate | escalate | `warning` |
| `HttpOnly` already set | escalate | -- | escalate | `warning` |
| name contains `csrf` / `xsrf` | escalate | **never** | escalate | `warning` |

**The columns are the three absence codes, and the other three read only the
middle two rows.** `cookie-samesite-none`, `cookie-persistent` and
`cookie-domain-broad` take `session-name` and `prefix` -- the rows that infer
whether the cookie matters -- and neither of the two rows that infer *intent*.
A misspelling is excluded because nothing was misspelled, and `HttpOnly`
already set is excluded because nothing was forgotten: the response asked for
cross-site sending, an expiry, or a parent domain deliberately in each case.
Leaving that row in inverted the ladder outright, so adding `HttpOnly` to a
correctly hardened analytics cookie raised two unrelated notes to warnings and
made the tool louder about hardening. `csrf` / `xsrf` does not reach them
either: it is `Secure`'s and `SameSite`'s row for the *absence* codes, and
these three are not absences.

**A misspelling outranks every other signal, and is the only one that reaches
`error`.** Every other row is an inference about whether the cookie matters. A
misspelling is not an inference: the author wrote `Secrue`, so they intended
`Secure` and did not get it, which is principle 3's definition of `error`
verbatim -- the response does not deliver the protection its presence implies.
It is the only evidence in this design that establishes *intent* rather than
guessing at *importance*.

Two guards, both necessary, and the second is what keeps the first honest:

- **Only for `secure`, `httponly` and `samesite`.** A misspelled `max-age` or
  `expires` makes the cookie session-scoped; a misspelled `path` narrows it to
  the request directory; a misspelled `domain` makes it host-only. Every one of
  those **fails safe** -- the mistake leaves the cookie *more* restricted, so
  an `error` would be a false claim. Only the three security flags fail open.
  Misspellings of the other six still surface as `cookie-unknown-attribute`.
- **Only when the correct attribute is absent from that cookie.**
  `Secure; Secrue` has the protection and the typo cost nothing. `Secrue`
  alone means the author asked and did not receive.

**Damerau-Levenshtein, not Levenshtein**, threshold 1. This is measured, not
chosen: of 21 realistic typos, **8 are Damerau-distance 1 but
Levenshtein-distance 2**, because all 8 are transpositions -- `secrue`,
`secuer`, `httponyl`, `httpolny`, `smaesite`, `expries`, `domian`, `paht`. A
plain-Levenshtein threshold of 1 would miss roughly 40% of real typos,
including the most likely misspelling of the most important attribute. Optimal
String Alignment is sufficient; typos in an eight-character token are adjacent
swaps, and OSA's restriction to adjacent transpositions costs nothing here.

**Threshold 1 has no collisions against any real attribute name.** Probed
against every cookie attribute that has ever existed and is not in the
recognised nine -- RFC 2965's `version`, `comment`, `commenturl`, `discard`,
`port`, plus the abandoned First-Party Sets `sameparty` -- the nearest
distance is **3**, and most are 4 or more. The residual risk is a *future*
name shaped like `samesite2`, `secured` or `httpsonly`, all of which are OSA 1;
the second guard is what contains it, since such a name would have to appear
on a cookie that omits the real attribute to reach `error`.

**One consequence of the suppression rule, stated so it is a decision.** On a
suppressed infrastructure cookie the typo appears as `cookie-unknown-attribute`
-- a note, naming the suspected correction -- and the `error` does not appear,
because the tier-2 finding it would have escalated is suppressed. The
misspelling stays visible; the risk is not asserted on a cookie this design
has already said is not a credential.

**The `csrf` row is the one that would otherwise be a bug**, and it is the
reason this table is per attribute rather than per cookie. A CSRF token cookie
without `HttpOnly` is a *correct* configuration: the cookie-to-header pattern
requires JavaScript to read it. OWASP's CSRF Prevention Cheat Sheet writes the
counter-example as literal sample code --
`response.setCookie("csrf_token=" + csrfToken + "; Secure") // Set Cookie
without HttpOnly flag` (`:114`) -- and says of Angular's `XSRF-TOKEN` that it
"is accessible via JavaScript (i.e., not `HttpOnly`)" (`:605`). All 24 rows in
Open-Cookie-Database's `Security` category are CSRF tokens, so this is the
rule and not an edge case. Escalating them for missing `HttpOnly` would be a
false positive on a correct configuration, which principle 4 names as the
worst outcome available.

**The exemption is not about CSRF tokens; it is about cookies whose own
specification requires script access.** A second, independently authored
standard says so in as many words -- OpenID Connect Session Management 1.0:
*"If a cookie is used to maintain the OP User Agent state, the HttpOnly flag
likely cannot be set for this cookie because it needs to be accessed from
JavaScript."* Two specifications from two bodies reaching the same conclusion
is what makes this a class rather than a carve-out, and it tells a later
maintainer what the row is *for*. OIDC adds no name to any list here: it
leaves the cookie name implementation-defined and permits localStorage
instead, so there is nothing to match on -- only the reasoning generalises.

**The exemption dominates every signal in the `HttpOnly` column, not only the
name match that decides whether it applies.** A csrf/xsrf-named cookie that
also carries a `__Secure-`/`__Host-`/`__Http-` prefix, or happens to match a
session-name pattern, must **never** be escalated for `HttpOnly` on the
strength of either: `prefix` and `session-name` only *infer* that a cookie
matters, and OWASP's own worked example for the exempted case is written with
exactly that shape --
`Set-Cookie: __Host-token=RANDOM; path=/; Secure`
(`Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md:494-514`) -- paired
with the same cheat sheet's statement that the cookie is deliberately not
`HttpOnly` (`:114`, `:605`). Letting a *hardened* name reintroduce the
escalation the exemption exists to prevent would be principle 4 in new
clothes: the correctly configured, spec-recommended form penalised while the
plain, unprefixed form is not. A misspelling of `HttpOnly` still escalates
regardless of any of this, because that establishes intent rather than
inferring importance -- see "A misspelling outranks every other signal" above.

A prefix does not escalate the attribute it names: `__Secure-sid` without
`Secure` is not a hardening gap but `cookie-prefix-violated`, tier 1.

### The suppression list

These names emit **no tier-2 finding at all**. The cookie is set by
infrastructure and carries a routing or bot-detection identifier, not a user
credential. Exact match, case-insensitive, plus four prefixes:

```
exact:   AWSALB AWSALBCORS AWSALBTG AWSALBTGCORS AWSELB AWSELBCORS
         ARRAffinity ARRAffinitySameSite __cflb __cf_bm ak_bmsc bm_sv _abck
prefix:  BIGipServer  NSC_  incap_ses_  visid_incap_
```

Sourced from Open-Cookie-Database, with `BIGipServer`, `NSC_`, `incap_ses_`
and `visid_incap_` carrying its own `Wildcard match` flag; five of the seven
classics are corroborated by a second source (WhatWeb plugins,
`burp/waf-detect`'s `WafFingerprints.csv`, Wappalyzer).

**Membership criterion -- the stricter of the two**, because a wrong entry here
silences a finding absolutely where a wrong escalation entry only mis-rates
one. Stated so a later addition has a test to meet: *the cookie carries a
routing or bot-detection identifier rather than a user credential, its name is
specific to one vendor, and that vendor attribution is on disk.* The last
clause is what the escalation list does **not** require -- there, observed
real-world use is enough, because the cost of being wrong is a mis-rating
rather than silence. Three candidates were
rejected against it -- `SERVERID`, a generic English word and the only entry a
real application might plausibly choose; `cf_clearance`, which is a bearer
token for challenge clearance and therefore is a credential; and `TS01`,
because `TS`-prefixed cookies are F5 ASM as well as Wix.

**Suppression is unconditional within tier 2.** An earlier draft cancelled it
whenever an escalation signal fired, as insurance against a name collision.
That was incoherent twice over. Mechanically, three of the four escalation
signals are disjoint from this list by construction -- `AWSALB` is not
`phpsessid`, and `__Secure-AWSALB` does not match `AWSALB` -- so only
"`HttpOnly` already set" could fire, and it fires on `__cf_bm` and
`cf_clearance`, precisely the entries that are correctly configured. The
override did nothing except un-suppress the best-behaved names on the list. In
principle it also inverted the evidence: the list is a curated, corroborated
assertion that a cookie is not a credential, and "HttpOnly is set" is a guess
about sensitivity. A guess must not override an assertion.

Removing the override flips the failure direction, which is the honest trade
to record. With it, a stale list could only under-suppress and make noise.
Without it, a wrong entry silences findings absolutely. That is why the answer
is a stricter membership bar rather than a softer mechanism -- the same
reasoning that admits `INFORMATION_HEADERS` while refusing csp-evaluator's
bypass lists: a curated list is acceptable exactly when you can state which
direction staleness fails in and accept it.

**Tier 1 is never suppressed**, and this is not the same contradiction. A
`SameSite=None` without `Secure` on `AWSALB` is a cookie the browser throws
away, breaking session affinity. That is a correctness statement about the
response, not a sensitivity judgement about the cookie.

`--ignore-cookie NAME` is reserved on `scan` and not implemented, on the
evidence that ZAP's operators want to own this list and that CLAUDE.md already
records the human wanting to compile their own boring-list.

## Consequences

Two new slugs, the first additions to a vocabulary deliberately closed at
eight. Cookies are the one area where CWE's coverage is unusually rich -- 1004,
1275, 614, 315, 539, 565, 784 -- so unlike the original eight, these do not
have to reach for a Class-level id.

```python
"session-theft": Consequence(
    "Session token theft",
    ("CWE-1004",),
    "An attacker could obtain the cookie carrying this session and act as the "
    "user without their credentials. Whether the cookie carries a session is "
    "not determined here.",
),
"csrf": Consequence(
    "Cross-site request forgery",
    ("CWE-352", "CAPEC-62"),
    "Another site could cause the browser to make an authenticated request to "
    "this origin using the user's own cookies. Whether the application has a "
    "state-changing endpoint that would accept one is not determined here.",
),
```

Both closing sentences follow the house rule: a hint about potential risk,
never a claim it is reachable. Neither is true of the existing eight, which is
the test a new slug has to pass -- `mitm` is the network path only, and
`data-disclosure` is third-party leakage.

CAPEC ids are chosen by cross-reference to the CWE already picked, not by name
match, per the rule CLAUDE.md records after keyword matching went wrong three
times in a dozen. That held for `csrf`: CAPEC-62 cross-references CWE-352 in
CAPEC 2.1, so the pairing survives the check it was chosen by. It did not hold
for `session-theft` as first drafted -- CAPEC-31 was picked by name match
("Session Theft" reads like the code) and turned out to cross-reference
CWE-113/20/302/311/315/384/472/539/565/602/642, never CWE-1004, and no pattern
in CAPEC 2.1 cross-references CWE-1004 at all. `session-theft` therefore
carries `("CWE-1004",)` alone, the same single-id shape `data-disclosure`
already has, rather than a CAPEC that does not cross-reference the CWE it
would ride alongside.

Assignments:

| code | consequences |
|---|---|
| `cookie-no-secure`, `cookie-secure-over-plaintext` | `mitm`, `session-theft` |
| `cookie-no-httponly` | `session-theft` |
| `cookie-no-samesite`, `cookie-samesite-invalid`, `cookie-samesite-none` | `csrf` |
| `cookie-samesite-none-insecure` | `csrf`, `mitm` |
| `cookie-prefix-violated`, `cookie-hidden-prefix` | `session-theft` |
| `cookie-domain-broad`, `cookie-domain-mismatch` | `session-theft` |
| `cookie-persistent` | `session-theft`, `cache-exposure` |
| `cookie-control-character`, `cookie-oversized` | `()` |
| `cookie-partitioned-insecure` | `()` |
| `cookie-unknown-attribute` | `()` |

The last four are empty and that is a result, not an omission. A discarded
cookie and a rejected `Partitioned` attribute both fail closed: nothing is
over-shared, a feature is simply absent. `cookie-unknown-attribute` is empty
for a different reason -- it asserts no defect at all, and where a misspelling
does cause one, the consequences are carried by the absence finding it
escalates, which already holds exactly the right slugs
(`cookie-no-secure` is `mitm` + `session-theft`, `cookie-no-httponly` is
`session-theft`, `cookie-no-samesite` is `csrf`). That is why one code suffices
where a dedicated typo code would have needed the union of all three, or three
codes to avoid it.

## What changes elsewhere

- `findings.py` -- `Finding` gains `level`; `level_of()`; `ESCALATABLE`;
  sixteen `FINDING_SEVERITY` defaults; sixteen `CODE_HEADER` entries, all
  `Set-Cookie`; sixteen `CODE_CONSEQUENCES` entries.
- `catalog.py` -- sixteen templates and two `CONSEQUENCES` entries. Templates
  name the cookie, and must read correctly at both levels, because a code has
  one template however it is rated.
- `references.py` -- `Set-Cookie` into `_MDN`. It is the 41st header a finding
  can name.
- `response.py` -- one call in `analyze()`, one key in `inventory()`.
- `reporting.py` -- `severity(finding.code)` becomes `level_of(finding)`.
- `cli/text.py` -- a `cookies` block in `_inventory_lines()`. The existing
  loop assumes `{name: value}`, so the list needs its own rendering.
- `cli/commands.py` -- `explain` prints `(may escalate)` for `ESCALATABLE`.

`REPEATABLE_HEADERS` already contains `set-cookie`; no change.

## Testing

- The existing bijection tests carry over unchanged: every emittable code has a
  `FINDING_SEVERITY` default and a template, and every rated code is emittable.
  A corpus case per code, or they pass vacuously.
- A new test that every `level` a finding carries is in `SEVERITIES`.
- A new test that `identity()` still ignores `level`, and that two cookies
  missing the same attribute are two findings rather than one -- the assertion
  the widened `identity()` was written for and that nothing has exercised.
- Parser tests from `security/cryptoparser`'s `test/httpx/test_header.py`,
  1143 lines of real header values with expected parses. It is the only
  per-header parse corpus on disk that is not this package's own, so it is a
  free source of awkward inputs. Note it implements **none** of the four
  prefixes, so it is a source of parse cases and not of rules.
- Mutation-test the ladder specifically: invert each escalation signal and each
  suppression entry and confirm a test fails. A ladder that rates everything
  the same passes every test that only counts findings.
- **Pin the typo metric with a transposition.** A case for `Secrue` and one for
  `httponyl`, both of which are Damerau 1 and Levenshtein 2, so swapping the
  implementation to plain Levenshtein makes a test fail. Without one of those,
  the wrong metric passes the whole suite -- the "passes both ways" failure the
  working practices warn about.
- A case for each fail-safe attribute (`Expries`, `Domian`, `Maxage`)
  confirming it reports `cookie-unknown-attribute` and does **not** escalate
  anything to `error`, and a case for `Secure; Secrue` confirming the second
  guard holds.
- A case for each of `version`, `comment`, `port` confirming they report as
  unknown with no `suspected` key, which is the negative half of the
  distance threshold.
- `tests/rendered_messages.txt` regenerated deliberately, and the diff read.

## Rejected alternatives

**Gating tier-2 findings on a name heuristic**, as every peer does. It converts
a mis-weighting into a false negative, and a session cookie named `id` -- which
OWASP's own cheat sheet recommends -- disappears entirely.

**Uniform judgement, no ladder**, as humble does. Fires on `lang=en` and `_ga`,
which is principle 4's worst outcome and the reason this project exists.

**Two codes per laddered attribute**, avoiding the `Finding.level` change.
Encodes a policy distinction as a fact distinction and doubles the code count.

**`Set-Cookie` into `PRESENT_ONLY_HEADERS` with no parsed table.** One line of
change, and every consumer re-parses by hand -- the chore `inventory()` exists
to remove.

**A `cookies` key beside `inventory` rather than inside it.** Two places would
then answer "what did the response carry".

**Names derived from configuration or an instance id.** Sonarr and Radarr
build the cookie name from the instance name; Nextcloud's ordinary session
cookie *is* the instance id; Gitea's and phpBB's are administrator-settable.
No static list matches these, and only phpBB is partly reachable, by the
both-ends pattern above on its default prefix.

**`token` as a transparent generic name.** Fails the negative-oracle test --
Adform uses it. Excluded despite reading exactly as unambiguously as `jwt`,
which passes.

**Wiki.js's and SonarQube's cookie names.** Wiki.js uses `jwt`, which is on
the list on its own merits rather than as a Wiki.js entry; SonarQube's is
equally generic and has no attestation here. Neither earns a
vendor-specific entry.

**Per-application entries beyond the point of diminishing reach.** Redmine,
Grafana, Mastodon, Mattermost and Etherpad are in. LibrePhotos, PicoShare,
Deluge (whose `_session_id` is already covered as a framework generic),
Draw.io (Tomcat's `JSESSIONID`, covered), GitLab (name not found) and
Supabase (no longer cookie-based) are not. The line is reach, and it is a
judgement, not a rule.

**The OWASP Cookies Database wiki as a source.** Reached from the Session
Management Cheat Sheet (`Session_Management_Cheat_Sheet.md:31`). Rejected on
two grounds, the second being the weaker one. It is a *fingerprinting*
database -- every cookie a product sets, not the session cookie -- so it
cannot be used without hand-filtering, and hand-filtering is where curated
data goes wrong. And it is an unversioned wiki on the legacy
`wiki.owasp.org`, so there is no revision to pin, which is incompatible with
reading a checkout at a known state. Its value is real but belongs to the
parked inverted "interesting headers" work, beside humble's 1 287-name
`fingerprint.txt`.

**Deriving the cookie inventory from findings.** Same reason
CLAUDE.md already records for the other tables: a correctly configured cookie
emits nothing, so it would vanish.

**Dropping unrecognised attributes at the parser, as both engines do.** The
parser's job is to record what was sent; discarding a name means the analysis
cannot report it and the inventory cannot show it. Engines drop them because
they have to act on the cookie; this package has to describe it.

**Restricting the recognised set to rfc6265bis.** It omits `priority`, which
Chromium parses and which Google sends on its own cookies, so the note would
fire on some of the most visited responses on the web. Browser source is the
authority for what is honoured -- the same rule that decided the `Report-To`
and `noopener-allow-popups` rulings.

**A dedicated `cookie-attribute-typo` error code.** Consequences are keyed by
code, and one code spanning `Secure`/`HttpOnly`/`SameSite` needs the union
`("mitm", "session-theft", "csrf")`, over-stating each individual case; three
codes to avoid that costs three codes. Escalating the *absence* finding
instead reuses slugs that are already exactly right and adds none.

**Plain Levenshtein at threshold 1.** Misses 8 of 21 realistic typos, every
one a transposition. See the ladder; this was measured rather than argued.

**Edit distance without the fail-safe filter.** A misspelled `Path`, `Domain`,
`Expires` or `Max-Age` leaves the cookie *more* restricted, so rating it
`error` asserts a defect that does not exist.

**Edit distance without the absent-attribute guard.** `Secure; Secrue` has the
protection. Rating it `error` is a false positive on a configuration that
works, and it is also what would let a future attribute name shaped like
`samesite2` produce one.

## Verified, with sources

Everything below was read on disk during the design, not recalled.

| claim | source |
|---|---|
| `SameSite` default is Lax in Chrome only | BCD `Set-Cookie.json` `SameSite.Lax_default`: Chrome 80 / Firefox 69 flag / Safari false |
| `SameSite=None` requires `Secure` | BCD `SameSite.none_requires_secure`: 80 / 131 / false; layered-cookies step 12 |
| `__Secure-`/`__Host-` are universal | BCD `host_secure_prefixes`: 49 / 50 / 13 |
| `__Http-`/`__Host-Http-` are not | BCD `http_host-http_prefixes`: 140 / 143 / false |
| `Partitioned` support | BCD: Chrome 114 / Firefox 141 / Safari 26.2 |
| four prefixes, longest-first, case-insensitive, all require a secure request | `netwerk/cookie/CookiePrefixes.cpp`; `net/cookies/cookie_util.cc:342,786,818` |
| `__Host-` tolerates `Domain` for IP-literal hosts | `cookie_util.cc:120` |
| a `Secure` cookie from a plaintext origin is not stored | `net/cookies/cookie_base.cc:124`; `netwerk/cookie/CookieService.cpp:1038` |
| localhost is trustworthy | `cookie_util.cc:709` |
| hidden prefix in the value of a nameless cookie | `cookie_util.cc:796`; layered-cookies step 17 |
| CTL or over-4096 discards the header | rfc6265bis algorithm [5] |
| an unknown `SameSite` becomes `Default` | rfc6265bis algorithm [11] |
| CSRF cookies are deliberately not `HttpOnly` | `Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md:114,605` |
| 29% of `session`-named cookies are analytics or marketing | Open-Cookie-Database, 28 of 98 of 2266 |
| all 24 `Security`-category cookies are CSRF tokens | Open-Cookie-Database |
| `*_session` is 65% precise, `*_sess` 50%, `*sessid` 50% | Open-Cookie-Database, hand-judged; analytics name visit-sessions alike |
| `jwt` appears nowhere in the 2266 rows; `token` is Adform's | Open-Cookie-Database |
| `PLAY_SESSION` is Play Framework's, not LinkedIn's | Open-Cookie-Database attribution error, third found |
| `rack.session` is Rack's | Open-Cookie-Database, Platform "Rack" |
| Keycloak: `KEYCLOAK_SESSION`, `AUTH_SESSION_ID(_LEGACY)` | Open-Cookie-Database, Platform "Keycloak" |
| Gitea: session `i_like_gitea`, remember-me `gitea_incredible` | `modules/setting/session.go`; config cheat sheet, read 2026-08-31 |
| Etherpad: `express_sid` | docs.etherpad.org/cookies.html, read 2026-08-31 |
| Nextcloud: `nc_token`/`nc_session_id`/`oc_sessionPassphrase` fixed; ordinary session is the instance id | Nextcloud GDPR cookies doc, read 2026-08-31 |
| Grafana: `grafana_session`, open source included | Grafana auth config doc, read 2026-08-31 |
| DokuWiki's cookie names could not be read (HTTP 402) | dokuwiki.org/faq:cookies |
| OIDC says the OP state cookie likely cannot be `HttpOnly` | OpenID Connect Session Management 1.0, read 2026-08-31 |
| OIDC standardises no cookie name (cookie or localStorage) | same |
| CRS ships no XenForo cookie rules on disk | `coreruleset`: XenForo only in `CHANGES.md`; cpanel hits are LFI paths |
| `xf_session`, `xf_tfa_trust`, `xf_csrf` are XenForo's | Open-Cookie-Database, Platform "Xenforo" |
| no on-disk source carries `cpsession` or `whostmgrsession` | queried OCD, Wappalyzer, WhatWeb, CRS |
| 4 of 8 names ending in `sessid` are not session tokens | Open-Cookie-Database; Qualtrics x2, Matomo, Magento cache |
| `CGISESSID` is Perl `CGI::Session`'s default | Open-Cookie-Database, Platform "Perl" |
| `PLESKSESSID` is Plesk's, `wordpress_logged_in_` is WordPress's | Open-Cookie-Database, `Wildcard match=1` on the latter |
| exact `sessid` appears in none of the 2266 rows | Open-Cookie-Database |
| OCD categories are privacy purposes, not token judgements | `sessionid`=Instagram/Marketing; `sid`=Google/Marketing |
| OCD `Platform` is where-observed, not who-defines | `connect.sid` attributed to Zendesk, not Express |
| ZAP's token list is cookies AND parameters, not cookies | `ScannerParam.java:336` registers `__VIEWSTATE` as `TYPE_POST_DATA` |
| ZAP's token list originates in one batch of six, no rationale | `zaproxy` `8f7573bc4`, 2012-02-18, `SessionParam.java` |
| Zen Cart is a live platform, not a dead one | Wappalyzer `z.json:156`; WhatWeb `plugins/zen-cart.rb` |
| `zenid` / `siteserver` are absent from Open-Cookie-Database | queried during review; one on-disk source each (ZAP) |
| ZAP flags every cookie and mutes by list | `CookieSecureFlagScanRule.java:89`; `HttpSessionsParam.java:55` |
| ZAP judges `Domain` breadth with no PSL | `CookieLooselyScopedScanRule.java:144` |
| humble re-splits a joined `Set-Cookie` | `humble.py:1437,5388` |
| securityheaders' prefix branches are unreachable | `checkers/setcookie/requiressecurity.py` |
| Chromium recognises nine attribute names, including `priority` | `net/cookies/parsed_cookie.cc:62-70,695` |
| Firefox recognises eight, without `priority` | `netwerk/cookie/CookieParser.cpp:306-315` |
| `SameParty` is gone from both engines | absent from `parsed_cookie.cc`; First-Party Sets abandoned |
| 8 of 21 realistic typos are Damerau 1 but Levenshtein 2 | computed during design; all 8 transpositions |
| no real attribute name is within Damerau 1 of the recognised nine | probed against RFC 2965's five plus `sameparty`; nearest is 3 |

Two things that could not be answered from disk, recorded so they are not
re-searched:

- **Prevalence.** OWASP's 250 000-domain corpus tracks 17 header names and
  `set-cookie` is not among them, so how often any of these configurations
  occurs in the wild is unmeasurable here. No threshold in this design depends
  on a prevalence figure, which is why that is acceptable.
- **Safari cookie behaviour** beyond what BCD records. WebKit's only prefix
  code is the curl backend (`CookieJarDB.cpp`), used by non-Apple ports;
  Safari goes through CFNetwork, which is not open source. BCD is the source
  for Safari, and it is the reason `__Http-` is rated on what Safari does
  *not* enforce.
