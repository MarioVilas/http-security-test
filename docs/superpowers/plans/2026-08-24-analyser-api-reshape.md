# Analyser API Reshape Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the analyser's input contract — `analyze_all(present, secure, host)` and friends — with `Exchange`/`Request`/`Response` value types constructed from raw bytes or structured parts, so the package analyses an HTTP exchange rather than a header dict.

**Architecture:** Three frozen value types in the analyser (`Request`/`Response` in `message.py`, which is already declared to be the HTTP *message* model; `Exchange`/`Connection` in a new `exchange.py`). One entry point per output form, each taking an `Exchange`. A lenient byte parser is the primary constructor; `adaptors.py` converts live library objects without importing them. The package gains a layer above the core (`adaptors`, and later `formats`), with `cli/` staying on top and `cli/live.py` remaining the only code that opens a socket.

**Tech Stack:** Python ≥ 3.9, standard library only in the core. `collections.namedtuple` with `defaults=` for value types, matching the existing house style in `cli/exchange.py`. pytest for tests, `ruff check` for lint.

**Spec:** [docs/designs/2026-08-24-analyser-api-reshape.md](../../designs/2026-08-24-analyser-api-reshape.md) — read it alongside this plan; every "why" lives there and is not repeated here.

## Global Constraints

- **Python floor is 3.9** (`pyproject.toml: requires-python = ">=3.9"`). This rules out `dataclass(slots=True)` (3.10) and bare `X | None` annotations evaluated at runtime (3.10). Use `collections.namedtuple(..., defaults=(...))`, as `cli/exchange.py` already does.
- **Standard library only in the analyser core.** No runtime dependency may be added. `hstspreload` stays the sole optional extra.
- **The analyser never fetches.** No `urllib.request`, `http.client`, `socket`, or `ssl` in any module outside `cli/`. `urllib.parse` is fine — it is pure string manipulation.
- **GPL-3.0-or-later notice at the top of every new source file**, copied verbatim from an existing module such as `http_security_test/message.py`.
- **`ruff check` must be clean.** Do not run `ruff format` and do not reformat existing code; the human owns formatting.
- **NEVER run a git command that writes.** No `add`, `commit`, `stash`, `push`, `checkout -- <path>`, `restore`, `reset --hard`, `clean`. Each task ends at a **Checkpoint** for the human to review and commit. To restore a file you broke on purpose, copy it back from a backup you made outside the repo — never from git.
- **Assume other agents are editing this tree.** Do not revert, tidy, or reformat files your task does not name.

---

## File Structure

| File | Responsibility |
|---|---|
| `http_security_test/message.py` | **Modified.** Gains `Request`, `Response`, the start-line parser and the `from_bytes`/`from_parts` constructors. Keeps the header-mapping helpers, which become the derived view rather than the front door. |
| `http_security_test/exchange.py` | **New.** `Exchange`, `Connection`, the `FIDELITY` vocabulary, and the URL guard. |
| `http_security_test/adaptors.py` | **New.** Named converters from live library objects. Imports nothing third-party. |
| `http_security_test/response.py` | **Modified.** `analyze(exchange)` and `inventory(exchange)`; the status-line suppression. |
| `http_security_test/reporting.py` | **Modified.** `report(exchange)`; `fidelity` in the output. |
| `http_security_test/__init__.py` | **Modified.** Exports the core only. |
| `http_security_test/cli/outcome.py` | **New, replacing `cli/exchange.py`.** `Hop`, `Failure`, `FAILURE_KINDS` — the run facts that stay CLI-side. |
| `http_security_test/cli/live.py`, `commands.py`, `run.py` | **Modified.** Build analyser types directly; `secure()`/`host()` deleted. |
| `tests/test_message_types.py` | **New.** Value types and `from_parts`. |
| `tests/test_message_parser.py` | **New.** The byte parser, including hostile input. |
| `tests/test_exchange.py` | **New.** `Exchange`, `Connection`, fidelity, the URL guard. |
| `tests/test_adaptors.py` | **New.** Adaptors against fakes. |
| `tests/test_headers.py` | **Modified.** ~105 call sites migrated to the new entry points. |
| `tests/test_cli_*.py` | **Modified.** Renamed module, new call shapes. |

---

### Task 1: `Request` and `Response` value types

**Files:**
- Modify: `http_security_test/message.py`
- Test: `tests/test_message_types.py` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `message.Request(url, method=None, version=None, headers=(), body=None, raw=None, fidelity=None)`, `message.Response(status=None, reason=None, version=None, headers=(), body=None, raw=None, fidelity=None)`, `message.Request.from_parts(...)`, `message.Response.from_parts(...)`, and `message.mapping(headers)` returning the lowercased `name -> [values]` dict the analysers consume.

- [ ] **Step 1: Write the failing test**

Create `tests/test_message_types.py` with the GPL notice copied from `tests/test_references.py`, then:

```python
import pytest

from http_security_test.message import Request, Response, mapping


def test_headers_keep_order_and_duplicates():
    # The whole reason the type stores pairs rather than a mapping: a dict
    # keeps one value per name, and repeated CSP is enforced conjunctively.
    r = Response.from_parts(
        status=200,
        headers=[
            ("Content-Security-Policy", "default-src 'self'"),
            ("Set-Cookie", "a=1"),
            ("Content-Security-Policy", "script-src 'none'"),
        ],
    )
    assert r.headers == (
        ("Content-Security-Policy", "default-src 'self'"),
        ("Set-Cookie", "a=1"),
        ("Content-Security-Policy", "script-src 'none'"),
    )


def test_mapping_is_derived_lowercased_and_keeps_every_value():
    r = Response.from_parts(
        headers=[("Content-Security-Policy", "a"), ("CONTENT-SECURITY-POLICY", "b")]
    )
    assert mapping(r.headers) == {"content-security-policy": ["a", "b"]}


def test_mapping_of_no_headers_is_empty():
    assert mapping(Response.from_parts().headers) == {}


def test_a_request_requires_a_url():
    with pytest.raises(TypeError):
        Request.from_parts()


def test_value_types_are_immutable():
    r = Response.from_parts(status=200)
    with pytest.raises(AttributeError):
        r.status = 404


def test_optional_fields_default_to_none_not_to_a_flattering_value():
    # secure=True was a policy default wearing a fact's clothes. Nothing here
    # may repeat that: an unknown fact is None, and a check that needs it is
    # disabled rather than answered.
    r = Response.from_parts()
    assert (r.status, r.reason, r.version, r.body, r.raw, r.fidelity) == (
        None, None, None, None, None, None
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_message_types.py -v`
Expected: FAIL — `ImportError: cannot import name 'Request' from 'http_security_test.message'`

- [ ] **Step 3: Write minimal implementation**

Append to `http_security_test/message.py`:

```python
import collections

_REQUEST_FIELDS = "url method version headers body raw fidelity"
_RESPONSE_FIELDS = "status reason version headers body raw fidelity"


class Request(collections.namedtuple("Request", _REQUEST_FIELDS,
                                     defaults=(None, None, (), None, None, None))):
    """One HTTP request as this package models it.

    `url` is required and is the one fact the wire cannot supply: an
    origin-form request line plus a Host header says nothing about the scheme,
    and the scheme is what decides HSTS suppression. Everything else is
    optional, because a redacted or truncated capture may genuinely lack it.

    `headers` is a tuple of (name, value) pairs in the order received, never a
    mapping: a mapping keeps one value per name, and repeated headers are not a
    corner case. Use mapping() for the derived view the analysers consume.
    """

    __slots__ = ()

    @classmethod
    def from_parts(cls, url, method=None, version=None, headers=(),
                   body=None, raw=None, fidelity=None):
        """A request from already-parsed pieces, as an adaptor supplies them."""
        return cls(url, method, version, tuple(tuple(p) for p in headers),
                   body, raw, fidelity)


class Response(collections.namedtuple("Response", _RESPONSE_FIELDS,
                                      defaults=(None, None, None, (), None, None, None))):
    """One HTTP response as this package models it.

    `reason` is None for an HTTP/2 exchange rather than empty: RFC 9113 carries
    only :status, so a reason phrase in an h2 capture was invented by whatever
    rendered it.
    """

    __slots__ = ()

    @classmethod
    def from_parts(cls, status=None, reason=None, version=None, headers=(),
                   body=None, raw=None, fidelity=None):
        """A response from already-parsed pieces, as an adaptor supplies them."""
        return cls(status, reason, version, tuple(tuple(p) for p in headers),
                   body, raw, fidelity)


def mapping(headers):
    """The lowercased `name -> [values]` view the analysers work from.

    Derived on demand rather than stored, so the pairs stay the single source
    of truth for order, duplication and reproduction of the head.
    """
    present = {}
    for name, value in headers:
        present.setdefault(name.strip().lower(), []).append(value)
    return present
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_message_types.py -v`
Expected: 6 passed

- [ ] **Step 5: Verify nothing else broke and lint is clean**

Run: `python -m pytest tests/ -q && ruff check`
Expected: 561 passed — the 555 existing, untouched, plus the 6 new. ruff clean

- [ ] **Step 6: Checkpoint**

Report to the human: `message.py` gained `Request`, `Response` and `mapping()`; nothing else changed; full suite green. **Do not commit** — tell them this is a commit point and let them do it.

---

### Task 2: The byte parser

**Files:**
- Modify: `http_security_test/message.py`
- Test: `tests/test_message_parser.py` (create)

**Interfaces:**
- Consumes: `Request`, `Response`, `mapping` from Task 1.
- Produces: `Request.from_bytes(data, url, fidelity=None)`, `Response.from_bytes(data, fidelity=None)`, and `message.parse_start_line(line)` returning `("request", method, target, version)` or `("response", version, status, reason)` or `None`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_message_parser.py` with the GPL notice, then:

```python
from http_security_test.message import Request, Response, mapping, parse_start_line

RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Security-Policy: default-src 'self'\r\n"
    b"Content-Security-Policy: script-src 'none'\r\n"
    b"Set-Cookie: a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT\r\n"
    b"\r\n"
    b"<html></html>"
)


def test_a_response_yields_status_reason_version_headers_and_body():
    r = Response.from_bytes(RESPONSE)
    assert (r.status, r.reason, r.version) == (200, "OK", "HTTP/1.1")
    assert mapping(r.headers)["content-security-policy"] == [
        "default-src 'self'", "script-src 'none'"
    ]
    assert r.body == b"<html></html>"
    assert r.raw == RESPONSE


def test_repeated_set_cookie_survives_the_comma_in_an_expires_date():
    # Comma-joining is the fourth wrong answer in CLAUDE.md's mapping table and
    # the nastiest, because the result still looks like a header value.
    r = Response.from_bytes(RESPONSE)
    assert mapping(r.headers)["set-cookie"] == [
        "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT"
    ]


def test_http_2_in_a_1_1_shaped_start_line_is_accepted():
    # Every capture tool writes this. Burp's own export is
    # `POST /x HTTP/2` with a Host header, and `HTTP/2 202 Accepted` with a
    # reason phrase h2 does not have. Rejecting it refuses the commonest input.
    r = Response.from_bytes(b"HTTP/2 202 Accepted\r\nDate: x\r\n\r\n")
    assert (r.version, r.status, r.reason) == ("HTTP/2", 202, "Accepted")
    q = Request.from_bytes(b"POST /x HTTP/2\r\nHost: a.example\r\n\r\n",
                           url="https://a.example/x")
    assert (q.method, q.version) == ("POST", "HTTP/2")


def test_bare_lf_is_accepted():
    r = Response.from_bytes(b"HTTP/1.1 200 OK\nX-A: 1\n\nbody")
    assert (r.status, r.body) == (200, b"body")


def test_a_response_with_no_reason_phrase_parses():
    # h11 serialises exactly this: "HTTP/1.1 200 \r\n".
    r = Response.from_bytes(b"HTTP/1.1 200 \r\nX-A: 1\r\n\r\n")
    assert (r.status, r.reason) == (200, None)


def test_garbage_never_raises_and_leaves_unknowns_none():
    r = Response.from_bytes(b"\x00\x01 not http at all")
    assert r.status is None and r.version is None
    assert r.raw == b"\x00\x01 not http at all"


def test_an_empty_message_never_raises():
    assert Response.from_bytes(b"").status is None


def test_a_latin1_header_value_survives():
    r = Response.from_bytes(b"HTTP/1.1 200 OK\r\nServer: caf\xe9-server\r\n\r\n")
    assert mapping(r.headers)["server"] == ["caf\xe9-server"]


def test_a_header_with_no_colon_is_skipped_not_fatal():
    r = Response.from_bytes(b"HTTP/1.1 200 OK\r\ngarbage line\r\nX-A: 1\r\n\r\n")
    assert mapping(r.headers) == {"x-a": ["1"]}


def test_no_body_gives_none_not_empty_bytes():
    # Absent beats empty: a message with no body and one with a zero-length
    # body are different facts.
    assert Response.from_bytes(b"HTTP/1.1 204 No Content\r\nX-A: 1\r\n\r\n").body is None


def test_text_input_is_accepted_and_encoded_latin_1():
    r = Response.from_bytes("HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\n")
    assert r.status == 200 and isinstance(r.raw, bytes)


def test_parse_start_line_discriminates_and_returns_none_on_nonsense():
    assert parse_start_line("HTTP/1.1 200 OK")[0] == "response"
    assert parse_start_line("GET / HTTP/1.1")[0] == "request"
    assert parse_start_line("nonsense") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_message_parser.py -v`
Expected: FAIL — `ImportError: cannot import name 'parse_start_line'`

- [ ] **Step 3: Write minimal implementation**

Append to `http_security_test/message.py`:

```python
def _as_bytes(data):
    """Bytes from bytes or text; text is latin-1, which is what headers are."""
    if isinstance(data, str):
        return data.encode("latin-1", "replace")
    return bytes(data)


def _split_head(data):
    """(head, body) at the first blank line, tolerating CRLF and bare LF.

    body is None when there is no blank line at all -- a truncated capture is
    a head with nothing after it, not a head with an empty body.
    """
    for separator in (b"\r\n\r\n", b"\n\n"):
        head, found, body = data.partition(separator)
        if found:
            return head, (body if body else None)
    return data, None


def parse_start_line(line):
    """Discriminate and split an HTTP start line, or None if it is neither.

    Returns ("response", version, status, reason) or
    ("request", method, target, version). Both forms are three
    space-separated fields, and which of them holds the version is what tells
    the two apart -- so `HTTP/2 202 Accepted` is a response and
    `POST /x HTTP/2` is a request, which is exactly how every capture tool
    renders an h2 exchange despite h2 having no start line at all.
    """
    fields = line.strip().split(" ", 2)
    if not fields or not fields[0]:
        return None
    if fields[0].upper().startswith("HTTP/"):
        if len(fields) < 2 or not fields[1].strip().isdigit():
            return None
        reason = fields[2].strip() if len(fields) > 2 and fields[2].strip() else None
        return ("response", fields[0], int(fields[1]), reason)
    if len(fields) == 3 and fields[2].upper().startswith("HTTP/"):
        return ("request", fields[0], fields[1], fields[2].strip())
    return None


def _parse_head(head):
    """(start_line_fields_or_None, header_pairs) from a decoded head block.

    Nothing here raises. This parses what a server actually sent, and a strict
    parser would refuse exactly the response most worth analysing.
    """
    lines = head.replace("\r\n", "\n").split("\n")
    start, offset = None, 0
    if lines:
        start = parse_start_line(lines[0])
        if start is not None:
            offset = 1
        elif ":" not in lines[0]:
            # An unparseable first line that is not a header either: skip it
            # rather than treating its text as a header name.
            offset = 1
    pairs = []
    for line in lines[offset:]:
        if not line.strip():
            continue
        if line[:1] in (" ", "\t") and pairs:
            # obs-fold: deprecated by RFC 9110 but still on the wire.
            name, value = pairs[-1]
            pairs[-1] = (name, value + " " + line.strip())
            continue
        name, found, value = line.partition(":")
        if not found or not name.strip():
            continue
        pairs.append((name.strip(), value.strip()))
    return start, tuple(pairs)
```

Then add the two constructors, inside the classes:

```python
    # ...inside Response
    @classmethod
    def from_bytes(cls, data, fidelity=None):
        """A response parsed from the bytes of one message.

        The primary constructor. It is what makes a byte-oriented source
        supportable at all -- scapy's structured model returns the LAST of two
        repeated headers, so its adaptor must ignore the model and come
        through here.
        """
        data = _as_bytes(data)
        head, body = _split_head(data)
        start, pairs = _parse_head(head.decode("latin-1"))
        status = reason = version = None
        if start is not None and start[0] == "response":
            _, version, status, reason = start
        return cls(status, reason, version, pairs, body, data, fidelity)
```

```python
    # ...inside Request
    @classmethod
    def from_bytes(cls, data, url, fidelity=None):
        """A request parsed from the bytes of one message, plus its URL.

        The URL is not optional and is not in the bytes: an origin-form request
        line carries a path, Host carries an authority, and neither says http
        or https.
        """
        data = _as_bytes(data)
        head, body = _split_head(data)
        start, pairs = _parse_head(head.decode("latin-1"))
        method = version = None
        if start is not None and start[0] == "request":
            _, method, _target, version = start
        return cls(url, method, version, pairs, body, data, fidelity)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_message_parser.py -v`
Expected: 12 passed

- [ ] **Step 5: Mutation-check the leniency guard**

Back up the file outside the repo first, because this deliberately breaks it:

```bash
cp http_security_test/message.py "$TMPDIR/message.py.bak"
```

In `_parse_head`, change `if not found or not name.strip(): continue` to `raise ValueError(line)`.
Run: `python -m pytest tests/test_message_parser.py -k no_colon -v`
Expected: FAIL. If it passes, the test is not pinning what it claims.

Restore with `cp "$TMPDIR/message.py.bak" http_security_test/message.py` — **never with git**.

- [ ] **Step 6: Verify the whole suite and lint**

Run: `python -m pytest tests/ -q && ruff check`
Expected: 573 passed (561 + the 12 new), ruff clean

- [ ] **Step 7: Checkpoint**

Report the parser's leniency rules and the mutation result. **Do not commit.**

---

### Task 3: `Exchange`, `Connection`, fidelity, and the URL guard

**Files:**
- Create: `http_security_test/exchange.py`
- Test: `tests/test_exchange.py` (create)

**Interfaces:**
- Consumes: `Request`, `Response` from Tasks 1–2.
- Produces: `exchange.Exchange(request, response, timestamp=None, connection=None)`, `exchange.Connection(host=None, ip=None, port=None, scheme=None)`, `exchange.FIDELITY` (a tuple), `exchange.scheme(url)`, `exchange.host(url)`, `exchange.url_was_mangled(url)`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_exchange.py` with the GPL notice, then:

```python
from http_security_test.exchange import (
    FIDELITY, Connection, Exchange, host, scheme, url_was_mangled,
)
from http_security_test.message import Request, Response


def _exchange(url="https://example.com/", **kw):
    return Exchange(Request.from_parts(url=url), Response.from_parts(status=200), **kw)


def test_scheme_and_host_come_from_the_url():
    assert scheme("https://Example.COM/a") == "https"
    assert host("https://Example.COM/a") == "example.com"


def test_host_drops_a_root_zone_trailing_dot():
    assert host("https://example.com./") == "example.com"


def test_a_malformed_url_yields_empty_rather_than_raising():
    # File sources hand over whatever was recorded, including invalid IPv6
    # authorities. A source of bad data must not become a traceback.
    assert host("http://[::1") == ""
    assert scheme("::::") == ""


def test_url_was_mangled_catches_what_urlsplit_silently_strips():
    # urlsplit removes CR, LF and TAB anywhere in the URL (bpo-43882). That is
    # right for a client avoiding SSRF and wrong for a tool whose job is to
    # notice a CRLF payload, so the fact is kept rather than the parse trusted.
    assert url_was_mangled("https://example.com/x\r\nSet-Cookie: evil=1") is True
    assert url_was_mangled("https://exam\rple.com/") is True
    assert url_was_mangled("https://example.com/ordinary") is False


def test_timestamp_and_connection_belong_to_the_exchange_not_a_message():
    # A request does not carry when it was sent, and Date is the server's
    # clock on the response. The hostname actually connected to is separate
    # from Host: because Host: can be forged.
    e = _exchange(
        timestamp="2026-08-24T12:00:00Z",
        connection=Connection(host="example.com", ip="93.184.216.34",
                              port=443, scheme="https"),
    )
    assert e.timestamp == "2026-08-24T12:00:00Z"
    assert e.connection.ip == "93.184.216.34"


def test_knowing_nothing_about_the_connection_is_one_none():
    assert _exchange().connection is None


def test_fidelity_vocabulary_is_closed_and_ordered_worst_last():
    assert FIDELITY == ("capture", "reconstructed", "redacted")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_exchange.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'http_security_test.exchange'`

- [ ] **Step 3: Write minimal implementation**

Create `http_security_test/exchange.py` with the GPL notice, then:

```python
"""One HTTP exchange: a request, its response, and the facts neither carries.

A request does not record when it was sent, and `Date` is the server's clock on
the response side. The hostname, IP and port actually connected to are
deliberately apart from `Host:`, because `Host:` can be forged and a test that
forges it is a thing security tools do on purpose -- Burp and mitmproxy both
model the two separately for that reason.

That is why this type exists now even though every exchange-level *rule* is
still parked: the rules can wait, the data has nowhere else to live.
"""

import collections
import urllib.parse

# What a raw blob is, worst last. `capture` is the bytes as they crossed the
# wire; `reconstructed` is a reassembly from a parsed model, which includes
# EVERY HTTP/2 exchange, since h2 has no start line and whatever rendered it
# invented one; `redacted` is a reconstruction known to have lost content.
FIDELITY = ("capture", "reconstructed", "redacted")

Connection = collections.namedtuple(
    "Connection", "host ip port scheme", defaults=(None, None, None, None)
)

Exchange = collections.namedtuple(
    "Exchange", "request response timestamp connection", defaults=(None, None)
)


def scheme(url):
    """The lowercased scheme, or "" when the URL will not parse.

    This replaces the old `secure` argument. A scheme that is stated cannot be
    defaulted to the flattering value, which is what `secure=True` did.
    """
    try:
        return urllib.parse.urlsplit(url).scheme.lower()
    except ValueError:
        return ""


def host(url):
    """The lowercased hostname with any root-zone trailing dot removed."""
    try:
        name = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return ""
    return (name or "").lower().rstrip(".")


def url_was_mangled(url):
    """Whether urlsplit would silently drop characters from this URL.

    `urlsplit` strips ASCII CR, LF and TAB from anywhere in a URL -- the
    bpo-43882 hardening -- so `https://example.com/x\\r\\nSet-Cookie: evil=1`
    parses to a clean-looking path and `geturl()` does not round-trip. Correct
    for a client avoiding SSRF, wrong for a tool whose job is to notice the
    payload. Nothing decides on this yet; it is kept so it is not lost.
    """
    return any(c in url for c in "\r\n\t")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_exchange.py -v`
Expected: 7 passed

- [ ] **Step 5: Verify the whole suite and lint**

Run: `python -m pytest tests/ -q && ruff check`
Expected: 580 passed (573 + the 7 new), ruff clean

- [ ] **Step 6: Checkpoint**

**Do not commit.** Note for the human that `scheme()`/`host()` here duplicate `cli/exchange.py`'s helpers on purpose for now; Task 6 deletes the CLI copies.

---

### Task 4: `analyze(exchange)` and `inventory(exchange)`

**Files:**
- Modify: `http_security_test/response.py`
- Modify: `tests/test_headers.py` (~105 call sites)
- Test: `tests/test_headers.py`

**Interfaces:**
- Consumes: `Exchange`, `scheme`, `host` from Task 3; `mapping` from Task 1.
- Produces: `response.analyze(exchange) -> [Finding]`, `response.inventory(exchange) -> dict`. Deletes `analyze_all`, the public `analyze(name, value)` (now `_analyze_header`), and the old `inventory(present)`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_headers.py`:

```python
from http_security_test import analyze, inventory
from http_security_test.exchange import Exchange
from http_security_test.message import Request, Response


def _ex(headers=None, url="https://example.com/", status=200):
    """One exchange from a header mapping, for the tests that predate types."""
    pairs = []
    for name, value in (headers or {}).items():
        for one in ([value] if isinstance(value, str) else value):
            pairs.append((name, one))
    return Exchange(
        Request.from_parts(url=url),
        Response.from_parts(status=status, headers=pairs),
    )


def test_analyze_takes_an_exchange_and_returns_findings():
    codes = {f.code for f in analyze(_ex())}
    assert "csp-missing" in codes


def test_the_scheme_comes_from_the_url_not_from_an_argument():
    # Over plaintext a browser ignores HSTS entirely, so its absence is not a
    # defect. That used to be `secure=False`; it is now a fact about the URL.
    over_tls = {f.code for f in analyze(_ex(url="https://example.com/"))}
    plaintext = {f.code for f in analyze(_ex(url="http://example.com/"))}
    assert "hsts-missing" in over_tls
    assert "hsts-missing" not in plaintext


def test_an_unparseable_url_disables_the_scheme_dependent_check():
    # A missing input disables the checks that need it. It never defaults them.
    codes = {f.code for f in analyze(_ex(url="::::"))}
    assert "hsts-missing" not in codes


def test_inventory_takes_an_exchange():
    found = inventory(_ex({"X-Frame-Options": "DENY"}))
    assert found["security"]["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in found["missing"]


def test_the_old_entry_points_are_gone():
    # No compatibility shim was wanted. A caller who kept the old call gets an
    # AttributeError now rather than a silently different analysis.
    import http_security_test

    assert not hasattr(http_security_test, "analyze_all")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_headers.py -k "exchange or scheme_comes or old_entry" -v`
Expected: FAIL — `ImportError: cannot import name 'analyze'` (the current `analyze` has a different signature and `_ex` is undefined)

- [ ] **Step 3: Write minimal implementation**

In `http_security_test/response.py`:

1. Rename `def analyze(name, value)` to `def _analyze_header(name, value)` and update its call site inside the old `analyze_all` body.
2. Replace `def analyze_all(present, secure=True, host=None)` with:

```python
def analyze(exchange):
    """Every finding for one exchange.

    The scheme and host come from the request URL rather than from arguments,
    which is what stops a caller silently claiming TLS by omission. A URL that
    will not parse yields "" for both, and every check that needs one is
    disabled rather than answered -- a missing input disables, it never
    defaults.
    """
    present = _normalize(_mapping(exchange.response.headers))
    url = exchange.request.url
    secure = _scheme(url) == "https"
    name = _host(url) or None
    findings = _report_missing(present, secure)
    ...  # the rest of the existing body, unchanged, using `present`
```

Keep the whole existing body from `findings = _report_missing(...)` onward; only the first three lines and the signature change. Import at the top of `response.py`:

```python
from .exchange import host as _host, scheme as _scheme
from .message import mapping as _mapping
```

3. Change `def inventory(present)` to `def inventory(exchange)` and make its first line `present = _normalize(_mapping(exchange.response.headers))`.

4. In `http_security_test/__init__.py`, replace `analyze, analyze_all, inventory` in the `.response` import and in `__all__` with `analyze, inventory`.

- [ ] **Step 4: Migrate the existing call sites**

`tests/test_headers.py` has ~60 `analyze_all(...)` and ~19 `inventory(...)` calls. Rewrite each mechanically:

| was | becomes |
|---|---|
| `headers.analyze_all({...})` | `analyze(_ex({...}))` |
| `headers.analyze_all({...}, secure=False)` | `analyze(_ex({...}, url="http://example.com/"))` |
| `headers.analyze_all({...}, host="x.com")` | `analyze(_ex({...}, url="https://x.com/"))` |
| `headers.inventory(X)` | `inventory(_ex(X))` |
| `headers.analyze("X-Frame-Options", "DENY")` | `response._analyze_header("X-Frame-Options", "DENY")` |

Do them in one pass and re-run after each file section, not at the end.

- [ ] **Step 5: Run the whole suite**

Run: `python -m pytest tests/ -q`
Expected: all green except the CLI tests, which still call `report(present, ...)`. Task 7 fixes those. If any *analyser* test fails, the migration is wrong — fix it before moving on.

- [ ] **Step 6: Behavioural equivalence check**

The refactor must not change a single verdict. Compare old against new over the corpus:

```bash
mkdir -p "$TMPDIR/equiv" && git show HEAD:http_security_test/response.py > "$TMPDIR/equiv/old_response.py"
```

Write a throwaway script that runs every header mapping in `tests/test_headers.py`'s corpus through both and diffs the `(header, code)` sets. Zero mismatches is the bar; both previous module splits were verified this way at 335 and 168 cases.

- [ ] **Step 7: Checkpoint**

Report the equivalence result with the case count. **Do not commit.**

---

### Task 5: The status line stops the 301 false positive

**Files:**
- Modify: `http_security_test/response.py`
- Test: `tests/test_headers.py`

**Interfaces:**
- Consumes: `analyze(exchange)` from Task 4.
- Produces: no new names. `_report_missing` gains a `status` parameter.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_headers.py`:

```python
# The six representation-scoped headers a bare redirect used to be scolded for.
REPRESENTATION_MISSING = {
    "csp-missing", "coop-missing", "corp-missing",
    "rp-missing", "xcto-missing", "xfo-missing",
}


def test_a_bare_redirect_is_not_scolded_for_headers_it_has_nothing_to_protect():
    # Measured before the fix: a bare 301 emitted all six. That is principle 4
    # once per hop, and it is why --all-hops was blocked.
    codes = {f.code for f in analyze(_ex({"Location": "https://example.com/next"},
                                         status=301))}
    assert not (codes & REPRESENTATION_MISSING)


def test_hsts_is_still_demanded_on_a_redirect():
    # A redirect over https is precisely where HSTS matters, so it is NOT in
    # the suppressed set. Getting this wrong would make per-hop analysis
    # worthless rather than merely noisy.
    codes = {f.code for f in analyze(_ex({}, status=301))}
    assert "hsts-missing" in codes


def test_a_200_still_gets_all_six():
    codes = {f.code for f in analyze(_ex({}, status=200))}
    assert REPRESENTATION_MISSING <= codes


def test_an_unknown_status_still_gets_all_six():
    # Absent status disables nothing: not knowing the status is not evidence
    # that the response carried no representation.
    codes = {f.code for f in analyze(_ex({}, status=None))}
    assert REPRESENTATION_MISSING <= codes
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_headers.py -k redirect -v`
Expected: FAIL — the 301 case reports all six

- [ ] **Step 3: Write minimal implementation**

In `http_security_test/response.py`:

```python
# Headers that protect a representation. A 3xx carries none, so demanding them
# there is a false positive once per hop -- measured at six on a bare 301.
# HSTS is deliberately absent: on the https legs of a chain a redirect is
# exactly where it matters.
REPRESENTATION_HEADERS = (
    "Content-Security-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Referrer-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
)


def _carries_a_representation(status):
    """Whether a response of this status has content for a header to protect.

    None means unknown, and unknown is not evidence of absence: every check
    stays on. Only a status we can read and that says 3xx suppresses.
    """
    return not (status is not None and 300 <= status < 400)
```

Then in `_report_missing(present, secure, status=None)`, add after the HSTS clause:

```python
        if not _carries_a_representation(status) and name in REPRESENTATION_HEADERS:
            continue
```

and pass `exchange.response.status` through from `analyze()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_headers.py -k "redirect or six" -v`
Expected: 4 passed

- [ ] **Step 5: Mutation-check the HSTS exclusion**

```bash
cp http_security_test/response.py "$TMPDIR/response.py.bak"
```

Add `"Strict-Transport-Security"` to `REPRESENTATION_HEADERS`.
Run: `python -m pytest tests/test_headers.py -k hsts_is_still_demanded -v`
Expected: FAIL. Restore with `cp "$TMPDIR/response.py.bak" http_security_test/response.py`.

- [ ] **Step 6: Verify the suite and lint**

Run: `python -m pytest tests/ -q && ruff check`
Expected: analyser tests green, CLI tests still failing from Task 4, ruff clean

- [ ] **Step 7: Checkpoint**

**Do not commit.** Note that `--all-hops` remains parked; this only removes the reason it was blocked.

---

### Task 6: Rename `cli/exchange.py` to `cli/outcome.py`

**Files:**
- Create: `http_security_test/cli/outcome.py`
- Delete: `http_security_test/cli/exchange.py`
- Modify: `http_security_test/cli/live.py`, `commands.py`, `run.py`
- Modify: `tests/test_cli_exchange.py` → `tests/test_cli_outcome.py`, `tests/test_cli_run.py`, `tests/test_cli_text.py`, `tests/test_cli_live.py`, `tests/test_cli_scan.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `cli.outcome.Hop`, `cli.outcome.Failure`, `cli.outcome.FAILURE_KINDS`. `cli.outcome` does **not** define an `Exchange`, `secure()` or `host()`.

Purely mechanical, and separated from Task 7 so the rename can be reviewed without the rewiring on top of it.

- [ ] **Step 1: Create the new module**

`git show HEAD:http_security_test/cli/exchange.py > /dev/null` first to confirm you are reading the committed version, then create `cli/outcome.py` holding only `Hop`, `Failure` and `FAILURE_KINDS`, with the GPL notice and this docstring:

```python
"""What the CLI's own run produced, as distinct from what crossed the wire.

`Hop`'s `followed` and `refused` are --scope outcomes: what this tool chose to
do, not facts about HTTP. Its `origin`, `code` and `destination` ARE wire facts
and are derivable from a list of exchanges, which is why the analyser needs no
hop type of its own to gain chain analysis later.

The old cli/exchange.py also held url, status, reason, headers and the raw
blobs. Those are message facts and now live in the analyser, along with the
secure()/host() helpers that existed only to crumble a URL on its behalf.
"""
```

- [ ] **Step 2: Update every importer**

```bash
grep -rn "cli import exchange\|cli\.exchange\|exchange\.Failure\|exchange\.Hop\|exchange\.FAILURE_KINDS" \
  http_security_test/ tests/
```

Replace `exchange` with `outcome` at each hit. Leave `exchange.Exchange`, `exchange.secure` and `exchange.host` references alone — Task 7 removes them.

- [ ] **Step 3: Delete the old module and rename its test**

```bash
rm http_security_test/cli/exchange.py
mv tests/test_cli_exchange.py tests/test_cli_outcome.py
```

Strip the `secure()`/`host()`/`Exchange` tests out of the renamed test file; they move to `tests/test_exchange.py`, where Task 3 already covers them.

- [ ] **Step 4: Run the suite**

Run: `python -m pytest tests/ -q && ruff check`
Expected: same failures as after Task 5 and no new ones. A `ModuleNotFoundError` for `cli.exchange` means an importer was missed.

- [ ] **Step 5: Checkpoint**

**Do not commit.**

---

### Task 7: `report(exchange)` with fidelity, and the CLI rewired

**Files:**
- Modify: `http_security_test/reporting.py`
- Modify: `http_security_test/cli/live.py`, `commands.py`, `run.py`
- Test: `tests/test_headers.py`, `tests/test_cli_scan.py`, `tests/test_cli_run.py`

**Interfaces:**
- Consumes: `analyze`, `inventory` (Task 4); `Exchange`, `FIDELITY` (Task 3).
- Produces: `reporting.report(exchange, message=True) -> dict`. Deletes the old signature entirely. `cli/live.py` now yields `Exchange` objects.

Bundled because the CLI is `report()`'s only in-tree consumer: splitting them leaves the suite red with nothing to review.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_headers.py`:

```python
from http_security_test import report


def test_report_takes_an_exchange_and_keeps_its_shape():
    doc = report(_ex({"X-Frame-Options": "DENY"}))
    assert set(doc["response"]) >= {"findings", "inventory", "references"}
    assert "url" not in doc["response"]  # a response does not know where it came from


def test_fidelity_rides_beside_raw_and_is_absent_when_raw_is():
    body = b"HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\n"
    e = Exchange(
        Request.from_parts(url="https://example.com/"),
        Response.from_bytes(body, fidelity="capture"),
    )
    doc = report(e)
    assert doc["response"]["fidelity"] == "capture"
    assert "raw" in doc["response"]

    bare = report(_ex({"X-Frame-Options": "DENY"}))
    assert "raw" not in bare["response"] and "fidelity" not in bare["response"]


def test_a_reconstruction_is_never_presented_as_a_capture():
    # from_parts has no wire bytes to offer, so it offers none rather than
    # reassembling them. Absent beats empty.
    e = Exchange(Request.from_parts(url="https://example.com/"),
                 Response.from_parts(status=200))
    assert "raw" not in report(e)["response"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_headers.py -k "report_takes or fidelity" -v`
Expected: FAIL — `report()` still takes `present`

- [ ] **Step 3: Rewrite `report()`**

In `http_security_test/reporting.py`:

```python
def report(exchange, message=True):
    """Findings and inventories for one exchange, ready to serialise.

    `raw` and `fidelity` travel together: a blob with no statement of what it
    is cannot be trusted for reproduction, and a statement with no blob says
    nothing. Both are absent when the caller supplied no bytes -- content this
    package derived is always present, content it was merely given is present
    only if it was given.
    """
    findings = order_findings(analyze(exchange))
    response = {
        "findings": [finding_as_dict(f, message=message) for f in findings],
        "inventory": inventory(exchange),
        "references": _references(findings),
    }
    _attach_raw(response, exchange.response)

    result = {"response": response}
    request = {}
    _attach_raw(request, exchange.request)
    if request:
        result["request"] = request
    return result


def _attach_raw(target, message):
    """The raw blob and its fidelity, or neither."""
    if message.raw is None:
        return
    target["raw"] = _blob(message.raw)
    if message.fidelity is not None:
        target["fidelity"] = message.fidelity
```

Update the module docstring's schema block to show `fidelity` beside `raw`, and replace the paragraph beginning *"The `raw` blobs are optional passthrough"* with one that states the capture/reconstructed/redacted vocabulary. Keep the credential warning verbatim — it was never a redaction feature and the spec keeps it.

- [ ] **Step 4: Rewire `cli/live.py`**

`live.py` currently yields `exchange.Exchange(kind, target, url, status, ...)`. It now yields the analyser's `Exchange`, carrying the run facts alongside rather than inside. Change `fetch()` to yield a `(runfacts, analyser_exchange)` pair, where `runfacts` is a small namedtuple in `outcome.py`:

```python
Run = collections.namedtuple("Run", "kind target url status reason hops",
                             defaults=((),))
```

and build the analyser exchange from what was fetched:

```python
        response = Response.from_bytes(raw_response, fidelity="capture") \
            if raw_response is not None else Response.from_parts(
                status=status, reason=reason, headers=list(head.items()))
        request = Request.from_bytes(raw_request, url=url, fidelity="capture") \
            if raw_request is not None else Request.from_parts(url=url)
        yield Run(kind, target, url, status, reason, hops), Exchange(request, response)
```

`--raw` is what decides whether `raw_request`/`raw_response` exist, so fidelity is `"capture"` exactly when real bytes were kept, and absent otherwise. That is the spec's rule stated by provenance.

- [ ] **Step 5: Rewire `cli/commands.py`**

Replace the `report(...)` call at [commands.py:195-201](../../../http_security_test/cli/commands.py#L195-L201):

```python
            results.append(run.analysed(facts, report(item)))
```

and delete the three-line comment above it about `secure` and `host` — the URL now carries both, so the warning it gave has no subject. Iterate `for facts, item in source(target, options):` and test `isinstance(facts, outcome.Failure)` on the failure path.

- [ ] **Step 6: Rewire `cli/run.py`**

`analysed(item, report)` reads `item.kind`, `item.url`, `item.status`, `item.reason`, `item.hops` — all now on `Run`, with the same attribute names, so only the parameter name and docstring change. Rename the parameter to `facts` for clarity.

- [ ] **Step 7: Run the whole suite**

Run: `python -m pytest tests/ -q && ruff check`
Expected: **everything green.** This is the task that closes the red window Task 4 opened. If `tests/cli_terminal_snapshot.txt` mismatches, read the diff before regenerating — the renderer's output should not have changed at all, and a changed snapshot here means a real behaviour change slipped in.

- [ ] **Step 8: End-to-end check against a real host**

Run: `python -m http_security_test.cli scan -j https://example.com | python -m json.tool | head -40`
Expected: a valid run document with `results[0].report.response.findings`, and **no** `fidelity` key (no `--raw`). Then:

Run: `python -m http_security_test.cli scan -j --raw https://example.com | python -m json.tool | grep -c fidelity`
Expected: at least 1

- [ ] **Step 9: Checkpoint**

Report both command outputs. **Do not commit.**

---

### Task 8: `adaptors.py`

**Files:**
- Create: `http_security_test/adaptors.py`
- Test: `tests/test_adaptors.py` (create)

**Interfaces:**
- Consumes: `Request`, `Response` (Tasks 1–2).
- Produces: `adaptors.from_http_client`, `from_requests`, `from_niquests`, `from_httpx`, `from_aiohttp`, `from_urllib3`, `from_tornado`, `from_curl_cffi`, `from_geventhttpclient`, `from_mitmproxy`, `from_scapy`, `from_werkzeug`, `from_starlette`, and `adaptors.http_version(value)`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_adaptors.py` with the GPL notice. Test against fakes, never real libraries — every adaptor is attribute reads, so a fake is a faithful stand-in and the suite installs nothing:

```python
import types

import pytest

from http_security_test import adaptors
from http_security_test.message import mapping

PAIRS = [
    ("Content-Security-Policy", "default-src 'self'"),
    ("Content-Security-Policy", "script-src 'none'"),
    ("Set-Cookie", "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT"),
]


class FakeHeaderDict:
    """urllib3's HTTPHeaderDict: get_all() is right, [name] comma-joins."""

    def __init__(self, pairs):
        self._pairs = list(pairs)

    def get_all(self, name):
        return [v for k, v in self._pairs if k.lower() == name.lower()]

    def items(self):
        return iter(self._pairs)

    def __getitem__(self, name):
        return ", ".join(self.get_all(name))


class FakeCaseInsensitiveDict(dict):
    """requests' CaseInsensitiveDict: duplicates already destroyed."""


@pytest.mark.parametrize("value,expected", [
    (11, "HTTP/1.1"),
    (10, "HTTP/1.0"),
    ("HTTP/1.1", "HTTP/1.1"),
    ("HTTP/2", "HTTP/2"),
    (types.SimpleNamespace(major=1, minor=1), "HTTP/1.1"),
    (None, None),
])
def test_http_version_normalises_every_encoding_we_found(value, expected):
    assert adaptors.http_version(value) == expected


def test_libcurls_integer_2_means_http_1_1_not_http_2():
    # CurlHttpVersion.V1_1 == 2, V2_0 == 3, V3 == 30. Reading `2` as HTTP/2 is
    # the trap this adaptor exists to own, and it is libcurl's rather than
    # curl_cffi's -- pycurl reports it identically.
    assert adaptors.curl_version(2) == "HTTP/1.1"
    assert adaptors.curl_version(3) == "HTTP/2"
    assert adaptors.curl_version(30) == "HTTP/3"


def test_from_requests_reads_raw_headers_not_headers():
    # .headers is a CaseInsensitiveDict and has already comma-joined the two
    # CSP policies with no accessor to recover them. Reading it would invert
    # the conjunctive-enforcement rule and make Set-Cookie unparseable.
    fake = types.SimpleNamespace(
        status_code=200,
        headers=FakeCaseInsensitiveDict({"Content-Security-Policy": "a, b"}),
        raw=types.SimpleNamespace(version=11, headers=FakeHeaderDict(PAIRS)),
        request=types.SimpleNamespace(
            method="GET", url="https://example.com/",
            headers=FakeCaseInsensitiveDict({"Accept": "*/*"})),
    )
    request, response = adaptors.from_requests(fake)
    assert mapping(response.headers)["content-security-policy"] == [
        "default-src 'self'", "script-src 'none'"
    ]
    assert response.version == "HTTP/1.1"
    assert request.url == "https://example.com/"


def test_an_adaptor_never_touches_the_body():
    # aiohttp's .read() is a coroutine, so a sync adaptor structurally cannot
    # read a body; and reading requests' .content on a stream=True response
    # materialises the whole thing silently. So no adaptor reads one, and the
    # caller passes it explicitly if they want it.
    touched = []

    class Trap:
        status_code = 200
        raw = types.SimpleNamespace(version=11, headers=FakeHeaderDict(PAIRS))
        request = types.SimpleNamespace(method="GET", url="https://x/", headers={})
        headers = FakeCaseInsensitiveDict()

        @property
        def content(self):
            touched.append(True)
            raise AssertionError("adaptor read the body")

    adaptors.from_requests(Trap())
    assert touched == []


def test_from_scapy_ignores_the_model_and_parses_the_bytes():
    # scapy is the inverse of every other library: byte-identical round trip,
    # but its named fields return the LAST of two repeated headers. The only
    # correct adaptor takes raw(pkt) and comes through from_bytes().
    raw = (b"HTTP/1.1 200 OK\r\n"
           b"Content-Security-Policy: default-src 'self'\r\n"
           b"Content-Security-Policy: script-src 'none'\r\n\r\n")
    response = adaptors.from_scapy_bytes(raw)
    assert mapping(response.headers)["content-security-policy"] == [
        "default-src 'self'", "script-src 'none'"
    ]
    assert response.fidelity == "capture"


def test_there_is_no_httplib2_adaptor():
    # Its Response is a dict subclass; duplicates are comma-joined with no
    # accessor and no underlying object. The data is destroyed before we could
    # see it, so the absence is deliberate and this pins it.
    assert not hasattr(adaptors, "from_httplib2")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_adaptors.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'http_security_test.adaptors'`

- [ ] **Step 3: Write minimal implementation**

Create `http_security_test/adaptors.py` with the GPL notice and this docstring:

```python
"""Converters from live HTTP library objects into this package's types.

A convenience, never a requirement: a caller who wants to control loading,
streaming or truncation builds Request and Response directly. These exist for
the case where our decisions are acceptable.

Nothing here imports the library it adapts. Every adaptor is attribute reads,
so the package keeps its zero dependencies and the tests need nothing
installed. There is deliberately no introspection dispatch either: requests and
httpx both spell it `.headers`, both are dict-like, and one of them destroys
duplicates -- so a converter that guessed from attribute names would pick the
destroying one and say nothing.

**No adaptor reads a body.** aiohttp's read() is a coroutine, so a synchronous
adaptor structurally cannot; and where it is possible it is harmful, since
touching requests' .content on a stream=True response materialises the whole
body with no error to notice. The body is always the caller's explicit act.
"""
```

Then:

```python
_CURL_VERSIONS = {0: None, 1: "HTTP/1.0", 2: "HTTP/1.1", 3: "HTTP/2",
                  4: "HTTP/2", 5: "HTTP/2", 30: "HTTP/3", 31: "HTTP/3"}


def curl_version(value):
    """libcurl's CURL_HTTP_VERSION_* constant as a wire token.

    V1_1 is 2 and V2_0 is 3, so the naive reading of `2` is off by one whole
    protocol version. pycurl and curl_cffi both report it this way.
    """
    return _CURL_VERSIONS.get(value)


def http_version(value):
    """One of the five encodings we found, as the wire token.

    'HTTP/1.1' passes through; 11 and 10 are the stdlib/urllib3 integers;
    aiohttp hands over a namedtuple with .major and .minor; None stays None.
    NOT libcurl's -- that one is ambiguous with the integers and has its own
    function.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value if value.upper().startswith("HTTP/") else None
    if isinstance(value, int):
        return {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(value)
    major = getattr(value, "major", None)
    minor = getattr(value, "minor", None)
    if major is None:
        return None
    return "HTTP/%d.%d" % (major, minor or 0)


def _pairs(container):
    """Ordered (name, value) pairs from any header container that has them.

    Tried in the order that preserves duplicates. `items()` is last because it
    is the only one CaseInsensitiveDict has, and for that type it is already
    lossy -- callers that could hit one must reach past it first.
    """
    for accessor in ("get_all", "getlist", "getall", "get_list"):
        if hasattr(container, accessor) and hasattr(container, "keys"):
            names = []
            for name in container.keys():
                if name.lower() not in [n.lower() for n in names]:
                    names.append(name)
            pairs = []
            for name in names:
                for value in getattr(container, accessor)(name):
                    pairs.append((name, value))
            return tuple(pairs)
    return tuple((k, v) for k, v in container.items())
```

Then one small function per library. `from_requests` and `from_niquests` are the two that carry real knowledge:

```python
def from_requests(response):
    """(Request, Response) from a requests.Response.

    Reads `.raw.headers`, NOT `.headers`. The latter is a CaseInsensitiveDict
    that has already comma-joined repeated headers with no accessor to recover
    them: two CSP policies become one string, which inverts the conjunctive
    rule, and two Set-Cookie values become unparseable because an Expires date
    contains a comma. Those five lines are the whole value of this function.
    """
    raw = response.raw
    reply = Response.from_parts(
        status=response.status_code,
        version=http_version(getattr(raw, "version", None)),
        headers=_pairs(raw.headers),
    )
    sent = response.request
    query = Request.from_parts(
        url=sent.url,
        method=sent.method,
        headers=_pairs(sent.headers),
    )
    return query, reply
```

`from_scapy_bytes(raw)` is `Response.from_bytes(raw, fidelity="capture")` with a docstring saying why the model is bypassed. Write the remaining adaptors the same shape; each is under fifteen lines.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_adaptors.py -v`
Expected: all passed

- [ ] **Step 5: Verify against the real libraries, out of tree**

The research venv at `./venv` has them installed. Run the probes from the design session's evidence — do **not** add this to the suite, which must install nothing:

```bash
./venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from http_security_test import adaptors
import requests
from http_security_test.message import mapping
r = requests.get('https://example.com')
q, p = adaptors.from_requests(r)
print(p.status, p.version, len(p.headers), q.url)
"
```

Expected: a status, `HTTP/1.1`, a plausible header count, the URL.

- [ ] **Step 6: Verify the suite and lint**

Run: `python -m pytest tests/ -q && ruff check`
Expected: all green, ruff clean

- [ ] **Step 7: Checkpoint**

**Do not commit.**

---

### Task 9: Layering, exports, and the docs

**Files:**
- Modify: `http_security_test/__init__.py`
- Modify: `tests/test_cli_structure.py`
- Modify: `CLAUDE.md`
- Modify: `docs/TODO.md` — **NO.** `docs/TODO.md` says *"Human maintained notes, agents must not edit."* Leave it alone; tell the human which line is now done.

**Interfaces:**
- Consumes: everything above.
- Produces: `__init__` exporting the core only; `test_cli_structure.py` enforcing a direction rule rather than a single-name check.

- [ ] **Step 1: Write the failing test**

Replace `test_no_analyser_module_imports_the_cli` in `tests/test_cli_structure.py` with a direction rule, keeping `_imports_cli` as a helper:

```python
# Lowest first. A module may import its own layer and anything below it.
LAYERS = ("core", "adaptors", "formats", "cli")

CORE = (
    "findings", "catalog", "message", "references", "csp", "hsts",
    "isolation", "policies", "legacy", "response", "reporting", "exchange",
)


def _layer_of(name):
    if name in CORE:
        return "core"
    return name if name in LAYERS else "core"


def _imported_layers(path):
    """The layers this module imports from, by first path component."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level:
            head = (node.module or "").split(".")[0]
            if head:
                found.add(_layer_of(head))
            else:
                found.update(_layer_of(a.name) for a in node.names)
    return found


def test_imports_only_ever_run_downhill():
    # Replaces a single-name check ("nothing outside cli/ may import cli") with
    # the rule that check was an instance of. It now also catches a format
    # parser reaching into adaptors, which the old one could not see.
    offenders = []
    for path in sorted(PACKAGE.glob("*.py")):
        if path.stem == "__init__":
            continue
        mine = LAYERS.index(_layer_of(path.stem))
        for other in _imported_layers(path):
            if LAYERS.index(other) > mine:
                offenders.append("%s -> %s" % (path.name, other))
    assert offenders == []


def test_importing_the_library_does_not_import_the_adaptors_or_the_cli():
    # __init__ exports the core only, which is what keeps the base import
    # cheap and dependency-free.
    probe = (
        "import http_security_test, sys; "
        "print(sorted(m for m in ('http_security_test.cli', "
        "'http_security_test.adaptors') if m in sys.modules))"
    )
    done = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert done.stdout.strip() == "[]"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli_structure.py -v`
Expected: FAIL — `__init__.py` currently has no adaptors import, so the second test may pass; the first fails only if a real violation exists. **If both pass immediately, mutate to confirm they can fail:** add `from . import adaptors` to `__init__.py`, re-run, see the second test fail, then remove it.

- [ ] **Step 3: Make `__init__` export the core only**

Remove any `adaptors` import from `http_security_test/__init__.py` and add to its docstring:

```
`adaptors` and (later) `formats` are deliberately NOT imported here. Importing
this package pulls in the analysis core and nothing else, which is what lets it
sit in a Burp extension or a CI job without dragging a tool along. Reach for
`from http_security_test import adaptors` when you want one.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cli_structure.py -v`
Expected: all passed

- [ ] **Step 5: Update CLAUDE.md**

Edit these sections, and no others:

1. **Layout** — add `exchange.py` and `adaptors.py`; change `cli/exchange.py` to `cli/outcome.py` with its new one-line description.
2. **Dependencies run one way** — replace the block with the four-layer direction rule and note that the test now enforces direction rather than a single name.
3. **The header mapping (easy to get wrong)** — add the fourth row to the access table: `CaseInsensitiveDict[name]` → **comma-joined**, with the `Expires`-date example showing 3 pieces for 2 cookies.
4. **The output schema** — add `fidelity` beside `raw` and the three-value vocabulary.
5. **Parked, with intent to do** — strike `--all-hops`'s blocker (the status line is now read), and add the three newly-unblocked finding families: protocol hygiene, verb/preflight, TRACE/XST.
6. **Working practices** — one sentence that `urllib.parse` is permitted in the analyser and `urllib.request` is not, since a reader will otherwise see `import urllib.parse` in `exchange.py` and call it a breach.
7. **Status** — update the test count and note the new modules.

Do **not** rewrite the design principles; none of them changed.

- [ ] **Step 6: Full verification**

Run: `python -m pytest tests/ -q && ruff check`
Expected: all green, ruff clean

Then confirm the claim CLAUDE.md's opening paragraph makes is still literally true:

```bash
python -c "import http_security_test, sys; print([m for m in sys.modules if 'socket' in m or 'urllib.request' in m])"
```

Expected: `[]`

- [ ] **Step 7: Checkpoint**

Report the final test count, and tell the human that `docs/TODO.md`'s line *"change api to expect full request/response pairs first, break down for just response, just headers, etc."* is now done and is theirs to strike — an agent must not edit that file.

---

## Self-Review

**Spec coverage.** Every section of the spec maps to a task: the types and required/optional rule → 1, 3; the byte parser and its leniency rules → 2; the URL guard and `urllib.parse` lossiness → 3; fidelity → 3, 7; adaptors including the head-only rule and the httplib2 exclusion → 8; the layering, `__init__` and the `live.py` carve-out → 9; what moves out of `cli/exchange.py` → 6, 7; the status-line open question → 5. **Deliberately unimplemented, as the spec says:** request analysis, meta-derived headers, the three new finding families, chain analysis, and `formats/` — which gets its decision recorded in CLAUDE.md (Task 9) and its directory when the first parser lands.

**Placeholders.** None. Task 8 says "write the remaining adaptors the same shape" after giving the full shape and the two that carry real knowledge; that is a repetition instruction, not a deferred decision.

**Type consistency.** `Request`/`Response`/`Exchange`/`Connection` field names are identical in Tasks 1, 3, 7 and 8. `mapping()` is spelled the same in 1, 4, 7, 8. `analyze(exchange)`/`inventory(exchange)`/`report(exchange)` are consistent from 4 onward. `Run` is introduced in Task 7 and carries exactly the attribute names `run.analysed()` already reads.

**One risk worth flagging to the executor:** Task 4 opens a red window in the CLI tests that stays open until Task 7 closes it. That is deliberate — the alternative is one task that rewrites the analyser and the CLI together, which is too large to review — but an executor who stops between them will find a failing suite and should not "fix" it by reverting anything.
