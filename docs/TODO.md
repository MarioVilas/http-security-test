# TODO

Human maintained notes, agents must not edit.

In no particular order:

## Ideas

- add sarif output support
- add http request analysis
- change api to expect full request/response pairs first, break down for just response, just headers, etc.
- active tests (probes with various methods, uris, cors, etc. full suite to be defined later)
- cookies analysis (flags + heuristically detect session cookies)
- jwt analysis (passive for sure cause it's basically free, probably not active since there are other tools for this anyway)
- csrf token detection (maybe?)

## References

- https://caniuse.com/
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers
- https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
- https://www.cloaked.pl/2021/02/the-gallery-of-http-headers/
- https://http.dev/headers
