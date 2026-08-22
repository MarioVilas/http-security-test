# TODO

Human maintained notes, agents must not edit.

In no particular order:

## Ideas

- cookies analysis (flags + heuristically detect session cookies + detect privacy cookies)
- jwt analysis (passive for sure cause it's basically free, probably not active since there are other tools for this anyway)
- csrf token detection (maybe?)
- add sarif output support
- add http request analysis
- change api to expect full request/response pairs first, break down for just response, just headers, etc.
- active tests (probes with various methods, uris, cors, etc. full suite to be defined later)
- improve the "explain" command to produce more text, kinda like a report, also add an option to take an output file and parse it instead of manually typing each code
- add a way to automatically download the curated data we don't want to keep inside the module due to maintenance burden (maybe a github action running periodically can update a json file or something)

## References

- https://caniuse.com/
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers
- https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
- https://www.cloaked.pl/2021/02/the-gallery-of-http-headers/
- https://http.dev/headers
