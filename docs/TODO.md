# TODO

Human maintained notes, agents must not edit.

In no particular order:

## Ideas

- finish json schema output
- add sarif output support
- add http request analysis
- change api to expect full request/response pairs first, break down for just response, just headers, etc.
- passive cors detection checks (origin header in request)
- active tests (probes with various methods, uris, cors, etc. full suite to be defined later)
- cookies analysis (flags + heuristically detect session cookies)
- jwt analysis (passive for sure cause it's basically free, probably not active since there are other tools for this anyway)
- csrf token detection (maybe?)
- cli tool (active tests + passive via imported files)

## References

### Data

- https://github.com/fyrd/caniuse
- https://github.com/sethmlarson/hstspreload
- https://github.com/AlexMelanFromRingo/rfc-library

### Tools

- https://github.com/google/csp-evaluator
- https://github.com/chromium/hstspreload

### Web Browsers

- https://github.com/chromium/chromium
- https://github.com/mozilla-firefox/firefox
- https://github.com/webKit/webkit
- https://github.com/gameprive/win2k.git (contains a legacy version of IE)
- https://github.com/selfrender/Windows-Server-2003 (same as above)
- https://github.com/tongzx/nt5src (same as above)
- https://github.com/zii/netscape
- https://lynx.invisible-island.net/current/index.html
- https://github.com/browsh-org/browsh.git

### Web Servers

- https://github.com/apache/httpd
- https://github.com/nginx/nginx
- https://github.com/apache/tomcat
- https://github.com/pallets/werkzeug
- https://github.com/caddyserver/caddy
- https://github.com/jetty/jetty.project
- https://github.com/javaee/glassfish (legacy)
- https://github.com/eclipse-ee4j/glassfish
- https://github.com/zopefoundation/Zope
- https://github.com/mirror/busybox
- https://gitlab.com/hsleisink/hiawatha
- https://git.lighttpd.net/lighttpd/lighttpd1.4
- https://git.lighttpd.net/lighttpd/lighttpd2
- https://github.com/jvirkki/heliod (Oracle)
- https://github.com/benoitc/gunicorn
- https://github.com/pgjones/hypercorn
- https://github.com/Kludex/uvicorn
- https://github.com/django/daphne
- https://github.com/unbit/uwsgi/
- https://github.com/twisted/twisted
- git://git.gnunet.org/libmicrohttpd2.git
