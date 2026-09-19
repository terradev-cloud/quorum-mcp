#!/usr/bin/env python3
"""Route-table test for the quorum HTTP transport.

Start the server first, then run:

    QUORUM_PORT=8799 python3 -m quorum_mcp.http_server &
    python3 tests/test_routes.py [port]
"""

import json
import sys
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
B = f"http://127.0.0.1:{PORT}"
J = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
N = json.dumps({"jsonrpc": "2.0",
                "method": "notifications/initialized"}).encode()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_noredir = urllib.request.build_opener(NoRedirect)


def req(method, path, body=None, accept=None, follow=True):
    r = urllib.request.Request(B + path, data=body, method=method)
    if body:
        r.add_header("Content-Type", "application/json")
    if accept is not None:
        r.add_header("Accept", accept)
    try:
        resp = (urllib.request.urlopen(r, timeout=3) if follow
                else _noredir.open(r, timeout=3))
        return resp.status, dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)
    except Exception as e:
        return str(e)[:50], {}


tests = [
    ("POST /mcp request",       req("POST", "/mcp", J), (200,)),
    ("POST /mcp notification",  req("POST", "/mcp", N), (202,)),
    ("POST / alias",            req("POST", "/", J), (200,)),
    ("GET / identity",          req("GET", "/"), (200,)),
    ("OPTIONS /",               req("OPTIONS", "/"), (204,)),
    ("OPTIONS /mcp",            req("OPTIONS", "/mcp"), (204,)),
    ("OPTIONS /sse",            req("OPTIONS", "/sse"), (204,)),
    ("POST /sse -> 307",        req("POST", "/sse", J, follow=False), (307,)),
    ("GET /health",             req("GET", "/health"), (200,)),
    ("GET /v1/info",            req("GET", "/v1/info"), (200,)),
    ("GET agent-card.json",     req("GET", "/.well-known/agent-card.json"), (200,)),
    ("GET agent.json",          req("GET", "/.well-known/agent.json"), (200,)),
    ("GET ard.json",            req("GET", "/.well-known/ard.json"), (200,)),
    ("GET oauth-protected-res", req("GET", "/.well-known/oauth-protected-resource"), (200,)),
    ("POST /mcp Accept:html",   req("POST", "/mcp", J, accept="text/html"), (406,)),
    ("POST /mcp Accept:*/*",    req("POST", "/mcp", J, accept="*/*"), (200,)),
    ("POST /mcp Accept:es",     req("POST", "/mcp", J, accept="text/event-stream"), (200,)),
]

fails = 0
for label, (code, headers), want in tests:
    ok = code in want
    if not ok:
        fails += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {label:28s} -> {code}")

_, h = req("OPTIONS", "/mcp")
acao = h.get("Access-Control-Allow-Origin")
ok = acao == "*"
fails += 0 if ok else 1
print(f"  {'PASS' if ok else 'FAIL'}  OPTIONS CORS ACAO -> {acao}")

_, h = req("GET", "/v1/info")
cc = h.get("Cache-Control")
ok = cc == "public, max-age=3600"
fails += 0 if ok else 1
print(f"  {'PASS' if ok else 'FAIL'}  v1/info Cache-Control -> {cc}")

_, h = req("POST", "/sse", J, follow=False)
loc = h.get("Location")
ok = loc == "/mcp"
fails += 0 if ok else 1
print(f"  {'PASS' if ok else 'FAIL'}  POST /sse Location -> {loc}")

print()
print("ALL PASS" if fails == 0 else f"{fails} FAILURES")
sys.exit(0 if fails == 0 else 1)
