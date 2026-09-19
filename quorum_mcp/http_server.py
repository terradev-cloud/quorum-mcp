#!/usr/bin/env python3
"""
Streamable-HTTP transport for quorum -- the same async dispatch() as the
stdio server, served over HTTP. Uses aiohttp for async concurrency.

MCP streamable-HTTP in miniature:

    POST /mcp  with a JSON-RPC body  -> 200 application/json response
    POST with only notifications     -> 202 Accepted, empty body
    GET  /mcp                        -> 200 text/event-stream (SSE keep-alive)
    POST /                           -> same dispatch as /mcp (alias)
    GET  /                           -> service identity JSON
    GET  /health                     -> 200 for the reverse proxy / monitors

TLS is NOT done here. This binds to localhost and a reverse proxy
(Caddy, nginx) terminates HTTPS in front of it. See deploy/.

The endpoint is public -- no authentication.
"""

import asyncio
import json
import os

from aiohttp import web

from quorum_mcp import __version__
from quorum_mcp import spans
from quorum_mcp.server import TOOLS, dispatch, error_response

# Cap concurrent POST /mcp work. /health and GET / are exempt -- they
# must stay responsive when the server is saturated.
sem = asyncio.Semaphore(100)

_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


def _json_response(payload, status=200, cache=False):
    headers = dict(_CORS)
    if cache:
        headers["Cache-Control"] = "public, max-age=3600"
    return web.Response(
        text=json.dumps(payload), status=status,
        content_type="application/json", headers=headers)


def _accept_ok(request):
    """Accept-header relaxation: take anything reasonable, reject only
    explicitly incompatible types. The 406 bug that cost days on Stamp
    was a strict check -- clients send Accept: */*, application/json,
    text/event-stream, or nothing at all. Only a pure text/html-style
    accept is genuinely incompatible with a JSON-RPC endpoint."""
    accept = request.headers.get("Accept", "")
    if not accept or "*/*" in accept:
        return True
    return any(t in accept for t in (
        "application/json", "text/event-stream", "application/*"))


async def _read_json(request):
    try:
        return await request.json()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def handle_root(request):
    return _json_response({
        "name": "quorum-mcp",
        "version": __version__,
        "description": "Attested multi-agent consensus with a shared "
                       "blackboard",
        "endpoints": {
            "mcp": "/mcp",
            "health": "/health",
            "oauth_discovery": "/.well-known/oauth-protected-resource",
        },
    })


async def handle_health(request):
    return _json_response({"status": "ok"})


async def handle_protected_resource_metadata(request):
    """RFC 9728: this resource server is public -- no auth servers."""
    base = f"{request.scheme}://{request.host}"
    return _json_response({
        "resource": base,
        "authorization_servers": [],
    })


async def handle_v1_info(request):
    """Self-describing service info for agents and crawlers -- no auth.

    One GET tells a client what this service is, which tools exist, how
    auth works, where spans go, and where the docs live. Same shape as
    the Terradev MCP /v1/info.
    """
    return _json_response({
        "service": {
            "name": "quorum-mcp",
            "version": __version__,
            "description": "Quorum MCP -- attested multi-agent consensus "
                           "with a shared blackboard. Proposals, votes, "
                           "and outcomes are Stamp-attested and traced "
                           "to Telinea.",
        },
        "tools": [t["name"] for t in TOOLS],
        "auth": {
            "model": "none",
            "description": "Public endpoint -- no authentication. The "
                           "proposal id is the capability: only agents "
                           "given the id can write or vote.",
        },
        "spans": {
            "ingest_url": spans.INGEST_URL,
            "description": "OTLP endpoint for Telinea span ingestion.",
        },
        "docs": "https://terradev.cloud/docs",
    }, cache=True)


async def handle_agent_card(request):
    """A2A-style agent card discovery -- same shape as Terradev MCP."""
    base = f"{request.scheme}://{request.host}"
    return _json_response({
        "name": "quorum-mcp",
        "endpoint": base,
        "skills": [t["name"] for t in TOOLS],
        "version": __version__,
        "authentication": None,
    }, cache=True)


async def handle_mcp_options(request):
    return web.Response(status=204, headers=_CORS)


async def handle_sse_post(request):
    """POST /sse -> 307 to /mcp. 307 not 308: some clients downgrade
    POST to GET on permanent redirects; 307 preserves method and body."""
    raise web.HTTPTemporaryRedirect("/mcp", headers=_CORS)


# Open SSE streams are held indefinitely -- cap them so a flood of
# GET /mcp connections can't exhaust sockets/tasks.
_sse_open = 0
_MAX_SSE = 256


async def handle_mcp_get(request):
    """SSE channel: clients that expect a streamable endpoint open GET
    /mcp and hold it. We send a keep-alive comment and hold the socket."""
    global _sse_open
    if _sse_open >= _MAX_SSE:
        return web.Response(status=503, headers=_CORS,
                            text="too many open streams")
    _sse_open += 1
    resp = web.StreamResponse(
        status=200,
        headers={**_CORS,
                 "Content-Type": "text/event-stream",
                 "Cache-Control": "no-cache",
                 "Connection": "keep-alive"})
    try:
        await resp.prepare(request)
        await resp.write(b": quorum-mcp SSE channel open\n\n")
        while True:
            await asyncio.sleep(30)
            await resp.write(b": keep-alive\n\n")
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        _sse_open -= 1
    return resp


# JSON-RPC batch ceiling: one request body can carry thousands of
# messages that would all dispatch under a single semaphore slot.
_MAX_BATCH = 64


async def _dispatch_one(m):
    if not isinstance(m, dict):
        return error_response(None, -32600, "Invalid Request")
    return await dispatch(m)


async def handle_mcp(request):
    if not _accept_ok(request):
        return _json_response(
            error_response(None, -32600,
                           "Not Acceptable: this endpoint speaks "
                           "application/json"),
            status=406)
    # Read the body BEFORE taking a dispatch slot: a slow upload must
    # not hold a semaphore slot and starve real requests.
    body = await _read_json(request)
    if body is None:
        return _json_response(
            error_response(None, -32700, "Parse error"), status=400)

    async with sem:
        if isinstance(body, list):
            if not body or len(body) > _MAX_BATCH:
                return _json_response(
                    error_response(
                        None, -32600,
                        f"Invalid Request: batch must be 1-{_MAX_BATCH} "
                        "messages"),
                    status=400)
            responses = []
            for m in body:
                r = await _dispatch_one(m)
                if r is not None:
                    responses.append(r)
            if not responses:
                return web.Response(status=202, headers=_CORS)
            return _json_response(responses)

        resp = await _dispatch_one(body)
        if resp is None:
            return web.Response(status=202, headers=_CORS)
        return _json_response(resp)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    app = web.Application()
    app.router.add_get("/", handle_root)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/v1/info", handle_v1_info)
    app.router.add_get("/.well-known/agent.json", handle_agent_card)
    app.router.add_get("/.well-known/agent-card.json", handle_agent_card)
    # Neuronto and other crawlers ask for ard.json -- serve the card.
    app.router.add_get("/.well-known/ard.json", handle_agent_card)
    app.router.add_get("/.well-known/oauth-protected-resource",
                       handle_protected_resource_metadata)
    app.router.add_get("/.well-known/oauth-protected-resource/",
                       handle_protected_resource_metadata)
    app.router.add_route("OPTIONS", "/", handle_mcp_options)
    app.router.add_post("/", handle_mcp)
    app.router.add_route("OPTIONS", "/mcp", handle_mcp_options)
    app.router.add_route("OPTIONS", "/mcp/", handle_mcp_options)
    app.router.add_get("/mcp", handle_mcp_get)
    app.router.add_post("/mcp", handle_mcp)
    app.router.add_post("/mcp/", handle_mcp)
    # /sse compatibility: some clients POST here expecting the old SSE
    # transport -- 307 preserves method+body into the /mcp handler.
    app.router.add_route("OPTIONS", "/sse", handle_mcp_options)
    app.router.add_get("/sse", handle_mcp_get)
    app.router.add_post("/sse", handle_sse_post)

    # Persistent loop: emit spans as background tasks, not inline awaits.
    spans.set_detached(True)
    # 0.0.0.0: inside the container, loopback is unreachable from Caddy
    # on the docker network. QUORUM_HOST=127.0.0.1 for local-only dev.
    host = os.environ.get("QUORUM_HOST", "0.0.0.0")
    port = int(os.environ.get("QUORUM_PORT", "8000"))
    web.run_app(app, host=host, port=port, print=None)


if __name__ == "__main__":
    main()
