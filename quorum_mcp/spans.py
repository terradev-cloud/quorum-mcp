#!/usr/bin/env python3
"""
quorum_mcp.spans -- OTel-style span emission to the Telinea ingest endpoint.

Every proposal is one trace. The root span (operation "proposal") opens
when propose is called and closes when resolve fires or the deadline
expires without quorum. Each blackboard write, each vote, and the
resolution is a child span emitted in real time -- if a vote arrives at
14:23:07 UTC that is when its span is created, attested, and pushed.
Nothing is reconstructed after the fact.

Span and trace ids are deterministic -- uuid5 over the proposal id and
the event sequence number -- so a restarted server re-emitting an event
produces the same span and ingest stays idempotent.

Auth is per-account: each span is pushed with the Telinea API key the
proposal's owner registered (see accounts.py) -- standard OTLP bearer
auth, so ingest attributes spans to the correct account. Proposals
without a registered key emit nothing.

Push is fire-and-forget and strictly fail-safe: a Telinea outage, a bad
key, or a slow network can never break a vote. Telemetry is best-effort.

Config (env):

    TELINEA_INGEST_URL                          -- default
                                                  https://ingest.terradev.cloud/v1/traces
    TELINEA_WORKSPACE_ID / TELINEA_PROJECT_ID   -- optional routing ids
    TELINEA_DISABLED=1                          -- hard off
"""

import asyncio
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone

INGEST_URL = os.environ.get(
    "TELINEA_INGEST_URL", "https://ingest.terradev.cloud/v1/traces")
WORKSPACE_ID = os.environ.get("TELINEA_WORKSPACE_ID", "").strip() or None
PROJECT_ID = os.environ.get("TELINEA_PROJECT_ID", "").strip() or None
DISABLED = os.environ.get("TELINEA_DISABLED", "").lower() in ("1", "true", "yes")

SERVICE = "quorum-mcp"

# uuid5 namespace for all quorum span/trace ids.
_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://quorum-mcp.terradev.cloud")

# Root spans already closed this process -- deadline-expiry closes are
# emitted lazily on the next call that touches the proposal, and this set
# keeps that from re-firing on every subsequent call. (Re-emits would be
# harmless anyway: the span id is deterministic.)
_closed_roots = set()

# Detached mode: http_server sets this so emits are scheduled as tasks on
# the persistent loop instead of awaited inline (stdio mode awaits --
# its loop dies with the dispatch call, so fire-and-forget would never
# deliver).
_detached = False


def set_detached(value=True):
    global _detached
    _detached = value


def configured():
    return not DISABLED


# ---------------------------------------------------------------------------
# Ids -- deterministic, so replays and restarts are idempotent
# ---------------------------------------------------------------------------

def trace_id_for(proposal_id):
    return uuid.uuid5(_NS, proposal_id).hex  # 32 hex chars, OTel trace id


def root_span_id_for(proposal_id):
    return uuid.uuid5(_NS, proposal_id + ":root").hex[:16]


def child_span_id(proposal_id, seq):
    return uuid.uuid5(_NS, f"{proposal_id}:{seq}").hex[:16]


# ---------------------------------------------------------------------------
# Span construction
# ---------------------------------------------------------------------------

def _iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _span(name, proposal_id, seq, start_ts, end_ts, status, attributes):
    """Build one span dict. seq=None -> the root span.

    Every span carries the classifier contract: service.name (fixed
    discriminator), quorum.proposal_id (trace linkage), and
    quorum.operation (lifecycle position). Telinea routes on these;
    generic dashboards see standard OTel fields."""
    root = seq is None
    attributes = {
        "service.name": SERVICE,
        "quorum.proposal_id": proposal_id,
        "quorum.operation": name,
        **attributes,
    }
    return {
        "trace_id": trace_id_for(proposal_id),
        "span_id": (root_span_id_for(proposal_id) if root
                    else child_span_id(proposal_id, seq)),
        "parent_span_id": None if root else root_span_id_for(proposal_id),
        "name": name,
        "service": SERVICE,
        "start_time": _iso(start_ts),
        "end_time": _iso(end_ts),
        "duration_ms": round((end_ts - start_ts) * 1000, 3),
        "status": status,
        "attributes": attributes,
    }


def root_span_open(proposal_id, cfg, attestation_id, now=None):
    """The root span as emitted at propose time: status OPEN, zero
    duration. Re-emitted at close with the same span id, final status,
    and the full deliberation duration."""
    now = now or time.time()
    return _span("proposal", proposal_id, None, now, now, "OPEN",
                 _root_attrs(cfg, attestation_id))


def root_span_close(proposal_id, cfg, attestation_id, opened_ts,
                    status, now=None):
    now = now or time.time()
    return _span("proposal", proposal_id, None, opened_ts, now, status,
                 _root_attrs(cfg, attestation_id))


def _root_attrs(cfg, attestation_id):
    return {
        "quorum.algorithm": cfg["algorithm"],
        "quorum.question": cfg["question"],
        "quorum.expected_voters": len(cfg["voters"]),
        "quorum.quorum_pct": cfg["quorum"],
        "quorum.deadline": cfg["deadline"],
        "attestation_id": attestation_id,
    }


def write_span(proposal_id, seq, key, author, value, attestation_id,
               start_ts, end_ts):
    return _span("blackboard.write", proposal_id, seq, start_ts, end_ts,
                 "OK", {
                     "quorum.key": key,
                     "quorum.author": author,
                     # size only -- blackboard content stays in Quorum
                     "quorum.value_bytes": len(json.dumps(value)),
                     "attestation_id": attestation_id,
                 })


def _vote_repr(algorithm, value):
    """Algorithm-appropriate vote representation for the span attribute.

    Option name where the ballot is a choice; a short sha256 of the
    canonical form where the ballot is a structure. Never the reasoning.
    """
    if algorithm in ("plurality", "supermajority"):
        return value
    if algorithm == "approval" and len(value) == 1:
        return value[0]
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()[:16]


def vote_span(proposal_id, seq, voter, algorithm, value, vote_number,
              vote_timing, attestation_id, start_ts, end_ts):
    return _span("vote", proposal_id, seq, start_ts, end_ts, "OK", {
        # voter_identity is how Telinea's agent registry builds the
        # agent map for governance traces
        "quorum.voter_identity": voter,
        "quorum.vote": _vote_repr(algorithm, value),
        "quorum.vote_seq": vote_number,
        # conformity-bias signal: early = first vote cast, late = cast
        # after a majority was already reached, median = between
        "quorum.vote_timing": vote_timing,
        "attestation_id": attestation_id,
    })


def resolve_span(proposal_id, seq, outcome, start_ts, end_ts):
    attrs = {
        "quorum.algorithm": outcome["algorithm"],
        "quorum.votes_cast": outcome["votes_cast"],
        "quorum.expected_voters": outcome["expected_voters"],
        "quorum.abstained": len(outcome["abstained"]),
        "quorum.quorum_met": outcome["quorum_met"],
        "quorum.confidence": outcome.get("confidence"),
        "attestation_id": outcome.get("attestation_id"),
    }
    if outcome["status"] == "decided":
        attrs["quorum.outcome"] = outcome["winner"]
        status = "OK" if outcome["quorum_met"] else "ERROR"
    else:
        attrs["quorum.co_winners"] = outcome["co_winners"]
        if outcome["algorithm"] == "condorcet":
            attrs["quorum.cycle"] = outcome["breakdown"].get("cycle")
        if outcome["algorithm"] == "supermajority":
            attrs["quorum.leader_share_pct"] = outcome["breakdown"].get(
                "leader_share_pct")
            attrs["quorum.threshold_pct"] = outcome["breakdown"].get(
                "threshold_pct")
        status = "UNRESOLVED"
    return _span("resolve", proposal_id, seq, start_ts, end_ts, status,
                 attrs)


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------

async def emit(span, telinea_key=None):
    """Emit one span authenticated with the account's Telinea key.

    Never raises; never blocks a tool call for long. No key -> no push
    (the proposal's owner never registered a Telinea key).
    """
    if not configured() or not telinea_key:
        return
    if _detached:
        asyncio.get_running_loop().create_task(_push(span, telinea_key))
    else:
        await _push(span, telinea_key)


async def emit_root_close_once(proposal_id, span, telinea_key=None):
    """Emit a root close at most once per process (deadline-expiry path)."""
    if proposal_id in _closed_roots:
        return
    _closed_roots.add(proposal_id)
    await emit(span, telinea_key)


async def _push(span, telinea_key):
    try:
        import aiohttp
        payload = {
            "workspace_id": WORKSPACE_ID,
            "project_id": PROJECT_ID,
            "events": [{
                "source": SERVICE,
                "event_type": "span",
                "ingested_at": _iso(time.time()),
                "span": span,
            }],
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {telinea_key}",
            "X-Telinea-Source": SERVICE,
        }
        timeout = aiohttp.ClientTimeout(total=5.0, connect=2.0)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(INGEST_URL, json=payload,
                                    headers=headers):
                pass  # fire and forget -- status intentionally ignored
    except Exception:
        pass  # fail-safe: telemetry can never break consensus
