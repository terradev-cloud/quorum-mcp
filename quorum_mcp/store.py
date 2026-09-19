#!/usr/bin/env python3
"""
quorum_mcp.store -- event-sourced proposal state.

Every proposal is one append-only JSONL file:

    ~/.quorum/proposals/<proposal_id>.jsonl     (override: QUORUM_DATA_DIR)

Each line is one event:

    {"seq": n, "type": "propose"|"write"|"vote"|"resolve",
     "at": <unix ts>, "attestation": {<stamp record>}, "data": {...}}

State is derived by replaying the log -- the log IS the history, which is
what makes the compliance artifact free: `history` is a filtered read of
the same file the tools append to. Nothing is ever rewritten or deleted.
"""

import asyncio
import json
import os
import re
import threading
import time

DATA_DIR = os.environ.get(
    "QUORUM_DATA_DIR", os.path.expanduser("~/.quorum/proposals"))

# One lock per proposal id, guarded by a global lock. Mutations (appends)
# serialize per proposal; loads replay unlocked -- readers never block
# writers on other proposals.
_locks = {}  # loop -> {proposal_id: asyncio.Lock}
_locks_guard = threading.Lock()

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
# Namespaced ids: <namespace>:<name> -- one colon, each segment follows
# the same charset. Namespaces isolate tenants on disk and in ops.
_NS_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def valid_id(proposal_id):
    """Proposal ids double as filenames -- restrict to safe characters.
    Accepts flat 'name' or namespaced 'ns:name'."""
    return isinstance(proposal_id, str) and bool(
        _ID_RE.match(proposal_id) or _NS_ID_RE.match(proposal_id))


def _path(proposal_id):
    if ":" in proposal_id:
        ns, name = proposal_id.split(":", 1)
        return os.path.join(DATA_DIR, ns, name + ".jsonl")
    return os.path.join(DATA_DIR, proposal_id + ".jsonl")


def mutation_lock(proposal_id):
    """The asyncio.Lock serializing mutations of one proposal on the
    current loop. Compound operations (check-then-append) hold it across
    their awaits; plain append() acquires it internally."""
    loop = asyncio.get_running_loop()
    with _locks_guard:
        per_loop = _locks.setdefault(loop, {})
        return per_loop.setdefault(proposal_id, asyncio.Lock())


def exists(proposal_id):
    return valid_id(proposal_id) and os.path.exists(_path(proposal_id))


def append_unlocked(proposal_id, event_type, data, attestation):
    """Append one event WITHOUT taking the mutation lock -- caller must
    hold mutation_lock(proposal_id). Returns the stored event."""
    path = _path(proposal_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # seq = current line count; read once, cheap for these sizes
    seq = 0
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for _ in f:
                seq += 1
    event = {
        "seq": seq,
        "type": event_type,
        "at": time.time(),
        "data": data,
        "attestation": attestation,
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, separators=(",", ":")) + "\n")
    return event


async def append(proposal_id, event_type, data, attestation):
    """Append one event to the proposal's log under the mutation lock."""
    async with mutation_lock(proposal_id):
        return append_unlocked(proposal_id, event_type, data, attestation)


def proposal_count():
    """Total proposals on disk (flat + namespaced). Used to cap growth."""
    n = 0
    for _root, _dirs, files in os.walk(DATA_DIR):
        n += sum(1 for f in files if f.endswith(".jsonl"))
    return n


def load(proposal_id):
    """Replay a proposal log into its current state.

    Returns None if the proposal does not exist. Otherwise:

        {
          "config":   {...propose event data...},
          "events":   [all events in order],
          "entries":  [blackboard writes in order],
          "votes":    {voter: {value, reasoning, seq, at, attestation_id}},
          "outcome":  {...resolve event data...} | None,
          "resolved": bool,
        }
    """
    if not valid_id(proposal_id):
        return None
    events = []
    try:
        with open(_path(proposal_id)) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return None
    if not events or events[0].get("type") != "propose":
        return None

    state = {"config": events[0]["data"], "events": events,
             "entries": [], "votes": {}, "outcome": None,
             "resolved": False}
    for ev in events[1:]:
        t = ev.get("type")
        d = ev.get("data") or {}
        att_id = (ev.get("attestation") or {}).get("id")
        if t == "write":
            state["entries"].append({
                "seq": ev["seq"], "key": d.get("key"),
                "value": d.get("value"), "author": d.get("author"),
                "at": ev.get("at"), "attestation_id": att_id})
        elif t == "vote":
            state["votes"][d.get("voter")] = {
                "value": d.get("value"), "reasoning": d.get("reasoning"),
                "seq": ev["seq"], "at": ev.get("at"),
                "attestation_id": att_id}
        elif t == "resolve":
            state["outcome"] = d
            state["resolved"] = True
    return state


def quorum_met(state):
    """Has the proposal reached its participation threshold?"""
    cfg = state["config"]
    expected = len(cfg.get("voters") or [])
    if expected == 0:
        return False
    pct = cfg.get("quorum", 100)
    return len(state["votes"]) / expected * 100 >= pct


def deadline_passed(state, now=None):
    dl = state["config"].get("deadline_ts")
    return dl is not None and (now or time.time()) >= dl
