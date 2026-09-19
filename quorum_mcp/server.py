#!/usr/bin/env python3
"""
quorum -- attested multi-agent consensus with a shared blackboard.

An orchestrator opens a proposal, agents write context to a shared
blackboard and vote with reasoning, Quorum applies a principled
aggregation algorithm, and every step -- proposal, writes, votes,
outcome -- is attested via Stamp. The record is immutable,
tamper-evident, and independently verifiable.

No MCP library. The entire protocol is:

    read line from stdin -> parse JSON-RPC -> dispatch -> write line -> flush

Six tools:

    propose   -- open a proposal: question, options, expected voters,
                 algorithm, deadline, quorum threshold. Returns the
                 proposal id and its creation attestation.
    write     -- append a key-value entry to the proposal's blackboard.
                 Writes are never replaced; the full history is kept.
    read      -- read the blackboard: every write in order, or filtered
                 by key. The deliberation record before voting.
    vote      -- submit a vote from an expected voter identity, with
                 optional reasoning. Validated, attested, immutable.
    resolve   -- apply the algorithm and attest the outcome. Fires
                 automatically when the deadline passes with quorum met.
    history   -- the complete attested record of a proposal: creation,
                 every write, every vote, the outcome.

State is event-sourced: one append-only JSONL file per proposal under
~/.quorum/proposals (see store.py). Attestations are Stamp records --
sha256 over the RFC 8785 canonical form, NTP-verified timestamp when
reachable.
"""

import asyncio
import hashlib
import json
import os
import sys
import time
import uuid
from collections import deque
from datetime import datetime, timezone

from quorum_mcp import __version__
from quorum_mcp import accounts, spans, store
from quorum_mcp.algorithms import ALGORITHMS, aggregate

try:
    from stamp_mcp.server import (
        query_time as _stamp_query_time,
        _canonical as _stamp_canonical)
except ImportError:  # pragma: no cover -- stamp-mcp is a hard dependency
    _stamp_query_time = None
    _stamp_canonical = None

NTP_SERVER = "time.cloudflare.com"

# Vote values are validated before they are stored; these bounds keep a
# malformed or adversarial ballot from bloating the log.
MAX_VOTERS = 1000
MAX_OPTIONS = 100
MAX_REASONING = 10_000
MAX_KEY = 256

TOOLS = [
    {
        "name": "register",
        "description": "One-time account setup: bind a Quorum API key to "
                       "a Telinea API key. The Telinea key is stored "
                       "encrypted under a key derived from the Quorum "
                       "key (AES-256-GCM, HKDF) -- the Quorum key itself "
                       "is never stored. Every span for this account's "
                       "proposals is then pushed with the stored "
                       "Telinea key, standard OTLP bearer auth.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {
                    "type": "string",
                    "description": "Your Quorum API key -- chosen by "
                                   "you, presented on propose, never "
                                   "stored.",
                },
                "telinea_key": {
                    "type": "string",
                    "description": "Your Telinea API key -- stored "
                                   "encrypted, used to authenticate "
                                   "span pushes.",
                },
            },
            "required": ["api_key", "telinea_key"],
        },
    },
    {
        "name": "propose",
        "description": "Open a new proposal: a question, named options, "
                       "expected voter identities, an aggregation "
                       "algorithm, a deadline, and a quorum threshold. "
                       "Returns the proposal id, the creation "
                       "attestation, and the deadline. All later "
                       "operations key off the proposal id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {
                    "type": "string",
                    "description": "Optional. Your Quorum API key (from "
                                   "register). Binds the proposal to "
                                   "your account so its spans push to "
                                   "your Telinea. Omit for anonymous "
                                   "use -- everything works, no spans.",
                },
                "name": {
                    "type": "string",
                    "description": "Human-readable proposal id, e.g. "
                                   "pr-review-2026-09-18. Letters, "
                                   "digits, . _ - only; becomes the key "
                                   "for all subsequent calls.",
                },
                "namespace": {
                    "type": "string",
                    "description": "Optional tenant namespace. The "
                                   "proposal id becomes "
                                   "'<namespace>:<name>' -- different "
                                   "teams can reuse names without "
                                   "colliding. Same charset as name.",
                },
                "question": {
                    "type": "string",
                    "description": "The thing being decided.",
                },
                "voters": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Expected voter identities. Only "
                                   "these may vote; missing voters at "
                                   "resolution are recorded abstained.",
                },
                "deadline_minutes": {
                    "type": "number",
                    "description": "Minutes until voting closes.",
                },
                "options": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Named options. Default [\"yes\",\"no\"].",
                },
                "algorithm": {
                    "type": "string",
                    "enum": list(ALGORITHMS),
                    "description": "Aggregation algorithm. Default "
                                   "approval -- robust general-purpose "
                                   "choice with no strategic incentive.",
                },
                "quorum": {
                    "type": "number",
                    "description": "Min percent of expected voters that "
                                   "must vote before resolution. "
                                   "Default 100.",
                },
                "threshold": {
                    "type": "number",
                    "description": "Supermajority only: required share "
                                   "of votes cast, percent. "
                                   "Default 66.67.",
                },
                "description": {
                    "type": "string",
                    "description": "Optional context for the audit trail.",
                },
            },
            "required": ["name", "question", "voters",
                         "deadline_minutes"],
        },
    },
    {
        "name": "write",
        "description": "Append a key-value entry to a proposal's "
                       "blackboard. Any agent may write; writes are "
                       "appended, never replaced -- the full ordered "
                       "history is preserved and attested.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "proposal_id": {"type": "string"},
                "key": {"type": "string",
                        "description": "Key other agents use to filter "
                                       "this entry on read."},
                "value": {"description": "Any JSON value."},
                "author": {"type": "string",
                           "description": "Optional author identity, "
                                          "recorded and attested."},
            },
            "required": ["proposal_id", "key", "value"],
        },
    },
    {
        "name": "read",
        "description": "Read a proposal's blackboard: every write in "
                       "order with timestamp, author, and attestation "
                       "id -- the complete deliberation record, or "
                       "filtered to one key.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "proposal_id": {"type": "string"},
                "key": {"type": "string",
                        "description": "Optional: only entries with "
                                       "this key."},
            },
            "required": ["proposal_id"],
        },
    },
    {
        "name": "vote",
        "description": "Submit a vote from an expected voter identity, "
                       "with optional reasoning stored in the attested "
                       "record. Vote shape depends on the algorithm: "
                       "plurality/supermajority take an option string; "
                       "approval takes an option or list of options; "
                       "borda takes a ranking of all options; condorcet "
                       "takes a ranking or a single option; opinion_pool "
                       "takes a probability distribution over options. "
                       "Duplicates and post-deadline votes are rejected.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "proposal_id": {"type": "string"},
                "voter": {"type": "string"},
                "value": {"description": "Ballot in the algorithm's "
                                         "format."},
                "reasoning": {"type": "string",
                              "description": "Free-text rationale, kept "
                                             "in the audit trail."},
            },
            "required": ["proposal_id", "voter", "value"],
        },
    },
    {
        "name": "resolve",
        "description": "Compute and attest the outcome once quorum is "
                       "met (or the deadline has passed). Idempotent: "
                       "resolving twice returns the recorded outcome. "
                       "Condorcet cycles and missed supermajority "
                       "thresholds return co_winners with status "
                       "unresolved rather than an arbitrary tiebreak.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "proposal_id": {"type": "string"},
            },
            "required": ["proposal_id"],
        },
    },
    {
        "name": "history",
        "description": "The complete attested record of a proposal in "
                       "chronological order: creation, every blackboard "
                       "write, every vote with reasoning, the outcome. "
                       "Optional filter: all | writes | votes | outcome.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "proposal_id": {"type": "string"},
                "filter": {
                    "type": "string",
                    "enum": ["all", "writes", "votes", "outcome"],
                    "description": "Default all.",
                },
            },
            "required": ["proposal_id"],
        },
    },
]


# ---------------------------------------------------------------------------
# Errors: structured, with a code and remediation, per the spec.
# ---------------------------------------------------------------------------

class QuorumError(Exception):
    def __init__(self, code, message, remediation):
        super().__init__(message)
        self.code = code
        self.remediation = remediation


def _err(code, message, remediation):
    return {"content": [{"type": "text", "text": json.dumps(
        {"error": {"code": code, "message": message,
                   "remediation": remediation}})}],
        "isError": True}


def _ok(payload):
    return {"content": [{"type": "text", "text": json.dumps(payload)}]}


# ---------------------------------------------------------------------------
# Attestation: every event is stamped. stamp-mcp is a hard dependency --
# its record shape (sha256-over-JCS, NTP-verified timestamp, local-clock
# fallback disclosed in the record) is preserved exactly.
#
# Async queue: N concurrent tool calls coalesce onto ONE NTP query per
# drain batch instead of one query per event. Each event still gets its
# own record -- unique id, own payload hash -- built from the shared
# sample. Throughput stops being bound by NTP round-trips.
# ---------------------------------------------------------------------------

_attest_q = None
_attest_worker = None
_attest_loop = None


def _stamp_sample(server):
    """One NTP time sample, shared by a drain batch of attestations."""
    ntp = _stamp_query_time(server)
    return {"attested_at": ntp["utc"], "time_source": "ntp",
            "time_server": ntp["server"],
            "clock_offset_ms": ntp["offset_ms"]}


def _stamp_record(payload, sample):
    """Build one attestation record from a shared sample -- identical
    shape to stamp's attest(), so `stamp verify` still validates it."""
    record = {"id": str(uuid.uuid4()), **sample, "payload": payload}
    record["sha256"] = hashlib.sha256(
        _stamp_canonical(record).encode()).hexdigest()
    return record


async def _attest_drain(q):
    """Queue worker: pull one item, coalesce whatever else queued up,
    take ONE time sample, fulfill every waiter with its own record."""
    while True:
        payload, fut = await q.get()
        batch = [(payload, fut)]
        while True:
            try:
                batch.append(q.get_nowait())
            except asyncio.QueueEmpty:
                break
        try:
            sample = await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(
                    None, _stamp_sample, NTP_SERVER),
                timeout=15.0)
        except Exception:
            # NTP unreachable/slow: local-clock fallback, disclosed in
            # every record -- same semantics as stamp's attest().
            sample = {
                "attested_at": datetime.now(timezone.utc).isoformat(),
                "time_source": "local",
            }
        for p, f in batch:
            if not f.done():
                f.set_result(_stamp_record(p, sample))


def _attest_queue():
    """The queue and its worker are bound to the loop that created them;
    a new loop (stdio re-entry, tests) gets a fresh pair."""
    global _attest_q, _attest_worker, _attest_loop
    loop = asyncio.get_running_loop()
    if _attest_q is None or _attest_loop is not loop:
        _attest_q = asyncio.Queue()
        _attest_worker = None
        _attest_loop = loop
    if _attest_worker is None or _attest_worker.done():
        _attest_worker = asyncio.ensure_future(_attest_drain(_attest_q))
    return _attest_q


async def _attest(payload):
    if _stamp_query_time is None:
        raise QuorumError(
            "attestation_unavailable",
            "stamp-mcp is not installed; cannot attest",
            "pip install stamp-mcp and restart quorum")
    fut = asyncio.get_running_loop().create_future()
    _attest_queue().put_nowait((payload, fut))
    return await fut


# ---------------------------------------------------------------------------
# Per-proposal rate limit: sliding window over mutating events (write,
# vote). One hot proposal can't starve the rest; Caddy's per-IP zone is
# now only a coarse backstop. QUORUM_PROPOSAL_RATE overrides.
# ---------------------------------------------------------------------------

_RATE_PER_MIN = int(os.environ.get("QUORUM_PROPOSAL_RATE", "120"))
_rate_windows = {}  # proposal_id -> deque of monotonic timestamps


def _rate_check(proposal_id):
    now = time.monotonic()
    dq = _rate_windows.setdefault(proposal_id, deque())
    while dq and now - dq[0] > 60:
        dq.popleft()
    if len(dq) >= _RATE_PER_MIN:
        raise QuorumError(
            "rate_limited",
            f"proposal '{proposal_id}' exceeded "
            f"{_RATE_PER_MIN} events/min",
            "slow down, or raise QUORUM_PROPOSAL_RATE on the server")
    dq.append(now)


# ---------------------------------------------------------------------------
# Vote validation: normalize a ballot into the shape the algorithm expects,
# or raise QuorumError. Normalization is stored, so the log holds exactly
# what the aggregator consumed.
# ---------------------------------------------------------------------------

def _validate_vote(algorithm, value, options):
    if algorithm in ("plurality", "supermajority"):
        if not isinstance(value, str) or value not in options:
            raise QuorumError(
                "invalid_vote",
                f"{algorithm} requires a single option string; "
                f"options are {options}",
                "call vote with value set to one of the option strings")
        return value
    if algorithm == "approval":
        approved = [value] if isinstance(value, str) else value
        if not isinstance(approved, list) or not approved or \
                any(not isinstance(o, str) or o not in options
                    for o in approved):
            raise QuorumError(
                "invalid_vote",
                f"approval requires an option string or a list of "
                f"option strings; options are {options}",
                "call vote with value set to one option or a list of "
                "options the voter approves")
        return sorted(set(approved))
    if algorithm == "borda":
        if not isinstance(value, list) or \
                sorted(value) != sorted(options):
            raise QuorumError(
                "invalid_vote",
                f"borda requires a ranked list of ALL options; "
                f"options are {options}",
                "call vote with value set to the options ranked "
                "best-first")
        return list(value)
    if algorithm == "condorcet":
        if isinstance(value, str):
            if value not in options:
                raise QuorumError(
                    "invalid_vote",
                    f"condorcet option must be one of {options}",
                    "call vote with value set to an option string or a "
                    "ranked list")
            return [value]  # ranks it first; others tie below
        if isinstance(value, list) and value and \
                all(isinstance(o, str) and o in options for o in value):
            return list(dict.fromkeys(value))  # dedupe, keep order
        raise QuorumError(
            "invalid_vote",
            f"condorcet requires an option string or a ranked list of "
            f"options; options are {options}",
            "call vote with value set to an option or a ranking")
    if algorithm == "opinion_pool":
        if not isinstance(value, dict) or \
                set(value.keys()) != set(options):
            raise QuorumError(
                "invalid_vote",
                f"opinion_pool requires a probability for every option; "
                f"options are {options}",
                "call vote with value mapping each option to a "
                "probability summing to 1")
        total = 0.0
        for o, p in value.items():
            if isinstance(p, bool) or not isinstance(p, (int, float)) \
                    or not 0 <= p <= 1:
                raise QuorumError(
                    "invalid_vote",
                    f"probability for '{o}' must be a number in [0,1]",
                    "call vote with probabilities between 0 and 1")
            total += p
        if abs(total - 1.0) > 0.01:
            raise QuorumError(
                "invalid_vote",
                f"probabilities sum to {total:.4f}, not 1",
                "adjust the distribution so it sums to 1")
        return {o: float(value[o]) / total for o in options}
    raise QuorumError("invalid_vote",
                      f"unknown algorithm '{algorithm}'",
                      "check the proposal's algorithm")


# ---------------------------------------------------------------------------
# Proposal lifecycle helpers
# ---------------------------------------------------------------------------

def _load_or_err(proposal_id):
    state = store.load(proposal_id)
    if state is None:
        raise QuorumError(
            "proposal_not_found",
            f"no proposal '{proposal_id}'",
            "check the proposal id returned by propose")
    return state


def _telinea_key_for(cfg):
    """The Telinea key for a proposal's spans, or None."""
    return accounts.resolve_key(cfg["proposal_id"],
                                cfg.get("telinea_key_enc"))


async def _maybe_auto_resolve(state):
    """Deadline passed -> resolve if quorum met, else close the trace.

    Lazy rather than a timer: the outcome is computed on the next call
    that touches the proposal, which also covers server restarts.
    """
    if state["resolved"] or not store.deadline_passed(state):
        return state
    if store.quorum_met(state):
        await _do_resolve(state)
        return store.load(state["config"]["proposal_id"])
    # Expired without quorum: close the root span ERROR once. No resolve
    # event -- no outcome was computed, nothing to attest.
    cfg = state["config"]
    propose_ev = state["events"][0]
    await spans.emit_root_close_once(
        cfg["proposal_id"],
        spans.root_span_close(
            cfg["proposal_id"], cfg,
            (propose_ev.get("attestation") or {}).get("id"),
            propose_ev.get("at", time.time()), "ERROR"),
        _telinea_key_for(cfg))
    return state


async def _do_resolve(state):
    """Compute the outcome, attest it, append the resolve event."""
    t0 = time.time()
    cfg = state["config"]
    votes = [v["value"] for v in state["votes"].values()]
    outcome = aggregate(cfg["algorithm"], votes, cfg["options"],
                        threshold=cfg.get("threshold", 66.67))
    abstained = sorted(v for v in cfg["voters"]
                       if v not in state["votes"])
    outcome.update({
        "proposal_id": cfg["proposal_id"],
        "algorithm": cfg["algorithm"],
        "question": cfg["question"],
        "votes_cast": len(state["votes"]),
        "expected_voters": len(cfg["voters"]),
        "quorum_met": store.quorum_met(state),
        "abstained": abstained,
        "vote_attestations": {
            voter: rec["attestation_id"]
            for voter, rec in state["votes"].items()},
    })
    record = await _attest({"type": "resolve",
                            "proposal_id": cfg["proposal_id"],
                            "outcome": outcome})
    outcome["attestation_id"] = record["id"]
    ev = await store.append(cfg["proposal_id"], "resolve", outcome,
                            record)
    # Resolution span (terminal child), then close the root span. Root
    # status: OK decided, UNRESOLVED ambiguous, ERROR no quorum.
    tkey = _telinea_key_for(cfg)
    await spans.emit(spans.resolve_span(
        cfg["proposal_id"], ev["seq"], outcome, t0, time.time()), tkey)
    if outcome["status"] == "decided":
        root_status = "OK" if outcome["quorum_met"] else "ERROR"
    else:
        root_status = "UNRESOLVED"
    propose_ev = state["events"][0]
    await spans.emit_root_close_once(
        cfg["proposal_id"],
        spans.root_span_close(
            cfg["proposal_id"], cfg,
            (propose_ev.get("attestation") or {}).get("id"),
            propose_ev.get("at", t0), root_status),
        tkey)
    return outcome


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

async def _register(args):
    api_key = args.get("api_key")
    telinea_key = args.get("telinea_key")
    if not isinstance(api_key, str) or len(api_key) < 8:
        raise QuorumError(
            "invalid_api_key",
            "api_key must be a string of at least 8 characters",
            "choose a strong key -- it derives your encryption key")
    if not isinstance(telinea_key, str) or not telinea_key.strip():
        raise QuorumError(
            "invalid_telinea_key",
            "telinea_key must be a non-empty string",
            "pass the API key from your Telinea account")
    if not accounts.available():
        raise QuorumError(
            "crypto_unavailable",
            "the cryptography package is not installed",
            "pip install cryptography and restart quorum")
    account_id = accounts.register(api_key, telinea_key.strip())
    return _ok({"account_id": account_id,
                "registered": True,
                "note": "present api_key on propose to bind proposals "
                        "to this account"})


async def _propose(args):
    # api_key is optional: Quorum is open -- the proposal id is the
    # capability. A key only binds the proposal to a Telinea account for
    # span streaming. A provided-but-unregistered key errors loudly
    # (likely a typo) rather than silently dropping telemetry.
    account_id, telinea_key = None, None
    api_key = args.get("api_key")
    if api_key is not None:
        if not isinstance(api_key, str) or not api_key:
            raise QuorumError(
                "invalid_api_key",
                "api_key must be a non-empty string",
                "pass the key from register, or omit it entirely")
        unlocked = accounts.unlock(api_key)
        if unlocked is None:
            raise QuorumError(
                "unknown_api_key",
                "api_key not recognized",
                "call register with this api_key and your telinea_key "
                "first, or omit api_key for anonymous use")
        account_id, telinea_key = unlocked
    name = args.get("name")
    if not store.valid_id(name) or ":" in name:
        raise QuorumError(
            "invalid_name",
            "name must be 1-128 chars of [A-Za-z0-9._-], "
            "starting with a letter or digit",
            "pick a descriptive id like pr-review-2026-09-18")
    namespace = args.get("namespace")
    if namespace is not None:
        if not store.valid_id(namespace) or ":" in namespace or \
                len(namespace) > 64:
            raise QuorumError(
                "invalid_namespace",
                "namespace must be 1-64 chars of [A-Za-z0-9._-]",
                "use a short tenant id like team-a or acme")
        name = f"{namespace}:{name}"
    if store.exists(name):
        raise QuorumError(
            "proposal_exists",
            f"proposal '{name}' already exists",
            "choose a different name -- proposal ids are unique")
    question = args.get("question")
    if not isinstance(question, str) or not question.strip():
        raise QuorumError("invalid_question",
                          "question must be a non-empty string",
                          "state the decision as a question")
    voters = args.get("voters")
    if not isinstance(voters, list) or not voters or \
            any(not isinstance(v, str) or not v for v in voters) or \
            len(set(voters)) != len(voters) or len(voters) > MAX_VOTERS:
        raise QuorumError(
            "invalid_voters",
            "voters must be a non-empty list of unique identity "
            f"strings (max {MAX_VOTERS})",
            "list the identities expected to call vote")
    options = args.get("options") or ["yes", "no"]
    if not isinstance(options, list) or len(options) < 2 or \
            any(not isinstance(o, str) or not o for o in options) or \
            len(set(options)) != len(options) or \
            len(options) > MAX_OPTIONS:
        raise QuorumError(
            "invalid_options",
            f"options must be 2-{MAX_OPTIONS} unique non-empty strings",
            "name the options being decided between")
    algorithm = args.get("algorithm", "approval")
    if algorithm not in ALGORITHMS:
        raise QuorumError(
            "invalid_algorithm",
            f"algorithm must be one of {list(ALGORITHMS)}",
            "approval is the robust default for most decisions")
    deadline_minutes = args.get("deadline_minutes")
    if isinstance(deadline_minutes, bool) or \
            not isinstance(deadline_minutes, (int, float)) or \
            deadline_minutes <= 0:
        raise QuorumError(
            "invalid_deadline",
            "deadline_minutes must be a positive number",
            "set how many minutes voting stays open")
    quorum = args.get("quorum", 100)
    if isinstance(quorum, bool) or not isinstance(quorum, (int, float)) \
            or not 0 < quorum <= 100:
        raise QuorumError(
            "invalid_quorum",
            "quorum must be a percentage in (0, 100]",
            "set the minimum share of expected voters, e.g. 66.7")
    threshold = args.get("threshold", 66.67)
    if isinstance(threshold, bool) or \
            not isinstance(threshold, (int, float)) or \
            not 0 < threshold <= 100:
        raise QuorumError(
            "invalid_threshold",
            "threshold must be a percentage in (0, 100]",
            "set the required share of votes cast, e.g. 66.67")

    deadline_ts = time.time() + deadline_minutes * 60
    cfg = {
        "account_id": account_id,
        # Proposal-scoped re-encryption under the server data key so
        # spans can authenticate after restart without the Quorum key.
        # None for anonymous proposals -- no spans are emitted.
        "telinea_key_enc": (accounts.seal_for_proposal(telinea_key)
                            if telinea_key else None),
        "proposal_id": name,
        "namespace": namespace,
        "question": question,
        "description": args.get("description"),
        "options": options,
        "voters": voters,
        "algorithm": algorithm,
        "quorum": quorum,
        "threshold": threshold,
        "deadline_ts": deadline_ts,
        "deadline": datetime.fromtimestamp(
            deadline_ts, tz=timezone.utc).isoformat(),
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    record = await _attest({"type": "propose", **cfg})
    await store.append(name, "propose", cfg, record)
    if telinea_key:
        accounts.cache_key(name, telinea_key)
    # Root span opens now; it closes at resolve or deadline expiry.
    await spans.emit(spans.root_span_open(name, cfg, record["id"]),
                     telinea_key)
    return _ok({
        "proposal_id": name,
        "attestation_id": record["id"],
        "deadline": cfg["deadline"],
        "algorithm": algorithm,
        "options": options,
        "voters": voters,
        "quorum": quorum,
        "blackboard_uri": f"quorum://{name}/blackboard",
    })


async def _write(args):
    pid = args.get("proposal_id")
    _rate_check(pid)
    state = await _maybe_auto_resolve(_load_or_err(pid))
    if state["resolved"]:
        raise QuorumError(
            "proposal_closed",
            f"proposal '{pid}' is resolved; the blackboard is sealed",
            "read the final record with history")
    key = args.get("key")
    if not isinstance(key, str) or not key or len(key) > MAX_KEY:
        raise QuorumError("invalid_key",
                          "key must be a non-empty string "
                          f"(max {MAX_KEY} chars)",
                          "pick a key other agents can filter on")
    if "value" not in args:
        raise QuorumError("invalid_value",
                          "write requires a 'value' argument",
                          "pass any JSON-serializable value")
    try:
        json.dumps(args["value"])
    except (TypeError, ValueError):
        raise QuorumError("invalid_value",
                          "value is not JSON-serializable",
                          "pass a string, number, array, or object")
    author = args.get("author")
    data = {"key": key, "value": args["value"], "author": author}
    t0 = time.time()
    record = await _attest({"type": "write", "proposal_id": pid, **data})
    ev = await store.append(pid, "write", data, record)
    await spans.emit(spans.write_span(
        pid, ev["seq"], key, author, args["value"], record["id"],
        t0, time.time()), _telinea_key_for(state["config"]))
    state = store.load(pid)
    return _ok({"attestation_id": record["id"],
                "blackboard": state["entries"]})


async def _read(args):
    pid = args.get("proposal_id")
    state = await _maybe_auto_resolve(_load_or_err(pid))
    key = args.get("key")
    entries = state["entries"]
    if key is not None:
        entries = [e for e in entries if e["key"] == key]
    return _ok({"proposal_id": pid,
                "resolved": state["resolved"],
                "count": len(entries),
                "entries": entries})


async def _vote(args):
    pid = args.get("proposal_id")
    _rate_check(pid)
    state = await _maybe_auto_resolve(_load_or_err(pid))
    cfg = state["config"]
    voter = args.get("voter")
    if voter not in cfg["voters"]:
        raise QuorumError(
            "unknown_voter",
            f"'{voter}' is not on the expected voter list",
            "vote with one of: " + ", ".join(cfg["voters"]))
    if voter in state["votes"]:
        raise QuorumError(
            "duplicate_vote",
            f"'{voter}' has already voted; votes are immutable",
            "the recorded vote stands -- see history")
    if state["resolved"]:
        raise QuorumError(
            "proposal_closed",
            f"proposal '{pid}' is resolved",
            "read the outcome with resolve or history")
    if store.deadline_passed(state):
        raise QuorumError(
            "deadline_passed",
            f"the deadline {cfg['deadline']} has passed",
            "the vote window is closed; call resolve")
    reasoning = args.get("reasoning")
    if reasoning is not None and \
            (not isinstance(reasoning, str)
             or len(reasoning) > MAX_REASONING):
        raise QuorumError(
            "invalid_reasoning",
            f"reasoning must be a string (max {MAX_REASONING} chars)",
            "shorten the rationale")
    value = _validate_vote(cfg["algorithm"], args.get("value"),
                           cfg["options"])
    data = {"voter": voter, "value": value, "reasoning": reasoning}
    # Conformity-bias signal: early = first vote, late = cast after a
    # majority of expected voters had already voted.
    prior = len(state["votes"])
    vote_timing = ("early" if prior == 0
                   else "late" if prior > len(cfg["voters"]) / 2
                   else "median")
    t0 = time.time()
    record = await _attest({"type": "vote", "proposal_id": pid, **data})
    ev = await store.append(pid, "vote", data, record)
    await spans.emit(spans.vote_span(
        pid, ev["seq"], voter, cfg["algorithm"], value, prior + 1,
        vote_timing, record["id"], t0, time.time()),
        _telinea_key_for(cfg))
    return _ok({"accepted": True, "voter": voter,
                "attestation_id": record["id"]})


async def _resolve(args):
    pid = args.get("proposal_id")
    state = _load_or_err(pid)
    if state["resolved"]:
        return _ok(state["outcome"])  # idempotent
    if not store.quorum_met(state) and not store.deadline_passed(state):
        cfg = state["config"]
        raise QuorumError(
            "quorum_not_met",
            f"{len(state['votes'])}/{len(cfg['voters'])} votes cast; "
            f"quorum is {cfg['quorum']}%",
            "wait for more votes or the deadline, or lower quorum "
            "on a future proposal")
    outcome = await _do_resolve(state)
    return _ok(outcome)


async def _history(args):
    pid = args.get("proposal_id")
    state = await _maybe_auto_resolve(_load_or_err(pid))
    filt = args.get("filter", "all")
    type_map = {"writes": "write", "votes": "vote", "outcome": "resolve"}
    events = state["events"]
    if filt in type_map:
        events = [e for e in events if e["type"] == type_map[filt]]
    elif filt != "all":
        raise QuorumError(
            "invalid_filter",
            "filter must be one of all | writes | votes | outcome",
            "omit filter for the full record")
    return _ok({"proposal_id": pid,
                "resolved": state["resolved"],
                "count": len(events),
                "events": events})


_TOOLS_DISPATCH = {
    "register": _register,
    "propose": _propose,
    "write": _write,
    "read": _read,
    "vote": _vote,
    "resolve": _resolve,
    "history": _history,
}


async def call_tool(name, arguments):
    fn = _TOOLS_DISPATCH.get(name)
    if fn is None:
        return _err("unknown_tool", f"Unknown tool: {name}",
                    f"available: {', '.join(sorted(_TOOLS_DISPATCH))}")
    try:
        return await fn(arguments or {})
    except QuorumError as e:
        return _err(e.code, str(e), e.remediation)
    except Exception as e:
        return _err("internal_error", f"{type(e).__name__}: {e}",
                    "retry; if it persists, check the server log")


# ---------------------------------------------------------------------------
# JSON-RPC plumbing (same shape as stamp)
# ---------------------------------------------------------------------------

def _write_msg(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def error_response(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}}


async def dispatch(req):
    """Dispatch one parsed JSON-RPC message -> response dict or None."""
    method = req.get("method")
    msg_id = req.get("id")  # None -> notification -> never respond

    if method == "initialize":
        requested = (req.get("params") or {}).get("protocolVersion")
        result = {
            "protocolVersion": requested or "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "quorum", "version": __version__},
        }
    elif method == "notifications/initialized":
        return None
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "resources/list":
        result = {"resources": []}
    elif method == "resources/templates/list":
        result = {"resourceTemplates": []}
    elif method == "prompts/list":
        result = {"prompts": []}
    elif method == "tools/call":
        params = req.get("params") or {}
        result = await call_tool(params.get("name"),
                                 params.get("arguments"))
    else:
        if msg_id is None:
            return None
        return error_response(msg_id, -32601,
                              f"Method not found: {method}")

    if msg_id is None:
        return None
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def main():
    """stdio transport: one JSON-RPC message per line."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            _write_msg(error_response(None, -32700, "Parse error"))
            continue
        resp = asyncio.run(dispatch(req))
        if resp is not None:
            _write_msg(resp)


if __name__ == "__main__":
    main()
