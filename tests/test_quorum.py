#!/usr/bin/env python3
"""End-to-end tests for quorum-mcp.

Run:  python3 tests/test_quorum.py
Attestation is stubbed with a local deterministic fake -- Stamp's own
test suite covers real NTP attestation; here we test Quorum's logic.
"""

import asyncio
import hashlib
import json
import os
import shutil
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_TMP = tempfile.mkdtemp(prefix="quorum-test-")
os.environ["QUORUM_DATA_DIR"] = os.path.join(_TMP, "proposals")
os.environ["QUORUM_ACCOUNTS"] = os.path.join(_TMP, "accounts.json")
os.environ["QUORUM_DATA_KEY"] = "test-data-key-0123456789abcdef"

from quorum_mcp.algorithms import aggregate          # noqa: E402
from quorum_mcp import accounts, spans               # noqa: E402
import quorum_mcp.server as server                   # noqa: E402

P, F = "PASS", "FAIL"
errors = 0


def check(label, cond, detail=""):
    global errors
    print(f"  {P if cond else F}  {label}"
          f"{' -- ' + detail if detail and not cond else ''}")
    if not cond:
        errors += 1


# Fast local time sample: the queue builds real Stamp records (real
# _canonical sha256) from this stubbed sample -- no NTP, full fidelity.
_sample_calls = [0]


def _fake_sample(server=None):
    _sample_calls[0] += 1
    return {"attested_at": "2026-09-18T00:00:00+00:00",
            "time_source": "local"}


server._stamp_sample = _fake_sample


def test_algorithms():
    opts = ["a", "b", "c"]
    r = aggregate("plurality", ["a", "a", "b"], opts)
    check("plurality decided", r["status"] == "decided" and r["winner"] == "a")
    r = aggregate("plurality", ["a", "b"], opts)
    check("plurality tie -> unresolved",
          r["status"] == "unresolved" and r["co_winners"] == ["a", "b"])
    r = aggregate("approval", [["a", "b"], ["a"], ["a", "c"]], opts)
    check("approval", r["winner"] == "a"
          and r["breakdown"]["approvals"] == {"a": 3, "b": 1, "c": 1})
    r = aggregate("approval", [["a", "b"], ["a"], ["b", "c"]], opts)
    check("approval tie -> unresolved",
          r["status"] == "unresolved" and r["co_winners"] == ["a", "b"])
    r = aggregate("borda", [["a", "b", "c"], ["a", "c", "b"], ["b", "a", "c"]], opts)
    check("borda", r["winner"] == "a" and r["breakdown"]["points"]["a"] == 5)
    r = aggregate("condorcet",
                  [["a", "b", "c"], ["b", "c", "a"], ["c", "a", "b"]], opts)
    check("condorcet cycle -> unresolved",
          r["status"] == "unresolved" and r["co_winners"] == ["a", "b", "c"])
    r = aggregate("condorcet",
                  [["a", "b", "c"], ["a", "b", "c"], ["b", "a", "c"]], opts)
    check("condorcet winner", r["status"] == "decided" and r["winner"] == "a")
    r = aggregate("opinion_pool",
                  [{"a": 0.7, "b": 0.2, "c": 0.1},
                   {"a": 0.5, "b": 0.4, "c": 0.1}], opts)
    check("opinion_pool", r["winner"] == "a"
          and abs(r["breakdown"]["distribution"]["a"] - 0.6) < 1e-6)
    r = aggregate("supermajority", ["a", "a", "b"], opts, threshold=66.67)
    check("supermajority met", r["status"] == "decided" and r["winner"] == "a")
    r = aggregate("supermajority", ["a", "a", "b", "b"], opts, threshold=66.67)
    check("supermajority missed -> unresolved", r["status"] == "unresolved")


def test_accounts():
    aid = accounts.register("qk-test-key-12345", "tel-secret-abc")
    check("register returns account_id", isinstance(aid, str) and len(aid) == 32)
    check("unlock returns telinea key",
          accounts.unlock("qk-test-key-12345") == (aid, "tel-secret-abc"))
    check("wrong key -> None", accounts.unlock("qk-wrong-key-999") is None)
    raw = open(os.environ["QUORUM_ACCOUNTS"]).read()
    check("quorum key not in db", "qk-test-key-12345" not in raw)
    check("telinea key not in db", "tel-secret-abc" not in raw)
    blob = accounts.seal_for_proposal("tel-secret-abc")
    check("seal_for_proposal", isinstance(blob, str))
    check("resolve via blob",
          accounts.resolve_key("p-x", blob) == "tel-secret-abc")
    check("resolve cached", accounts.resolve_key("p-x", None) == "tel-secret-abc")


def test_spans():
    cfg = {"proposal_id": "test-p1", "question": "q?", "algorithm": "approval",
           "voters": ["v1", "v2"], "quorum": 100,
           "deadline": "2026-09-18T00:00:00+00:00"}
    s = spans.root_span_open("test-p1", cfg, "att-1", now=1000.0)
    check("root open: OPEN", s["status"] == "OPEN" and s["parent_span_id"] is None)
    a = s["attributes"]
    check("root: classifier contract",
          a["service.name"] == "quorum-mcp"
          and a["quorum.proposal_id"] == "test-p1"
          and a["quorum.operation"] == "proposal"
          and a["quorum.algorithm"] == "approval")
    s2 = spans.root_span_close("test-p1", cfg, "att-1", 1000.0, "OK", now=1257.0)
    check("root close: same id + duration",
          s2["span_id"] == s["span_id"] and s2["duration_ms"] == 257000.0)
    ws = spans.write_span("test-p1", 2, "analysis", "agent-a", {"x": 1},
                          "att-2", 1000.0, 1000.05)
    check("write span: parent + no value",
          ws["parent_span_id"] == s["span_id"]
          and "value" not in ws["attributes"]
          and "quorum.value" not in ws["attributes"])
    check("write span: operation + author",
          ws["attributes"]["quorum.operation"] == "blackboard.write"
          and ws["attributes"]["quorum.author"] == "agent-a")
    vs = spans.vote_span("test-p1", 3, "v1", "borda", ["a", "b", "c"], 1,
                         "early", "att-3", 1000.0, 1000.02)
    check("vote span: borda hashed",
          vs["attributes"]["quorum.vote"].startswith("sha256:"))
    check("vote span: voter_identity",
          vs["attributes"]["quorum.voter_identity"] == "v1")
    vs2 = spans.vote_span("test-p1", 4, "v2", "plurality", "a", 2, "late",
                          "att-4", 1000.0, 1000.02)
    check("vote span: option name + timing",
          vs2["attributes"]["quorum.vote"] == "a"
          and vs2["attributes"]["quorum.vote_timing"] == "late")
    outcome = {"algorithm": "plurality", "status": "decided", "winner": "a",
               "votes_cast": 2, "expected_voters": 2, "abstained": [],
               "quorum_met": True, "confidence": 1.0,
               "attestation_id": "att-5", "co_winners": ["a"],
               "breakdown": {}}
    rs = spans.resolve_span("test-p1", 5, outcome, 1000.0, 1001.0)
    check("resolve span: outcome + algorithm",
          rs["attributes"]["quorum.operation"] == "resolve"
          and rs["attributes"]["quorum.outcome"] == "a"
          and rs["attributes"]["quorum.algorithm"] == "plurality")


def test_otlp_wire_format():
    """Round-trip a span through the OTLP converter AND terradev-cloud's
    actual ingest parser -- proves the payload lands as a real span row."""
    cfg = {"proposal_id": "wire-p1", "question": "q?", "algorithm": "borda",
           "voters": ["v1"], "quorum": 100,
           "deadline": "2026-09-18T00:00:00+00:00"}
    span = spans.root_span_open("wire-p1", cfg, "att-1", now=1000.0)
    payload = spans._to_otlp_payload(span)

    # Structural checks on the wire format itself
    rs = payload["resourceSpans"][0]
    check("otlp: resourceSpans present", "scopeSpans" in rs)
    otlp_span = rs["scopeSpans"][0]["spans"][0]
    check("otlp: ids + times",
          otlp_span["traceId"] == span["trace_id"]
          and otlp_span["spanId"] == span["span_id"]
          and otlp_span["startTimeUnixNano"].isdigit())
    check("otlp: status code", otlp_span["status"]["code"] == 0)  # OPEN->UNSET

    # Feed through the real ingest parser from terradev-cloud. The module
    # pulls FastAPI/SQLAlchemy/SECRET_KEY on import, so extract the pure
    # parser functions from source via ast -- same code, no dep chain.
    import ast, base64, binascii, typing
    from datetime import datetime as _dt, timezone as _tz
    src = open("/Users/theowolfenden/CascadeProjects/terradev-cloud/"
               "api/terradev_cloud/routers/ingest.py").read()
    tree = ast.parse(src)
    wanted = {"_get", "_otlp_value", "_kv_list_to_dict", "_norm_id",
              "_ns_to_iso", "_span_kind_name", "_status_name",
              "_iter_otlp_spans", "_map_events"}
    ns = {"json": json, "base64": base64, "binascii": binascii,
          "datetime": _dt, "timezone": _tz,
          "Any": typing.Any, "Dict": typing.Dict, "List": typing.List,
          "Optional": typing.Optional, "Tuple": typing.Tuple}
    found = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):  # module constants like _SPAN_KINDS
            for t in node.targets:
                if getattr(t, "id", "") == "_SPAN_KINDS":
                    exec(compile(ast.Module([node], []), "<ing>", "exec"), ns)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name in wanted:
            exec(compile(ast.Module([node], []), "<ing>", "exec"), ns)
            found.add(node.name)
    check("otlp: parser functions extracted", found == wanted,
          str(wanted - found))
    _iter_otlp_spans = ns["_iter_otlp_spans"]
    _kv_list_to_dict = ns["_kv_list_to_dict"]
    _norm_id = ns["_norm_id"]
    _ns_to_iso = ns["_ns_to_iso"]
    _span_kind_name = ns["_span_kind_name"]
    _status_name = ns["_status_name"]

    parsed = list(_iter_otlp_spans(payload))
    check("otlp: parser yields 1 span", len(parsed) == 1)
    resource_attrs, sp = parsed[0]
    check("otlp: resource service.name",
          resource_attrs.get("service.name") == "quorum-mcp")
    check("otlp: trace/span ids normalize",
          _norm_id(sp.get("traceId"), 32) == span["trace_id"]
          and _norm_id(sp.get("spanId"), 16) == span["span_id"])
    check("otlp: kind + status",
          _span_kind_name(sp.get("kind")) == "INTERNAL"
          and _status_name(sp.get("status")) == "UNSET")
    check("otlp: times parse",
          _ns_to_iso(sp.get("startTimeUnixNano")) is not None)
    attrs = _kv_list_to_dict(sp.get("attributes"))
    check("otlp: quorum attrs survive",
          attrs.get("quorum.proposal_id") == "wire-p1"
          and attrs.get("quorum.operation") == "proposal"
          and attrs.get("quorum.algorithm") == "borda"
          and attrs.get("service.name") == "quorum-mcp")


async def _call(name, args, _id=[0]):
    _id[0] += 1
    r = await server.dispatch({"jsonrpc": "2.0", "id": _id[0],
                               "method": "tools/call",
                               "params": {"name": name, "arguments": args}})
    res = r["result"]
    return json.loads(res["content"][0]["text"]), res.get("isError")


async def test_lifecycle():
    r = await server.dispatch({"jsonrpc": "2.0", "id": 99,
                               "method": "tools/list"})
    names = [t["name"] for t in r["result"]["tools"]]
    check("7 tools",
          set(names) == {"register", "propose", "write", "read", "vote",
                         "resolve", "history"}, str(names))

    # Anonymous propose: no api_key -> works, no account binding
    out, err = await _call("propose", {
        "name": "anon-prop", "question": "Anonymous ok?",
        "voters": ["a"], "deadline_minutes": 5})
    check("anonymous propose ok",
          not err and out["proposal_id"] == "anon-prop"
          and "attestation_id" in out, str(out))

    # Provided-but-unregistered key still errors loudly
    out, err = await _call("propose", {
        "api_key": "nope-key-123", "name": "x", "question": "q",
        "voters": ["a"], "deadline_minutes": 5})
    check("unregistered api_key rejected",
          err and out["error"]["code"] == "unknown_api_key")

    out, err = await _call("register", {
        "api_key": "qk-orchestrator-1", "telinea_key": "tel-key-xyz"})
    check("register tool", not err and out["registered"] and "account_id" in out)

    out, err = await _call("propose", {
        "api_key": "qk-orchestrator-1", "name": "test-prop-1",
        "question": "Ship it?", "voters": ["agent-a", "agent-b", "agent-c"],
        "deadline_minutes": 30, "options": ["ship", "hold"],
        "algorithm": "plurality"})
    check("propose ok", not err and out["proposal_id"] == "test-prop-1"
          and "attestation_id" in out, str(out))

    out, err = await _call("propose", {
        "api_key": "qk-orchestrator-1", "name": "test-prop-1",
        "question": "q", "voters": ["x"], "deadline_minutes": 5})
    check("dup propose rejected",
          err and out["error"]["code"] == "proposal_exists")

    out, err = await _call("write", {
        "proposal_id": "test-prop-1", "key": "security",
        "value": {"ok": True}, "author": "agent-a"})
    check("write ok", not err and "attestation_id" in out
          and len(out["blackboard"]) == 1)

    out, err = await _call("read", {"proposal_id": "test-prop-1"})
    check("read all", not err and out["count"] == 1)
    out, err = await _call("read", {"proposal_id": "test-prop-1", "key": "nope"})
    check("read filtered empty", not err and out["count"] == 0)

    out, err = await _call("vote", {
        "proposal_id": "test-prop-1", "voter": "agent-a",
        "value": "ship", "reasoning": "lgtm"})
    check("vote a ok", not err and out["accepted"])
    out, err = await _call("vote", {
        "proposal_id": "test-prop-1", "voter": "agent-a", "value": "hold"})
    check("dup vote rejected", err and out["error"]["code"] == "duplicate_vote")
    out, err = await _call("vote", {
        "proposal_id": "test-prop-1", "voter": "intruder", "value": "ship"})
    check("unknown voter rejected",
          err and out["error"]["code"] == "unknown_voter")
    out, err = await _call("vote", {
        "proposal_id": "test-prop-1", "voter": "agent-b", "value": "bogus"})
    check("invalid value rejected", err and out["error"]["code"] == "invalid_vote")
    out, err = await _call("vote", {
        "proposal_id": "test-prop-1", "voter": "agent-b", "value": "ship"})
    check("vote b ok", not err)
    out, err = await _call("vote", {
        "proposal_id": "test-prop-1", "voter": "agent-c", "value": "hold"})
    check("vote c ok", not err)

    out, err = await _call("resolve", {"proposal_id": "test-prop-1"})
    check("resolve decided", not err and out["status"] == "decided"
          and out["winner"] == "ship", str(out))
    check("resolve attestation + abstained",
          "attestation_id" in out and out["abstained"] == [])
    check("vote_attestations", len(out["vote_attestations"]) == 3)
    out2, _ = await _call("resolve", {"proposal_id": "test-prop-1"})
    check("resolve idempotent", out2["attestation_id"] == out["attestation_id"])
    out, err = await _call("vote", {
        "proposal_id": "test-prop-1", "voter": "agent-a", "value": "hold"})
    check("post-resolve vote rejected", err)

    out, err = await _call("history", {"proposal_id": "test-prop-1"})
    check("history 6 events", not err and out["count"] == 6,
          str(out.get("count")))
    types = [e["type"] for e in out["events"]]
    check("history order",
          types == ["propose", "write", "vote", "vote", "vote", "resolve"],
          str(types))
    out, err = await _call("history", {
        "proposal_id": "test-prop-1", "filter": "votes"})
    check("history votes filter", not err and out["count"] == 3)

    await _call("propose", {
        "api_key": "qk-orchestrator-1", "name": "test-prop-2",
        "question": "q", "voters": ["x", "y", "z"], "deadline_minutes": 30})
    await _call("vote", {"proposal_id": "test-prop-2", "voter": "x",
                         "value": "yes"})
    out, err = await _call("resolve", {"proposal_id": "test-prop-2"})
    check("quorum_not_met", err and out["error"]["code"] == "quorum_not_met",
          str(out))

    out, err = await _call("read", {"proposal_id": "nonexistent"})
    check("not found", err and out["error"]["code"] == "proposal_not_found")


async def test_namespace_rate_queue():
    # -- namespace: ns:name ids, isolated on disk --
    out, err = await _call("propose", {
        "name": "deploy-1", "namespace": "team-a",
        "question": "Deploy?", "voters": ["v1"], "deadline_minutes": 5})
    check("namespaced propose", not err
          and out["proposal_id"] == "team-a:deploy-1", str(out))
    ns_path = os.path.join(os.environ["QUORUM_DATA_DIR"],
                           "team-a", "deploy-1.jsonl")
    check("namespace subdir on disk", os.path.exists(ns_path), ns_path)
    # same name in a different namespace doesn't collide
    out, err = await _call("propose", {
        "name": "deploy-1", "namespace": "team-b",
        "question": "Deploy?", "voters": ["v1"], "deadline_minutes": 5})
    check("same name, other namespace ok",
          not err and out["proposal_id"] == "team-b:deploy-1", str(out))
    out, err = await _call("vote", {
        "proposal_id": "team-a:deploy-1", "voter": "v1", "value": "yes"})
    check("vote on namespaced id", not err and out["accepted"])
    out, err = await _call("propose", {
        "name": "bad:name", "question": "q", "voters": ["v1"],
        "deadline_minutes": 5})
    check("colon in name rejected", err
          and out["error"]["code"] == "invalid_name")

    # -- per-proposal rate limit --
    server._rate_windows.clear()
    old_rate = server._RATE_PER_MIN
    server._RATE_PER_MIN = 3
    try:
        await _call("propose", {
            "name": "rate-prop", "question": "q", "voters": ["v1"],
            "deadline_minutes": 5})
        for i in range(3):
            out, err = await _call("write", {
                "proposal_id": "rate-prop", "key": f"k{i}",
                "value": i, "author": "a"})
            assert not err, out
        out, err = await _call("write", {
            "proposal_id": "rate-prop", "key": "k4",
            "value": 4, "author": "a"})
        check("rate_limited at cap", err
              and out["error"]["code"] == "rate_limited", str(out))
        # a different proposal is unaffected
        await _call("propose", {
            "name": "rate-prop-2", "question": "q", "voters": ["v1"],
            "deadline_minutes": 5})
        out, err = await _call("write", {
            "proposal_id": "rate-prop-2", "key": "k", "value": 1})
        check("other proposal unaffected", not err)
    finally:
        server._RATE_PER_MIN = old_rate
        server._rate_windows.clear()

    # -- attestation queue coalescing: N concurrent attests -> 1 sample --
    _sample_calls[0] = 0
    payloads = [{"type": "write", "i": i} for i in range(8)]
    records = await asyncio.gather(*[server._attest(p) for p in payloads])
    check("queue: all fulfilled", len(records) == 8
          and all("sha256" in r and "id" in r for r in records))
    check("queue: coalesced to 1 sample", _sample_calls[0] == 1,
          str(_sample_calls[0]))
    check("queue: unique ids, shared sample",
          len({r["id"] for r in records}) == 8
          and len({r["attested_at"] for r in records}) == 1)


def main():
    print("\n-- algorithms --")
    test_algorithms()
    print("\n-- accounts (AES-256-GCM envelope) --")
    test_accounts()
    print("\n-- spans --")
    test_spans()
    print("\n-- OTLP wire format (round-trip through ingest parser) --")
    test_otlp_wire_format()
    print("\n-- lifecycle (register -> propose -> write -> vote -> resolve -> history) --")
    asyncio.run(test_lifecycle())
    print("\n-- namespace + rate limit + attestation queue --")
    asyncio.run(test_namespace_rate_queue())
    print()
    shutil.rmtree(_TMP, ignore_errors=True)
    if errors:
        print(f"  {F}  {errors} failure(s)")
        sys.exit(1)
    print(f"  {P}  All tests passed")


if __name__ == "__main__":
    main()
