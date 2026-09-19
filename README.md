# Quorum

Attested multi-agent consensus with a shared blackboard — an MCP server.

An orchestrator opens a proposal, participating agents write context to a
shared blackboard and vote with reasoning, Quorum applies a principled
aggregation algorithm from the social choice literature, and every step —
proposal, writes, votes, outcome — is attested via
[Stamp](https://github.com/theoddden/Stamp-MCP) and traced to Telinea.
The record is immutable, tamper-evident, and independently verifiable.

**Hosted endpoint (no sign-in, public):**
`https://quorum-mcp.terradev.cloud/mcp`

---

## Why

Majority vote among LLM agents fails on disputed questions because agents
trained on overlapping data share systematic blind spots — they are not
the independent voters the Condorcet Jury Theorem requires. And when
agents do decide together, the decision *process* — who voted, what they
said, what context they worked from — is invisible.

Quorum is the complete primitive: algorithm plus state plus provenance.

## Tools

- **`register`** — one-time account setup: bind your `api_key` (a Quorum
  key you choose) to your `telinea_key`. The Telinea key is stored
  encrypted under a key derived from your Quorum key (AES-256-GCM,
  HKDF) — the Quorum key itself is never stored. Every span for your
  proposals is then pushed with your Telinea key, standard OTLP bearer
  auth.

- **`propose`** — open a proposal: `name` (becomes the proposal id),
  `question`, `voters` (expected identities), `deadline_minutes`.
  Optional: `api_key` (from register — binds the proposal to your
  Telinea account for span streaming; omit for anonymous use),
  `options` (default `["yes","no"]`), `algorithm` (default
  `approval`), `quorum` (min % of voters, default 100), `threshold`
  (supermajority share, default 66.67), `description`. Returns the
  proposal id, creation attestation id, deadline, and blackboard URI.

- **`write`** — append `key`/`value` to the proposal's blackboard, with
  optional `author`. Writes are appended, never replaced — the full
  ordered history is preserved and attested.

- **`read`** — read the blackboard: every write in order with timestamp,
  author, and attestation id. Optional `key` filter. The deliberation
  record before voting.

- **`vote`** — submit a ballot from an expected `voter` identity, with
  optional `reasoning` (stored in the attested record, never affects the
  outcome). Ballot shape depends on the algorithm — see below. Duplicate
  votes and post-deadline votes are rejected with structured errors.

- **`resolve`** — apply the algorithm and attest the outcome. Callable
  once quorum is met (or after the deadline); also fires automatically
  when the deadline passes with quorum. Idempotent. Condorcet cycles and
  missed supermajority thresholds return `co_winners` with status
  `unresolved` — genuine ambiguity is surfaced, never hidden.

- **`history`** — the complete attested record: creation, every write,
  every vote with reasoning, the outcome. Optional `filter`:
  `all | writes | votes | outcome`. The compliance artifact.

## Algorithms

| Algorithm | Ballot | Use when |
|---|---|---|
| `plurality` | option string | Binary decisions only |
| `approval` | option or list of options | **Default.** No strategic incentive; weak/multiple preferences |
| `borda` | ranking of all options | 3–5 options; surfaces the broadly-acceptable choice |
| `condorcet` | ranking or single option | Rational preference aggregation; cycles returned as `co_winners` |
| `opinion_pool` | `{option: probability}` summing to 1 | Genuine probabilistic beliefs; returns full distribution |
| `supermajority` | option string | High-stakes decisions needing >50% (set `threshold`) |

## The blackboard

LLM consensus failures are often information failures, not algorithm
failures — agents vote in isolation. The blackboard is shared working
memory scoped to one proposal: agents write analysis, read each other's
findings, then vote informed. Write-first, read-second ordering and
immutable pre-deadline votes are the conformity-bias defenses.

## Tracing

Every proposal is one Telinea trace. The root span (`proposal`) opens at
`propose` and closes at `resolve` or deadline expiry — its duration is
the deliberation time. Each write, vote, and the resolution is a child
span emitted in real time with its Stamp attestation id. Root status:
`OK` decided, `UNRESOLVED` ambiguous, `ERROR` expired without quorum.

Span ids are deterministic (uuid5 over proposal id + event seq), so
replays and restarts stay idempotent. Push is fire-and-forget and
fail-safe — telemetry can never break a vote.

Auth is per-account: spans are pushed with the Telinea key registered
via `register`, so ingest attributes them to the correct account. The
key is stored encrypted (AES-256-GCM under HKDF of your Quorum key —
never stored); a proposal-scoped re-encryption under the server-held
`QUORUM_DATA_KEY` lets spans authenticate after restarts without
re-presenting the Quorum key. A database dump exposes only ciphertext.

Config: `TELINEA_INGEST_URL` (default
`https://ingest.terradev.cloud/v1/traces`), `TELINEA_WORKSPACE_ID`,
`TELINEA_PROJECT_ID`, `TELINEA_DISABLED=1`, `QUORUM_DATA_KEY`,
`QUORUM_ACCOUNTS` (account store path, default
`~/.quorum/accounts.json`).

## HTTP transport

| Endpoint | Method | Description |
|---|---|---|
| `/mcp` | `POST` | JSON-RPC 2.0 — single or batch; notifications → 202 |
| `/mcp` | `GET` | SSE keep-alive channel |
| `/` | `GET`/`POST` | Service identity / MCP alias |
| `/health` | `GET` | `{"status":"ok"}` |
| `/v1/info` | `GET` | Self-describing service info (tools, auth, spans, docs) |
| `/.well-known/agent.json` | `GET` | Agent card |
| `/.well-known/oauth-protected-resource` | `GET` | RFC 9728 — public, no auth |

Concurrency capped at 100 simultaneous `POST /mcp` via `asyncio.Semaphore`.

## State

Event-sourced: one append-only JSONL file per proposal under
`~/.quorum/proposals` (override `QUORUM_DATA_DIR`). The log *is* the
history — `history` is a filtered read of the same file the tools
append to. Nothing is rewritten or deleted.

## Self-hosting

```bash
git clone https://github.com/theoddden/quorum-mcp.git
cd quorum-mcp
docker compose up -d --build
```

Caddy handles TLS once DNS points at the host. See `deploy/Caddyfile`.

## License

Copyright 2026 theoddden. Licensed under the
[Apache License, Version 2.0](LICENSE).
