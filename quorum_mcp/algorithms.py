#!/usr/bin/env python3
"""
quorum_mcp.algorithms -- vote aggregation from the social choice literature.

Six algorithms. Each takes the validated, normalized votes plus the
proposal config and returns a uniform outcome dict:

    {
        "status":     "decided" | "unresolved",
        "winner":     <option> | None,
        "co_winners": [<option>, ...] | None,   # set when genuinely ambiguous
        "breakdown":  {...},                    # algorithm-specific detail
        "confidence": float | None,             # 0..1 where meaningful
    }

"unresolved" is a first-class result. A Condorcet cycle or a missed
supermajority threshold is genuine ambiguity -- it is surfaced to the
orchestrator, never hidden behind an arbitrary tiebreak.

Normalized vote shapes (validation happens in server.py before votes are
stored):

    plurality, supermajority : "option"
    approval                 : ["option", ...]   (one or more)
    borda, condorcet         : ["top", ..., "bottom"]  (ranked; condorcet
                               also accepts a bare string = rank that
                               option first, all others tied below)
    opinion_pool             : {"option": probability, ...}  (sums to 1)
"""

ALGORITHMS = ("plurality", "borda", "condorcet",
              "approval", "opinion_pool", "supermajority")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _counts(options):
    return {o: 0 for o in options}


def _top(counts):
    """Return (sorted winners list, top tally) for a {option: number} map."""
    top = max(counts.values())
    winners = sorted(o for o, c in counts.items() if c == top)
    return winners, top


def _decided(winner, breakdown, confidence=None):
    return {"status": "decided", "winner": winner, "co_winners": None,
            "breakdown": breakdown, "confidence": confidence}


def _unresolved(co_winners, breakdown, confidence=None):
    return {"status": "unresolved", "winner": None,
            "co_winners": co_winners, "breakdown": breakdown,
            "confidence": confidence}


# ---------------------------------------------------------------------------
# plurality -- most first-choice votes wins. Correct for binary decisions;
# ignores preference structure, so ties and split votes are surfaced.
# ---------------------------------------------------------------------------

def plurality(votes, options, **_cfg):
    counts = _counts(options)
    for v in votes:
        counts[v] += 1
    winners, top = _top(counts)
    breakdown = {"counts": counts, "votes_cast": len(votes)}
    if len(winners) == 1:
        conf = top / len(votes) if votes else None
        return _decided(winners[0], breakdown, conf)
    return _unresolved(winners, breakdown)


# ---------------------------------------------------------------------------
# approval -- each ballot approves a SET of options; most approvals wins.
# No strategic incentive: approving B never hurts A.
# ---------------------------------------------------------------------------

def approval(votes, options, **_cfg):
    counts = _counts(options)
    for approved in votes:
        for o in approved:
            counts[o] += 1
    winners, top = _top(counts)
    breakdown = {"approvals": counts, "ballots": len(votes)}
    if len(winners) == 1:
        conf = top / len(votes) if votes else None
        return _decided(winners[0], breakdown, conf)
    return _unresolved(winners, breakdown)


# ---------------------------------------------------------------------------
# borda -- ranked ballots; rank i of n earns (n-1-i) points. Surfaces the
# broadly-acceptable option. Best restricted to 3-5 options.
# ---------------------------------------------------------------------------

def borda(votes, options, **_cfg):
    n = len(options)
    points = _counts(options)
    for ranking in votes:
        for rank, opt in enumerate(ranking):
            points[opt] += (n - 1) - rank
    winners, top = _top(points)
    max_possible = (n - 1) * len(votes)
    breakdown = {"points": points, "ballots": len(votes)}
    if len(winners) == 1:
        conf = top / max_possible if max_possible else None
        return _decided(winners[0], breakdown, conf)
    return _unresolved(winners, breakdown)


# ---------------------------------------------------------------------------
# condorcet -- the option that beats every other pairwise wins. If none,
# return the Smith set (smallest set with no member beaten by an outsider)
# as co_winners, unresolved. A cycle is genuine ambiguity: surface it.
#
# Ballots are ranked lists. Options absent from a ballot are treated as
# tied below every ranked option (a bare-string vote ranks one option
# first and ties the rest).
# ---------------------------------------------------------------------------

def _pairwise(votes, options):
    """pairwise[a][b] = number of ballots ranking a strictly above b."""
    idx = {o: i for i, o in enumerate(options)}
    matrix = {a: {b: 0 for b in options} for a in options}
    for ranking in votes:
        rank = {opt: i for i, opt in enumerate(ranking)}
        n_ranked = len(ranking)
        for a in options:
            ra = rank.get(a, n_ranked)  # unranked sorts below all ranked
            for b in options:
                if a == b:
                    continue
                rb = rank.get(b, n_ranked)
                if ra < rb:
                    matrix[a][b] += 1
    return matrix


def _smith_set(options, defeats):
    """Smallest set S such that no member of S is defeated by a non-member.

    Computed as the minimal closure under the 'defeated-by' relation:
    for each candidate c, close {c} under 'everyone who defeats x'. The
    smallest such closure is the Smith set (a Condorcet winner closes to
    itself; a cycle closes to the whole cycle).
    """
    best = None
    for c in options:
        seen = {c}
        stack = [c]
        while stack:
            x = stack.pop()
            for y in options:
                if y not in seen and defeats[y][x]:
                    seen.add(y)
                    stack.append(y)
        if best is None or len(seen) < len(best):
            best = seen
    return sorted(best)


def condorcet(votes, options, **_cfg):
    matrix = _pairwise(votes, options)
    n_ballots = len(votes)
    # defeats[a][b] = a beats b in a strict pairwise majority
    defeats = {a: {b: matrix[a][b] > matrix[b][a] for b in options}
               for a in options}
    for a in options:
        if all(defeats[a][b] for b in options if b != a):
            breakdown = {"pairwise": matrix, "ballots": n_ballots}
            return _decided(a, breakdown, confidence=1.0)
    smith = _smith_set(options, defeats)
    breakdown = {"pairwise": matrix, "ballots": n_ballots,
                 "cycle": smith,
                 "note": "no Condorcet winner -- Smith set returned as "
                         "co_winners; orchestrator decides how to proceed"}
    return _unresolved(smith, breakdown)


# ---------------------------------------------------------------------------
# opinion_pool -- linear pool: aggregated distribution = mean of the
# submitted distributions. Winner = argmax, but the full distribution is
# returned so the orchestrator sees the uncertainty, not just the pick.
# ---------------------------------------------------------------------------

def opinion_pool(votes, options, **_cfg):
    pooled = _counts(options)
    for dist in votes:
        for o in options:
            pooled[o] += dist[o]
    n = len(votes)
    pooled = {o: pooled[o] / n for o in options}
    winners, top = _top(pooled)
    breakdown = {"distribution": {o: round(pooled[o], 6) for o in options},
                 "ballots": n}
    if len(winners) == 1:
        return _decided(winners[0], breakdown, confidence=round(top, 6))
    return _unresolved(winners, breakdown)


# ---------------------------------------------------------------------------
# supermajority -- plurality with a required share of votes cast.
# threshold is a percentage (e.g. 66.67). Below threshold -> unresolved.
# ---------------------------------------------------------------------------

def supermajority(votes, options, threshold=66.67, **_cfg):
    counts = _counts(options)
    for v in votes:
        counts[v] += 1
    winners, top = _top(counts)
    # Round to the precision thresholds are expressed at: 2/3 must meet
    # a 66.67% bar, not fail on a 0.003 float hair.
    share = round(top / len(votes) * 100, 2) if votes else 0.0
    breakdown = {"counts": counts, "votes_cast": len(votes),
                 "threshold_pct": threshold,
                 "leader_share_pct": share}
    if len(winners) == 1 and share >= threshold:
        return _decided(winners[0], breakdown, confidence=share / 100)
    breakdown["note"] = ("threshold not met" if len(winners) == 1
                         else "tied at the top")
    return _unresolved(winners, breakdown)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_FUNCS = {
    "plurality": plurality,
    "borda": borda,
    "condorcet": condorcet,
    "approval": approval,
    "opinion_pool": opinion_pool,
    "supermajority": supermajority,
}


def aggregate(algorithm, votes, options, threshold=66.67):
    """Run one algorithm over normalized votes. Returns the outcome dict."""
    return _FUNCS[algorithm](votes, options, threshold=threshold)
