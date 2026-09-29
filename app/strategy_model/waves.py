"""Dependency-aware wave planning.

Starting point: the risk engine's wave (or the wave a person set), adjusted by strategy:
  RETIRE -> Decommission review, RETAIN -> Blocked (migrates later).
Then confirmed app-to-app dependencies are applied: an app never moves before an app it depends on.
  * If the app it depends on is Blocked, it waits too.
  * Apps that depend on each other move together, in the latest wave among them.
  * Depending on an app that is being retired is flagged (someone must decide), not moved.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from app.models.db import Application, Dependency
from app.services.estimate import WAVE_ORDER
from app.strategy_model.dependencies import app_node

ORDERED = [w for w in WAVE_ORDER if w != "Blocked"]      # Wave 0 (pilot) .. Wave 3 (high impact)


@dataclass
class Placement:
    wave: str
    base: str
    reasons: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


def _rank(w: str) -> int:
    if w in ORDERED:
        return ORDERED.index(w)
    if w == "Blocked":
        return len(ORDERED)
    return -1          # Decommission review / Out of scope: not in the sequence


def plan(apps: list[Application], deps: list[Dependency]) -> dict[str, Placement]:
    out: dict[str, Placement] = {}
    for a in apps:
        base = a.wave or a.suggested_wave or "Wave 2"
        p = Placement(base, base)
        if a.strategy == "RETIRE":
            p.wave = "Decommission review"
            if base != p.wave:
                p.reasons.append("Strategy RETIRE: decommission review instead of migration")
        elif a.strategy == "RETAIN":
            p.wave = "Blocked"
            if base != p.wave:
                p.reasons.append("Strategy RETAIN: stays on Okta for now, migrates after the blocking decision")
        out[a.id] = p

    by_node = {app_node(a.id): a for a in apps}
    labels = {a.id: a.label for a in apps}
    g = nx.DiGraph()
    g.add_nodes_from(a.id for a in apps)
    for d in deps:
        s, t = by_node.get(d.source), by_node.get(d.target)
        if s and t and s.id != t.id:
            g.add_edge(s.id, t.id)

    # Apps that depend on each other (strongly connected groups) move together, in the latest wave among them.
    for comp in nx.strongly_connected_components(g):
        if len(comp) < 2:
            continue
        ranks = [(_rank(out[i].wave), out[i].wave) for i in comp if _rank(out[i].wave) >= 0]
        names = ", ".join(sorted(labels[i] for i in comp))
        for i in comp:
            out[i].flags.append(f"Mutual dependency with {names}: migrate together")
        if not ranks:
            continue
        target = max(ranks)[1]
        for i in comp:
            if _rank(out[i].wave) >= 0 and out[i].wave != target:
                out[i].reasons.append(f"Moved to {target}: mutual dependency ({names})")
                out[i].wave = target

    for _ in range(len(apps) + 1):          # propagate until stable
        changed = False
        for s, t in g.edges():
            ps, pt = out[s], out[t]
            if _rank(ps.wave) < 0:
                continue
            if _rank(pt.wave) < 0:
                msg = f"Depends on {labels[t]}, which is planned for {pt.wave}: decide before migrating"
                if msg not in ps.flags:
                    ps.flags.append(msg)
                continue
            if _rank(ps.wave) < _rank(pt.wave):
                ps.reasons.append(f"Moved from {ps.wave} to {pt.wave}: depends on {labels[t]}")
                ps.wave = pt.wave
                changed = True
        if not changed:
            break
    return out
