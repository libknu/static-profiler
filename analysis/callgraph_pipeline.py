from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Set, Tuple
import csv

from .indirect_resolver import IndirectCallSite, LocalIndirectCallResolver


@dataclass
class AnalysisState:
    direct_edges: Set[Tuple[str, str]]
    syscall_sinks: Dict[str, Set[str]]
    indirect_sites: List[IndirectCallSite]


def read_direct_edges(path: str) -> Set[Tuple[str, str]]:
    edges: Set[Tuple[str, str]] = set()
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if len(row) < 3:
                continue
            _tu, caller, callee = row[:3]
            edges.add((caller, callee))
    return edges


def read_syscall_sinks(path: str) -> Dict[str, Set[str]]:
    sinks: Dict[str, Set[str]] = defaultdict(set)
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if len(row) < 5:
                continue
            _tu, fn, _kind, _callee, nr = row[:5]
            sinks[fn].add(nr)
    return dict(sinks)


def read_indirect_sites(path: str) -> List[IndirectCallSite]:
    """Reader for extended indirect-callsite format.

    Expected columns:
    site_id,function,insn_uid,file,line,bb,callee_kind,callee_operand
    """
    out: List[IndirectCallSite] = []
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if len(row) < 8:
                continue
            site_id, function, insn_uid, *_middle, callee_kind, callee_operand = row[:8]
            out.append(
                IndirectCallSite(
                    site_id=site_id,
                    function=function,
                    insn_uid=int(insn_uid),
                    callee_kind=callee_kind,
                    callee_operand=callee_operand,
                )
            )
    return out


def reverse_reachable_to_sinks(edges: Set[Tuple[str, str]], sinks: Set[str]) -> Set[str]:
    rev: Dict[str, Set[str]] = defaultdict(set)
    for caller, callee in edges:
        rev[callee].add(caller)

    seen: Set[str] = set(sinks)
    stack = list(sinks)
    while stack:
        cur = stack.pop()
        for prev in rev.get(cur, ()):
            if prev not in seen:
                seen.add(prev)
                stack.append(prev)
    return seen


def resolve_relevant_indirect_sites(
    state: AnalysisState,
    resolver: LocalIndirectCallResolver,
) -> Dict[str, Set[str]]:
    reachable = reverse_reachable_to_sinks(state.direct_edges, set(state.syscall_sinks.keys()))

    resolved: Dict[str, Set[str]] = {}
    for site in state.indirect_sites:
        if site.function not in reachable:
            continue
        cands = resolver.resolve(site)
        if cands:
            resolved[site.site_id] = cands
    return resolved


def iterate_until_convergence(
    state: AnalysisState,
    resolver: LocalIndirectCallResolver,
    max_iter: int = 10,
) -> Set[Tuple[str, str]]:
    edges = set(state.direct_edges)

    for _ in range(max_iter):
        delta = 0
        resolved = resolve_relevant_indirect_sites(
            AnalysisState(edges, state.syscall_sinks, state.indirect_sites),
            resolver,
        )
        by_id = {s.site_id: s for s in state.indirect_sites}
        for site_id, targets in resolved.items():
            caller = by_id[site_id].function
            for t in targets:
                edge = (caller, t)
                if edge not in edges:
                    edges.add(edge)
                    delta += 1
        if delta == 0:
            break

    return edges
