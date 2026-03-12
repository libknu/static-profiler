from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set, Tuple
import csv


def read_direct_edges(path: str) -> Set[Tuple[str, str]]:
    """Read direct edge CSV rows as (caller, callee). Expects tu,caller,callee."""
    edges: Set[Tuple[str, str]] = set()
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if len(row) < 3:
                continue
            _tu, caller, callee = row[:3]
            edges.add((caller, callee))
    return edges


def read_syscall_sink_functions(path: str) -> Set[str]:
    """Read syscall sink functions from syscall_sites.csv (tu,caller,site_kind,callee,syscall_nr)."""
    sinks: Set[str] = set()
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if len(row) < 2:
                continue
            _tu, function = row[:2]
            sinks.add(function)
    return sinks


def compute_syscall_reachable_functions(
    direct_edges: Iterable[Tuple[str, str]],
    sink_functions: Iterable[str],
) -> Set[str]:
    reverse_graph: Dict[str, Set[str]] = defaultdict(set)
    for caller, callee in direct_edges:
        reverse_graph[callee].add(caller)

    reachable: Set[str] = set(sink_functions)
    q = deque(reachable)

    while q:
        callee = q.popleft()
        for caller in reverse_graph.get(callee, ()):
            if caller not in reachable:
                reachable.add(caller)
                q.append(caller)

    return reachable


def read_indirect_callsites(path: str) -> Tuple[List[str], List[List[str]]]:
    """Read indirect callsite CSV with header auto-detection.

    Returns (header, rows). Header is [] if absent.
    """
    with open(path, newline="") as f:
        rows = [row for row in csv.reader(f) if row]

    if not rows:
        return [], []

    first = rows[0]
    lower = [c.strip().lower() for c in first]
    has_header = "function" in lower or "site_id" in lower or "insn_uid" in lower

    if has_header:
        return first, rows[1:]

    return [], rows


def _function_column_index(header: Sequence[str]) -> int:
    if not header:
        return 1  # current repo sample format: tu,function,target_code

    lowered = [c.strip().lower() for c in header]
    if "function" in lowered:
        return lowered.index("function")
    if "caller" in lowered:
        return lowered.index("caller")
    return 1


def filter_syscall_related_indirect_callsites(
    header: Sequence[str],
    rows: Iterable[Sequence[str]],
    reachable_functions: Set[str],
) -> List[List[str]]:
    idx = _function_column_index(header)
    out: List[List[str]] = []
    for row in rows:
        if len(row) <= idx:
            continue
        if row[idx] in reachable_functions:
            out.append(list(row))
    return out


def write_single_column_csv(path: str, column_name: str, values: Iterable[str]) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([column_name])
        for v in sorted(set(values)):
            w.writerow([v])


def write_rows_csv(path: str, header: Sequence[str], rows: Iterable[Sequence[str]]) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        if header:
            w.writerow(list(header))
        for row in rows:
            w.writerow(list(row))


def run_step_bc(
    direct_edges_csv: str,
    syscall_sites_csv: str,
    indirect_callsites_csv: str,
    out_reachable_csv: str,
    out_related_indirect_csv: str,
) -> Tuple[Set[str], List[List[str]]]:
    edges = read_direct_edges(direct_edges_csv)
    sinks = read_syscall_sink_functions(syscall_sites_csv)
    reachable = compute_syscall_reachable_functions(edges, sinks)

    header, indirect_rows = read_indirect_callsites(indirect_callsites_csv)
    related_indirect = filter_syscall_related_indirect_callsites(header, indirect_rows, reachable)

    write_single_column_csv(out_reachable_csv, "function", reachable)
    write_rows_csv(out_related_indirect_csv, header, related_indirect)

    return reachable, related_indirect
