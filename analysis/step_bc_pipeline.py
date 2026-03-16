from __future__ import annotations

import csv
from collections import defaultdict, deque
from pathlib import Path


def compute_syscall_reachable_functions(
    direct_edges_csv: str | Path,
    syscall_sites_csv: str | Path,
    output_csv: str | Path,
) -> set[str]:
    """
    Step B:
    Compute the set of functions that can reach a syscall site through
    zero or more direct-call edges.

    direct_edges.csv columns:
        tu,caller,callee

    syscall_sites.csv columns:
        tu,function,site_kind,callee,syscall_nr

    output syscall_reachable_functions.csv columns:
        function
    """
    reverse_graph: dict[str, set[str]] = defaultdict(set)

    with open(direct_edges_csv, "r", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 3:
                continue

            _, caller, callee = row[:3]

            if caller == "caller" and callee == "callee":
                # tolerate accidental header row
                continue

            caller = caller.strip()
            callee = callee.strip()
            if caller and callee:
                reverse_graph[callee].add(caller)

    syscall_funcs: set[str] = set()
    with open(syscall_sites_csv, "r", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 2:
                continue

            # syscall_sites.csv: tu,function,site_kind,callee,syscall_nr
            fn = row[1].strip()
            if fn and fn != "function":
                syscall_funcs.add(fn)

    reachable: set[str] = set(syscall_funcs)
    worklist = deque(syscall_funcs)

    while worklist:
        callee = worklist.popleft()
        for caller in reverse_graph.get(callee, ()):
            if caller not in reachable:
                reachable.add(caller)
                worklist.append(caller)

    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["function"])
        for fn in sorted(reachable):
            writer.writerow([fn])

    return reachable


def _load_reachable_functions(syscall_reachable_functions_csv: str | Path) -> set[str]:
    reachable: set[str] = set()

    with open(syscall_reachable_functions_csv, "r", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue

            fn = row[0].strip()
            if not fn or fn == "function":
                continue

            reachable.add(fn)

    return reachable


def filter_syscall_related_indirect_callsites(
    indirect_callsites_csv: str | Path,
    syscall_reachable_functions_csv: str | Path,
    output_csv: str | Path,
) -> int:
    """
    Step C:
    Filter indirect callsites to only those whose enclosing function is
    syscall-reachable.

    Important:
    - Preserve the full input row shape.
    - Support both:
        old format: tu,function,target_code
        new format: tu,function,bb,insn_idx,loc,target_code
    - Input is treated as headerless.
    """
    reachable = _load_reachable_functions(syscall_reachable_functions_csv)
    kept = 0

    with open(indirect_callsites_csv, "r", newline="") as fin, open(output_csv, "w", newline="") as fout:
        reader = csv.reader(fin)
        writer = csv.writer(fout)

        for row in reader:
            if not row or len(row) < 2:
                continue

            fn = row[1].strip()
            if not fn or fn == "function":
                continue

            if fn in reachable:
                writer.writerow(row)
                kept += 1

    return kept


def run_step_bc(
    direct_edges_csv: str | Path,
    syscall_sites_csv: str | Path,
    indirect_callsites_csv: str | Path,
    out_reachable_csv: str | Path,
    out_filtered_indirect_csv: str | Path,
) -> tuple[int, int]:
    reachable = compute_syscall_reachable_functions(
        direct_edges_csv=direct_edges_csv,
        syscall_sites_csv=syscall_sites_csv,
        output_csv=out_reachable_csv,
    )

    kept = filter_syscall_related_indirect_callsites(
        indirect_callsites_csv=indirect_callsites_csv,
        syscall_reachable_functions_csv=out_reachable_csv,
        output_csv=out_filtered_indirect_csv,
    )

    return len(reachable), kept
