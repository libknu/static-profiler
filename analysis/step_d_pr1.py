from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Sequence, Set, Tuple
import csv

from analysis.step_bc_pipeline import read_indirect_callsites


def read_function_universe(path: str) -> Set[str]:
    """Read function universe from CSV.

    Accepts either:
    - headered CSV containing a `function` column
    - legacy rows in the form `tu,function`
    """
    with open(path, newline="") as f:
        rows = [row for row in csv.reader(f) if row]

    if not rows:
        return set()

    header = [c.strip().lower() for c in rows[0]]
    if "function" in header:
        idx = header.index("function")
        body = rows[1:]
    else:
        idx = 1 if len(rows[0]) > 1 else 0
        body = rows

    out: Set[str] = set()
    for row in body:
        if len(row) <= idx:
            continue
        fn = row[idx].strip()
        if fn:
            out.add(fn)
    return out


def normalize_indirect_callsites(path: str) -> List[Tuple[str, str, str, str]]:
    """Return rows as (site_id, tu, function, raw_target_code)."""
    header, rows = read_indirect_callsites(path)

    # Current repository format is [tu,function,target_code], with optional header.
    lowered = [c.strip().lower() for c in header] if header else []
    tu_idx = lowered.index("tu") if "tu" in lowered else 0
    fn_idx = lowered.index("function") if "function" in lowered else 1
    target_idx = lowered.index("target_code") if "target_code" in lowered else 2

    out: List[Tuple[str, str, str, str]] = []
    for i, row in enumerate(rows, start=1):
        tu = row[tu_idx] if len(row) > tu_idx else ""
        fn = row[fn_idx] if len(row) > fn_idx else ""
        target = row[target_idx] if len(row) > target_idx else ""
        out.append((f"cs_{i:06d}", tu, fn, target))
    return out


def write_address_taken_functions(path: str, functions: Iterable[str]) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["function", "evidence_kind", "evidence_loc"])
        for fn in sorted(set(functions)):
            w.writerow([fn, "bootstrap-functions-seen", "<unknown>"])


def write_normalized_callsites(path: str, rows: Sequence[Tuple[str, str, str, str]]) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["site_id", "tu", "function", "raw_indirect_expr"])
        w.writerows(rows)


def write_pr1_candidates(
    path: str,
    normalized_callsites: Sequence[Tuple[str, str, str, str]],
    address_taken_functions: Set[str],
) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    sorted_candidates = sorted(address_taken_functions)
    joined = ";".join(sorted_candidates)

    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "site_id",
            "enclosing_function",
            "candidate_count",
            "candidates",
            "source",
            "confidence",
        ])
        for site_id, _tu, function, _raw in normalized_callsites:
            w.writerow(
                [
                    site_id,
                    function,
                    len(sorted_candidates),
                    joined,
                    "ADDRESS_TAKEN_COARSE_UNIVERSE",
                    "LOW",
                ]
            )


def run_step_d_pr1(
    syscall_related_indirect_callsites_csv: str,
    functions_seen_csv: str,
    out_address_taken_csv: str,
    out_normalized_callsites_csv: str,
    out_candidates_csv: str,
) -> Tuple[int, int]:
    function_universe = read_function_universe(functions_seen_csv)
    normalized_callsites = normalize_indirect_callsites(syscall_related_indirect_callsites_csv)

    write_address_taken_functions(out_address_taken_csv, function_universe)
    write_normalized_callsites(out_normalized_callsites_csv, normalized_callsites)
    write_pr1_candidates(out_candidates_csv, normalized_callsites, function_universe)

    return len(normalized_callsites), len(function_universe)
