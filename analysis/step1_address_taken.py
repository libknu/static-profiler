from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence, Set, Tuple


@dataclass(frozen=True, order=True)
class AddressTakenEvidence:
    tu: str
    function: str
    evidence_kind: str
    evidence_text: str


def _normalize_function_symbol(raw: str) -> str:
    """Normalize callee symbol spelling from plugin output.

    Current GCC plugin output may prefix some symbol refs with '*'.
    We treat the normalized spelling as the candidate function name.
    """
    return raw.lstrip("*").strip()


def extract_address_taken_from_direct_edges(
    direct_edges_rows: Iterable[Sequence[str]],
) -> Set[AddressTakenEvidence]:
    """Conservatively recover address-taken functions from direct edge artifacts.

    Evidence rule in Step 1:
    - If `direct_edges.csv` callee starts with `*`, treat that symbol reference as
      an address-taken-like occurrence and emit the normalized symbol.
    """
    out: Set[AddressTakenEvidence] = set()

    for row in direct_edges_rows:
        if len(row) < 3:
            continue

        tu, caller, callee = row[:3]
        callee = callee.strip()
        if not callee.startswith("*"):
            continue

        function = _normalize_function_symbol(callee)
        if not function:
            continue

        out.add(
            AddressTakenEvidence(
                tu=tu,
                function=function,
                evidence_kind="symbol_ref_star_callee",
                evidence_text=f"caller={caller};raw_callee={callee}",
            )
        )

    return out


def read_direct_edges_rows(path: str) -> List[List[str]]:
    with open(path, newline="") as f:
        return [row for row in csv.reader(f) if row]


def write_address_taken_csv(path: str, rows: Iterable[AddressTakenEvidence]) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    sorted_rows = sorted(set(rows))
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["tu", "function", "evidence_kind", "evidence_text"])
        for row in sorted_rows:
            w.writerow([row.tu, row.function, row.evidence_kind, row.evidence_text])


def run_step1_extract_address_taken(
    direct_edges_csv: str,
    out_address_taken_csv: str,
) -> Set[AddressTakenEvidence]:
    direct_edges_rows = read_direct_edges_rows(direct_edges_csv)
    evidence = extract_address_taken_from_direct_edges(direct_edges_rows)
    write_address_taken_csv(out_address_taken_csv, evidence)
    return evidence
