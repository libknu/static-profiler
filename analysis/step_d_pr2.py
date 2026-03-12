from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set, Tuple
import csv

from analysis.step_d_pr1 import (
    normalize_indirect_callsites,
    read_function_universe,
    write_address_taken_functions,
    write_normalized_callsites,
)


@dataclass(frozen=True)
class ExplicitFpFact:
    tu: str
    function: str
    loc: str
    lhs_kind: str
    lhs_key: str
    rhs_function: str
    evidence_kind: str


def read_explicit_fp_facts(path: str) -> List[ExplicitFpFact]:
    """Read explicit function-pointer assignment facts.

    Supported schemas:
    - Headered with columns matching PR2 schema.
    - Headerless legacy rows in order:
      tu,function,loc,lhs_kind,lhs_key,rhs_function,evidence_kind
    """
    with open(path, newline="") as f:
        rows = [row for row in csv.reader(f) if row]

    if not rows:
        return []

    first_lower = [c.strip().lower() for c in rows[0]]
    if "rhs_function" in first_lower:
        idx = {
            "tu": first_lower.index("tu") if "tu" in first_lower else 0,
            "function": first_lower.index("function") if "function" in first_lower else 1,
            "loc": first_lower.index("loc") if "loc" in first_lower else 2,
            "lhs_kind": first_lower.index("lhs_kind") if "lhs_kind" in first_lower else 3,
            "lhs_key": first_lower.index("lhs_key") if "lhs_key" in first_lower else 4,
            "rhs_function": first_lower.index("rhs_function"),
            "evidence_kind": first_lower.index("evidence_kind") if "evidence_kind" in first_lower else 6,
        }
        body = rows[1:]
    else:
        idx = {
            "tu": 0,
            "function": 1,
            "loc": 2,
            "lhs_kind": 3,
            "lhs_key": 4,
            "rhs_function": 5,
            "evidence_kind": 6,
        }
        body = rows

    out: List[ExplicitFpFact] = []
    for row in body:
        if len(row) <= idx["rhs_function"]:
            continue
        rhs = row[idx["rhs_function"]].strip()
        fn = row[idx["function"]].strip() if len(row) > idx["function"] else ""
        if not rhs or not fn:
            continue
        out.append(
            ExplicitFpFact(
                tu=row[idx["tu"]].strip() if len(row) > idx["tu"] else "",
                function=fn,
                loc=row[idx["loc"]].strip() if len(row) > idx["loc"] else "",
                lhs_kind=row[idx["lhs_kind"]].strip() if len(row) > idx["lhs_kind"] else "",
                lhs_key=row[idx["lhs_key"]].strip() if len(row) > idx["lhs_key"] else "",
                rhs_function=rhs,
                evidence_kind=row[idx["evidence_kind"]].strip()
                if len(row) > idx["evidence_kind"]
                else "explicit-assignment",
            )
        )

    return out


def write_fp_assignment_facts(path: str, facts: Sequence[ExplicitFpFact]) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["fact_id", "tu", "function", "loc", "lhs_kind", "lhs_key", "rhs_function", "evidence_kind"])
        for i, fact in enumerate(facts, start=1):
            w.writerow(
                [
                    f"fact_{i:06d}",
                    fact.tu,
                    fact.function,
                    fact.loc,
                    fact.lhs_kind,
                    fact.lhs_key,
                    fact.rhs_function,
                    fact.evidence_kind or "explicit-assignment",
                ]
            )


def _explicit_candidates_by_function(facts: Sequence[ExplicitFpFact]) -> Dict[str, Set[str]]:
    by_fn: Dict[str, Set[str]] = {}
    for fact in facts:
        by_fn.setdefault(fact.function, set()).add(fact.rhs_function)
    return by_fn


def write_pr2_candidates(
    path: str,
    normalized_callsites: Sequence[Tuple[str, str, str, str]],
    address_taken_functions: Set[str],
    explicit_facts: Sequence[ExplicitFpFact],
) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    by_fn = _explicit_candidates_by_function(explicit_facts)

    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "site_id",
                "enclosing_function",
                "hard_candidate_count",
                "hard_candidates",
                "soft_candidate_count",
                "soft_candidates",
                "primary_source",
                "confidence",
            ]
        )

        for site_id, _tu, function, _raw in normalized_callsites:
            hard = sorted(by_fn.get(function, set()))
            soft = sorted(address_taken_functions - set(hard))

            if hard:
                source = "EXPLICIT_ASSIGNMENT"
                confidence = "HIGH"
            elif soft:
                source = "ADDRESS_TAKEN_COARSE_UNIVERSE"
                confidence = "LOW"
            else:
                source = "NONE"
                confidence = "LOW"

            w.writerow(
                [
                    site_id,
                    function,
                    len(hard),
                    ";".join(hard),
                    len(soft),
                    ";".join(soft),
                    source,
                    confidence,
                ]
            )


def run_step_d_pr2(
    syscall_related_indirect_callsites_csv: str,
    functions_seen_csv: str,
    explicit_fp_facts_csv: str | None,
    out_address_taken_csv: str,
    out_normalized_callsites_csv: str,
    out_fp_assignment_facts_csv: str,
    out_candidates_csv: str,
) -> Tuple[int, int, int]:
    function_universe = read_function_universe(functions_seen_csv)
    normalized_callsites = normalize_indirect_callsites(syscall_related_indirect_callsites_csv)

    explicit_facts = read_explicit_fp_facts(explicit_fp_facts_csv) if explicit_fp_facts_csv else []

    write_address_taken_functions(out_address_taken_csv, function_universe)
    write_normalized_callsites(out_normalized_callsites_csv, normalized_callsites)
    write_fp_assignment_facts(out_fp_assignment_facts_csv, explicit_facts)
    write_pr2_candidates(out_candidates_csv, normalized_callsites, function_universe, explicit_facts)

    return len(normalized_callsites), len(function_universe), len(explicit_facts)
