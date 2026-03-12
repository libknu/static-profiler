from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set, Tuple
import csv

from analysis.step_d_pr1 import (
    normalize_indirect_callsites,
    read_function_universe,
    write_address_taken_functions,
    write_normalized_callsites,
)
from analysis.step_d_pr2 import ExplicitFpFact, read_explicit_fp_facts, write_fp_assignment_facts


def build_intra_fp_states(explicit_facts: Sequence[ExplicitFpFact]) -> Dict[Tuple[str, str], Set[str]]:
    """Build per-function/per-fp-symbol candidate sets from explicit assignments.

    Key = (enclosing_function, fp_symbol/lhs_key)
    Value = set of RHS function candidates observed in the function.
    """
    states: Dict[Tuple[str, str], Set[str]] = {}
    for fact in explicit_facts:
        fp_symbol = fact.lhs_key.strip() or "<unknown-fp>"
        key = (fact.function, fp_symbol)
        states.setdefault(key, set()).add(fact.rhs_function)
    return states


def write_intra_fp_states(path: str, states: Dict[Tuple[str, str], Set[str]]) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["function", "fp_symbol", "candidate_count", "candidate_set"])
        for (function, fp_symbol), cands in sorted(states.items()):
            sorted_cands = sorted(cands)
            w.writerow([function, fp_symbol, len(sorted_cands), ";".join(sorted_cands)])


def intra_candidates_by_function(states: Dict[Tuple[str, str], Set[str]]) -> Dict[str, Set[str]]:
    by_fn: Dict[str, Set[str]] = {}
    for (function, _fp_symbol), cands in states.items():
        by_fn.setdefault(function, set()).update(cands)
    return by_fn


def write_pr3_candidates(
    path: str,
    normalized_callsites: Sequence[Tuple[str, str, str, str]],
    address_taken_functions: Set[str],
    intra_by_function: Dict[str, Set[str]],
) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "site_id",
                "enclosing_function",
                "intra_candidate_count",
                "intra_candidates",
                "soft_candidate_count",
                "soft_candidates",
                "primary_source",
                "confidence",
            ]
        )

        for site_id, _tu, function, _raw in normalized_callsites:
            intra = sorted(intra_by_function.get(function, set()))
            soft = sorted(address_taken_functions - set(intra))

            if intra:
                source = "INTRA_FLOW"
                confidence = "MEDIUM"
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
                    len(intra),
                    ";".join(intra),
                    len(soft),
                    ";".join(soft),
                    source,
                    confidence,
                ]
            )


def run_step_d_pr3(
    syscall_related_indirect_callsites_csv: str,
    functions_seen_csv: str,
    explicit_fp_facts_csv: str | None,
    out_address_taken_csv: str,
    out_normalized_callsites_csv: str,
    out_fp_assignment_facts_csv: str,
    out_intra_states_csv: str,
    out_candidates_csv: str,
) -> Tuple[int, int, int, int]:
    function_universe = read_function_universe(functions_seen_csv)
    normalized_callsites = normalize_indirect_callsites(syscall_related_indirect_callsites_csv)
    explicit_facts = read_explicit_fp_facts(explicit_fp_facts_csv) if explicit_fp_facts_csv else []

    states = build_intra_fp_states(explicit_facts)
    intra_by_fn = intra_candidates_by_function(states)

    write_address_taken_functions(out_address_taken_csv, function_universe)
    write_normalized_callsites(out_normalized_callsites_csv, normalized_callsites)
    write_fp_assignment_facts(out_fp_assignment_facts_csv, explicit_facts)
    write_intra_fp_states(out_intra_states_csv, states)
    write_pr3_candidates(out_candidates_csv, normalized_callsites, function_universe, intra_by_fn)

    return len(normalized_callsites), len(function_universe), len(explicit_facts), len(states)
