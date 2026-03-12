#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.step_d_pr3 import run_step_d_pr3


def main() -> None:
    p = argparse.ArgumentParser(description="Run PR3 intra-procedural indirect candidate recovery")
    p.add_argument("--syscall-related-indirect", required=True)
    p.add_argument("--functions-seen", required=True)
    p.add_argument("--explicit-fp-facts", default=None)
    p.add_argument("--out-address-taken", default="out/step_d/address_taken_functions.csv")
    p.add_argument("--out-normalized-callsites", default="out/step_d/indirect_callsites_normalized.csv")
    p.add_argument("--out-fp-assignment-facts", default="out/step_d/fp_assignment_facts.csv")
    p.add_argument("--out-intra-states", default="out/step_d/intra_procedural_fp_states.csv")
    p.add_argument("--out-candidates", default="out/step_d/indirect_candidates_pr3.csv")
    args = p.parse_args()

    n_sites, n_universe, n_facts, n_states = run_step_d_pr3(
        syscall_related_indirect_callsites_csv=args.syscall_related_indirect,
        functions_seen_csv=args.functions_seen,
        explicit_fp_facts_csv=args.explicit_fp_facts,
        out_address_taken_csv=args.out_address_taken,
        out_normalized_callsites_csv=args.out_normalized_callsites,
        out_fp_assignment_facts_csv=args.out_fp_assignment_facts,
        out_intra_states_csv=args.out_intra_states,
        out_candidates_csv=args.out_candidates,
    )

    print(f"indirect_sites={n_sites}")
    print(f"coarse_candidate_universe={n_universe}")
    print(f"explicit_fp_facts={n_facts}")
    print(f"intra_fp_states={n_states}")


if __name__ == "__main__":
    main()
