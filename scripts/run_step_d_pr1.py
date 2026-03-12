#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.step_d_pr1 import run_step_d_pr1


def main() -> None:
    p = argparse.ArgumentParser(description="Run PR1 (Step D1) coarse indirect resolution")
    p.add_argument("--syscall-related-indirect", required=True)
    p.add_argument("--functions-seen", required=True)
    p.add_argument("--out-address-taken", default="out/step_d/address_taken_functions.csv")
    p.add_argument("--out-normalized-callsites", default="out/step_d/indirect_callsites_normalized.csv")
    p.add_argument("--out-candidates", default="out/step_d/indirect_candidates_pr1.csv")
    args = p.parse_args()

    n_sites, n_universe = run_step_d_pr1(
        syscall_related_indirect_callsites_csv=args.syscall_related_indirect,
        functions_seen_csv=args.functions_seen,
        out_address_taken_csv=args.out_address_taken,
        out_normalized_callsites_csv=args.out_normalized_callsites,
        out_candidates_csv=args.out_candidates,
    )

    print(f"indirect_sites={n_sites}")
    print(f"coarse_candidate_universe={n_universe}")


if __name__ == "__main__":
    main()
