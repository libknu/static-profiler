#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.step1_address_taken import run_step1_extract_address_taken


def main() -> None:
    p = argparse.ArgumentParser(
        description="Step 1/7: extract conservative address-taken function pool"
    )
    p.add_argument("--direct-edges", required=True)
    p.add_argument(
        "--out-address-taken",
        default="out/step1/address_taken_functions.csv",
    )
    args = p.parse_args()

    evidence = run_step1_extract_address_taken(
        direct_edges_csv=args.direct_edges,
        out_address_taken_csv=args.out_address_taken,
    )
    unique_functions = {row.function for row in evidence}
    print(f"address_taken_evidence_rows={len(evidence)}")
    print(f"address_taken_unique_functions={len(unique_functions)}")


if __name__ == "__main__":
    main()
