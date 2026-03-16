#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.step_bc_pipeline import run_step_bc


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Step B/C analysis only")
    parser.add_argument("--direct-edges", required=True)
    parser.add_argument("--syscall-sites", required=True)
    parser.add_argument("--indirect-callsites", required=True)
    parser.add_argument(
        "--out-reachable",
        default="out/syscall_reachable_functions.csv",
    )
    parser.add_argument(
        "--out-related-indirect",
        default="out/syscall_related_indirect_callsites.csv",
    )
    args = parser.parse_args()

    reachable_count, related_count = run_step_bc(
        direct_edges_csv=Path(args.direct_edges),
        syscall_sites_csv=Path(args.syscall_sites),
        indirect_callsites_csv=Path(args.indirect_callsites),
        out_reachable_csv=Path(args.out_reachable),
        out_filtered_indirect_csv=Path(args.out_related_indirect),
    )

    print(f"reachable_functions={reachable_count}")
    print(f"related_indirect_sites={related_count}")


if __name__ == "__main__":
    main()
