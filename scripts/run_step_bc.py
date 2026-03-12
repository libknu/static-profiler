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
    p = argparse.ArgumentParser(description="Run Step B/C analysis only")
    p.add_argument("--direct-edges", required=True)
    p.add_argument("--syscall-sites", required=True)
    p.add_argument("--indirect-callsites", required=True)
    p.add_argument("--out-reachable", default="out/syscall_reachable_functions.csv")
    p.add_argument("--out-related-indirect", default="out/syscall_related_indirect_callsites.csv")
    args = p.parse_args()

    reachable, related = run_step_bc(
        direct_edges_csv=args.direct_edges,
        syscall_sites_csv=args.syscall_sites,
        indirect_callsites_csv=args.indirect_callsites,
        out_reachable_csv=args.out_reachable,
        out_related_indirect_csv=args.out_related_indirect,
    )

    print(f"reachable_functions={len(reachable)}")
    print(f"related_indirect_sites={len(related)}")


if __name__ == "__main__":
    main()
