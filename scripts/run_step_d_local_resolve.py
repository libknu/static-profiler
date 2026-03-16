#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.step_d_local_resolve import run_step_d_local_resolve


def main() -> None:
    p = argparse.ArgumentParser(description="Step D: same-function local indirect target resolver")
    p.add_argument("--indirect-callsites", required=True, help="syscall-reachable indirect callsite CSV")
    p.add_argument("--defuse-csv", required=True, help="defuse_events.csv path")
    p.add_argument("--out", required=True)
    args = p.parse_args()

    _header, out_rows = run_step_d_local_resolve(
        indirect_callsites_csv=args.indirect_callsites,
        defuse_csv=args.defuse_csv,
        out_csv=args.out,
    )
    print(f"resolved_rows={len(out_rows)}")


if __name__ == "__main__":
    main()
