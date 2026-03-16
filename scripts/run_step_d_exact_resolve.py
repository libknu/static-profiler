from __future__ import annotations

import argparse

from analysis.step_d_exact_resolve import run_step_d_exact_resolve


def main() -> None:
    p = argparse.ArgumentParser(description="Step D: exact indirect target resolver")
    p.add_argument("--indirect-callsites", required=True)
    p.add_argument("--defuse-csv", default="", help="Insn-level def/use CSV exported by plugin")
    p.add_argument("--out", required=True)
    args = p.parse_args()

    run_step_d_exact_resolve(
        indirect_callsites_csv=args.indirect_callsites,
        defuse_csv=args.defuse_csv,
        out_csv=args.out,
    )


if __name__ == "__main__":
    main()
