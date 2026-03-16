from __future__ import annotations

import argparse

from analysis.step_d_defuse_from_rtl import run_step_d_defuse_from_rtl


def main() -> None:
    p = argparse.ArgumentParser(description="Extract insn-level def/use CSV from GCC RTL dump")
    p.add_argument("--rtl-dump", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--tu", default="rtl-dump")
    args = p.parse_args()

    rows = run_step_d_defuse_from_rtl(args.rtl_dump, args.out, tu=args.tu)
    print(f"defuse_events={len(rows)}")


if __name__ == "__main__":
    main()
