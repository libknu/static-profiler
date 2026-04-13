import argparse
import json
import sys
from pathlib import Path

# examples/에서 직접 실행할 수 있도록 import 경로 보정
THIS_DIR = Path(__file__).resolve().parent
PKG_ROOT = THIS_DIR.parent
if str(PKG_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(PKG_ROOT.parent))

from LLM_icall_resolver.bootlin import bootlin_ident


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Test Bootlin ident API lookup for a single symbol."
    )
    parser.add_argument("symbol", help="Symbol name to query, e.g. key_call_socket")
    parser.add_argument("--project", default="glibc", help="Bootlin project name")
    parser.add_argument("--version", default="glibc-2.41", help="Bootlin version")
    parser.add_argument("--family", default="C", help="Bootlin language family")
    parser.add_argument(
        "--show-defs-only",
        action="store_true",
        help="Print only the definitions array",
    )
    args = parser.parse_args()

    try:
        result = bootlin_ident(
            project=args.project,
            version=args.version,
            family=args.family,
            symbol=args.symbol,
        )
    except Exception as e:
        print(f"[ERROR] bootlin_ident failed for symbol={args.symbol}: {e}")
        return 1

    print("=== QUERY ===")
    print(f"project={args.project}")
    print(f"version={args.version}")
    print(f"family={args.family}")
    print(f"symbol={args.symbol}")
    print()

    defs = result.get("definitions", [])
    refs = result.get("references", [])

    print("=== SUMMARY ===")
    print(f"definitions: {len(defs)}")
    print(f"references: {len(refs)}")
    print()

    if args.show_defs_only:
        print("=== DEFINITIONS ===")
        print(json.dumps(defs, indent=2, ensure_ascii=False))
        return 0

    print("=== FULL RESPONSE ===")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
