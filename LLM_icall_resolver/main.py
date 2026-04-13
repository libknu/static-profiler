import argparse
import json

from .graph import build_graph


def build_initial_state(args) -> dict:
    return {
        "project_root": args.project_root,
        "project": args.project,
        "version": args.version,
        "family": args.family,

        "caller_symbol": args.caller_symbol,
        "current_symbol": args.caller_symbol,
        "icall_expr": args.icall_expr,
        "icall_location": args.icall_location,

        "visited_symbols": [args.caller_symbol],
        "retrieved_chunks": [],
        "observations": [],
        "visible_trace": [],
        "candidate_callees": [],
        "macro_context": [],
        "struct_context": [],
        "assignment_context": [],


        "hop_count": 0,
        "max_hops": args.max_hops,
        "status": "running",
    }


def print_result(result: dict) -> None:
    print("STATUS:", result.get("status", "unknown"))
    print()

    print("OBSERVATIONS:")
    for x in result.get("observations", []):
        print("-", x)
    print()

    print("FINAL ANSWER:")
    print(result.get("final_answer", ""))
    print()

    print("VISIBLE TRACE:")
    traces = result.get("visible_trace", [])
    if not traces:
        print("(empty)")
        return

    for item in traces:
        print(
            f"[step={item['step']}] "
            f"symbol={item['focus_symbol']} "
            f"decision={item['decision']} "
            f"next={item['next_symbol']}"
        )
        print("  summary:", item["summary"])
        if item.get("candidate_callees"):
            print("  candidate_callees:", item["candidate_callees"])
        for ev in item.get("evidence", []):
            print("  evidence:", ev)
        print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--project-root",
        default="/home/jiwoo/workspace/glibc-src/glibc-2.41",
    )
    parser.add_argument("--project", default="glibc")
    parser.add_argument("--version", default="glibc-2.41")
    parser.add_argument("--family", default="C")

    parser.add_argument("--caller-symbol", default="key_call_socket")
    parser.add_argument("--icall-expr", default="clnt_call(clnt, proc, xdr_arg, arg, xdr_rslt, rslt, wait_time)")
    parser.add_argument("--icall-location", default="sunrpc/key_call.c")

    parser.add_argument("--max-hops", type=int, default=6)
    parser.add_argument(
        "--stream",
        action="store_true",
        help="stream node updates while graph is running",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print final state as JSON",
    )

    args = parser.parse_args()

    app = build_graph()
    initial_state = build_initial_state(args)

    if args.stream:
        print("=== STREAM UPDATES ===")
        final_result = None
        for update in app.stream(initial_state, stream_mode="updates"):
            print(json.dumps(update, indent=2, ensure_ascii=False))
            final_result = update
        print("=== END STREAM ===")
        print()

        # stream_mode="updates"는 마지막 전체 state를 항상 주는 것은 아니므로
        # 최종 결과는 invoke로 한 번 더 가져온다.
        result = app.invoke(initial_state)
    else:
        result = app.invoke(initial_state)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_result(result)


if __name__ == "__main__":
    main()
