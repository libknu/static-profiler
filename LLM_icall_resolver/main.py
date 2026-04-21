import argparse
import json
import os
import re

from .graph import build_graph
from .trace_store import prepare_output_dir, save_final_result, save_run_manifest


DEFAULT_OUTPUT_ROOT = "/home/jiwoo/workspace/LLM_icall_resolver/outputs"


def sanitize_name(s: str) -> str:
    s = re.sub(r"[^\w.-]+", "_", s.strip())
    return s.strip("_") or "run"


def derive_run_name(args) -> str:
    if args.run_name:
        return sanitize_name(args.run_name)

    loc = sanitize_name(args.icall_location.replace("/", "_"))
    caller = sanitize_name(args.caller_symbol)
    return f"{caller}_{loc}"


def build_initial_state(args, run_name: str, output_dir: str) -> dict:
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
        "initializer_context": [],

        "hop_count": 0,
        "iteration": 0,
        "max_hops": args.max_hops,
        "status": "running",

        "bootlin_references": [],
        "reference_jump_candidates": [],

        "run_name": run_name,
        "output_root": args.output_root,
        "output_dir": output_dir,
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
            f"[iteration={item['iteration']}] "
            f"[step={item['step']}] "
            f"symbol={item['focus_symbol']} "
            f"decision={item['decision']} "
            f"next={item['next_symbol']} "
            f"jump_kind={item.get('jump_kind')}"
        )
        print("  summary:", item["summary"])
        if item.get("candidate_callees"):
            print("  candidate_callees:", item["candidate_callees"])
        if item.get("grounded_sources"):
            print("  grounded_sources:", item["grounded_sources"])
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
    parser.add_argument("--run-name", default=os.environ.get("LLM_ICALL_RUN_NAME"))
    parser.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT)

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

    run_name = derive_run_name(args)
    output_dir = prepare_output_dir(args.output_root, run_name)

    initial_state = build_initial_state(args, run_name=run_name, output_dir=output_dir)

    save_run_manifest(
        output_dir,
        {
            "run_name": run_name,
            "args": vars(args),
            "initial_state": initial_state,
        },
    )

    app = build_graph()

    if args.stream:
        print()
        print("=== STREAM UPDATES ===")
        result = None
        for state in app.stream(initial_state, stream_mode="values"):
            print(json.dumps(state, indent=2, ensure_ascii=False))
            result = state
        print("=== END STREAM ===")
        print()
    else:
        result = app.invoke(initial_state)

    save_final_result(output_dir, result)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_result(result)


if __name__ == "__main__":
    main()
