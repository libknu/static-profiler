import argparse
import json
import os
import re

from .graph import build_graph
from .analyzer import DEFAULT_MODEL_NAME, DEFAULT_PROVIDER, normalize_provider
from .trace_store import prepare_output_dir, save_final_result, save_run_manifest
from .deterministic import prepare_callsite_inputs


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


def infer_icall_line_from_name(name: str | None) -> int | None:
    if not name:
        return None
    parts = sanitize_name(name).rsplit("_", 3)
    if len(parts) != 4:
        return None
    line, bb, insn = parts[1:]
    if line.isdigit() and bb.isdigit() and insn.isdigit():
        return int(line)
    return None


def build_initial_state(args, run_name: str, output_dir: str) -> dict:
    return {
        "project_root": args.project_root,
        "project": args.project,
        "version": args.version,
        "family": args.family,
        "provider": args.provider,
        "model": args.model,

        "caller_symbol": args.caller_symbol,
        "current_symbol": args.caller_symbol,
        "icall_expr": args.icall_expr,
        "icall_location": args.icall_location,
        "icall_line": args.icall_line,

        "visited_symbols": [args.caller_symbol],
        "retrieved_chunks": [],
        "observations": getattr(args, "prepared_observations", []),
        "visible_trace": [],
        "candidate_callees": [],
        "macro_context": [],
        "struct_context": [],
        "assignment_context": [],
        "initializer_context": [],

        "hop_count": 0,
        "iteration": 0,
        "max_hops": args.max_hops,
        "max_iterations": args.max_iterations,
        "status": "running",
        "icall_resolution_status": "unresolved",
        "icall_resolved": False,
        "icall_resolution_reason": "",
        "icall_targets": [],

        "bootlin_references": [],
        "reference_jump_candidates": [],

        "run_name": run_name,
        "output_root": args.output_root,
        "output_dir": output_dir,
    }


def print_result(result: dict) -> None:
    print("STATUS:", result.get("status", "unknown"))
    print("ICALL_RESOLUTION_STATUS:", result.get("icall_resolution_status", "unknown"))
    print("ICALL_RESOLVED:", result.get("icall_resolved", False))
    if result.get("icall_resolution_reason"):
        print("ICALL_REASON:", result["icall_resolution_reason"])
    if result.get("icall_targets"):
        print("ICALL_TARGETS:", result["icall_targets"])
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
    parser.add_argument(
        "--provider",
        choices=["openai", "anthropic"],
        default=os.environ.get("LLM_ICALL_PROVIDER"),
    )
    parser.add_argument("--model", default=os.environ.get("LLM_ICALL_MODEL", DEFAULT_MODEL_NAME))

    parser.add_argument("--caller-symbol", default="key_call_socket")
    parser.add_argument("--icall-expr", default="clnt_call(clnt, proc, xdr_arg, arg, xdr_rslt, rslt, wait_time)")
    parser.add_argument("--icall-location", default="sunrpc/key_call.c")
    parser.add_argument("--icall-line", type=int, default=None)

    parser.add_argument("--max-hops", type=int, default=6)
    parser.add_argument("--max-iterations", type=int, default=10)
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
    args.provider = normalize_provider(args.provider, args.model)

    run_name = derive_run_name(args)
    if args.icall_line is None:
        args.icall_line = infer_icall_line_from_name(run_name)
    prepared = prepare_callsite_inputs(vars(args))
    args.prepared_observations = prepared.get("observations", [])
    if prepared.get("icall_location"):
        args.icall_location = prepared["icall_location"]
    if prepared.get("icall_expr"):
        args.icall_expr = prepared["icall_expr"]
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
