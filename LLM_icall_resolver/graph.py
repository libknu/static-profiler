import re

try:
    from langgraph.graph import StateGraph, START, END
except ModuleNotFoundError:
    StateGraph = None
    START = END = None

from .state import ResolverState
from .bootlin import bootlin_ident
from .treesitter_retriever import (
    get_context_bundle,
    get_reference_jump_candidates,
)
from .analyzer import llm_analyze_step
from .trace_store import save_step_artifacts


IDENT_PAT = re.compile(r"\b[A-Za-z_]\w*\b")


def _extract_symbols(text: str) -> set[str]:
    return set(IDENT_PAT.findall(text or ""))


def _extract_symbols_from_context_list(items: list[str]) -> set[str]:
    out = set()
    for item in items or []:
        out.update(_extract_symbols(item))
    return out


def classify_jump_kind(state: ResolverState, next_symbol: str | None) -> tuple[str | None, list[str]]:
    if not next_symbol:
        return None, []

    matched_sources = []

    if next_symbol in _extract_symbols(state.get("current_block", "")):
        matched_sources.append("current_block")

    if next_symbol in _extract_symbols_from_context_list(state.get("macro_context", [])):
        matched_sources.append("macro_context")

    if next_symbol in _extract_symbols_from_context_list(state.get("struct_context", [])):
        matched_sources.append("struct_context")

    if next_symbol in _extract_symbols_from_context_list(state.get("assignment_context", [])):
        matched_sources.append("assignment_context")

    if next_symbol in _extract_symbols_from_context_list(state.get("initializer_context", [])):
        matched_sources.append("initializer_context")

    ref_syms = {
        c.get("symbol")
        for c in state.get("reference_jump_candidates", [])
        if c.get("symbol")
    }
    if next_symbol in ref_syms:
        matched_sources.append("reference_jump_candidates")

    if matched_sources:
        return "grounded", matched_sources
    return "speculative", []


def summarize_icall_resolution(candidates: list[str], decision_reason: str) -> str:
    if candidates:
        return f"Resolved indirect-call target(s): {', '.join(candidates)}"

    reason = (decision_reason or "").lower()
    if "not an indirect call" in reason or "not a call" in reason:
        return "The analyzed expression is not an indirect call."
    return "No candidate callees were identified."


def classify_icall_resolution(candidates: list[str], decision_reason: str) -> str:
    if candidates:
        return "resolved"

    reason = (decision_reason or "").lower()
    if "not an indirect call" in reason or "not a call" in reason:
        return "not_icall"
    return "unresolved"


def select_definition(defs: list[dict], icall_location: str | None) -> dict:
    if not defs:
        raise ValueError("select_definition requires at least one definition")

    if not icall_location:
        return defs[0]

    for d in defs:
        if d.get("path") == icall_location:
            return d

    icall_dir = icall_location.rsplit("/", 1)[0] if "/" in icall_location else ""
    if icall_dir:
        for d in defs:
            if str(d.get("path", "")).startswith(icall_dir + "/"):
                return d

    return defs[0]


def index_symbol(state: ResolverState) -> ResolverState:
    symbol = state["current_symbol"]

    ident = bootlin_ident(
        project=state["project"],
        version=state["version"],
        family=state["family"],
        symbol=symbol,
        project_root=state["project_root"],
    )

    defs = ident.get("definitions", [])
    refs = ident.get("references", [])

    if not defs:
        return {
            "status": "failed",
            "final_answer": f"definition not found for symbol={symbol}",
            "observations": [f"Bootlin ident lookup failed for {symbol}"],
        }

    d = select_definition(defs, state.get("icall_location"))
    return {
        "current_path": d["path"],
        "current_line": int(d["line"]),
        "current_kind": d["type"],
        "bootlin_references": refs,
        "observations": [
            f"{symbol} defined at {d['path']}:{d['line']} ({d['type']})",
            f"bootlin references: {len(refs)}",
        ],
    }


def retrieve_block(state: ResolverState) -> ResolverState:
    if state.get("hop_count", 0) > state.get("max_hops", 6):
        return {
            "status": "failed",
            "final_answer": "max hops exceeded",
            "observations": ["stopped because max_hops was exceeded"],
        }

    if state["current_kind"] not in {
        "function",
        "prototype",
        "unknown",
        "macro",
        "variable",
        "struct",
        "typedef",
        "member",
        "externvar",
    }:
        return {
            "status": "failed",
            "final_answer": f"unsupported kind for current retriever: {state['current_kind']}",
            "observations": [
                f"retriever does not support current kind: {state['current_kind']}"
            ],
        }

    try:
        bundle = get_context_bundle(
            project_root=state["project_root"],
            relative_path=state["current_path"],
            symbol=state["current_symbol"],
            line_1_based=state["current_line"],
            icall_expr=state["icall_expr"],
            ident_kind=state["current_kind"],
        )
    except Exception as e:
        return {
            "status": "failed",
            "final_answer": f"retrieval failed for {state['current_symbol']}: {e}",
            "observations": [f"retrieval error: {e}"],
        }

    chunks = [bundle["primary_block"]]

    for x in bundle["macro_definitions"]:
        chunks.append(f"[macro] {x['path']}:{x['line']}\n{x['text']}")
    for x in bundle["struct_definitions"]:
        chunks.append(f"[struct] {x['path']}:{x['line']}\n{x['text']}")
    for x in bundle["local_assignments"]:
        chunks.append(f"[assignment] {x['path']}:{x['line']}\n{x['text']}")
    for x in bundle["initializer_definitions"]:
        chunks.append(f"[initializer] {x['path']}:{x['line']}\n{x['text']}")

    observations = [
        f"retrieved {bundle['primary_block_kind']} for {state['current_symbol']} ({state['current_kind']})"
    ]
    if bundle["macro_definitions"]:
        observations.append(f"found {len(bundle['macro_definitions'])} related macro definitions")
    if bundle["struct_definitions"]:
        observations.append(f"found {len(bundle['struct_definitions'])} related struct definitions")
    if bundle["local_assignments"]:
        observations.append(f"found {len(bundle['local_assignments'])} related local assignments")
    if bundle["initializer_definitions"]:
        observations.append(f"found {len(bundle['initializer_definitions'])} related initializer snippets")

    return {
        "current_block": "\n\n".join(chunks),
        "current_block_kind": "context_bundle",
        "retrieved_chunks": chunks,
        "macro_context": [x["text"] for x in bundle["macro_definitions"]],
        "struct_context": [x["text"] for x in bundle["struct_definitions"]],
        "assignment_context": [x["text"] for x in bundle["local_assignments"]],
        "initializer_context": [x["text"] for x in bundle["initializer_definitions"]],
        "observations": observations,
        "status": "running",
    }


def expand_reference_candidates(state: ResolverState) -> ResolverState:
    refs = state.get("bootlin_references", [])
    if not refs:
        return {
            "reference_jump_candidates": [],
            "observations": ["no bootlin references to expand"],
        }

    try:
        candidates = get_reference_jump_candidates(
            project_root=state["project_root"],
            references=refs,
        )
    except Exception as e:
        return {
            "reference_jump_candidates": [],
            "observations": [f"reference expansion failed: {e}"],
        }

    obs = [f"expanded {len(candidates)} reference-based jump candidates"]
    for c in candidates:
        obs.append(
            f"reference candidate: {c['symbol']} at {c['path']}:{c['line']} "
            f"(from ref line {c['ref_line']})"
        )

    return {
        "reference_jump_candidates": candidates,
        "observations": obs,
    }


def analyze_with_llm(state: ResolverState) -> ResolverState:
    bundle = llm_analyze_step(state)
    result = bundle["llm_output"]

    iteration = state.get("iteration", 0) + 1
    icall_targets = list(dict.fromkeys(result["candidate_callees"]))
    icall_resolved = bool(icall_targets)
    icall_resolution_reason = summarize_icall_resolution(
        icall_targets,
        result["analysis_summary"],
    )
    icall_resolution_status = classify_icall_resolution(
        icall_targets,
        result["analysis_summary"],
    )
    jump_kind, grounded_sources = classify_jump_kind(state, result.get("next_symbol"))
    selected_from_reference_candidates = result.get("next_symbol") in {
        c.get("symbol") for c in state.get("reference_jump_candidates", []) if c.get("symbol")
    }

    trace_item = {
        "iteration": iteration,
        "step": state.get("hop_count", 0),
        "focus_symbol": state.get("current_symbol"),
        "decision": result["decision"],
        "next_symbol": result["next_symbol"],
        "summary": result["analysis_summary"],
        "evidence": result["evidence"],
        "candidate_callees": result["candidate_callees"],
        "resolved": result["resolved"],
        "jump_kind": jump_kind,
        "grounded_sources": grounded_sources,
        "selected_from_reference_candidates": selected_from_reference_candidates,
    }

    save_step_artifacts(
        output_dir=state["output_dir"],
        iteration=iteration,
        prompt_payload=bundle["prompt_payload"],
        prompt_text=bundle["prompt_text"],
        response_payload={
            "iteration": iteration,
            "model": bundle["model"],
            "icall_resolved": icall_resolved,
            "icall_resolution_status": icall_resolution_status,
            "icall_resolution_reason": icall_resolution_reason,
            "icall_targets": icall_targets,
            "llm_output": result,
            "jump_kind": jump_kind,
            "grounded_sources": grounded_sources,
            "selected_from_reference_candidates": selected_from_reference_candidates,
            "state_snapshot": {
                "current_symbol": state.get("current_symbol"),
                "caller_symbol": state.get("caller_symbol"),
                "icall_expr": state.get("icall_expr"),
                "current_path": state.get("current_path"),
                "current_line": state.get("current_line"),
                "current_kind": state.get("current_kind"),
                "hop_count": state.get("hop_count", 0),
                "visited_symbols": state.get("visited_symbols", []),
                "reference_jump_candidates": state.get("reference_jump_candidates", []),
            },
        },
    )

    return {
        "iteration": iteration,
        "decision": result["decision"],
        "decision_reason": result["analysis_summary"],
        "next_symbol": result["next_symbol"],
        "candidate_callees": result["candidate_callees"],
        "icall_resolution_status": icall_resolution_status,
        "icall_resolved": icall_resolved,
        "icall_resolution_reason": icall_resolution_reason,
        "icall_targets": icall_targets,
        "observations": result["evidence"],
        "visible_trace": [trace_item],
        "status": "resolved" if result["decision"] == "finish" else "running",
    }


def jump_symbol(state: ResolverState) -> ResolverState:
    next_sym = state.get("next_symbol")

    if not next_sym:
        return {
            "status": "failed",
            "final_answer": "LLM did not provide next_symbol",
            "observations": ["jump requested but next_symbol was empty"],
        }

    visited = state.get("visited_symbols", [])
    if next_sym in visited:
        return {
            "status": "resolved",
            "decision": "finish",
            "decision_reason": (
                f"Loop detected at {next_sym}. The resolver reached a previously "
                "visited symbol without new value-flow evidence, so this path is "
                "classified as unresolved instead of failed."
            ),
            "next_symbol": None,
            "observations": [f"stopped before revisiting already visited symbol {next_sym}"],
        }

    if state.get("hop_count", 0) >= state.get("max_hops", 6):
        return {
            "status": "failed",
            "final_answer": "max hops exceeded",
            "observations": ["stopped before jump because max_hops was reached"],
        }

    return {
        "current_symbol": next_sym,
        "visited_symbols": [next_sym],
        "hop_count": state.get("hop_count", 0) + 1,
        "observations": [f"jumping to next symbol: {next_sym}"],
        "status": "running",
    }


def finish(state: ResolverState) -> ResolverState:
    visited = state.get("visited_symbols", [])
    traces = state.get("visible_trace", [])
    candidates = list(dict.fromkeys(state.get("candidate_callees", [])))
    icall_resolved = bool(candidates)
    icall_resolution_reason = summarize_icall_resolution(
        candidates,
        state.get("decision_reason", ""),
    )
    icall_resolution_status = classify_icall_resolution(
        candidates,
        state.get("decision_reason", ""),
    )

    lines = []
    lines.append(f"ICall expression: {state.get('icall_expr', '')}")
    lines.append(f"Caller symbol: {state.get('caller_symbol', '')}")
    lines.append(f"ICall resolution status: {icall_resolution_status}")
    lines.append(f"ICall resolved: {icall_resolved}")
    lines.append(f"ICall resolution reason: {icall_resolution_reason}")
    lines.append(f"Iterations: {state.get('iteration', 0)}")
    lines.append(f"Visited path: {' -> '.join(visited)}")

    if candidates:
        lines.append("Candidate callees:")
        for cand in candidates:
            lines.append(f"- {cand}")
    else:
        lines.append("Candidate callees: none")

    lines.append("")
    lines.append("Trace:")
    for item in traces:
        lines.append(
            f"- iteration={item['iteration']} step={item['step']} "
            f"symbol={item['focus_symbol']} decision={item['decision']} "
            f"next={item['next_symbol']} jump_kind={item.get('jump_kind')}"
        )
        lines.append(f"  summary: {item['summary']}")
        if item.get("grounded_sources"):
            lines.append(f"  grounded_sources: {item['grounded_sources']}")
        if item.get("evidence"):
            for ev in item["evidence"]:
                lines.append(f"  evidence: {ev}")

    return {
        "status": "resolved",
        "icall_resolution_status": icall_resolution_status,
        "icall_resolved": icall_resolved,
        "icall_resolution_reason": icall_resolution_reason,
        "icall_targets": candidates,
        "final_answer": "\n".join(lines),
    }


def fail(state: ResolverState) -> ResolverState:
    traces = state.get("visible_trace", [])
    lines = []
    lines.append("Resolver failed.")
    lines.append(f"Reason: {state.get('final_answer', 'unknown failure')}")
    lines.append(f"Iterations: {state.get('iteration', 0)}")
    lines.append(f"Visited path: {' -> '.join(state.get('visited_symbols', []))}")
    if traces:
        lines.append("")
        lines.append("Trace:")
        for item in traces:
            lines.append(
                f"- iteration={item['iteration']} step={item['step']} "
                f"symbol={item['focus_symbol']} decision={item['decision']} "
                f"next={item['next_symbol']} jump_kind={item.get('jump_kind')}"
            )
            lines.append(f"  summary: {item['summary']}")
    return {
        "status": "failed",
        "icall_resolution_status": "failed",
        "icall_resolved": False,
        "icall_resolution_reason": state.get("final_answer", "resolver failed"),
        "icall_targets": [],
        "final_answer": "\n".join(lines),
    }


def route_after_retrieve(state: ResolverState):
    if state.get("status") == "failed":
        return "fail"
    return "expand_reference_candidates"


def route_after_llm(state: ResolverState):
    decision = state.get("decision")

    if decision == "finish":
        return "finish"
    if decision == "jump":
        return "jump_symbol"
    return "fail"


def route_after_jump(state: ResolverState):
    if state.get("status") == "failed":
        return "fail"
    if state.get("status") == "resolved":
        return "finish"
    return "index_symbol"


def build_graph():
    if StateGraph is None:
        raise RuntimeError("langgraph package is required for build_graph")

    graph = StateGraph(ResolverState)

    graph.add_node("index_symbol", index_symbol)
    graph.add_node("retrieve_block", retrieve_block)
    graph.add_node("expand_reference_candidates", expand_reference_candidates)
    graph.add_node("analyze_with_llm", analyze_with_llm)
    graph.add_node("jump_symbol", jump_symbol)
    graph.add_node("finish", finish)
    graph.add_node("fail", fail)

    graph.add_edge(START, "index_symbol")
    graph.add_edge("index_symbol", "retrieve_block")

    graph.add_conditional_edges(
        "retrieve_block",
        route_after_retrieve,
        {
            "expand_reference_candidates": "expand_reference_candidates",
            "fail": "fail",
        },
    )

    graph.add_edge("expand_reference_candidates", "analyze_with_llm")

    graph.add_conditional_edges(
        "analyze_with_llm",
        route_after_llm,
        {
            "finish": "finish",
            "jump_symbol": "jump_symbol",
            "fail": "fail",
        },
    )

    graph.add_conditional_edges(
        "jump_symbol",
        route_after_jump,
        {
            "index_symbol": "index_symbol",
            "finish": "finish",
            "fail": "fail",
        },
    )

    graph.add_edge("finish", END)
    graph.add_edge("fail", END)

    return graph.compile()
