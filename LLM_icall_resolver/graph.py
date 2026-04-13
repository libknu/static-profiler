from langgraph.graph import StateGraph, START, END

from .state import ResolverState
from .bootlin import bootlin_ident
from .treesitter_retriever import get_context_bundle
from .analyzer import llm_analyze_step


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
    if not defs:
        return {
            "status": "failed",
            "final_answer": f"definition not found for symbol={symbol}",
            "observations": [f"Bootlin ident lookup failed for {symbol}"],
        }

    d = defs[0]
    return {
        "current_path": d["path"],
        "current_line": int(d["line"]),
        "current_kind": d["type"],
        "observations": [f"{symbol} defined at {d['path']}:{d['line']} ({d['type']})"],
    }

def retrieve_block(state: ResolverState) -> ResolverState:
    if state.get("hop_count", 0) > state.get("max_hops", 6):
        return {
            "status": "failed",
            "final_answer": "max hops exceeded",
            "observations": ["stopped because max_hops was exceeded"],
        }

    if state["current_kind"] not in {"function", "unknown"}:
        return {
            "status": "failed",
            "final_answer": f"unsupported kind for current retriever: {state['current_kind']}",
            "observations": [
                f"retriever currently supports only function, got {state['current_kind']}"
            ],
        }

    try:
        bundle = get_context_bundle(
            project_root=state["project_root"],
            relative_path=state["current_path"],
            symbol=state["current_symbol"],
            line_1_based=state["current_line"],
            icall_expr=state["icall_expr"],
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

    observations = [
        f"retrieved {bundle['primary_block_kind']} for {state['current_symbol']} ({state['current_kind']})"
    ]
    if bundle["macro_definitions"]:
        observations.append(f"found {len(bundle['macro_definitions'])} related macro definitions")
    if bundle["struct_definitions"]:
        observations.append(f"found {len(bundle['struct_definitions'])} related struct definitions")
    if bundle["local_assignments"]:
        observations.append(f"found {len(bundle['local_assignments'])} related local assignments")

    return {
        "current_block": "\n\n".join(chunks),
        "current_block_kind": "context_bundle",
        "retrieved_chunks": chunks,
        "macro_context": [x["text"] for x in bundle["macro_definitions"]],
        "struct_context": [x["text"] for x in bundle["struct_definitions"]],
        "assignment_context": [x["text"] for x in bundle["local_assignments"]],
        "observations": observations,
        "status": "running",
    }


def analyze_with_llm(state: ResolverState) -> ResolverState:
    result = llm_analyze_step(state)

    trace_item = {
        "step": state.get("hop_count", 0),
        "focus_symbol": state.get("current_symbol"),
        "decision": result["decision"],
        "next_symbol": result["next_symbol"],
        "summary": result["analysis_summary"],
        "evidence": result["evidence"],
        "candidate_callees": result["candidate_callees"],
        "resolved": result["resolved"],
    }

    return {
        "decision": result["decision"],
        "decision_reason": result["analysis_summary"],
        "next_symbol": result["next_symbol"],
        "candidate_callees": result["candidate_callees"],
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
            "status": "failed",
            "final_answer": f"loop detected: {next_sym}",
            "observations": [f"refusing to revisit already visited symbol {next_sym}"],
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
    candidates = state.get("candidate_callees", [])

    lines = []
    lines.append(f"ICall expression: {state.get('icall_expr', '')}")
    lines.append(f"Caller symbol: {state.get('caller_symbol', '')}")
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
            f"- step={item['step']} symbol={item['focus_symbol']} "
            f"decision={item['decision']} next={item['next_symbol']}"
        )
        lines.append(f"  summary: {item['summary']}")
        if item.get("evidence"):
            for ev in item["evidence"]:
                lines.append(f"  evidence: {ev}")

    return {
        "status": "resolved",
        "final_answer": "\n".join(lines),
    }


def fail(state: ResolverState) -> ResolverState:
    traces = state.get("visible_trace", [])
    lines = []
    lines.append(f"Resolver failed.")
    lines.append(f"Reason: {state.get('final_answer', 'unknown failure')}")
    lines.append(f"Visited path: {' -> '.join(state.get('visited_symbols', []))}")
    if traces:
        lines.append("")
        lines.append("Trace:")
        for item in traces:
            lines.append(
                f"- step={item['step']} symbol={item['focus_symbol']} "
                f"decision={item['decision']} next={item['next_symbol']}"
            )
            lines.append(f"  summary: {item['summary']}")
    return {
        "status": "failed",
        "final_answer": "\n".join(lines),
    }


def route_after_retrieve(state: ResolverState):
    if state.get("status") == "failed":
        return "fail"
    return "analyze_with_llm"


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
    return "index_symbol"


def build_graph():
    graph = StateGraph(ResolverState)

    graph.add_node("index_symbol", index_symbol)
    graph.add_node("retrieve_block", retrieve_block)
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
            "analyze_with_llm": "analyze_with_llm",
            "fail": "fail",
        },
    )

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
            "fail": "fail",
        },
    )

    graph.add_edge("finish", END)
    graph.add_edge("fail", END)

    return graph.compile()
