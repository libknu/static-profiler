from langgraph.graph import StateGraph, START, END

from .state import ResolverState
from .bootlin import bootlin_ident
from .treesitter_retriever import get_function_source
from .analyzer import static_analyze_block


def index_symbol(state: ResolverState) -> ResolverState:
    symbol = state["current_symbol"]

    ident = bootlin_ident(
        project=state["project"],
        version=state["version"],
        family=state["family"],
        symbol=symbol,
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
    if state["current_kind"] != "function":
        return {
            "status": "failed",
            "final_answer": f"unsupported kind for initial version: {state['current_kind']}",
            "observations": [f"retriever currently supports only function, got {state['current_kind']}"],
        }

    block_text, block_kind = get_function_source(
        project_root=state["project_root"],
        relative_path=state["current_path"],
        symbol=state["current_symbol"],
        line_1_based=state["current_line"],
    )

    return {
        "current_block": block_text,
        "current_block_kind": block_kind,
        "retrieved_chunks": [block_text],
        "observations": [f"retrieved {block_kind} for {state['current_symbol']}"],
    }


def analyze_block(state: ResolverState) -> ResolverState:
    result = static_analyze_block(
        symbol=state["current_symbol"],
        ident_kind=state["current_kind"],
        code=state["current_block"],
    )
    return {
        "next_symbols": result.next_symbols,
        "candidate_callees": result.candidate_callees,
        "observations": result.observations,
        "status": result.status,
    }


def finish(state: ResolverState) -> ResolverState:
    return {
        "status": "resolved",
        "final_answer": state.get("current_block", ""),
    }


def fail(state: ResolverState) -> ResolverState:
    return {
        "status": "failed",
        "final_answer": state.get("final_answer", "resolution failed"),
    }


def route_after_analysis(state: ResolverState):
    if state["status"] == "resolved":
        return "finish"
    return "fail"


def build_graph():
    graph = StateGraph(ResolverState)

    graph.add_node("index_symbol", index_symbol)
    graph.add_node("retrieve_block", retrieve_block)
    graph.add_node("analyze_block", analyze_block)
    graph.add_node("finish", finish)
    graph.add_node("fail", fail)

    graph.add_edge(START, "index_symbol")
    graph.add_edge("index_symbol", "retrieve_block")
    graph.add_edge("retrieve_block", "analyze_block")

    graph.add_conditional_edges(
        "analyze_block",
        route_after_analysis,
        {
            "finish": "finish",
            "fail": "fail",
        },
    )

    graph.add_edge("finish", END)
    graph.add_edge("fail", END)

    return graph.compile()
