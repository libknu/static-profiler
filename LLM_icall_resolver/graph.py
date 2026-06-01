import re
from pathlib import Path
import subprocess

try:
    from langgraph.graph import StateGraph, START, END
except ModuleNotFoundError:
    StateGraph = None
    START = END = None

from .state import ResolverState
from .bootlin import bootlin_ident
from .treesitter_retriever import (
    get_enclosing_function_info,
    get_context_bundle,
    get_reference_jump_candidates,
    get_provider_context_bundle,
)
from .analyzer import llm_analyze_step
from .trace_store import save_step_artifacts
from .deterministic import classify_deterministically, prepare_callsite_inputs


IDENT_PAT = re.compile(r"\b[A-Za-z_]\w*\b")


def _extract_symbols(text: str) -> set[str]:
    return set(IDENT_PAT.findall(text or ""))


def _extract_symbols_from_context_list(items: list[str]) -> set[str]:
    out = set()
    for item in items or []:
        out.update(_extract_symbols(item))
    return out


def find_local_symbol_references(
    project_root: str,
    symbol: str,
    definition_path: str | None = None,
    definition_line: int | None = None,
    max_results: int = 20,
) -> list[dict]:
    root = Path(project_root)
    if not root.is_dir():
        return []

    refs = []
    pat = re.compile(rf"\b{re.escape(symbol)}\b")
    exts = {".c", ".h", ".cc", ".hh", ".hpp"}

    def scan_file(path: Path) -> bool:
        rel = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return False

        for line_no, line in enumerate(lines, start=1):
            if rel == definition_path and definition_line and abs(line_no - definition_line) <= 1:
                continue
            if not pat.search(line):
                continue
            refs.append({"path": rel, "line": str(line_no), "type": "local_reference"})
            if len(refs) >= max_results:
                return True
        return False

    if definition_path:
        primary = root / definition_path
        if primary.is_file():
            scan_file(primary)
            if refs:
                return refs

    try:
        proc = subprocess.run(
            [
                "rg",
                "--line-number",
                "--no-heading",
                "--glob",
                "*.{c,h,cc,hh,hpp}",
                rf"\b{re.escape(symbol)}\b",
                str(root),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=20,
        )
    except Exception:
        return refs

    for raw in proc.stdout.splitlines():
        parts = raw.split(":", 2)
        if len(parts) < 2:
            continue
        path_text, line_text = parts[:2]
        try:
            path = Path(path_text)
            line_no = int(line_text)
            rel = path.relative_to(root).as_posix()
        except Exception:
            continue
        if rel == definition_path and definition_line and abs(line_no - definition_line) <= 1:
            continue
        refs.append({"path": rel, "line": str(line_no), "type": "local_reference"})
        if len(refs) >= max_results:
            return refs
    return refs


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


FIELD_PROVIDER_PAT = re.compile(
    r"(::|->|\.|@|:[0-9]+|__gconv_step|SVCXPRT|xp_ops|cl_ops|ah_ops|x_ops)"
)


def looks_like_provider_symbol(symbol: str | None) -> bool:
    if not symbol:
        return False
    return bool(FIELD_PROVIDER_PAT.search(symbol))


def summarize_icall_resolution(
    candidates: list[str],
    decision_reason: str,
    explicit_status: str | None = None,
) -> str:
    if candidates:
        return f"Resolved indirect-call target(s): {', '.join(candidates)}"

    if explicit_status == "not_icall":
        return "The analyzed expression is not an indirect call."
    if explicit_status == "unresolved":
        if decision_reason:
            return decision_reason
        return "No candidate callees were identified."

    reason = (decision_reason or "").lower()
    if "not an indirect call" in reason or "not a call" in reason:
        return "The analyzed expression is not an indirect call."
    return "No candidate callees were identified."


def classify_icall_resolution(
    candidates: list[str],
    decision_reason: str,
    explicit_status: str | None = None,
) -> str:
    if candidates:
        return "resolved"

    if explicit_status in {"unresolved", "not_icall"}:
        return explicit_status

    reason = (decision_reason or "").lower()
    if "not an indirect call" in reason or "not a call" in reason:
        return "not_icall"
    return "unresolved"


def normalize_llm_output(result: dict) -> dict:
    result = dict(result)
    result.setdefault("candidate_callees", [])
    result.setdefault("analysis_summary", "")
    result.setdefault("evidence", [])
    result.setdefault("resolved", bool(result["candidate_callees"]))

    if result.get("candidate_callees"):
        result["resolution_status"] = "resolved"
    elif result.get("resolution_status") not in {"resolved", "unresolved", "not_icall"}:
        result["resolution_status"] = classify_icall_resolution(
            result["candidate_callees"],
            result.get("analysis_summary", ""),
        )

    if result.get("decision") == "fail":
        result["decision"] = "finish"
        result["next_symbol"] = None
        result["resolved"] = False
        result["candidate_callees"] = []
        result["resolution_status"] = "unresolved"
    return result


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


def preclassify_icall(state: ResolverState) -> ResolverState:
    updates = prepare_callsite_inputs(state)
    normalized_state = dict(state)
    normalized_state.update({k: v for k, v in updates.items() if k != "observations"})

    result = classify_deterministically(normalized_state)
    if result is None:
        if updates:
            updates.setdefault("status", "running")
            return updates
        return {"status": "running"}

    iteration = state.get("iteration", 0) + 1
    candidates = list(dict.fromkeys(result.get("candidate_callees", [])))
    resolution_status = result.get("resolution_status", "unresolved")
    resolved = resolution_status == "resolved" and bool(candidates)
    reason = summarize_icall_resolution(
        candidates,
        result.get("analysis_summary", ""),
        resolution_status,
    )

    evidence = result.get("evidence", [])
    observations = list(updates.get("observations", []))
    observations.extend(evidence)
    trace_item = {
        "iteration": iteration,
        "step": state.get("hop_count", 0),
        "focus_symbol": state.get("current_symbol"),
        "decision": "finish",
        "next_symbol": None,
        "summary": result.get("analysis_summary", ""),
        "evidence": evidence,
        "candidate_callees": candidates,
        "resolved": resolved,
        "jump_kind": "deterministic",
        "grounded_sources": ["preclassify_icall"],
        "selected_from_reference_candidates": False,
    }

    return {
        **{k: v for k, v in updates.items() if k != "observations"},
        "iteration": iteration,
        "decision": "finish",
        "decision_reason": result.get("analysis_summary", ""),
        "next_symbol": None,
        "candidate_callees": candidates,
        "icall_resolution_status": resolution_status,
        "icall_resolved": resolved,
        "icall_resolution_reason": reason,
        "icall_targets": candidates if resolved else [],
        "observations": observations,
        "visible_trace": [trace_item],
        "status": "resolved",
    }


def index_symbol(state: ResolverState) -> ResolverState:
    symbol = state["current_symbol"]

    if looks_like_provider_symbol(symbol):
        bundle = get_provider_context_bundle(
            project_root=state["project_root"],
            symbol=symbol,
            icall_location=state.get("icall_location"),
            icall_line=state.get("icall_line"),
        )
        chunks = [bundle["primary_block"]]
        return {
            "current_path": state.get("icall_location", ""),
            "current_line": state.get("icall_line") or 1,
            "current_kind": "provider_context",
            "current_block": bundle["primary_block"],
            "current_block_kind": bundle["primary_block_kind"],
            "retrieved_chunks": chunks,
            "bootlin_references": [],
            "observations": [
                f"using provider-context fallback for non-Bootlin symbol {symbol}",
                f"provider snippets: {len(bundle.get('provider_contexts', []))}",
            ],
            "status": "running",
        }

    if state.get("hop_count", 0) == 0 and state.get("icall_location") and state.get("icall_line"):
        callsite_def = get_enclosing_function_info(
            project_root=state["project_root"],
            relative_path=state["icall_location"],
            line_1_based=int(state["icall_line"]),
        )
        if callsite_def is not None:
            callsite_symbol = callsite_def["symbol"]
            ident = bootlin_ident(
                project=state["project"],
                version=state["version"],
                family=state["family"],
                symbol=callsite_symbol,
                project_root=state["project_root"],
            )
            refs = ident.get("references", [])
            ref_source = "bootlin"
            if not refs:
                refs = find_local_symbol_references(
                    project_root=state["project_root"],
                    symbol=callsite_symbol,
                    definition_path=callsite_def["path"],
                    definition_line=int(callsite_def["line"]),
                )
                ref_source = "local"
            observations = [
                (
                    "selected original callsite enclosing function "
                    f"{callsite_symbol} at {callsite_def['path']}:{callsite_def['line']}"
                ),
                f"{ref_source} references: {len(refs)}",
            ]
            if callsite_symbol != symbol:
                observations.append(
                    f"caller_symbol {symbol} differs from callsite enclosing function {callsite_symbol}"
                )
            return {
                "current_symbol": callsite_symbol,
                "current_path": callsite_def["path"],
                "current_line": int(callsite_def["line"]),
                "current_kind": callsite_def["type"],
                "visited_symbols": [callsite_symbol] if callsite_symbol != symbol else [],
                "bootlin_references": refs,
                "observations": observations,
            }

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
        bundle = get_provider_context_bundle(
            project_root=state["project_root"],
            symbol=symbol,
            icall_location=state.get("icall_location"),
            icall_line=state.get("icall_line"),
        )
        return {
            "current_path": state.get("icall_location", ""),
            "current_line": state.get("icall_line") or 1,
            "current_kind": "provider_context",
            "current_block": bundle["primary_block"],
            "current_block_kind": bundle["primary_block_kind"],
            "retrieved_chunks": [bundle["primary_block"]],
            "bootlin_references": [],
            "observations": [
                f"Bootlin ident lookup failed for {symbol}; using provider-context fallback",
                f"provider snippets: {len(bundle.get('provider_contexts', []))}",
            ],
            "status": "running",
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
            "status": "resolved",
            "decision": "finish",
            "decision_reason": "max hops exceeded before retrieval; unresolved",
            "icall_resolution_status": "unresolved",
            "icall_resolved": False,
            "icall_resolution_reason": "Analysis ended without a confident static resolution.",
            "candidate_callees": [],
            "icall_targets": [],
            "observations": ["stopped because max_hops was exceeded"],
        }

    if state.get("current_kind") == "provider_context":
        return {
            "current_block": state.get("current_block", ""),
            "current_block_kind": "provider_context",
            "retrieved_chunks": [state.get("current_block", "")],
            "observations": ["provider-context block already prepared"],
            "status": "running",
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
            icall_location=state.get("icall_location"),
            icall_line=state.get("icall_line"),
        )
    except Exception as e:
        return {
            "status": "failed",
            "final_answer": f"retrieval failed for {state['current_symbol']}: {e}",
            "observations": [f"retrieval error: {e}"],
        }

    chunks = [bundle["primary_block"]]
    if bundle.get("callsite_context"):
        chunks.insert(0, bundle["callsite_context"])

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
    if bundle.get("callsite_context"):
        observations.append(
            f"included original callsite context from {state.get('icall_location')}:{state.get('icall_line')}"
        )

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
    if state.get("iteration", 0) >= state.get("max_iterations", 10):
        return {
            "status": "resolved",
            "decision": "finish",
            "decision_reason": (
                f"max iterations exceeded: iteration={state.get('iteration', 0)} "
                f"max_iterations={state.get('max_iterations', 10)}; unresolved"
            ),
            "icall_resolution_status": "unresolved",
            "icall_resolved": False,
            "icall_resolution_reason": "Analysis ended without a confident static resolution.",
            "candidate_callees": [],
            "icall_targets": [],
            "observations": ["stopped before LLM call because max_iterations was reached"],
        }

    bundle = llm_analyze_step(state)
    result = normalize_llm_output(bundle["llm_output"])

    iteration = state.get("iteration", 0) + 1
    icall_targets = list(dict.fromkeys(result["candidate_callees"]))
    icall_resolved = bool(icall_targets)
    explicit_status = result.get("resolution_status")
    icall_resolution_reason = summarize_icall_resolution(
        icall_targets,
        result["analysis_summary"],
        explicit_status,
    )
    icall_resolution_status = classify_icall_resolution(
        icall_targets,
        result["analysis_summary"],
        explicit_status,
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
            "provider": bundle["provider"],
            "model": bundle["model"],
            "system_prompt": bundle.get("system_prompt"),
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
                "icall_location": state.get("icall_location"),
                "icall_line": state.get("icall_line"),
                "current_path": state.get("current_path"),
                "current_line": state.get("current_line"),
                "current_kind": state.get("current_kind"),
                "hop_count": state.get("hop_count", 0),
                "max_iterations": state.get("max_iterations", 10),
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
            "status": "resolved",
            "decision": "finish",
            "decision_reason": "LLM did not provide next_symbol; unresolved",
            "icall_resolution_status": "unresolved",
            "icall_resolved": False,
            "icall_resolution_reason": "Analysis ended without a confident static resolution.",
            "candidate_callees": [],
            "icall_targets": [],
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
                "classified as unresolved."
            ),
            "next_symbol": None,
            "icall_resolution_status": "unresolved",
            "icall_resolved": False,
            "icall_resolution_reason": "Analysis ended without a confident static resolution.",
            "candidate_callees": [],
            "icall_targets": [],
            "observations": [f"stopped before revisiting already visited symbol {next_sym}"],
        }

    if state.get("hop_count", 0) >= state.get("max_hops", 6):
        return {
            "status": "resolved",
            "decision": "finish",
            "decision_reason": "max hops exceeded; unresolved",
            "icall_resolution_status": "unresolved",
            "icall_resolved": False,
            "icall_resolution_reason": "Analysis ended without a confident static resolution.",
            "candidate_callees": [],
            "icall_targets": [],
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
    explicit_status = state.get("icall_resolution_status")
    if explicit_status in {"unresolved", "not_icall", "failed"}:
        candidates = []
    else:
        candidates = list(dict.fromkeys(state.get("candidate_callees", [])))
    icall_resolved = bool(candidates)
    icall_resolution_reason = summarize_icall_resolution(
        candidates,
        state.get("decision_reason", ""),
        state.get("icall_resolution_status"),
    )
    icall_resolution_status = classify_icall_resolution(
        candidates,
        state.get("decision_reason", ""),
        state.get("icall_resolution_status"),
    )

    lines = []
    lines.append(f"ICall expression: {state.get('icall_expr', '')}")
    lines.append(f"ICall location: {state.get('icall_location', '')}:{state.get('icall_line', '')}")
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
    if state.get("status") == "resolved":
        return "finish"
    return "expand_reference_candidates"


def route_after_preclassify(state: ResolverState):
    if state.get("status") == "resolved":
        return "finish"
    if state.get("status") == "failed":
        return "fail"
    return "index_symbol"


def route_after_llm(state: ResolverState):
    decision = state.get("decision")

    if decision == "finish":
        return "finish"
    if decision == "jump":
        return "jump_symbol"
    return "finish"


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

    graph.add_node("preclassify_icall", preclassify_icall)
    graph.add_node("index_symbol", index_symbol)
    graph.add_node("retrieve_block", retrieve_block)
    graph.add_node("expand_reference_candidates", expand_reference_candidates)
    graph.add_node("analyze_with_llm", analyze_with_llm)
    graph.add_node("jump_symbol", jump_symbol)
    graph.add_node("finish", finish)
    graph.add_node("fail", fail)

    graph.add_edge(START, "preclassify_icall")
    graph.add_conditional_edges(
        "preclassify_icall",
        route_after_preclassify,
        {
            "index_symbol": "index_symbol",
            "finish": "finish",
            "fail": "fail",
        },
    )
    graph.add_edge("index_symbol", "retrieve_block")

    graph.add_conditional_edges(
        "retrieve_block",
        route_after_retrieve,
        {
            "expand_reference_candidates": "expand_reference_candidates",
            "finish": "finish",
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
