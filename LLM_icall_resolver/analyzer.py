import os
import json
import requests
try:
    from openai import OpenAI
except ModuleNotFoundError:
    OpenAI = None

DEFAULT_MODEL_NAME = "gpt-5.4"
DEFAULT_PROVIDER = "openai"
ANTHROPIC_API_VERSION = "2023-06-01"
MODEL_NAME = DEFAULT_MODEL_NAME

JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "decision": {
            "type": "string",
            "enum": ["jump", "finish"]
        },
        "resolution_status": {
            "type": "string",
            "enum": ["resolved", "unresolved", "not_icall", "inconclusive"]
        },
        "next_symbol": {
            "type": ["string", "null"]
        },
        "candidate_callees": {
            "type": "array",
            "items": {"type": "string"}
        },
        "analysis_summary": {"type": "string"},
        "evidence": {
            "type": "array",
            "items": {"type": "string"}
        },
        "resolved": {"type": "boolean"}
    },
    "required": [
        "decision",
        "next_symbol",
        "candidate_callees",
        "resolution_status",
        "analysis_summary",
        "evidence",
        "resolved"
    ],
    "additionalProperties": False
}


SYSTEM_PROMPT = """You are an expert in C static analysis and indirect call resolution.

Given:
- a caller function
- an indirect call site
- current code context
- possibly related macro definitions
- possibly related struct/field definitions
- possibly related local assignments
- possibly related initializer snippets
- reference-derived jump candidates

Your job:
1. Decide whether the indirect target is resolved
2. If not, decide which symbol to analyze next

Rules:
- A call written as foo(...) may still be indirect if foo is a macro wrapper.
- Prefer value-flow relevant symbols, struct field providers, ops tables, wrapper-returning helpers, and initializer sources.
- Do NOT hallucinate arbitrary symbols.
- If unsure, continue with jump.
- Use resolution_status="unresolved" only when the target is inherently not
  statically decidable from source context, such as runtime-loaded providers,
  user callbacks, configured dispatch tables, or dynamic loader/audit hooks.
- If this is a real indirect call but the available evidence is insufficient,
  there is no grounded next symbol, or analysis cannot confidently continue,
  finish with resolution_status="inconclusive", candidate_callees=[],
  resolved=false.
- If the reported site is not an indirect call, finish with
  resolution_status="not_icall", candidate_callees=[], resolved=false.
- The decision field has only two valid values: "jump" and "finish".
- Do not report ordinary unresolved static-analysis results as failures.

Output MUST be valid JSON following the schema.
"""


ANTHROPIC_SYSTEM_PROMPT = SYSTEM_PROMPT + """

Claude-specific decision policy:
- Be exploration-oriented before declaring unresolved.
- If reference-derived jump candidates are provided and the current context does
  not directly resolve the callee, choose decision="jump" to the most relevant
  grounded function-level candidate.
- If the current context shows a function-pointer field, typedef, macro wrapper,
  ops table, or callback slot but no concrete assignment, do not finish as
  unresolved until you have followed at least one grounded setup/caller/provider
  candidate when one is available.
- Do not use a typedef, struct name, field name, or function-pointer type as a
  candidate callee. candidate_callees must be concrete callable function symbols.
- Finish with resolution_status="unresolved" only when no grounded next_symbol is
  available or when the evidence shows the target is inherently runtime-selected.
- Prefer jump over finish when the only reason for unresolved is "assignment not
  visible in the current context".
"""

#- Only use identifiers that actually appear in the provided context unless you are making a necessary speculative provider/helper inference.
#- Bootlin references show where the current symbol is used.
#- If the provider cannot be found locally, prefer jumping to symbols appearing in those reference locations.
#- Prefer next_symbol as a function-level provider or user site rather than a raw struct field name when possible.
#- If local value flow is insufficient, use the reference-derived jump candidates to continue analysis.
#- Avoid jumping to bare field names if a function-level reference candidate is available.
#- If the current site expands to a function-pointer field access, do not finish too early.


def format_bootlin_references(refs: list[dict]) -> str:
    if not refs:
        return "(none)"

    lines = []
    for r in refs:
        path = r.get("path", "")
        line = r.get("line", "")
        lines.append(f"- {path}:{line}")
    return "\n".join(lines)


def format_reference_jump_candidates(cands: list[dict]) -> str:
    if not cands:
        return "(none)"

    lines = []
    for c in cands:
        lines.append(
            f"- symbol={c.get('symbol')} "
            f"path={c.get('path')}:{c.get('line')} "
            f"ref_line={c.get('ref_line')} "
            f"reason={c.get('reason')}"
        )
    return "\n".join(lines)


def build_step_prompt_payload(state: dict) -> dict:
    return {
        "iteration": state.get("iteration", 0) + 1,
        "current_symbol": state.get("current_symbol"),
        "caller_symbol": state.get("caller_symbol"),
        "icall_expr": state.get("icall_expr"),
        "icall_location": state.get("icall_location"),
        "icall_line": state.get("icall_line"),
        "visited_symbols": state.get("visited_symbols", []),
        "bootlin_references": state.get("bootlin_references", []),
        "reference_jump_candidates": state.get("reference_jump_candidates", []),
        "current_block": state.get("current_block", ""),
        "macro_context": state.get("macro_context", []),
        "struct_context": state.get("struct_context", []),
        "assignment_context": state.get("assignment_context", []),
        "initializer_context": state.get("initializer_context", []),
        "observations": state.get("observations", []),
    }


def render_step_prompt(payload: dict) -> str:
    return f"""
Iteration: {payload.get("iteration")}
Current symbol: {payload.get("current_symbol")}
Caller: {payload.get("caller_symbol")}
ICall: {payload.get("icall_expr")}
ICall location: {payload.get("icall_location")}:{payload.get("icall_line")}

Visited:
{payload.get("visited_symbols")}

Bootlin references:
{format_bootlin_references(payload.get("bootlin_references", []))}

Reference-derived jump candidates:
{format_reference_jump_candidates(payload.get("reference_jump_candidates", []))}

Current code:
{payload.get("current_block", "")}

Macro context:
{payload.get("macro_context", [])}

Struct context:
{payload.get("struct_context", [])}

Assignment context:
{payload.get("assignment_context", [])}

Initializer context:
{payload.get("initializer_context", [])}

Previous observations:
{payload.get("observations", [])}
"""


def normalize_provider(provider: str | None, model: str | None = None) -> str:
    provider = (provider or "").strip().lower()
    if provider:
        return provider
    if model and model.startswith("claude-"):
        return "anthropic"
    return DEFAULT_PROVIDER


def build_openai_chat_body(model: str, prompt_text: str) -> dict:
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt_text},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "resolver_decision",
                "schema": JSON_SCHEMA
            }
        },
        "temperature": 0.0,
    }


def system_prompt_for_provider(provider: str | None, model: str | None = None) -> str:
    provider = normalize_provider(provider, model)
    if provider == "anthropic":
        return ANTHROPIC_SYSTEM_PROMPT
    return SYSTEM_PROMPT


def build_anthropic_messages_body(model: str, prompt_text: str) -> dict:
    return {
        "model": model,
        "max_tokens": 4096,
        "system": ANTHROPIC_SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": prompt_text},
        ],
        "tools": [
            {
                "name": "resolver_decision",
                "description": "Return the indirect-call resolver decision.",
                "input_schema": JSON_SCHEMA,
            }
        ],
        "tool_choice": {"type": "tool", "name": "resolver_decision"},
        "temperature": 0.0,
    }


def extract_anthropic_tool_input(message: dict) -> dict:
    for block in message.get("content", []):
        if block.get("type") == "tool_use" and block.get("name") == "resolver_decision":
            tool_input = block.get("input")
            if isinstance(tool_input, dict):
                return tool_input
            raise ValueError(f"Anthropic tool input was not an object: {tool_input!r}")
    raise ValueError(f"Anthropic response did not contain resolver_decision tool_use: {message}")


def call_openai(model: str, prompt_text: str) -> dict:
    if OpenAI is None:
        raise RuntimeError("openai package is required for provider=openai")

    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    resp = client.chat.completions.create(**build_openai_chat_body(model, prompt_text))
    return json.loads(resp.choices[0].message.content)


def call_anthropic(model: str, prompt_text: str) -> dict:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is required for provider=anthropic")

    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_API_VERSION,
            "content-type": "application/json",
        },
        json=build_anthropic_messages_body(model, prompt_text),
        timeout=120,
    )
    response.raise_for_status()
    return extract_anthropic_tool_input(response.json())


def llm_analyze_step(state: dict) -> dict:
    prompt_payload = build_step_prompt_payload(state)
    prompt_text = render_step_prompt(prompt_payload)
    model = state.get("model") or DEFAULT_MODEL_NAME
    provider = normalize_provider(state.get("provider"), model)

    if provider == "openai":
        data = call_openai(model, prompt_text)
    elif provider == "anthropic":
        data = call_anthropic(model, prompt_text)
    else:
        raise ValueError(f"unsupported provider: {provider}")

    return {
        "provider": provider,
        "model": model,
        "prompt_payload": prompt_payload,
        "prompt_text": prompt_text,
        "system_prompt": system_prompt_for_provider(provider, model),
        "llm_output": data,
    }
