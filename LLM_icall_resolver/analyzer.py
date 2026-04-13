import os
import json
from openai import OpenAI

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "decision": {
            "type": "string",
            "enum": ["jump", "finish", "fail"]
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

Your job:
1. Decide whether the indirect target is resolved
2. If not, decide which symbol to analyze next

Rules:
- A call written as foo(...) may still be indirect if foo is a macro wrapper.
- Prefer value-flow relevant symbols, struct field providers, ops tables, wrapper-returning helpers, and initializer sources.
- Only use identifiers that actually appear in the provided context.
- Do NOT hallucinate symbols.
- If the current site expands to a function-pointer field access, do not finish too early.
- If unsure, continue with jump.

Output MUST be valid JSON following the schema.
"""

def llm_analyze_step(state: dict) -> dict:
    prompt = f"""
Current symbol: {state.get("current_symbol")}
Caller: {state.get("caller_symbol")}
ICall: {state.get("icall_expr")}

Visited: {state.get("visited_symbols")}

Current code:
{state.get("current_block")}

Previous observations:
{state.get("observations")}
"""

    resp = client.chat.completions.create(
        model="gpt-5.4",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "resolver_decision",
                "schema": JSON_SCHEMA
            }
        },
        temperature=0.0,
    )

    data = json.loads(resp.choices[0].message.content)

    return data
