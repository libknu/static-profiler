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

Your job:
1. Decide whether the target is resolved
2. If not, decide which symbol to analyze next

Rules:
- Only use identifiers that actually appear in the code
- Prefer value-flow relevant symbols (assignments, function calls)
- Do NOT hallucinate symbols
- If unsure, continue (jump)

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
        model="gpt-5.3",   # 또는 gpt-4o
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
