from typing import Annotated, Literal, Optional, TypedDict
import operator


class ResolverState(TypedDict, total=False):
    project_root: str #initial input
    project: str
    version: str
    family: str
    model: str

    caller_symbol: str
    icall_expr: str
    icall_location: str
    icall_line: int

    current_symbol: str #index symbol
    current_path: str
    current_line: int
    current_kind: str
    current_block: str
    current_block_kind: str

    macro_context: Annotated[list[str], operator.add]  #retrive block
    struct_context: Annotated[list[str], operator.add]
    assignment_context: Annotated[list[str], operator.add]
    initializer_context: Annotated[list[str], operator.add]

    bootlin_references: list[dict] #expand references
    reference_jump_candidates: Annotated[list[dict], operator.add]

    retrieved_chunks: Annotated[list[str], operator.add] #analyze with LLM
    observations: Annotated[list[str], operator.add]
    candidate_callees: list[str]
    visited_symbols: Annotated[list[str], operator.add]
    visible_trace: Annotated[list[dict], operator.add]

    decision: str
    decision_reason: str
    next_symbol: Optional[str]

    hop_count: int
    iteration: int
    max_hops: int
    max_iterations: int

    status: Literal["running", "resolved", "failed"]
    icall_resolution_status: Literal["resolved", "unresolved", "not_icall", "inconclusive", "failed"]
    icall_resolved: bool
    icall_resolution_reason: str
    icall_targets: list[str]
    final_answer: Optional[str]

    run_name: str
    output_root: str
    output_dir: str
