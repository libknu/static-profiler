from typing import Annotated, Literal, Optional
from typing_extensions import TypedDict
import operator


class ResolverState(TypedDict, total=False):
    project_root: str
    project: str
    version: str
    family: str

    caller_symbol: str
    icall_expr: str
    icall_location: str

    current_symbol: str
    current_path: str
    current_line: int
    current_kind: str

    current_block: str
    current_block_kind: str

    retrieved_chunks: Annotated[list[str], operator.add]
    observations: Annotated[list[str], operator.add]
    candidate_callees: Annotated[list[str], operator.add]
    visited_symbols: Annotated[list[str], operator.add]
    visible_trace: Annotated[list[dict], operator.add]

    macro_context: Annotated[list[str], operator.add]
    struct_context: Annotated[list[str], operator.add]
    assignment_context: Annotated[list[str], operator.add]

    decision: str
    decision_reason: str
    next_symbol: Optional[str]

    hop_count: int
    max_hops: int

    status: Literal["running", "resolved", "failed"]
    final_answer: Optional[str]
