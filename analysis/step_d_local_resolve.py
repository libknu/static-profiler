from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
import csv
import re


SYMBOL_REF_RE = re.compile(r"^\s*SYMBOL_REF\(([^)]+)\)\s*$")
REG_LIKE_RE = re.compile(r"^(REG\([^)]*\)|r\d+)$", re.IGNORECASE)


@dataclass(frozen=True)
class DefUseEvent:
    order: int
    function: str
    insn_uid: str
    kind: str
    var: str
    value: str


@dataclass(frozen=True)
class Resolution:
    resolution_class: str
    resolved_target: str
    stop_reason: str


UNSAFE_KINDS = {"escape", "store", "arg_pass", "alias", "mem_write", "unknown", "phi", "merge"}
DEF_KINDS = {"def", "set", "assign"}
SKIP_KINDS = {"call_arg"}
MAX_TRACE_DEPTH = 32


def _pick(row: Mapping[str, str], keys: Sequence[str]) -> str:
    for key in keys:
        if key in row and row[key] is not None:
            return row[key].strip()
    return ""


def _normalize_dict_row(row: Mapping[str, str]) -> Dict[str, str]:
    return {str(k).strip().lower(): ("" if v is None else str(v).strip()) for k, v in row.items()}


def _safe_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_subreg_inner(value: str) -> str:
    text = value.strip()
    if not text.startswith("SUBREG(") or not text.endswith(")"):
        return text

    inner = text[len("SUBREG(") : -1]
    depth = 0
    for i, ch in enumerate(inner):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            return inner[:i].strip()
    return text


def _normalize_operand(value: str) -> str:
    out = value.strip()
    while True:
        next_value = _extract_subreg_inner(out)
        if next_value == out:
            return out
        out = next_value


def _extract_symbol_ref(value: str) -> str:
    m = SYMBOL_REF_RE.match(value)
    if not m:
        return ""
    return m.group(1).strip().strip('"\'')


def _is_register_like(value: str) -> bool:
    return bool(REG_LIKE_RE.match(value.strip()))


def read_indirect_callsites(path: str) -> Tuple[List[str], List[List[str]]]:
    with open(path, newline="") as f:
        rows = [row for row in csv.reader(f) if row]

    if not rows:
        return [], []

    first = rows[0]
    lower = [c.strip().lower() for c in first]
    has_header = "function" in lower or "site_id" in lower or "insn_uid" in lower

    if has_header:
        return first, rows[1:]
    return [], rows


def read_defuse_events(path: str) -> List[DefUseEvent]:
    events: List[DefUseEvent] = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for i, raw in enumerate(reader):
            row = _normalize_dict_row(raw)
            function = _pick(row, ["function", "func", "caller"])
            if not function:
                continue
            events.append(
                DefUseEvent(
                    order=i,
                    function=function,
                    insn_uid=_pick(row, ["insn_uid", "uid", "insn"]),
                    kind=_pick(row, ["kind", "event", "op"]).lower(),
                    var=_normalize_operand(_pick(row, ["var", "operand", "register", "dst", "name"])),
                    value=_normalize_operand(_pick(row, ["value", "rhs", "src", "expr"])),
                )
            )
    return events


def _header_index(header: Sequence[str], candidates: Sequence[str], default: int = -1) -> int:
    lowered = [c.strip().lower() for c in header]
    for key in candidates:
        if key in lowered:
            return lowered.index(key)
    return default


def _events_before_call(function_events: Sequence[DefUseEvent], call_uid: str) -> List[DefUseEvent]:
    call_uid_num = _safe_int(call_uid)
    if call_uid_num is None:
        return []

    out: List[DefUseEvent] = []
    for event in function_events:
        uid_num = _safe_int(event.insn_uid)
        if uid_num is None:
            continue
        if uid_num <= call_uid_num:
            out.append(event)
    return out


def _resolve_callsite(function: str, call_insn_uid: str, operand: str, function_events: Sequence[DefUseEvent]) -> Resolution:
    operand = _normalize_operand(operand)
    if not function or not call_insn_uid or not operand:
        return Resolution("unresolved", "", "missing-callsite-fields")

    candidates = _events_before_call(function_events, call_insn_uid)
    if not candidates:
        return Resolution("unresolved", "", "missing-or-invalid-insn_uid")

    current_var = operand
    visited = {current_var}

    for depth in range(MAX_TRACE_DEPTH):
        matched_event: Optional[DefUseEvent] = None
        for event in reversed(candidates):
            if event.kind in SKIP_KINDS:
                continue
            if event.var != current_var:
                continue
            matched_event = event
            break

        if matched_event is None:
            return Resolution("unresolved", "", f"no-local-def-for:{current_var}")

        if matched_event.kind in UNSAFE_KINDS:
            return Resolution("unresolved", "", f"unsafe-kind:{matched_event.kind}")

        if matched_event.kind not in DEF_KINDS:
            return Resolution("unresolved", "", f"non-def-kind:{matched_event.kind}")

        value = matched_event.value
        target = _extract_symbol_ref(value)
        if target:
            klass = "direct-symbol" if depth == 0 else "reg-copy-chain"
            return Resolution(klass, target, "")

        if _is_register_like(value):
            next_var = _normalize_operand(value)
            if next_var in visited:
                return Resolution("unresolved", "", "copy-cycle")
            visited.add(next_var)
            current_var = next_var
            continue

        return Resolution("unresolved", "", f"value-not-supported:{value}")

    return Resolution("unresolved", "", "max-trace-depth")


def resolve_indirect_callsites(
    header: Sequence[str],
    rows: Iterable[Sequence[str]],
    defuse_events: Sequence[DefUseEvent],
) -> Tuple[List[str], List[List[str]]]:
    rows_list = [list(r) for r in rows]
    base_header = list(header) if header else ["tu", "function", "callee_kind"]

    fn_idx = _header_index(base_header, ["function", "caller"], 1)
    uid_idx = _header_index(base_header, ["insn_uid", "uid", "insn"], -1)
    op_idx = _header_index(base_header, ["target_operand", "operand", "target", "callee_operand", "reg"], -1)

    events_by_function: Dict[str, List[DefUseEvent]] = {}
    for event in defuse_events:
        events_by_function.setdefault(event.function, []).append(event)

    for function_events in events_by_function.values():
        function_events.sort(key=lambda e: ((_safe_int(e.insn_uid) is None), _safe_int(e.insn_uid) or 0, e.order))

    out_rows: List[List[str]] = []
    for row in rows_list:
        function = row[fn_idx] if fn_idx >= 0 and len(row) > fn_idx else ""
        insn_uid = row[uid_idx] if uid_idx >= 0 and len(row) > uid_idx else ""
        operand = row[op_idx] if op_idx >= 0 and len(row) > op_idx else ""

        result = _resolve_callsite(function, insn_uid, operand, events_by_function.get(function, []))
        out_rows.append(row + [result.resolution_class, result.resolved_target, result.stop_reason])

    return base_header + ["resolution_class", "resolved_target", "stop_reason"], out_rows


def write_rows_csv(path: str, header: Sequence[str], rows: Iterable[Sequence[str]]) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        if header:
            w.writerow(list(header))
        for row in rows:
            w.writerow(list(row))


def run_step_d_local_resolve(indirect_callsites_csv: str, out_csv: str, defuse_csv: str) -> Tuple[List[str], List[List[str]]]:
    header, rows = read_indirect_callsites(indirect_callsites_csv)
    events = read_defuse_events(defuse_csv)
    out_header, out_rows = resolve_indirect_callsites(header, rows, events)
    write_rows_csv(out_csv, out_header, out_rows)
    return out_header, out_rows
