from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
import csv
import re


SYMBOL_REF_RE = re.compile(r"^\s*SYMBOL_REF\(([^)]+)\)\s*$")


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
    status: str
    target: str


UNSAFE_KINDS = {"escape", "store", "arg_pass", "call_arg", "alias", "mem_write", "unknown", "phi", "merge"}
DEF_KINDS = {"def", "set", "assign"}


def _pick(row: Mapping[str, str], keys: Sequence[str]) -> str:
    for key in keys:
        if key in row and row[key] is not None:
            return row[key].strip()
    return ""


def _normalize_dict_row(row: Mapping[str, str]) -> Dict[str, str]:
    return {str(k).strip().lower(): ("" if v is None else str(v).strip()) for k, v in row.items()}


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
                    var=_pick(row, ["var", "operand", "register", "dst", "name"]),
                    value=_pick(row, ["value", "rhs", "src", "expr"]),
                )
            )
    return events


def _safe_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_exact_target(value: str) -> str:
    m = SYMBOL_REF_RE.match(value)
    if not m:
        return ""
    return m.group(1).strip().strip('"\'')


def _header_index(header: Sequence[str], candidates: Sequence[str], default: int = -1) -> int:
    lowered = [c.strip().lower() for c in header]
    for key in candidates:
        if key in lowered:
            return lowered.index(key)
    return default


def _resolve_callsite(function: str, call_insn_uid: str, operand: str, events: List[DefUseEvent]) -> Resolution:
    if not call_insn_uid or not operand:
        return Resolution("unresolved", "")

    call_uid_num = _safe_int(call_insn_uid)

    def is_before_or_equal(e: DefUseEvent) -> bool:
        if e.function != function:
            return False
        if call_uid_num is None:
            return True
        uid_num = _safe_int(e.insn_uid)
        return uid_num is not None and uid_num <= call_uid_num

    candidates = [e for e in events if is_before_or_equal(e)]

    for event in reversed(candidates):
        if event.var != operand:
            continue
        if event.kind in UNSAFE_KINDS:
            return Resolution("unresolved", "")
        if event.kind in DEF_KINDS:
            target = _extract_exact_target(event.value)
            if target:
                return Resolution("exact", target)
            return Resolution("unresolved", "")

    return Resolution("unresolved", "")


def resolve_indirect_callsites(
    header: Sequence[str],
    rows: Iterable[Sequence[str]],
    defuse_events: Sequence[DefUseEvent],
) -> Tuple[List[str], List[List[str]]]:
    rows_list = [list(r) for r in rows]

    base_header: List[str]
    if header:
        base_header = list(header)
    else:
        base_header = ["tu", "function", "callee_kind"]

    fn_idx = _header_index(base_header, ["function", "caller"], 1)
    uid_idx = _header_index(base_header, ["insn_uid", "uid", "insn"], -1)
    op_idx = _header_index(base_header, ["target_operand", "operand", "target", "callee_operand", "reg"], -1)

    out_rows: List[List[str]] = []
    for row in rows_list:
        function = row[fn_idx] if fn_idx >= 0 and len(row) > fn_idx else ""
        insn_uid = row[uid_idx] if uid_idx >= 0 and len(row) > uid_idx else ""
        operand = row[op_idx] if op_idx >= 0 and len(row) > op_idx else ""

        result = _resolve_callsite(function, insn_uid, operand, list(defuse_events))
        out_rows.append(row + [result.status, result.target])

    return base_header + ["resolution_status", "resolved_target"], out_rows


def write_rows_csv(path: str, header: Sequence[str], rows: Iterable[Sequence[str]]) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        if header:
            w.writerow(list(header))
        for row in rows:
            w.writerow(list(row))


def run_step_d_exact_resolve(indirect_callsites_csv: str, out_csv: str, defuse_csv: str = "") -> Tuple[List[str], List[List[str]]]:
    header, rows = read_indirect_callsites(indirect_callsites_csv)
    events = read_defuse_events(defuse_csv) if defuse_csv else []
    out_header, out_rows = resolve_indirect_callsites(header, rows, events)
    write_rows_csv(out_csv, out_header, out_rows)
    return out_header, out_rows
