from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List
import csv
import re


FUNC_RE = re.compile(r"^;;\s*Function\s+([^\s(]+)")
INSN_RE = re.compile(r"\((?:insn|call_insn|jump_insn)\s+(\d+)\b")
DEF_SYMBOL_RE = re.compile(r"\(set\s+\(reg:[^\s)]*\s+(\d+)\)\s+\(symbol_ref[^\"]*\"([^\"]+)\"")
STORE_ESCAPE_RE = re.compile(r"\(set\s+\(mem[^\n]*\(reg:[^\s)]*\s+(\d+)\)")
CALL_ARG_RE = re.compile(r"\(call[^\n]*\(mem[^\n]*\(reg:[^\s)]*\s+(\d+)\)")


@dataclass(frozen=True)
class DefUseRow:
    tu: str
    function: str
    insn_uid: str
    kind: str
    var: str
    value: str


def _reg_token(regno: str) -> str:
    return f"REG({regno})"


def extract_defuse_rows_from_rtl_dump(path: str, tu: str = "rtl-dump") -> List[DefUseRow]:
    rows: List[DefUseRow] = []
    current_fn = ""

    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            m_fn = FUNC_RE.search(line)
            if m_fn:
                current_fn = m_fn.group(1)
                continue

            m_insn = INSN_RE.search(line)
            if not m_insn:
                continue
            insn_uid = m_insn.group(1)

            m_def = DEF_SYMBOL_RE.search(line)
            if m_def and current_fn:
                rows.append(
                    DefUseRow(
                        tu=tu,
                        function=current_fn,
                        insn_uid=insn_uid,
                        kind="def",
                        var=_reg_token(m_def.group(1)),
                        value=f"SYMBOL_REF({m_def.group(2)})",
                    )
                )

            m_escape = STORE_ESCAPE_RE.search(line)
            if m_escape and current_fn:
                rows.append(
                    DefUseRow(
                        tu=tu,
                        function=current_fn,
                        insn_uid=insn_uid,
                        kind="escape",
                        var=_reg_token(m_escape.group(1)),
                        value="store-to-mem",
                    )
                )

            m_call_arg = CALL_ARG_RE.search(line)
            if m_call_arg and current_fn:
                rows.append(
                    DefUseRow(
                        tu=tu,
                        function=current_fn,
                        insn_uid=insn_uid,
                        kind="call_arg",
                        var=_reg_token(m_call_arg.group(1)),
                        value="indirect-call-target",
                    )
                )

    return rows


def write_defuse_csv(path: str, rows: Iterable[DefUseRow]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["tu", "function", "insn_uid", "kind", "var", "value"])
        for r in rows:
            w.writerow([r.tu, r.function, r.insn_uid, r.kind, r.var, r.value])


def run_step_d_defuse_from_rtl(rtl_dump: str, out_csv: str, tu: str = "rtl-dump") -> List[DefUseRow]:
    rows = extract_defuse_rows_from_rtl_dump(rtl_dump, tu=tu)
    write_defuse_csv(out_csv, rows)
    return rows
