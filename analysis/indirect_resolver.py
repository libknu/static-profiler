from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple
import re


@dataclass(frozen=True)
class IndirectCallSite:
    site_id: str
    function: str
    insn_uid: int
    callee_kind: str
    callee_operand: str


@dataclass
class Instruction:
    uid: int
    text: str


@dataclass(frozen=True)
class SlotRef:
    """Represents a tracked memory slot such as a stack location expression."""

    expr: str


REG_SET_RE = re.compile(r"\(set\s+\((reg[^\)]*)\)\s+(.*)\)$")
MEM_SET_RE = re.compile(r"\(set\s+\((mem[^\)]*\([^\)]*\)[^\)]*)\)\s+(.*)\)$")
CALL_RE = re.compile(r"\(call\s+\(([^\)]*)\)\)")
SYMBOL_REF_RE = re.compile(r"\(symbol_ref(?::[^\s\)]*)?\s+\"([^\"]+)\"\)")
REG_REF_RE = re.compile(r"\((reg[^\)]*)\)")
MEM_REF_RE = re.compile(r"\((mem[^\)]*\([^\)]*\)[^\)]*)\)")


class RtlFunctionIndex:
    """Small in-memory index of function RTL instructions keyed by UID."""

    def __init__(self, functions: Dict[str, List[Instruction]]):
        self.functions = functions

    @classmethod
    def from_expand_dump(cls, dump_text: str) -> "RtlFunctionIndex":
        functions: Dict[str, List[Instruction]] = {}
        current_fn: Optional[str] = None
        current_uid: Optional[int] = None
        current_insn_lines: List[str] = []

        def flush_insn() -> None:
            nonlocal current_uid, current_insn_lines
            if current_fn is None or current_uid is None or not current_insn_lines:
                return
            insn = Instruction(uid=current_uid, text=" ".join(line.strip() for line in current_insn_lines))
            functions.setdefault(current_fn, []).append(insn)
            current_uid = None
            current_insn_lines = []

        for raw in dump_text.splitlines():
            line = raw.rstrip("\n")
            if line.startswith(";; Function "):
                flush_insn()
                parts = line.split()
                current_fn = parts[2] if len(parts) >= 3 else "<unknown>"
                continue

            m = re.match(r"\(insn\s+(\d+)\s", line.strip())
            if m:
                flush_insn()
                current_uid = int(m.group(1))
                current_insn_lines = [line.strip()]
                continue

            if current_uid is not None:
                current_insn_lines.append(line.strip())
                if line.strip().endswith(")"):
                    flush_insn()

        flush_insn()

        for fn in functions:
            functions[fn].sort(key=lambda x: x.uid)

        return cls(functions)

    def function_instructions(self, fn: str) -> List[Instruction]:
        return self.functions.get(fn, [])


class LocalIndirectCallResolver:
    """Intra-procedural resolver for RTL indirect-call targets.

    Supported flows:
    - (set regX (symbol_ref "foo"))
    - (set regY regX)
    - (set (mem slot) regX), (set regY (mem slot))
    - multiple reaching defs (e.g. conditional assignments) => union set
    """

    def __init__(self, rtl_index: RtlFunctionIndex, backward_budget: int = 300):
        self.rtl_index = rtl_index
        self.backward_budget = backward_budget

    def resolve(self, site: IndirectCallSite) -> Set[str]:
        insns = self.rtl_index.function_instructions(site.function)
        if not insns:
            return set()

        pos = next((i for i, insn in enumerate(insns) if insn.uid == site.insn_uid), None)
        if pos is None:
            return set()

        work: List[Tuple[object, int]] = []
        visited: Set[Tuple[object, int]] = set()
        out: Set[str] = set()

        seed = self._seed_operand(site.callee_operand)
        if seed is None:
            return set()

        work.append((seed, pos - 1))

        while work:
            tracked, idx = work.pop()
            state = (tracked, idx)
            if state in visited:
                continue
            visited.add(state)

            for j in range(idx, max(-1, idx - self.backward_budget), -1):
                insn = insns[j]
                rhs = self._reaching_rhs(insn.text, tracked)
                if rhs is None:
                    continue

                syms = self._extract_symbols(rhs)
                if syms:
                    out.update(syms)

                next_refs = self._extract_trackables(rhs)
                for nxt in next_refs:
                    work.append((nxt, j - 1))

        return out

    def _seed_operand(self, operand: str) -> Optional[object]:
        reg = self._match_reg(operand)
        if reg:
            return self._reg_key(reg)
        mem = self._match_mem(operand)
        if mem:
            return SlotRef(mem)
        return None

    def _match_reg(self, text: str) -> Optional[str]:
        m = re.search(r"reg[^\)]*", text)
        return m.group(0) if m else None

    def _match_mem(self, text: str) -> Optional[str]:
        m = re.search(r"mem[^\)]*\([^\)]*\)[^\)]*", text)
        return m.group(0) if m else None


    def _reg_key(self, reg_expr: str) -> Tuple[str, int]:
        m = re.search(r"(\d+)$", reg_expr.strip())
        if not m:
            return ("reg", -1)
        return ("reg", int(m.group(1)))
    def _reaching_rhs(self, insn_text: str, tracked: object) -> Optional[str]:
        set_payload = self._extract_set_payload(insn_text)
        if set_payload is None:
            return None

        lhs, rhs = set_payload
        if isinstance(tracked, tuple) and tracked and tracked[0] == "reg":
            lhs_reg = self._match_reg(lhs)
            if lhs_reg and self._reg_key(lhs_reg) == tracked:
                return rhs
        elif isinstance(tracked, SlotRef):
            lhs_mem = self._match_mem(lhs)
            if lhs_mem and lhs_mem == tracked.expr:
                return rhs
        return None

    def _extract_set_payload(self, text: str) -> Optional[Tuple[str, str]]:
        s = text.strip()
        if "(set " not in s:
            return None
        start = s.find("(set ")
        frag = s[start:]
        # Lightweight parser for "(set <lhs> <rhs>)"
        if not frag.startswith("(set "):
            return None
        body = frag[len("(set ") :]

        lhs, rem = self._consume_sexpr(body)
        if lhs is None:
            return None
        rhs, _ = self._consume_sexpr(rem.lstrip())
        if rhs is None:
            return None
        return lhs, rhs

    def _consume_sexpr(self, text: str) -> Tuple[Optional[str], str]:
        txt = text.lstrip()
        if not txt:
            return None, text
        if txt[0] != "(":
            atom = txt.split(maxsplit=1)[0]
            rest = txt[len(atom) :]
            return atom, rest
        depth = 0
        for i, ch in enumerate(txt):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return txt[: i + 1], txt[i + 1 :]
        return None, txt

    def _extract_symbols(self, rhs: str) -> Set[str]:
        return set(SYMBOL_REF_RE.findall(rhs))

    def _extract_trackables(self, rhs: str) -> Set[object]:
        refs: Set[object] = set()

        reg = self._match_reg(rhs)
        if reg:
            refs.add(self._reg_key(reg))

        mem = self._match_mem(rhs)
        if mem:
            refs.add(SlotRef(mem))

        return refs
