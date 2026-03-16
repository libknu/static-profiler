from pathlib import Path

from analysis.step_d_defuse_from_rtl import extract_defuse_rows_from_rtl_dump


def test_extract_defuse_rows_from_rtl_dump(tmp_path: Path):
    dump = tmp_path / "a.expand"
    dump.write_text(
        """
;; Function foo
(insn 10 9 11 2 (set (reg:DI 77) (symbol_ref:DI (\"bar\"))) )
(insn 11 10 12 2 (set (mem:DI (reg:DI 77)) (reg:DI 5)) )
(call_insn 12 11 13 2 (call (mem:QI (reg:DI 77)) (const_int 0)))
""".strip()
    )

    rows = extract_defuse_rows_from_rtl_dump(str(dump), tu="tu1")

    assert [r.kind for r in rows] == ["def", "escape", "call_arg"]
    assert rows[0].function == "foo"
    assert rows[0].insn_uid == "10"
    assert rows[0].var == "REG(77)"
    assert rows[0].value == "SYMBOL_REF(bar)"
    assert rows[1].var == "REG(5)"
    assert rows[2].insn_uid == "12"
