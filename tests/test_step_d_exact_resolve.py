from analysis.step_d_exact_resolve import DefUseEvent, resolve_indirect_callsites


def test_exact_resolution_when_latest_def_is_symbol_ref():
    header = ["site_id", "function", "insn_uid", "target_operand"]
    rows = [["s1", "foo", "20", "r10"]]
    events = [
        DefUseEvent(order=0, function="foo", insn_uid="10", kind="def", var="r10", value="SYMBOL_REF(bar)"),
    ]

    out_header, out_rows = resolve_indirect_callsites(header, rows, events)

    assert out_header[-2:] == ["resolution_status", "resolved_target"]
    assert out_rows == [["s1", "foo", "20", "r10", "exact", "bar"]]


def test_unresolved_on_escape_before_call():
    header = ["site_id", "function", "insn_uid", "target_operand"]
    rows = [["s2", "foo", "20", "r10"]]
    events = [
        DefUseEvent(order=0, function="foo", insn_uid="10", kind="def", var="r10", value="SYMBOL_REF(bar)"),
        DefUseEvent(order=1, function="foo", insn_uid="15", kind="escape", var="r10", value=""),
    ]

    _out_header, out_rows = resolve_indirect_callsites(header, rows, events)

    assert out_rows == [["s2", "foo", "20", "r10", "unresolved", ""]]


def test_unresolved_on_non_symbol_ref_def():
    header = ["site_id", "function", "insn_uid", "target_operand"]
    rows = [["s3", "foo", "30", "r10"]]
    events = [
        DefUseEvent(order=0, function="foo", insn_uid="25", kind="def", var="r10", value="PLUS(r1,4)"),
    ]

    _out_header, out_rows = resolve_indirect_callsites(header, rows, events)

    assert out_rows == [["s3", "foo", "30", "r10", "unresolved", ""]]


def test_unresolved_when_missing_uid_or_operand():
    header = ["function", "callee_kind"]
    rows = [["foo", "mem-reg"]]
    events = [
        DefUseEvent(order=0, function="foo", insn_uid="10", kind="def", var="r10", value="SYMBOL_REF(bar)"),
    ]

    _out_header, out_rows = resolve_indirect_callsites(header, rows, events)

    assert out_rows == [["foo", "mem-reg", "unresolved", ""]]
