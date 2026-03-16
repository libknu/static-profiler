from analysis.step_d_local_resolve import DefUseEvent, resolve_indirect_callsites


def test_direct_symbol_resolution():
    header = ["site_id", "function", "insn_uid", "target_operand"]
    rows = [["s1", "foo", "20", "REG(10)"]]
    events = [
        DefUseEvent(order=0, function="foo", insn_uid="10", kind="def", var="REG(10)", value="SYMBOL_REF(bar)"),
    ]

    out_header, out_rows = resolve_indirect_callsites(header, rows, events)

    assert out_header[-3:] == ["resolution_class", "resolved_target", "stop_reason"]
    assert out_rows == [["s1", "foo", "20", "REG(10)", "direct-symbol", "bar", ""]]


def test_register_copy_chain_resolution():
    header = ["site_id", "function", "insn_uid", "target_operand"]
    rows = [["s2", "foo", "30", "REG(10)"]]
    events = [
        DefUseEvent(order=0, function="foo", insn_uid="10", kind="def", var="REG(11)", value="SYMBOL_REF(baz)"),
        DefUseEvent(order=1, function="foo", insn_uid="20", kind="def", var="REG(10)", value="REG(11)"),
    ]

    _out_header, out_rows = resolve_indirect_callsites(header, rows, events)

    assert out_rows == [["s2", "foo", "30", "REG(10)", "reg-copy-chain", "baz", ""]]


def test_unresolved_on_unsafe_or_unknown_values():
    header = ["site_id", "function", "insn_uid", "target_operand"]
    rows = [["s3", "foo", "30", "REG(10)"]]
    events = [
        DefUseEvent(order=0, function="foo", insn_uid="25", kind="def", var="REG(10)", value="MEM[(REG(1))]"),
    ]

    _out_header, out_rows = resolve_indirect_callsites(header, rows, events)

    assert out_rows == [["s3", "foo", "30", "REG(10)", "unresolved", "", "value-not-supported:MEM[(REG(1))]"]]


def test_call_arg_marker_is_ignored_for_resolution():
    header = ["site_id", "function", "insn_uid", "target_operand"]
    rows = [["s4", "foo", "30", "SUBREG(REG(10),0)"]]
    events = [
        DefUseEvent(order=0, function="foo", insn_uid="10", kind="def", var="REG(10)", value="SYMBOL_REF(bar)"),
        DefUseEvent(order=1, function="foo", insn_uid="20", kind="call_arg", var="REG(10)", value=""),
    ]

    _out_header, out_rows = resolve_indirect_callsites(header, rows, events)

    assert out_rows == [["s4", "foo", "30", "SUBREG(REG(10),0)", "direct-symbol", "bar", ""]]
