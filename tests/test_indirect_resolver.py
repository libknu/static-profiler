from analysis.indirect_resolver import IndirectCallSite, LocalIndirectCallResolver, RtlFunctionIndex, Instruction


def build_index(fn, insns):
    return RtlFunctionIndex({fn: [Instruction(uid=u, text=t) for u, t in insns]})


def test_direct_symbol_assignment_resolution():
    idx = build_index(
        "caller",
        [
            (10, '(insn 10 ... (set (reg:DI 84) (symbol_ref:DI "f2")))'),
            (20, '(insn 20 ... (call (mem:QI (reg/f:DI 84))))'),
        ],
    )
    resolver = LocalIndirectCallResolver(idx)
    site = IndirectCallSite("s1", "caller", 20, "REG", "(reg/f:DI 84)")
    assert resolver.resolve(site) == {"f2"}


def test_register_copy_and_stack_slot_flow_resolution():
    idx = build_index(
        "caller",
        [
            (10, '(insn 10 ... (set (reg:DI 84) (symbol_ref:DI "f2")))'),
            (12, '(insn 12 ... (set (mem/f/c:DI (plus:DI (reg/f:DI 7) (const_int -24))) (reg:DI 84)))'),
            (14, '(insn 14 ... (set (reg:DI 85) (mem/f/c:DI (plus:DI (reg/f:DI 7) (const_int -24)))))'),
            (20, '(insn 20 ... (call (mem:QI (reg/f:DI 85))))'),
        ],
    )
    resolver = LocalIndirectCallResolver(idx)
    site = IndirectCallSite("s2", "caller", 20, "REG", "(reg/f:DI 85)")
    assert resolver.resolve(site) == {"f2"}


def test_conditional_assignments_return_set_of_candidates():
    idx = build_index(
        "caller",
        [
            (8, '(insn 8 ... (set (reg:DI 84) (symbol_ref:DI "f1")))'),
            (10, '(insn 10 ... (set (reg:DI 84) (symbol_ref:DI "f2")))'),
            (20, '(insn 20 ... (call (mem:QI (reg/f:DI 84))))'),
        ],
    )
    resolver = LocalIndirectCallResolver(idx)
    site = IndirectCallSite("s3", "caller", 20, "REG", "(reg/f:DI 84)")
    assert resolver.resolve(site) == {"f1", "f2"}
