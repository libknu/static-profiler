from analysis.step_bc_pipeline import (
    compute_syscall_reachable_functions,
    filter_syscall_related_indirect_callsites,
)


def test_reverse_reachability_from_syscall_sinks():
    edges = {
        ("A", "B"),
        ("B", "C"),
        ("X", "Y"),
    }
    sinks = {"C"}

    reachable = compute_syscall_reachable_functions(edges, sinks)

    assert reachable == {"A", "B", "C"}


def test_filter_indirect_callsites_by_containing_function_without_header():
    header = []
    rows = [
        ["tu1.c", "A", "mem-reg"],
        ["tu1.c", "X", "mem-reg"],
    ]
    reachable = {"A", "B", "C"}

    filtered = filter_syscall_related_indirect_callsites(header, rows, reachable)

    assert filtered == [["tu1.c", "A", "mem-reg"]]


def test_filter_indirect_callsites_by_containing_function_with_header():
    header = ["site_id", "function", "insn_uid", "file", "line", "bb", "callee_kind"]
    rows = [
        ["s1", "A", "101", "a.c", "10", "2", "REG"],
        ["s2", "X", "102", "x.c", "30", "5", "MEM"],
    ]
    reachable = {"A", "B", "C"}

    filtered = filter_syscall_related_indirect_callsites(header, rows, reachable)

    assert filtered == [["s1", "A", "101", "a.c", "10", "2", "REG"]]
