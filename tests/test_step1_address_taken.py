from analysis.step1_address_taken import (
    AddressTakenEvidence,
    extract_address_taken_from_direct_edges,
)


def test_extracts_only_star_callee_rows_as_step1_evidence():
    rows = [
        ["a.c", "caller_a", "*foo"],
        ["a.c", "caller_a", "bar"],
        ["b.c", "caller_b", "*baz"],
    ]

    got = extract_address_taken_from_direct_edges(rows)

    assert got == {
        AddressTakenEvidence(
            tu="a.c",
            function="foo",
            evidence_kind="symbol_ref_star_callee",
            evidence_text="caller=caller_a;raw_callee=*foo",
        ),
        AddressTakenEvidence(
            tu="b.c",
            function="baz",
            evidence_kind="symbol_ref_star_callee",
            evidence_text="caller=caller_b;raw_callee=*baz",
        ),
    }


def test_deduplicates_identical_rows_via_set_semantics():
    rows = [
        ["a.c", "caller_a", "*foo"],
        ["a.c", "caller_a", "*foo"],
    ]

    got = extract_address_taken_from_direct_edges(rows)

    assert len(got) == 1
