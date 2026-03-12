from analysis.step_d_pr1 import (
    normalize_indirect_callsites,
    read_function_universe,
    run_step_d_pr1,
)


def test_read_function_universe_legacy_rows(tmp_path):
    p = tmp_path / "functions_seen.csv"
    p.write_text("tu1.c,foo\ntu2.c,bar\n")

    got = read_function_universe(str(p))

    assert got == {"foo", "bar"}


def test_normalize_indirect_callsites_without_header(tmp_path):
    p = tmp_path / "indirect.csv"
    p.write_text("tu1.c,func_a,mem-reg\ntu2.c,func_b,reg\n")

    rows = normalize_indirect_callsites(str(p))

    assert rows == [
        ("cs_000001", "tu1.c", "func_a", "mem-reg"),
        ("cs_000002", "tu2.c", "func_b", "reg"),
    ]


def test_run_step_d_pr1_writes_expected_outputs(tmp_path):
    indirect = tmp_path / "syscall_related_indirect_callsites.csv"
    functions_seen = tmp_path / "functions_seen.csv"

    out_address_taken = tmp_path / "address_taken_functions.csv"
    out_normalized = tmp_path / "indirect_callsites_normalized.csv"
    out_candidates = tmp_path / "indirect_candidates_pr1.csv"

    indirect.write_text("tu1.c,caller_a,mem-reg\n")
    functions_seen.write_text("tu1.c,target_a\ntu2.c,target_b\n")

    n_sites, n_universe = run_step_d_pr1(
        syscall_related_indirect_callsites_csv=str(indirect),
        functions_seen_csv=str(functions_seen),
        out_address_taken_csv=str(out_address_taken),
        out_normalized_callsites_csv=str(out_normalized),
        out_candidates_csv=str(out_candidates),
    )

    assert n_sites == 1
    assert n_universe == 2

    address_rows = out_address_taken.read_text().strip().splitlines()
    assert address_rows[0] == "function,evidence_kind,evidence_loc"
    assert "target_a,bootstrap-functions-seen,<unknown>" in address_rows
    assert "target_b,bootstrap-functions-seen,<unknown>" in address_rows

    normalized_rows = out_normalized.read_text().strip().splitlines()
    assert normalized_rows == [
        "site_id,tu,function,raw_indirect_expr",
        "cs_000001,tu1.c,caller_a,mem-reg",
    ]

    candidates_rows = out_candidates.read_text().strip().splitlines()
    assert candidates_rows[0] == (
        "site_id,enclosing_function,candidate_count,candidates,source,confidence"
    )
    assert candidates_rows[1] == (
        "cs_000001,caller_a,2,target_a;target_b,ADDRESS_TAKEN_COARSE_UNIVERSE,LOW"
    )
