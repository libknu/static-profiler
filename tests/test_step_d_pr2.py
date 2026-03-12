from analysis.step_d_pr2 import read_explicit_fp_facts, run_step_d_pr2


def test_read_explicit_fp_facts_with_header(tmp_path):
    p = tmp_path / "fp_facts.csv"
    p.write_text(
        "fact_id,tu,function,loc,lhs_kind,lhs_key,rhs_function,evidence_kind\n"
        "fact_1,tu1.c,caller_a,10:2,REG,fp,target_a,assign\n"
    )

    facts = read_explicit_fp_facts(str(p))

    assert len(facts) == 1
    assert facts[0].function == "caller_a"
    assert facts[0].rhs_function == "target_a"


def test_run_step_d_pr2_with_explicit_facts(tmp_path):
    indirect = tmp_path / "syscall_related_indirect_callsites.csv"
    functions_seen = tmp_path / "functions_seen.csv"
    explicit_facts = tmp_path / "input_fp_facts.csv"

    out_address_taken = tmp_path / "address_taken_functions.csv"
    out_normalized = tmp_path / "indirect_callsites_normalized.csv"
    out_facts = tmp_path / "fp_assignment_facts.csv"
    out_candidates = tmp_path / "indirect_candidates_pr2.csv"

    indirect.write_text("tu1.c,caller_a,mem-reg\ntu2.c,caller_b,reg\n")
    functions_seen.write_text("tuX.c,target_a\ntuY.c,target_b\n")
    explicit_facts.write_text(
        "tu,function,loc,lhs_kind,lhs_key,rhs_function,evidence_kind\n"
        "tu1.c,caller_a,12:4,REG,fp,target_a,assign\n"
    )

    n_sites, n_universe, n_facts = run_step_d_pr2(
        syscall_related_indirect_callsites_csv=str(indirect),
        functions_seen_csv=str(functions_seen),
        explicit_fp_facts_csv=str(explicit_facts),
        out_address_taken_csv=str(out_address_taken),
        out_normalized_callsites_csv=str(out_normalized),
        out_fp_assignment_facts_csv=str(out_facts),
        out_candidates_csv=str(out_candidates),
    )

    assert (n_sites, n_universe, n_facts) == (2, 2, 1)

    rows = out_candidates.read_text().strip().splitlines()
    assert rows[0] == (
        "site_id,enclosing_function,hard_candidate_count,hard_candidates,"
        "soft_candidate_count,soft_candidates,primary_source,confidence"
    )
    assert rows[1] == (
        "cs_000001,caller_a,1,target_a,1,target_b,EXPLICIT_ASSIGNMENT,HIGH"
    )
    assert rows[2] == (
        "cs_000002,caller_b,0,,2,target_a;target_b,ADDRESS_TAKEN_COARSE_UNIVERSE,LOW"
    )


def test_run_step_d_pr2_without_explicit_facts_file(tmp_path):
    indirect = tmp_path / "syscall_related_indirect_callsites.csv"
    functions_seen = tmp_path / "functions_seen.csv"

    out_address_taken = tmp_path / "address_taken_functions.csv"
    out_normalized = tmp_path / "indirect_callsites_normalized.csv"
    out_facts = tmp_path / "fp_assignment_facts.csv"
    out_candidates = tmp_path / "indirect_candidates_pr2.csv"

    indirect.write_text("tu1.c,caller_a,mem-reg\n")
    functions_seen.write_text("tuX.c,target_a\n")

    n_sites, n_universe, n_facts = run_step_d_pr2(
        syscall_related_indirect_callsites_csv=str(indirect),
        functions_seen_csv=str(functions_seen),
        explicit_fp_facts_csv=None,
        out_address_taken_csv=str(out_address_taken),
        out_normalized_callsites_csv=str(out_normalized),
        out_fp_assignment_facts_csv=str(out_facts),
        out_candidates_csv=str(out_candidates),
    )

    assert (n_sites, n_universe, n_facts) == (1, 1, 0)
    fact_rows = out_facts.read_text().strip().splitlines()
    assert fact_rows == ["fact_id,tu,function,loc,lhs_kind,lhs_key,rhs_function,evidence_kind"]
