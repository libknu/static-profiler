from analysis.step_d_pr3 import build_intra_fp_states, run_step_d_pr3
from analysis.step_d_pr2 import ExplicitFpFact


def test_build_intra_fp_states_merges_by_function_and_fp_symbol():
    facts = [
        ExplicitFpFact("tu1.c", "caller_a", "10:1", "REG", "fp", "foo", "assign"),
        ExplicitFpFact("tu1.c", "caller_a", "11:1", "REG", "fp", "bar", "assign"),
        ExplicitFpFact("tu1.c", "caller_a", "12:1", "REG", "cb", "baz", "assign"),
    ]

    states = build_intra_fp_states(facts)

    assert states[("caller_a", "fp")] == {"foo", "bar"}
    assert states[("caller_a", "cb")] == {"baz"}


def test_run_step_d_pr3_writes_intra_states_and_candidates(tmp_path):
    indirect = tmp_path / "syscall_related_indirect_callsites.csv"
    functions_seen = tmp_path / "functions_seen.csv"
    explicit_facts = tmp_path / "input_fp_facts.csv"

    out_address_taken = tmp_path / "address_taken_functions.csv"
    out_normalized = tmp_path / "indirect_callsites_normalized.csv"
    out_facts = tmp_path / "fp_assignment_facts.csv"
    out_intra_states = tmp_path / "intra_procedural_fp_states.csv"
    out_candidates = tmp_path / "indirect_candidates_pr3.csv"

    indirect.write_text("tu1.c,caller_a,mem-reg\ntu2.c,caller_b,reg\n")
    functions_seen.write_text("tuX.c,foo\ntuY.c,bar\ntuZ.c,baz\n")
    explicit_facts.write_text(
        "tu,function,loc,lhs_kind,lhs_key,rhs_function,evidence_kind\n"
        "tu1.c,caller_a,10:2,REG,fp,foo,assign\n"
        "tu1.c,caller_a,11:2,REG,fp,bar,assign\n"
    )

    n_sites, n_universe, n_facts, n_states = run_step_d_pr3(
        syscall_related_indirect_callsites_csv=str(indirect),
        functions_seen_csv=str(functions_seen),
        explicit_fp_facts_csv=str(explicit_facts),
        out_address_taken_csv=str(out_address_taken),
        out_normalized_callsites_csv=str(out_normalized),
        out_fp_assignment_facts_csv=str(out_facts),
        out_intra_states_csv=str(out_intra_states),
        out_candidates_csv=str(out_candidates),
    )

    assert (n_sites, n_universe, n_facts, n_states) == (2, 3, 2, 1)

    states_rows = out_intra_states.read_text().strip().splitlines()
    assert states_rows == [
        "function,fp_symbol,candidate_count,candidate_set",
        "caller_a,fp,2,bar;foo",
    ]

    rows = out_candidates.read_text().strip().splitlines()
    assert rows[0] == (
        "site_id,enclosing_function,intra_candidate_count,intra_candidates,"
        "soft_candidate_count,soft_candidates,primary_source,confidence"
    )
    assert rows[1] == (
        "cs_000001,caller_a,2,bar;foo,1,baz,INTRA_FLOW,MEDIUM"
    )
    assert rows[2] == (
        "cs_000002,caller_b,0,,3,bar;baz;foo,ADDRESS_TAKEN_COARSE_UNIVERSE,LOW"
    )
