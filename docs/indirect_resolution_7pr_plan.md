# Staged 7-PR plan for indirect call resolution refinement

This plan extends the current Step B/C pipeline (syscall-reachable function computation + syscall-related indirect callsite filtering) into a progressive indirect-call resolution workflow.

## PR1 — Address-taken universe + stable per-callsite schema

- **Goal**: Introduce a minimal, stable schema for indirect-callsite-centric analysis and establish the first coarse candidate pool from address-taken functions.
- **New capability**:
  - Parse/extract address-taken functions.
  - Attach the coarse candidate universe to each syscall-related indirect callsite.
- **Expected outputs**:
  - `out/step_d/address_taken_functions.csv`
    - columns: `function,evidence_kind,evidence_loc`
  - `out/step_d/indirect_callsites_normalized.csv`
    - columns: `site_id,tu,function,file,line,raw_indirect_expr`
  - `out/step_d/indirect_candidates_pr1.csv`
    - columns: `site_id,enclosing_function,candidate,source,confidence`
    - initial values: `source=ADDRESS_TAKEN`, `confidence=LOW`
- **Pipeline changes**:
  - Add Step D1 after existing Step B/C outputs.
  - Keep Step B/C logic untouched; consume `syscall_related_indirect_callsites.csv`.
- **Limitations**:
  - Large over-approximation (high false-positive candidate sets).
  - No per-callsite precision yet beyond global address-taken universe.

## PR2 — Explicit function-pointer fact extraction

- **Goal**: Capture high-signal syntactic evidence about function-pointer flow.
- **New capability**:
  - Extract facts for:
    - direct assignments (`fp = foo`)
    - field assignments (`obj->ops.read = foo`)
    - static initializer/table entries
    - returns of function pointers
    - function-pointer arguments passed to calls
- **Expected outputs**:
  - `out/step_d/fp_assignment_facts.csv`
    - columns: `fact_id,tu,function,loc,lhs_kind,lhs_key,rhs_function,evidence_kind`
  - `out/step_d/indirect_candidates_pr2.csv`
    - merged/deduped by `(site_id,candidate)`
    - sources include `EXPLICIT_ASSIGNMENT` and fallback `ADDRESS_TAKEN`
- **Pipeline changes**:
  - Add a fact-extraction stage before candidate assembly.
  - Preserve provenance for each candidate.
- **Limitations**:
  - Mostly syntactic; no real def-use propagation yet.
  - Alias-heavy patterns remain unresolved.

## PR3 — Intra-procedural candidate recovery

- **Goal**: Resolve common within-function patterns via lightweight propagation.
- **New capability**:
  - Intra-procedural value-set propagation for function-pointer variables.
  - Handle patterns like:
    - `fp = foo; fp()`
    - `fp = cond ? foo : bar; fp()`
    - simple reassign/merge cases in one function.
- **Expected outputs**:
  - `out/step_d/intra_procedural_fp_states.csv`
    - columns: `function,program_point,fp_symbol,candidate_set`
  - `out/step_d/indirect_candidates_pr3.csv`
    - adds `source=INTRA_FLOW`, improves per-site precision.
- **Pipeline changes**:
  - Add per-function propagation pass over normalized facts/CFG-like ordering.
  - Candidate merge precedence: `INTRA_FLOW` over earlier coarse sources.
- **Limitations**:
  - No interprocedural flow.
  - Conservative handling for complex control flow and aliasing.

## PR4 — Static table and dispatch-structure linking

- **Goal**: Improve precision for table-driven dispatch.
- **New capability**:
  - Parse static function-pointer arrays/struct initializers/vtable-like objects.
  - Link indirect callsites to concrete table entries when field/index evidence exists.
- **Expected outputs**:
  - `out/step_d/fp_tables.csv`
    - columns: `table_id,tu,symbol,type_name,field_or_index,target_function`
  - `out/step_d/callsite_table_links.csv`
    - columns: `site_id,table_id,link_kind,field_or_index,match_score`
  - `out/step_d/indirect_candidates_pr4.csv`
    - adds `source=TABLE_LINK`
- **Pipeline changes**:
  - Add table inventory stage and table-to-callsite linker.
  - Update merge precedence: `TABLE_LINK > INTRA_FLOW > EXPLICIT_ASSIGNMENT > ADDRESS_TAKEN`.
- **Limitations**:
  - Dynamic table mutation not covered.
  - Requires enough structural metadata to link field/index.

## PR5 — Lightweight interprocedural summaries

- **Goal**: Recover cross-function flows without a full pointer-analysis framework.
- **New capability**:
  - Summary templates for:
    - callback registration APIs
    - pass-through wrappers
    - function-pointer return wrappers
  - Bounded iterative propagation across summaries.
- **Expected outputs**:
  - `out/step_d/function_summaries.csv`
    - columns: `function,summary_kind,in_slot,out_slot,notes`
  - `out/step_d/interproc_propagation.csv`
    - columns: `src,dst,rule,iteration`
  - `out/step_d/indirect_candidates_pr5.csv`
    - adds `source=INTERPROC_SUMMARY`
- **Pipeline changes**:
  - Add summary-builder and bounded fixpoint propagation stage.
  - Keep explainable rule-based propagation (no heavy context sensitivity).
- **Limitations**:
  - Limited pattern coverage.
  - Potential over-approximation for generic wrappers.

## PR6 — Candidate classification + resolution status

- **Goal**: Standardize interpretation of candidate sets for downstream triage.
- **New capability**:
  - Partition candidates into:
    - `hard_candidates` (strong evidence)
    - `soft_candidates` (heuristic/fallback)
  - Assign status labels:
    - `FULLY_RESOLVED_SINGLETON`
    - `FULLY_RESOLVED_SET`
    - `PARTIALLY_RESOLVED`
    - `UNRESOLVED`
- **Expected outputs**:
  - `out/step_d/indirect_resolution_summary.csv`
    - columns: `site_id,enclosing_function,hard_count,soft_count,status,primary_evidence`
  - `out/step_d/indirect_candidates_pr6.csv`
    - includes `is_hard` and `resolution_status`
- **Pipeline changes**:
  - Add classification policy module after candidate aggregation.
  - Document deterministic status rules for repeatability.
- **Limitations**:
  - Hard/soft boundary is policy-based and may need tuning.
  - Not probabilistic confidence yet.

## PR7 — Syscall relevance integration + prioritized final report

- **Goal**: Produce actionable ranking for manual inspection by combining resolution with syscall reachability.
- **New capability**:
  - For each callsite, compute syscall relevance from candidate callees' reachability to syscall sinks.
  - Rank callsites by relevance + confidence + ambiguity.
- **Expected outputs**:
  - `out/final/indirect_syscall_ranked_report.csv`
    - columns: `rank,site_id,enclosing_function,status,hard_candidates,soft_candidates,syscall_relevant_candidates,relevance_score,confidence,notes`
  - `out/final/indirect_syscall_ranked_report.md`
    - human-readable buckets and top-N inspection list.
- **Pipeline changes**:
  - Add final scoring/ranking stage that consumes Step B reachability and Step D resolution outputs.
  - Keep transparent scoring formula with interpretable components.
- **Limitations**:
  - Ranking quality depends on upstream extraction/coverage.
  - Still conservative for dynamic features not modeled in prior steps.

## Why this sequence is review-friendly

1. Starts with schema + coarse baseline (PR1).
2. Adds one precision mechanism at a time (PR2–PR5).
3. Adds explicit interpretation layer (PR6).
4. Ends with end-user prioritization output (PR7).

Each PR yields visible CSV artifacts and can be diff-validated independently.
