# static-profiler

GCC RTL 패스 기반 정적 분석 프로젝트입니다.

현재 저장소에는 **Step B/C + PR1(D1) + PR2(D2) + PR3(D3)** 까지 포함합니다.

- Step A: GCC 플러그인 추출 (기존/외부)
- Step B: direct edge 역방향 순회로 syscall 도달 가능 함수 집합 계산
- Step C: Step B 결과를 사용해 syscall 관련 indirect callsite만 필터링
- Step D1(PR1): coarse address-taken 후보 유니버스 + callsite 정규화 + 초기 후보 산출
- Step D2(PR2): explicit function-pointer fact 통합 + hard/soft 후보 분리
- Step D3(PR3): intra-procedural candidate state 복원 + INTRA_FLOW 후보 산출
- Step D4 이후는 **범위 밖**

## 입력 데이터

- `direct_edges.csv` (`tu,caller,callee`)
- `syscall_sites.csv` (`tu,function,site_kind,callee,syscall_nr`)
- `indirect_callsites.csv` (기존 포맷 유지; 헤더 유무 모두 처리)

샘플 파일은 `out/2.41/`에 있습니다.

## Step B/C 분석 실행

```bash
python scripts/run_step_bc.py \
  --direct-edges out/2.41/direct_edges.csv \
  --syscall-sites out/2.41/syscall_sites.csv \
  --indirect-callsites out/2.41/indirect_callsites.csv \
  --out-reachable out/step_bc/syscall_reachable_functions.csv \
  --out-related-indirect out/step_bc/syscall_related_indirect_callsites.csv
```

## 출력

- `syscall_reachable_functions.csv`
  - 컬럼: `function`
- `syscall_related_indirect_callsites.csv`
  - 입력 `indirect_callsites.csv`의 컬럼을 그대로 보존(헤더가 있으면 헤더도 보존)

## 로컬 테스트

```bash
python -m pytest -q
```

테스트는 Step B/C만 검증합니다.


## PR1 / Step D1 실행 (coarse address-taken universe)

```bash
python scripts/run_step_d_pr1.py \
  --syscall-related-indirect out/step_bc/syscall_related_indirect_callsites.csv \
  --functions-seen out/2.41/functions_seen.csv \
  --out-address-taken out/step_d/address_taken_functions.csv \
  --out-normalized-callsites out/step_d/indirect_callsites_normalized.csv \
  --out-candidates out/step_d/indirect_candidates_pr1.csv
```

출력:
- `address_taken_functions.csv`: PR1에서의 coarse 후보 유니버스 (`functions_seen.csv` 기반 bootstrap)
- `indirect_callsites_normalized.csv`: callsite 중심 정규화 스키마
- `indirect_candidates_pr1.csv`: 각 callsite에 대한 coarse 후보 집합 (LOW confidence)


## PR2 / Step D2 실행 (explicit function-pointer facts 통합)

```bash
python scripts/run_step_d_pr2.py \
  --syscall-related-indirect out/step_bc/syscall_related_indirect_callsites.csv \
  --functions-seen out/2.41/functions_seen.csv \
  --explicit-fp-facts out/step_d/input_fp_facts.csv \
  --out-address-taken out/step_d/address_taken_functions.csv \
  --out-normalized-callsites out/step_d/indirect_callsites_normalized.csv \
  --out-fp-assignment-facts out/step_d/fp_assignment_facts.csv \
  --out-candidates out/step_d/indirect_candidates_pr2.csv
```

출력:
- `fp_assignment_facts.csv`: explicit function-pointer assignment 정규화 결과
- `indirect_candidates_pr2.csv`: callsite별 hard/soft 후보 집합 + primary source/confidence

`--explicit-fp-facts`를 생략하면 PR2는 PR1 coarse 후보를 유지하고 explicit facts 출력은 헤더만 생성합니다.


## PR3 / Step D3 실행 (intra-procedural candidate recovery)

```bash
python scripts/run_step_d_pr3.py \
  --syscall-related-indirect out/step_bc/syscall_related_indirect_callsites.csv \
  --functions-seen out/2.41/functions_seen.csv \
  --explicit-fp-facts out/step_d/input_fp_facts.csv \
  --out-address-taken out/step_d/address_taken_functions.csv \
  --out-normalized-callsites out/step_d/indirect_callsites_normalized.csv \
  --out-fp-assignment-facts out/step_d/fp_assignment_facts.csv \
  --out-intra-states out/step_d/intra_procedural_fp_states.csv \
  --out-candidates out/step_d/indirect_candidates_pr3.csv
```

출력:
- `intra_procedural_fp_states.csv`: `(function, fp_symbol)`별 intra 후보 집합
- `indirect_candidates_pr3.csv`: callsite별 intra 후보(`INTRA_FLOW`) + soft fallback

현재 callsite-별 fp 심볼 식별자가 없으므로, PR3는 함수 범위 intra 상태를 callsite에 보수적으로 적용합니다.
