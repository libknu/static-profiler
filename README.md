# static-profiler

GCC RTL 패스 기반 정적 분석 프로젝트입니다.

현재 저장소에는 **Step B/C + PR1(=Step D1)** 까지 포함합니다.

- Step A: GCC 플러그인 추출 (기존/외부)
- Step B: direct edge 역방향 순회로 syscall 도달 가능 함수 집합 계산
- Step C: Step B 결과를 사용해 syscall 관련 indirect callsite만 필터링
- Step D1(PR1): coarse address-taken 후보 유니버스 + callsite 정규화 + 초기 후보 산출
- Step D2 이후는 **범위 밖**

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
