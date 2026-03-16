# static-profiler

GCC RTL 패스 기반 정적 분석 프로젝트입니다.

이 저장소는 Step B/C와 보수적 Step D(exact resolve)까지 포함합니다.

- Step A: GCC 플러그인 추출 (기존/외부)
- Step B: direct edge 역방향 순회로 syscall 도달 가능 함수 집합 계산
- Step C: Step B 결과를 사용해 syscall 관련 indirect callsite만 필터링
- Step D 이후(간접 타깃 해석/반복 고정점)는 **범위 밖**

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


## Step D exact resolve 실행

`indirect_callsites.csv`와 insn-level def/use CSV를 입력으로 받아, 동일 함수 내 최근 def를 역추적해
`SYMBOL_REF(<func>)` 단일값인 경우만 `exact`로 확정합니다.
escape/alias/phi/merge가 관측되거나 정보가 부족하면 `unresolved`로 처리합니다.

```bash
python scripts/run_step_d_exact_resolve.py \
  --indirect-callsites out/2.41/indirect_callsites.csv \
  --defuse-csv out/2.41/defuse_events.csv \
  --out out/step_d/resolved_indirect_callsites.csv
```

출력 CSV는 입력 컬럼 뒤에 아래 컬럼을 추가합니다.

- `resolution_status` (`exact` 또는 `unresolved`)
- `resolved_target` (exact일 때 함수명, 아니면 빈 값)

## 출력

- `syscall_reachable_functions.csv`
  - 컬럼: `function`
- `syscall_related_indirect_callsites.csv`
  - 입력 `indirect_callsites.csv`의 컬럼을 그대로 보존(헤더가 있으면 헤더도 보존)

## 로컬 테스트

```bash
python -m pytest -q
```

테스트는 Step B/C 및 Step D exact resolver 동작을 검증합니다.
