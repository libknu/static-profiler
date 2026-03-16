# static-profiler

GCC RTL 패스 기반 정적 분석 프로젝트입니다.

이 저장소는 Step B/C와 Step D(동일 함수 로컬 resolver)까지 포함합니다.

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


## defuse_events.csv 자동 생성

`defuse_events.csv`가 없으면 아래 둘 중 하나로 생성할 수 있습니다.

1) **GCC plugin 사용 시 자동 생성**
- 최신 plugin은 `outdir` 아래에 `defuse_events.csv`를 함께 기록합니다.
- 또한 `indirect_callsites.csv`에 `insn_uid`, `target_operand` 컬럼을 함께 기록합니다.

2) **RTL dump에서 추출**
```bash
python scripts/run_step_d_defuse_from_rtl.py \
  --rtl-dump path/to/file.expand \
  --tu path/to/file.c \
  --out out/step_d/defuse_events.csv
```

## Step D local resolve 실행

`syscall-reachable indirect callsites.csv`와 `defuse_events.csv`를 입력으로 받아,
동일 함수 안에서만 target operand를 backward trace 합니다.

지원 범위:
- `REG <- SYMBOL_REF(func)` => `direct-symbol`
- `REGa <- REGb` copy chain을 따라가 최종 `SYMBOL_REF(func)`에 도달 => `reg-copy-chain`
- 그 외(memory/merge/unknown/ambiguous 포함) => `unresolved`

제한 사항:
- 인터프로시저 전파 없음
- 포인터/alias 분석 없음
- memory 기반 추적 없음
- 보수적으로 해석 불가 시 즉시 `unresolved`

```bash
python scripts/run_step_d_local_resolve.py \
  --indirect-callsites out/2.41/syscall_related_indirect_callsites.csv \
  --defuse-csv out/2.41/defuse_events.csv \
  --out out/step_d/resolved_indirect_callsites.csv
```

출력 CSV는 입력 컬럼 뒤에 아래 컬럼을 추가합니다.

- `resolution_class` (`direct-symbol`, `reg-copy-chain`, `unresolved`)
- `resolved_target` (resolve 성공 시 함수명, 아니면 빈 값)
- `stop_reason` (unresolved 사유)

## 출력

- `syscall_reachable_functions.csv`
  - 컬럼: `function`
- `syscall_related_indirect_callsites.csv`
  - 입력 `indirect_callsites.csv`의 컬럼을 그대로 보존(헤더가 있으면 헤더도 보존)

## 로컬 테스트

```bash
python -m pytest -q
```

테스트는 Step B/C 및 Step D local resolver 동작을 검증합니다.
