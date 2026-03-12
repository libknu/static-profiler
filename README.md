# static-profiler

GCC RTL 패스 기반 정적 분석 프로젝트입니다.

이 PR 범위의 분석 단계는 **Step 1 + Step B/C** 까지 포함합니다.

- Step 1: `direct_edges.csv` 기반 보수적 address-taken 함수 풀 추출
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

## 출력

- `syscall_reachable_functions.csv`
  - 컬럼: `function`
- `syscall_related_indirect_callsites.csv`
  - 입력 `indirect_callsites.csv`의 컬럼을 그대로 보존(헤더가 있으면 헤더도 보존)

## 로컬 테스트

```bash
python -m pytest -q
```

테스트는 Step B/C와 Step 1 추출 로직을 검증합니다.


## Step 1 실행 (address-taken 함수 추출)

```bash
python scripts/run_step1_address_taken.py \
  --direct-edges out/2.41/direct_edges.csv \
  --out-address-taken out/step1/address_taken_functions.csv
```

### Step 1 출력

- `out/step1/address_taken_functions.csv`
  - 컬럼: `tu,function,evidence_kind,evidence_text`
  - 현재 Step 1에서 address-taken으로 간주하는 기준:
    - `direct_edges.csv`에서 `callee`가 `*`로 시작하는 행 (`symbol_ref_star_callee`)
  - `function`은 `*` prefix를 제거한 심볼명으로 정규화
  - 동일 `(tu,function,evidence_kind,evidence_text)`는 중복 제거

### Step 1 비목표 / 제한사항

- 아직 callsite 해석은 하지 않음
- hard/soft 후보 분류 없음
- interprocedural 전파 없음
- `*callee` 기반 규칙은 보수적 휴리스틱이며, "주소가 취해졌다"는 의미를 완전히 증명하지는 않음
