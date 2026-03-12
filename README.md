# static-profiler

GCC RTL 패스 기반의 정적 분석 파이프라인입니다. 목표는 glibc 함수가 도달 가능한 Linux syscall 집합을 계산하는 것입니다.

예시 결과:

- `open -> {openat}`
- `read -> {read}`
- `printf -> {write}`
- `malloc -> {brk, mmap}`

## 구성 요소

- `plugin/src/plugin.cpp`: GCC RTL 플러그인 (`callsite_plugin`)
- `analysis/indirect_resolver.py`: **Step D** 로컬 간접호출 해석기 (신규)
- `analysis/callgraph_pipeline.py`: 역방향 도달성 + 간접호출 해석을 반복해 엣지 수렴
- `out/2.41/*.csv`: 추출 결과 샘플

## 플러그인이 추출하는 데이터

- `functions_seen.csv`: `tu,function`
- `direct_edges.csv`: `tu,caller,callee`
- `indirect_callsites.csv`: (기본 샘플은 축약 포맷) `tu,caller,target_code`
- `syscall_sites.csv`: `tu,caller,site_kind,callee,syscall_nr`

## Step D: 간접호출 해석 (로컬, intra-procedural)

`analysis/indirect_resolver.py`는 간접 call site 하나에 대해 RTL 명령을 함수 내부에서 역방향 추적해 후보 타깃 **집합**을 반환합니다.

지원 범위:

1. Direct symbol assignment
   - `(set regX (symbol_ref "foo"))`
2. Register copy
   - `(set regY regX)`
3. Stack slot flow
   - `(set (mem slot) regX)` + `(set regY (mem slot))`
4. Conditional/multi reaching defs
   - 가능한 정의를 모두 모아 `{f1, f2, ...}` 반환

비지원:

- 전역 포인터 분석
- inter-procedural points-to
- heap alias 정밀 추론

## 반복 루프

`analysis/callgraph_pipeline.py`에서 다음을 반복합니다.

1. direct edge로 그래프 구성
2. syscall sink 기준 역방향 도달성 계산
3. syscall 경로 관련 indirect site 필터링
4. site별 후보 타깃 집합 해석
5. 새 edge 추가
6. 신규 edge가 없으면 종료

## 빌드 (플러그인)

```bash
make -C plugin
```

## 테스트 (resolver)

```bash
python -m pytest -q
```
