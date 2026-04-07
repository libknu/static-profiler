# static-profiler

GCC RTL 패스 기반 정적 분석 프로젝트입니다.

이 PR 범위의 분석 단계는 **Step B/C까지만** 포함합니다.

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

테스트는 Step B/C만 검증합니다.

## LLM_icall_resolver 사용 가이드

`LLM_icall_resolver` 하위 모듈은 Tree-sitter 기반으로 C 심볼 원문(function/macro)을 추출하고, LLM 기반 간접 호출 해석 그래프를 실행하기 위한 코드입니다.

- 상세 기능 설명/트러블슈팅: `LLM_icall_resolver/README.md`
- 핵심 API: `LLM_icall_resolver.treesitter_retriever.get_symbol_source(...)`

### venv-icall-resolver로 function/macro 추출 테스트

```bash
cd ~/workspace/static-profiler
python -m venv venv-icall-resolver
source venv-icall-resolver/bin/activate
pip install -U pip
pip install -r requirements.txt

cd ~/workspace
PYTHONPATH=$PWD python - <<'PY'
from LLM_icall_resolver.treesitter_retriever import get_symbol_source

print("=== function ===")
text, kind = get_symbol_source(
    "/home/jiwoo/workspace/glibc-src/glibc-2.41",
    "sunrpc/key_call.c",
    "key_call_socket",
    488,
    "function",
)
print(kind)
print(text)

print("\n=== macro ===")
text, kind = get_symbol_source(
    "/home/jiwoo/workspace/glibc-src/glibc-2.41",
    "sunrpc/key_call.c",
    "key_call_private_main",
    390,
    "macro",
)
print(kind)
print(text)
PY
```
