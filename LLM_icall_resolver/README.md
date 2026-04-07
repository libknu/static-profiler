# LLM_icall_resolver

`LLM_icall_resolver`는 Tree-sitter 기반 코드 추출과 LLM 그래프 탐색을 결합해 C 코드의 간접 호출(icmp) 해석을 돕는 모듈입니다.

## 기능별 구성

### 1) Tree-sitter 심볼 원문 추출 (`treesitter_retriever.py`)
- C 파일을 파싱해서 심볼 원문을 찾아옵니다.
- 현재 지원 심볼 종류:
  - `function` → `function_definition`
  - `macro` → `preproc_def`, `preproc_function_def`
- 진입 함수:
  - `get_symbol_source(project_root, relative_path, symbol, line_1_based, ident_kind)`

### 2) 분석 상태 모델 (`state.py`)
- 그래프 탐색에서 사용하는 상태(`project`, `current_symbol`, `observations`, `candidate_callees` 등)를 관리합니다.

### 3) 분석 그래프 구성 (`graph.py`, `analyzer.py`, `bootlin.py`)
- LangGraph로 분석 노드들을 연결하여 간접 호출 해석 과정을 단계적으로 실행합니다.
- Bootlin 식별 정보와 코드 스니펫을 근거로 후보 callee를 좁혀갑니다.

### 4) CLI 실행 (`main.py`)
- 기본 인자(`--project-root`, `--caller-symbol`, `--icall-expr` 등)로 그래프 분석을 실행합니다.
- `--stream`: 중간 업데이트 스트리밍 출력
- `--json`: 최종 상태 JSON 출력

## 환경 준비 (venv-icall-resolver)

아래 예시는 질문에서 주신 `venv-icall-resolver` 기준입니다.

```bash
cd ~/workspace/static-profiler
python -m venv venv-icall-resolver
source venv-icall-resolver/bin/activate
pip install -U pip
pip install -r requirements.txt
```

## 질문 주신 테스트(함수/매크로 추출) 실행 방법

아래처럼 실행하면 `function`/`macro` 각각에 대해 추출 결과를 확인할 수 있습니다.

```bash
cd ~/workspace
source venv-icall-resolver/bin/activate

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

### 기대 결과
- function 구간에서 `function_definition`이 출력되고, `key_call_socket` 함수 본문이 출력됩니다.
- macro 구간에서 `preproc_def`(또는 케이스에 따라 `preproc_function_def`)가 출력되고, 해당 `#define` 한 줄이 출력됩니다.

## 자주 나는 오류
- `ModuleNotFoundError: No module named 'LLM_icall_resolver'`
  - `PYTHONPATH=$PWD`가 빠졌거나, `cd ~/workspace`가 아닌 다른 경로에서 실행한 경우입니다.
- `FileNotFoundError` 또는 `function/macro not found`
  - `project_root`, `relative_path`, `symbol`, `line_1_based`, `ident_kind` 값이 실제 소스와 불일치한 경우입니다.
- `tree-sitter` 관련 import 오류
  - 가상환경 활성화 여부와 `pip install -r requirements.txt` 설치 여부를 먼저 확인하세요.
