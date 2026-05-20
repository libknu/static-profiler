import csv
from pathlib import Path
import shlex
import os
import re

INPUT_CSV = "/home/jiwoo/workspace/out/2.41.bak/indirect_callsites.sorted.csv"
GLIBC_ROOT = Path("/home/jiwoo/workspace/glibc-src/glibc-2.41")
OUTPUT_DIR = Path("./inputs")

OUTPUT_DIR.mkdir(exist_ok=True)


def shell_escape(s: str) -> str:
    return shlex.quote(s)


STRONG_INDIRECT_CALL_PATTERNS = [
    re.compile(r"^\(\s*\*"),
    re.compile(r"\(\s*\*[^)]*\)\s*\("),
    re.compile(r"\bDL_CALL_FCT\s*\("),
    re.compile(r"\bGL_READDIR\s*\("),
    re.compile(r"\b[A-Z0-9_]+_(?:CALL|GET|PUT|SET|DESTROY|VALIDATE|MARSHALL|REFRESH|SYNC|SEEK|OVERFLOW|PBACKFAIL)\s*\("),
    re.compile(r"->\s*[A-Za-z_]\w*\s*\("),
    re.compile(r"\[[^]]+\]\s*\)\s*\("),
]

WEAK_INDIRECT_CALL_PATTERNS = [
    re.compile(r"(?:^|=|return\s+)\s*(?:fn|fct\d*|end_fct|init|hook|callback|onfct|atfct|cxafct|xargs|proc|dfault)\s*\("),
]


def parse_loc(loc: str):
    parts = loc.rsplit(":", 2)
    if len(parts) < 2:
        return None, None, None
    column = None
    if len(parts) == 3:
        try:
            column = int(parts[2])
        except ValueError:
            column = None
    return parts[0], int(parts[1]), column


def normalize_path(path: str):
    while path.startswith("../"):
        path = path[3:]
    return path


def sanitize_filename(s: str):
    return s.replace("/", "_").replace(".", "_").replace("-", "_")


def resolve_source_path(rel_path: str):
    full = GLIBC_ROOT / rel_path
    if full.exists():
        return full

    name = Path(rel_path).name
    matches = list(GLIBC_ROOT.rglob(name))
    if matches:
        return matches[0]

    return None


def read_line(rel_path: str, line_no: int):
    full = resolve_source_path(rel_path)
    if full is None:
        return "UNKNOWN_CALL"

    try:
        lines = full.read_text(encoding="utf-8", errors="ignore").splitlines()
        if 1 <= line_no <= len(lines):
            return lines[line_no - 1].strip()
    except Exception:
        pass

    return "UNKNOWN_CALL"


def indirect_call_score(line: str) -> int:
    text = line.strip()
    if not text or text.startswith("/*") or text.startswith("*"):
        return 0
    if text.startswith(("if ", "if(", "while ", "while(", "for ", "for(")):
        return 0
    if any(p.search(text) for p in STRONG_INDIRECT_CALL_PATTERNS):
        return 100
    if any(p.search(text) for p in WEAK_INDIRECT_CALL_PATTERNS):
        return 40
    return 0


def looks_like_indirect_call(line: str) -> bool:
    return indirect_call_score(line) > 0


def read_icall_expr(rel_path: str, line_no: int, column: int | None, target: str):
    full = resolve_source_path(rel_path)
    if full is None:
        return "UNKNOWN_CALL"

    try:
        lines = full.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return "UNKNOWN_CALL"

    if not (1 <= line_no <= len(lines)):
        return "UNKNOWN_CALL"

    current = lines[line_no - 1].strip()
    current_score = indirect_call_score(current)
    if current_score >= 100:
        return current

    if target != "unknown":
        start = max(1, line_no - 6)
        end = min(len(lines), line_no + 12)
        best_score = current_score
        best_candidate = current if current_score else ""
        for idx in range(start, end + 1):
            candidate = lines[idx - 1].strip()
            score = indirect_call_score(candidate)
            if score > best_score:
                best_score = score
                best_candidate = candidate
        if best_candidate:
            return best_candidate

    if column:
        suffix = lines[line_no - 1][max(0, column - 1):].strip()
        if looks_like_indirect_call(suffix):
            return suffix

    return current


def make_filename(idx: int, func: str, rel_path: str, line_no: int, bb: str, insn: str):
    func_s = sanitize_filename(func)
    path_s = sanitize_filename(rel_path)
    return f"{idx:06d}_{func_s}_{path_s}_{line_no}_{bb}_{insn}.sh"


def generate_script(idx: int, row):
    tu, func, bb, insn, loc, target = row

    loc_path, line_no, column = parse_loc(loc)
    rel_path = normalize_path(loc_path if loc_path else tu)
    if line_no is None:
        return

    icall_expr = read_icall_expr(rel_path, line_no, column, target)

    fname = make_filename(idx, func, rel_path, line_no, bb, insn)
    out_path = OUTPUT_DIR / fname

    content = f"""#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="${{WORKSPACE_ROOT:-$HOME/workspace}}"
PROJECT_ROOT="${{PROJECT_ROOT:-$WORKSPACE_ROOT/glibc-src/glibc-2.41}}"
PYTHON_BIN="${{PYTHON_BIN:-python3}}"
MODEL_NAME="${{LLM_ICALL_MODEL:-gpt-5.4}}"

CASE_NAME="$(basename "$0" .sh)"

cd "$WORKSPACE_ROOT"

exec "$PYTHON_BIN" -m LLM_icall_resolver.main \\
  --project-root "$PROJECT_ROOT" \\
  --project glibc \\
  --version glibc-2.41 \\
  --family C \\
  --model "$MODEL_NAME" \\
  --caller-symbol {shell_escape(func)} \\
  --icall-expr {shell_escape(icall_expr)} \\
  --icall-location {shell_escape(rel_path)} \\
  --icall-line {line_no} \\
  --max-hops 10 \\
  --max-iterations 10 \\
  --run-name "$CASE_NAME" \\
  --stream
"""

    out_path.write_text(content)
    os.chmod(out_path, 0o755)


def main():
    with open(INPUT_CSV, newline="") as f:
        reader = csv.reader(f)
        for idx, row in enumerate(reader, start=1):
            if len(row) != 6:
                continue
            generate_script(idx, row)


if __name__ == "__main__":
    main()
