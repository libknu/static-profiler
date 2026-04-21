import csv
from pathlib import Path
import shlex
import os

INPUT_CSV = "/home/jiwoo/workspace/out/2.41.bak/indirect_callsites.sorted.csv"
GLIBC_ROOT = Path("/home/jiwoo/workspace/glibc-src/glibc-2.41")
OUTPUT_DIR = Path("./inputs")

OUTPUT_DIR.mkdir(exist_ok=True)


def shell_escape(s: str) -> str:
    return shlex.quote(s)


def parse_loc(loc: str):
    parts = loc.rsplit(":", 2)
    if len(parts) < 2:
        return None, None
    return parts[0], int(parts[1])


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


def make_filename(idx: int, func: str, rel_path: str, line_no: int, bb: str, insn: str):
    func_s = sanitize_filename(func)
    path_s = sanitize_filename(rel_path)
    return f"{idx:06d}_{func_s}_{path_s}_{line_no}_{bb}_{insn}.sh"


def generate_script(idx: int, row):
    tu, func, bb, insn, loc, target = row

    loc_path, line_no = parse_loc(loc)
    rel_path = normalize_path(loc_path if loc_path else tu)

    icall_expr = read_line(rel_path, line_no)

    fname = make_filename(idx, func, rel_path, line_no, bb, insn)
    out_path = OUTPUT_DIR / fname

    content = f"""#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="${{WORKSPACE_ROOT:-$HOME/workspace}}"
PROJECT_ROOT="${{PROJECT_ROOT:-$WORKSPACE_ROOT/glibc-src/glibc-2.41}}"
PYTHON_BIN="${{PYTHON_BIN:-python3}}"

CASE_NAME="$(basename "$0" .sh)"

cd "$WORKSPACE_ROOT"

exec "$PYTHON_BIN" -m LLM_icall_resolver.main \\
  --project-root "$PROJECT_ROOT" \\
  --project glibc \\
  --version glibc-2.41 \\
  --family C \\
  --caller-symbol {shell_escape(func)} \\
  --icall-expr {shell_escape(icall_expr)} \\
  --icall-location {shell_escape(rel_path)} \\
  --max-hops 10 \\
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
