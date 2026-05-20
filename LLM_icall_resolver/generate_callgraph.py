#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def csv_fieldnames() -> list[str]:
    return [
        "caller",
        "callee",
        "run_name",
        "icall_location",
        "icall_line",
        "icall_expr",
        "resolution_status",
        "reason",
    ]


def get_targets(data: dict[str, Any]) -> list[str]:
    targets = data.get("icall_targets") or data.get("candidate_callees") or []
    return [str(target) for target in targets if str(target).strip()]


def iter_edges(outputs_dir: Path):
    for final_path in sorted(outputs_dir.glob("*/final.json")):
        data = load_json(final_path)
        status = data.get("icall_resolution_status")
        if status != "resolved":
            continue

        caller = data.get("caller_symbol")
        if not caller:
            continue

        for callee in get_targets(data):
            yield {
                "caller": str(caller),
                "callee": callee,
                "run_name": final_path.parent.name,
                "icall_location": data.get("icall_location") or "",
                "icall_line": data.get("icall_line") or "",
                "icall_expr": data.get("icall_expr") or "",
                "resolution_status": status,
                "reason": data.get("icall_resolution_reason") or data.get("decision_reason") or "",
            }


def write_csv(path: Path, edges: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fieldnames())
        writer.writeheader()
        writer.writerows(edges)


def dot_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_dot(path: Path, edges: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["digraph icall_callgraph {"]
    for edge in edges:
        label_parts = []
        if edge["icall_location"]:
            label_parts.append(edge["icall_location"])
        if edge["icall_line"]:
            label_parts.append(str(edge["icall_line"]))
        label = ":".join(label_parts)
        attrs = f" [label={dot_quote(label)}]" if label else ""
        lines.append(f"  {dot_quote(edge['caller'])} -> {dot_quote(edge['callee'])}{attrs};")
    lines.append("}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_json_edges(path: Path, edges: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(edges, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build an indirect-call call graph from icall resolver outputs."
    )
    parser.add_argument("outputs_dir", type=Path, help="Directory containing per-run final.json files.")
    parser.add_argument("--csv", type=Path, default=Path("icall_callgraph.csv"))
    parser.add_argument("--dot", type=Path, default=Path("icall_callgraph.dot"))
    parser.add_argument("--json", type=Path, default=Path("icall_callgraph.json"))
    args = parser.parse_args()

    edges = list(iter_edges(args.outputs_dir))
    edges.sort(key=lambda edge: (edge["caller"], edge["callee"], edge["run_name"]))

    write_csv(args.csv, edges)
    write_dot(args.dot, edges)
    write_json_edges(args.json, edges)

    print(f"wrote {len(edges)} edges")
    print(f"csv: {args.csv}")
    print(f"dot: {args.dot}")
    print(f"json: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
