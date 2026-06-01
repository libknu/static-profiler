from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any


def _to_jsonable(obj: Any):
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_jsonable(x) for x in obj]
    return repr(obj)


def write_json(path: str | Path, data: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_to_jsonable(data), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def prepare_output_dir(output_root: str, run_name: str) -> str:
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)

    out_dir = root / run_name

    if out_dir.exists():
        if not sys.stdin.isatty():
            raise SystemExit(
                f"output directory already exists and interactive prompt is unavailable: {out_dir}"
            )

        ans = input(
            f"[LLM_icall_resolver] output dir already exists:\n"
            f"  {out_dir}\n"
            f"Delete it and continue? [y/N]: "
        ).strip().lower()

        if ans not in {"y", "yes"}:
            raise SystemExit("aborted by user")

        shutil.rmtree(out_dir)

    out_dir.mkdir(parents=True, exist_ok=True)
    return str(out_dir)


def save_run_manifest(output_dir: str, manifest: dict) -> None:
    write_json(Path(output_dir) / "run_manifest.json", manifest)


def save_step_artifacts(
    output_dir: str,
    iteration: int,
    prompt_payload: dict,
    prompt_text: str,
    response_payload: dict,
) -> None:
    prompt_path = Path(output_dir) / f"step{iteration}_prompt.json"
    response_path = Path(output_dir) / f"step{iteration}_response.json"

    write_json(
        prompt_path,
        {
            "iteration": iteration,
            "prompt_payload": prompt_payload,
            "prompt_text": prompt_text,
        },
    )
    write_json(response_path, response_payload)


def order_final_result(result: dict) -> dict:
    preferred_order = [
        "project_root",
        "project",
        "version",
        "family",
        "provider",
        "model",
        "caller_symbol",
        "icall_expr",
        "icall_location",
        "icall_line",
        "status",
        "icall_resolution_status",
        "icall_resolved",
        "icall_resolution_reason",
        "icall_targets",
        "candidate_callees",
        "max_hops",
        "max_iterations",
    ]

    ordered = {}
    for key in preferred_order:
        if key in result:
            ordered[key] = result[key]
    for key, value in result.items():
        if key not in ordered:
            ordered[key] = value
    return ordered


def save_final_result(output_dir: str, result: dict) -> None:
    output_dir = Path(output_dir)
    write_json(output_dir / "final.json", order_final_result(result))

    resolution_status = result.get("icall_resolution_status", "failed")
    (output_dir / f"status.{resolution_status}").write_text(
        resolution_status + "\n",
        encoding="utf-8",
    )

    if result.get("icall_resolved"):
        candidates = result.get("icall_targets") or result.get("candidate_callees", [])
        (output_dir / "candidates.list").write_text(
            "\n".join(str(candidate) for candidate in candidates) + "\n",
            encoding="utf-8",
        )
