from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .analyzer import DEFAULT_MODEL_NAME, JSON_SCHEMA, SYSTEM_PROMPT, build_step_prompt_payload, render_step_prompt
from .graph import (
    classify_icall_resolution,
    classify_jump_kind,
    expand_reference_candidates,
    fail,
    finish,
    index_symbol,
    jump_symbol,
    summarize_icall_resolution,
    retrieve_block,
)
from .main import DEFAULT_OUTPUT_ROOT, build_initial_state, sanitize_name
from .trace_store import save_final_result, save_run_manifest, save_step_artifacts, write_json


ADD_LIST_FIELDS = {
    "macro_context",
    "struct_context",
    "assignment_context",
    "initializer_context",
    "reference_jump_candidates",
    "retrieved_chunks",
    "observations",
    "candidate_callees",
    "visited_symbols",
    "visible_trace",
}

PACKAGE_ROOT = Path(__file__).resolve().parent
MAX_ROUNDS_DEFAULT = 30


@dataclass
class Case:
    run_name: str
    state: dict[str, Any]
    done: bool = False
    resumed_steps: int = 0


def merge_state(state: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    merged = dict(state)
    for key, value in update.items():
        if key in ADD_LIST_FIELDS:
            merged[key] = list(merged.get(key, [])) + list(value or [])
        else:
            merged[key] = value
    return merged


def parse_input_script(path: Path, workspace_root: Path, project_root: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    command_text = text.replace("\\\n", " ")
    marker = "LLM_icall_resolver.main"
    if marker not in command_text:
        raise ValueError(f"could not find {marker} invocation")

    tail = command_text.split(marker, 1)[1]
    tokens = shlex.split(tail)

    values = {
        "project_root": str(project_root),
        "project": "glibc",
        "version": "glibc-2.41",
        "family": "C",
        "model": DEFAULT_MODEL_NAME,
        "caller_symbol": None,
        "icall_expr": None,
        "icall_location": None,
        "icall_line": infer_icall_line_from_name(path.stem),
        "max_hops": 10,
        "max_iterations": 10,
        "run_name": path.stem,
        "output_root": DEFAULT_OUTPUT_ROOT,
    }

    i = 0
    while i < len(tokens):
        token = tokens[i]
        if not token.startswith("--"):
            i += 1
            continue
        key = token[2:].replace("-", "_")
        if key in {"stream", "json"}:
            i += 1
            continue
        if i + 1 >= len(tokens):
            break
        value = tokens[i + 1]
        if key == "project_root" and "$PROJECT_ROOT" in value:
            value = str(project_root)
        elif key == "run_name" and "$CASE_NAME" in value:
            value = path.stem
        elif key == "output_root" and "$WORKSPACE_ROOT" in value:
            value = value.replace("$WORKSPACE_ROOT", str(workspace_root))
        if key in {"max_hops", "max_iterations", "icall_line"}:
            value = int(value)
        if key in values:
            values[key] = value
        i += 2

    missing = [key for key in ("caller_symbol", "icall_expr", "icall_location") if not values[key]]
    if missing:
        raise ValueError(f"missing required arguments in {path.name}: {', '.join(missing)}")

    return values


def infer_icall_line_from_name(name: str) -> int | None:
    parts = name.rsplit("_", 3)
    if len(parts) != 4:
        return None
    line, bb, insn = parts[1:]
    if line.isdigit() and bb.isdigit() and insn.isdigit():
        return int(line)
    return None


def make_args(values: dict[str, Any]):
    return argparse.Namespace(**values)


def load_case_names(case_file: Path | None) -> set[str] | None:
    if case_file is None:
        return None
    names: set[str] = set()
    for line in case_file.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        names.add(text.split(",", 1)[0].strip())
    return names


def summarize_case_statuses(cases: list[Case]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for case in cases:
        if case.done:
            counts["done"] += 1
        else:
            counts["pending"] += 1
        status = case.state.get("icall_resolution_status") or "unknown"
        counts[f"icall_{status}"] += 1
    return counts


def preview_case_names(cases: list[Case], limit: int = 5) -> str:
    names = [case.run_name for case in cases[:limit]]
    if not names:
        return "-"
    if len(cases) > limit:
        return ", ".join(names) + f", ... (+{len(cases) - limit} more)"
    return ", ".join(names)


def load_existing_final(output_dir: Path) -> dict[str, Any] | None:
    final_path = output_dir / "final.json"
    if not final_path.exists():
        return None
    try:
        return json.loads(final_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def is_resolved_final(data: dict[str, Any] | None) -> bool:
    if not data:
        return False
    return (
        data.get("icall_resolution_status") == "resolved"
        or bool(data.get("icall_resolved"))
        or bool(data.get("icall_targets"))
    )


def archive_existing_output(output_dir: Path) -> Path:
    base_name = f"old.{output_dir.name}"
    archive_dir = output_dir.with_name(base_name)
    if not archive_dir.exists():
        shutil.move(str(output_dir), str(archive_dir))
        return archive_dir

    index = 1
    while True:
        candidate = output_dir.with_name(f"{base_name}.{index}")
        if not candidate.exists():
            shutil.move(str(output_dir), str(candidate))
            return candidate
        index += 1


def prepare_case_output(
    output_root: Path,
    run_name: str,
    overwrite: bool,
    skip_existing: bool,
    skip_resolved: bool = False,
    archive_existing: bool = False,
) -> str | None:
    output_dir = output_root / run_name
    if output_dir.exists():
        existing_final = load_existing_final(output_dir)
        if skip_resolved and is_resolved_final(existing_final):
            return None
        if skip_existing and existing_final is not None:
            return None
        if overwrite:
            shutil.rmtree(output_dir)
        elif archive_existing and existing_final is not None:
            archive_existing_output(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return str(output_dir)


def initialize_cases(
    inputs_dir: Path,
    output_root: Path,
    workspace_root: Path,
    project_root: Path,
    limit: int | None,
    overwrite: bool,
    skip_existing: bool,
    skip_resolved: bool,
    archive_existing: bool,
    case_names: set[str] | None,
    model: str,
    max_iterations: int,
) -> list[Case]:
    cases: list[Case] = []
    scripts = sorted(inputs_dir.glob("*.sh"))
    if limit is not None:
        scripts = scripts[:limit]

    for script in scripts:
        run_name = sanitize_name(script.stem)
        if case_names is not None and run_name not in case_names:
            continue
        try:
            values = parse_input_script(script, workspace_root=workspace_root, project_root=project_root)
        except ValueError as exc:
            output_dir = prepare_case_output(
                output_root=output_root,
                run_name=run_name,
                overwrite=overwrite,
                skip_existing=skip_existing,
                skip_resolved=skip_resolved,
                archive_existing=archive_existing,
            )
            if output_dir is None:
                continue
            state = {
                "project_root": str(project_root),
                "project": "glibc",
                "version": "glibc-2.41",
                "family": "C",
                "model": model,
                "caller_symbol": "",
                "icall_expr": "",
                "icall_location": "",
                "icall_line": None,
                "visited_symbols": [],
                "retrieved_chunks": [],
                "observations": [str(exc)],
                "visible_trace": [],
                "candidate_callees": [],
                "macro_context": [],
                "struct_context": [],
                "assignment_context": [],
                "initializer_context": [],
                "hop_count": 0,
                "iteration": 0,
                "max_hops": 0,
                "max_iterations": 10,
                "status": "failed",
                "icall_resolution_status": "failed",
                "icall_resolved": False,
                "icall_resolution_reason": str(exc),
                "icall_targets": [],
                "bootlin_references": [],
                "reference_jump_candidates": [],
                "run_name": run_name,
                "output_root": str(output_root),
                "output_dir": output_dir,
                "final_answer": str(exc),
            }
            save_run_manifest(
                output_dir,
                {
                    "run_name": run_name,
                    "input_script": str(script),
                    "parse_error": str(exc),
                    "initial_state": state,
                    "runner": "run_all_batch",
                },
            )
            save_final_result(output_dir, state)
            cases.append(Case(run_name=run_name, state=state, done=True))
            continue

        values["model"] = model
        values["max_iterations"] = max_iterations
        run_name = sanitize_name(values["run_name"])
        if case_names is not None and run_name not in case_names:
            continue
        output_dir = prepare_case_output(
            output_root=output_root,
            run_name=run_name,
            overwrite=overwrite,
            skip_existing=skip_existing,
            skip_resolved=skip_resolved,
            archive_existing=archive_existing,
        )
        if output_dir is None:
            continue

        values["run_name"] = run_name
        values["output_root"] = str(output_root)
        args = make_args(values)
        state = build_initial_state(args, run_name=run_name, output_dir=output_dir)
        save_run_manifest(
            output_dir,
            {
                "run_name": run_name,
                "input_script": str(script),
                "args": vars(args),
                "initial_state": state,
                "runner": "run_all_batch",
            },
        )
        case = Case(run_name=run_name, state=state)
        if not overwrite:
            replay_existing_steps(case)
        cases.append(case)

    return cases


def _step_response_iteration(path: Path) -> int:
    stem = path.stem
    if stem.startswith("step") and stem.endswith("_response"):
        return int(stem.removeprefix("step").removesuffix("_response"))
    return 0


def replay_existing_steps(case: Case) -> None:
    output_dir = Path(case.state["output_dir"])
    step_paths = sorted(
        output_dir.glob("step*_response.json"),
        key=_step_response_iteration,
    )

    for step_path in step_paths:
        if case.done:
            break

        step_payload = json.loads(step_path.read_text(encoding="utf-8"))
        llm_output = step_payload.get("llm_output")
        if not llm_output:
            break

        expected_iteration = case.state.get("iteration", 0) + 1
        if step_payload.get("iteration") != expected_iteration:
            break

        snapshot = step_payload.get("state_snapshot") or {}
        case.state.update(
            {
                key: value
                for key, value in snapshot.items()
                if key
                in {
                    "current_symbol",
                    "caller_symbol",
                    "icall_expr",
                    "icall_location",
                    "icall_line",
                    "current_path",
                    "current_line",
                    "current_kind",
                    "hop_count",
                    "max_iterations",
                    "visited_symbols",
                    "reference_jump_candidates",
                }
            }
        )

        trace_item = {
            "iteration": expected_iteration,
            "step": case.state.get("hop_count", 0),
            "focus_symbol": case.state.get("current_symbol"),
            "decision": llm_output["decision"],
            "next_symbol": llm_output["next_symbol"],
            "summary": llm_output["analysis_summary"],
            "evidence": llm_output["evidence"],
            "candidate_callees": llm_output["candidate_callees"],
            "resolved": llm_output.get("resolved", bool(llm_output["candidate_callees"])),
            "jump_kind": step_payload.get("jump_kind"),
            "grounded_sources": step_payload.get("grounded_sources", []),
            "selected_from_reference_candidates": step_payload.get(
                "selected_from_reference_candidates",
                False,
            ),
        }

        case.state = merge_state(
            case.state,
            {
                "iteration": expected_iteration,
                "decision": llm_output["decision"],
                "decision_reason": llm_output["analysis_summary"],
                "next_symbol": llm_output["next_symbol"],
                "candidate_callees": llm_output["candidate_callees"],
                "icall_resolution_status": step_payload.get("icall_resolution_status", "unresolved"),
                "icall_resolved": step_payload.get("icall_resolved", False),
                "icall_resolution_reason": step_payload.get("icall_resolution_reason", ""),
                "icall_targets": step_payload.get("icall_targets", []),
                "observations": llm_output["evidence"],
                "visible_trace": [trace_item],
                "status": "resolved" if llm_output["decision"] == "finish" else "running",
            },
        )

        if case.state.get("decision") == "finish":
            case.state = merge_state(case.state, finish(case.state))
            case.done = True
            save_final_result(case.state["output_dir"], case.state)
        elif case.state.get("decision") == "jump":
            case.state = merge_state(case.state, jump_symbol(case.state))
            if case.state.get("status") == "failed":
                case.state = merge_state(case.state, fail(case.state))
                case.done = True
                save_final_result(case.state["output_dir"], case.state)
        else:
            case.state = merge_state(case.state, {"status": "failed", "final_answer": "LLM returned fail decision"})
            case.state = merge_state(case.state, fail(case.state))
            case.done = True
            save_final_result(case.state["output_dir"], case.state)

        case.resumed_steps += 1


def run_local_until_llm(case: Case) -> None:
    state = case.state
    if state.get("status") == "failed":
        case.state = merge_state(state, fail(state))
        save_final_result(case.state["output_dir"], case.state)
        case.done = True
        return

    if state.get("iteration", 0) >= state.get("max_iterations", 10):
        state = merge_state(
            state,
            {
                "status": "failed",
                "final_answer": (
                    f"max iterations exceeded: iteration={state.get('iteration', 0)} "
                    f"max_iterations={state.get('max_iterations', 10)}"
                ),
            },
        )
        case.state = merge_state(state, fail(state))
        save_final_result(case.state["output_dir"], case.state)
        case.done = True
        return

    for node in (index_symbol, retrieve_block):
        state = merge_state(state, node(state))
        if state.get("status") == "failed":
            state = merge_state(state, fail(state))
            case.state = state
            save_final_result(state["output_dir"], state)
            case.done = True
            return

    state = merge_state(state, expand_reference_candidates(state))
    case.state = state


def run_local_until_llm_many(cases: list[Case], workers: int) -> None:
    pending = [case for case in cases if not case.done]
    if not pending:
        return
    total = len(pending)
    workers = max(1, workers)
    if workers == 1 or len(pending) == 1:
        print(f"local prepare: workers=1 cases={total}", flush=True)
        started_at = time.monotonic()
        for case in pending:
            case_started_at = time.monotonic()
            run_local_until_llm(case)
            completed = pending.index(case) + 1
            elapsed = time.monotonic() - case_started_at
            total_elapsed = time.monotonic() - started_at
            print(
                f"local prepare: completed={completed}/{total} "
                f"status={case.state.get('status')} elapsed={elapsed:.1f}s "
                f"total_elapsed={total_elapsed:.1f}s case={case.run_name}",
                flush=True,
            )
        return

    workers = min(workers, len(pending))
    print(f"local prepare: workers={workers} cases={total}", flush=True)
    completed = 0
    started_at = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_case = {executor.submit(run_local_until_llm, case): (case, time.monotonic()) for case in pending}
        for future in as_completed(future_to_case):
            case, case_started_at = future_to_case[future]
            try:
                future.result()
            except Exception as exc:
                state = merge_state(
                    case.state,
                    {
                        "status": "failed",
                        "final_answer": f"local prepare failed: {exc}",
                    },
                )
                case.state = merge_state(state, fail(state))
                case.done = True
                save_final_result(case.state["output_dir"], case.state)
                print(f"local prepare failed: {case.run_name}: {exc}", flush=True)
            completed += 1
            elapsed = time.monotonic() - case_started_at
            total_elapsed = time.monotonic() - started_at
            print(
                f"local prepare: completed={completed}/{total} "
                f"status={case.state.get('status')} elapsed={elapsed:.1f}s "
                f"total_elapsed={total_elapsed:.1f}s case={case.run_name}",
                flush=True,
            )


def build_batch_request(case: Case) -> tuple[str, dict[str, Any], str, str]:
    state = case.state
    model = state.get("model") or DEFAULT_MODEL_NAME
    iteration = state.get("iteration", 0) + 1
    custom_id = f"{case.run_name}::step{iteration}"
    prompt_payload = build_step_prompt_payload(state)
    prompt_text = render_step_prompt(prompt_payload)
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt_text},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "resolver_decision",
                "schema": JSON_SCHEMA,
            },
        },
        "temperature": 0.0,
    }
    request = {
        "custom_id": custom_id,
        "method": "POST",
        "url": "/v1/chat/completions",
        "body": body,
    }
    return custom_id, request, prompt_text, prompt_payload


def submit_batch(client: OpenAI, batch_dir: Path, requests: list[dict[str, Any]], round_no: int):
    batch_dir.mkdir(parents=True, exist_ok=True)
    input_path = write_batch_input(batch_dir=batch_dir, requests=requests, round_no=round_no)

    with input_path.open("rb") as f:
        uploaded = client.files.create(file=f, purpose="batch")

    batch = client.batches.create(
        input_file_id=uploaded.id,
        endpoint="/v1/chat/completions",
        completion_window="24h",
        metadata={"runner": "LLM_icall_resolver.run_all", "round": str(round_no)},
    )
    write_json(batch_dir / f"round{round_no:03d}_batch.json", batch.model_dump())
    return batch, input_path


def write_batch_input(batch_dir: Path, requests: list[dict[str, Any]], round_no: int) -> Path:
    batch_dir.mkdir(parents=True, exist_ok=True)
    input_path = batch_dir / f"round{round_no:03d}_input.jsonl"
    with input_path.open("w", encoding="utf-8") as f:
        for request in requests:
            f.write(json.dumps(request, ensure_ascii=False) + "\n")
    return input_path


def wait_for_batch(client: OpenAI, batch_id: str, poll_seconds: int):
    terminal = {"completed", "failed", "expired", "cancelled"}
    while True:
        batch = client.batches.retrieve(batch_id)
        print(
            f"batch={batch.id} status={batch.status} "
            f"completed={getattr(batch.request_counts, 'completed', 0) if batch.request_counts else 0} "
            f"failed={getattr(batch.request_counts, 'failed', 0) if batch.request_counts else 0}",
            flush=True,
        )
        if batch.status in terminal:
            return batch
        time.sleep(poll_seconds)


def response_text(file_response: Any) -> str:
    if hasattr(file_response, "text"):
        text_attr = file_response.text
        return text_attr() if callable(text_attr) else text_attr
    if hasattr(file_response, "read"):
        data = file_response.read()
        return data.decode("utf-8") if isinstance(data, bytes) else data
    if isinstance(file_response, bytes):
        return file_response.decode("utf-8")
    return str(file_response)


def fetch_batch_outputs(client: OpenAI, batch: Any, batch_dir: Path, round_no: int) -> dict[str, dict[str, Any]]:
    if batch.status != "completed":
        raise RuntimeError(f"batch did not complete: {batch.id} status={batch.status}")
    if not batch.output_file_id:
        raise RuntimeError(f"batch completed without output_file_id: {batch.id}")

    content = response_text(client.files.content(batch.output_file_id))
    output_path = batch_dir / f"round{round_no:03d}_output.jsonl"
    output_path.write_text(content, encoding="utf-8")

    outputs: dict[str, dict[str, Any]] = {}
    for line in content.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        outputs[item["custom_id"]] = item
    return outputs


def extract_llm_output(batch_item: dict[str, Any]) -> dict[str, Any]:
    error = batch_item.get("error")
    if error:
        raise RuntimeError(error)
    response = batch_item.get("response") or {}
    body = response.get("body") or {}
    choices = body.get("choices") or []
    if not choices:
        raise RuntimeError(f"missing choices in batch response: {batch_item}")
    content = choices[0]["message"]["content"]
    return json.loads(content)


def apply_llm_result(case: Case, llm_output: dict[str, Any], prompt_payload: dict[str, Any], prompt_text: str) -> None:
    state = case.state
    iteration = state.get("iteration", 0) + 1
    icall_targets = list(dict.fromkeys(llm_output["candidate_callees"]))
    icall_resolved = bool(icall_targets)
    icall_resolution_reason = summarize_icall_resolution(
        icall_targets,
        llm_output["analysis_summary"],
    )
    icall_resolution_status = classify_icall_resolution(
        icall_targets,
        llm_output["analysis_summary"],
    )
    jump_kind, grounded_sources = classify_jump_kind(state, llm_output.get("next_symbol"))
    selected_from_reference_candidates = llm_output.get("next_symbol") in {
        c.get("symbol") for c in state.get("reference_jump_candidates", []) if c.get("symbol")
    }

    trace_item = {
        "iteration": iteration,
        "step": state.get("hop_count", 0),
        "focus_symbol": state.get("current_symbol"),
        "decision": llm_output["decision"],
        "next_symbol": llm_output["next_symbol"],
        "summary": llm_output["analysis_summary"],
        "evidence": llm_output["evidence"],
        "candidate_callees": llm_output["candidate_callees"],
        "resolved": llm_output.get("resolved", bool(llm_output["candidate_callees"])),
        "jump_kind": jump_kind,
        "grounded_sources": grounded_sources,
        "selected_from_reference_candidates": selected_from_reference_candidates,
    }

    save_step_artifacts(
        output_dir=state["output_dir"],
        iteration=iteration,
        prompt_payload=prompt_payload,
        prompt_text=prompt_text,
        response_payload={
            "iteration": iteration,
            "model": state.get("model") or DEFAULT_MODEL_NAME,
            "icall_resolved": icall_resolved,
            "icall_resolution_status": icall_resolution_status,
            "icall_resolution_reason": icall_resolution_reason,
            "icall_targets": icall_targets,
            "llm_output": llm_output,
            "jump_kind": jump_kind,
            "grounded_sources": grounded_sources,
            "selected_from_reference_candidates": selected_from_reference_candidates,
            "state_snapshot": {
                "current_symbol": state.get("current_symbol"),
                "caller_symbol": state.get("caller_symbol"),
                "icall_expr": state.get("icall_expr"),
                "icall_location": state.get("icall_location"),
                "icall_line": state.get("icall_line"),
                "current_path": state.get("current_path"),
                "current_line": state.get("current_line"),
                "current_kind": state.get("current_kind"),
                "hop_count": state.get("hop_count", 0),
                "max_iterations": state.get("max_iterations", 10),
                "visited_symbols": state.get("visited_symbols", []),
                "reference_jump_candidates": state.get("reference_jump_candidates", []),
            },
        },
    )

    update = {
        "iteration": iteration,
        "decision": llm_output["decision"],
        "decision_reason": llm_output["analysis_summary"],
        "next_symbol": llm_output["next_symbol"],
        "candidate_callees": llm_output["candidate_callees"],
        "icall_resolution_status": icall_resolution_status,
        "icall_resolved": icall_resolved,
        "icall_resolution_reason": icall_resolution_reason,
        "icall_targets": icall_targets,
        "observations": llm_output["evidence"],
        "visible_trace": [trace_item],
        "status": "resolved" if llm_output["decision"] == "finish" else "running",
    }
    state = merge_state(state, update)

    if state.get("decision") == "finish":
        state = merge_state(state, finish(state))
        case.done = True
        save_final_result(state["output_dir"], state)
    elif state.get("decision") == "jump":
        state = merge_state(state, jump_symbol(state))
        if state.get("status") == "failed":
            state = merge_state(state, fail(state))
            case.done = True
            save_final_result(state["output_dir"], state)
    else:
        state = merge_state(state, {"status": "failed", "final_answer": "LLM returned fail decision"})
        state = merge_state(state, fail(state))
        case.done = True
        save_final_result(state["output_dir"], state)

    case.state = state


def mark_batch_error(case: Case, error: str) -> None:
    state = merge_state(case.state, {"status": "failed", "final_answer": error})
    state = merge_state(state, fail(state))
    case.state = state
    case.done = True
    save_final_result(state["output_dir"], state)


def run_all(args: argparse.Namespace) -> None:
    workspace_root = args.workspace_root.expanduser().resolve()
    project_root = args.project_root.expanduser().resolve()
    output_root = args.output_root.expanduser().resolve()
    batch_dir = args.batch_dir.expanduser().resolve()
    inputs_dir = args.inputs_dir.expanduser()
    if not inputs_dir.is_absolute():
        inputs_dir = (PACKAGE_ROOT / inputs_dir).resolve()
    case_names = load_case_names(args.cases_file.expanduser().resolve()) if args.cases_file else None

    cases = initialize_cases(
        inputs_dir=inputs_dir,
        output_root=output_root,
        workspace_root=workspace_root,
        project_root=project_root,
        limit=args.limit,
        overwrite=args.overwrite,
        skip_existing=(not args.no_skip_existing) and (not args.rerun_unresolved),
        skip_resolved=args.rerun_unresolved,
        archive_existing=args.rerun_unresolved and not args.overwrite,
        case_names=case_names,
        model=args.model,
        max_iterations=args.max_iterations,
    )
    print(f"loaded {len(cases)} case(s)")
    resumed_steps = sum(case.resumed_steps for case in cases)
    if resumed_steps:
        resumed_cases = sum(1 for case in cases if case.resumed_steps)
        print(f"resumed {resumed_steps} saved step(s) across {resumed_cases} case(s)")
    status_counts = summarize_case_statuses(cases)
    print(
        "initial status: "
        f"pending={status_counts['pending']} done={status_counts['done']} "
        f"resolved={status_counts['icall_resolved']} "
        f"unresolved={status_counts['icall_unresolved']} "
        f"not_icall={status_counts['icall_not_icall']} "
        f"failed={status_counts['icall_failed']}"
    )
    if not cases:
        print("no cases to run")
        return

    if args.prepare_only:
        run_local_until_llm_many(cases, args.local_workers)
        pending = [case for case in cases if not case.done]
        requests = [build_batch_request(case)[1] for case in pending]
        input_path = write_batch_input(batch_dir=batch_dir, requests=requests, round_no=1)
        print(f"prepared batch input without submitting: {input_path}")
        print(f"requests: {len(requests)}")
        return

    try:
        from openai import OpenAI
    except ModuleNotFoundError as exc:
        raise SystemExit("openai package is required to submit Batch API jobs") from exc

    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

    round_no = 1
    while True:
        if round_no > args.max_rounds:
            pending = [case for case in cases if not case.done]
            print(
                f"stopping because round limit was reached: max_rounds={args.max_rounds} "
                f"pending={len(pending)}"
            )
            break

        pending = [case for case in cases if not case.done]
        if not pending:
            break

        round_status = summarize_case_statuses(cases)
        print(
            f"round {round_no}/{args.max_rounds}: "
            f"pending={round_status['pending']} done={round_status['done']} "
            f"resolved={round_status['icall_resolved']} "
            f"unresolved={round_status['icall_unresolved']} "
            f"not_icall={round_status['icall_not_icall']} "
            f"failed={round_status['icall_failed']}"
        )
        print(f"round {round_no}: pending preview: {preview_case_names(pending)}")
        run_local_until_llm_many(pending, args.local_workers)

        pending = [case for case in cases if not case.done]
        if not pending:
            print(f"round {round_no}: all cases completed locally before batch submission")
            break

        requests = []
        request_context: dict[str, tuple[Case, dict[str, Any], str]] = {}
        for case in pending:
            custom_id, request, prompt_text, prompt_payload = build_batch_request(case)
            requests.append(request)
            request_context[custom_id] = (case, prompt_payload, prompt_text)

        batch, input_path = submit_batch(
            client=client,
            batch_dir=batch_dir,
            requests=requests,
            round_no=round_no,
        )
        print(
            f"submitted round {round_no}: batch={batch.id} "
            f"requests={len(requests)} input={input_path}"
        )

        if args.submit_only:
            print("submit-only mode: stopping after first batch submission")
            return

        batch = wait_for_batch(client, batch.id, args.poll_seconds)
        outputs = fetch_batch_outputs(client, batch, batch_dir=batch_dir, round_no=round_no)
        print(
            f"round {round_no}: batch completed status={batch.status} "
            f"output_file={batch.output_file_id} "
            f"request_counts="
            f"completed={getattr(batch.request_counts, 'completed', 0) if batch.request_counts else 0}, "
            f"failed={getattr(batch.request_counts, 'failed', 0) if batch.request_counts else 0}, "
            f"total={getattr(batch.request_counts, 'total', 0) if batch.request_counts else 0}"
        )

        for custom_id, (case, prompt_payload, prompt_text) in request_context.items():
            item = outputs.get(custom_id)
            if item is None:
                mark_batch_error(case, f"missing batch output for {custom_id}")
                continue
            try:
                llm_output = extract_llm_output(item)
                apply_llm_result(case, llm_output, prompt_payload, prompt_text)
            except Exception as exc:
                mark_batch_error(case, f"batch response processing failed for {custom_id}: {exc}")

        round_status = summarize_case_statuses(cases)
        print(
            f"round {round_no}: post-apply pending={round_status['pending']} done={round_status['done']} "
            f"resolved={round_status['icall_resolved']} "
            f"unresolved={round_status['icall_unresolved']} "
            f"not_icall={round_status['icall_not_icall']} "
            f"failed={round_status['icall_failed']}"
        )
        round_no += 1

    print("done")
    print(f"completed cases: {sum(1 for case in cases if case.done)}")
    print(f"outputs: {output_root}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run all generated input cases using OpenAI Batch API for LLM calls."
    )
    parser.add_argument("--inputs-dir", type=Path, default=Path("inputs"))
    parser.add_argument("--output-root", type=Path, default=Path(DEFAULT_OUTPUT_ROOT))
    parser.add_argument("--batch-dir", type=Path, default=Path("outputs/_batches"))
    parser.add_argument("--workspace-root", type=Path, default=Path("~/workspace"))
    parser.add_argument("--project-root", type=Path, default=Path("~/workspace/glibc-src/glibc-2.41"))
    parser.add_argument("--model", default=os.environ.get("LLM_ICALL_MODEL", DEFAULT_MODEL_NAME))
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--poll-seconds", type=int, default=60)
    parser.add_argument("--max-rounds", type=int, default=MAX_ROUNDS_DEFAULT)
    parser.add_argument("--max-iterations", type=int, default=10)
    parser.add_argument(
        "--local-workers",
        type=int,
        default=4,
        help="number of parallel workers for local retrieval before each Batch API round",
    )
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--submit-only", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument(
        "--no-skip-existing",
        action="store_true",
        help="include runs that already have final.json unless --overwrite is also used",
    )
    parser.add_argument(
        "--rerun-unresolved",
        action="store_true",
        help=(
            "skip runs whose existing final.json is resolved, archive the remaining "
            "existing outputs under old.<run_name>, and rerun them"
        ),
    )
    parser.add_argument(
        "--cases-file",
        type=Path,
        default=None,
        help="optional file with one run_name per line to limit the cases that are loaded",
    )
    args = parser.parse_args()
    run_all(args)


if __name__ == "__main__":
    main()
