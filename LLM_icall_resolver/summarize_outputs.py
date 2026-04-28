#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


RESOLUTION_STATUSES = ("resolved", "unresolved", "not_icall", "failed")


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def has_candidates(data: dict[str, Any]) -> bool:
    return bool(data.get("icall_targets") or data.get("candidate_callees"))


def looks_not_icall(data: dict[str, Any]) -> bool:
    text_parts = [
        data.get("icall_resolution_reason", ""),
        data.get("decision_reason", ""),
        data.get("final_answer", ""),
    ]
    for item in data.get("visible_trace", []):
        text_parts.append(item.get("summary", ""))
        text_parts.extend(item.get("evidence", []))

    text = "\n".join(str(part) for part in text_parts).lower()
    not_icall_markers = (
        "not an indirect call",
        "not a call",
        "not a function pointer",
        "no function pointer",
        "conditional, not a call",
        "conditional expression rather than a call",
        "does not introduce indirect dispatch",
        "no indirect dispatch",
        "non-indirect",
    )
    return any(marker in text for marker in not_icall_markers)


def classify_result(data: dict[str, Any]) -> str:
    explicit = data.get("icall_resolution_status")
    if explicit in RESOLUTION_STATUSES:
        return explicit

    if data.get("status") == "failed":
        return "failed"
    if data.get("icall_resolved") or has_candidates(data):
        return "resolved"
    if looks_not_icall(data):
        return "not_icall"
    return "unresolved"


def get_reason(data: dict[str, Any] | None, error: str | None) -> str:
    if error:
        return error
    if not data:
        return ""

    reason = data.get("icall_resolution_reason")
    if reason:
        return str(reason).replace("\n", " ")

    if data.get("status") == "failed":
        return str(data.get("final_answer", "resolver failed")).replace("\n", " ")

    decision_reason = data.get("decision_reason")
    if decision_reason:
        return str(decision_reason).replace("\n", " ")

    if looks_not_icall(data):
        return "The analyzed expression is not an indirect call."
    if has_candidates(data):
        return "Resolved indirect-call target(s)."
    return "No candidate callees were identified."


def iter_run_results(outputs_dir: Path):
    for final_path in sorted(outputs_dir.glob("*/final.json")):
        run_dir = final_path.parent
        try:
            data = load_json(final_path)
        except Exception as exc:
            yield run_dir.name, "failed", None, f"could not read final.json: {exc}"
            continue
        yield run_dir.name, classify_result(data), data, None


def percent(count: int, total: int) -> str:
    if total == 0:
        return "0.0%"
    return f"{count / total * 100:.1f}%"


def write_status_lists(
    outputs_dir: Path,
    runs_by_status: dict[str, list[str]],
    reasons_by_run: dict[str, str],
) -> None:
    for status in RESOLUTION_STATUSES:
        path = outputs_dir / f"{status}.list"
        runs = runs_by_status.get(status, [])
        if status == "resolved":
            lines = [f"{run_name}\n" for run_name in runs]
        else:
            lines = [
                f"{run_name}, {reasons_by_run.get(run_name, '')}\n"
                for run_name in runs
            ]
        path.write_text(
            "".join(lines),
            encoding="utf-8",
        )


def print_summary(outputs_dir: Path, details: bool) -> None:
    counts: Counter[str] = Counter()
    runs_by_status: dict[str, list[str]] = defaultdict(list)
    reasons_by_run: dict[str, str] = {}
    errors: list[tuple[str, str]] = []

    for run_name, status, data, error in iter_run_results(outputs_dir):
        counts[status] += 1
        runs_by_status[status].append(run_name)
        reasons_by_run[run_name] = get_reason(data, error)
        if error:
            errors.append((run_name, error))

    write_status_lists(outputs_dir, runs_by_status, reasons_by_run)

    total = sum(counts.values())

    print(f"Outputs directory: {outputs_dir}")
    print(f"Total runs with final.json: {total}")
    print()
    print("Resolution statistics:")
    for status in RESOLUTION_STATUSES:
        count = counts[status]
        print(f"- {status}: {count} ({percent(count, total)})")
    print()
    print("Wrote status lists:")
    for status in RESOLUTION_STATUSES:
        print(f"- {outputs_dir / f'{status}.list'}")

    unknown_count = total - sum(counts[status] for status in RESOLUTION_STATUSES)
    if unknown_count:
        print(f"- unknown: {unknown_count} ({percent(unknown_count, total)})")

    if errors:
        print()
        print("Read errors:")
        for run_name, error in errors:
            print(f"- {run_name}: {error}")

    if details:
        print()
        print("Runs by status:")
        for status in RESOLUTION_STATUSES:
            print(f"[{status}]")
            for run_name in runs_by_status.get(status, []):
                print(f"- {run_name}")
            if not runs_by_status.get(status):
                print("- (none)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize icall resolver outcomes under an outputs directory."
    )
    parser.add_argument(
        "outputs_dir",
        nargs="?",
        default="outputs",
        type=Path,
        help="directory containing per-run output folders",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="list run names under each resolution status",
    )
    args = parser.parse_args()

    outputs_dir = args.outputs_dir
    if not outputs_dir.exists():
        raise SystemExit(f"outputs directory does not exist: {outputs_dir}")

    print_summary(outputs_dir=outputs_dir, details=args.details)


if __name__ == "__main__":
    main()
