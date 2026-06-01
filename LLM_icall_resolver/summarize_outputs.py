#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


RESOLUTION_STATUSES = ("resolved", "unresolved", "not_icall", "failed")
ROUND_DIR_RE = re.compile(r"^round(\d+)$")


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
    if explicit == "inconclusive":
        return "unresolved"
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
            yield run_dir.name, "old" if run_dir.name.startswith("old.") else "current", "failed", None, f"could not read final.json: {exc}"
            continue
        yield run_dir.name, "old" if run_dir.name.startswith("old.") else "current", classify_result(data), data, None


def round_index_from_name(name: str) -> int:
    match = ROUND_DIR_RE.match(name)
    if not match:
        return 0
    return int(match.group(1))


def is_cascade_outputs_root(outputs_dir: Path) -> bool:
    return any(
        child.is_dir() and ROUND_DIR_RE.match(child.name)
        for child in outputs_dir.iterdir()
    )


def case_id_for_result(run_name: str, data: dict[str, Any] | None) -> str:
    if data:
        case_id = data.get("case_id")
        if case_id:
            return str(case_id)
    case_id = run_name.removeprefix("old.")
    return re.sub(r"\.\d+$", "", case_id)


def iter_cascade_results(outputs_root: Path):
    for round_dir in sorted(outputs_root.iterdir(), key=lambda p: (round_index_from_name(p.name), p.name)):
        if not round_dir.is_dir() or not ROUND_DIR_RE.match(round_dir.name):
            continue

        fallback_round_index = round_index_from_name(round_dir.name)
        for final_path in sorted(round_dir.glob("*/final.json")):
            run_dir = final_path.parent
            bucket = "old" if run_dir.name.startswith("old.") else "current"
            try:
                data = load_json(final_path)
                status = classify_result(data)
                error = None
            except Exception as exc:
                data = None
                status = "failed"
                error = f"could not read final.json: {exc}"

            if data is not None:
                data["_run_name"] = run_dir.name
                data["_round"] = data.get("run_round") or round_dir.name
                data["_round_index"] = int(data.get("run_round_index") or fallback_round_index)
                data["_final_path"] = str(final_path)

            yield (
                run_dir.name,
                bucket,
                status,
                data,
                error,
                round_dir.name,
                int((data or {}).get("run_round_index") or fallback_round_index),
                str(final_path),
            )


def base_case_ids_from_round1(rows: list[tuple]) -> set[str]:
    return {
        case_id_for_result(run_name, data)
        for run_name, bucket, _status, data, _error, source_round, _round_index, _final_path in rows
        if source_round == "round1" and bucket == "current" and data is not None
    }


def latest_cascade_rows(rows: list[tuple], base_case_ids: set[str] | None = None):
    latest: dict[str, tuple] = {}
    for row in rows:
        run_name, bucket, _status, data, _error, _round_name, round_index, final_path = row
        case_id = case_id_for_result(run_name, data)
        if base_case_ids is not None and case_id not in base_case_ids:
            continue
        previous = latest.get(case_id)
        if previous is None:
            latest[case_id] = row
            continue

        previous_round_index = previous[6]
        previous_bucket_rank = 1 if previous[1] == "current" else 0
        previous_final_path = previous[7]
        bucket_rank = 1 if bucket == "current" else 0
        if (round_index, bucket_rank, final_path) >= (
            previous_round_index,
            previous_bucket_rank,
            previous_final_path,
        ):
            latest[case_id] = row
    return [latest[case_id] for case_id in sorted(latest)]


def basic_rows(cascade_rows: list[tuple]) -> list[tuple[str, str, str, dict[str, Any] | None, str | None]]:
    return [row[:5] for row in cascade_rows]


def case_id_rows(cascade_rows: list[tuple]) -> list[tuple[str, str, str, dict[str, Any] | None, str | None]]:
    return [
        (case_id_for_result(run_name, data), bucket, status, data, error)
        for run_name, bucket, status, data, error, *_rest in cascade_rows
    ]


def write_latest_case_results_csv(stats_dir: Path, round_name: str, rows: list[tuple]) -> Path:
    path = stats_dir / f"{round_name}_case_results.csv"
    fields = [
        "case_id",
        "latest_round",
        "latest_round_index",
        "run_name",
        "bucket",
        "status",
        "caller_symbol",
        "icall_location",
        "icall_line",
        "icall_expr",
        "num_candidates",
        "icall_targets",
        "reason",
        "final_json",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for run_name, _bucket, status, data, error, source_round, round_index, final_path in rows:
            targets = []
            if data:
                targets = [str(x) for x in (data.get("icall_targets") or data.get("candidate_callees") or [])]
            writer.writerow(
                {
                    "case_id": case_id_for_result(run_name, data),
                    "latest_round": source_round,
                    "latest_round_index": round_index,
                    "run_name": run_name,
                    "bucket": _bucket,
                    "status": status,
                    "caller_symbol": (data or {}).get("caller_symbol", ""),
                    "icall_location": (data or {}).get("icall_location", ""),
                    "icall_line": (data or {}).get("icall_line", ""),
                    "icall_expr": (data or {}).get("icall_expr", ""),
                    "num_candidates": len(targets),
                    "icall_targets": ";".join(targets),
                    "reason": get_reason(data, error),
                    "final_json": final_path,
                }
            )
    return path


def percent(count: int, total: int) -> str:
    if total == 0:
        return "0.0%"
    return f"{count / total * 100:.1f}%"


def bucket_failure_reason(reason: str) -> str:
    reason = (reason or "").strip()
    if not reason:
        return "unknown"
    if reason.startswith("Resolver failed."):
        if "Reason:" in reason:
            reason = reason.split("Reason:", 1)[1].strip()
    if reason.startswith("Resolver failed"):
        reason = reason.removeprefix("Resolver failed").strip(" .")
    if reason.startswith("retrieval failed"):
        return "retrieval failed"
    if reason.startswith("loop detected"):
        return "loop detected"
    if reason.startswith("missing batch output"):
        return "missing batch output"
    if reason.startswith("batch response processing failed"):
        return "batch response processing failed"
    if reason.startswith("unsupported kind"):
        return "unsupported kind"
    if reason.startswith("max hops exceeded"):
        return "max hops exceeded"
    if reason.startswith("definition not found"):
        return "definition not found"
    if reason.startswith("missing required arguments"):
        return "missing required arguments"
    if "LLM returned fail decision" in reason:
        return "LLM returned fail decision"
    return "other"


def summarize_bucket(rows: list[tuple[str, str, str, dict[str, Any] | None, str | None]]):
    counts: Counter[str] = Counter()
    runs_by_status: dict[str, list[str]] = defaultdict(list)
    reasons_by_run: dict[str, str] = {}
    errors: list[tuple[str, str]] = []

    for run_name, bucket, status, data, error in rows:
        del bucket
        counts[status] += 1
        runs_by_status[status].append(run_name)
        reasons_by_run[run_name] = get_reason(data, error)
        if error:
            errors.append((run_name, error))
    return counts, runs_by_status, reasons_by_run, errors


def write_status_lists(
    stats_dir: Path,
    round_name: str,
    runs_by_status: dict[str, list[str]],
    reasons_by_run: dict[str, str],
    prefix: str = "",
) -> None:
    stem = f"{round_name}{prefix}"
    for status in RESOLUTION_STATUSES:
        path = stats_dir / f"{stem}.{status}.list"
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

    pending_path = stats_dir / f"{stem}.pending.list"
    pending_runs = (
        runs_by_status.get("failed", [])
        + runs_by_status.get("unresolved", [])
        + runs_by_status.get("not_icall", [])
    )
    pending_path.write_text(
        "".join(f"{run_name}\n" for run_name in pending_runs),
        encoding="utf-8",
    )


def write_round_stat(
    stats_dir: Path,
    round_name: str,
    outputs_dir: Path,
    counts: Counter[str],
    total: int,
    reasons_by_run: dict[str, str],
    runs_by_status: dict[str, list[str]],
    prefix: str = "",
) -> Path:
    stem = f"{round_name}{prefix}"
    lines = [
        f"Round: {round_name}",
        f"Bucket: {prefix.lstrip('.') or 'overall'}",
        f"Outputs directory: {outputs_dir}",
        f"Total runs with final.json: {total}",
        "",
        "Resolution statistics:",
    ]
    for status in RESOLUTION_STATUSES:
        count = counts[status]
        lines.append(f"- {status}: {count} ({percent(count, total)})")

    unknown_count = total - sum(counts[status] for status in RESOLUTION_STATUSES)
    if unknown_count:
        lines.append(f"- unknown: {unknown_count} ({percent(unknown_count, total)})")

    failed_reasons: Counter[str] = Counter()
    for run_name in runs_by_status.get("failed", []):
        failed_reasons[bucket_failure_reason(reasons_by_run.get(run_name, ""))] += 1
    if failed_reasons:
        lines.append("")
        lines.append("Failed cases by primary reason:")
        for reason, count in failed_reasons.most_common():
            lines.append(f"- {reason}: {count}")

    path = stats_dir / f"{stem}.stat"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def print_summary(outputs_dir: Path, stats_dir: Path, round_name: str, details: bool) -> None:
    rows = list(iter_run_results(outputs_dir))
    overall_counts, overall_runs_by_status, overall_reasons_by_run, overall_errors = summarize_bucket(rows)
    current_rows = [row for row in rows if row[1] == "current"]
    old_rows = [row for row in rows if row[1] == "old"]
    current_counts, current_runs_by_status, current_reasons_by_run, current_errors = summarize_bucket(current_rows)
    old_counts, old_runs_by_status, old_reasons_by_run, old_errors = summarize_bucket(old_rows)

    stats_dir.mkdir(parents=True, exist_ok=True)
    write_status_lists(stats_dir, round_name, current_runs_by_status, current_reasons_by_run)
    write_status_lists(stats_dir, round_name, old_runs_by_status, old_reasons_by_run, prefix=".old")

    total = sum(overall_counts.values())
    write_round_stat(stats_dir, round_name, outputs_dir, overall_counts, total, overall_reasons_by_run, overall_runs_by_status)
    write_round_stat(stats_dir, round_name, outputs_dir, current_counts, sum(current_counts.values()), current_reasons_by_run, current_runs_by_status, prefix=".current")
    write_round_stat(stats_dir, round_name, outputs_dir, old_counts, sum(old_counts.values()), old_reasons_by_run, old_runs_by_status, prefix=".old")

    print(f"Outputs directory: {outputs_dir}")
    print(f"Stats directory: {stats_dir}")
    print(f"Round name: {round_name}")
    print(f"Total runs with final.json: {total}")
    print()
    print("Resolution statistics:")
    for status in RESOLUTION_STATUSES:
        count = overall_counts[status]
        print(f"- {status}: {count} ({percent(count, total)})")
    print()
    print("Current bucket:")
    for status in RESOLUTION_STATUSES:
        count = current_counts[status]
        print(f"- {status}: {count} ({percent(count, sum(current_counts.values()))})")
    print()
    print("Old bucket:")
    for status in RESOLUTION_STATUSES:
        count = old_counts[status]
        print(f"- {status}: {count} ({percent(count, sum(old_counts.values()))})")
    print()
    print("Wrote status lists:")
    for status in RESOLUTION_STATUSES:
        print(f"- {stats_dir / f'{round_name}.{status}.list'}")
    print(f"- {stats_dir / f'{round_name}.pending.list'}")
    print(f"- {stats_dir / f'{round_name}.stat'}")
    print(f"- {stats_dir / f'{round_name}.current.stat'}")
    print(f"- {stats_dir / f'{round_name}.old.stat'}")

    if overall_errors or current_errors or old_errors:
        print()
        print("Read errors:")
        for run_name, error in overall_errors:
            print(f"- {run_name}: {error}")

    if details:
        print()
        print("Runs by status:")
        for status in RESOLUTION_STATUSES:
            print(f"[{status}]")
            for run_name in current_runs_by_status.get(status, []):
                print(f"- {run_name}")
            if not current_runs_by_status.get(status):
                print("- (none)")


def print_cascade_latest_summary(outputs_root: Path, stats_dir: Path, round_name: str, details: bool) -> None:
    cascade_rows = list(iter_cascade_results(outputs_root))
    base_case_ids = base_case_ids_from_round1(cascade_rows)
    latest_rows = latest_cascade_rows(cascade_rows, base_case_ids=base_case_ids)
    rows = case_id_rows(latest_rows)
    counts, runs_by_status, reasons_by_run, errors = summarize_bucket(rows)

    stats_dir.mkdir(parents=True, exist_ok=True)
    write_status_lists(stats_dir, round_name, runs_by_status, reasons_by_run)
    stat_path = write_round_stat(
        stats_dir,
        round_name,
        outputs_root,
        counts,
        sum(counts.values()),
        reasons_by_run,
        runs_by_status,
    )
    csv_path = write_latest_case_results_csv(stats_dir, round_name, latest_rows)

    round_counts: Counter[str] = Counter(row[5] for row in latest_rows)

    total_executions = len(cascade_rows)
    total_cases = len(latest_rows)
    print(f"Outputs root: {outputs_root}")
    print(f"Stats directory: {stats_dir}")
    print(f"Summary mode: latest result per unique case")
    print(f"Final result policy: group by case_id/run_name, pick largest round index")
    print(f"Total executions with final.json: {total_executions}")
    print(f"Base unique cases from round1 current final.json: {len(base_case_ids)}")
    print(f"Unique cases with latest final result: {total_cases}")
    print()
    print("Latest result source round:")
    for source_round, count in sorted(round_counts.items(), key=lambda item: round_index_from_name(item[0])):
        print(f"- {source_round}: {count} ({percent(count, total_cases)})")
    print()
    print("Final resolution statistics:")
    for status in RESOLUTION_STATUSES:
        count = counts[status]
        print(f"- {status}: {count} ({percent(count, total_cases)})")
    print()
    print("Wrote latest-case outputs:")
    for status in RESOLUTION_STATUSES:
        print(f"- {stats_dir / f'{round_name}.{status}.list'}")
    print(f"- {stats_dir / f'{round_name}.pending.list'}")
    print(f"- {stat_path}")
    print(f"- {csv_path}")

    if errors:
        print()
        print("Read errors:")
        for run_name, error in errors:
            print(f"- {run_name}: {error}")

    if details:
        print()
        print("Latest cases by status:")
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
    parser.add_argument(
        "--stats-dir",
        type=Path,
        default=None,
        help="directory where round stats and status lists are written",
    )
    parser.add_argument(
        "--round-name",
        default="round1",
        help="label used in generated stat/list filenames",
    )
    parser.add_argument(
        "--latest-cascade",
        action="store_true",
        help=(
            "treat outputs_dir as a root containing round1/round2/round3 directories "
            "and summarize the latest result for each unique case"
        ),
    )
    args = parser.parse_args()

    outputs_dir = args.outputs_dir
    if not outputs_dir.exists():
        raise SystemExit(f"outputs directory does not exist: {outputs_dir}")

    stats_dir = args.stats_dir if args.stats_dir is not None else outputs_dir.parent / "stats"
    if args.latest_cascade or is_cascade_outputs_root(outputs_dir):
        round_name = args.round_name
        if round_name == "round1":
            round_name = "latest"
        print_cascade_latest_summary(
            outputs_root=outputs_dir,
            stats_dir=stats_dir,
            round_name=round_name,
            details=args.details,
        )
    else:
        print_summary(
            outputs_dir=outputs_dir,
            stats_dir=stats_dir,
            round_name=args.round_name,
            details=args.details,
        )


if __name__ == "__main__":
    main()
