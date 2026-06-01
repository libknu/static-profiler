#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import os
import shlex
from pathlib import Path

from .bootlin import bootlin_ident


def parse_caller_symbol(script: Path) -> str | None:
    text = script.read_text(encoding="utf-8", errors="ignore").replace("\\\n", " ")
    tokens = shlex.split(text)
    for i, token in enumerate(tokens):
        if token == "--caller-symbol" and i + 1 < len(tokens):
            return tokens[i + 1]
    return None


def collect_symbols(inputs_dir: Path) -> list[str]:
    symbols = set()
    for script in sorted(inputs_dir.glob("*.sh")):
        symbol = parse_caller_symbol(script)
        if symbol:
            symbols.add(symbol)
    return sorted(symbols)


def prewarm_one(args: tuple[str, argparse.Namespace]) -> tuple[str, str, int, int]:
    symbol, ns = args
    result = bootlin_ident(
        project=ns.project,
        version=ns.version,
        family=ns.family,
        symbol=symbol,
        project_root=str(ns.project_root),
    )
    return (
        symbol,
        result.get("source", "unknown"),
        len(result.get("definitions", []) or []),
        len(result.get("references", []) or []),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Prewarm Bootlin ident cache for input scripts.")
    parser.add_argument("--inputs-dir", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, default=Path("~/workspace/glibc-src/glibc-2.41"))
    parser.add_argument("--project", default="glibc")
    parser.add_argument("--version", default="glibc-2.41")
    parser.add_argument("--family", default="C")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(".cache/llm_icall_resolver"),
        help="sets LLM_ICALL_CACHE_DIR for this run",
    )
    args = parser.parse_args()
    args.project_root = args.project_root.expanduser().resolve()
    args.cache_dir = args.cache_dir.expanduser().resolve()
    os.environ["LLM_ICALL_CACHE_DIR"] = str(args.cache_dir)

    symbols = collect_symbols(args.inputs_dir.expanduser().resolve())
    print(f"cache_dir={args.cache_dir}", flush=True)
    print(f"symbols={len(symbols)}", flush=True)
    if not symbols:
        return

    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = [executor.submit(prewarm_one, (symbol, args)) for symbol in symbols]
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            try:
                symbol, source, defs, refs = future.result()
                print(
                    f"prewarm {completed}/{len(symbols)} symbol={symbol} "
                    f"source={source} defs={defs} refs={refs}",
                    flush=True,
                )
            except Exception as exc:
                print(f"prewarm {completed}/{len(symbols)} failed: {exc}", flush=True)


if __name__ == "__main__":
    main()
