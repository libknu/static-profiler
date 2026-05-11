from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Optional
import threading

import requests


CACHE_VERSION = "bootlin_v1"


def _cache_root() -> Path:
    return Path(os.environ.get("LLM_ICALL_CACHE_DIR", "/tmp/llm_icall_resolver_cache"))


def _cache_enabled() -> bool:
    return os.environ.get("LLM_ICALL_DISABLE_CACHE", "").lower() not in {"1", "true", "yes"}


def _cache_path(namespace: str, payload: object) -> Path:
    raw = json.dumps(
        {"version": CACHE_VERSION, "namespace": namespace, "payload": payload},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return _cache_root() / namespace / f"{digest}.json"


def _disk_cache_get(namespace: str, payload: object):
    if not _cache_enabled():
        return None
    path = _cache_path(namespace, payload)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _disk_cache_set(namespace: str, payload: object, value: object) -> None:
    if not _cache_enabled():
        return
    path = _cache_path(namespace, payload)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except Exception:
        return


def _bootlin_ident_remote(project: str, version: str, family: str, symbol: str) -> dict:
    url = f"https://elixir.bootlin.com/api/ident/{project}/{symbol}"
    params = {
        "version": version,
        "family": family,
    }
    r = requests.get(url, params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def _collect_c_family_files(project_root: str) -> list[Path]:
    root = Path(project_root)
    exts = {".c", ".h", ".cc", ".hh", ".hpp"}
    return [p for p in root.rglob("*") if p.is_file() and p.suffix in exts]


def _make_local_def(path: Path, project_root: str, line_no: int, kind: str, text: str) -> dict:
    return {
        "path": str(path.relative_to(project_root)),
        "line": line_no,
        "type": kind,
        "text": text.strip(),
        "source": "local_fallback",
    }


def _def_priority(d: dict) -> tuple[int, str, int]:
    typ = d.get("type")
    path = d.get("path", "")
    line = int(d.get("line", 10**9))

    # 구현체 우선
    if typ == "function":
        pri = 0
    elif typ == "unknown":
        pri = 1
    elif typ == "macro":
        pri = 2
    elif typ == "prototype":
        pri = 3
    else:
        pri = 4

    return (pri, path, line)


def _sort_definitions(defs: list[dict]) -> list[dict]:
    return sorted(defs, key=_def_priority)


def _dedup_definitions(defs: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for d in defs:
        key = (d.get("path"), int(d.get("line", -1)), d.get("type"))
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


def _search_local_symbol(project_root: str, symbol: str, max_results: int = 20) -> dict:
    results: list[dict] = []

    macro_pat = re.compile(rf"^\s*#\s*define\s+{re.escape(symbol)}\b")

    # 반환형이 여러 줄로 끊겨도 어느 정도 잡히게 완화
    func_pat = re.compile(
        rf"^\s*(?:[\w\*\s]+)?\b{re.escape(symbol)}\b\s*\(",
    )

    decl_pat = re.compile(rf"\b{re.escape(symbol)}\b")

    for path in _collect_c_family_files(project_root):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue

        i = 0
        while i < len(lines):
            line = lines[i]

            if macro_pat.search(line):
                chunk = [line]
                j = i + 1
                while chunk[-1].rstrip().endswith("\\") and j < len(lines):
                    chunk.append(lines[j])
                    j += 1

                results.append(
                    _make_local_def(
                        path=path,
                        project_root=project_root,
                        line_no=i + 1,
                        kind="macro",
                        text="\n".join(chunk),
                    )
                )
                i = j
                if len(results) >= max_results:
                    break
                continue

            if func_pat.search(line):
                text = line
                kind = "unknown"

                j = i + 1
                while j < len(lines) and j < i + 12:
                    text += "\n" + lines[j]
                    if "{" in lines[j]:
                        kind = "function"
                        break
                    if ";" in lines[j]:
                        kind = "prototype"
                        break
                    j += 1

                results.append(
                    _make_local_def(
                        path=path,
                        project_root=project_root,
                        line_no=i + 1,
                        kind=kind,
                        text=text,
                    )
                )
                if len(results) >= max_results:
                    break

            i += 1

        if len(results) >= max_results:
            break

    if not results:
        for path in _collect_c_family_files(project_root):
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue

            for i, line in enumerate(lines, start=1):
                if decl_pat.search(line):
                    results.append(
                        _make_local_def(
                            path=path,
                            project_root=project_root,
                            line_no=i,
                            kind="unknown",
                            text=line,
                        )
                    )
                    if len(results) >= max_results:
                        break
            if len(results) >= max_results:
                break

    results = _sort_definitions(_dedup_definitions(results))

    return {
        "definitions": results,
        "references": [],
        "documentations": [],
        "source": "local_fallback" if results else "none",
    }

def bootlin_ident(
    project: str,
    version: str,
    family: str,
    symbol: str,
    project_root: Optional[str] = None,
) -> dict:
    cache_payload = {
        "project": project,
        "version": version,
        "family": family,
        "symbol": symbol,
        "project_root": project_root,
    }
    cached = _disk_cache_get("bootlin_ident", cache_payload)
    if cached is not None:
        return cached

    try:
        remote = _bootlin_ident_remote(project, version, family, symbol)
    except Exception:
        remote = {
            "definitions": [],
            "references": [],
            "documentations": [],
            "source": "bootlin_error",
        }

    remote_defs = remote.get("definitions", []) or []
    remote_refs = remote.get("references", []) or []

    # 1) remote에 definition이 있으면 local fallback을 섞지 않음
    if remote_defs:
        result = {
            "definitions": _sort_definitions(_dedup_definitions(remote_defs)),
            "references": remote_refs,
            "documentations": remote.get("documentations", []),
            "source": "bootlin",
        }
        _disk_cache_set("bootlin_ident", cache_payload, result)
        return result

    # 2) remote definition이 없을 때만 local fallback 사용
    local_defs: list[dict] = []
    if project_root:
        local = _search_local_symbol(project_root, symbol)
        local_defs = local.get("definitions", []) or []

    if local_defs or remote_refs:
        result = {
            "definitions": _sort_definitions(_dedup_definitions(local_defs)),
            "references": remote_refs,
            "documentations": remote.get("documentations", []),
            "source": "local_fallback" if local_defs else "bootlin_refs_only",
        }
        _disk_cache_set("bootlin_ident", cache_payload, result)
        return result

    remote["source"] = "bootlin_empty"
    _disk_cache_set("bootlin_ident", cache_payload, remote)
    return remote
