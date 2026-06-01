from __future__ import annotations

from pathlib import Path
from typing import Optional, Iterable
from functools import lru_cache
import hashlib
import json
import os
import re
import subprocess
import threading

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node


CACHE_VERSION = "treesitter_retriever_v1"


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


def get_c_language() -> Language:
    return Language(tsc.language())


def build_parser() -> Parser:
    return Parser(get_c_language())


@lru_cache(maxsize=4096)
def read_text_safe(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


@lru_cache(maxsize=4096)
def read_bytes_safe(path: Path) -> bytes:
    return path.read_bytes()


@lru_cache(maxsize=4096)
def _parse_tree_cached(path_text: str, mtime_ns: int, size: int):
    source = read_bytes_safe(Path(path_text))
    parser = build_parser()
    return parser.parse(source)


def parse_tree_safe(path: Path):
    stat = path.stat()
    return _parse_tree_cached(str(path), stat.st_mtime_ns, stat.st_size)


def node_text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def extract_identifier_from_declarator(node: Node, source: bytes) -> Optional[str]:
    if node.type == "identifier":
        return node_text(node, source)
    for child in node.children:
        name = extract_identifier_from_declarator(child, source)
        if name is not None:
            return name
    return None


def line_contains_node(line_1_based: int, node: Node) -> bool:
    start_line = node.start_point[0] + 1
    end_line = node.end_point[0] + 1
    return start_line <= line_1_based <= end_line


def iter_nodes(root: Node) -> Iterable[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def find_function_definition_by_name_and_line(
    root: Node,
    source: bytes,
    symbol: str,
    line_1_based: int,
) -> Optional[Node]:
    for node in iter_nodes(root):
        if node.type != "function_definition":
            continue
        if not line_contains_node(line_1_based, node):
            continue

        declarator = None
        substack = [node]
        while substack and declarator is None:
            cur = substack.pop()
            if cur.type.endswith("_declarator"):
                declarator = cur
                break
            substack.extend(reversed(cur.children))

        if declarator is None:
            continue

        name = extract_identifier_from_declarator(declarator, source)
        if name == symbol:
            return node
    return None


def get_function_source(
    project_root: str,
    relative_path: str,
    symbol: str,
    line_1_based: int,
) -> tuple[str, str]:
    cache_payload = {
        "project_root": project_root,
        "relative_path": relative_path,
        "symbol": symbol,
        "line_1_based": line_1_based,
    }
    cached = _disk_cache_get("function_source", cache_payload)
    if cached is not None:
        return cached["text"], cached["kind"]

    file_path = Path(project_root) / relative_path
    source = read_bytes_safe(file_path)
    tree = parse_tree_safe(file_path)

    fn_node = find_function_definition_by_name_and_line(
        tree.root_node, source, symbol, line_1_based
    )

    
    if fn_node is None:
        # fallback: symbol 이름만으로 다시 찾기
        for node in iter_nodes(tree.root_node):
            if node.type != "function_definition":
                continue

            substack = [node]
            while substack:
                cur = substack.pop()
                if cur.type.endswith("_declarator"):
                    name = extract_identifier_from_declarator(cur, source)
                    if name == symbol:
                        fn_node = node
                        break
                substack.extend(reversed(cur.children))

            if fn_node:
                break

    if fn_node is None:
        raise ValueError(
            f"function not found: symbol={symbol}, line={line_1_based}, file={file_path}"
        )

    result = {"text": node_text(fn_node, source), "kind": "function_definition"}
    _disk_cache_set("function_source", cache_payload, result)
    return result["text"], result["kind"]

def extract_call_like_identifier(icall_expr: str) -> Optional[str]:
    matches = re.findall(r"([A-Za-z_]\w*)\s*\(", icall_expr)
    if not matches:
        return None
    
    blacklist = {
        "if", "while", "for", "switch", "return", "sizeof"
    }
    
    for name in reversed(matches):
        if name not in blacklist:
            return name
    
    return None


def extract_field_names(expr: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"(?:->|\.)([A-Za-z_]\w*)", expr)))


@lru_cache(maxsize=8)
def collect_c_family_files(project_root: str) -> tuple[Path, ...]:
    root = Path(project_root)
    exts = {".c", ".h", ".hpp", ".hh", ".cc"}
    return tuple(p for p in root.rglob("*") if p.is_file() and p.suffix in exts)


@lru_cache(maxsize=4096)
def find_c_family_files_containing(project_root: str, terms: tuple[str, ...]) -> tuple[Path, ...]:
    root = Path(project_root)
    clean_terms = tuple(dict.fromkeys(t for t in terms if t))
    if not clean_terms:
        return ()

    pattern = "|".join(rf"\b{re.escape(term)}\b" for term in clean_terms)
    try:
        proc = subprocess.run(
            [
                "rg",
                "--files-with-matches",
                "--glob",
                "*.{c,h,cc,hh,hpp}",
                pattern,
                str(root),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=20,
        )
    except Exception:
        return collect_c_family_files(project_root)

    if proc.returncode == 1:
        return ()
    if proc.returncode != 0:
        return collect_c_family_files(project_root)

    paths = []
    for line in proc.stdout.splitlines():
        path = Path(line)
        if path.is_file():
            paths.append(path)
    return tuple(paths)


def get_macro_definitions(
    project_root: str,
    macro_name: str,
    max_results: int = 5,
) -> list[dict]:
    cache_payload = {
        "project_root": project_root,
        "macro_name": macro_name,
        "max_results": max_results,
    }
    cached = _disk_cache_get("macro_definitions", cache_payload)
    if cached is not None:
        return cached

    results: list[dict] = []
    define_pat = re.compile(rf"^\s*#\s*define\s+{re.escape(macro_name)}\b")

    for path in collect_c_family_files(project_root):
        lines = read_text_safe(path).splitlines()
        i = 0
        while i < len(lines):
            if define_pat.search(lines[i]):
                chunk = [lines[i]]
                j = i + 1
                while chunk[-1].rstrip().endswith("\\") and j < len(lines):
                    chunk.append(lines[j])
                    j += 1

                results.append(
                    {
                        "kind": "macro_definition",
                        "path": str(path.relative_to(project_root)),
                        "line": i + 1,
                        "text": "\n".join(chunk),
                    }
                )
                if len(results) >= max_results:
                    _disk_cache_set("macro_definitions", cache_payload, results)
                    return results
                i = j
            else:
                i += 1
    _disk_cache_set("macro_definitions", cache_payload, results)
    return results


def get_typedef_definitions(
    project_root: str,
    name: str,
    max_results: int = 5,
) -> list[dict]:
    results: list[dict] = []
    pat = re.compile(rf"\btypedef\b.*\b{re.escape(name)}\b\s*;")

    for path in collect_c_family_files(project_root):
        text = read_text_safe(path)
        for m in pat.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            snippet = text[m.start(): text.find(";", m.start()) + 1]
            results.append(
                {
                    "kind": "typedef_definition",
                    "path": str(path.relative_to(project_root)),
                    "line": line,
                    "text": snippet,
                }
            )
            if len(results) >= max_results:
                return results
    return results


def get_struct_definitions_for_field(
    project_root: str,
    field_name: str,
    max_results: int = 5,
) -> list[dict]:
    cache_payload = {
        "project_root": project_root,
        "field_name": field_name,
        "max_results": max_results,
    }
    cached = _disk_cache_get("struct_definitions_for_field", cache_payload)
    if cached is not None:
        return cached

    results: list[dict] = []
    field_pat = re.compile(rf"\b{re.escape(field_name)}\b")

    for path in find_c_family_files_containing(project_root, (field_name,)):
        source = read_bytes_safe(path)
        tree = parse_tree_safe(path)

        for node in iter_nodes(tree.root_node):
            if node.type not in {"struct_specifier", "union_specifier"}:
                continue

            text = node_text(node, source)
            if not field_pat.search(text):
                continue

            if re.search(rf"\b{re.escape(field_name)}\b\s*(?:;|\[)", text):
                line = node.start_point[0] + 1
                results.append(
                    {
                        "kind": "struct_definition",
                        "path": str(path.relative_to(project_root)),
                        "line": line,
                        "text": text,
                    }
                )
                if len(results) >= max_results:
                    _disk_cache_set("struct_definitions_for_field", cache_payload, results)
                    return results
    _disk_cache_set("struct_definitions_for_field", cache_payload, results)
    return results


def get_lines_with_identifier(
    project_root: str,
    ident: str,
    max_results: int = 10,
) -> list[dict]:
    results: list[dict] = []
    pat = re.compile(rf"\b{re.escape(ident)}\b")

    for path in collect_c_family_files(project_root):
        lines = read_text_safe(path).splitlines()
        for i, line in enumerate(lines, start=1):
            if pat.search(line):
                results.append(
                    {
                        "kind": "identifier_occurrence",
                        "path": str(path.relative_to(project_root)),
                        "line": i,
                        "text": line,
                    }
                )
                if len(results) >= max_results:
                    return results
    return results


def get_local_assignment_lines(
    relative_path: str,
    function_text: str,
    identifiers: list[str],
    max_results: int = 10,
) -> list[dict]:
    cache_payload = {
        "relative_path": relative_path,
        "function_text": function_text,
        "identifiers": identifiers,
        "max_results": max_results,
    }
    cached = _disk_cache_get("local_assignment_lines", cache_payload)
    if cached is not None:
        return cached

    results: list[dict] = []
    pats = [
        re.compile(rf"\b{re.escape(ident)}\b.*=") for ident in identifiers if ident
    ]

    for i, line in enumerate(function_text.splitlines(), start=1):
        if any(p.search(line) for p in pats):
            results.append(
                {
                    "kind": "local_assignment",
                    "path": relative_path,
                    "line": i,
                    "text": line,
                }
            )
            if len(results) >= max_results:
                _disk_cache_set("local_assignment_lines", cache_payload, results)
                return results
    _disk_cache_set("local_assignment_lines", cache_payload, results)
    return results


def get_macro_source(
    project_root: str,
    macro_name: str,
    relative_path: Optional[str] = None,
    line_1_based: Optional[int] = None,
) -> tuple[str, str]:
    candidates: list[Path] = []

    if relative_path is not None:
        file_path = Path(project_root) / relative_path
        if file_path.exists():
            candidates.append(file_path)

    for path in collect_c_family_files(project_root):
        if path not in candidates:
            candidates.append(path)

    define_pat = re.compile(rf"^\s*#\s*define\s+{re.escape(macro_name)}\b")

    for path in candidates:
        lines = read_text_safe(path).splitlines()
        i = 0
        while i < len(lines):
            if define_pat.search(lines[i]):
                chunk = [lines[i]]
                j = i + 1
                while chunk[-1].rstrip().endswith("\\") and j < len(lines):
                    chunk.append(lines[j])
                    j += 1

                return "\n".join(chunk), "macro_definition"
            i += 1

    raise ValueError(
        f"macro not found: symbol={macro_name}, line={line_1_based}, file={relative_path}"
    )


def get_callsite_context(
    project_root: str,
    relative_path: Optional[str],
    line_1_based: Optional[int],
) -> str:
    if not relative_path or not line_1_based:
        return ""

    file_path = Path(project_root) / relative_path
    if not file_path.exists():
        return ""

    source = read_bytes_safe(file_path)
    tree = parse_tree_safe(file_path)
    fn = find_enclosing_function_by_line(tree.root_node, source, line_1_based)
    if fn is not None:
        text = node_text(fn, source)
        return f"[original_callsite] {relative_path}:{line_1_based}\n{text}"

    snippet, _ = get_nearby_source_snippet(
        project_root=project_root,
        relative_path=relative_path,
        line_1_based=line_1_based,
        radius=80,
    )
    return f"[original_callsite] {relative_path}:{line_1_based}\n{snippet}"


def get_enclosing_function_info(
    project_root: str,
    relative_path: str,
    line_1_based: int,
) -> Optional[dict]:
    cache_payload = {
        "project_root": project_root,
        "relative_path": relative_path,
        "line_1_based": line_1_based,
    }
    cached = _disk_cache_get("enclosing_function", cache_payload)
    if cached is not None:
        return cached

    file_path = Path(project_root) / relative_path
    if not file_path.exists():
        return None

    source = read_bytes_safe(file_path)
    tree = parse_tree_safe(file_path)
    fn = find_enclosing_function_by_line(tree.root_node, source, line_1_based)
    if fn is None:
        return None

    name = get_function_name_from_definition(fn, source)
    if not name:
        return None

    result = {
        "path": relative_path,
        "line": fn.start_point[0] + 1,
        "type": "function",
        "symbol": name,
        "source": "callsite_enclosing_function",
    }
    _disk_cache_set("enclosing_function", cache_payload, result)
    return result




def get_context_bundle(
    project_root: str,
    relative_path: str,
    symbol: str,
    line_1_based: int,
    icall_expr: str,
    ident_kind: str = "function",
    icall_location: Optional[str] = None,
    icall_line: Optional[int] = None,
) -> dict:
    cache_payload = {
        "project_root": project_root,
        "relative_path": relative_path,
        "symbol": symbol,
        "line_1_based": line_1_based,
        "icall_expr": icall_expr,
        "ident_kind": ident_kind,
        "icall_location": icall_location,
        "icall_line": icall_line,
    }
    cached = _disk_cache_get("context_bundle", cache_payload)
    if cached is not None:
        return cached

    if ident_kind == "macro":
        primary_text, primary_kind = get_macro_source(
                project_root=project_root,
                macro_name=symbol,
                relative_path=relative_path,
                line_1_based=line_1_based,
                )
    elif ident_kind in {"function", "prototype", "unknown"}:
        try:
            primary_text, primary_kind = get_function_source(
                project_root=project_root,
                relative_path=relative_path,
                symbol=symbol,
                line_1_based=line_1_based,
            )
        except Exception:
            primary_text, primary_kind = get_global_symbol_source(
                project_root=project_root,
                relative_path=relative_path,
                symbol=symbol,
                line_1_based=line_1_based,
            )
    else:
        primary_text, primary_kind = get_global_symbol_source(
            project_root=project_root,
            relative_path=relative_path,
            symbol=symbol,
            line_1_based=line_1_based,
        )

    callee_token = extract_call_like_identifier(icall_expr)
    field_names = extract_field_names(icall_expr)

    macro_defs = []
    if callee_token is not None:
        macro_defs = get_macro_definitions(project_root, callee_token)

    struct_defs = []
    for field in field_names:
        struct_defs.extend(
            get_struct_definitions_for_field(project_root, field, max_results=3)
        )

    local_assignments = []
    if primary_kind == "function_definition":
        local_assignments = get_local_assignment_lines(
            relative_path=relative_path,
            function_text=primary_text,
            identifiers=field_names + ([callee_token] if callee_token else []),
        )

    initializer_defs = get_initializer_occurrences(
        project_root=project_root,
        identifiers=field_names + ([callee_token] if callee_token else []),
        max_results=10,
    )
    callsite_context = get_callsite_context(
        project_root=project_root,
        relative_path=icall_location,
        line_1_based=icall_line,
    )

    result = {
        "primary_block": primary_text,
        "primary_block_kind": primary_kind,
        "callsite_context": callsite_context,
        "macro_definitions": macro_defs,
        "struct_definitions": struct_defs,
        "local_assignments": local_assignments,
        "initializer_definitions": initializer_defs,
    }
    _disk_cache_set("context_bundle", cache_payload, result)
    return result


def find_declaration_by_name_and_line(
    root: Node,
    source: bytes,
    symbol: str,
    line_1_based: int,
) -> Optional[Node]:
    for node in iter_nodes(root):
        if node.type != "declaration":
            continue

        if not line_contains_node(line_1_based, node):
            continue

        text = node_text(node, source)

        # symbol이 declaration 안에 실제로 들어있는지 확인
        if re.search(rf"\b{re.escape(symbol)}\b", text):
            return node

    return None


def find_declaration_by_name(root: Node, source: bytes, symbol: str) -> Optional[Node]:
    for node in iter_nodes(root):
        if node.type != "declaration":
            continue
        text = node_text(node, source)
        if re.search(rf"\b{re.escape(symbol)}\b", text):
            return node
    return None


def get_nearby_source_snippet(
    project_root: str,
    relative_path: str,
    line_1_based: int,
    radius: int = 25,
) -> tuple[str, str]:
    cache_payload = {
        "project_root": project_root,
        "relative_path": relative_path,
        "line_1_based": line_1_based,
        "radius": radius,
    }
    cached = _disk_cache_get("nearby_source_snippet", cache_payload)
    if cached is not None:
        return cached["text"], cached["kind"]

    file_path = Path(project_root) / relative_path
    lines = read_text_safe(file_path).splitlines()
    if not lines:
        return "", "source_snippet"

    start = max(1, line_1_based - radius)
    end = min(len(lines), line_1_based + radius)
    numbered = [
        f"{line_no}: {lines[line_no - 1]}"
        for line_no in range(start, end + 1)
    ]
    result = {"text": "\n".join(numbered), "kind": "source_snippet"}
    _disk_cache_set("nearby_source_snippet", cache_payload, result)
    return result["text"], result["kind"]


def get_global_symbol_source(
    project_root: str,
    relative_path: str,
    symbol: str,
    line_1_based: int,
) -> tuple[str, str]:
    cache_payload = {
        "project_root": project_root,
        "relative_path": relative_path,
        "symbol": symbol,
        "line_1_based": line_1_based,
    }
    cached = _disk_cache_get("global_symbol_source", cache_payload)
    if cached is not None:
        return cached["text"], cached["kind"]

    file_path = Path(project_root) / relative_path
    source = read_bytes_safe(file_path)
    tree = parse_tree_safe(file_path)

    decl_node = find_declaration_by_name_and_line(
        tree.root_node, source, symbol, line_1_based
    )
    if decl_node is None:
        decl_node = find_declaration_by_name(tree.root_node, source, symbol)
    if decl_node is None:
        result = get_nearby_source_snippet(
            project_root=project_root,
            relative_path=relative_path,
            line_1_based=line_1_based,
        )
        _disk_cache_set("global_symbol_source", cache_payload, {"text": result[0], "kind": result[1]})
        return result

    result = {"text": node_text(decl_node, source), "kind": "global_declaration"}
    _disk_cache_set("global_symbol_source", cache_payload, result)
    return result["text"], result["kind"]

def parse_bootlin_line_field(line_field) -> list[int]:
    if isinstance(line_field, int):
        return [line_field]
    if not line_field:
        return []

    out = []
    for x in str(line_field).split(","):
        x = x.strip()
        if not x:
            continue
        try:
            out.append(int(x))
        except ValueError:
            pass
    return out


def find_enclosing_function_by_line(
    root: Node,
    source: bytes,
    line_1_based: int,
) -> Optional[Node]:
    for node in iter_nodes(root):
        if node.type != "function_definition":
            continue
        if line_contains_node(line_1_based, node):
            return node
    return None


def get_function_name_from_definition(node: Node, source: bytes) -> Optional[str]:
    substack = [node]
    while substack:
        cur = substack.pop()
        if cur.type.endswith("_declarator"):
            return extract_identifier_from_declarator(cur, source)
        substack.extend(reversed(cur.children))
    return None


def get_reference_jump_candidates(
    project_root: str,
    references: list[dict],
    max_candidates: int = 8,
) -> list[dict]:
    cache_payload = {
        "project_root": project_root,
        "references": references,
        "max_candidates": max_candidates,
    }
    cached = _disk_cache_get("reference_jump_candidates", cache_payload)
    if cached is not None:
        return cached

    results = []
    seen = set()

    for ref in references:
        rel_path = ref.get("path")
        if not rel_path:
            continue

        file_path = Path(project_root) / rel_path
        if not file_path.exists():
            continue

        source = read_bytes_safe(file_path)
        tree = parse_tree_safe(file_path)

        for line_no in parse_bootlin_line_field(ref.get("line")):
            fn = find_enclosing_function_by_line(tree.root_node, source, line_no)
            if fn is None:
                continue

            fn_name = get_function_name_from_definition(fn, source)
            if not fn_name:
                continue

            key = (rel_path, fn_name, fn.start_point[0] + 1)
            if key in seen:
                continue
            seen.add(key)

            results.append({
                "symbol": fn_name,
                "path": rel_path,
                "line": fn.start_point[0] + 1,
                "ref_line": line_no,
                "reason": "enclosing function of Bootlin reference",
            })

            if len(results) >= max_candidates:
                _disk_cache_set("reference_jump_candidates", cache_payload, results)
                return results

    _disk_cache_set("reference_jump_candidates", cache_payload, results)
    return results

def get_initializer_occurrences(
    project_root: str,
    identifiers: list[str],
    max_results: int = 10,
) -> list[dict]:
    cache_payload = {
        "project_root": project_root,
        "identifiers": identifiers,
        "max_results": max_results,
    }
    cached = _disk_cache_get("initializer_occurrences", cache_payload)
    if cached is not None:
        return cached

    results: list[dict] = []
    identifiers = [x for x in identifiers if x]
    if not identifiers:
        return results

    for path in find_c_family_files_containing(project_root, tuple(identifiers)):
        source = read_bytes_safe(path)
        tree = parse_tree_safe(path)

        for node in iter_nodes(tree.root_node):
            if node.type not in {"declaration", "init_declarator"}:
                continue

            text = node_text(node, source)
            if "=" not in text:
                continue

            if not any(re.search(rf"\b{re.escape(ident)}\b", text) for ident in identifiers):
                continue

            results.append(
                {
                    "kind": "initializer_occurrence",
                    "path": str(path.relative_to(project_root)),
                    "line": node.start_point[0] + 1,
                    "text": text,
                }
            )
            if len(results) >= max_results:
                _disk_cache_set("initializer_occurrences", cache_payload, results)
                return results

    _disk_cache_set("initializer_occurrences", cache_payload, results)
    return results


def _symbol_search_terms(symbol: str) -> list[str]:
    terms: list[str] = []
    raw = (symbol or "").strip()
    if raw:
        terms.append(raw)

    for sep in ("::", "->", "."):
        if sep in raw:
            tail = raw.rsplit(sep, 1)[-1].strip()
            if tail:
                terms.append(tail)

    if raw.endswith("__fct"):
        terms.extend(["__fct", "struct __gconv_step"])

    return list(dict.fromkeys(t for t in terms if t))


def _line_window(lines: list[str], line_no: int, radius: int = 8) -> tuple[int, str]:
    start = max(1, line_no - radius)
    end = min(len(lines), line_no + radius)
    numbered = [
        f"{idx}: {lines[idx - 1]}"
        for idx in range(start, end + 1)
    ]
    return start, "\n".join(numbered)


def get_provider_context_bundle(
    project_root: str,
    symbol: str,
    icall_location: Optional[str] = None,
    icall_line: Optional[int] = None,
    max_results: int = 24,
) -> dict:
    cache_payload = {
        "project_root": project_root,
        "symbol": symbol,
        "icall_location": icall_location,
        "icall_line": icall_line,
        "max_results": max_results,
    }
    cached = _disk_cache_get("provider_context_bundle", cache_payload)
    if cached is not None:
        return cached

    terms = _symbol_search_terms(symbol)
    results: list[dict] = []
    seen = set()

    preferred_names = {
        "gconv_int.h",
        "gconv_db.c",
        "gconv_builtin.c",
        "gconv_cache.c",
        "gconv_conf.c",
        "skeleton.c",
    }
    paths = list(collect_c_family_files(project_root))
    paths.sort(key=lambda p: (p.name not in preferred_names, str(p)))

    for path in paths:
        try:
            lines = read_text_safe(path).splitlines()
        except Exception:
            continue
        text = "\n".join(lines)
        for term in terms:
            if term not in text:
                continue
            for i, line in enumerate(lines, start=1):
                if term not in line:
                    continue
                key = (str(path), i, term)
                if key in seen:
                    continue
                seen.add(key)
                start, snippet = _line_window(lines, i)
                results.append(
                    {
                        "kind": "provider_occurrence",
                        "path": str(path.relative_to(project_root)),
                        "line": start,
                        "text": snippet,
                    }
                )
                if len(results) >= max_results:
                    result = {
                        "primary_block": _format_provider_context(symbol, results),
                        "primary_block_kind": "provider_context",
                        "provider_contexts": results,
                    }
                    _disk_cache_set("provider_context_bundle", cache_payload, result)
                    return result

    if icall_location and icall_line:
        snippet, _ = get_nearby_source_snippet(
            project_root=project_root,
            relative_path=icall_location,
            line_1_based=icall_line,
            radius=80,
        )
        results.append(
            {
                "kind": "callsite_fallback",
                "path": icall_location,
                "line": max(1, icall_line - 80),
                "text": snippet,
            }
        )

    result = {
        "primary_block": _format_provider_context(symbol, results),
        "primary_block_kind": "provider_context",
        "provider_contexts": results,
    }
    _disk_cache_set("provider_context_bundle", cache_payload, result)
    return result


def _format_provider_context(symbol: str, contexts: list[dict]) -> str:
    if not contexts:
        return f"[provider_context] no local provider snippets found for {symbol}"
    chunks = [f"[provider_context] symbol={symbol}"]
    for ctx in contexts:
        chunks.append(f"[{ctx['kind']}] {ctx['path']}:{ctx['line']}\n{ctx['text']}")
    return "\n\n".join(chunks)
