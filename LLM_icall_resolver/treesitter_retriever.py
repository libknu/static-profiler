from __future__ import annotations

from pathlib import Path
from typing import Optional, Iterable
import re

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node


def get_c_language() -> Language:
    return Language(tsc.language())


def build_parser() -> Parser:
    return Parser(get_c_language())


def read_text_safe(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def read_bytes_safe(path: Path) -> bytes:
    return path.read_bytes()


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
    file_path = Path(project_root) / relative_path
    source = read_bytes_safe(file_path)

    parser = build_parser()
    tree = parser.parse(source)

    fn_node = find_function_definition_by_name_and_line(
        tree.root_node, source, symbol, line_1_based
    )
    if fn_node is None:
        raise ValueError(
            f"function not found: symbol={symbol}, line={line_1_based}, file={file_path}"
        )

    return node_text(fn_node, source), "function_definition"


def extract_call_like_identifier(icall_expr: str) -> Optional[str]:
    m = re.match(r"\s*([A-Za-z_]\w*)\s*\(", icall_expr)
    if not m:
        return None
    return m.group(1)


def extract_field_names(expr: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"(?:->|\.)([A-Za-z_]\w*)", expr)))


def collect_c_family_files(project_root: str) -> list[Path]:
    root = Path(project_root)
    exts = {".c", ".h", ".hpp", ".hh", ".cc"}
    return [p for p in root.rglob("*") if p.is_file() and p.suffix in exts]


def get_macro_definitions(
    project_root: str,
    macro_name: str,
    max_results: int = 5,
) -> list[dict]:
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
                    return results
                i = j
            else:
                i += 1
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
    results: list[dict] = []
    field_pat = re.compile(rf"\b{re.escape(field_name)}\b")

    for path in collect_c_family_files(project_root):
        source = read_bytes_safe(path)
        parser = build_parser()
        tree = parser.parse(source)

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
                    return results
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
                return results
    return results


def get_context_bundle(
    project_root: str,
    relative_path: str,
    symbol: str,
    line_1_based: int,
    icall_expr: str,
) -> dict:
    function_text, function_kind = get_function_source(
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
        struct_defs.extend(get_struct_definitions_for_field(project_root, field, max_results=3))

    local_assignments = get_local_assignment_lines(
        relative_path=relative_path,
        function_text=function_text,
        identifiers=field_names + ([callee_token] if callee_token else []),
    )

    return {
        "primary_block": function_text,
        "primary_block_kind": function_kind,
        "macro_definitions": macro_defs,
        "struct_definitions": struct_defs,
        "local_assignments": local_assignments,
    }
