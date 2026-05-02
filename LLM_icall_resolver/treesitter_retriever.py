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

    return node_text(fn_node, source), "function_definition"

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




def get_context_bundle(
    project_root: str,
    relative_path: str,
    symbol: str,
    line_1_based: int,
    icall_expr: str,
    ident_kind: str = "function",
) -> dict:
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

    return {
        "primary_block": primary_text,
        "primary_block_kind": primary_kind,
        "macro_definitions": macro_defs,
        "struct_definitions": struct_defs,
        "local_assignments": local_assignments,
        "initializer_definitions": initializer_defs,
    }


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
    return "\n".join(numbered), "source_snippet"


def get_global_symbol_source(
    project_root: str,
    relative_path: str,
    symbol: str,
    line_1_based: int,
) -> tuple[str, str]:
    file_path = Path(project_root) / relative_path
    source = read_bytes_safe(file_path)

    parser = build_parser()
    tree = parser.parse(source)

    decl_node = find_declaration_by_name_and_line(
        tree.root_node, source, symbol, line_1_based
    )
    if decl_node is None:
        decl_node = find_declaration_by_name(tree.root_node, source, symbol)
    if decl_node is None:
        return get_nearby_source_snippet(
            project_root=project_root,
            relative_path=relative_path,
            line_1_based=line_1_based,
        )

    return node_text(decl_node, source), "global_declaration"

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
        parser = build_parser()
        tree = parser.parse(source)

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
                return results

    return results

def get_initializer_occurrences(
    project_root: str,
    identifiers: list[str],
    max_results: int = 10,
) -> list[dict]:
    results: list[dict] = []
    identifiers = [x for x in identifiers if x]
    if not identifiers:
        return results

    for path in collect_c_family_files(project_root):
        source = read_bytes_safe(path)
        parser = build_parser()
        tree = parser.parse(source)

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
                return results

    return results
