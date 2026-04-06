from pathlib import Path
from typing import Optional

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node


def get_c_language() -> Language:
    return Language(tsc.language())


def extract_identifier_from_declarator(node: Node, source: bytes) -> Optional[str]:
    if node.type == "identifier":
        return source[node.start_byte:node.end_byte].decode("utf-8")
    for child in node.children:
        name = extract_identifier_from_declarator(child, source)
        if name is not None:
            return name
    return None


def line_contains_node(line_1_based: int, node: Node) -> bool:
    start_line = node.start_point[0] + 1
    end_line = node.end_point[0] + 1
    return start_line <= line_1_based <= end_line


def find_function_definition_by_name_and_line(
    root: Node,
    source: bytes,
    symbol: str,
    line_1_based: int,
) -> Optional[Node]:
    stack = [root]
    while stack:
        node = stack.pop()

        if node.type == "function_definition" and line_contains_node(line_1_based, node):
            declarator = None

            substack = [node]
            while substack and declarator is None:
                cur = substack.pop()
                if cur.type.endswith("_declarator"):
                    declarator = cur
                    break
                substack.extend(reversed(cur.children))

            if declarator is not None:
                name = extract_identifier_from_declarator(declarator, source)
                if name == symbol:
                    return node

        stack.extend(reversed(node.children))
    return None


def get_function_source(
    project_root: str,
    relative_path: str,
    symbol: str,
    line_1_based: int,
) -> tuple[str, str]:
    file_path = Path(project_root) / relative_path
    source = file_path.read_bytes()

    parser = Parser(get_c_language())
    tree = parser.parse(source)

    fn_node = find_function_definition_by_name_and_line(
        tree.root_node, source, symbol, line_1_based
    )
    if fn_node is None:
        raise ValueError(
            f"function not found: symbol={symbol}, line={line_1_based}, file={file_path}"
        )

    text = source[fn_node.start_byte:fn_node.end_byte].decode("utf-8")
    return text, "function_definition"
