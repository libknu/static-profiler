from pathlib import Path
from typing import Optional

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node


def get_c_language() -> Language:
    return Language(tsc.language())


def _node_text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8")


def extract_identifier_from_declarator(node: Node, source: bytes) -> Optional[str]:
    if node.type == "identifier":
        return _node_text(node, source)

    for child in node.children:
        name = extract_identifier_from_declarator(child, source)
        if name is not None:
            return name
    return None


def line_contains_node(line_1_based: int, node: Node) -> bool:
    start_line = node.start_point[0] + 1
    end_line = node.end_point[0] + 1
    return start_line <= line_1_based <= end_line


def _iter_nodes(root: Node):
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
    for node in _iter_nodes(root):
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


def extract_macro_name_from_preproc_node(node: Node, source: bytes) -> Optional[str]:
    """
    tree-sitter-c의 preprocessor 노드에서 매크로 이름(identifier)을 찾는다.
    보통 preproc_def / preproc_function_def 아래에 identifier가 있다.
    """
    for sub in _iter_nodes(node):
        if sub.type == "identifier":
            return _node_text(sub, source)
    return None


def find_macro_definition_by_name_and_line(
    root: Node,
    source: bytes,
    symbol: str,
    line_1_based: int,
) -> Optional[Node]:
    """
    function-like macro와 object-like macro 둘 다 지원:
      - preproc_function_def
      - preproc_def
    """
    macro_node_types = {"preproc_function_def", "preproc_def"}

    for node in _iter_nodes(root):
        if node.type not in macro_node_types:
            continue
        if not line_contains_node(line_1_based, node):
            continue

        name = extract_macro_name_from_preproc_node(node, source)
        if name == symbol:
            return node

    return None


def _parse_file(project_root: str, relative_path: str) -> tuple[bytes, Node]:
    file_path = Path(project_root) / relative_path
    source = file_path.read_bytes()

    parser = Parser(get_c_language())
    tree = parser.parse(source)
    return source, tree.root_node


def get_function_source(
    project_root: str,
    relative_path: str,
    symbol: str,
    line_1_based: int,
) -> tuple[str, str]:
    source, root = _parse_file(project_root, relative_path)

    fn_node = find_function_definition_by_name_and_line(
        root=root,
        source=source,
        symbol=symbol,
        line_1_based=line_1_based,
    )
    if fn_node is None:
        raise ValueError(
            f"function not found: symbol={symbol}, line={line_1_based}, "
            f"file={Path(project_root) / relative_path}"
        )

    text = _node_text(fn_node, source)
    return text, "function_definition"


def get_macro_source(
    project_root: str,
    relative_path: str,
    symbol: str,
    line_1_based: int,
) -> tuple[str, str]:
    source, root = _parse_file(project_root, relative_path)

    macro_node = find_macro_definition_by_name_and_line(
        root=root,
        source=source,
        symbol=symbol,
        line_1_based=line_1_based,
    )
    if macro_node is None:
        raise ValueError(
            f"macro not found: symbol={symbol}, line={line_1_based}, "
            f"file={Path(project_root) / relative_path}"
        )

    text = _node_text(macro_node, source)
    return text, macro_node.type


def get_symbol_source(
    project_root: str,
    relative_path: str,
    symbol: str,
    line_1_based: int,
    ident_kind: str,
) -> tuple[str, str]:
    """
    Bootlin ident의 type 값을 기준으로 적절한 extractor로 분기한다.
    현재 지원:
      - function
      - macro
    """
    if ident_kind == "function":
        return get_function_source(
            project_root=project_root,
            relative_path=relative_path,
            symbol=symbol,
            line_1_based=line_1_based,
        )

    if ident_kind == "macro":
        return get_macro_source(
            project_root=project_root,
            relative_path=relative_path,
            symbol=symbol,
            line_1_based=line_1_based,
        )

    raise ValueError(f"unsupported ident_kind: {ident_kind}")
