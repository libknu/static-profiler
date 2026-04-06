from __future__ import annotations

from pathlib import Path
from typing import Optional

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node


def get_c_language() -> Language:
    return Language(tsc.language())


def extract_identifier_from_declarator(node: Node, source: bytes) -> Optional[str]:
    """
    C declarator subtree에서 최종 함수 이름(identifier)을 재귀적으로 찾는다.
    function_declarator / pointer_declarator / parenthesized_declarator 등을 모두 통과한다.
    """
    if node.type == "identifier":
        return source[node.start_byte:node.end_byte].decode("utf-8")

    for child in node.children:
        name = extract_identifier_from_declarator(child, source)
        if name is not None:
            return name
    return None


def line_contains_node(line_1_based: int, node: Node) -> bool:
    """
    tree-sitter point.row는 0-based 이므로 변환해서 비교.
    end_point는 노드 끝 '직후' 위치 성격으로 보는 편이 안전해서
    start <= line <= end+1 방식보다, 일반적으로 start~end 범위로 충분하다.
    """
    start_line = node.start_point[0] + 1
    end_line = node.end_point[0] + 1
    return start_line <= line_1_based <= end_line


def find_function_definition_by_name_and_line(
    root: Node,
    source: bytes,
    symbol: str,
    line_1_based: int,
) -> Optional[Node]:
    """
    파일 전체를 순회하면서:
    1) function_definition 노드이고
    2) 지정한 line을 포함하며
    3) declarator에서 추출한 이름이 symbol과 일치하는
    노드를 찾는다.
    """
    stack = [root]

    while stack:
        node = stack.pop()

        if node.type == "function_definition" and line_contains_node(line_1_based, node):
            declarator = None
            for child in node.children:
                if child.type == "function_declarator" or child.type.endswith("_declarator"):
                    declarator = child
                    break

            if declarator is None:
                # direct child에서 못 찾으면 subtree 전체에서 찾아본다.
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
    glibc_root: str | Path,
    relative_path: str,
    symbol: str,
    line_1_based: int,
) -> str:
    """
    예:
      glibc_root   = '/home/jiwoo/workspace/glibc-src/glibc-2.41'
      relative_path = 'sunrpc/key_call.c'
      symbol        = 'key_call_socket'
      line_1_based  = 488
    """
    file_path = Path(glibc_root) / relative_path
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

    return source[fn_node.start_byte:fn_node.end_byte].decode("utf-8")


if __name__ == "__main__":
    glibc_root = "/home/jiwoo/workspace/glibc-src/glibc-2.41"
    relative_path = "sunrpc/key_call.c"
    symbol = "key_call_socket"
    line_1_based = 488

    fn_src = get_function_source(
        glibc_root=glibc_root,
        relative_path=relative_path,
        symbol=symbol,
        line_1_based=line_1_based,
    )
    print(fn_src)
