from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import re

from .treesitter_retriever import collect_c_family_files, read_text_safe


IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")


LIBIO_MACRO_TO_FIELD = {
    "_IO_FINISH": "finish",
    "_IO_WFINISH": "finish",
    "_IO_OVERFLOW": "overflow",
    "_IO_WOVERFLOW": "overflow",
    "_IO_UNDERFLOW": "underflow",
    "_IO_WUNDERFLOW": "underflow",
    "_IO_UFLOW": "uflow",
    "_IO_WUFLOW": "uflow",
    "_IO_PBACKFAIL": "pbackfail",
    "_IO_WPBACKFAIL": "pbackfail",
    "_IO_XSPUTN": "xsputn",
    "_IO_WXSPUTN": "xsputn",
    "_IO_XSGETN": "xsgetn",
    "_IO_WXSGETN": "xsgetn",
    "_IO_SEEKOFF": "seekoff",
    "_IO_WSEEKOFF": "seekoff",
    "_IO_SEEKPOS": "seekpos",
    "_IO_WSEEKPOS": "seekpos",
    "_IO_SETBUF": "setbuf",
    "_IO_WSETBUF": "setbuf",
    "_IO_SYNC": "sync",
    "_IO_WSYNC": "sync",
    "_IO_DOALLOCATE": "doallocate",
    "_IO_WDOALLOCATE": "doallocate",
    "_IO_SYSREAD": "read",
    "_IO_WSYSREAD": "read",
    "_IO_SYSWRITE": "write",
    "_IO_WSYSWRITE": "write",
    "_IO_SYSSEEK": "seek",
    "_IO_WSYSSEEK": "seek",
    "_IO_SYSCLOSE": "close",
    "_IO_WSYSCLOSE": "close",
    "_IO_SYSSTAT": "stat",
    "_IO_WSYSSTAT": "stat",
    "_IO_SHOWMANYC": "showmanyc",
    "_IO_WSHOWMANYC": "showmanyc",
    "_IO_IMBUE": "imbue",
    "_IO_WIMBUE": "imbue",
    "_IO_sputn": "xsputn",
    "_IO_sgetn": "xsgetn",
    "_IO_sungetc": "pbackfail",
    "_IO_sputbackc": "pbackfail",
    "_IO_sputbackwc": "pbackfail",
}


SUNRPC_MACRO_FIELDS = {
    "CLNT_CALL": ("clnt_ops", "cl_call"),
    "clnt_call": ("clnt_ops", "cl_call"),
    "CLNT_ABORT": ("clnt_ops", "cl_abort"),
    "clnt_abort": ("clnt_ops", "cl_abort"),
    "CLNT_GETERR": ("clnt_ops", "cl_geterr"),
    "clnt_geterr": ("clnt_ops", "cl_geterr"),
    "CLNT_FREERES": ("clnt_ops", "cl_freeres"),
    "clnt_freeres": ("clnt_ops", "cl_freeres"),
    "CLNT_DESTROY": ("clnt_ops", "cl_destroy"),
    "clnt_destroy": ("clnt_ops", "cl_destroy"),
    "CLNT_CONTROL": ("clnt_ops", "cl_control"),
    "clnt_control": ("clnt_ops", "cl_control"),
    "SVC_RECV": ("xp_ops", "xp_recv"),
    "svc_recv": ("xp_ops", "xp_recv"),
    "SVC_STAT": ("xp_ops", "xp_stat"),
    "svc_stat": ("xp_ops", "xp_stat"),
    "SVC_GETARGS": ("xp_ops", "xp_getargs"),
    "svc_getargs": ("xp_ops", "xp_getargs"),
    "SVC_REPLY": ("xp_ops", "xp_reply"),
    "svc_reply": ("xp_ops", "xp_reply"),
    "SVC_FREEARGS": ("xp_ops", "xp_freeargs"),
    "svc_freeargs": ("xp_ops", "xp_freeargs"),
    "SVC_DESTROY": ("xp_ops", "xp_destroy"),
    "svc_destroy": ("xp_ops", "xp_destroy"),
    "XDR_GETLONG": ("xdr_ops", "x_getlong"),
    "XDR_PUTLONG": ("xdr_ops", "x_putlong"),
    "XDR_GETBYTES": ("xdr_ops", "x_getbytes"),
    "XDR_PUTBYTES": ("xdr_ops", "x_putbytes"),
    "XDR_GETPOS": ("xdr_ops", "x_getpostn"),
    "XDR_SETPOS": ("xdr_ops", "x_setpostn"),
    "XDR_INLINE": ("xdr_ops", "x_inline"),
    "XDR_DESTROY": ("xdr_ops", "x_destroy"),
    "XDR_GETINT32": ("xdr_ops", "x_getint32"),
    "XDR_PUTINT32": ("xdr_ops", "x_putint32"),
    "AUTH_NEXTVERF": ("auth_ops", "ah_nextverf"),
    "auth_nextverf": ("auth_ops", "ah_nextverf"),
    "AUTH_MARSHALL": ("auth_ops", "ah_marshal"),
    "auth_marshall": ("auth_ops", "ah_marshal"),
    "AUTH_VALIDATE": ("auth_ops", "ah_validate"),
    "auth_validate": ("auth_ops", "ah_validate"),
    "AUTH_REFRESH": ("auth_ops", "ah_refresh"),
    "auth_refresh": ("auth_ops", "ah_refresh"),
    "AUTH_DESTROY": ("auth_ops", "ah_destroy"),
    "auth_destroy": ("auth_ops", "ah_destroy"),
}


SUNRPC_FIELD_ORDER = {
    "clnt_ops": ["cl_call", "cl_abort", "cl_geterr", "cl_freeres", "cl_destroy", "cl_control"],
    "xp_ops": ["xp_recv", "xp_stat", "xp_getargs", "xp_reply", "xp_freeargs", "xp_destroy"],
    "xdr_ops": [
        "x_getlong",
        "x_putlong",
        "x_getbytes",
        "x_putbytes",
        "x_getpostn",
        "x_setpostn",
        "x_inline",
        "x_destroy",
        "x_getint32",
        "x_putint32",
    ],
    "auth_ops": ["ah_nextverf", "ah_marshal", "ah_validate", "ah_refresh", "ah_destroy"],
}


def normalize_source_path(project_root: str, relative_path: str | None) -> tuple[str | None, str | None]:
    if not relative_path:
        return relative_path, None

    root = Path(project_root)
    original = relative_path.strip()
    if not original:
        return original, None

    direct = root / original
    if direct.is_file():
        return original, None

    normalized = original.lstrip("./")
    direct = root / normalized
    if direct.is_file():
        return normalized, f"normalized source path from {original} to {normalized}"

    suffix_matches = [
        p.relative_to(root).as_posix()
        for p in collect_c_family_files(project_root)
        if p.relative_to(root).as_posix().endswith("/" + normalized)
    ]
    if len(suffix_matches) == 1:
        return suffix_matches[0], f"normalized source path from {original} to {suffix_matches[0]}"

    basename = Path(normalized).name
    if basename:
        basename_matches = [
            p.relative_to(root).as_posix()
            for p in collect_c_family_files(project_root)
            if p.name == basename
        ]
        if len(basename_matches) == 1:
            return basename_matches[0], f"normalized source path from {original} to {basename_matches[0]}"

    return original, None


def recover_icall_expr(
    project_root: str,
    relative_path: str | None,
    line_1_based: int | None,
    current_expr: str | None = None,
) -> tuple[str | None, str | None]:
    if current_expr and current_expr.strip():
        return current_expr, None
    if not relative_path or not line_1_based:
        return current_expr, None

    file_path = Path(project_root) / relative_path
    if not file_path.is_file():
        return current_expr, None

    lines = read_text_safe(file_path).splitlines()
    if not 1 <= line_1_based <= len(lines):
        return current_expr, None

    start = line_1_based - 1
    for _ in range(8):
        if start <= 0:
            break
        prev = lines[start - 1].strip()
        if not prev or prev.startswith("#") or prev.endswith((";", "{", "}")):
            break
        start -= 1

    end = line_1_based - 1
    paren_balance = 0
    for idx in range(start, min(len(lines), line_1_based + 12)):
        paren_balance += lines[idx].count("(") - lines[idx].count(")")
        end = idx
        if ";" in lines[idx] and paren_balance <= 0:
            break

    expr = " ".join(line.strip() for line in lines[start : end + 1]).strip()
    expr = re.sub(r"\s+", " ", expr)
    if not expr:
        return current_expr, None
    return expr, f"recovered icall_expr from {relative_path}:{line_1_based}"


def prepare_callsite_inputs(state: dict) -> dict:
    updates: dict = {}
    observations: list[str] = []

    normalized_path, path_obs = normalize_source_path(
        state.get("project_root", ""),
        state.get("icall_location"),
    )
    if normalized_path and normalized_path != state.get("icall_location"):
        updates["icall_location"] = normalized_path
    if path_obs:
        observations.append(path_obs)

    expr, expr_obs = recover_icall_expr(
        state.get("project_root", ""),
        normalized_path or state.get("icall_location"),
        state.get("icall_line"),
        state.get("icall_expr"),
    )
    if expr and expr != state.get("icall_expr"):
        updates["icall_expr"] = expr
    if expr_obs:
        observations.append(expr_obs)

    if observations:
        updates["observations"] = observations
    return updates


@lru_cache(maxsize=8)
def _libio_vtable_targets(project_root: str) -> dict[str, list[str]]:
    path = Path(project_root) / "libio" / "vtables.c"
    if not path.is_file():
        return {}

    text = read_text_safe(path)
    targets: dict[str, list[str]] = {}
    for line in text.splitlines():
        match = re.search(r"JUMP_INIT\s*\(\s*([A-Za-z_]\w*)\s*,\s*(.*?)\s*\),?\s*$", line)
        if not match:
            continue
        field, raw_target = match.groups()
        names = IDENT_RE.findall(raw_target)
        if not names:
            continue
        target = names[-1]
        if target.startswith("_IO_") or target.startswith("__printf") or target.startswith("__wprintf"):
            targets.setdefault(field, []).append(target)

    return {field: list(dict.fromkeys(values)) for field, values in targets.items()}


def _extract_struct_initializer_body(text: str, struct_name: str) -> list[str]:
    bodies: list[str] = []
    pattern = re.compile(
        rf"(?:static\s+)?(?:const\s+)?struct\s+{re.escape(struct_name)}\s+\w+\s*=\s*\{{",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        depth = 1
        idx = match.end()
        while idx < len(text) and depth:
            if text[idx] == "{":
                depth += 1
            elif text[idx] == "}":
                depth -= 1
            idx += 1
        if depth == 0:
            bodies.append(text[match.end() : idx - 1])
    return bodies


@lru_cache(maxsize=8)
def _sunrpc_ops_targets(project_root: str, struct_name: str) -> dict[str, list[str]]:
    field_order = SUNRPC_FIELD_ORDER[struct_name]
    targets = {field: [] for field in field_order}
    root = Path(project_root)
    sunrpc = root / "sunrpc"
    if not sunrpc.is_dir():
        return targets

    for path in sunrpc.glob("*.c"):
        text = read_text_safe(path)
        for body in _extract_struct_initializer_body(text, struct_name):
            entries = []
            for raw in body.split(","):
                names = IDENT_RE.findall(raw)
                if not names:
                    continue
                name = names[-1]
                if name not in {"NULL", "FALSE", "TRUE"}:
                    entries.append(name)
            for field, target in zip(field_order, entries):
                targets[field].append(target)

    return {field: list(dict.fromkeys(values)) for field, values in targets.items()}


def _detect_called_macro(expr: str, names: set[str]) -> str | None:
    for name in sorted(names, key=len, reverse=True):
        if re.search(rf"\b{re.escape(name)}\s*\(", expr):
            return name
    return None


def _result(
    *,
    status: str,
    reason: str,
    candidates: list[str] | None = None,
    evidence: list[str] | None = None,
) -> dict:
    candidate_callees = list(dict.fromkeys(candidates or []))
    return {
        "matched": True,
        "resolution_status": status,
        "candidate_callees": candidate_callees,
        "analysis_summary": reason,
        "evidence": evidence or [],
    }


def classify_deterministically(state: dict) -> dict | None:
    expr = state.get("icall_expr") or ""
    location = state.get("icall_location") or ""
    project_root = state.get("project_root", "")
    caller = state.get("caller_symbol") or ""

    macro = _detect_called_macro(expr, set(LIBIO_MACRO_TO_FIELD))
    if macro:
        field = LIBIO_MACRO_TO_FIELD[macro]
        candidates = _libio_vtable_targets(project_root).get(field, [])
        if candidates:
            return _result(
                status="resolved",
                candidates=candidates,
                reason=(
                    f"{macro} dispatches through struct _IO_jump_t field {field}; "
                    "returning statically known libio vtable entries for that slot."
                ),
                evidence=[
                    f"macro={macro}",
                    f"field={field}",
                    "source=libio/vtables.c JUMP_INIT entries",
                ],
            )

    macro = _detect_called_macro(expr, set(SUNRPC_MACRO_FIELDS))
    if macro:
        struct_name, field = SUNRPC_MACRO_FIELDS[macro]
        candidates = _sunrpc_ops_targets(project_root, struct_name).get(field, [])
        if candidates:
            return _result(
                status="resolved",
                candidates=candidates,
                reason=(
                    f"{macro} dispatches through struct {struct_name} field {field}; "
                    "returning statically known RPC/XDR ops initializers for that slot."
                ),
                evidence=[
                    f"macro={macro}",
                    f"field={field}",
                    "source=sunrpc ops table initializers",
                ],
            )

    lowered_context = " ".join([expr, location, caller]).lower()
    if "dl_call_fct" in lowered_context and (
        "/nss/" in f"/{location}" or "nss" in lowered_context
    ):
        return _result(
            status="unresolved",
            reason=(
                "NSS backend dispatch through DL_CALL_FCT. The call is a real indirect "
                "dispatch, but the concrete backend is selected by runtime NSS service "
                "configuration, so this static pass leaves it unresolved."
            ),
            evidence=["pattern=DL_CALL_FCT", "domain=NSS backend dispatch"],
        )

    if "dl_call_fct" in lowered_context and (
        "gconv" in lowered_context or "iconv" in lowered_context
    ):
        return _result(
            status="unresolved",
            reason=(
                "gconv/iconv dispatch through DL_CALL_FCT. Builtin and loadable gconv "
                "modules are selected through conversion descriptors, so this static pass "
                "classifies the site but does not choose a unique callee."
            ),
            evidence=["pattern=DL_CALL_FCT", "domain=gconv/iconv provider dispatch"],
        )

    if "glro" in lowered_context or "vdso" in lowered_context:
        fields = re.findall(r"GLRO\s*\(\s*([A-Za-z_]\w*)\s*\)", expr)
        names = fields or re.findall(r"\b(dl_vdso_[A-Za-z_]\w*|vdso_[A-Za-z_]\w*)\b", expr)
        suffix = " Runtime pointer(s): " + ", ".join(dict.fromkeys(names)) + "." if names else ""
        return _result(
            status="unresolved",
            reason=(
                "vDSO/GLRO dispatch uses loader-populated runtime function pointers; "
                f"this static pass classifies the site but does not bind a fixed callee.{suffix}"
            ),
            evidence=["pattern=vDSO/GLRO runtime function pointer"],
        )

    if re.search(r"\b(?:dlsym|dlvsym|__libc_dlsym|__libc_dlvsym)\s*\(", expr):
        symbols = re.findall(r'"([^"]+)"', expr)
        suffix = f" Requested symbol(s): {', '.join(symbols)}." if symbols else ""
        return _result(
            status="unresolved",
            reason=(
                "dlsym/dlvsym returns a runtime-selected function pointer; this static "
                f"pass can identify the lookup pattern but not bind the loaded object.{suffix}"
            ),
            evidence=["pattern=dlsym/dlvsym runtime lookup"],
        )

    return None
