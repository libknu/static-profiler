#include "gcc-plugin.h"
#include "plugin-version.h"

#include "context.h"
#include "coretypes.h"
#include "backend.h"
#include "tree.h"
#include "rtl.h"
#include "tm.h"
#include "function.h"
#include "basic-block.h"
#include "print-rtl.h"
#include "tree-pass.h"
#include "cfghooks.h"

#include "gimple.h"
#include "gimple-iterator.h"
#include "tree-ssa.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <fstream>
#include <sstream>

int plugin_is_GPL_compatible;

static std::string g_outdir = ".";
static std::string g_functions_file = "functions_seen.csv";
static std::string g_direct_file = "direct_edges.csv";
static std::string g_indirect_file = "indirect_callsites.csv";
static std::string g_syscall_file = "syscall_sites.csv";

/* New outputs for local indirect-call resolution */
static std::string g_indirect_operands_file = "indirect_call_operands.csv";
/*
 * columns:
 *   tu,function,bb,stmt_idx,loc,callee_kind,callee_value
 */
static std::string g_local_defs_file = "local_value_defs.csv";
/*
 * columns:
 *   tu,function,lhs_ssa,def_kind,rhs_value,loc
 *
 * def_kind:
 *   direct_addr
 *   copy
 *   call_result
 *   unknown
 */
static std::string g_local_phi_file = "local_phi_edges.csv";
/*
 * columns:
 *   tu,function,lhs_ssa,arg_index,arg_kind,arg_value,loc
 */

static std::string join_path(const std::string &a, const std::string &b) {
    if (a.empty()) return b;
    if (a.back() == '/') return a + b;
    return a + "/" + b;
}

static void append_line(const std::string &path, const std::string &line) {
    std::ofstream ofs(path, std::ios::app);
    ofs << line << "\n";
}

static std::string get_current_function_name() {
    if (!current_function_decl) return "<unknown>";
    tree decl_name = DECL_NAME(current_function_decl);
    if (!decl_name) return "<unknown>";
    const char *name = IDENTIFIER_POINTER(decl_name);
    return name ? std::string(name) : std::string("<unknown>");
}

static std::string get_current_tu_name() {
    const char *src = main_input_filename;
    return src ? std::string(src) : std::string("<unknown-tu>");
}

static std::string sanitize_csv(const std::string &s) {
    std::string out = s;
    for (char &c : out) {
        if (c == ',' || c == '\n' || c == '\r')
            c = '_';
    }
    return out;
}

static std::string get_location_string(location_t loc) {
    if (loc == UNKNOWN_LOCATION)
        return "unknown";

    expanded_location xloc = expand_location(loc);
    std::ostringstream oss;
    if (xloc.file)
        oss << xloc.file;
    else
        oss << "unknown";
    oss << ":" << xloc.line << ":" << xloc.column;
    return oss.str();
}

static std::string get_rtl_location_string(rtx_insn *insn) {
    if (!insn)
        return "unknown";

    location_t loc = INSN_LOCATION(insn);
    return get_location_string(loc);
}

static void log_function_seen(const std::string &tu, const std::string &fn) {
    append_line(join_path(g_outdir, g_functions_file),
                sanitize_csv(tu) + "," + sanitize_csv(fn));
}

static void log_direct_edge(const std::string &tu,
                            const std::string &caller,
                            const std::string &callee) {
    append_line(join_path(g_outdir, g_direct_file),
                sanitize_csv(tu) + "," + sanitize_csv(caller) + "," +
                sanitize_csv(callee));
}

static void log_indirect_callsite(const std::string &tu,
                                  const std::string &caller,
                                  int bb_index,
                                  int insn_idx,
                                  const std::string &loc,
                                  const std::string &target_code) {
    append_line(join_path(g_outdir, g_indirect_file),
                sanitize_csv(tu) + "," + sanitize_csv(caller) + "," +
                std::to_string(bb_index) + "," + std::to_string(insn_idx) + "," +
                sanitize_csv(loc) + "," + sanitize_csv(target_code));
}

static void log_syscall_site(const std::string &tu,
                             const std::string &caller,
                             const std::string &site_kind,
                             const std::string &callee,
                             const std::string &syscall_nr) {
    append_line(join_path(g_outdir, g_syscall_file),
                sanitize_csv(tu) + "," + sanitize_csv(caller) + "," +
                sanitize_csv(site_kind) + "," + sanitize_csv(callee) + "," +
                sanitize_csv(syscall_nr));
}

static void log_indirect_call_operand(const std::string &tu,
                                      const std::string &caller,
                                      int bb_index,
                                      int stmt_idx,
                                      const std::string &loc,
                                      const std::string &callee_kind,
                                      const std::string &callee_value) {
    append_line(join_path(g_outdir, g_indirect_operands_file),
                sanitize_csv(tu) + "," + sanitize_csv(caller) + "," +
                std::to_string(bb_index) + "," + std::to_string(stmt_idx) + "," +
                sanitize_csv(loc) + "," + sanitize_csv(callee_kind) + "," +
                sanitize_csv(callee_value));
}

static void log_local_value_def(const std::string &tu,
                                const std::string &caller,
                                const std::string &lhs_ssa,
                                const std::string &def_kind,
                                const std::string &rhs_value,
                                const std::string &loc) {
    append_line(join_path(g_outdir, g_local_defs_file),
                sanitize_csv(tu) + "," + sanitize_csv(caller) + "," +
                sanitize_csv(lhs_ssa) + "," + sanitize_csv(def_kind) + "," +
                sanitize_csv(rhs_value) + "," + sanitize_csv(loc));
}

static void log_local_phi_edge(const std::string &tu,
                               const std::string &caller,
                               const std::string &lhs_ssa,
                               int arg_index,
                               const std::string &arg_kind,
                               const std::string &arg_value,
                               const std::string &loc) {
    append_line(join_path(g_outdir, g_local_phi_file),
                sanitize_csv(tu) + "," + sanitize_csv(caller) + "," +
                sanitize_csv(lhs_ssa) + "," + std::to_string(arg_index) + "," +
                sanitize_csv(arg_kind) + "," + sanitize_csv(arg_value) + "," +
                sanitize_csv(loc));
}

enum WrapperKind {
    WRAP_NONE = 0,
    WRAP_EXPLICIT_SYSCALL,
    WRAP_SYSCALL_CANCEL,
    WRAP_INTERNAL_SYSCALL_CANCEL,
    WRAP_SYSCALL_CANCEL_ARCH,
    WRAP_NOCANCEL_HELPER
};

static WrapperKind classify_wrapper(const char *callee) {
    if (!callee) return WRAP_NONE;

    if (std::strcmp(callee, "syscall") == 0)
        return WRAP_EXPLICIT_SYSCALL;

    if (std::strcmp(callee, "__syscall_cancel") == 0)
        return WRAP_SYSCALL_CANCEL;

    if (std::strcmp(callee, "__internal_syscall_cancel") == 0)
        return WRAP_INTERNAL_SYSCALL_CANCEL;

    if (std::strcmp(callee, "__syscall_cancel_arch") == 0)
        return WRAP_SYSCALL_CANCEL_ARCH;

    if (std::strstr(callee, "nocancel") != nullptr)
        return WRAP_NOCANCEL_HELPER;

    return WRAP_NONE;
}

static const char *wrapper_kind_to_site_kind(WrapperKind k) {
    switch (k) {
        case WRAP_EXPLICIT_SYSCALL:
            return "explicit-syscall-func";
        case WRAP_SYSCALL_CANCEL:
        case WRAP_INTERNAL_SYSCALL_CANCEL:
        case WRAP_SYSCALL_CANCEL_ARCH:
        case WRAP_NOCANCEL_HELPER:
            return "glibc-wrapper";
        default:
            return "unknown";
    }
}

static const char *get_direct_callee_name(rtx_insn *insn) {
    rtx call = PATTERN(insn);
    if (!call) return nullptr;

    rtx expr = nullptr;
    rtx set = single_set(insn);
    if (set) expr = SET_SRC(set);
    else expr = call;

    if (!expr) return nullptr;

    if (GET_CODE(expr) == CALL) {
        rtx target = XEXP(expr, 0);

        if (target && GET_CODE(target) == MEM) {
            rtx mem_target = XEXP(target, 0);
            if (mem_target && GET_CODE(mem_target) == SYMBOL_REF)
                return XSTR(mem_target, 0);
        }

        if (target && GET_CODE(target) == SYMBOL_REF)
            return XSTR(target, 0);
    }

    if (GET_CODE(call) == CALL) {
        rtx target = XEXP(call, 0);

        if (target && GET_CODE(target) == MEM) {
            rtx mem_target = XEXP(target, 0);
            if (mem_target && GET_CODE(mem_target) == SYMBOL_REF)
                return XSTR(mem_target, 0);
        }

        if (target && GET_CODE(target) == SYMBOL_REF)
            return XSTR(target, 0);
    }

    return nullptr;
}

static rtx get_call_target(rtx_insn *insn) {
    rtx call = PATTERN(insn);
    if (!call) return nullptr;

    rtx expr = nullptr;
    rtx set = single_set(insn);
    if (set) expr = SET_SRC(set);
    else expr = call;

    if (!expr) return nullptr;

    if (GET_CODE(expr) == CALL)
        return XEXP(expr, 0);

    if (GET_CODE(call) == CALL)
        return XEXP(call, 0);

    return nullptr;
}

static std::string classify_call_target(rtx target) {
    if (!target) return "unknown";

    enum rtx_code code = GET_CODE(target);

    if (code == MEM) {
        rtx inner = XEXP(target, 0);
        if (!inner) return "mem";

        enum rtx_code inner_code = GET_CODE(inner);
        if (inner_code == SYMBOL_REF) return "mem-symbol_ref";
        if (inner_code == REG) return "mem-reg";
        if (inner_code == PLUS) return "mem-plus";
        if (inner_code == SUBREG) return "mem-subreg";
        return std::string("mem-") + GET_RTX_NAME(inner_code);
    }

    if (code == SYMBOL_REF) return "symbol_ref";
    if (code == REG) return "reg";
    if (code == SUBREG) return "subreg";

    return GET_RTX_NAME(code);
}

static bool is_x86_64_first_arg_reg(rtx x) {
    if (!x) return false;

    if (GET_CODE(x) == SUBREG)
        x = SUBREG_REG(x);

    if (GET_CODE(x) != REG)
        return false;

    return REGNO(x) == 5;  // rdi
}

static bool is_stack_push_mem(rtx x) {
    if (!x) return false;
    if (GET_CODE(x) != MEM) return false;

    rtx addr = XEXP(x, 0);
    if (!addr) return false;

    if (GET_CODE(addr) == PRE_DEC) {
        rtx base = XEXP(addr, 0);
        return base && GET_CODE(base) == REG && REGNO(base) == STACK_POINTER_REGNUM;
    }

    return false;
}

static std::string extract_syscall_nr_from_explicit_syscall_call(rtx_insn *call_insn) {
    if (!call_insn)
        return "unknown";

    int budget = 12;
    for (rtx_insn *prev = PREV_INSN(call_insn); prev && budget-- > 0; prev = PREV_INSN(prev)) {
        if (!INSN_P(prev))
            continue;

        rtx set = single_set(prev);
        if (!set)
            continue;

        rtx dest = SET_DEST(set);
        rtx src  = SET_SRC(set);

        if (!is_x86_64_first_arg_reg(dest))
            continue;

        if (src && GET_CODE(src) == CONST_INT)
            return std::to_string((long long) INTVAL(src));

        if (src && (GET_CODE(src) == REG || GET_CODE(src) == SUBREG)) {
            rtx src_reg = src;
            if (GET_CODE(src_reg) == SUBREG)
                src_reg = SUBREG_REG(src_reg);

            if (GET_CODE(src_reg) == REG) {
                unsigned src_regno = REGNO(src_reg);
                int budget2 = 12;

                for (rtx_insn *prev2 = PREV_INSN(prev); prev2 && budget2-- > 0; prev2 = PREV_INSN(prev2)) {
                    if (!INSN_P(prev2))
                        continue;

                    rtx set2 = single_set(prev2);
                    if (!set2)
                        continue;

                    rtx dest2 = SET_DEST(set2);
                    rtx src2  = SET_SRC(set2);

                    if (GET_CODE(dest2) == SUBREG)
                        dest2 = SUBREG_REG(dest2);

                    if (GET_CODE(dest2) == REG && REGNO(dest2) == src_regno) {
                        if (src2 && GET_CODE(src2) == CONST_INT)
                            return std::to_string((long long) INTVAL(src2));
                    }
                }
            }
        }
    }

    return "unknown";
}

static std::string extract_syscall_nr_from_syscall_cancel_call(rtx_insn *call_insn) {
    if (!call_insn)
        return "unknown";

    int budget = 16;
    for (rtx_insn *prev = PREV_INSN(call_insn); prev && budget-- > 0; prev = PREV_INSN(prev)) {
        if (!INSN_P(prev))
            continue;

        rtx set = single_set(prev);
        if (!set)
            continue;

        rtx dest = SET_DEST(set);
        rtx src  = SET_SRC(set);

        if (is_stack_push_mem(dest) && src && GET_CODE(src) == CONST_INT) {
            return std::to_string((long long) INTVAL(src));
        }
    }

    return "unknown";
}

static const char *safe_asm_string(rtx x) {
    if (!x) return nullptr;
#if defined(ASM_OPERANDS_TEMPLATE)
    return ASM_OPERANDS_TEMPLATE(x);
#else
    return nullptr;
#endif
}

static int asm_input_count(rtx x) {
#if defined(ASM_OPERANDS_INPUT_LENGTH)
    return ASM_OPERANDS_INPUT_LENGTH(x);
#else
    (void)x;
    return 0;
#endif
}

static rtx asm_input_rtx(rtx x, int idx) {
#if defined(ASM_OPERANDS_INPUT)
    return ASM_OPERANDS_INPUT(x, idx);
#else
    (void)x; (void)idx;
    return nullptr;
#endif
}

static bool string_contains_syscall(const char *s) {
    return s && std::strstr(s, "syscall") != nullptr;
}

static rtx find_asm_operands_in_setsrc(rtx src) {
    if (!src) return nullptr;

    if (GET_CODE(src) == ASM_OPERANDS)
        return src;

    if (GET_CODE(src) == SUBREG)
        return find_asm_operands_in_setsrc(SUBREG_REG(src));

    return nullptr;
}

static rtx find_syscall_asm_operands(rtx_insn *insn) {
    if (!insn) return nullptr;

    rtx pat = PATTERN(insn);
    if (!pat) return nullptr;

    if (GET_CODE(pat) == SET) {
        rtx src = SET_SRC(pat);
        rtx asmop = find_asm_operands_in_setsrc(src);
        if (asmop && string_contains_syscall(safe_asm_string(asmop)))
            return asmop;
    }

    if (GET_CODE(pat) == PARALLEL) {
        int len = XVECLEN(pat, 0);
        for (int i = 0; i < len; ++i) {
            rtx elem = XVECEXP(pat, 0, i);
            if (!elem) continue;

            if (GET_CODE(elem) == SET) {
                rtx src = SET_SRC(elem);
                rtx asmop = find_asm_operands_in_setsrc(src);
                if (asmop && string_contains_syscall(safe_asm_string(asmop)))
                    return asmop;
            }
        }
    }

    return nullptr;
}

static rtx normalize_reg_like(rtx x) {
    if (!x) return nullptr;
    if (GET_CODE(x) == SUBREG)
        x = SUBREG_REG(x);
    return x;
}

static std::string extract_syscall_nr_from_inline_syscall_insn(rtx_insn *insn) {
    rtx asmop = find_syscall_asm_operands(insn);
    if (!asmop)
        return "unknown";

    int ninputs = asm_input_count(asmop);
    if (ninputs <= 0)
        return "unknown";

    rtx nr_input = asm_input_rtx(asmop, 0);
    if (!nr_input)
        return "unknown";

    nr_input = normalize_reg_like(nr_input);

    if (GET_CODE(nr_input) == CONST_INT) {
        return std::to_string((long long) INTVAL(nr_input));
    }

    if (GET_CODE(nr_input) != REG)
        return "unknown";

    unsigned nr_regno = REGNO(nr_input);

    int budget = 16;
    for (rtx_insn *prev = PREV_INSN(insn); prev && budget-- > 0; prev = PREV_INSN(prev)) {
        if (!INSN_P(prev))
            continue;

        rtx set = single_set(prev);
        if (!set)
            continue;

        rtx dest = normalize_reg_like(SET_DEST(set));
        rtx src  = SET_SRC(set);

        if (!dest || GET_CODE(dest) != REG)
            continue;

        if (REGNO(dest) != nr_regno)
            continue;

        if (src && GET_CODE(src) == CONST_INT)
            return std::to_string((long long) INTVAL(src));

        if (src && (GET_CODE(src) == REG || GET_CODE(src) == SUBREG)) {
            rtx src_reg = normalize_reg_like(src);
            if (src_reg && GET_CODE(src_reg) == REG) {
                unsigned src_regno = REGNO(src_reg);
                int budget2 = 12;

                for (rtx_insn *prev2 = PREV_INSN(prev); prev2 && budget2-- > 0; prev2 = PREV_INSN(prev2)) {
                    if (!INSN_P(prev2))
                        continue;

                    rtx set2 = single_set(prev2);
                    if (!set2)
                        continue;

                    rtx dest2 = normalize_reg_like(SET_DEST(set2));
                    rtx src2  = SET_SRC(set2);

                    if (!dest2 || GET_CODE(dest2) != REG)
                        continue;

                    if (REGNO(dest2) == src_regno && src2 && GET_CODE(src2) == CONST_INT)
                        return std::to_string((long long) INTVAL(src2));
                }
            }
        }
    }

    return "unknown";
}

/* ------------------------------------------------------------------------- */
/* GIMPLE / SSA helpers for local indirect-call resolution                    */
/* ------------------------------------------------------------------------- */

static std::string function_decl_name(tree t) {
    if (!t || TREE_CODE(t) != FUNCTION_DECL)
        return "<non-function>";
    tree name = DECL_NAME(t);
    if (!name) return "<anon-function>";
    const char *s = IDENTIFIER_POINTER(name);
    return s ? std::string(s) : std::string("<anon-function>");
}

static std::string ssa_name_id(tree t) {
    if (!t || TREE_CODE(t) != SSA_NAME)
        return "<non-ssa>";

    std::ostringstream oss;
    tree var = SSA_NAME_VAR(t);

    if (var && DECL_P(var) && DECL_NAME(var)) {
        oss << IDENTIFIER_POINTER(DECL_NAME(var));
    } else {
        oss << "ssa";
    }

    oss << "_" << SSA_NAME_VERSION(t);
    return oss.str();
}

static tree strip_simple_casts(tree t) {
    while (t) {
        enum tree_code code = TREE_CODE(t);
        if (code == NOP_EXPR ||
            code == CONVERT_EXPR ||
            code == NON_LVALUE_EXPR ||
            code == VIEW_CONVERT_EXPR) {
            t = TREE_OPERAND(t, 0);
            continue;
        }
        break;
    }
    return t;
}

static void classify_value_tree(tree t, std::string &kind, std::string &value) {
    t = strip_simple_casts(t);

    if (!t) {
        kind = "unknown";
        value = "null";
        return;
    }

    switch (TREE_CODE(t)) {
        case SSA_NAME:
            kind = "ssa";
            value = ssa_name_id(t);
            return;

        case FUNCTION_DECL:
            kind = "direct_addr";
            value = function_decl_name(t);
            return;

        case ADDR_EXPR: {
            tree op = TREE_OPERAND(t, 0);
            op = strip_simple_casts(op);
            if (op && TREE_CODE(op) == FUNCTION_DECL) {
                kind = "direct_addr";
                value = function_decl_name(op);
                return;
            }
            kind = "addr_expr";
            value = get_tree_code_name(TREE_CODE(op));
            return;
        }

        case INTEGER_CST:
            kind = "const";
            value = "integer_cst";
            return;

        default:
            kind = "expr";
            value = get_tree_code_name(TREE_CODE(t));
            return;
    }
}

static void maybe_log_gimple_assign_def(const std::string &tu,
                                        const std::string &caller,
                                        gimple *stmt) {
    if (!is_gimple_assign(stmt))
        return;

    tree lhs = gimple_assign_lhs(stmt);
    if (!lhs || TREE_CODE(lhs) != SSA_NAME)
        return;

    std::string lhs_id = ssa_name_id(lhs);
    std::string loc = get_location_string(gimple_location(stmt));

    /*
     * Minimal D1 scope:
     *   - lhs = foo
     *   - lhs = &foo
     *   - lhs = rhs_ssa
     *   - lhs = (cast) rhs_ssa
     *   - everything else -> unknown
     */
    tree rhs1 = gimple_assign_rhs1(stmt);
    std::string rhs_kind, rhs_value;
    classify_value_tree(rhs1, rhs_kind, rhs_value);

    if (rhs_kind == "direct_addr") {
        log_local_value_def(tu, caller, lhs_id, "direct_addr", rhs_value, loc);
        return;
    }

    if (rhs_kind == "ssa") {
        log_local_value_def(tu, caller, lhs_id, "copy", rhs_value, loc);
        return;
    }

    log_local_value_def(tu, caller, lhs_id, "unknown", rhs_value, loc);
}

static void maybe_log_gimple_call_result_def(const std::string &tu,
                                             const std::string &caller,
                                             gimple *stmt) {
    if (!is_gimple_call(stmt))
        return;

    tree lhs = gimple_call_lhs(stmt);
    if (!lhs || TREE_CODE(lhs) != SSA_NAME)
        return;

    std::string lhs_id = ssa_name_id(lhs);
    std::string loc = get_location_string(gimple_location(stmt));

    /* local-only resolver cannot resolve interprocedural call result */
    log_local_value_def(tu, caller, lhs_id, "call_result", "unknown", loc);
}

static void maybe_log_gimple_phi_edges(const std::string &tu,
                                       const std::string &caller,
                                       gimple *stmt) {
    if (!stmt || gimple_code(stmt) != GIMPLE_PHI)
        return;

    gphi *phi = as_a<gphi *>(stmt);
    tree lhs = gimple_phi_result(phi);
    if (!lhs || TREE_CODE(lhs) != SSA_NAME)
        return;

    std::string lhs_id = ssa_name_id(lhs);
    std::string loc = get_location_string(gimple_location(stmt));

    unsigned nargs = gimple_phi_num_args(phi);
    for (unsigned i = 0; i < nargs; ++i) {
        tree arg = gimple_phi_arg_def(phi, i);
        std::string arg_kind, arg_value;
        classify_value_tree(arg, arg_kind, arg_value);
        log_local_phi_edge(tu, caller, lhs_id, (int)i, arg_kind, arg_value, loc);
    }
}

static void maybe_log_indirect_call_operand(const std::string &tu,
                                            const std::string &caller,
                                            int bb_index,
                                            int stmt_idx,
                                            gimple *stmt) {
    if (!is_gimple_call(stmt))
        return;

    tree direct = gimple_call_fndecl(stmt);
    if (direct)
        return;

    tree fn = gimple_call_fn(stmt);
    std::string kind, value;
    classify_value_tree(fn, kind, value);

    std::string loc = get_location_string(gimple_location(stmt));
    log_indirect_call_operand(tu, caller, bb_index, stmt_idx, loc, kind, value);
}

/* ------------------------------------------------------------------------- */
/* Passes                                                                     */
/* ------------------------------------------------------------------------- */

namespace {

const pass_data local_facts_pass_data = {
    GIMPLE_PASS,
    "local_facts_gimple_pass",
    OPTGROUP_NONE,
    TV_NONE,
    PROP_cfg | PROP_ssa,
    0,
    0,
    0,
    0
};

class local_facts_gimple_pass : public gimple_opt_pass {
public:
    local_facts_gimple_pass(gcc::context *ctx) : gimple_opt_pass(local_facts_pass_data, ctx) {}

    bool gate(function *) override { return true; }

    unsigned int execute(function *fun) override {
        std::string tu = get_current_tu_name();
        std::string caller = get_current_function_name();

        basic_block bb;
        FOR_ALL_BB_FN(bb, fun) {
            for (gimple_stmt_iterator gsi = gsi_start_phis(bb);
                 !gsi_end_p(gsi);
                 gsi_next(&gsi)) {
                gimple *stmt = gsi_stmt(gsi);
                maybe_log_gimple_phi_edges(tu, caller, stmt);
            }

            int stmt_idx = 0;
            for (gimple_stmt_iterator gsi = gsi_start_bb(bb);
                 !gsi_end_p(gsi);
                 gsi_next(&gsi), ++stmt_idx) {
                gimple *stmt = gsi_stmt(gsi);

                maybe_log_gimple_assign_def(tu, caller, stmt);
                maybe_log_gimple_call_result_def(tu, caller, stmt);
                maybe_log_indirect_call_operand(tu, caller, bb->index, stmt_idx, stmt);
            }
        }

        return 0;
    }
};

const pass_data my_pass_data = {
    RTL_PASS,
    "callsite_rtl_pass",
    OPTGROUP_NONE,
    TV_NONE,
    PROP_rtl,
    0,
    0,
    0,
    0
};

class callsite_rtl_pass : public rtl_opt_pass {
public:
    callsite_rtl_pass(gcc::context *ctx) : rtl_opt_pass(my_pass_data, ctx) {}

    bool gate(function *) override { return true; }

    unsigned int execute(function *) override {
        std::string tu = get_current_tu_name();
        std::string caller = get_current_function_name();

        log_function_seen(tu, caller);

        basic_block bb;
        FOR_ALL_BB_FN(bb, cfun) {
            int insn_idx = 0;

            for (rtx_insn *insn = BB_HEAD(bb); insn; insn = NEXT_INSN(insn), ++insn_idx) {
                if (CALL_P(insn)) {
                    const char *callee = get_direct_callee_name(insn);
                    if (callee) {
                        std::string callee_str(callee);
                        log_direct_edge(tu, caller, callee_str);

                        WrapperKind wk = classify_wrapper(callee);
                        switch (wk) {
                            case WRAP_EXPLICIT_SYSCALL: {
                                std::string nr = extract_syscall_nr_from_explicit_syscall_call(insn);
                                log_syscall_site(tu, caller,
                                                 wrapper_kind_to_site_kind(wk),
                                                 callee_str,
                                                 nr);
                                break;
                            }
                            case WRAP_SYSCALL_CANCEL: {
                                std::string nr = extract_syscall_nr_from_syscall_cancel_call(insn);
                                log_syscall_site(tu, caller,
                                                 wrapper_kind_to_site_kind(wk),
                                                 callee_str,
                                                 nr);
                                break;
                            }
                            case WRAP_INTERNAL_SYSCALL_CANCEL:
                            case WRAP_SYSCALL_CANCEL_ARCH:
                            case WRAP_NOCANCEL_HELPER: {
                                log_syscall_site(tu, caller,
                                                 wrapper_kind_to_site_kind(wk),
                                                 callee_str,
                                                 "unknown");
                                break;
                            }
                            case WRAP_NONE:
                            default:
                                break;
                        }
                    } else {
                        rtx target = get_call_target(insn);
                        std::string target_code = classify_call_target(target);
                        std::string loc = get_rtl_location_string(insn);
                        log_indirect_callsite(tu, caller, bb->index, insn_idx, loc, target_code);
                    }
                }

                rtx asmop = find_syscall_asm_operands(insn);
                if (asmop) {
                    std::string nr = extract_syscall_nr_from_inline_syscall_insn(insn);
                    log_syscall_site(tu, caller,
                                     "glibc-inline-syscall",
                                     "inline-asm",
                                     nr);
                }

                if (insn == BB_END(bb))
                    break;
            }
        }

        return 0;
    }
};

} // anonymous namespace

static struct plugin_info my_plugin_info = {
    "0.9",
    "RTL callsite + GIMPLE local-facts extraction with site identity for indirect-call joins"
};

int plugin_init(struct plugin_name_args *plugin_info,
                struct plugin_gcc_version *version) {
    if (!plugin_default_version_check(version, &gcc_version)) {
        std::fprintf(stderr, "[callsite_plugin] GCC version mismatch\n");
        return 1;
    }

    for (int i = 0; i < plugin_info->argc; ++i) {
        const char *key = plugin_info->argv[i].key;
        const char *value = plugin_info->argv[i].value;
        if (!key || !value) continue;

        if (std::strcmp(key, "outdir") == 0)
            g_outdir = value;
    }

    register_callback(plugin_info->base_name,
                      PLUGIN_INFO,
                      nullptr,
                      &my_plugin_info);

    static struct register_pass_info gimple_pass_info;
    gimple_pass_info.pass = new local_facts_gimple_pass(g);
    gimple_pass_info.reference_pass_name = "ssa";
    gimple_pass_info.ref_pass_instance_number = 1;
    gimple_pass_info.pos_op = PASS_POS_INSERT_AFTER;

    register_callback(plugin_info->base_name,
                      PLUGIN_PASS_MANAGER_SETUP,
                      nullptr,
                      &gimple_pass_info);

    static struct register_pass_info rtl_pass_info;
    rtl_pass_info.pass = new callsite_rtl_pass(g);
    rtl_pass_info.reference_pass_name = "expand";
    rtl_pass_info.ref_pass_instance_number = 1;
    rtl_pass_info.pos_op = PASS_POS_INSERT_AFTER;

    register_callback(plugin_info->base_name,
                      PLUGIN_PASS_MANAGER_SETUP,
                      nullptr,
                      &rtl_pass_info);

    std::fprintf(stderr, "[callsite_plugin] loaded, outdir=%s\n", g_outdir.c_str());
    return 0;
}
