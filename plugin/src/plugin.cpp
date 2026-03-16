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

#include <cstdio>
#include <cstring>
#include <string>
#include <fstream>

int plugin_is_GPL_compatible;

static std::string g_outdir = ".";
static std::string g_functions_file = "functions_seen.csv";
static std::string g_direct_file = "direct_edges.csv";
static std::string g_indirect_file = "indirect_callsites.csv";
static std::string g_syscall_file = "syscall_sites.csv";
static std::string g_defuse_file = "defuse_events.csv";

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

static void log_function_seen(const std::string &tu, const std::string &fn) {
    append_line(join_path(g_outdir, g_functions_file), tu + "," + fn);
}

static void log_direct_edge(const std::string &tu,
                            const std::string &caller,
                            const std::string &callee) {
    append_line(join_path(g_outdir, g_direct_file),
                tu + "," + caller + "," + callee);
}

static void log_indirect_callsite(const std::string &tu,
                                  const std::string &caller,
                                  const std::string &insn_uid,
                                  const std::string &target_operand,
                                  const std::string &target_code) {
    append_line(join_path(g_outdir, g_indirect_file),
                tu + "," + caller + "," + insn_uid + "," + target_operand + "," + target_code);
}

static void log_defuse_event(const std::string &tu,
                             const std::string &caller,
                             const std::string &insn_uid,
                             const std::string &kind,
                             const std::string &var,
                             const std::string &value) {
    append_line(join_path(g_outdir, g_defuse_file),
                tu + "," + caller + "," + insn_uid + "," + kind + "," + var + "," + value);
}

static void log_syscall_site(const std::string &tu,
                             const std::string &caller,
                             const std::string &site_kind,
                             const std::string &callee,
                             const std::string &syscall_nr) {
    append_line(join_path(g_outdir, g_syscall_file),
                tu + "," + caller + "," + site_kind + "," + callee + "," + syscall_nr);
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

static std::string reg_token(rtx x) {
    x = normalize_reg_like(x);
    if (!x || GET_CODE(x) != REG)
        return "";
    return std::string("REG(") + std::to_string((unsigned) REGNO(x)) + ")";
}

static std::string rtx_value_to_string(rtx x) {
    if (!x)
        return "";

    if (GET_CODE(x) == SUBREG)
        x = SUBREG_REG(x);

    if (GET_CODE(x) == SYMBOL_REF) {
        const char *s = XSTR(x, 0);
        return std::string("SYMBOL_REF(") + (s ? s : "") + ")";
    }

    if (GET_CODE(x) == REG)
        return reg_token(x);

    if (GET_CODE(x) == CONST_INT)
        return std::to_string((long long) INTVAL(x));

    return GET_RTX_NAME(GET_CODE(x));
}

static std::string extract_call_target_operand(rtx target) {
    if (!target)
        return "";

    if (GET_CODE(target) == MEM) {
        rtx inner = XEXP(target, 0);
        if (!inner)
            return "";

        if (GET_CODE(inner) == REG || GET_CODE(inner) == SUBREG)
            return reg_token(inner);

        if (GET_CODE(inner) == PLUS) {
            rtx lhs = XEXP(inner, 0);
            if (lhs && (GET_CODE(lhs) == REG || GET_CODE(lhs) == SUBREG))
                return reg_token(lhs);
        }
        return "";
    }

    if (GET_CODE(target) == REG || GET_CODE(target) == SUBREG)
        return reg_token(target);

    return "";
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

namespace {

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
            for (rtx_insn *insn = BB_HEAD(bb); insn; insn = NEXT_INSN(insn)) {
                // 1) normal call-based handling
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
                        std::string insn_uid = std::to_string((long long) INSN_UID(insn));
                        std::string operand = extract_call_target_operand(target);
                        std::string target_code = classify_call_target(target);
                        log_indirect_callsite(tu, caller, insn_uid, operand, target_code);

                        if (!operand.empty()) {
                            log_defuse_event(tu, caller, insn_uid, "call_arg", operand, "indirect-call-target");
                        }
                    }
                }

                // 1.5) def/use-like event extraction for Step D exact resolver
                if (INSN_P(insn)) {
                    rtx set = single_set(insn);
                    if (set) {
                        std::string insn_uid = std::to_string((long long) INSN_UID(insn));
                        rtx dest = SET_DEST(set);
                        rtx src = SET_SRC(set);

                        std::string def_var = reg_token(dest);
                        if (!def_var.empty()) {
                            log_defuse_event(tu, caller, insn_uid, "def", def_var, rtx_value_to_string(src));
                        }

                        if (dest && GET_CODE(dest) == MEM) {
                            std::string esc_var = reg_token(src);
                            if (!esc_var.empty()) {
                                log_defuse_event(tu, caller, insn_uid, "escape", esc_var, "store-to-mem");
                            }
                        }
                    }
                }

                // 2) inline-asm syscall handling
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
    "0.7",
    "Milestone 1-5 + M8 + M10 inline-asm syscall support"
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

    // Per GCC invocation initialize headers.
    {
        std::ofstream ofs_indirect(join_path(g_outdir, g_indirect_file), std::ios::trunc);
        ofs_indirect << "tu,function,insn_uid,target_operand,callee_kind\n";
    }
    {
        std::ofstream ofs_defuse(join_path(g_outdir, g_defuse_file), std::ios::trunc);
        ofs_defuse << "tu,function,insn_uid,kind,var,value\n";
    }

    static struct register_pass_info pass_info;
    pass_info.pass = new callsite_rtl_pass(g);
    pass_info.reference_pass_name = "expand";
    pass_info.ref_pass_instance_number = 1;
    pass_info.pos_op = PASS_POS_INSERT_AFTER;

    register_callback(plugin_info->base_name,
                      PLUGIN_PASS_MANAGER_SETUP,
                      nullptr,
                      &pass_info);

    std::fprintf(stderr, "[callsite_plugin] loaded, outdir=%s\n", g_outdir.c_str());
    return 0;
}
