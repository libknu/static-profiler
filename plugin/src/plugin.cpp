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
#include <iostream>

int plugin_is_GPL_compatible;

static std::string g_outdir = ".";
static std::string g_functions_file = "functions_seen.csv";
static std::string g_direct_file = "direct_edges.csv";

static std::string join_path(const std::string &a, const std::string &b) {
    if (a.empty()) return b;
    if (a.back() == '/') return a + b;
    return a + "/" + b;
}

static std::string get_current_function_name() {
    if (!current_function_decl) return "<unknown>";
    const char *name = IDENTIFIER_POINTER(DECL_NAME(current_function_decl));
    return name ? std::string(name) : std::string("<unknown>");
}

static std::string get_current_tu_name() {
    const char *src = main_input_filename;
    return src ? std::string(src) : std::string("<unknown-tu>");
}

static void append_line(const std::string &path, const std::string &line) {
    std::ofstream ofs(path, std::ios::app);
    ofs << line << "\n";
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

static const char *get_direct_callee_name(rtx_insn *insn) {
    rtx call = PATTERN(insn);

    if (!call)
        return nullptr;

    /*
     * CALL_INSN pattern is often:
     *   (call_insn ... (call (mem:QI (symbol_ref ...)) ...))
     * but exact wrapping can vary.
     * We use single_set() first when possible.
     */
    rtx expr = nullptr;

    rtx set = single_set(insn);
    if (set) {
        expr = SET_SRC(set);
    } else {
        expr = call;
    }

    if (!expr)
        return nullptr;

    if (GET_CODE(expr) == CALL) {
        rtx target = XEXP(expr, 0);

        if (target && GET_CODE(target) == MEM) {
            rtx mem_target = XEXP(target, 0);
            if (mem_target && GET_CODE(mem_target) == SYMBOL_REF) {
                return XSTR(mem_target, 0);
            }
        }

        if (target && GET_CODE(target) == SYMBOL_REF) {
            return XSTR(target, 0);
        }
    }

    /*
     * Fallback: inspect the raw pattern a bit more defensively.
     */
    if (GET_CODE(call) == CALL) {
        rtx target = XEXP(call, 0);
        if (target && GET_CODE(target) == MEM) {
            rtx mem_target = XEXP(target, 0);
            if (mem_target && GET_CODE(mem_target) == SYMBOL_REF) {
                return XSTR(mem_target, 0);
            }
        }
    }

    return nullptr;
}

namespace {

const pass_data my_pass_data = {
    RTL_PASS,                 /* type */
    "callsite_rtl_pass",      /* name */
    OPTGROUP_NONE,            /* optinfo_flags */
    TV_NONE,                  /* tv_id */
    PROP_rtl,                 /* properties_required */
    0,                        /* properties_provided */
    0,                        /* properties_destroyed */
    0,                        /* todo_flags_start */
    0                         /* todo_flags_finish */
};

class callsite_rtl_pass : public rtl_opt_pass {
public:
    callsite_rtl_pass(gcc::context *ctx) : rtl_opt_pass(my_pass_data, ctx) {}

    bool gate(function *) override {
        return true;
    }


	unsigned int execute(function *) override {
    std::string tu = get_current_tu_name();
    std::string caller = get_current_function_name();

    log_function_seen(tu, caller);

	basic_block bb;
	FOR_ALL_BB_FN(bb, cfun) {
		for (rtx_insn *insn = BB_HEAD(bb); insn; insn = NEXT_INSN(insn)) {
			if (CALL_P(insn)) {
				const char *callee = get_direct_callee_name(insn);
				if (callee) {
					log_direct_edge(tu, caller, std::string(callee));
				}
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
    .version = "0.1",
    .help = "Milestone 1/2 plugin: function inventory + direct call edges"
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

        if (std::strcmp(key, "outdir") == 0) {
            g_outdir = value;
        }
    }

    register_callback(plugin_info->base_name,
                      PLUGIN_INFO,
                      nullptr,
                      &my_plugin_info);

    static struct register_pass_info pass_info;
    pass_info.pass = new callsite_rtl_pass(g);
    pass_info.reference_pass_name = "expand";
    pass_info.ref_pass_instance_number = 1;
    pass_info.pos_op = PASS_POS_INSERT_AFTER;

    register_callback(plugin_info->base_name,
                      PLUGIN_PASS_MANAGER_SETUP,
                      nullptr,
                      &pass_info);

    std::fprintf(stderr,
                 "[callsite_plugin] loaded, outdir=%s\n",
                 g_outdir.c_str());

    return 0;
}
