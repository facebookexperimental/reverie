#include "dr_api.h"
#include <string.h>

static app_pc branch_pc, truncate_pc;
static bool enabled, stored;
static unsigned rewrites, truncations, recreations;

static void require(bool ok, const char *message) {
    if (!ok) {
        dr_fprintf(STDERR, "translation fixture refusal: %s\n", message);
        dr_exit_process(41);
    }
}

static void module_load(void *dc, const module_data_t *module, bool loaded) {
    (void)dc;
    (void)loaded;
    app_pc pc = (app_pc)dr_get_proc_address(module->handle, "translation_branch");
    if (pc == NULL)
        return;
    require(branch_pc == NULL, "one fixture module");
    branch_pc = pc;
    truncate_pc = (app_pc)dr_get_proc_address(module->handle, "translation_truncate");
    require(truncate_pc != NULL, "truncation symbol");
}

static dr_emit_flags_t instrument(void *dc, void *tag, instrlist_t *bb,
                                  bool for_trace, bool translating) {
    (void)tag;
    if (translating)
        ++recreations;
    if (!enabled)
        return DR_EMIT_DEFAULT;
    for (instr_t *in = instrlist_first_app(bb); in != NULL;
         in = instr_get_next_app(in)) {
        app_pc pc = instr_get_app_pc(in);
        if (pc == branch_pc) {
            require(instr_get_opcode(in) == OP_jz &&
                        opnd_is_pc(instr_get_target(in)) &&
                        in == instrlist_last_app(bb),
                    "terminal near fixture JZ");
            /* The fixture executes XOR EAX,EAX immediately before this JZ.
             * Replacing its always-taken branch preserves that fixture path.
             * The deliberately tested API shape is an app UBR whose truthful
             * translation is its own explicit target, including an unreadable one.
             */
            app_pc target = opnd_get_pc(instr_get_target(in));
            instr_t *jump = INSTR_CREATE_jmp(dc, opnd_create_pc(target));
            instr_set_translation(jump, target);
            instrlist_replace(bb, in, jump);
            instr_destroy(dc, in);
            if (!for_trace && !translating) {
                ++rewrites;
                dr_fprintf(STDERR, "translation rewrite source=" PFX " target=" PFX
                                   " stored=%d\n", pc, target, stored);
            }
            break;
        }
        if (pc == truncate_pc) {
            require(instr_get_opcode(in) == OP_nop, "ordinary truncation NOP");
            instr_t *next = instr_get_next(in);
            while (next != NULL) {
                instr_t *after = instr_get_next(next);
                instrlist_remove(bb, next);
                instr_destroy(dc, next);
                next = after;
            }
            if (!for_trace && !translating)
                ++truncations;
            break;
        }
    }
    return stored ? DR_EMIT_STORE_TRANSLATIONS : DR_EMIT_DEFAULT;
}

static void translation_exit_event(void) {
    require(branch_pc != NULL, "fixture module observed");
    dr_fprintf(STDERR, "translation completed enabled=%d stored=%d rewrites=%u"
                       " truncations=%u recreations=%u\n", enabled, stored, rewrites,
                       truncations, recreations);
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    (void)id;
    require(argc == 2 && (!strcmp(argv[1], "disabled") ||
                         !strcmp(argv[1], "normal") || !strcmp(argv[1], "stored")),
            "explicit fixture mode");
    enabled = strcmp(argv[1], "disabled") != 0;
    stored = strcmp(argv[1], "stored") == 0;
    dr_register_module_load_event(module_load);
    dr_register_bb_event(instrument);
    dr_register_exit_event(translation_exit_event);
}
