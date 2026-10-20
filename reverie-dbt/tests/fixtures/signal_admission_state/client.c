#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include "dr_api.h"
#include "drmgr.h"

enum { CONTROL, DELIVER, SUPPRESS, MASK, RESTART_CONTROL, RESTART_DELIVER,
       RESTART_SUPPRESS, PPOLL_MASK, MASK_SUPPRESS, MASK_IGNORE };
typedef struct {
  uint64 token;
  int signal;
  unsigned phase;
  bool in_returning_injection;
  dr_mcontext_t selected_registers;
} state_t;
static int tls_index;
static bool legacy;
static bool validation_post;
static unsigned validation_checks;
static bool inject_wait;
static bool transform_result;
static bool terminal_result;
static bool transform_signal_result;
static byte *stub;
static const int *case_address, *level_address;
static _Atomic unsigned *seen_address;
static app_pc read_instruction, read_after, mask_after, mask_alternate;
static unsigned admissions, ordinary_signals, commits, restart_contexts;
static unsigned first_signals, second_signals;
static unsigned injected_entries, injected_completions;
extern void clobber_fp_state(unsigned);

static void require(bool condition, const char *message) {
  if (!condition) {
    dr_fprintf(STDERR, "signal admission client failure: %s\n", message);
    dr_exit_process(43);
  }
}

static int read_int(const int *address) {
  int value;
  require(address != NULL && dr_safe_read(address, sizeof(value), &value, NULL),
          "read exported fixture state");
  return value;
}

static void mark_admitted(void) {
  /* This pointer names the fixture's exported, permanently mapped C11 atomic,
   * not arbitrary application memory or a production signal side channel. */
  require(seen_address != NULL, "fixture handshake address");
  atomic_store_explicit(seen_address, 1, memory_order_release);
}

static void thread_init(void *dc) {
  state_t *s = dr_thread_alloc(dc, sizeof(*s));
  require(s != NULL, "TLS allocation");
  memset(s, 0, sizeof(*s));
  require(drmgr_set_tls_field(dc, tls_index, s), "TLS publication");
}

static void thread_exit(void *dc) {
  state_t *s = drmgr_get_tls_field(dc, tls_index);
  require(s != NULL && s->token == 0 && s->phase == 0, "no live continuation at exit");
  dr_thread_free(dc, s, sizeof(*s));
}

static void module_load(void *dc, const module_data_t *module, bool loaded) {
  (void)dc; (void)loaded;
  const int *found = (const int *)dr_get_proc_address(module->handle, "probe_case");
  if (found == NULL) return;
  require(case_address == NULL, "one guest fixture");
  case_address = found;
  level_address = (const int *)dr_get_proc_address(module->handle, "probe_vector_level");
  seen_address = (_Atomic unsigned *)dr_get_proc_address(module->handle, "probe_admission_seen");
  read_instruction = (app_pc)dr_get_proc_address(module->handle, "probe_read_instruction");
  read_after = (app_pc)dr_get_proc_address(module->handle, "probe_read_after");
  mask_after = (app_pc)dr_get_proc_address(module->handle, "probe_mask_after");
  mask_alternate = (app_pc)dr_get_proc_address(module->handle, "probe_mask_alternate");
  require(level_address && seen_address && read_instruction && read_after &&
              mask_after && mask_alternate,
          "all fixture symbols");
}

static dr_signal_action_t ordinary_signal(void *dc, dr_siginfo_t *event) {
  (void)dc;
  int mode = read_int(case_address);
  require(event->sig == SIGUSR1 ||
              ((mode == MASK_SUPPRESS || mode == MASK_IGNORE) && event->sig == SIGUSR2),
          "only the scheduled signal");
  ++ordinary_signals;
  if (event->sig == SIGUSR1) ++first_signals;
  else ++second_signals;
  if (legacy && (mode == SUPPRESS || mode == RESTART_SUPPRESS ||
                 (mode == MASK_SUPPRESS && event->sig == SIGUSR1))) {
    if (mode == RESTART_SUPPRESS) {
      require(event->mcontext->pc == read_instruction &&
                  event->mcontext->xax == SYS_read,
              "legacy control really sees a restart-adjusted read frame");
      ++restart_contexts;
    }
    mark_admitted();
    return DR_SIGNAL_SUPPRESS;
  }
  if (mode == MASK_SUPPRESS && event->sig == SIGUSR2)
    require(first_signals == 1, "suppressed first signal accounted before second");
  return DR_SIGNAL_DELIVER;
}

static dr_signal_admission_status_t admission(
    void *dc, const dr_signal_admission_t *event, dr_mcontext_t *redirect) {
  state_t *s = drmgr_get_tls_field(dc, tls_index);
  if (event == NULL) {
    if (case_address == NULL || s == NULL) return DR_SIGNAL_ADMISSION_BYPASS;
    return s->token || s->in_returning_injection
        ? DR_SIGNAL_ADMISSION_WAIT : DR_SIGNAL_ADMISSION_START;
  }
  int mode = read_int(case_address);
  require(s != NULL && !s->in_returning_injection &&
              injected_entries == injected_completions &&
              s->token == 0 && event->token != 0 &&
              (event->sig == SIGUSR1 ||
               ((mode == MASK_SUPPRESS || mode == MASK_IGNORE) && event->sig == SIGUSR2)) &&
              redirect != NULL,
          "single authentic signal owner");
  if (mode == RESTART_SUPPRESS || mode == RESTART_DELIVER) {
    require(event->mcontext->pc == read_instruction &&
                event->mcontext->xax == SYS_read && redirect->pc == read_after &&
                (ptr_int_t)redirect->xax == -4 /* EINTR */,
            "ordinary and restart contexts are actually distinct");
    ++restart_contexts;
  }
  if (inject_wait) {
    ptr_int_t expected = transform_result ? -1 /* EPERM */ : -514 /* ERESTARTNOHAND */;
    require((ptr_int_t)event->mcontext->xax == expected &&
                (ptr_int_t)redirect->xax == expected,
            "signal policy sees the final interrupted result before disposition");
  }
  if (transform_signal_result) {
    require(event->mcontext->pc == mask_after && redirect->pc == mask_after,
            "policy edits the actual application continuation");
    s->selected_registers = *redirect;
    s->selected_registers.xax = (reg_t)-(ptr_int_t)1 /* EPERM */;
    s->selected_registers.pc = mask_alternate;
  }
  s->token = event->token;
  s->signal = event->sig;
  s->phase = 1;
  ++admissions;
  redirect->pc = stub;
  redirect->xax = SYS_gettid;
  return DR_SIGNAL_ADMISSION_START;
}

static bool filter_syscall(void *dc, int number) {
  (void)dc; (void)number;
  return true;
}

static bool pre_syscall(void *dc, int number) {
  state_t *s = drmgr_get_tls_field(dc, tls_index);
  if (inject_wait && number == SYS_rt_sigsuspend && s != NULL && s->phase == 0) {
    require(!s->in_returning_injection, "no returning callback reentry");
    reg_t original_pointer = dr_syscall_get_param(dc, 0);
    reg_t size = dr_syscall_get_param(dc, 1);
    volatile uint64_t private_mask;
    /* Existing invalid-argument cases still exercise DR's ordinary error path.
     * Only a valid logical wait participates in the returning continuation. */
    if (size != sizeof(private_mask) ||
        !dr_safe_read((void *)original_pointer, sizeof(private_mask),
                     (void *)&private_mask, NULL))
      return true;
    s->in_returning_injection = true;
    ++injected_entries;
    uint64_t old_mask = 0;
    reg_t query[4] = { SIG_SETMASK, 0, (reg_t)&old_mask, sizeof(old_mask) };
    dr_syscall_invoke_result_t queried;
    require(dr_invoke_syscall_as_app_with_result(dc, SYS_rt_sigprocmask, 4,
                                               query, &queried) &&
                queried.value == 0 && queried.interruption == 0,
            "capture full old mask before returning wait");
    reg_t args[2] = { (reg_t)&private_mask, size };
    dr_syscall_invoke_result_t result;
    require(dr_invoke_syscall_as_app_with_result(dc, number, 2, args, &result) &&
                result.interruption != 0 && (ptr_int_t)result.value == -514,
            "typed authentic returning interruption");
    require(dr_syscall_get_param(dc, 0) == original_pointer,
            "returning injection restores the original application pointer");
    /* This stack cell is neither the application's restart argument nor the
     * captured mask owned by the interrupted attempt. Poison it and perform a
     * real later injection before relinquishing callback ownership. */
    private_mask = UINT64_MAX;
    dr_syscall_invoke_result_t post;
    require(dr_invoke_syscall_as_app_with_result(dc, SYS_gettid, 0, NULL, &post) &&
                (ptr_int_t)post.value > 0 && post.interruption == 0,
            "post-hook injection preserves the held interruption");
    ++injected_completions;
    s->in_returning_injection = false;
    if (terminal_result) {
      require(dr_cancel_syscall_interruption(dc, result.interruption) &&
                  !dr_cancel_syscall_interruption(dc, result.interruption),
              "terminal outcome consumes interruption exactly once");
      uint64_t restored = UINT64_MAX;
      query[2] = (reg_t)&restored;
      require(dr_invoke_syscall_as_app_with_result(dc, SYS_rt_sigprocmask, 4,
                                                 query, &queried) &&
                  queried.value == 0 && restored == old_mask,
              "terminal cancellation restores captured old mask");
      dr_fprintf(STDOUT, "terminal interruption consumed status=31\n");
      dr_exit_process(31);
      require(false, "terminal outcome cannot resume application");
    }
    reg_t final_result = transform_result ? (reg_t)-(ptr_int_t)1 /* EPERM */
                                         : result.value;
    require(dr_complete_syscall_interruption(dc, result.interruption, final_result),
            "complete once after returning callback work");
    require(!dr_complete_syscall_interruption(dc, result.interruption, final_result),
            "reject duplicate completion");
    dr_syscall_set_result(dc, final_result);
    return false;
  }
  if (s == NULL || s->phase != 1) return true;
  require(s->token != 0 && number == SYS_gettid, "actual private syscall continuation");
  s->phase = 2;
  mark_admitted();
  dr_syscall_set_result(dc, 0);
  return false;
}

static void post_syscall(void *dc, int number) {
  if (!validation_post || number != SYS_pselect6) return;
  require(validation_checks++ == 0 && dr_syscall_get_result(dc) == 0,
          "one real ordinary application pselect seed");
  uint64_t old_mask = 0, current = 0;
  reg_t query[4] = { SIG_SETMASK, 0, (reg_t)&old_mask, sizeof(old_mask) };
  dr_syscall_invoke_result_t result;
  require(dr_invoke_syscall_as_app_with_result(dc, SYS_rt_sigprocmask, 4,
                                             query, &result) && result.value == 0,
          "read application mask after real pselect posthandling");
  uint64_t changed = old_mask | (UINT64_C(1) << (SIGUSR2 - 1));
  require(changed != old_mask, "nonvacuous changed mask");
  reg_t set[4] = { SIG_SETMASK, (reg_t)&changed, 0, sizeof(changed) };
  require(dr_invoke_syscall_as_app_with_result(dc, SYS_rt_sigprocmask, 4,
                                             set, &result) && result.value == 0,
          "set distinct application mask in post callback");
  uint64_t temporary = 0;
  struct { int64_t sec, nsec; } malformed = { 0, 1000000000 };
  struct { uint64_t *mask; size_t bytes; } wrapper = { &temporary, sizeof(temporary) };
  reg_t args[6] = { 0, 0, 0, 0, (reg_t)&malformed, (reg_t)&wrapper };
  require(dr_invoke_syscall_as_app_with_purpose(
              dc, SYS_pselect6, 6, args, 0, false,
              (dr_syscall_injection_purpose_t)99, &result) ==
              DR_SYSCALL_INVOKE_PURPOSE_REFUSED,
          "unknown purpose is a mechanism refusal");
  require(dr_invoke_syscall_as_app_with_purpose(
              dc, SYS_pselect6, 6, args, 0, false,
              DR_SYSCALL_INJECTION_PSELECT6_WRAPPER_VALIDATION, &result) ==
              DR_SYSCALL_INVOKE_COMPLETED &&
              (ptr_int_t)result.value == -22 && result.interruption == 0,
          "tagged validation reaches kernel EINVAL");
  query[2] = (reg_t)&current;
  require(dr_invoke_syscall_as_app_with_result(dc, SYS_rt_sigprocmask, 4,
                                             query, &result) && result.value == 0 &&
              current == changed && wrapper.mask == &temporary &&
              malformed.sec == 0 && malformed.nsec == 1000000000,
          "validation post does not restore stale ordinary pselect metadata");
  set[1] = (reg_t)&old_mask;
  require(dr_invoke_syscall_as_app_with_result(dc, SYS_rt_sigprocmask, 4,
                                             set, &result) && result.value == 0,
          "restore fixture application mask");
}

static void finish_admission(void) {
  void *dc = dr_get_current_drcontext();
  state_t *s = drmgr_get_tls_field(dc, tls_index);
  require(s != NULL && s->token != 0 && s->phase == 2, "actual private return boundary");
  uint64 token = s->token;
  int mode = read_int(case_address);
  int signal = transform_signal_result || mode == SUPPRESS || mode == RESTART_SUPPRESS ||
                       (mode == MASK_SUPPRESS && s->signal == SIGUSR1)
                   ? 0 : s->signal;
  if (transform_signal_result) {
    const ptr_int_t unsupported[] = { -512, -513, -516 };
    for (unsigned i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); ++i) {
      dr_mcontext_t rejected = s->selected_registers;
      rejected.xax = (reg_t)unsupported[i];
      require(!dr_signal_admission_resume(dc, token, signal, NULL, &rejected),
              "unsupported restart edit refuses without consuming owned token");
    }
  }
  unsigned level = (unsigned)read_int(level_address);
  s->token = 0; s->phase = 0;
  ++commits;
  /* The application has already saved/seeded its state in assembly. This
   * destructive private call must be undone by the owned return, not a C ABI
   * promise or the clean-call epilogue (successful resume never returns). */
  clobber_fp_state(level);
  bool returned = dr_signal_admission_resume(
      dc, token, signal, NULL, transform_signal_result ? &s->selected_registers : NULL);
  (void)returned;
  require(false, "valid owned resume must not return");
}

static dr_emit_flags_t instrument(void *dc, void *tag, instrlist_t *bb,
                                 instr_t *instruction, bool for_trace,
                                 bool translating, void *data) {
  (void)tag; (void)for_trace; (void)translating; (void)data;
  if (instr_is_app(instruction) && instr_get_app_pc(instruction) == stub + 2)
    dr_insert_clean_call(dc, bb, instruction, (void *)finish_admission, false, 0);
  return DR_EMIT_DEFAULT;
}

static void exit_event(void) {
  int mode = read_int(case_address);
  if (validation_post) {
    require(validation_checks == 1, "post validation control executed");
    dr_fprintf(STDOUT, "pselect validation post=ok\n");
  }
  unsigned expected = mode == CONTROL || mode == RESTART_CONTROL ? 0 : 1;
  if (terminal_result) expected = 0;
  if (mode == MASK_SUPPRESS) {
    require(first_signals == 1 && second_signals == 1,
            "one suppressed first signal and one caught second signal");
    expected = 2;
  } else if (mode == MASK_IGNORE) {
    require(first_signals <= 1 && second_signals == 1,
            "ignored signal may be discarded; caught second signal is exact");
    expected = first_signals + second_signals;
  }
  require(ordinary_signals == expected, "exact ordinary signal callback count");
  require(admissions == (legacy ? 0 : expected) && commits == admissions,
          "every owned token committed once");
  require(restart_contexts ==
              (mode == RESTART_DELIVER || mode == RESTART_SUPPRESS ? 1u : 0u),
          "requested restart boundary was exercised");
  if (inject_wait) {
    unsigned entries = mode == MASK_SUPPRESS ? 2u
        : mode == MASK_IGNORE ? first_signals + 1u : 1u;
    require(injected_entries == entries && injected_completions == entries,
            "every true restart reenters and finishes the real syscall callback");
    dr_fprintf(STDOUT, "returning injections entries=%u completions=%u\n",
               injected_entries, injected_completions);
  }
  dr_fprintf(STDOUT,
             "client completed legacy=%d signals=%u admissions=%u commits=%u restart_contexts=%u\n",
             legacy, ordinary_signals, admissions, commits, restart_contexts);
  drmgr_unregister_bb_insertion_event(instrument);
  drmgr_unregister_pre_syscall_event(pre_syscall);
  if (validation_post) drmgr_unregister_post_syscall_event(post_syscall);
  drmgr_unregister_filter_syscall_event(filter_syscall);
  drmgr_unregister_signal_event(ordinary_signal);
  if (!legacy) require(dr_unregister_signal_admission_event(admission), "unregister admission");
  drmgr_unregister_module_load_event(module_load);
  drmgr_unregister_thread_init_event(thread_init);
  drmgr_unregister_thread_exit_event(thread_exit);
  drmgr_unregister_tls_field(tls_index);
  dr_nonheap_free(stub, dr_page_size());
  drmgr_exit();
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
  (void)id;
  require((argc == 2 || (argc == 3 && !strcmp(argv[2], "require-emulated-mask"))) &&
              (!strcmp(argv[1], "owned") || !strcmp(argv[1], "legacy") ||
               !strcmp(argv[1], "validation-post") ||
               !strcmp(argv[1], "owned-inject") ||
               !strcmp(argv[1], "owned-inject-result") ||
               !strcmp(argv[1], "owned-inject-signal-result") ||
               !strcmp(argv[1], "owned-inject-terminal")),
          "exact client mode");
  validation_post = !strcmp(argv[1], "validation-post");
  legacy = !strcmp(argv[1], "legacy") || validation_post;
  transform_result = !strcmp(argv[1], "owned-inject-result");
  terminal_result = !strcmp(argv[1], "owned-inject-terminal");
  transform_signal_result = !strcmp(argv[1], "owned-inject-signal-result");
  inject_wait = !strcmp(argv[1], "owned-inject") || transform_result || terminal_result ||
                transform_signal_result;
  if (argc == 3) {
    uint64 code_api = 0, intercept_all = 0;
    require(dr_get_integer_option("code_api", &code_api) && code_api == 1 &&
                dr_get_integer_option("intercept_all_signals", &intercept_all) &&
                intercept_all == 1,
            "actual client mode requires code_api and full signal interception");
    dr_fprintf(STDOUT, "client mode code_api=1 intercept_all_signals=1\n");
  }
  require(drmgr_init(), "drmgr");
  tls_index = drmgr_register_tls_field();
  require(tls_index >= 0, "TLS field");
  stub = dr_nonheap_alloc(dr_page_size(), DR_MEMPROT_READ | DR_MEMPROT_WRITE | DR_MEMPROT_EXEC);
  require(stub != NULL, "private stub");
  memcpy(stub, "\x0f\x05\x0f\x0b", 4);
  require(drmgr_register_thread_init_event(thread_init) &&
              drmgr_register_thread_exit_event(thread_exit) &&
              drmgr_register_module_load_event(module_load) &&
              drmgr_register_bb_instrumentation_event(NULL, instrument, NULL) &&
              drmgr_register_filter_syscall_event(filter_syscall) &&
              drmgr_register_pre_syscall_event(pre_syscall) &&
              drmgr_register_signal_event(ordinary_signal) &&
              drmgr_register_exit_event(exit_event),
          "register actual native events");
  if (validation_post) require(drmgr_register_post_syscall_event(post_syscall), "post control");
  if (!legacy) require(dr_register_signal_admission_event(admission), "register owned API");
}
