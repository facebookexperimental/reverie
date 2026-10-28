#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include "dr_api.h"
#include "drmgr.h"

/* This client supplies a deliberately different identity to the production
 * returning-injection API. It does not implement a virtual identity map. */
enum { PROJECTED_PID = 7777 };
typedef struct {
  uint64 token;
  unsigned phase;
  bool injecting;
  byte raw_info[128];
} state_t;
static int tls_index;
static bool replace_info;
static bool purpose_api;
static byte *stub;
static unsigned admissions, commits;

static void require(bool ok, const char *message) {
  if (!ok) {
    dr_fprintf(STDERR, "SIGPIPE client failure: %s\n", message);
    dr_exit_process(43);
  }
}
static void thread_init(void *dc) {
  state_t *s = dr_thread_alloc(dc, sizeof(*s));
  memset(s, 0, sizeof(*s));
  require(drmgr_set_tls_field(dc, tls_index, s), "publish TLS");
}
static void thread_exit(void *dc) {
  state_t *s = drmgr_get_tls_field(dc, tls_index);
  require(s && !s->token && !s->phase && !s->injecting, "no retained ownership");
  dr_thread_free(dc, s, sizeof(*s));
}
static dr_signal_admission_status_t admission(
    void *dc, const dr_signal_admission_t *event, dr_mcontext_t *redirect) {
  state_t *s = drmgr_get_tls_field(dc, tls_index);
  if (!event)
    return !s || s->injecting || s->token ? DR_SIGNAL_ADMISSION_WAIT
                                         : DR_SIGNAL_ADMISSION_START;
  require(s && !s->injecting && !s->token && event->sig == SIGPIPE && redirect,
          "actual owned SIGPIPE after injection returned");
  siginfo_t raw;
  _Static_assert(sizeof(raw) == sizeof(s->raw_info), "Linux siginfo representation");
  memcpy(&raw, event->siginfo, sizeof(raw));
  require(raw.si_pid == dr_get_process_id() &&
              (raw.si_code == SI_USER || raw.si_code == SI_TKILL) &&
              raw.si_errno == 0,
          "policy observes authentic unprojected sender bytes");
  memcpy(s->raw_info, event->siginfo, sizeof(s->raw_info));
  s->token = event->token;
  s->phase = 1;
  ++admissions;
  redirect->pc = stub;
  redirect->xax = SYS_gettid;
  return DR_SIGNAL_ADMISSION_START;
}
static bool filter(void *dc, int number) { (void)dc; (void)number; return true; }
static bool pre_syscall(void *dc, int number) {
  state_t *s = drmgr_get_tls_field(dc, tls_index);
  if (s && s->phase == 1) {
    require(number == SYS_gettid, "owned private continuation");
    s->phase = 2;
    dr_syscall_set_result(dc, 0);
    return false;
  }
  if (number != SYS_write && number != SYS_writev && number != SYS_pwritev2 &&
      number != SYS_rt_tgsigqueueinfo)
    return true;
  require(s && !s->injecting, "one returning injection");
  reg_t args[6];
  for (int i = 0; i < 6; ++i) args[i] = dr_syscall_get_param(dc, i);
  s->injecting = true;
  dr_syscall_invoke_result_t result;
  bool completed = purpose_api
      ? dr_invoke_syscall_as_app_with_purpose(
            dc, number, 6, args, PROJECTED_PID, false,
            DR_SYSCALL_INJECTION_APPLICATION, &result) == DR_SYSCALL_INVOKE_COMPLETED
      : dr_invoke_syscall_as_app_with_result_and_sigpipe_identity(
            dc, number, 6, args, PROJECTED_PID, &result);
  require(completed && !result.interruption, "real returning syscall");
  s->injecting = false;
  dr_syscall_set_result(dc, result.value);
  return false;
}
static void finish(void) {
  void *dc = dr_get_current_drcontext();
  state_t *s = drmgr_get_tls_field(dc, tls_index);
  require(s && s->token && s->phase == 2, "finish exact owned continuation");
  uint64 token = s->token;
  s->token = 0; s->phase = 0;
  ++commits;
  /* Even byte-identical replacement is an explicit client choice. It must not
   * subsequently acquire the pending record's projected identity. */
  dr_signal_admission_resume(dc, token, SIGPIPE,
                             replace_info ? s->raw_info : NULL, NULL);
  require(false, "successful owned resume never returns");
}
static dr_emit_flags_t instrument(void *dc, void *tag, instrlist_t *bb,
                                 instr_t *instruction, bool trace,
                                 bool translating, void *data) {
  (void)tag; (void)trace; (void)translating; (void)data;
  if (instr_is_app(instruction) && instr_get_app_pc(instruction) == stub + 2)
    dr_insert_clean_call(dc, bb, instruction, (void *)finish, false, 0);
  return DR_EMIT_DEFAULT;
}
static void exit_event(void) {
  require(admissions == 5 && commits == 5, "five caught signals committed once");
  dr_fprintf(STDOUT, "SIGPIPE client: raw admissions=5 commits=5\n");
  drmgr_exit();
}
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
  (void)id;
  require((argc == 2 || (argc == 3 && !strcmp(argv[2], "purpose"))) &&
              (!strcmp(argv[1], "project") || !strcmp(argv[1], "replace")),
          "exact mode");
  replace_info = !strcmp(argv[1], "replace");
  purpose_api = argc == 3;
  require(drmgr_init(), "drmgr");
  tls_index = drmgr_register_tls_field();
  require(tls_index >= 0, "TLS index");
  stub = dr_nonheap_alloc(dr_page_size(), DR_MEMPROT_READ | DR_MEMPROT_WRITE | DR_MEMPROT_EXEC);
  require(stub != NULL, "private continuation allocation");
  memcpy(stub, "\x0f\x05\x0f\x0b", 4);
  require(drmgr_register_thread_init_event(thread_init) &&
              drmgr_register_thread_exit_event(thread_exit) &&
              drmgr_register_bb_instrumentation_event(NULL, instrument, NULL) &&
              drmgr_register_filter_syscall_event(filter) &&
              drmgr_register_pre_syscall_event(pre_syscall) &&
              dr_register_signal_admission_event(admission) &&
              drmgr_register_exit_event(exit_event), "register real events");
}
