/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Native source and ABI controls. These supplement the actual caller/Strace
//! executions; they do not establish that a native image loaded or ran.

use std::mem::align_of;
use std::mem::offset_of;
use std::mem::size_of;

use reverie_dbt::DBT_RUNTIME_ABI_VERSION;
use reverie_dbt::DbtRuntimeCallbacks;
use reverie_dbt::caller_abi::ImageDescriptor;
use reverie_dbt::caller_abi::ReadySnapshot;
use reverie_dbt::caller_abi::TerminalFact;

const NATIVE: &str = include_str!("../native/client.c");
const CMAKE: &str = include_str!("../native/CMakeLists.txt");
const CALLER_EFFECTS: &str = include_str!("../src/caller_effects.rs");

fn refusal_symbols(source: &str, prefix: &str) -> std::collections::BTreeSet<String> {
    source
        .split(prefix)
        .skip(1)
        .map(|suffix| {
            suffix
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                .collect()
        })
        .collect()
}

fn check_refusal_symbols(native: &str, rust: &str) {
    let native = between(
        native,
        "static bool caller_unsupported_operation(\n",
        "static bool is_exec_syscall(int sysnum);",
    );
    let rust = &rust[rust.find("pub(crate) fn unsupported_operation(").unwrap()..];
    for prefix in ["SYS_", "PR_"] {
        assert_eq!(
            refusal_symbols(native, prefix),
            refusal_symbols(rust, prefix)
        );
    }
}

#[test]
fn refusal_symbol_control_rejects_unpaired_native_or_rust_operations() {
    check_refusal_symbols(NATIVE, CALLER_EFFECTS);
    let native = NATIVE.replacen("case SYS_clone:", "case SYS_getuid: case SYS_clone:", 1);
    assert!(std::panic::catch_unwind(|| check_refusal_symbols(&native, CALLER_EFFECTS)).is_err());
    let rust = CALLER_EFFECTS.replacen("libc::SYS_clone", "libc::SYS_getuid | libc::SYS_clone", 1);
    assert!(std::panic::catch_unwind(|| check_refusal_symbols(NATIVE, &rust)).is_err());
}

#[test]
fn rpc_transport_failure_uses_native_ownership_and_the_exact_table() {
    let status = NATIVE
        .lines()
        .find_map(|line| line.strip_prefix("#define REVERIE_TOOL_RPC_FAILURE_EXIT_CODE "))
        .unwrap()
        .parse::<i32>()
        .unwrap();
    assert_eq!(status, reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE);
    assert_eq!(status, 123);
    assert_eq!(size_of::<DbtRuntimeCallbacks>(), 104);
    assert_eq!(offset_of!(DbtRuntimeCallbacks, rpc_transport_fatal), 96);
    let fatal = between(
        NATIVE,
        "static void runtime_rpc_transport_fatal(uintptr_t context) {",
        "static bool caller_terminal_preparation_failure(",
    );
    ordered(
        fatal,
        &[
            "drcontext == dr_get_current_drcontext()",
            "!caller_live_context(drcontext, counters, false)",
            "native_runtime_entries == 0",
            "CALLER_NOT_ENDING",
            "CALLER_CONSUMING",
            "exit_runtime_tree(101)",
            "counters->caller_terminal_state = CALLER_FAILED;",
            "caller Tool RPC transport failure",
            "exit_runtime_tree(REVERIE_TOOL_RPC_FAILURE_EXIT_CODE)",
        ],
    );
    assert!(!fatal.contains("invoke_syscall("));
    assert!(!fatal.contains("reverie_dbt_runtime_thread_exit("));

    // This is a source/order control, not an execution of an old image. The
    // exact exported-size check rejects a former 96-byte ABI16 runtime before
    // events can start the helper that delivers the table to Rust.
    let main = NATIVE
        .split_once("DR_EXPORT void dr_client_main")
        .unwrap()
        .1;
    ordered(
        main,
        &[
            "runtime_abi_version != REVERIE_DBT_RUNTIME_ABI_VERSION ||",
            "reverie_dbt_runtime_callbacks_size() != sizeof(runtime_callbacks_t)",
            "native/runtime ABI version or callback size mismatch",
            "dr_exit_process(101);",
            "runtime_image_descriptor = reverie_dbt_runtime_image_init();",
            "runtime_callbacks_page.value.rpc_transport_fatal = runtime_rpc_transport_fatal;",
            "drmgr_register_bb_instrumentation_event(",
        ],
    );
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .rsplit_once(start)
        .unwrap_or_else(|| panic!("missing native boundary: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing native boundary: {end}"))
        .0
}

fn ordered(source: &str, markers: &[&str]) {
    let mut rest = source;
    for marker in markers {
        rest = rest
            .split_once(marker)
            .unwrap_or_else(|| panic!("missing or out-of-order native step: {marker}"))
            .1;
    }
}

fn native_function(signature: &str) -> &str {
    let source = &NATIVE[NATIVE.rfind(signature).expect("native function signature")..];
    let start = source.find('{').expect("native function body");
    let mut depth = 0;
    for (offset, byte) in source.bytes().enumerate().skip(start) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[..=offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated native function {signature}");
}

#[test]
fn native_register_view_ownership_refuses_without_mutation() {
    use std::process::Command;

    use sha2::Digest;

    // Compile the actual C owner/read/write bodies, with controlled DR context
    // callbacks. This executes native-state refusal and commit logic; it does
    // not establish live SDK signal provenance or a loaded caller identity.
    let declarations = NATIVE
        .split_once("typedef enum {\n  REGISTER_ORIG_UNKNOWN,")
        .expect("native register origin declarations")
        .1
        .split_once("} register_orig_t;")
        .unwrap()
        .0;
    let mut source = String::from(
        r#"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/user.h>
typedef int process_id_t;
typedef int thread_id_t;
typedef unsigned char* app_pc;
typedef uint64_t reg_t;
#define DR_MC_ALL 7
#define DR_ASSERT assert
typedef struct {
  size_t size;
  unsigned int flags;
  uint64_t r15, r14, r13, r12, xbp, xbx, r11, r10, r9, r8;
  uint64_t xax, xcx, xdx, xsi, xdi;
  union { app_pc xip; app_pc pc; };
  uint64_t xflags, xsp;
  uint64_t other_context[8];
} dr_mcontext_t;
"#,
    );
    source.push_str("typedef enum {\n  REGISTER_ORIG_UNKNOWN,");
    source.push_str(declarations);
    source.push_str("} register_orig_t;\n");
    source.push_str(
        r#"
typedef struct {
  register_orig_t register_orig, preempt_register_orig;
  uint64_t signal_token, pending_thread_start, preempt_pending;
  bool in_syscall_event, signal_registers_changed, initial_register_view_pending;
  app_pc admission_pc;
  dr_mcontext_t* signal_mcontext;
} prototype_counters_t;
static prototype_counters_t state;
static dr_mcontext_t machine, interrupted;
static _Atomic uint64_t image_generation = 17;
static process_id_t current_pid = 100;
static thread_id_t current_tid = 100;
static void* current_context = (void*)0x1234;
static int thread_state_index, diagnostic_file;
static bool get_ok = true, set_ok = true;
static unsigned get_calls, set_calls;
static char diagnostic[256];
static void* dr_get_current_drcontext(void) { return current_context; }
static process_id_t dr_get_process_id(void) { return current_pid; }
static thread_id_t dr_get_thread_id(void* context) { (void)context; return current_tid; }
static void* drmgr_get_tls_field(void* context, int index) {
  (void)index;
  return context == current_context ? &state : NULL;
}
static bool dr_get_mcontext(void* context, dr_mcontext_t* out) {
  assert(context == current_context);
  ++get_calls;
  if (!get_ok) return false;
  memcpy(out, &machine, sizeof(machine));
  return true;
}
static bool dr_set_mcontext(void* context, dr_mcontext_t* in) {
  assert(context == current_context);
  ++set_calls;
  if (!set_ok) return false;
  memcpy(&machine, in, sizeof(machine));
  return true;
}
static void dr_fprintf(int channel, const char* format, ...) {
  assert(channel == diagnostic_file);
  va_list args;
  va_start(args, format);
  vsnprintf(diagnostic, sizeof(diagnostic), format, args);
  va_end(args);
}
"#,
    );
    for signature in [
        "static void clear_register_orig(",
        "static void save_preempt_register_orig(",
        "static void restore_preempt_register_orig(",
        "static void bind_register_orig(",
        "static bool register_orig_available(",
        "static int32_t refuse_register_orig(",
        "static int32_t read_registers(",
        "static int32_t write_registers(",
        "static void canonicalize_syscall_clobbers(",
        "static void capture_syscall_register_orig(",
    ] {
        source.push_str(native_function(signature));
        source.push('\n');
    }
    source.push_str(
        r#"
static void reset_calls(void) {
  get_calls = set_calls = 0;
  diagnostic[0] = '\0';
}
static bool same_orig(register_orig_t a, register_orig_t b) {
  return a.value == b.value && a.image == b.image && a.pid == b.pid &&
      a.tid == b.tid && a.kind == b.kind;
}
static void assert_refused(struct user_regs_struct* requested) {
  dr_mcontext_t before, saved_before;
  register_orig_t origin_before;
  memcpy(&before, &machine, sizeof(before));
  memcpy(&origin_before, &state.register_orig, sizeof(origin_before));
  memcpy(&saved_before, &interrupted, sizeof(saved_before));
  reset_calls();
  assert(write_registers((uintptr_t)current_context, requested) == 0);
  assert(strstr(diagnostic, "register-view-orig-rax-") != NULL);
  assert(get_calls == 0 && set_calls == 0);
  assert(memcmp(&machine, &before, sizeof(machine)) == 0);
  assert(memcmp(&state.register_orig, &origin_before, sizeof(origin_before)) == 0);
  assert(memcmp(&interrupted, &saved_before, sizeof(interrupted)) == 0);
}
int main(void) {
  memset(&machine, 0x3c, sizeof(machine));
  machine.size = sizeof(machine);
  machine.flags = DR_MC_ALL;
  machine.xax = 7;
  machine.xip = (app_pc)0x400100;
  machine.xsp = 0x700000;
  machine.xflags = 0x246;
  memcpy(&interrupted, &machine, sizeof(interrupted));
  state.signal_mcontext = &interrupted;
  struct user_regs_struct requested = {0}, observed, untouched;
  requested.rax = 1515847937;
  requested.orig_rax = 59;
  memset(&observed, 0xa5, sizeof(observed));
  untouched = observed;
  assert(read_registers((uintptr_t)current_context, &observed) == 0);
  assert(strcmp(diagnostic,
      "reverie-dbt: register-view-orig-rax-unavailable (read)\n") == 0);
  fputs(diagnostic, stdout);
  assert(memcmp(&observed, &untouched, sizeof(observed)) == 0);
  assert_refused(&requested);
  fputs(diagnostic, stdout);

  state.pending_thread_start = 1;
  state.admission_pc = (app_pc)0x400000;
  bind_register_orig(&state, current_context, REGISTER_ORIG_IMAGE_START, 59);
  assert(read_registers((uintptr_t)current_context, &observed) == 1);
  assert(observed.rax == 7 && observed.orig_rax == 59);
  assert(observed.rip == 0x400000);
  requested = observed;
  requested.rax = 1515847937;
  dr_mcontext_t expected;
  memcpy(&expected, &machine, sizeof(expected));
  expected.xax = requested.rax;
  assert(write_registers((uintptr_t)current_context, &requested) == 1);
  assert(memcmp(&machine, &expected, sizeof(machine)) == 0);
  assert(read_registers((uintptr_t)current_context, &observed) == 1);
  assert(observed.rax == 1515847937 && observed.orig_rax == 59);
  requested = observed;
  requested.orig_rax = 61;
  assert(write_registers((uintptr_t)current_context, &requested) == 1);
  assert(machine.xax == 1515847937 && state.register_orig.value == 61);
  requested.orig_rax = 63;
  requested.rax = 123;
  set_ok = false;
  assert(write_registers((uintptr_t)current_context, &requested) == 0);
  assert(machine.xax == 1515847937 && state.register_orig.value == 61);
  set_ok = true;

  register_orig_t owned;
  memcpy(&owned, &state.register_orig, sizeof(owned));
  ++current_pid;
  assert_refused(&requested); // fork-copy storage has the parent's PID
  --current_pid;
  ++current_tid;
  assert_refused(&requested);
  --current_tid;
  atomic_fetch_add(&image_generation, 1);
  assert_refused(&requested);
  atomic_fetch_sub(&image_generation, 1);
  assert(memcmp(&state.register_orig, &owned, sizeof(owned)) == 0);
  state.admission_pc = NULL;
  assert_refused(&requested); // a late start does not acquire image-start59

  state.in_syscall_event = true;
  machine.xax = UINT64_C(0x1234567800000027);
  state.initial_register_view_pending = true;
  capture_syscall_register_orig(current_context, SYS_getpid);
  assert(!state.initial_register_view_pending);
  assert(state.register_orig.kind == REGISTER_ORIG_SYSCALL);
  assert(state.register_orig.value == UINT64_C(0x1234567800000027));
  assert_refused(&requested); // still in the late thread-start callback
  state.pending_thread_start = 0;
  machine.xax = (uint64_t)-9;
  assert(read_registers((uintptr_t)current_context, &observed) == 1);
  assert(observed.rax == (uint64_t)-9);
  assert(observed.orig_rax == UINT64_C(0x1234567800000027));
  requested = observed;
  requested.rax = 123;
  requested.orig_rax = SYS_getppid;
  assert_refused(&requested);
  assert(strcmp(diagnostic,
      "reverie-dbt: register-view-orig-rax-write-unsupported\n") == 0);
  fputs(diagnostic, stdout);
  requested.orig_rax = observed.orig_rax;
  assert(write_registers((uintptr_t)current_context, &requested) == 1);
  assert(machine.xax == 123);
  state.in_syscall_event = false;
  assert_refused(&requested); // a last syscall is not a continuation fact

  // The saved preemption view and temporary SchedYield view are independent.
  register_orig_t interrupted_orig;
  memcpy(&interrupted_orig, &state.register_orig, sizeof(interrupted_orig));
  save_preempt_register_orig(&state);
  assert(state.register_orig.kind == REGISTER_ORIG_UNKNOWN);
  state.preempt_pending = 1;
  state.in_syscall_event = true;
  machine.xax = SYS_sched_yield;
  capture_syscall_register_orig(current_context, SYS_sched_yield);
  assert(state.register_orig.kind == REGISTER_ORIG_PREEMPT_SYSCALL);
  assert(state.register_orig.value == SYS_sched_yield);
  assert(same_orig(state.preempt_register_orig, interrupted_orig));
  machine.xcx = 77;
  machine.r11 = 88;
  memcpy(&expected, &machine, sizeof(expected));
  expected.xcx = (reg_t)expected.xip;
  expected.r11 = expected.xflags;
  dr_mcontext_t saved_interrupted;
  memcpy(&saved_interrupted, &interrupted, sizeof(saved_interrupted));
  canonicalize_syscall_clobbers(current_context, SYS_sched_yield);
  assert(memcmp(&machine, &expected, sizeof(machine)) == 0);
  assert(memcmp(&interrupted, &saved_interrupted, sizeof(interrupted)) == 0);
  assert(same_orig(state.preempt_register_orig, interrupted_orig));
  assert(state.register_orig.value == SYS_sched_yield);
  restore_preempt_register_orig(&state);
  state.preempt_pending = 0;
  assert(same_orig(state.register_orig, interrupted_orig));
  assert(state.preempt_register_orig.kind == REGISTER_ORIG_UNKNOWN);
  machine.xax = SYS_sched_yield;
  capture_syscall_register_orig(current_context, SYS_sched_yield);
  assert(state.register_orig.kind == REGISTER_ORIG_SYSCALL);

  // Private Gettid never supplies the missing saved-signal origin. No stored
  // context or application metadata is guessed from its live XAX.
  state.signal_token = 1;
  machine.xax = SYS_gettid;
  capture_syscall_register_orig(current_context, SYS_gettid);
  assert(state.register_orig.kind == REGISTER_ORIG_UNKNOWN);
  assert(read_registers((uintptr_t)current_context, &observed) == 0);
  assert_refused(&requested);
  reset_calls();
  memcpy(&expected, &machine, sizeof(expected));
  canonicalize_syscall_clobbers(current_context, SYS_gettid);
  assert(get_calls == 0 && set_calls == 0);
  assert(memcmp(&machine, &expected, sizeof(machine)) == 0);
  assert(memcmp(&interrupted, &saved_interrupted, sizeof(interrupted)) == 0);
  state.signal_token = 0;
  canonicalize_syscall_clobbers(current_context, SYS_rt_sigreturn);
  assert(get_calls == 0 && set_calls == 0);

  // Internal clobber repair remains valid even when no Tool register view is
  // available, and modifies exactly RCX/R11 in the physical context.
  clear_register_orig(&state);
  machine.xcx = 1;
  machine.r11 = 2;
  memcpy(&expected, &machine, sizeof(expected));
  expected.xcx = (reg_t)expected.xip;
  expected.r11 = expected.xflags;
  canonicalize_syscall_clobbers(current_context, SYS_getpid);
  assert(memcmp(&machine, &expected, sizeof(machine)) == 0);
  assert(state.register_orig.kind == REGISTER_ORIG_UNKNOWN);
  puts("native register view ownership controls passed");
  return 0;
}
"#,
    );
    let directory = tempfile::tempdir().expect("native register-view control directory");
    let input = directory.path().join("register-view-control.c");
    let output = directory.path().join("register-view-control");
    std::fs::write(&input, source.as_bytes()).expect("write native register-view control");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let mut command = Command::new(&compiler);
    command
        .args(["-std=gnu11", "-Wall", "-Werror", "-O0"])
        .arg(&input)
        .arg("-o")
        .arg(&output);
    eprintln!("native register-view control compiler={command:?}");
    let compiled = command
        .output()
        .expect("compile native register-view control");
    eprintln!(
        "native register-view control compile status={:?} stdout={:?} stderr={:?}",
        compiled.status.code(),
        compiled.stdout,
        compiled.stderr
    );
    assert!(
        compiled.status.success(),
        "native register-view control compile failed"
    );
    let bytes = std::fs::read(&output).expect("read native register-view control image");
    eprintln!(
        "native register-view control source_sha256={:x} image_sha256={:x} image_bytes={}",
        sha2::Sha256::digest(source.as_bytes()),
        sha2::Sha256::digest(&bytes),
        bytes.len()
    );
    let result = Command::new(&output)
        .output()
        .expect("run native register-view control");
    eprintln!(
        "native register-view control status={:?} stdout={:?} stderr={:?}",
        result.status.code(),
        result.stdout,
        result.stderr
    );
    assert!(
        result.status.success(),
        "native register-view control failed"
    );
    assert_eq!(result.stdout, b"reverie-dbt: register-view-orig-rax-unavailable (read)\nreverie-dbt: register-view-orig-rax-unavailable (write)\nreverie-dbt: register-view-orig-rax-write-unsupported\nnative register view ownership controls passed\n");
    assert!(result.stderr.is_empty());

    // These bind the actual production call sites to the exercised helpers.
    let gate = between(
        NATIVE,
        "static void start_pending_thread(app_pc pc) {",
        "static void maybe_preempt(app_pc pc);",
    );
    ordered(
        gate,
        &[
            "initial_register_view_pending = false;",
            "pc != NULL",
            "REGISTER_ORIG_IMAGE_START, SYS_execve",
            "admit_pending_thread();",
            "clear_register_orig(counters);",
        ],
    );
    let pre = native_function("static bool pre_syscall_event(");
    ordered(
        pre,
        &[
            "capture_syscall_register_orig(drcontext, sysnum);",
            "set_in_syscall_event(drcontext, true);",
            "pre_syscall(drcontext, sysnum)",
            "canonicalize_syscall_clobbers(drcontext, sysnum);",
            "set_in_syscall_event(drcontext, false);",
        ],
    );
    assert!(
        !native_function("static void try_start_pending_thread(").contains("bind_register_orig")
    );
    let init = native_function("static void thread_init(");
    assert!(init.contains("host_tid == dr_get_process_id() && !has_copied_runtime()"));
    assert!(init.contains("pending_child == 0 && dr_get_process_id() == runtime_owner_pid"));
}

fn c_layout(name: &str, size: usize, fields: &[(&str, usize)]) {
    assert!(NATIVE.contains(&format!("sizeof({name}) == {size}")));
    for (field, offset) in fields {
        assert!(
            NATIVE.contains(&format!("offsetof({name}, {field}) == {offset}")),
            "missing checked C field {name}.{field}"
        );
    }
}

#[test]
fn abi16_c_layouts_bind_the_actual_rust_records() {
    assert_eq!(DBT_RUNTIME_ABI_VERSION, 16);
    assert!(NATIVE.contains("#define REVERIE_DBT_RUNTIME_ABI_VERSION 16u"));
    assert_eq!(size_of::<DbtRuntimeCallbacks>(), 104);
    c_layout(
        "runtime_callbacks_t",
        size_of::<DbtRuntimeCallbacks>(),
        &[
            ("emit", offset_of!(DbtRuntimeCallbacks, emit)),
            ("idle", offset_of!(DbtRuntimeCallbacks, idle)),
            (
                "panic_on_unsupported_syscalls",
                offset_of!(DbtRuntimeCallbacks, panic_on_unsupported_syscalls),
            ),
            (
                "unsupported_report_fd",
                offset_of!(DbtRuntimeCallbacks, unsupported_report_fd),
            ),
            ("emit_stdout", offset_of!(DbtRuntimeCallbacks, emit_stdout)),
            (
                "emit_evidence",
                offset_of!(DbtRuntimeCallbacks, emit_evidence),
            ),
            (
                "evidence_log_level",
                offset_of!(DbtRuntimeCallbacks, evidence_log_level),
            ),
            (
                "compare_exchange_u32",
                offset_of!(DbtRuntimeCallbacks, compare_exchange_u32),
            ),
            (
                "controller_capture_control",
                offset_of!(DbtRuntimeCallbacks, controller_capture_control),
            ),
            (
                "runtime_private_memory",
                offset_of!(DbtRuntimeCallbacks, runtime_private_memory),
            ),
            ("branch_fact", offset_of!(DbtRuntimeCallbacks, branch_fact)),
            (
                "mapping_capture",
                offset_of!(DbtRuntimeCallbacks, mapping_capture),
            ),
            (
                "admit_terminal",
                offset_of!(DbtRuntimeCallbacks, admit_terminal),
            ),
            (
                "rpc_transport_fatal",
                offset_of!(DbtRuntimeCallbacks, rpc_transport_fatal),
            ),
        ],
    );
    assert_eq!(size_of::<ImageDescriptor>(), 56);
    c_layout(
        "image_descriptor_t",
        size_of::<ImageDescriptor>(),
        &[
            ("size", offset_of!(ImageDescriptor, size)),
            ("abi", offset_of!(ImageDescriptor, abi)),
            ("capabilities", offset_of!(ImageDescriptor, capabilities)),
            (
                "image_generation",
                offset_of!(ImageDescriptor, image_generation),
            ),
            (
                "runtime_input_identity",
                offset_of!(ImageDescriptor, runtime_input_identity),
            ),
        ],
    );
    assert_eq!(size_of::<ReadySnapshot>(), 48);
    c_layout(
        "ready_snapshot_t",
        size_of::<ReadySnapshot>(),
        &[
            ("size", offset_of!(ReadySnapshot, size)),
            (
                "selected_event_bits",
                offset_of!(ReadySnapshot, selected_event_bits),
            ),
            (
                "raw_config_digest",
                offset_of!(ReadySnapshot, raw_config_digest),
            ),
            (
                "owner_generation",
                offset_of!(ReadySnapshot, owner_generation),
            ),
        ],
    );
    assert_eq!(size_of::<TerminalFact>(), 104);
    assert_eq!(align_of::<TerminalFact>(), 8);
    assert!(NATIVE.contains("_Alignof(terminal_fact_t) == 8"));
    c_layout(
        "terminal_fact_t",
        size_of::<TerminalFact>(),
        &[
            ("size", offset_of!(TerminalFact, size)),
            ("kind", offset_of!(TerminalFact, kind)),
            ("image", offset_of!(TerminalFact, image)),
            ("context", offset_of!(TerminalFact, context)),
            ("pid", offset_of!(TerminalFact, pid)),
            ("tid", offset_of!(TerminalFact, tid)),
            ("sysno", offset_of!(TerminalFact, sysno)),
            ("args", offset_of!(TerminalFact, args)),
            ("cookie", offset_of!(TerminalFact, cookie)),
            ("origin", offset_of!(TerminalFact, origin)),
            ("reserved", offset_of!(TerminalFact, reserved)),
        ],
    );
    assert!(NATIVE.contains("offsetof(prototype_counters_t, runtime_state) == 24"));
    let fields = between(NATIVE, "  void* runtime_state;", "} prototype_counters_t;");
    ordered(
        fields,
        &[
            "app_pc admission_pc;",
            "uintptr_t caller_context;",
            "terminal_fact_t caller_terminal;",
        ],
    );
}

#[test]
fn descriptor_identity_precedes_instrumentation_without_translation_waits() {
    assert!(CMAKE.contains("if(DEFINED REVERIE_DBT_CALLER_INPUT_IDENTITY)"));
    assert!(CMAKE.contains("NOT caller_identity_length EQUAL 64"));
    assert!(CMAKE.contains("MATCHES \"^[0-9a-f]+$\""));
    let validation = between(
        NATIVE,
        "static bool valid_runtime_image_descriptor(void) {",
        "static bool runtime_ready_for_image(void);",
    );
    ordered(
        validation,
        &[
            "descriptor->capabilities != 0",
            "descriptor->capabilities != REVERIE_DBT_CALLER_CAPABILITIES",
            "if (!caller_mode())",
            "strlen(expected) != 64",
            "byte != descriptor->runtime_input_identity[i]",
        ],
    );
    assert!(validation.contains("digit >= 'a' && digit <= 'f'"));
    assert!(NATIVE.contains("#define REVERIE_DBT_CALLER_CAPABILITIES UINT64_C(7)"));
    let main = NATIVE
        .split_once("DR_EXPORT void dr_client_main")
        .unwrap()
        .1;
    ordered(
        main,
        &[
            "runtime_image_descriptor = reverie_dbt_runtime_image_init();",
            "!valid_runtime_image_descriptor()",
            "&image_generation,",
            "runtime_callbacks_page.value.admit_terminal = runtime_admit_terminal;",
            "runtime_callbacks_page.value.rpc_transport_fatal = runtime_rpc_transport_fatal;",
            "drmgr_register_bb_app2app_event(rewrite_cpuid",
            "drmgr_register_bb_instrumentation_event(",
        ],
    );
    for (start, end) in [
        (
            "static dr_emit_flags_t rewrite_cpuid(",
            "static uint64_t guest_tsc(",
        ),
        (
            "static dr_emit_flags_t rewrite_rdtsc(",
            "static void set_pending_thread_start(",
        ),
    ] {
        let rewrite = between(NATIVE, start, end);
        ordered(
            rewrite,
            &[
                "if (caller_mode())",
                "return DR_EMIT_DEFAULT;",
                "for (instruction = instrlist_first_app(bb)",
                "instrlist_replace(bb, instruction, marker);",
            ],
        );
        assert!(!rewrite.contains("runtime_ready_for_image"));
        assert!(!rewrite.contains("dr_sleep("));
    }
}

#[test]
fn ready_and_real_start_ack_hold_the_existing_first_instruction_gate() {
    let inspection = between(
        NATIVE,
        "static runtime_readiness_t inspect_runtime_readiness(void) {",
        "static bool runtime_ready_for_image(void) {",
    );
    ordered(
        inspection,
        &[
            "background == RUNTIME_BACKGROUND_FAILED",
            "return RUNTIME_READINESS_FAILED;",
            "reverie_dbt_runtime_ready(image, &snapshot)",
            "background == RUNTIME_BACKGROUND_FAILED",
            "return RUNTIME_READINESS_FAILED;",
            "if (status == 0)",
            "return RUNTIME_READINESS_PENDING;",
            "status != 1",
            "snapshot.size != sizeof(snapshot)",
            "snapshot.owner_generation != image",
            "snapshot.selected_event_bits != 0",
            "return RUNTIME_READINESS_INVALID;",
            "return RUNTIME_READINESS_READY;",
        ],
    );
    for forbidden in [
        "exit_runtime_tree(",
        "dr_fprintf(",
        "dr_sleep(",
        "atomic_store",
    ] {
        assert!(!inspection.contains(forbidden));
    }
    let ready = between(
        NATIVE,
        "static bool runtime_ready_for_image(void) {",
        "static bool wait_for_runtime_ready(",
    );
    ordered(
        ready,
        &[
            "inspect_runtime_readiness()",
            "readiness == RUNTIME_READINESS_FAILED",
            "exit_runtime_tree(CLIENT_THREAD_START_FAILURE_EXIT_CODE);",
            "readiness == RUNTIME_READINESS_INVALID",
            "exit_runtime_tree(101);",
            "readiness != RUNTIME_READINESS_READY",
            "return false;",
            "&runtime_readiness_observed, true, memory_order_release",
            "return true;",
        ],
    );
    let wait = between(
        NATIVE,
        "static bool wait_for_runtime_ready(",
        "static bool caller_live_context(",
    );
    ordered(
        wait,
        &[
            "bool ready = runtime_ready_for_image();",
            "if (ready && (!require_background_finished ||",
            "&runtime_background_state, memory_order_acquire) == 3",
            "return true;",
            "dr_sleep(1);",
        ],
    );
    let start = between(
        NATIVE,
        "static void try_start_pending_thread(void) {",
        "static void admit_pending_thread(void) {",
    );
    ordered(
        start,
        &[
            "caller_live_context(drcontext, counters, false)",
            "if (!runtime_ready_for_image())",
            "set_pending_thread_start(counters, 2);",
            "caller_unfiltered(drcontext)",
            "reverie_dbt_runtime_thread_init(",
            "if (init_result > 0)",
            "if (init_result < 0)",
            "counters->caller_admitted = true;",
            "set_pending_thread_start(counters, 0);",
        ],
    );
    let admission = between(
        NATIVE,
        "static void admit_pending_thread(void) {",
        "static void start_pending_thread(app_pc pc) {",
    );
    assert!(
        admission.contains("const uint64_t timeout_ms = test_stalled_thread_start ? 100 : 60000;")
    );
    ordered(
        admission,
        &[
            "clock_gettime(CLOCK_MONOTONIC, &started)",
            "try_start_pending_thread();",
            "elapsed_ms >= timeout_ms",
            "exit_runtime_tree(96);",
        ],
    );
    let gate = between(
        NATIVE,
        "static void start_pending_thread(app_pc pc) {",
        "static void maybe_preempt(app_pc pc);",
    );
    ordered(
        gate,
        &[
            "ensure_runtime_background();",
            "if (!caller_mode() && !wait_for_runtime_ready(false))",
            "return;",
            "counters->admission_pc = pc;",
            "admit_pending_thread();",
        ],
    );
    let instrumentation = between(
        NATIVE,
        "static dr_emit_flags_t instrument_instruction(",
        "static int64_t\ninvoke_raw_syscall",
    );
    assert!(instrumentation.contains("insert_thread_admission("));
    assert!(
        instrumentation
            .contains("instr_is_app(instruction) && instruction == instrlist_first_app(bb)")
    );
}

fn terminal_forward(source: &str) -> &str {
    between(
        source,
        "static bool prepare_caller_terminal_forward(",
        "// TODO-HUMAN-REVIEW(PR-66)",
    )
}

fn check_prepared_consumption(source: &str) {
    ordered(
        terminal_forward(source),
        &[
            "caller_terminal_boundary(drcontext, counters)",
            "reserve_caller_terminal(drcontext, counters, sysnum, args, origin)",
            "caller_terminal_matches(drcontext, counters, sysnum, args, origin)",
            "!caller_unfiltered(drcontext)",
            "protect_evidence_socket_syscall(",
            "preserve_internal_descriptors(",
            "!prepare_original_task_syscall(",
            "dr_get_mcontext(drcontext, &prepared)",
            "(int64_t)prepared.xax != sysnum",
            "dr_syscall_get_param(drcontext, i) != args[i]",
            "counters->caller_terminal_state = CALLER_CONSUMING;",
            "int32_t status = reverie_dbt_runtime_thread_exit(",
            "&counters->caller_terminal);",
            "if (status != 0)",
            "counters->caller_terminal_state = CALLER_CONSUMED_FOR_FORWARD;",
            "return true;",
        ],
    );
}

#[test]
fn terminal_reserves_real_context_but_consumes_only_after_final_preparation() {
    let probe = between(
        NATIVE,
        "static bool caller_unfiltered(void* drcontext) {",
        "static bool caller_unsupported_operation(",
    );
    assert!(probe.contains("{PR_GET_SECCOMP, 0, 0, 0, 0, 0}"));
    assert!(probe.contains("invoke_raw_syscall((uintptr_t)drcontext, SYS_prctl, args) == 0"));
    let context = between(
        NATIVE,
        "static bool caller_live_context(\n",
        "static dr_emit_flags_t rewrite_cpuid(",
    );
    for fact in [
        "drcontext == dr_get_current_drcontext()",
        "dr_get_process_id() == task_state->root_pid",
        "dr_get_process_id() == runtime_owner_pid",
        "dr_get_thread_id(drcontext) == dr_get_process_id()",
        "counters->kernel_ppid == dr_get_parent_id()",
        "counters->caller_image == runtime_image_descriptor.image_generation",
    ] {
        assert!(context.contains(fact), "missing actual owner fact: {fact}");
    }
    let reservation = between(
        NATIVE,
        "static bool reserve_caller_terminal(",
        "static bool caller_terminal_preparation_failure(",
    );
    ordered(
        reservation,
        &[
            "caller_terminal_boundary(drcontext, counters)",
            "CALLER_NOT_ENDING",
            "!caller_unfiltered(drcontext)",
            "++counters->caller_cookie_sequence",
            "memcpy(fact.args, args, sizeof(fact.args));",
            "counters->caller_terminal = fact;",
            "counters->caller_terminal_state = CALLER_RESERVED;",
        ],
    );
    assert!(reservation.contains("!counters->caller_syscall_callback"));
    assert!(reservation.contains("native_runtime_entries != 1"));
    assert!(reservation.contains("sysnum, args, 2)"));
    assert!(reservation.contains("*out = counters->caller_terminal;\n  return 1;"));
    assert!(!reservation.contains("reverie_dbt_runtime_thread_exit("));
    let failure = between(
        NATIVE,
        "static bool caller_terminal_preparation_failure(",
        "static bool prepare_caller_terminal_forward(",
    );
    ordered(
        failure,
        &[
            "CALLER_FAILED",
            "dr_syscall_get_result(drcontext)",
            "exit_runtime_tree(101);",
            "return false;",
        ],
    );
    assert!(!failure.contains("reverie_dbt_runtime_thread_exit("));
    check_prepared_consumption(NATIVE);
}

#[test]
fn consumption_order_control_rejects_cleanup_moved_before_preparation() {
    let forward = terminal_forward(NATIVE);
    let begin = forward
        .find("  counters->caller_terminal_state = CALLER_CONSUMING;")
        .unwrap();
    let end = begin + forward[begin..].find("  if (status != 0)").unwrap();
    let consume = &forward[begin..end];
    let moved = forward.replacen(consume, "", 1).replacen(
        "  int64_t result = 0;",
        &format!("{consume}  int64_t result = 0;"),
        1,
    );
    let mutated = NATIVE.replacen(forward, &moved, 1);
    assert_eq!(
        terminal_forward(&mutated)
            .matches("reverie_dbt_runtime_thread_exit(")
            .count(),
        1
    );
    assert!(std::panic::catch_unwind(|| check_prepared_consumption(&mutated)).is_err());
}

#[test]
fn caller_refusals_precede_effects_and_legacy_cleanup_order_remains() {
    check_refusal_symbols(NATIVE, CALLER_EFFECTS);
    let guards = between(
        NATIVE,
        "static bool caller_unsupported_operation(\n",
        "static bool is_exec_syscall(int sysnum);",
    );
    for symbol in [
        "clone",
        "clone3",
        "fork",
        "vfork",
        "execve",
        "execveat",
        "seccomp",
        "ptrace",
        "kill",
        "tkill",
        "tgkill",
        "rt_sigqueueinfo",
        "rt_tgsigqueueinfo",
        "pidfd_send_signal",
        "unshare",
        "setns",
        "setsid",
        "setpgid",
        "setuid",
        "setgid",
        "setreuid",
        "setregid",
        "setresuid",
        "setresgid",
        "setfsuid",
        "setfsgid",
        "setgroups",
        "capset",
    ] {
        assert!(guards.contains(&format!("case SYS_{symbol}:")));
    }
    for option in ["PR_SET_SECCOMP", "PR_SET_PTRACER", "PR_SET_NO_NEW_PRIVS"] {
        assert!(guards.contains(&format!("(int32_t)args[0] == {option}")));
    }
    assert!(guards.contains("returning && (sysnum == SYS_exit || sysnum == SYS_exit_group)"));
    let invoke = between(
        NATIVE,
        "invoke_syscall(uintptr_t context, int64_t sysnum, const uint64_t* args, uint32_t purpose) {",
        "static int32_t read_registers(",
    );
    ordered(
        invoke,
        &[
            "caller_unsupported_operation(sysnum, args, true)",
            "capture_observe_lifecycle(",
            "complete_runtime_thread_exit(",
            "invoke_raw_syscall_with_purpose(context, sysnum, translated, purpose)",
        ],
    );
    assert!(invoke.contains("CALLER_CONSUMING"));
    assert!(invoke.contains("native_runtime_entries == 1"));
    assert!(invoke.contains("(sysnum == SYS_read || sysnum == SYS_write)"));
    let pre = between(
        NATIVE,
        "static bool pre_syscall(void* drcontext, int sysnum) {",
        "static void compare_exchange_increment_many(",
    );
    ordered(
        pre,
        &[
            "caller_unsupported_operation(sysnum, args, false)",
            "capture_observe_lifecycle(sysnum, args);",
            "reverie_dbt_runtime_pre_syscall(",
            "counters->caller_syscall_callback = false;",
        ],
    );
    let deferred = pre.split_once("if (action == 2) {").unwrap().1;
    ordered(
        deferred,
        &[
            "caller_unsupported_operation(deferred_sysnum, deferred_args, false)",
            "dr_syscall_set_sysnum(drcontext, sysnum);",
            "prepare_caller_terminal_forward(drcontext, counters, sysnum, args, 2)",
            "complete_runtime_thread_exit(",
            "prepare_original_task_syscall(",
        ],
    );
    let original = pre
        .split_once("/* A runtime that declines a call")
        .unwrap()
        .1;
    ordered(
        original,
        &[
            "prepare_caller_terminal_forward(drcontext, counters, sysnum, args, 1)",
            "complete_runtime_thread_exit(",
            "prepare_original_task_syscall(",
        ],
    );
    let copied = between(
        pre,
        "if (has_copied_runtime() &&\n      (!runtime_uses_external_global()",
        "  if (caller_mode()) {",
    );
    ordered(
        copied,
        &[
            "complete_runtime_thread_exit(",
            "prepare_original_task_syscall(",
        ],
    );
}

#[test]
fn native_notifications_do_not_repeat_consumption_or_invent_status() {
    let completion = between(
        NATIVE,
        "static void complete_runtime_thread_exit(\n",
        "static void thread_exit(void* drcontext) {",
    );
    ordered(
        completion,
        &[
            "if (caller_mode())",
            "CALLER_CONSUMED_FOR_FORWARD",
            "CALLER_FAILED",
            "return;",
            "terminal_fact_t unknown",
            ".kind = 2",
            ".origin = 3",
            "mark_backend_failure();",
            "invoke_syscall, &unknown)",
            "return;",
            "invoke_syscall, NULL)",
        ],
    );
    let unknown = between(
        completion,
        "terminal_fact_t unknown",
        "mark_backend_failure();",
    );
    for invented in [".sysno", ".args", ".cookie"] {
        assert!(!unknown.contains(invented));
    }
    let signals = between(
        NATIVE,
        "static dr_signal_admission_status_t signal_admission_event(",
        "static void signal_admission_return(void) {",
    );
    let caller = signals
        .split_once("  if (event == NULL) {\n    if (counters == NULL")
        .unwrap()
        .0;
    ordered(
        caller,
        &[
            "caller_live_context(drcontext, counters, false)",
            "DR_SIGNAL_ADMISSION_BYPASS",
            "native_runtime_entries != 0",
            "DR_SIGNAL_ADMISSION_WAIT",
            "event->sig",
            "exit_runtime_tree(101);",
        ],
    );
    assert!(!caller.contains("runtime_ready_for_image"));
    assert!(!caller.contains("reverie_dbt_runtime_signal_event"));
}

fn check_suppression_only_boundaries(native: &str, runtime: &str, driver: &str) {
    check_refusal_symbols(native, CALLER_EFFECTS);
    let pre = between(
        native,
        "static bool pre_syscall(void* drcontext, int sysnum) {",
        "static void compare_exchange_increment_many(",
    );
    let dispatch = pre
        .split_once("capture_observe_lifecycle(sysnum, args);")
        .unwrap()
        .0;
    assert!(dispatch.contains(
        "(sysnum != SYS_tgkill &&\n        caller_unsupported_operation(sysnum, args, false))"
    ));
    ordered(
        dispatch,
        &[
            "!caller_live_context(drcontext, counters, true)",
            "sysnum != SYS_tgkill",
            "caller_unsupported_operation(sysnum, args, false)",
            "caller application operation refused before effect (%d)",
            "exit_runtime_tree(101);",
            "return false;",
        ],
    );
    let suppress = between(pre, "  if (action == 1) {", "  if (action == 2) {");
    ordered(
        suppress,
        &[
            "dr_syscall_set_result(drcontext, (reg_t)result);",
            "return false;",
        ],
    );
    for effect in ["prepare_", "invoke_syscall(", "dr_syscall_set_sysnum("] {
        assert!(!suppress.contains(effect));
    }
    let deferred = between(pre, "  if (action == 2) {", "  /* A declined call");
    assert!(deferred.contains("if (caller_mode() && sysnum == SYS_tgkill &&\n        counters->caller_terminal_state == CALLER_NOT_ENDING)"));
    ordered(
        deferred,
        &[
            "sysnum == SYS_tgkill",
            "counters->caller_terminal_state == CALLER_NOT_ENDING",
            "caller suppression-only forwarding refused before effect",
            "exit_runtime_tree(101);",
            "return false;",
            "caller_unsupported_operation(deferred_sysnum, deferred_args, false)",
            "caller deferred operation refused before effect",
            "exit_runtime_tree(101);",
            "return false;",
            "sysnum = (int)deferred_sysnum;",
            "memcpy(args, deferred_args, sizeof(args));",
            "!caller_terminal_matches(drcontext, counters, deferred_sysnum, args, 2)",
            "runtime replaced an established terminal reservation",
            "capture_observe_lifecycle(sysnum, args);",
            "dr_syscall_set_sysnum(drcontext, sysnum);",
            "prepare_caller_terminal_forward(drcontext, counters, sysnum, args, 2)",
            "protect_evidence_socket_syscall(",
            "preserve_internal_descriptors(",
            "prepare_original_task_syscall(",
        ],
    );
    let original = pre.split_once("  /* A declined call").unwrap().1;
    ordered(
        original,
        &[
            "if (caller_mode() && caller_unsupported_operation(sysnum, args, false))",
            "caller application operation refused before effect (%d)",
            "exit_runtime_tree(101);",
            "return false;",
            "prepare_caller_terminal_forward(drcontext, counters, sysnum, args, 1)",
            "complete_runtime_thread_exit(",
            "prepare_original_task_syscall(",
            "return execute;",
        ],
    );
    let runtime = between(
        runtime,
        "    pub unsafe fn pre_syscall(",
        "    unsafe fn attachment",
    );
    ordered(
        runtime,
        &[
            "self.attachment(counters, context, pid, tid, image)",
            "attachment.phase != Phase::Running",
            "let suppression_only = number == libc::SYS_tgkill;",
            "if !suppression_only",
            "crate::caller_effects::unsupported_operation(number, &args, false)",
            "caller-application-lifecycle-unsupported",
            "let config = self",
            "let selected = config",
            ".any(|selected| selected.id() as i64 == number)",
            "if suppression_only && !selected",
            "caller-application-lifecycle-unsupported",
            "self.observed.fetch_add",
            "let syscall = raw_syscall(number, args)?;",
            "if !selected",
            "crate::sync_rpc::protect_guest_operation(",
            "crate::run_caller_syscall_with_guest(",
        ],
    );
    let execute = between(
        runtime,
        "crate::CallerSyscallOutcome::ExecuteOriginal(call) => {",
        "crate::CallerSyscallOutcome::Terminal(fact) => {",
    );
    ordered(
        execute,
        &[
            "if suppression_only",
            "caller-suppression-only-forwarding-unsupported",
            "self.rewritten.fetch_add",
            "crate::write_deferred_syscall(",
        ],
    );
    let driver = between(
        driver,
        "pub fn run_caller_syscall_with_guest<T: Tool>(",
        "fn protect_tool_syscall(",
    );
    ordered(
        driver,
        &[
            "reverie::CallbackDecision::Established(fact)",
            "return Ok(CallerSyscallOutcome::Terminal(fact));",
            "reverie::CallbackDecision::Deferred { number, args }",
            "if matches!(syscall, Syscall::Tgkill(_))",
            "caller-suppression-only-forwarding-unsupported",
            "let number = reverie::syscalls::Sysno::from(",
            "let syscall = Syscall::from_raw(",
            "match protect_tool_syscall(",
        ],
    );
}

#[test]
fn tgkill_suppression_dispatch_and_final_effect_boundaries_are_exact() {
    check_suppression_only_boundaries(
        NATIVE,
        include_str!("../src/caller_runtime.rs"),
        include_str!("../src/lib.rs"),
    );
}

#[test]
fn suppression_boundary_controls_reject_forwarding_and_widening_mutations() {
    let runtime = include_str!("../src/caller_runtime.rs");
    let driver = include_str!("../src/lib.rs");
    check_suppression_only_boundaries(NATIVE, runtime, driver);
    let refused = |native: &str, runtime: &str, driver: &str| {
        assert!(
            std::panic::catch_unwind(|| check_suppression_only_boundaries(native, runtime, driver))
                .is_err()
        );
    };
    let original_start = NATIVE.find("  /* A declined call").unwrap();
    let guard_start = original_start
        + NATIVE[original_start..]
            .find("  if (caller_mode()")
            .unwrap();
    let guard_end = guard_start + NATIVE[guard_start..].find("\n  }\n").unwrap() + "\n  }\n".len();
    let original_guard = &NATIVE[guard_start..guard_end];
    let removed = NATIVE.replacen(original_guard, "", 1);
    refused(&removed, runtime, driver);
    let marker = "  bool execute = prepare_original_task_syscall(\n      drcontext, counters, sysnum, args, false);";
    assert_eq!(removed.matches(marker).count(), 1);
    let late = removed.replacen(marker, &format!("{marker}\n{original_guard}"), 1);
    refused(&late, runtime, driver);

    let deferred_start = NATIVE
        .find("    if (caller_mode() && sysnum == SYS_tgkill &&")
        .unwrap();
    let deferred_end =
        deferred_start + NATIVE[deferred_start..].find("\n    }\n").unwrap() + "\n    }\n".len();
    let deferred_guard = &NATIVE[deferred_start..deferred_end];
    let removed = NATIVE.replacen(deferred_guard, "", 1);
    refused(&removed, runtime, driver);
    let late = removed.replacen(
        "    sysnum = (int)deferred_sysnum;",
        &format!("    sysnum = (int)deferred_sysnum;\n{deferred_guard}"),
        1,
    );
    refused(&late, runtime, driver);
    let widened = NATIVE.replacen(
        "sysnum != SYS_tgkill &&",
        "sysnum != SYS_tgkill && sysnum != SYS_kill &&",
        1,
    );
    refused(&widened, runtime, driver);
    let widened = runtime.replacen(
        "number == libc::SYS_tgkill;",
        "matches!(number, libc::SYS_tgkill | libc::SYS_kill);",
        1,
    );
    refused(NATIVE, &widened, driver);
    let suppress = between(NATIVE, "  if (action == 1) {", "  if (action == 2) {");
    let fallthrough = NATIVE.replacen(suppress, &suppress.replacen("    return false;", "", 1), 1);
    refused(&fallthrough, runtime, driver);

    let early = "                if matches!(syscall, Syscall::Tgkill(_)) {\n                    return Err(caller_error(\n                        \"caller-suppression-only-forwarding-unsupported\",\n                    ));\n                }";
    assert_eq!(driver.matches(early).count(), 1);
    let removed = driver.replacen(early, "", 1);
    refused(NATIVE, runtime, &removed);
    let original_start = runtime
        .find("                crate::CallerSyscallOutcome::ExecuteOriginal(call) => {")
        .unwrap();
    let guard = between(
        &runtime[original_start..],
        "                    if suppression_only {",
        "                    self.rewritten.fetch_add",
    );
    let removed = runtime.replacen(
        &format!("                    if suppression_only {{{guard}"),
        "",
        1,
    );
    refused(NATIVE, &removed, driver);
    let unselected = "            if suppression_only && !selected {\n                return Err(crate::caller_error(\n                    \"caller-application-lifecycle-unsupported\",\n                ));\n            }";
    assert_eq!(runtime.matches(unselected).count(), 1);
    let late = runtime.replacen(unselected, "", 1).replacen(
        "            self.observed.fetch_add(1, Ordering::Relaxed);",
        &format!("            self.observed.fetch_add(1, Ordering::Relaxed);\n{unselected}"),
        1,
    );
    refused(NATIVE, &late, driver);
}

#[test]
fn native_instruction_callbacks_own_register_view() {
    use std::process::Command;

    use sha2::Digest;

    // Execute the actual production instruction callbacks and register owners,
    // with controlled DR/runtime callbacks. This is C body/state coverage, not
    // a loaded DR image, a hardware trap, or live saved-signal qualification.
    let declarations = NATIVE
        .split_once("typedef enum {\n  REGISTER_ORIG_UNKNOWN,")
        .expect("native register origin declarations")
        .1
        .split_once("} register_orig_t;")
        .unwrap()
        .0;
    let mut source = String::from(
        r#"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/user.h>
typedef int process_id_t;
typedef int thread_id_t;
typedef unsigned char* app_pc;
typedef uint64_t reg_t;
#define DR_MC_INTEGER 1
#define DR_MC_CONTROL 2
#define DR_MC_ALL 7
#define DR_ASSERT assert
typedef struct {
  size_t size;
  unsigned int flags;
  uint64_t r15, r14, r13, r12, xbp, xbx, r11, r10, r9, r8;
  uint64_t xax, xcx, xdx, xsi, xdi;
  union { app_pc xip; app_pc pc; };
  uint64_t xflags, xsp;
  uint64_t other_context[8];
} dr_mcontext_t;
"#,
    );
    source.push_str("typedef enum {\n  REGISTER_ORIG_UNKNOWN,");
    source.push_str(declarations);
    source.push_str("} register_orig_t;\n");
    source.push_str(
        NATIVE
            .lines()
            .find(|line| line.starts_with("#define VIRTUAL_TSC_STRIDE "))
            .expect("existing fallback stride"),
    );
    source.push_str(
        r#"
typedef struct {
  register_orig_t register_orig;
  uint64_t signal_token, pending_thread_start, preempt_pending;
  bool in_syscall_event, signal_registers_changed;
  app_pc admission_pc;
  dr_mcontext_t* signal_mcontext;
} prototype_counters_t;
typedef int64_t (*invoker_t)(uintptr_t, int64_t, const uint64_t*, uint32_t);
typedef int32_t (*reader_t)(uintptr_t, struct user_regs_struct*);
typedef int32_t (*writer_t)(uintptr_t, const struct user_regs_struct*);
typedef void (*emitter_t)(const char*, size_t);
static prototype_counters_t state;
static dr_mcontext_t machine;
static _Atomic uint64_t image_generation = 17, branch_count = 19, virtual_tsc;
static process_id_t current_pid = 100;
static process_id_t copied_process_runtime_pid;
static thread_id_t current_tid = 100;
static void* current_context = (void*)0x1234;
static int thread_state_index, diagnostic_file;
static bool copied, external_global, copied_vfork, ready = true, set_ok = true;
static bool expect_access = true, nest;
static unsigned gets, sets, depth, entered, left, exits, callbacks[4];
static int expected_event, runtime_answer = 1;
static uint32_t expected_leaf, expected_subleaf;
static register_orig_t expected_exit_owner;
static char diagnostic[256];
static const uint64_t callback_tsc = UINT64_C(0x123456789abcdef0);
static const uint32_t callback_aux = UINT32_C(0x76543210);
static bool same_orig(register_orig_t a, register_orig_t b) {
  return a.value == b.value && a.image == b.image && a.pid == b.pid &&
      a.tid == b.tid && a.kind == b.kind;
}
static void* dr_get_current_drcontext(void) { return current_context; }
static process_id_t dr_get_process_id(void) { return current_pid; }
static thread_id_t dr_get_thread_id(void* context) { (void)context; return current_tid; }
static void* drmgr_get_tls_field(void* context, int index) {
  (void)index;
  return context == current_context ? &state : NULL;
}
static bool dr_get_mcontext(void* context, dr_mcontext_t* out) {
  assert(context == current_context);
  ++gets;
  unsigned flags = out->flags;
  memcpy(out, &machine, sizeof(machine));
  out->flags = flags;
  return true;
}
static bool dr_set_mcontext(void* context, dr_mcontext_t* in) {
  assert(context == current_context);
  ++sets;
  if (!set_ok) return false;
  if (in->flags & DR_MC_INTEGER) {
    machine.r15 = in->r15; machine.r14 = in->r14; machine.r13 = in->r13;
    machine.r12 = in->r12; machine.xbp = in->xbp; machine.xbx = in->xbx;
    machine.r11 = in->r11; machine.r10 = in->r10; machine.r9 = in->r9;
    machine.r8 = in->r8; machine.xax = in->xax; machine.xcx = in->xcx;
    machine.xdx = in->xdx; machine.xsi = in->xsi; machine.xdi = in->xdi;
  }
  if (in->flags & DR_MC_CONTROL) {
    machine.xip = in->xip; machine.xsp = in->xsp; machine.xflags = in->xflags;
  }
  if (in->flags & 4)
    memcpy(machine.other_context, in->other_context, sizeof(machine.other_context));
  return true;
}
static void dr_fprintf(int channel, const char* format, ...) {
  assert(channel == diagnostic_file);
  va_list args;
  va_start(args, format);
  vsnprintf(diagnostic, sizeof(diagnostic), format, args);
  va_end(args);
}
static bool has_copied_runtime(void) { return copied; }
static bool runtime_uses_external_global(void) { return external_global; }
static bool is_copied_vfork_process(void) { return copied_vfork; }
static void ensure_runtime_background(void) {}
static bool wait_for_runtime_ready(bool finished) { assert(!finished); return ready; }
static void evidence_callback_enter(void) { ++depth; ++entered; }
static void evidence_callback_leave(void) { assert(depth != 0); --depth; ++left; }
static void exit_runtime_tree(int status) {
  assert(status == 101 && depth == 0);
  assert(same_orig(state.register_orig, expected_exit_owner));
  ++exits;
}
static int64_t invoke_syscall(uintptr_t context, int64_t number,
    const uint64_t* args, uint32_t purpose) {
  (void)context; (void)number; (void)args; (void)purpose;
  assert(false); // These controls do not fabricate an injected syscall result.
  return 0;
}
static void reverie_dbt_emit(const char* bytes, size_t len) {
  (void)bytes; (void)len;
  assert(false);
}
static int32_t reverie_dbt_runtime_rdtsc(void*, prototype_counters_t*,
    int32_t, int32_t, uint64_t, int32_t, invoker_t, reader_t, writer_t,
    emitter_t, uint64_t*, uint32_t*);
static int32_t reverie_dbt_runtime_cpuid(void*, prototype_counters_t*,
    int32_t, int32_t, uint64_t, uint32_t, uint32_t, invoker_t, reader_t,
    writer_t, emitter_t, uint32_t*);
"#,
    );
    for signature in [
        "static void clear_register_orig(",
        "static void bind_register_orig(",
        "static register_orig_t enter_instruction_register_orig(",
        "static bool register_orig_available(",
        "static int32_t refuse_register_orig(",
        "static int32_t read_registers(",
        "static int32_t write_registers(",
        "static uint64_t next_virtual_tsc(",
        "static uint64_t guest_tsc(",
        "static void emulate_cpuid(",
        "static void emulate_rdtsc(",
        "static void emulate_rdtscp(",
    ] {
        source.push_str(native_function(signature));
        source.push('\n');
    }
    source.push_str(
        r#"
static void assert_unavailable(reader_t reader, writer_t writer) {
  struct user_regs_struct observed, untouched, requested = {0};
  memset(&observed, 0xa5, sizeof(observed));
  untouched = observed;
  requested.rax = 999;
  requested.orig_rax = 888;
  dr_mcontext_t before;
  memcpy(&before, &machine, sizeof(machine));
  register_orig_t owner = state.register_orig;
  unsigned old_gets = gets, old_sets = sets;
  assert(reader((uintptr_t)current_context, &observed) == 0);
  assert(strcmp(diagnostic,
      "reverie-dbt: register-view-orig-rax-unavailable (read)\n") == 0);
  assert(memcmp(&observed, &untouched, sizeof(observed)) == 0);
  assert(writer((uintptr_t)current_context, &requested) == 0);
  assert(strcmp(diagnostic,
      "reverie-dbt: register-view-orig-rax-unavailable (write)\n") == 0);
  assert(gets == old_gets && sets == old_sets);
  assert(memcmp(&machine, &before, sizeof(machine)) == 0);
  assert(same_orig(state.register_orig, owner));
}
static void observe_callback(void* context, prototype_counters_t* counters,
    int32_t tid, int32_t pid, uint64_t branches, int event,
    invoker_t invoke, reader_t reader, writer_t writer, emitter_t emit) {
  assert(context == current_context && counters == &state);
  assert(tid == current_tid && pid == current_pid && branches == 19);
  assert(event == expected_event && depth != 0);
  assert(invoke == invoke_syscall && reader == read_registers &&
      writer == write_registers && emit == reverie_dbt_emit);
  ++callbacks[event];
  if (!expect_access) {
    assert_unavailable(reader, writer);
    return;
  }
  struct user_regs_struct before, requested, observed;
  assert(reader((uintptr_t)context, &before) == 1);
  assert(before.orig_rax == UINT64_MAX && before.rax == machine.xax);
  assert(before.rip == (uint64_t)machine.xip && before.rsp == machine.xsp);
  assert(state.register_orig.kind == REGISTER_ORIG_INSTRUCTION);

  // RAX-only writes do not alias orig_rax; all other physical fields survive.
  requested = before;
  requested.rax = 1515847937 + (uint64_t)event;
  dr_mcontext_t expected;
  memcpy(&expected, &machine, sizeof(machine));
  expected.xax = requested.rax;
  assert(writer((uintptr_t)context, &requested) == 1);
  assert(memcmp(&machine, &expected, sizeof(machine)) == 0);
  assert(reader((uintptr_t)context, &observed) == 1);
  assert(memcmp(&observed, &requested, sizeof(observed)) == 0);

  // This no-pending instruction hook permits an independent explicit orig
  // write/readback. It does not request a syscall or rewrite instruction outputs.
  requested.orig_rax = UINT64_C(0x123456780000003d);
  assert(writer((uintptr_t)context, &requested) == 1);
  assert(memcmp(&machine, &expected, sizeof(machine)) == 0);
  assert(reader((uintptr_t)context, &observed) == 1);
  assert(memcmp(&observed, &requested, sizeof(observed)) == 0);
  register_orig_t owner = state.register_orig;
  requested.orig_rax = 999;
  requested.rax = 888;
  set_ok = false;
  assert(writer((uintptr_t)context, &requested) == 0);
  set_ok = true;
  assert(memcmp(&machine, &expected, sizeof(machine)) == 0);
  assert(same_orig(state.register_orig, owner));

  // Current owner checks still apply inside a real callback invocation.
  ++current_pid; assert_unavailable(reader, writer); --current_pid;
  ++current_tid; assert_unavailable(reader, writer); --current_tid;
  atomic_fetch_add(&image_generation, 1);
  assert_unavailable(reader, writer);
  atomic_fetch_sub(&image_generation, 1);
  state.signal_token = 1; assert_unavailable(reader, writer); state.signal_token = 0;
  state.preempt_pending = 1; assert_unavailable(reader, writer); state.preempt_pending = 0;
  state.pending_thread_start = 1; assert_unavailable(reader, writer); state.pending_thread_start = 0;
  state.in_syscall_event = true; assert_unavailable(reader, writer); state.in_syscall_event = false;
  if (nest) {
    nest = false;
    int outer = expected_event;
    expected_event = 2;
    uint32_t aux;
    assert(guest_tsc(context, false, &aux) == callback_tsc);
    assert(aux == callback_aux && depth == 1);
    expected_event = outer;
    assert(same_orig(state.register_orig, owner));
  }
}
static int32_t reverie_dbt_runtime_rdtsc(void* context,
    prototype_counters_t* counters, int32_t tid, int32_t pid, uint64_t branches,
    int32_t with_aux, invoker_t invoke, reader_t reader, writer_t writer,
    emitter_t emit, uint64_t* tsc, uint32_t* aux) {
  assert(with_aux == 0 || with_aux == 1);
  observe_callback(context, counters, tid, pid, branches, with_aux ? 3 : 2,
      invoke, reader, writer, emit);
  *tsc = callback_tsc;
  *aux = callback_aux;
  return runtime_answer;
}
static int32_t reverie_dbt_runtime_cpuid(void* context,
    prototype_counters_t* counters, int32_t tid, int32_t pid, uint64_t branches,
    uint32_t leaf, uint32_t subleaf, invoker_t invoke, reader_t reader,
    writer_t writer, emitter_t emit, uint32_t* result) {
  assert(leaf == expected_leaf && subleaf == expected_subleaf);
  observe_callback(context, counters, tid, pid, branches, 1,
      invoke, reader, writer, emit);
  result[0] = 11; result[1] = 22; result[2] = 33; result[3] = 44;
  return runtime_answer;
}
static void reset(void) {
  memset(&state, 0, sizeof(state));
  memset(&machine, 0x3c, sizeof(machine));
  machine.size = sizeof(machine); machine.flags = DR_MC_ALL;
  machine.xax = 7; machine.xcx = 8; machine.xip = (app_pc)0x400100;
  machine.xsp = 0x700000; machine.xflags = 0x246;
  current_pid = current_tid = 100;
  copied_process_runtime_pid = 0;
  copied = external_global = copied_vfork = nest = false;
  ready = set_ok = expect_access = true;
  runtime_answer = 1;
  gets = sets = depth = entered = left = exits = 0;
  memset(callbacks, 0, sizeof(callbacks));
  diagnostic[0] = '\0';
  atomic_store(&virtual_tsc, 0);
  expected_exit_owner = state.register_orig;
}
static void call_cpuid(void) {
  expected_event = 1;
  expected_leaf = (uint32_t)machine.xax;
  expected_subleaf = (uint32_t)machine.xcx;
  emulate_cpuid();
}
static void assert_scope_closed(register_orig_t owner) {
  assert(depth == 0 && entered == left);
  assert(same_orig(state.register_orig, owner));
}
int main(void) {
  reset();
  dr_mcontext_t expected;
  memcpy(&expected, &machine, sizeof(machine));
  call_cpuid();
  expected.xax = 11; expected.xbx = 22; expected.xcx = 33; expected.xdx = 44;
  assert(memcmp(&machine, &expected, sizeof(machine)) == 0);
  assert(callbacks[1] == 1 && entered == 1 && exits == 0);
  assert_scope_closed(expected_exit_owner);
  assert_unavailable(read_registers, write_registers);
  puts("instruction callback CPUID: owned read/write and completion");

  reset(); memcpy(&expected, &machine, sizeof(machine)); expected_event = 2;
  emulate_rdtsc();
  expected.xax = (uint32_t)callback_tsc; expected.xdx = callback_tsc >> 32;
  assert(memcmp(&machine, &expected, sizeof(machine)) == 0);
  assert(callbacks[2] == 1 && entered == 1 && exits == 0);
  assert_scope_closed(expected_exit_owner);
  puts("instruction callback RDTSC: owned read/write and completion");

  reset(); memcpy(&expected, &machine, sizeof(machine)); expected_event = 3;
  emulate_rdtscp();
  expected.xax = (uint32_t)callback_tsc; expected.xdx = callback_tsc >> 32;
  expected.xcx = callback_aux;
  assert(memcmp(&machine, &expected, sizeof(machine)) == 0);
  assert(callbacks[3] == 1 && entered == 1 && exits == 0);
  assert_scope_closed(expected_exit_owner);
  puts("instruction callback RDTSCP: owned read/write and completion");

  // Model the marker published only after successful external-global rebase.
  // These are actual production callback bodies under controlled state, not a
  // live fork/rebase claim. An inherited image-start fact never becomes the
  // child's instruction view; UNKNOWN and retired current facts work too.
  for (int prior = 0; prior != 3; ++prior) {
    for (int event = 1; event != 4; ++event) {
      reset();
      if (prior == 1)
        bind_register_orig(&state, current_context, REGISTER_ORIG_IMAGE_START,
            SYS_execve);
      copied = external_global = true;
      current_pid = current_tid = 101;
      copied_process_runtime_pid = current_pid;
      if (prior == 2)
        bind_register_orig(&state, current_context, REGISTER_ORIG_SYSCALL,
            SYS_getpid);
      register_orig_t previous = state.register_orig;
      expected_exit_owner = previous;
      assert_unavailable(read_registers, write_registers);
      memcpy(&expected, &machine, sizeof(machine));
      bool nested_child = prior == 2 && event == 1;
      nest = nested_child;
      if (event == 1) {
        call_cpuid();
        expected.xax = 11; expected.xbx = 22; expected.xcx = 33; expected.xdx = 44;
      } else {
        expected_event = event;
        if (event == 2) emulate_rdtsc(); else emulate_rdtscp();
        expected.xax = (uint32_t)callback_tsc; expected.xdx = callback_tsc >> 32;
        if (event == 3) expected.xcx = callback_aux;
      }
      assert(memcmp(&machine, &expected, sizeof(machine)) == 0);
      assert(callbacks[event] == 1 && entered == (nested_child ? 2u : 1u));
      if (nested_child) assert(callbacks[2] == 1);
      assert(exits == 0);
      assert_scope_closed(previous);
      assert_unavailable(read_registers, write_registers);
    }
  }

  // Prior metadata can be UNKNOWN, a retired syscall, or an outer instruction
  // with an explicit Tool write. No prior valid origin is needed for entry.
  reset();
  bind_register_orig(&state, current_context, REGISTER_ORIG_SYSCALL, SYS_getpid);
  register_orig_t retired = state.register_orig;
  expected_exit_owner = retired;
  nest = true;
  call_cpuid();
  assert(callbacks[1] == 1 && callbacks[2] == 1 && entered == 2);
  assert_scope_closed(retired);
  assert_unavailable(read_registers, write_registers);
  for (int answer = -1; answer <= 1; ++answer) {
    reset(); runtime_answer = answer; expected_event = 2;
    uint32_t aux = 999;
    uint64_t tsc = guest_tsc(current_context, false, &aux);
    assert(tsc == (answer == 1 ? callback_tsc : answer == 0 ? VIRTUAL_TSC_STRIDE : 0));
    assert(aux == (answer == 1 ? callback_aux : 0));
    assert(exits == (answer < 0 ? 1u : 0u) && callbacks[2] == 1);
    assert_scope_closed(expected_exit_owner);
    reset(); runtime_answer = answer;
    call_cpuid();
    assert(exits == (answer == 1 ? 0u : 1u) && callbacks[1] == 1);
    assert_scope_closed(expected_exit_owner);
  }
  reset(); ready = false;
  call_cpuid();
  uint32_t aux = 999;
  assert(guest_tsc(current_context, true, &aux) == 0 && aux == 0);
  assert(entered == 0 && exits == 0);
  assert_scope_closed(expected_exit_owner);
  reset(); copied = true;
  call_cpuid();
  assert(exits == 1 && entered == 0);
  assert(strstr(diagnostic, "refusing cpuid in a copied child") != NULL);
  assert(guest_tsc(current_context, false, &aux) == VIRTUAL_TSC_STRIDE);
  assert(aux == 0 && entered == 0);
  assert_scope_closed(expected_exit_owner);

  // A matching PID is not enough outside the supported rebase lifecycle.
  // Both the owner helper and physical callback routing retain their refusals.
  for (int vfork = 0; vfork != 2; ++vfork) {
    reset(); copied = true;
    external_global = copied_vfork = vfork;
    current_pid = current_tid = 101;
    copied_process_runtime_pid = current_pid;
    register_orig_t previous = enter_instruction_register_orig(&state, current_context);
    assert_unavailable(read_registers, write_registers);
    state.register_orig = previous;
    call_cpuid();
    assert(exits == 1 && entered == 0 && callbacks[1] == 0);
    assert(strstr(diagnostic, "refusing cpuid in a copied child") != NULL);
    assert(guest_tsc(current_context, true, &aux) == VIRTUAL_TSC_STRIDE);
    assert(aux == 0 && entered == 0 && callbacks[3] == 0);
    assert_scope_closed(previous);
  }
  puts("instruction callback scopes: nested and returned branches restored");

  // Enter the actual runtime callback while each disallowed context is active.
  // This tests controlled state, not live delayed/nested-signal provenance.
  for (int refused = 0; refused != 6; ++refused) {
    reset(); expect_access = false;
    switch (refused) {
      case 0: state.signal_token = 1; break;
      case 1: state.preempt_pending = 1; break;
      case 2: state.pending_thread_start = 1; break;
      case 3:
        state.in_syscall_event = true;
        bind_register_orig(&state, current_context, REGISTER_ORIG_SYSCALL, SYS_getpid);
        break;
      case 4: copied = external_global = true; break;
      case 5:
        copied = external_global = true;
        copied_process_runtime_pid = current_pid;
        ++current_pid; ++current_tid; // A nested child must rebase again.
        break;
    }
    register_orig_t before = state.register_orig;
    call_cpuid();
    assert(callbacks[1] == 1);
    assert_scope_closed(before);
    expected_event = 3;
    assert(guest_tsc(current_context, true, &aux) == callback_tsc);
    assert(callbacks[3] == 1);
    assert_scope_closed(before);
  }
  for (int private_yield = 0; private_yield != 2; ++private_yield) {
    reset();
    state.in_syscall_event = true;
    state.preempt_pending = private_yield;
    bind_register_orig(&state, current_context,
        private_yield ? REGISTER_ORIG_PREEMPT_SYSCALL : REGISTER_ORIG_SYSCALL,
        private_yield ? SYS_sched_yield : SYS_getpid);
    struct user_regs_struct requested;
    assert(read_registers((uintptr_t)current_context, &requested) == 1);
    requested.orig_rax = SYS_getppid; requested.rax = 999;
    dr_mcontext_t before;
    memcpy(&before, &machine, sizeof(machine));
    register_orig_t owner = state.register_orig;
    unsigned old_gets = gets, old_sets = sets;
    assert(write_registers((uintptr_t)current_context, &requested) == 0);
    assert(strcmp(diagnostic,
        "reverie-dbt: register-view-orig-rax-write-unsupported\n") == 0);
    assert(gets == old_gets && sets == old_sets);
    assert(memcmp(&machine, &before, sizeof(machine)) == 0);
    assert(same_orig(state.register_orig, owner));
  }
  puts("instruction callback refusals: unknown and pending writes preserved");
  return 0;
}
"#,
    );
    let directory = tempfile::tempdir().expect("native instruction-view control directory");
    let input = directory.path().join("instruction-view-control.c");
    let output = directory.path().join("instruction-view-control");
    std::fs::write(&input, source.as_bytes()).expect("write native instruction-view control");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let mut command = Command::new(&compiler);
    command
        .args(["-std=gnu11", "-Wall", "-Werror", "-O0"])
        .arg(&input)
        .arg("-o")
        .arg(&output);
    eprintln!("native instruction-view control compiler={command:?}");
    let compiled = command
        .output()
        .expect("compile native instruction-view control");
    eprintln!(
        "native instruction-view control compile status={:?} stdout={:?} stderr={:?}",
        compiled.status.code(),
        compiled.stdout,
        compiled.stderr
    );
    assert!(
        compiled.status.success(),
        "native instruction-view control compile failed"
    );
    let bytes = std::fs::read(&output).expect("read native instruction-view control image");
    eprintln!(
        "native instruction-view control source_sha256={:x} image_sha256={:x} image_bytes={}",
        sha2::Sha256::digest(source.as_bytes()),
        sha2::Sha256::digest(&bytes),
        bytes.len()
    );
    let result = Command::new(&output)
        .output()
        .expect("run native instruction-view control");
    eprintln!(
        "native instruction-view control status={:?} stdout={:?} stderr={:?}",
        result.status.code(),
        result.stdout,
        result.stderr
    );
    assert!(
        result.status.success(),
        "native instruction-view control failed"
    );
    assert_eq!(result.stdout, b"instruction callback CPUID: owned read/write and completion\ninstruction callback RDTSC: owned read/write and completion\ninstruction callback RDTSCP: owned read/write and completion\ninstruction callback scopes: nested and returned branches restored\ninstruction callback refusals: unknown and pending writes preserved\n");
    assert!(result.stderr.is_empty());
}

#[test]
fn native_initial_stack_fact_capture_and_layout() {
    use std::process::Command;

    use reverie_dbt::caller_abi::InitialStackFact;
    use sha2::Digest;

    assert_eq!(size_of::<InitialStackFact>(), 56);
    assert_eq!(align_of::<InitialStackFact>(), 8);
    c_layout(
        "initial_stack_fact_t",
        size_of::<InitialStackFact>(),
        &[
            ("size", offset_of!(InitialStackFact, size)),
            ("version", offset_of!(InitialStackFact, version)),
            ("kind", offset_of!(InitialStackFact, kind)),
            ("reserved", offset_of!(InitialStackFact, reserved)),
            ("context", offset_of!(InitialStackFact, context)),
            ("pid", offset_of!(InitialStackFact, pid)),
            ("tid", offset_of!(InitialStackFact, tid)),
            ("image", offset_of!(InitialStackFact, image)),
            ("pc", offset_of!(InitialStackFact, pc)),
            ("rsp", offset_of!(InitialStackFact, rsp)),
        ],
    );
    // Actual production capture, admission forwarding and live-owner predicate;
    // DR and Rust callback implementations are controlled, not live DR proof.
    let mut source = String::from(
        r#"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
typedef unsigned char* app_pc;
#define DR_MC_INTEGER 1
#define DR_MC_CONTROL 2
typedef struct { size_t size; unsigned flags; uint64_t xsp; } dr_mcontext_t;
"#,
    );
    source.push_str(between(
        NATIVE,
        "/* Private versioned caller admission record, independent of callback ABI16. */",
        "typedef enum {\n  REGISTER_ORIG_UNKNOWN,",
    ));
    source.push_str(r#"
typedef struct {
  uintptr_t caller_context;
  uint64_t caller_image;
  int32_t kernel_pid, kernel_ppid, kernel_tid, pending_birth_token;
  uint64_t pending_thread_clone, pending_process_clone_result, pending_thread_start;
  bool caller_admitted, in_syscall_event;
  uint64_t signal_token, preempt_pending, register_orig_sentinel;
  bool initial_register_view_pending;
  bool initial_stack_pending, initial_stack_attempted;
  initial_stack_fact_t initial_stack_fact;
} prototype_counters_t;
static prototype_counters_t state;
static void* current_context = (void*)0x1234;
static int current_pid = 100, current_tid = 100, parent_pid = 10;
static int thread_state_index;
static int runtime_owner_pid = 100;
static struct { int root_pid; } task = {100}, *task_state = &task;
static struct { uint64_t image_generation; } runtime_image_descriptor = {17};
static _Atomic uint64_t image_generation = 17, branch_count = 23;
static bool copied, caller = true, read_ok = true, tls_ok = true;
static uint64_t app_rsp = 0x700000;
static unsigned reads, forwards;
static initial_stack_fact_t forwarded;
static void* dr_get_current_drcontext(void) { return current_context; }
static int dr_get_process_id(void) { return current_pid; }
static int dr_get_thread_id(void* context) { assert(context == current_context); return current_tid; }
static int dr_get_parent_id(void) { return parent_pid; }
static bool has_copied_runtime(void) { return copied; }
static bool caller_mode(void) { return caller; }
static void* drmgr_get_tls_field(void* context, int index) {
  assert(context == current_context && index == thread_state_index);
  return tls_ok ? &state : NULL;
}
static bool dr_get_mcontext(void* context, dr_mcontext_t* out) {
  assert(context == current_context);
  assert(out->size == sizeof(*out) && out->flags == (DR_MC_INTEGER | DR_MC_CONTROL));
  ++reads;
  if (!read_ok) return false;
  out->xsp = app_rsp;
  return true;
}
static int in_tree_parent_pid(void) { return -1; }
typedef int (*test_callback_t)(void);
static int invoke_syscall(void) { return 0; }
static int read_registers(void) { return 0; }
static int write_registers(void) { return 0; }
static int32_t reverie_dbt_runtime_caller_thread_init_v1(
    prototype_counters_t* counters, void* context, int32_t tid, int32_t pid,
    int32_t ppid, uint64_t branches, int32_t defer,
    test_callback_t invoke, test_callback_t read, test_callback_t write,
    const initial_stack_fact_t* fact) {
  assert(counters == &state && context == current_context);
  assert(tid == current_tid && pid == current_pid && ppid == -1);
  assert(branches == 23 && defer == 0);
  assert(invoke == invoke_syscall && read == read_registers && write == write_registers);
  assert(fact == &state.initial_stack_fact && state.initial_stack_attempted);
  assert(fact->size == 56 && fact->version == 1);
  forwarded = *fact;
  ++forwards;
  return 7; /* controlled readiness retry, not actual Tool execution */
}
"#);
    source.push_str(native_function("static bool caller_live_context("));
    source.push_str(native_function("static void capture_initial_stack_fact("));
    source.push_str(native_function(
        "static int32_t caller_thread_init_with_stack(",
    ));
    source.push_str(
        r#"
static void reset(void) {
  memset(&state, 0, sizeof(state));
  current_pid = current_tid = runtime_owner_pid = task.root_pid = 100;
  parent_pid = 10;
  runtime_image_descriptor.image_generation = 17;
  atomic_store(&image_generation, 17);
  caller = read_ok = tls_ok = true;
  copied = false;
  reads = forwards = 0;
  app_rsp = 0x700000;
  state.caller_context = (uintptr_t)current_context;
  state.caller_image = 17;
  state.kernel_pid = state.kernel_tid = 100;
  state.kernel_ppid = 10;
  state.initial_stack_pending = state.initial_register_view_pending = true;
  state.register_orig_sentinel = 0xdeadbeef;
}
static void check_old_fields(const prototype_counters_t* before) {
  assert(memcmp(before, &state,
      offsetof(prototype_counters_t, initial_stack_pending)) == 0);
}
int main(void) {
  reset();
  prototype_counters_t before;
  memcpy(&before, &state, sizeof(state));
  capture_initial_stack_fact(current_context, &state, (app_pc)0x401000);
  check_old_fields(&before);
  assert(reads == 1 && state.initial_stack_attempted && !state.initial_stack_pending);
  initial_stack_fact_t fact = state.initial_stack_fact;
  assert(fact.kind == 1 && fact.reserved == 0 && fact.context == (uintptr_t)current_context);
  assert(fact.pid == 100 && fact.tid == 100 && fact.image == 17);
  assert(fact.pc == 0x401000 && fact.rsp == 0x700000);
  assert(caller_thread_init_with_stack(&state, current_context) == 7);
  assert(memcmp(&forwarded, &fact, sizeof(fact)) == 0);
  app_rsp = 0x710000;
  capture_initial_stack_fact(current_context, &state, (app_pc)0x402000);
  assert(reads == 1 && memcmp(&state.initial_stack_fact, &fact, sizeof(fact)) == 0);
  assert(caller_thread_init_with_stack(&state, current_context) == 7);
  assert(forwards == 2 && memcmp(&forwarded, &fact, sizeof(fact)) == 0);
  reset(); app_rsp = 0;
  capture_initial_stack_fact(current_context, &state, (app_pc)0x401000);
  assert(state.initial_stack_fact.kind == 1 && state.initial_stack_fact.rsp == 0);
  puts("native initial-stack first-block and immutable retry passed");
  for (unsigned scenario = 0; scenario < 17; ++scenario) {
    reset();
    app_pc pc = (app_pc)0x401000;
    switch (scenario) {
      case 0: pc = NULL; break; /* actual late fallback argument */
      case 1: state.initial_stack_pending = false; break;
      case 2: read_ok = false; break;
      case 3: ++state.caller_context; break;
      case 4: ++state.kernel_pid; break;
      case 5: ++current_tid; break;
      case 6: ++state.caller_image; break;
      case 7: atomic_store(&image_generation, 18); break;
      case 8: copied = true; break; /* copied/vfork forbidden owner */
      case 9: copied = true; current_pid = current_tid = 102; break; /* nested copy */
      case 10: state.in_syscall_event = true; break;
      case 11: state.signal_token = 1; break;
      case 12: state.preempt_pending = 1; break;
      case 13: state.pending_birth_token = 1; break;
      case 14: tls_ok = false; break;
      case 15: caller = false; break;
      case 16: ++state.kernel_tid; break;
    }
    memcpy(&before, &state, sizeof(state));
    capture_initial_stack_fact(current_context, &state, pc);
    check_old_fields(&before);
    assert(state.initial_stack_attempted && !state.initial_stack_pending);
    assert(state.initial_stack_fact.size == 56 && state.initial_stack_fact.version == 1);
    assert(state.initial_stack_fact.kind == 0 && state.initial_stack_fact.rsp == 0);
    assert(reads == (scenario == 2 ? 1U : 0U));
    fact = state.initial_stack_fact;
    // A later valid-looking callback cannot upgrade the consumed opportunity.
    state.caller_context = (uintptr_t)current_context;
    state.caller_image = 17;
    state.kernel_pid = state.kernel_tid = current_pid = current_tid = 100;
    atomic_store(&image_generation, 17);
    copied = false; caller = read_ok = tls_ok = true;
    state.in_syscall_event = false; state.signal_token = state.preempt_pending = 0;
    state.pending_birth_token = 0;
    capture_initial_stack_fact(current_context, &state, (app_pc)0x401000);
    assert(memcmp(&fact, &state.initial_stack_fact, sizeof(fact)) == 0);
  }
  // An inherited observed record cannot create a valid copied caller owner.
  reset(); capture_initial_stack_fact(current_context, &state, (app_pc)0x401000);
  fact = state.initial_stack_fact;
  copied = true; current_pid = current_tid = 101;
  assert(!caller_live_context(current_context, &state, false));
  capture_initial_stack_fact(current_context, &state, (app_pc)0x401000);
  assert(memcmp(&fact, &state.initial_stack_fact, sizeof(fact)) == 0);
  puts("native initial-stack late missing wrong-owner copied controls passed");
  puts("native initial-stack versioned admission forwarding passed");
  return 0;
}
"#,
    );
    let directory = tempfile::tempdir().expect("native initial-stack control directory");
    let input = directory.path().join("initial-stack-control.c");
    let output = directory.path().join("initial-stack-control");
    std::fs::write(&input, &source).unwrap();
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let mut command = Command::new(&compiler);
    command
        .args(["-std=gnu11", "-Wall", "-Werror", "-O0"])
        .arg(&input)
        .arg("-o")
        .arg(&output);
    eprintln!("native initial-stack control compiler={command:?}");
    let compiled = command
        .output()
        .expect("compile native initial-stack control");
    eprintln!(
        "native initial-stack control compile status={:?} stdout={:?} stderr={:?}",
        compiled.status.code(),
        compiled.stdout,
        compiled.stderr
    );
    assert!(
        compiled.status.success(),
        "native initial-stack control compile failed"
    );
    let bytes = std::fs::read(&output).unwrap();
    eprintln!(
        "native initial-stack control source_sha256={:x} image_sha256={:x} image_bytes={}",
        sha2::Sha256::digest(source.as_bytes()),
        sha2::Sha256::digest(&bytes),
        bytes.len()
    );
    let result = Command::new(&output)
        .output()
        .expect("run native initial-stack control");
    eprintln!(
        "native initial-stack control status={:?} stdout={:?} stderr={:?}",
        result.status.code(),
        result.stdout,
        result.stderr
    );
    assert!(
        result.status.success(),
        "native initial-stack control failed"
    );
    assert_eq!(result.stdout, b"native initial-stack first-block and immutable retry passed\nnative initial-stack late missing wrong-owner copied controls passed\nnative initial-stack versioned admission forwarding passed\n");
    assert!(result.stderr.is_empty());

    // Keep every old first-occurrence marker bound to its original statement.
    let gate = native_function("static void start_pending_thread(");
    ordered(
        gate,
        &[
            "capture_initial_stack_fact(dr_get_current_drcontext(), counters, pc);",
            "ensure_runtime_background();",
            "counters->admission_pc = pc;",
            "initial_register_view_pending = false;",
            "pc != NULL",
            "REGISTER_ORIG_IMAGE_START, SYS_execve",
            "admit_pending_thread();",
        ],
    );
    let admission = native_function("static void try_start_pending_thread(");
    ordered(
        admission,
        &[
            "caller_live_context(drcontext, counters, false)",
            "if (!runtime_ready_for_image())",
            "caller_unfiltered(drcontext)",
            "#ifdef REVERIE_DBT_CALLER_INITIAL_STACK_V1",
            "init_result = caller_thread_init_with_stack(counters, drcontext);",
            "#else",
            "init_result = reverie_dbt_runtime_thread_init(",
            "if (init_result > 0)",
        ],
    );
    ordered(
        NATIVE,
        &[
            "#ifdef REVERIE_DBT_CALLER_INPUT_IDENTITY",
            "#define REVERIE_DBT_CALLER_INITIAL_STACK_V1 1",
            "#ifndef REVERIE_DBT_CALLER_INPUT_IDENTITY",
        ],
    );
    let init = native_function("static void thread_init(");
    ordered(
        init,
        &[
            "bool pending_image_start =",
            "host_tid == dr_get_process_id() && !has_copied_runtime()",
            "counters->initial_stack_pending = pending_image_start &&",
            "pending_child == 0 && dr_get_process_id() == runtime_owner_pid;",
            "evidence_emit_image_initialization();",
            "int32_t init_result = reverie_dbt_runtime_thread_init(",
        ],
    );
}
