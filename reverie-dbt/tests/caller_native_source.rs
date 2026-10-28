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
