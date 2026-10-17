/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Static facts about how a backend runs a guest.
//!
//! A tool that models a guest (for example a deterministic scheduler) sometimes
//! has to act differently depending on what the backend underneath it does: is a
//! guest thread a host task that a host signal can reach, does the kernel finish
//! robust-list cleanup before the tool hears about a thread exit, does the tool
//! share the guest's descriptor table? [`BackendCapabilities`] answers those
//! questions, one field per fact, so the tool reads the fact it needs instead of
//! asking which backend it is running on.
//!
//! # Scope: one answer per run
//!
//! Every field is a property of the backend for the whole run. One backend runs
//! every guest thread of a run, none of these facts change while it runs, and a
//! tool that runs inside the guest receives its configuration (including this
//! struct) once, before the first guest callback. Facts that depend on a
//! particular thread or a particular request (for example where a parked signal
//! may be observed) are not here; they stay queries on [`Guest`](crate::Guest).
//!
//! # Where the values live
//!
//! The per-backend values are associated constants of this type, in the core
//! crate, rather than only in each backend crate. A host such as Hermit selects
//! a backend at run time and must configure its tool for backends it was not
//! built to link (some backends are optional, heavy builds). Each backend crate
//! still answers for itself: [`Backend::capabilities`](crate::Backend::capabilities)
//! for [`Backend`](crate::Backend) implementors, and an inherent
//! `capabilities()` on backends that do not implement that trait. Those return
//! the matching constant. The tests below pin every constant field by field.
//!
//! # Adding a field
//!
//! The struct is `#[non_exhaustive]`, so code outside this crate cannot build
//! one field by field: it starts from a constant. A new field must be given a
//! value in every constant below; there is no default to fall back on.

use serde::Deserialize;
use serde::Serialize;

/// Static, per-run facts about a backend that a tool may need to model the
/// guest correctly. The documentation at the top of
/// `reverie/src/capabilities.rs` gives their scope and ownership.
///
/// Field names describe what the backend does, never which backend it is.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// The tool runs inside the guest process and shares its descriptor table,
    /// so it can describe a guest descriptor it has not seen opened (an
    /// inherited stdio descriptor, or one passed through a descriptor-passing
    /// call) by inspecting it directly.
    pub tool_shares_guest_descriptor_table: bool,

    /// After a successful `execve`, the backend starts the tool afresh in the
    /// new image, and the tool rediscovers the guest's live descriptors from
    /// the process rather than keeping its own model. Descriptor state that only
    /// the tool's model holds (for example a pipe the tool made physically
    /// nonblocking while the guest still sees it as blocking) must therefore be
    /// handed across the exec explicitly.
    pub rediscovers_descriptors_after_exec: bool,

    /// Scheduler turns for I/O on a tool-managed internal pipe (a pipe that is
    /// physically nonblocking while the guest sees it as blocking) include a
    /// descriptor-discovery turn whose count depends on host timing. The tool
    /// marks those turns so their count is not treated as guest-visible
    /// progress.
    pub internal_pipe_turns_are_host_timed: bool,

    /// A zero-timeout poll by a task that owns a loopback connection must
    /// yield its turn to another runnable task first; without that yield a
    /// poller can starve the loopback peer it is waiting for.
    pub loopback_pollers_yield_to_peers: bool,

    /// Guest clock reads may bypass the backend's time virtualization, so an
    /// absolute futex deadline may have been computed from the host clock
    /// rather than from the tool's logical clock.
    pub guest_clock_reads_bypass_backend: bool,

    /// The backend already returns deterministic values in every register that
    /// a `syscall` instruction clobbers, so the tool must not write the whole
    /// register set back after a syscall.
    pub virtualizes_syscall_clobbers: bool,

    /// A pending tool request from a thread that the tool has logically killed
    /// is not resolved by the kernel's exit-group teardown, so the tool must
    /// cancel it explicitly.
    pub needs_killed_thread_rpc_cancellation: bool,

    /// The backend reports a process's final physical exit separately, after
    /// the tool's logical cleanup for that process, so the tool can order
    /// guest-visible child-exit events after the kernel publishes them.
    pub reports_physical_process_exits: bool,

    /// A process leaves the host some time after its scheduler-granted exit,
    /// outside any turn, and the backend reports each such exit, once the
    /// kernel has published it to the parent, through the tool's
    /// physical-exit completion. The tool must not select another turn while
    /// such an exit is pending, or a peer could observe the exiting process's
    /// descriptors still open.
    pub process_exits_complete_asynchronously: bool,

    /// A signal interrupts a blocking syscall that the backend runs outside the
    /// tool's scheduler, and the interrupted thread's continuation request
    /// arrives only afterwards. The tool must wait for that continuation
    /// instead of treating the thread as parked inside its own scheduler.
    pub signal_interrupts_external_syscalls: bool,

    /// The backend reports every process child through the tool's
    /// child-registration callbacks, so the tool's own record of children is
    /// complete. When this is false the tool must not conclude ECHILD from an
    /// empty record.
    pub tracks_process_children: bool,

    /// The kernel completes a thread's robust-futex list cleanup before the
    /// backend delivers that thread's exit to the tool, so the tool can leave
    /// the owner-word update to the kernel.
    pub runs_exit_robust_list: bool,

    /// The backend cannot execute a process-directed signal syscall with the
    /// tool's process identifier, so the tool must translate an unambiguous
    /// process target to a specific thread.
    pub requires_thread_directed_process_signals: bool,

    /// The backend can interrupt a pipe write that the tool's scheduler has
    /// parked when another task signals the writer, preserving Linux's signal
    /// mask, disposition and syscall-restart behavior.
    pub supports_parked_write_signal_interruption: bool,

    /// The backend starts a `CLONE_VFORK` child only after the parent's clone
    /// call has returned to the tool, so the child registers after the parent
    /// asks to continue. The tool must keep waiting for the late child rather
    /// than treat its absence as a failed clone.
    pub defers_vfork_child_registration: bool,

    /// The backend implements guest-visible `madvise` semantics, so the tool
    /// may forward an `madvise` call to it.
    pub supports_madvise: bool,

    /// The backend implements `MADV_DONTNEED` (private anonymous pages then
    /// read as zeros; shared contents survive), so the tool may forward that
    /// advice even when it may not forward the others (`supports_madvise`).
    pub supports_madv_dontneed: bool,

    /// The backend reports, through
    /// [`GlobalTool::on_backend_process_exited`](crate::GlobalTool::on_backend_process_exited),
    /// the moment the kernel publishes a guest child process's exit to its
    /// guest parent. Under ptrace that is when the tracer consumes the
    /// process leader's final wait status: the kernel notifies the real parent
    /// of a traced child only then. A tool can hold its schedule until the
    /// report, so the parent's exit notification is generated at a
    /// scheduler-chosen point.
    ///
    /// The report covers every ordinary, initialized process leader whose
    /// final status the tracer consumes, once each, including one killed
    /// before its exit was scheduled (it can arrive before the tool grants
    /// that exit). Processes the tool never registered or initialized (a fork
    /// child that dies during initialization, the root before it starts,
    /// unregistered children reaped at cleanup) are not reported; the tool
    /// never schedules an exit for them.
    pub reports_child_exit_publication: bool,

    /// The backend owns guest signal delivery: a host signal sent to a host
    /// task cannot reach a guest thread, and the backend offers a run-scoped
    /// process signal control (see
    /// [`BackendSignalControlMode`](crate::BackendSignalControlMode)) through
    /// which a tool publishes process signals. A tool that models real-time
    /// interval timers must publish their expiries through that control rather
    /// than by sending host signals.
    pub provides_process_signal_control: bool,

    /// The backend implements the child-wait syscalls (`wait4`, `waitid`)
    /// itself against its own process records, including the copy of the
    /// result to guest memory. A child can become waitable before the backend
    /// reports its final CPU time, and only terminal events (exits and the
    /// terminal subset of `WUNTRACED`) are waitable.
    pub emulates_child_waits: bool,

    /// While a guest installs a SIGALRM handler, the backend keeps the
    /// guest's SIGALRM action and signal mask virtual (signal phase 1): the
    /// physical action is the backend's own, the physical mask always blocks
    /// SIGALRM, and the tool owns the process's pending SIGALRM. A tool must
    /// then publish the disposition and the guest's SIGALRM blocked bit to
    /// its scheduler, and deliver pending SIGALRMs through the backend rather
    /// than by sending host signals. A backend reports this only when it can
    /// admit a handler at all; when it does not admit one in a given process,
    /// the guest's `rt_sigaction` fails and nothing is published.
    pub virtualizes_guest_sigalrm: bool,

    /// At a syscall stop the backend hands the kernel's signal delivery a
    /// restart errno (such as `ERESTARTNOHAND`), which the kernel turns into
    /// `EINTR` or a restart as Linux does, and it reports a thread's signal
    /// state in `/proc` (measured on ptrace,
    /// <https://github.com/rrnewton/hermit/issues/3146>). A tool may then let a
    /// guest signal end a blocked wait the way Linux ends it. Without it a
    /// restart errno could reach guest code, so a tool keeps such waits from
    /// being interrupted by signals.
    pub supports_blocked_wait_signal_interruption: bool,

    /// The backend arms a preemption timer and delivers its events, so a
    /// tool's time slice really preempts a thread that makes no syscall
    /// (<https://github.com/rrnewton/hermit/issues/4068>).
    pub delivers_preemption_timer_events: bool,

    /// Guest code can run while a tool handler is between two of its injected
    /// syscalls: the backend runs an accepted native guest signal handler
    /// inside the tool's handler, and passes that handler's syscalls to
    /// Linux. A tool must then not make two injected calls that need a
    /// descriptor number to stay unchanged between them.
    pub runs_guest_code_between_injections: bool,

    /// The tool runs inside each guest process, and before every native fork,
    /// process-copying clone or exec the backend's runtime performs for a
    /// guest, it promotes the open-file descriptions whose model must stay one
    /// copy to the tool's shared global state, and carries the promoted ones
    /// across exec as survivors. A tool may then keep such a description's
    /// model (a timerfd's virtual-time expirations, say) inside the guest:
    /// every process that shares the description reaches the same copy. A
    /// backend whose tool runs outside the guest shares one copy without
    /// promoting, and reports false.
    pub promotes_open_files_before_native_lifecycle: bool,
}

impl BackendCapabilities {
    /// `reverie-ptrace`: every guest thread is a host task stopped and resumed
    /// through ptrace, so the kernel does most of the work.
    pub const PTRACE: Self = Self {
        tool_shares_guest_descriptor_table: false,
        rediscovers_descriptors_after_exec: false,
        internal_pipe_turns_are_host_timed: false,
        loopback_pollers_yield_to_peers: false,
        guest_clock_reads_bypass_backend: false,
        virtualizes_syscall_clobbers: false,
        needs_killed_thread_rpc_cancellation: false,
        reports_physical_process_exits: false,
        process_exits_complete_asynchronously: false,
        signal_interrupts_external_syscalls: false,
        tracks_process_children: true,
        runs_exit_robust_list: true,
        requires_thread_directed_process_signals: false,
        supports_parked_write_signal_interruption: true,
        defers_vfork_child_registration: false,
        supports_madvise: true,
        supports_madv_dontneed: true,
        reports_child_exit_publication: true,
        provides_process_signal_control: false,
        emulates_child_waits: false,
        virtualizes_guest_sigalrm: false,
        supports_blocked_wait_signal_interruption: true,
        delivers_preemption_timer_events: true,
        runs_guest_code_between_injections: false,
        promotes_open_files_before_native_lifecycle: false,
    };

    /// `reverie-e9patch`: the guest is rewritten ahead of time and then run
    /// under the ptrace tracer, so its run-time facts are ptrace's.
    pub const E9PATCH: Self = Self::PTRACE;

    /// `reverie-liteinst` with its in-guest runtime: the tool runs in the
    /// guest, with no ptrace exit-group teardown behind it.
    pub const LITEINST_IN_GUEST: Self = Self {
        needs_killed_thread_rpc_cancellation: true,
        process_exits_complete_asynchronously: true,
        runs_exit_robust_list: false,
        supports_parked_write_signal_interruption: false,
        reports_child_exit_publication: false,
        virtualizes_guest_sigalrm: true,
        supports_blocked_wait_signal_interruption: false,
        delivers_preemption_timer_events: false,
        runs_guest_code_between_injections: true,
        ..Self::PTRACE
    };

    /// `reverie-sabre`: the tool runs inside the guest process as a SaBRe
    /// plugin, under a ptrace supervisor that reaps processes.
    pub const SABRE: Self = Self {
        tool_shares_guest_descriptor_table: true,
        rediscovers_descriptors_after_exec: true,
        internal_pipe_turns_are_host_timed: true,
        loopback_pollers_yield_to_peers: true,
        guest_clock_reads_bypass_backend: true,
        virtualizes_syscall_clobbers: true,
        needs_killed_thread_rpc_cancellation: true,
        reports_physical_process_exits: true,
        signal_interrupts_external_syscalls: true,
        runs_exit_robust_list: false,
        supports_parked_write_signal_interruption: false,
        reports_child_exit_publication: false,
        supports_blocked_wait_signal_interruption: false,
        delivers_preemption_timer_events: false,
        runs_guest_code_between_injections: true,
        ..Self::PTRACE
    };

    /// `reverie-dbt`: the guest runs under dynamic binary translation with the
    /// tool in the guest process.
    pub const DBT: Self = Self {
        tool_shares_guest_descriptor_table: true,
        rediscovers_descriptors_after_exec: true,
        needs_killed_thread_rpc_cancellation: true,
        tracks_process_children: false,
        runs_exit_robust_list: false,
        requires_thread_directed_process_signals: true,
        supports_parked_write_signal_interruption: false,
        reports_child_exit_publication: false,
        supports_blocked_wait_signal_interruption: false,
        delivers_preemption_timer_events: false,
        promotes_open_files_before_native_lifecycle: true,
        ..Self::PTRACE
    };

    /// `reverie-kvm`: guest threads run in a virtual machine that the backend
    /// drives, and the backend implements many syscalls itself.
    pub const KVM: Self = Self {
        needs_killed_thread_rpc_cancellation: true,
        runs_exit_robust_list: false,
        defers_vfork_child_registration: true,
        supports_madvise: false,
        provides_process_signal_control: true,
        emulates_child_waits: true,
        reports_child_exit_publication: false,
        supports_blocked_wait_signal_interruption: false,
        delivers_preemption_timer_events: false,
        ..Self::PTRACE
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field of `caps`, by name, so a test can compare a whole constant
    /// against a literal table. Serializing covers every field, including ones
    /// added later, and a new field makes every table below fail until it is
    /// given a value.
    fn table(caps: BackendCapabilities) -> serde_json::Value {
        serde_json::to_value(caps).unwrap()
    }

    fn ptrace_table() -> serde_json::Value {
        serde_json::json!({
            "tool_shares_guest_descriptor_table": false,
            "rediscovers_descriptors_after_exec": false,
            "internal_pipe_turns_are_host_timed": false,
            "loopback_pollers_yield_to_peers": false,
            "guest_clock_reads_bypass_backend": false,
            "virtualizes_syscall_clobbers": false,
            "needs_killed_thread_rpc_cancellation": false,
            "reports_physical_process_exits": false,
            "process_exits_complete_asynchronously": false,
            "signal_interrupts_external_syscalls": false,
            "tracks_process_children": true,
            "runs_exit_robust_list": true,
            "requires_thread_directed_process_signals": false,
            "supports_parked_write_signal_interruption": true,
            "defers_vfork_child_registration": false,
            "supports_madvise": true,
            "supports_madv_dontneed": true,
            "reports_child_exit_publication": true,
            "provides_process_signal_control": false,
            "emulates_child_waits": false,
            "virtualizes_guest_sigalrm": false,
            "supports_blocked_wait_signal_interruption": true,
            "delivers_preemption_timer_events": true,
            "runs_guest_code_between_injections": false,
            "promotes_open_files_before_native_lifecycle": false,
        })
    }

    /// The ptrace table with `changes` applied; every key in `changes` must
    /// already exist and must actually change, so a table cannot list a no-op.
    fn ptrace_with(changes: serde_json::Value) -> serde_json::Value {
        let mut table = ptrace_table();
        for (key, value) in changes.as_object().unwrap() {
            let slot = table
                .get_mut(key)
                .unwrap_or_else(|| panic!("unknown field {key}"));
            assert_ne!(slot, value, "{key} does not differ from ptrace");
            *slot = value.clone();
        }
        table
    }

    #[test]
    fn ptrace_capabilities() {
        assert_eq!(table(BackendCapabilities::PTRACE), ptrace_table());
    }

    #[test]
    fn e9patch_capabilities_are_ptraces() {
        assert_eq!(table(BackendCapabilities::E9PATCH), ptrace_table());
    }

    #[test]
    fn liteinst_in_guest_capabilities() {
        assert_eq!(
            table(BackendCapabilities::LITEINST_IN_GUEST),
            ptrace_with(serde_json::json!({
                "needs_killed_thread_rpc_cancellation": true,
                "process_exits_complete_asynchronously": true,
                "runs_exit_robust_list": false,
                "supports_parked_write_signal_interruption": false,
                "reports_child_exit_publication": false,
                "virtualizes_guest_sigalrm": true,
                "supports_blocked_wait_signal_interruption": false,
                "delivers_preemption_timer_events": false,
                "runs_guest_code_between_injections": true,
            }))
        );
    }

    #[test]
    fn sabre_capabilities() {
        assert_eq!(
            table(BackendCapabilities::SABRE),
            ptrace_with(serde_json::json!({
                "tool_shares_guest_descriptor_table": true,
                "rediscovers_descriptors_after_exec": true,
                "internal_pipe_turns_are_host_timed": true,
                "loopback_pollers_yield_to_peers": true,
                "guest_clock_reads_bypass_backend": true,
                "virtualizes_syscall_clobbers": true,
                "needs_killed_thread_rpc_cancellation": true,
                "reports_physical_process_exits": true,
                "signal_interrupts_external_syscalls": true,
                "runs_exit_robust_list": false,
                "supports_parked_write_signal_interruption": false,
                "reports_child_exit_publication": false,
                "supports_blocked_wait_signal_interruption": false,
                "delivers_preemption_timer_events": false,
                "runs_guest_code_between_injections": true,
            }))
        );
    }

    #[test]
    fn dbt_capabilities() {
        assert_eq!(
            table(BackendCapabilities::DBT),
            ptrace_with(serde_json::json!({
                "tool_shares_guest_descriptor_table": true,
                "rediscovers_descriptors_after_exec": true,
                "needs_killed_thread_rpc_cancellation": true,
                "tracks_process_children": false,
                "runs_exit_robust_list": false,
                "requires_thread_directed_process_signals": true,
                "supports_parked_write_signal_interruption": false,
                "reports_child_exit_publication": false,
                "supports_blocked_wait_signal_interruption": false,
                "delivers_preemption_timer_events": false,
                "promotes_open_files_before_native_lifecycle": true,
            }))
        );
    }

    #[test]
    fn kvm_capabilities() {
        assert_eq!(
            table(BackendCapabilities::KVM),
            ptrace_with(serde_json::json!({
                "needs_killed_thread_rpc_cancellation": true,
                "runs_exit_robust_list": false,
                "defers_vfork_child_registration": true,
                "supports_madvise": false,
                "provides_process_signal_control": true,
                "emulates_child_waits": true,
                "reports_child_exit_publication": false,
                "supports_blocked_wait_signal_interruption": false,
                "delivers_preemption_timer_events": false,
            }))
        );
    }

    #[test]
    fn capabilities_round_trip_through_serde() {
        for caps in [
            BackendCapabilities::PTRACE,
            BackendCapabilities::E9PATCH,
            BackendCapabilities::LITEINST_IN_GUEST,
            BackendCapabilities::SABRE,
            BackendCapabilities::DBT,
            BackendCapabilities::KVM,
        ] {
            let json = serde_json::to_string(&caps).unwrap();
            assert_eq!(
                serde_json::from_str::<BackendCapabilities>(&json).unwrap(),
                caps
            );
        }
    }
}
