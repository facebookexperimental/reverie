// Authenticated library-test adapter. Bootstrap occurs only in the separately
// built ordinary-main launcher, never in a libtest worker or constructor.
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::native_exit_broker;
use crate::native_exit_broker::BrokerClient;

#[path = "broker_test_client.rs"]
mod broker_test_client;
#[path = "broker_test_protocol.rs"]
mod broker_test_protocol;

const LAUNCHER_ENV: &str = "REVERIE_KVM_TEST_BROKER_LAUNCHER";
const LAUNCHER_NAME: &str = concat!(env!("CARGO_PKG_NAME"), "-broker-test-launcher");

/// Some means the authenticated, selected child may enter the test body.
/// None means its isolated exact child completed successfully and was reaped.
/// Neither unavailable helpers nor empty libtest selections are successes.
pub(crate) fn selected_child(test: &str) -> Option<BrokerClient> {
    assert!(matches!(
        test,
        "executor::tests::terminal_cleanup_preserves_live_shared_table_and_does_not_wait_for_its_lock"
            | "executor::tests::terminal_cleanup_retires_socket_despite_fdinfo_observer_table_pin"
            | "terminal_cleanup::tests::dropped_waiter_keeps_native_wait_and_owned_service_alive"
            | "executor::tests::pdeath_abi_adoption_full_width_and_scalar_copyout_are_exact"
            | "executor::tests::pdeath_close_replacement_and_exec_cloexec_require_owned_completion_authority"
            | "executor::tests::pdeath_creator_thread_exit_publishes_process_si_user_once"
            | "executor::tests::pdeath_enrolled_raw_waits_refuse_before_effect_and_capture_remains_supported"
            | "executor::tests::pdeath_exec_uses_image_boundary_and_cleanup_never_impersonates_it"
            | "executor::tests::pdeath_finite_domain_rejects_unmodeled_io_and_shared_task_creation_before_effects"
            | "executor::tests::pdeath_ignored_generation_obeys_mask_observer_and_real_disposition_transitions"
            | "executor::tests::pdeath_late_clear_preserves_frozen_event_and_disposition_generation_discards_it"
            | "executor::tests::pdeath_mutable_timeout_readiness_refuses_before_original_or_injected_effects"
            | "executor::tests::pdeath_original_preflight_is_exact_uncached_and_preserves_zero_readiness"
            | "executor::tests::pdeath_pipe_chld_ignore_and_standard_coalescing_preserve_first_siginfo"
            | "executor::tests::pdeath_publication_failure_retains_exact_prefix_and_survives_sender_cleanup"
            | "executor::tests::pdeath_real_ignore_transition_invalidates_only_the_frozen_generation"
            | "executor::tests::pdeath_registration_reset_sticky_domain_and_exec_capability_gain"
            | "executor::tests::pdeath_reparented_sibling_death_repeats_but_reused_creator_tid_does_not"
            | "executor::tests::pdeath_retained_exec_preserves_permission_and_copyin_errors_after_admission"
            | "executor::tests::pdeath_retained_exec_rejects_missing_or_dynamic_authority_and_stale_callback_identity"
            | "executor::tests::pdeath_retained_exec_snapshot_survives_path_mutation_and_consumes_exact_conversion_once"
            | "executor::tests::pdeath_sendfile_checks_both_owned_endpoints_before_offset_or_output_changes"
            | "executor::tests::pdeath_signal_zero_covers_group_exec_empty_and_ignored_batches"
            | "executor::tests::pdeath_signal_zero_waits_for_publication_without_reviving_delivery"
            | "executor::tests::pdeath_stale_registration_get_and_frozen_receiver_do_not_target_reused_pid"
            | "executor::tests::pdeath_unenrolled_pointer_readiness_and_enrolled_scalar_zero_remain_supported"
            | "runtime::parent_death_tests::initial_exec_preflight_requires_original_context_and_keeps_enrollment_after_replacement"
            | "runtime::parent_death_tests::original_exec_callback_drop_revokes_staged_image_without_injection"
    ));
    if std::env::var(broker_test_protocol::CHILD_ENV).as_deref() == Ok(test) {
        broker_test_client::attach(test);
        return Some(broker_test_client::client());
    }
    let executable = std::env::current_exe().expect("library test executable");
    let launcher = launcher_path(&executable);
    let result_directory = ResultDirectory::new();
    let execution_log = result_directory.0.join("libtest.log");
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "30s"])
        .arg(launcher)
        .arg(executable)
        .args(["--exact", test, "--nocapture", "--logfile"])
        .arg(&execution_log)
        .env(broker_test_protocol::CHILD_ENV, test)
        .output()
        .expect("start ordinary-main broker test launcher");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{test}: status={:?} stdout={} stderr={}",
        output.status.code(),
        stdout,
        stderr
    );
    let executions = std::fs::read_to_string(&execution_log)
        .expect("selected libtest child must write its own execution record");
    assert_eq!(
        executions,
        format!("ok {test}\n"),
        "\n{test}: bounded child execution record mismatch; exit_code={:?}\nexecution records: {executions:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    None
}

pub(crate) fn launcher_path(executable: &std::path::Path) -> PathBuf {
    let path = if let Some(value) = std::env::var_os(LAUNCHER_ENV) {
        let path = PathBuf::from(value);
        // Test runners may provide the helper relative to their working directory.
        let path = if path.is_relative() {
            std::env::current_dir()
                .expect("test working directory")
                .join(path)
        } else {
            path
        };
        assert!(
            path.is_absolute(),
            "{LAUNCHER_ENV} must be an absolute helper path"
        );
        path
    } else {
        // Normal Cargo unit ELF is <target>/<profile>/deps/reverie_kvm-HASH.
        // Derive its profile directory, never search for a newest executable.
        let parent = executable.parent().expect("library executable parent");
        let profile = if parent.file_name().is_some_and(|name| name == "deps") {
            parent.parent().expect("Cargo profile directory")
        } else {
            parent
        };
        profile.join(LAUNCHER_NAME)
    };
    let metadata = std::fs::metadata(&path).unwrap_or_else(|error| {
        panic!("required ordinary-main broker helper {} is unavailable: {error}; build --bin {LAUNCHER_NAME} or supply {LAUNCHER_ENV}; no runtime bootstrap fallback", path.display())
    });
    assert!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "required broker helper is not an executable file: {}",
        path.display()
    );
    path
}

struct ResultDirectory(PathBuf);
impl ResultDirectory {
    fn new() -> Self {
        let mut template = b"/tmp/reverie-kvm-broker-libtest-XXXXXX\0".to_vec();
        let result = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
        assert!(
            !result.is_null(),
            "private libtest record directory: {}",
            std::io::Error::last_os_error()
        );
        let bytes = unsafe { std::ffi::CStr::from_ptr(result) }
            .to_bytes()
            .to_vec();
        let path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
        // mkdtemp atomically creates a new 0700 directory, with no reused path.
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        Self(path)
    }
}
impl Drop for ResultDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Actual cleanup capability for direct-executor fixtures. The ordinary-main
/// launcher authenticates the client before this libtest thread can use it.
/// No bootstrap, fake readiness or synthetic terminal receipt occurs here.
pub(crate) struct CleanupFixture {
    factory: Option<crate::terminal_cleanup::CleanupFactory>,
    admission: Option<crate::executor::RunAdmission>,
    failures: std::sync::Arc<std::sync::Mutex<Vec<crate::Error>>>,
}

impl CleanupFixture {
    pub(crate) fn selected(test: &str) -> Option<Self> {
        let client = selected_child(test)?;
        let runs = std::sync::Arc::new(std::sync::Mutex::new(
            crate::executor::AbandonedRuns::default(),
        ));
        let admission = crate::executor::RunAdmission::begin(&runs).unwrap();
        let factory = admission.terminal_factory(client);
        Some(Self {
            factory: Some(factory),
            admission: Some(admission),
            failures: Default::default(),
        })
    }

    pub(crate) fn executor(&self, mut executor: crate::executor::ElfExecutor) -> CleanupExecutor {
        executor
            .configure_terminal_cleanup(
                self.factory.as_ref().unwrap().clone(),
                std::sync::Arc::new(std::sync::Mutex::new(None)),
            )
            .unwrap();
        CleanupExecutor::ready(executor, self.failures.clone()).unwrap()
    }
}

impl Drop for CleanupFixture {
    fn drop(&mut self) {
        // Declared before all executors: each executor first submits and joins
        // its real service. Failed child creation may leave an empty service
        // in the actual run reaper; join that reaper too, rather than assume
        // factory presence or queue emptiness proves native wait completion.
        drop(self.factory.take());
        self.admission.take().unwrap().finish_fixture_cleanup();
        let failures = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        if !failures.is_empty() {
            if std::thread::panicking() {
                eprintln!("additional actual fixture cleanup failures: {failures:?}");
            } else {
                panic!("actual fixture cleanup failed: {failures:?}");
            }
        }
    }
}

/// Test owner only: delegates every operation to the unchanged real executor.
/// Derived children inherit its actual factory and must report READY before use.
pub(crate) struct CleanupExecutor {
    executor: crate::executor::ElfExecutor,
    failures: std::sync::Arc<std::sync::Mutex<Vec<crate::Error>>>,
}

impl CleanupExecutor {
    fn ready(
        executor: crate::executor::ElfExecutor,
        failures: std::sync::Arc<std::sync::Mutex<Vec<crate::Error>>>,
    ) -> crate::Result<Self> {
        let mut owned = Self { executor, failures };
        futures::executor::block_on(owned.executor.ready_terminal_cleanup())?;
        Ok(owned)
    }

    pub(crate) fn thread_child(&self, tid: i32) -> crate::Result<Self> {
        Self::ready(self.executor.thread_child(tid)?, self.failures.clone())
    }

    pub(crate) fn fork_child(
        &self,
        pid: i32,
        clear_sighand: bool,
        share_address_space: bool,
    ) -> crate::Result<Self> {
        Self::ready(
            self.executor
                .fork_child(pid, clear_sighand, share_address_space)?,
            self.failures.clone(),
        )
    }
}

impl std::ops::Deref for CleanupExecutor {
    type Target = crate::executor::ElfExecutor;
    fn deref(&self) -> &Self::Target {
        &self.executor
    }
}
impl std::ops::DerefMut for CleanupExecutor {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.executor
    }
}
impl Drop for CleanupExecutor {
    fn drop(&mut self) {
        if let Err(error) = futures::executor::block_on(self.executor.finish_terminal_cleanup()) {
            self.failures
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(error);
        }
    }
}
