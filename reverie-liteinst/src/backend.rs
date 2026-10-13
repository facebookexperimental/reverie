//! Compatibility API for the shared preload launcher.

pub use reverie_inguest::bootstrap::COORDINATOR_ENV;
pub use reverie_inguest::bootstrap::PreloadBootstrap;
pub use reverie_inguest::bootstrap::STATS_COORDINATOR_ENV;
pub use reverie_inguest::bootstrap::TOOL_PRELOAD_ENV;
pub use reverie_inguest::bootstrap::take_preload_bootstrap;
#[cfg(feature = "exec-private-init")]
pub use reverie_inguest::launcher::InitialImageStatsCollector;
#[cfg(feature = "exec-private-init")]
pub use reverie_inguest::launcher::InitialImageStatsServer;
pub use reverie_inguest::launcher::PreloadBackend as LiteinstBackend;

#[cfg(all(test, feature = "exec-private-init"))]
mod initial_stats_tests {
    use std::io;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use reverie::Tid;
    use reverie_rpc_transport::Admitted;
    use reverie_rpc_transport::ConnectionAdmission;
    use reverie_rpc_transport::RpcError;
    use reverie_rpc_transport::RpcIssueMonitor;

    use super::*;

    #[derive(Default)]
    struct TestAdmission {
        calls: AtomicUsize,
        refuse: bool,
    }

    impl ConnectionAdmission for TestAdmission {
        fn admit(&self, _peer: OwnedFd) -> io::Result<Admitted> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.refuse {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "test refusal",
                ));
            }
            // A transport component fixture, not a same-birth authenticator.
            Ok(Admitted {
                process_id: std::process::id() as i32,
            })
        }
    }

    fn directory() -> tempfile::TempDir {
        let directory = tempfile::Builder::new()
            .prefix("reverie-initial-stats-")
            .tempdir_in("/tmp")
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    async fn stop_server(
        task: tokio::task::JoinHandle<Result<(), RpcError>>,
        issues: &RpcIssueMonitor,
    ) {
        issues.planned_shutdown();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[test]
    fn initial_stats_real_collector_reports_and_drains() {
        const CHILD_REPORTS: &str = "REVERIE_COMPONENT_INITIAL_STATS_REPORTS";
        const TEST: &str =
            "backend::initial_stats_tests::initial_stats_real_collector_reports_and_drains";
        let Some(reports) = std::env::var_os(CHILD_REPORTS) else {
            // Isolate the real process-wide OnceLock. Missing, one, and duplicate
            // reports all traverse the actual collector and typed transport.
            for reports in [0, 1, 2] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--test-threads=1"])
                    .env(CHILD_REPORTS, reports.to_string())
                    .output()
                    .unwrap();
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .any(|line| line == format!("test {TEST} ... ok")),
                    "selected collector control did not execute: {}",
                    String::from_utf8_lossy(&output.stdout)
                );
                assert!(
                    output.status.success(),
                    "report case {reports}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        };
        let reports: u64 = reports.to_str().unwrap().parse().unwrap();
        assert!(reports <= 2);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let directory = directory();
                let tool_rpc = directory.path().join("rpc.sock");
                let endpoint =
                    crate::initial_image_stats::initial_image_stats_endpoint(&tool_rpc).unwrap();
                let admission = Arc::new(TestAdmission::default());
                let (server, collector) =
                    InitialImageStatsServer::bind(&tool_rpc, directory.path(), admission.clone())
                        .unwrap();
                let connections = server.connection_monitor();
                let issues = server.issue_monitor();
                let task = tokio::spawn(server.serve());
                assert!(!crate::guest_stats_enabled());
                let hooks = crate::stats::initialize_guest_stats(&endpoint).unwrap();
                hooks.record_path(crate::LiteinstDispatchPath::InGuestPhysicalSigsys);
                hooks.record_path(crate::LiteinstDispatchPath::InGuestPhysicalSigsys);
                hooks.record_path(crate::LiteinstDispatchPath::PatchingDisabledFallback);
                tokio::task::spawn_blocking(move || {
                    for _ in 0..reports {
                        crate::runtime::submit_process_stats(
                            Tid::from_raw(std::process::id() as i32),
                            hooks,
                        )
                        .unwrap();
                    }
                })
                .await
                .unwrap();
                tokio::time::timeout(Duration::from_secs(2), connections.wait_for_idle())
                    .await
                    .unwrap();
                assert_eq!(connections.active_connections(), 0);
                assert!(issues.snapshot().is_empty());
                stop_server(task, &issues).await;
                assert_eq!(connections.active_connections(), 0);
                assert!(issues.snapshot().is_empty());
                assert_eq!(admission.calls.load(Ordering::Relaxed) as u64, reports);
                let source = collector.into_source().await.unwrap();
                let snapshot = source.snapshot();
                assert_eq!(snapshot.process_reports(), reports);
                assert_eq!(snapshot.patch_shapes().patched_rips(), 0);
                assert_eq!(
                    snapshot
                        .dispatch_paths()
                        .count(&crate::LiteinstDispatchPath::DirectHook),
                    0
                );
                assert_eq!(
                    snapshot
                        .dispatch_paths()
                        .count(&crate::LiteinstDispatchPath::PtraceInstallation),
                    0
                );
                assert_eq!(
                    snapshot
                        .dispatch_paths()
                        .count(&crate::LiteinstDispatchPath::InGuestPhysicalSigsys),
                    reports * 2
                );
                assert_eq!(
                    snapshot
                        .dispatch_paths()
                        .count(&crate::LiteinstDispatchPath::PatchingDisabledFallback),
                    reports
                );
            });
    }
}
