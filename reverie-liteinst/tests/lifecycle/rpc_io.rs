//! Installed callback routing and unchanged public-accessor admission controls.

use super::*;

fn assert_joined_without_rpc_issues(
    observations: &[reverie_inguest::launcher::RpcLaunchObservationForTest],
) {
    assert_eq!(
        observations.len(),
        1,
        "actual Tool server: {observations:?}"
    );
    assert_eq!(observations[0].active_connections, 0, "{observations:?}");
    assert!(observations[0].issues.is_empty(), "{observations:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_rpc_adapter_uses_private_gate_only_in_an_actual_callback() {
    let (_preload_directory, preload) = compile_noop_preload();
    let admission = std::sync::Arc::new(SharedHandlerAdmission::default());
    let mut command = guest_command("shared-handler-rpc-io");
    // Observe actual signal routing without a previously patched libc site.
    // The existing installed-owner and nested-hook tests still exercise hooks.
    command.env(SITE_PATCHING_ENV, "0");
    let (result, observations) =
        tokio::time::timeout(
            Duration::from_secs(10),
            LiteinstBackend::with_rpc_issues_for_test(LiteinstBackend::with_connection_admission(
                admission.clone(),
                LiteinstBackend::run_with_output_and_preload_and_stats::<
                    SharedHandlerCoordinatorTool,
                >(command, (), preload),
            )),
        )
        .await
        .expect("actual callback socket controls hung");
    let (output, global, stats) = result.expect("actual installed launcher must complete");
    assert_joined_without_rpc_issues(&observations);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        output.stdout,
        concat!(
            "shared handler: callbacks=2 owner=stable LI=2 shared=2 wrong-global=4 reentry=2 outer=1\n",
            "rpc io: libc_nested=1,1 callback_nested=0,0 outside_guest=1,1\n",
        )
        .as_bytes(),
        "{output:?}",
    );
    let requests = global.requests.lock().unwrap();
    assert_eq!(requests.len(), 5, "{requests:?}");
    let source = requests[0].0;
    assert!(source > 0);
    assert_eq!(
        *requests,
        [1001, 2001, 3001, 1002, 2002].map(|tag| (source, tag)),
        "socket controls must preserve the actual owner's request sequence",
    );
    assert_eq!(*admission.peers.lock().unwrap(), [source]);
    assert_eq!(stats.snapshot().process_reports(), 1, "{stats}");
}

async fn outside_callback_accessor_is_terminal_without_wire_or_handler(mode: &str) {
    let (_preload_directory, preload) = compile_noop_preload();
    let admission = std::sync::Arc::new(SharedHandlerAdmission::default());
    let (result, observations) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::with_rpc_issues_for_test(LiteinstBackend::with_connection_admission(
            admission.clone(),
            LiteinstBackend::run_with_output_and_preload::<SharedHandlerCoordinatorTool>(
                guest_command(mode),
                (),
                preload,
            ),
        )),
    )
    .await
    .expect("outside-callback installed accessor hung");
    let (output, global) = result.expect("terminal guest must still drain the actual launcher");
    assert_joined_without_rpc_issues(&observations);
    assert_eq!(
        output.status.code(),
        Some(123),
        "protected socket I/O must fail before a socket Tool handler (124): {output:?}",
    );
    // A valid matching-global probe follows these five completed exchanges.
    // No issue after a normal joined drain excludes a partial extra frame;
    // this exact request list also excludes a complete additional request.
    assert_shared_handler_owner(&output, &global);
    let source = global.requests.lock().unwrap()[0].0;
    assert_eq!(*admission.peers.lock().unwrap(), [source]);
}

#[tokio::test(flavor = "current_thread")]
async fn installed_shared_accessor_outside_callback_is_terminal_without_wire_or_handler() {
    outside_callback_accessor_is_terminal_without_wire_or_handler("shared-handler-outside-shared")
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn installed_liteinst_accessor_outside_callback_is_terminal_without_wire_or_handler() {
    outside_callback_accessor_is_terminal_without_wire_or_handler(
        "shared-handler-outside-liteinst",
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn guest_memory_copies_in_an_actual_callback_do_not_reenter_sigsys() {
    let (_preload_directory, preload) = compile_noop_preload();
    let admission = std::sync::Arc::new(SharedHandlerAdmission::default());
    let mut command = guest_command("shared-handler-memory-io");
    command.env(SITE_PATCHING_ENV, "0");
    let (result, observations) =
        tokio::time::timeout(
            Duration::from_secs(10),
            LiteinstBackend::with_rpc_issues_for_test(LiteinstBackend::with_connection_admission(
                admission.clone(),
                LiteinstBackend::run_with_output_and_preload_and_stats::<
                    SharedHandlerCoordinatorTool,
                >(command, (), preload),
            )),
        )
        .await
        .expect("actual callback memory controls hung");
    let (output, global, stats) = result.expect("actual installed launcher must complete");
    assert_joined_without_rpc_issues(&observations);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        output.stdout,
        concat!(
            "shared handler: callbacks=2 owner=stable LI=2 shared=2 wrong-global=4 reentry=2 outer=1\n",
            "memory io: libc_nested=1,1 copies=13 nested=0 partial=3 faults=EFAULT,0\n",
        )
        .as_bytes(),
        "{output:?}",
    );
    let requests = global.requests.lock().unwrap();
    assert_eq!(requests.len(), 5, "{requests:?}");
    let source = requests[0].0;
    assert!(source > 0);
    assert_eq!(
        *requests,
        [1001, 2001, 3001, 1002, 2002].map(|tag| (source, tag)),
        "memory controls must preserve the actual owner's request sequence",
    );
    assert_eq!(*admission.peers.lock().unwrap(), [source]);
    assert_eq!(stats.snapshot().process_reports(), 1, "{stats}");
}

#[tokio::test(flavor = "current_thread")]
async fn tool_syscall_in_an_actual_callback_uses_the_private_gate() {
    let (_preload_directory, preload) = compile_noop_preload();
    let admission = std::sync::Arc::new(SharedHandlerAdmission::default());
    let mut command = guest_command("shared-handler-tool-syscall");
    command.env(SITE_PATCHING_ENV, "0");
    let (result, observations) =
        tokio::time::timeout(
            Duration::from_secs(10),
            LiteinstBackend::with_rpc_issues_for_test(LiteinstBackend::with_connection_admission(
                admission.clone(),
                LiteinstBackend::run_with_output_and_preload_and_stats::<
                    SharedHandlerCoordinatorTool,
                >(command, (), preload),
            )),
        )
        .await
        .expect("actual callback Tool syscall controls hung");
    let (output, global, stats) = result.expect("actual installed launcher must complete");
    assert_joined_without_rpc_issues(&observations);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        output.stdout,
        concat!(
            "tool syscall: actual_callback=1 libc_nested=1\n",
            "shared handler: callbacks=2 owner=stable LI=2 shared=2 wrong-global=4 reentry=2 outer=1\n",
            "tool syscall: calls=4 nested=0 errno=EBADF link=matched stat=matched\n",
        )
        .as_bytes(),
        "{output:?}",
    );
    let requests = global.requests.lock().unwrap();
    assert_eq!(requests.len(), 5, "{requests:?}");
    let source = requests[0].0;
    assert!(source > 0);
    assert_eq!(
        *requests,
        [1001, 2001, 3001, 1002, 2002].map(|tag| (source, tag)),
        "Tool syscall controls must preserve the actual owner's request sequence",
    );
    assert_eq!(*admission.peers.lock().unwrap(), [source]);
    assert_eq!(stats.snapshot().process_reports(), 1, "{stats}");
}
