use std::sync::atomic::AtomicU64;

use super::*;

#[test]
fn worker_cleanup_joins_all_batches_and_retains_every_error_in_tid_order() {
    let group = Arc::new(GuestThreadGroup::default());
    let completed = Arc::new(AtomicU64::new(0));
    let nested_group = group.clone();
    let nested_completed = completed.clone();
    group.add_worker_handle(
        9,
        std::thread::spawn(move || {
            nested_group.add_worker_handle(
                3,
                std::thread::spawn(move || {
                    nested_completed.fetch_add(1, Ordering::SeqCst);
                    Err(Error::UnexpectedVcpuExit("nested failure".into()))
                }),
            );
            Err(Error::UnexpectedVcpuExit("outer failure".into()))
        }),
    );
    let success = completed.clone();
    group.add_worker_handle(
        7,
        std::thread::spawn(move || {
            success.fetch_add(1, Ordering::SeqCst);
            Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
        }),
    );
    group.add_worker_handle(5, std::thread::spawn(|| panic!("forced worker panic")));
    group.join_workers();
    assert_eq!(completed.load(Ordering::SeqCst), 2);
    assert!(group.worker_handles.lock().unwrap().is_empty());
    let first = group.teardown_result().unwrap_err().to_string();
    assert!(first.contains("nested failure"));
    assert!(first.contains("outer failure"));
    assert!(first.contains("guest thread panicked during teardown"));
    assert!(first.find("thread 3:").unwrap() < first.find("thread 5:").unwrap());
    assert!(first.find("thread 5:").unwrap() < first.find("thread 9:").unwrap());
    group.join_workers();
    assert_eq!(
        group.teardown_result().unwrap_err().to_string(),
        first,
        "an intermediate join must not consume a failure"
    );
    group.add_worker_handle(
        4,
        std::thread::spawn(|| Err(Error::UnexpectedVcpuExit("later failure".into()))),
    );
    group.join_workers();
    let final_error = group.teardown_result().unwrap_err().to_string();
    for message in [
        "nested failure",
        "outer failure",
        "later failure",
        "guest thread panicked",
    ] {
        assert!(final_error.contains(message), "{final_error}");
    }
    assert!(final_error.find("thread 3:").unwrap() < final_error.find("thread 4:").unwrap());
    assert!(final_error.find("thread 4:").unwrap() < final_error.find("thread 5:").unwrap());
}
