// A group exit's last-user answer counts a sibling that the Tool retired for
// that exit before the exit reached this backend, as a Tool may retire the
// siblings of an exit_group as soon as it has ordered the exit.
use super::*;

/// How many child processes saw their worker's exit reach the Tool before
/// the main thread's exit_group was injected: the order under test.
#[derive(Default)]
struct RetiredBeforeExitGlobal {
    forced: AtomicU64,
}
#[reverie::global_tool]
impl GlobalTool for RetiredBeforeExitGlobal {
    type Request = ();
    type Response = ();
    type Config = ();
    async fn receive_rpc(&self, _from: Pid, _request: Self::Request) {
        self.forced.fetch_add(1, Ordering::SeqCst);
    }
}

/// Per process (each forked child gets its own): when the main thread of a
/// process with a worker calls exit_group, the Tool first retires the worker
/// at its next sched_yield and waits until the worker's exit has reached the
/// Tool, and only then lets the exit_group run.
#[derive(Default)]
struct RetireSiblingBeforeExitTool {
    worker: std::sync::atomic::AtomicI32,
    retire_worker: AtomicBool,
    worker_exited: AtomicBool,
}
#[reverie::tool]
impl Tool for RetireSiblingBeforeExitTool {
    type GlobalState = RetiredBeforeExitGlobal;
    type ThreadState = ();
    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        if guest.pid() != guest.tid() {
            self.worker.store(guest.tid().as_raw(), Ordering::SeqCst);
        }
        Ok(())
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, reverie::Error> {
        if guest.pid() != guest.tid()
            && call.number() == Sysno::sched_yield
            && self.retire_worker.load(Ordering::SeqCst)
        {
            guest.retire_current_thread().await;
        }
        if guest.pid() == guest.tid()
            && call.number() == Sysno::exit_group
            && self.worker.load(Ordering::SeqCst) != 0
        {
            self.retire_worker.store(true, Ordering::SeqCst);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !self.worker_exited.load(Ordering::SeqCst) {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the worker's retirement never reached the Tool"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            guest.send_rpc(()).await;
        }
        guest.tail_inject(call).await
    }
    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Pid,
        _global: &G,
        _thread_state: (),
        _status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        if tid.as_raw() == self.worker.load(Ordering::SeqCst) {
            self.worker_exited.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
}

/// `fixtures/shared_file_threads.c` mode "group-cleartid": the child's main
/// thread, whose clear_child_tid word is the marker, calls exit_group while a
/// worker spins in sched_yield. Here the Tool retires the worker for that
/// exit and lets the exit_group run only once the worker's exit has reached
/// it, so the worker has retired from the address space before the exit is
/// first published, the order a Tool's sibling retirement can give when
/// host threads happen to run that way. The worker was live at the exit's
/// commit, so the exit's answer is that another thread was live and the main
/// thread stores zero, as without a Tool, every time; counting only the
/// threads not yet retired at the publication would leave the marker.
#[test]
fn a_group_exit_counts_a_sibling_its_tool_retired_before_the_exit_was_published() {
    const TEST: &str = "tool_retired_group_exit::a_group_exit_counts_a_sibling_its_tool_retired_before_the_exit_was_published";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "shared-file-threads",
        include_str!("../fixtures/shared_file_threads.c"),
    );
    let image = std::fs::read(&program).unwrap();
    for round in 0..3 {
        let run_directory = directory.0.join(format!("round-{round}"));
        std::fs::create_dir(&run_directory).unwrap();
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[program.to_str().unwrap(), "group-cleartid"],
                &[],
                &run_directory,
            )
            .unwrap();
        let completion = futures::executor::block_on(
            backend.run_static_elf_with_tool_completion::<RetireSiblingBeforeExitTool>((), true),
        )
        .unwrap();
        assert_eq!(
            completion.global_state.forced.load(Ordering::SeqCst),
            1,
            "round {round}: the worker's retirement must reach the Tool before the exit_group"
        );
        let (status, stdout, stderr) = completion.result.unwrap();
        assert_eq!(
            (status, String::from_utf8_lossy(&stdout).into_owned()),
            (
                ExitStatus::Exited(0),
                "the child's group exit ended it; its clear_child_tid word holds 0\n".to_owned()
            ),
            "round {round}: stderr={}",
            String::from_utf8_lossy(&stderr)
        );
    }
}
