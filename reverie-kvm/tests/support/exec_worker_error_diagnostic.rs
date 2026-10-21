use super::*;

static EVENTS: Mutex<Vec<(u8, i32)>> = Mutex::new(Vec::new());

#[derive(Default, Debug)]
struct Log;
#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = ();
    type Response = ();
    type Config = u8;
    async fn receive_rpc(&self, _: Pid, _: ()) {}
}

#[derive(Default)]
struct HookTool {
    pid: i32,
    mode: u8,
}
#[reverie::tool]
impl Tool for HookTool {
    type GlobalState = Log;
    type ThreadState = i32;
    fn new(pid: Pid, mode: &u8) -> Self {
        Self {
            pid: pid.as_raw(),
            mode: *mode,
        }
    }
    fn subscriptions(mode: &u8) -> Subscription {
        let mut result = Subscription::all_syscalls();
        if mode & 8 != 0 {
            result.disable_syscalls([Sysno::execve, Sysno::execveat]);
        }
        result
    }
    fn init_thread_state(&self, tid: Pid, _: Option<(Pid, &i32)>) -> i32 {
        tid.as_raw()
    }
    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        EVENTS.lock().unwrap().push((0, guest.tid().as_raw()));
        Ok(())
    }
    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        EVENTS.lock().unwrap().push((3, guest.tid().as_raw()));
        Ok(())
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        guest.tail_inject(syscall).await
    }
    async fn on_exit_thread<G: GlobalRPC<Log>>(
        &self,
        tid: Pid,
        _: &G,
        state: i32,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        assert_eq!(tid.as_raw(), state);
        assert_eq!(
            status,
            if tid.as_raw() == self.pid && self.mode & 1 != 0 {
                ExitStatus::Exited(255)
            } else {
                ExitStatus::SUCCESS
            }
        );
        EVENTS.lock().unwrap().push((1, tid.as_raw()));
        if self.mode & 1 != 0 && tid.as_raw() != self.pid {
            return Err(Errno::EIO.into());
        }
        if self.mode & 2 != 0 && tid.as_raw() == self.pid {
            return Err(Errno::ENOSPC.into());
        }
        Ok(())
    }
    async fn on_exit_process<G: GlobalRPC<Log>>(
        self,
        pid: Pid,
        _: &G,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        assert_eq!(self.pid, pid.as_raw());
        assert_eq!(
            status,
            if self.mode & 1 != 0 {
                ExitStatus::Exited(255)
            } else {
                ExitStatus::SUCCESS
            }
        );
        EVENTS.lock().unwrap().push((2, pid.as_raw()));
        if self.mode & 4 != 0 {
            return Err(Errno::EACCES.into());
        }
        Ok(())
    }
}

const GUEST: &str = r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>
static _Atomic int entered;
static void *worker(void *unused) {
  (void)unused;
  atomic_store(&entered, 1);
  for (;;) sched_yield();
  return NULL;
}
int main(int argc, char **argv) {
  alarm(15);
  if (argc == 2) {
    puts("exec-replacement");
    return 0;
  }
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL)) return 20;
  while (!atomic_load(&entered)) sched_yield();
  char *next[] = {argv[0], "replaced", NULL};
  execv(argv[0], next);
  return 21;
}
"#;

#[test]
fn exec_worker_error_still_consumes_root_and_process_hooks() {
    const TEST: &str =
        "exec_worker_error_diagnostic::exec_worker_error_still_consumes_root_and_process_hooks";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(&directory.0, "exec-worker-error", GUEST);
    if let Some(dest) = std::env::var_os("REVERIE_TERMINAL_ARTIFACTS") {
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::copy(&executable, PathBuf::from(&dest).join("guest")).unwrap();
        std::fs::copy(
            executable.with_extension("c"),
            PathBuf::from(&dest).join("guest.c"),
        )
        .unwrap();
    }
    // Cover Tool-injected exec and exec performed by the backend because the
    // Tool did not subscribe to it. Keep successful exec neighbors for both.
    for mode in [0u8, 1, 3, 5, 7, 8, 9, 11, 13, 15] {
        EVENTS.lock().unwrap().clear();
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[executable.to_str().unwrap()],
                &[],
                &directory.0,
            )
            .unwrap();
        let result =
            futures::executor::block_on(backend.run_static_elf_with_tool::<HookTool>(mode, true));
        let events = EVENTS.lock().unwrap().clone();
        eprintln!("exec worker error mode={mode} result={result:?} events={events:?}");
        if mode & 1 != 0 {
            let error = result.unwrap_err().to_string();
            assert_eq!(
                error.matches("EIO").count(),
                1,
                "original worker error: {error}"
            );
            assert_eq!(
                error.matches("ENOSPC").count(),
                usize::from(mode & 2 != 0),
                "root hook error: {error}"
            );
            assert_eq!(
                error.matches("EACCES").count(),
                usize::from(mode & 4 != 0),
                "process hook error: {error}"
            );
            if mode & 6 == 0 {
                assert_eq!(
                    error,
                    "unexpected vCPU exit: KVM worker cleanup failed: thread 2: Reverie tool failed: -5 EIO (I/O error)"
                );
            }
        } else {
            let (_, status, stdout, stderr) = result.unwrap();
            assert_eq!(status, 0);
            assert_eq!(stdout, b"exec-replacement\n");
            assert!(stderr.is_empty());
        }
        let starts = events
            .iter()
            .filter(|e| e.0 == 0)
            .map(|e| e.1)
            .collect::<Vec<_>>();
        assert_eq!(starts.len(), 2);
        for tid in &starts {
            assert_eq!(
                events.iter().filter(|e| **e == (1, *tid)).count(),
                1,
                "each started thread must have one consuming exit hook: {events:?}"
            );
        }
        assert_eq!(
            events.iter().filter(|e| **e == (2, starts[0])).count(),
            1,
            "one consuming process hook: {events:?}"
        );
        assert_eq!(events.last(), Some(&(2, starts[0])));
        assert_eq!(
            events.iter().filter(|e| **e == (3, starts[0])).count(),
            if mode & 1 != 0 { 1 } else { 2 },
            "failed teardown never enters the replacement image: {events:?}"
        );
    }
}
