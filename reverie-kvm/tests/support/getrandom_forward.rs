use super::*;

/// The getrandom(2) calls the fixture makes itself (glibc's start-up makes
/// another, for its malloc tcache key).
const FIXTURE_CALLS: usize = 17;

/// The bytes [`GetrandomAnsweringTool`] stores, and the most it stores.
const DECIDED_BYTES: [u8; 24] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
];

/// What each getrandom callback of a test Tool returned, in order.
#[derive(Default)]
struct GetrandomLog {
    results: Mutex<Vec<i64>>,
}

impl GetrandomLog {
    fn results(&self) -> Vec<i64> {
        self.results
            .lock()
            .expect("getrandom log lock poisoned")
            .clone()
    }
}

#[reverie::global_tool]
impl GlobalTool for GetrandomLog {
    type Request = i64;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, result: i64) {
        self.results
            .lock()
            .expect("getrandom log lock poisoned")
            .push(result);
    }
}

/// Answers every getrandom itself and never injects it: it stores the first
/// `min(length, 24)` bytes of [`DECIDED_BYTES`] and returns that count, and
/// it fails a zero-length call with EIO, which Linux's getrandom never
/// returns. Other calls are not subscribed.
#[derive(Clone, Copy, Debug, Default)]
struct GetrandomAnsweringTool;

#[reverie::tool]
impl Tool for GetrandomAnsweringTool {
    type GlobalState = GetrandomLog;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscalls([Sysno::getrandom]);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let Syscall::Getrandom(call) = syscall else {
            return Ok(guest.inject(syscall).await?);
        };
        let length = call.buflen().min(DECIDED_BYTES.len());
        let result = if length == 0 {
            -i64::from(libc::EIO)
        } else {
            let buffer = call.buf().ok_or(Errno::EFAULT)?;
            guest.memory().write(buffer, &DECIDED_BYTES[..length])?;
            length as i64
        };
        guest.send_rpc(result).await;
        if result < 0 {
            Err(Errno::EIO.into())
        } else {
            Ok(result)
        }
    }
}

/// Injects every getrandom and returns the injected call's result, which it
/// also logs. Other calls are not subscribed.
#[derive(Clone, Copy, Debug, Default)]
struct GetrandomInjectingTool;

#[reverie::tool]
impl Tool for GetrandomInjectingTool {
    type GlobalState = GetrandomLog;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscalls([Sysno::getrandom]);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let result = guest.inject(syscall).await;
        guest
            .send_rpc(result.unwrap_or_else(|errno| -i64::from(errno.into_raw())))
            .await;
        Ok(result?)
    }
}

/// How the fixture's getrandom calls are run on KVM.
#[derive(Clone, Copy, Debug)]
enum Mode {
    /// No Tool: the backend answers every call.
    Direct,
    /// The example strace Tool, which injects every call.
    Strace,
    /// [`GetrandomInjectingTool`].
    Injecting,
}

fn compile_fixture(directory: &TestDirectory) -> PathBuf {
    compile_c_program(
        &directory.0,
        "getrandom-forward",
        include_str!("../fixtures/getrandom_forward.c"),
    )
}

fn install(
    executable: &std::path::Path,
    arguments: &[&str],
    directory: &TestDirectory,
) -> KvmBackend {
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    let mut argv = vec![executable.to_str().unwrap()];
    argv.extend_from_slice(arguments);
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(executable).unwrap(),
            &argv,
            &[],
            &directory.0,
        )
        .unwrap();
    backend
}

/// The raw result (a negative errno for a failure) of each `result=R errno=E`
/// line the fixture printed.
fn printed_results(stdout: &str) -> Vec<i64> {
    stdout
        .lines()
        .filter_map(|line| {
            let field = |name: &str| -> Option<i64> {
                line.split(' ')
                    .find_map(|word| word.strip_prefix(name))
                    .map(|value| value.parse().unwrap())
            };
            let result = field("result=")?;
            let errno = field("errno=").unwrap();
            Some(if result == -1 { -errno } else { result })
        })
        .collect()
}

/// `results` without glibc's own call: the fixture's calls are the guest's
/// only getrandom calls except one 8-byte call, glibc's for its malloc tcache
/// key, which it makes on its first allocation, between two of the fixture's
/// calls. Removing the first 8 is enough: if the fixture's own 8 comes first,
/// removing it instead leaves the same sequence.
fn without_glibc_call(results: &[i64]) -> Option<Vec<i64>> {
    (results.len() == FIXTURE_CALLS + 1)
        .then(|| results.iter().position(|result| *result == 8))
        .flatten()
        .map(|glibc| {
            let mut fixture = results.to_vec();
            fixture.remove(glibc);
            fixture
        })
}

/// getrandom is forwarded to the host: each of the fixture's calls (a filled
/// buffer, GRND_NONBLOCK, GRND_RANDOM, GRND_INSECURE, zero lengths, invalid
/// flags, a read-only page, buffers that run into one, and addresses that are
/// not user memory) returns on KVM what it returns natively, with the same
/// errno, and writes exactly the bytes it counts. The fixture's output names
/// no random byte, so the whole output must equal the native run's. A Tool
/// that injects the call gets the host's answer, which the guest then sees.
fn run_getrandom_forward(mode: Mode) {
    Kvm::new()
        .unwrap_or_else(|error| panic!("getrandom forward requires usable /dev/kvm: {error}"));
    let directory = TestDirectory::new();
    let executable = compile_fixture(&directory);
    let native = std::process::Command::new(&executable).output().unwrap();
    assert!(native.status.success(), "native: {native:?}");
    assert!(native.stderr.is_empty(), "native: {native:?}");
    let native_stdout = String::from_utf8(native.stdout).unwrap();
    assert_eq!(
        native_stdout.lines().count(),
        FIXTURE_CALLS + 1,
        "{native_stdout}"
    );
    assert!(!native_stdout.contains("WRONG"), "{native_stdout}");
    assert!(
        native_stdout.contains("plain result=4096 errno=0 buffer=exact\n"),
        "{native_stdout}"
    );
    let mut backend = install(&executable, &[], &directory);
    let (code, stdout, stderr) = match mode {
        Mode::Direct => backend.run_static_elf_captured().unwrap(),
        Mode::Strace => {
            let (log, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            let calls = log
                .syscalls()
                .iter()
                .filter(|call| *call == "getrandom")
                .count();
            assert!(
                calls > FIXTURE_CALLS,
                "every getrandom must reach the Tool: {calls}"
            );
            (code, stdout, stderr)
        }
        Mode::Injecting => {
            let (log, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<GetrandomInjectingTool>((), true),
            )
            .unwrap();
            // The Tool saw the host's answers, and they are what the guest saw.
            let results = log.results();
            let printed = printed_results(&String::from_utf8_lossy(&stdout));
            assert_eq!(printed.len(), FIXTURE_CALLS, "{printed:?}");
            assert_eq!(
                without_glibc_call(&results),
                Some(printed.clone()),
                "Tool saw {results:?}, guest printed {printed:?}"
            );
            (code, stdout, stderr)
        }
    };
    let stdout = String::from_utf8(stdout).unwrap();
    assert_eq!(
        code,
        0,
        "stdout={stdout} stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, native_stdout);
}

#[test]
fn getrandom_forwards_to_the_host_direct() {
    run_getrandom_forward(Mode::Direct);
}

#[test]
fn getrandom_forwards_to_the_host_strace_tool() {
    run_getrandom_forward(Mode::Strace);
}

#[test]
fn getrandom_forwards_to_the_host_injecting_tool() {
    run_getrandom_forward(Mode::Injecting);
}

/// A Tool that answers getrandom itself decides the call: the guest sees
/// exactly the Tool's bytes and return value, and its EIO, and never host
/// entropy, though the backend forwards an injected getrandom to the host.
#[test]
fn getrandom_answered_by_the_tool_is_the_tools() {
    Kvm::new()
        .unwrap_or_else(|error| panic!("getrandom decision requires usable /dev/kvm: {error}"));
    let directory = TestDirectory::new();
    let executable = compile_fixture(&directory);
    let mut backend = install(&executable, &["decided"], &directory);
    let (log, code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<GetrandomAnsweringTool>((), true),
    )
    .unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    assert_eq!(
        code,
        0,
        "stdout={stdout} stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    let mut bytes: String = DECIDED_BYTES
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    bytes.push_str(&"a5".repeat(64 - DECIDED_BYTES.len()));
    assert_eq!(
        stdout,
        format!(
            "decided result=24 errno=0 bytes={bytes}\ndecided_zero result=-1 errno={}\n",
            libc::EIO
        )
    );
    // The fixture's two calls and glibc's own 8-byte call for its malloc
    // tcache key, all answered by the Tool.
    let mut results = log.results();
    let glibc = results.iter().position(|result| *result == 8);
    assert!(glibc.is_some(), "{results:?}");
    results.remove(glibc.unwrap());
    assert_eq!(results, [24, -i64::from(libc::EIO)]);
}
