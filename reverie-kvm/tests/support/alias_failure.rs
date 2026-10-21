// Shared by unit and KVM integration controls. Each selected case runs in a
// separate bounded process; the interposer remains dormant until explicitly armed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub(crate) enum Case {
    Reservation = 1,
    SecondExtent = 2,
    Foreign = 3,
    AtomicCollision = 4,
    CleanupAfterSuccess = 5,
    WrongAddress = 6,
    MiddleExtent = 7,
    ConstructionCleanup = 8,
    SuffixCleanup = 9,
    PersistentCleanup = 10,
    CleanupAtEof = 11,
}

impl Case {
    pub(crate) fn setup_succeeds(self) -> bool {
        matches!(
            self,
            Case::AtomicCollision
                | Case::CleanupAfterSuccess
                | Case::PersistentCleanup
                | Case::CleanupAtEof
        )
    }
    fn from_stage(stage: i32) -> Self {
        match stage {
            1 => Self::Reservation,
            2 => Self::SecondExtent,
            3 => Self::Foreign,
            4 => Self::AtomicCollision,
            5 => Self::CleanupAfterSuccess,
            6 => Self::WrongAddress,
            7 => Self::MiddleExtent,
            8 => Self::ConstructionCleanup,
            9 => Self::SuffixCleanup,
            10 => Self::PersistentCleanup,
            11 => Self::CleanupAtEof,
            _ => panic!("unknown alias failure stage: {stage}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AliasAddresses {
    pub(crate) base: usize,
    pub(crate) length: usize,
    pub(crate) wrong: usize,
    pub(crate) ambiguous: usize,
    pub(crate) operation: usize,
}

#[derive(Debug)]
pub(crate) struct AliasObservation {
    pub(crate) case: Case,
    pub(crate) addresses: AliasAddresses,
    pub(crate) counters: [u64; 32],
}

pub(crate) struct Fault {
    case: Case,
    arm: unsafe extern "C" fn(i32),
    finish: unsafe extern "C" fn(),
    count: unsafe extern "C" fn(i32) -> libc::c_ulong,
    address: unsafe extern "C" fn(i32) -> usize,
    operation: std::cell::Cell<usize>,
}

struct TestDirectory {
    path: std::path::PathBuf,
    removed: bool,
}

impl TestDirectory {
    fn new(path: std::path::PathBuf) -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self {
            path,
            removed: false,
        })
    }

    fn close(mut self) -> std::io::Result<()> {
        std::fs::remove_dir_all(&self.path)?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        if !self.removed {
            // Keep the original failure if compilation or child setup panics.
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

// Retain the original two stages for every existing caller.
pub(crate) fn child(test: &str) -> Option<Fault> {
    child_cases(test, &[Case::Reservation, Case::SecondExtent])
}

pub(crate) fn child_case(test: &str, case: Case) -> Option<Fault> {
    child_cases(test, &[case])
}

fn child_cases(test: &str, cases: &[Case]) -> Option<Fault> {
    if std::env::var("REVERIE_ALIAS_FAILURE_TEST").as_deref() == Ok(test) {
        let stage = std::env::var("REVERIE_ALIAS_FAILURE_STAGE")
            .unwrap()
            .parse()
            .unwrap();
        let case = Case::from_stage(stage);
        assert!(cases.contains(&case), "unselected alias case: {case:?}");
        // SAFETY: the child retains our explicitly loaded fixture. These
        // exported symbols have the exact signatures below.
        let (arm, finish, count, address) = unsafe {
            let arm = libc::dlsym(libc::RTLD_DEFAULT, c"reverie_alias_failure_arm".as_ptr());
            let finish = libc::dlsym(libc::RTLD_DEFAULT, c"reverie_alias_failure_finish".as_ptr());
            let count = libc::dlsym(libc::RTLD_DEFAULT, c"reverie_alias_failure_count".as_ptr());
            let address = libc::dlsym(
                libc::RTLD_DEFAULT,
                c"reverie_alias_failure_address".as_ptr(),
            );
            assert!(!arm.is_null() && !finish.is_null() && !count.is_null() && !address.is_null());
            (
                std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn(i32)>(arm),
                std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn()>(finish),
                std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn(i32) -> libc::c_ulong>(
                    count,
                ),
                std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn(i32) -> usize>(
                    address,
                ),
            )
        };
        return Some(Fault {
            case,
            arm,
            finish,
            count,
            address,
            operation: std::cell::Cell::new(0),
        });
    }
    assert!(!cases.is_empty(), "an alias child must select a case");
    let directory = TestDirectory::new(std::env::temp_dir().join(format!(
        "reverie-alias-failure-{}-{}",
        std::process::id(),
        test.replace(':', "_")
    )))
    .unwrap();
    let library = directory.path.join("fault.so");
    let source = std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or_else(
            || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            std::path::PathBuf::from,
        )
        .join("tests/fixtures/getdents_alias_failure.c");
    let build = std::process::Command::new("timeout")
        .args([
            "--kill-after=2s",
            "30s",
            "/usr/bin/gcc",
            "-O2",
            "-shared",
            "-fPIC",
            "-pthread",
        ])
        .arg(source)
        .arg("-o")
        .arg(&library)
        .output()
        .unwrap();
    assert!(build.status.success(), "{build:?}");
    let outputs: Vec<_> = cases
        .iter()
        .map(|&case| {
            let stage = (case as i32).to_string();
            // Fresh per-case logfile in a newly created private directory.
            let execution_log = directory.path.join(format!("libtest-{stage}.log"));
            let output = std::process::Command::new("timeout")
                .args(["--kill-after=2s", "30s"])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    test,
                    "--nocapture",
                    "--test-threads=1",
                    "--logfile",
                ])
                .arg(&execution_log)
                .env("REVERIE_ALIAS_FAILURE_TEST", test)
                .env("REVERIE_ALIAS_FAILURE_STAGE", &stage)
                .env("LD_PRELOAD", &library)
                .output()
                .unwrap();
            let executions = std::fs::read_to_string(&execution_log);
            (stage, output, executions)
        })
        .collect();
    directory.close().unwrap();
    for (stage, output, executions) in outputs {
        eprintln!("\nstage={stage} {output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{test}: stage={stage} status={:?} stdout={stdout} stderr={stderr}",
            output.status.code()
        );
        let executions = executions.unwrap_or_else(|error| panic!(
            "{test}: stage={stage} missing execution logfile: {error}; stdout={stdout} stderr={stderr}"
        ));
        // stdout can contain arbitrary guest bytes and is never execution proof.
        assert_eq!(
            executions,
            format!("ok {test}\n"),
            "\n{test}: alias child execution record mismatch; stage={stage}; exit_code={:?}\nexecution records: {executions:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status.code()
        );
    }
    None
}

impl Fault {
    pub(crate) fn case(&self) -> Case {
        self.case
    }
    pub(crate) fn succeeds(&self) -> bool {
        self.case == Case::AtomicCollision
    }
    pub(crate) fn arm(&self) {
        let operation = self.operation.get() + 1;
        assert!(operation == 1 || (self.case == Case::PersistentCleanup && operation <= 3));
        self.operation.set(operation);
        // SAFETY: symbols belong to the retained, bounded child fixture.
        unsafe { (self.arm)(self.case as i32) };
    }
    pub(crate) fn pages(&self) -> usize {
        if matches!(self.case, Case::MiddleExtent | Case::SuffixCleanup) {
            5
        } else {
            3
        }
    }
    pub(crate) fn addresses(&self) -> AliasAddresses {
        // SAFETY: the fixture returns scalar addresses, never Rust references.
        let values = std::array::from_fn::<_, 5, _>(|i| unsafe { (self.address)(i as i32) });
        assert_eq!(values[4], self.operation.get());
        AliasAddresses {
            base: values[0],
            length: values[1],
            wrong: values[2],
            ambiguous: values[3],
            operation: values[4],
        }
    }
    /// Native unit tests bind an ID from an independently queried ledger record.
    /// Integration tests cannot inspect that private ledger and pass no ID.
    pub(crate) fn cause<'a>(
        &self,
        error: &'a crate::Error,
        retention_id: Option<usize>,
    ) -> Option<&'a crate::Error> {
        if retention_id == Some(0) {
            return None;
        }
        let addresses = self.addresses();
        let expected = CaseCause::for_case(self.case, addresses, retention_id)?;
        alias_case_cause(error, expected)
    }
    pub(crate) fn assert_fired(&self) -> AliasObservation {
        // Finish observes before the fixture's own allocator releases its marker.
        unsafe { (self.finish)() };
        let counts = std::array::from_fn::<_, 32, _>(|i| unsafe { (self.count)(i as i32) });
        let mut expected = match self.case {
            Case::Reservation => [
                1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            Case::SecondExtent => [
                1, 2, 1, 1, 0, 1, 1, 0, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            Case::Foreign => [
                1, 2, 1, 1, 1, 1, 1, 0, 3, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
                0, 0, 0, 0,
            ],
            Case::AtomicCollision => [
                1, 2, 2, 0, 0, 1, 1, 0, 7, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0, 0, 0, 0,
            ],
            Case::CleanupAfterSuccess => [
                1, 2, 2, 0, 0, 1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            Case::WrongAddress => [
                1, 2, 1, 1, 1, 2, 2, 0, 3, 0, 1, 1, 1, 1, 2, 2, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1,
                0, 0, 0, 0,
            ],
            Case::MiddleExtent => [
                1, 2, 1, 1, 1, 2, 2, 0, 27, 0, 1, 1, 1, 1, 2, 2, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0,
                1, 0, 0, 0, 0,
            ],
            Case::ConstructionCleanup => [
                1, 2, 1, 1, 0, 1, 0, 1, 0, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            Case::SuffixCleanup => [
                1, 2, 1, 1, 0, 2, 1, 1, 3, 24, 1, 1, 1, 1, 1, 2, 1, 1, 0, 0, 0, 0, 1, 24, 0, 0, 0,
                1, 1, 0, 0, 0,
            ],
            Case::PersistentCleanup => [
                1, 2, 2, 0, 0, 1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            Case::CleanupAtEof => [
                1, 0, 0, 0, 0, 1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        };
        if self.case == Case::PersistentCleanup {
            expected[29] = (self.operation.get() - 1) as u64;
        }
        assert_eq!(counts, expected, "atomic alias case {:?}", self.case);
        let observation = AliasObservation {
            case: self.case,
            addresses: self.addresses(),
            counters: counts,
        };
        eprintln!(
            "\natomic alias case={:?} operation={} counters={:?} addresses=AliasAddresses {{ base: {}, length: {}, wrong: {}, ambiguous: {}, operation: {} }}",
            observation.case,
            observation.addresses.operation,
            observation.counters,
            observation.addresses.base,
            observation.addresses.length,
            observation.addresses.wrong,
            observation.addresses.ambiguous,
            observation.addresses.operation,
        );
        observation
    }
}

pub(crate) const AMBIGUOUS_PHASE: &str =
    "failed writable-alias MAP_FIXED target retained until process exit (ownership unknown)";

#[derive(Clone, Copy)]
struct CaseCause {
    mapping: Option<ExpectedCause>,
    ambiguous: bool,
    cleanup_range: Option<(usize, usize)>,
    retention_id: Option<usize>,
}
impl CaseCause {
    fn for_case(
        case: Case,
        addresses: AliasAddresses,
        retention_id: Option<usize>,
    ) -> Option<Self> {
        let mapping = match case {
            Case::AtomicCollision => return None,
            _ if case.setup_succeeds() => None,
            Case::WrongAddress => Some(ExpectedCause::UnexpectedAddress),
            _ => Some(ExpectedCause::Errno(libc::ENOMEM)),
        };
        let ambiguous = matches!(
            case,
            Case::SecondExtent
                | Case::Foreign
                | Case::WrongAddress
                | Case::MiddleExtent
                | Case::ConstructionCleanup
                | Case::SuffixCleanup
        );
        let cleanup_range = match case {
            Case::CleanupAfterSuccess | Case::PersistentCleanup | Case::CleanupAtEof => {
                Some((addresses.base, addresses.length))
            }
            Case::ConstructionCleanup => Some((addresses.base, 2 * 4096)),
            Case::SuffixCleanup => Some((addresses.base + 3 * 4096, 2 * 4096)),
            _ => None,
        };
        Some(Self {
            mapping,
            ambiguous,
            cleanup_range,
            retention_id,
        })
    }
}

// Only the fixed ambiguous-target context is admitted, only on cases which
// deliberately create ambiguity, and only around their construction cause.
// Other context wrappers remain rejected. Each distinct leaf kind must retain
// its exact object identity across every repeated occurrence.
fn alias_case_cause(error: &crate::Error, expected: CaseCause) -> Option<&crate::Error> {
    struct Seen<'a> {
        mapping: Option<&'a crate::Error>,
        cleanup: Option<&'a crate::Error>,
        primary: Option<&'a crate::Error>,
    }
    fn same<'a>(slot: &mut Option<&'a crate::Error>, error: &'a crate::Error) -> bool {
        if let Some(previous) = slot {
            std::ptr::eq(*previous, error)
        } else {
            *slot = Some(error);
            true
        }
    }
    fn visit<'a>(
        error: &'a crate::Error,
        expected: CaseCause,
        seen: &mut Seen<'a>,
        context: bool,
        primary: bool,
    ) -> bool {
        match error {
            crate::Error::MemoryMapping(io) => {
                let matches = match expected.mapping {
                    Some(ExpectedCause::Errno(errno)) => io.raw_os_error() == Some(errno),
                    Some(ExpectedCause::UnexpectedAddress) => {
                        io.raw_os_error().is_none()
                            && io.kind() == std::io::ErrorKind::Other
                            && io.to_string() == UNEXPECTED_ADDRESS
                    }
                    None => false,
                };
                matches
                    && context == expected.ambiguous
                    && same(&mut seen.mapping, error)
                    && (!primary || same(&mut seen.primary, error))
            }
            crate::Error::WriteAliasCleanup {
                source,
                address,
                length,
                retention_id,
            } => {
                !context
                    && expected.cleanup_range == Some((*address, *length))
                    && source.raw_os_error() == Some(libc::ENOMEM)
                    && *retention_id != 0
                    && expected.retention_id.is_none_or(|id| id == *retention_id)
                    && same(&mut seen.cleanup, error)
                    && (!primary || same(&mut seen.primary, error))
            }
            crate::Error::SharedFailure(cause) => visit(cause, expected, seen, context, primary),
            crate::Error::WithCleanup {
                primary: cause,
                cleanup,
            } => {
                visit(cause, expected, seen, context, primary)
                    && cleanup
                        .iter()
                        .all(|cause| visit(cause, expected, seen, context, false))
            }
            crate::Error::Cleanup { phase, error } => {
                expected.ambiguous
                    && !context
                    && *phase == AMBIGUOUS_PHASE
                    && visit(error, expected, seen, true, primary)
            }
            _ => false,
        }
    }
    let mut seen = Seen {
        mapping: None,
        cleanup: None,
        primary: None,
    };
    if !visit(error, expected, &mut seen, false, true)
        || seen.mapping.is_some() != expected.mapping.is_some()
        || seen.cleanup.is_some() != expected.cleanup_range.is_some()
    {
        return None;
    }
    let wanted = if expected.mapping.is_some() {
        seen.mapping?
    } else {
        seen.cleanup?
    };
    seen.primary
        .filter(|primary| std::ptr::eq(*primary, wanted))
}

// Ownership may repeat a cause, but every leaf must retain that exact cause.
// Context-bearing errors are not ownership envelopes and must remain visible.
pub(crate) fn mapping_cause(error: &crate::Error) -> Option<&crate::Error> {
    mapping_cause_for_errno(error, libc::ENOMEM)
}

// Historical pure EEXIST predicate control remains strict. AtomicCollision
// is a successful operation and never calls this failure classifier.
pub(crate) fn mapping_collision_cause(error: &crate::Error) -> Option<&crate::Error> {
    mapping_cause_for_errno(error, libc::EEXIST)
}

const UNEXPECTED_ADDRESS: &str = "MAP_FIXED installed a writable alias at an unexpected address";

pub(crate) fn mapping_unexpected_address_cause(error: &crate::Error) -> Option<&crate::Error> {
    mapping_cause_expected(error, ExpectedCause::UnexpectedAddress)
}

#[derive(Clone, Copy)]
enum ExpectedCause {
    Errno(libc::c_int),
    UnexpectedAddress,
}

fn mapping_cause_for_errno(error: &crate::Error, errno: libc::c_int) -> Option<&crate::Error> {
    mapping_cause_expected(error, ExpectedCause::Errno(errno))
}

// Fixed public wrappers select the expected leaf independently of the observed
// result. Every repeated leaf must be the same object; context is never erased.
fn mapping_cause_expected(error: &crate::Error, expected: ExpectedCause) -> Option<&crate::Error> {
    fn visit<'a>(
        error: &'a crate::Error,
        original: &mut Option<&'a crate::Error>,
        expected: ExpectedCause,
    ) -> bool {
        match error {
            crate::Error::MemoryMapping(io) => {
                let matches = match expected {
                    ExpectedCause::Errno(errno) => io.raw_os_error() == Some(errno),
                    ExpectedCause::UnexpectedAddress => {
                        io.raw_os_error().is_none()
                            && io.kind() == std::io::ErrorKind::Other
                            && io.to_string() == UNEXPECTED_ADDRESS
                    }
                };
                if !matches {
                    return false;
                }
                if let Some(original) = original {
                    std::ptr::eq(*original, error)
                } else {
                    *original = Some(error);
                    true
                }
            }
            crate::Error::SharedFailure(cause) => visit(cause, original, expected),
            crate::Error::WithCleanup { primary, cleanup } => {
                visit(primary, original, expected)
                    && cleanup.iter().all(|cause| visit(cause, original, expected))
            }
            _ => false,
        }
    }
    let mut original = None;
    if visit(error, &mut original, expected) {
        original
    } else {
        None
    }
}

#[test]
fn mapping_failure_oracle_keeps_all_causes_and_context() {
    use std::sync::Arc;

    use crate::Error;

    let original = Arc::new(Error::MemoryMapping(std::io::Error::from_raw_os_error(
        libc::ENOMEM,
    )));
    let direct = Error::SharedFailure(original.clone());
    assert!(std::ptr::eq(mapping_cause(&direct).unwrap(), &*original));
    let positive = Error::WithCleanup {
        primary: Arc::new(Error::SharedFailure(Arc::new(Error::SharedFailure(
            original.clone(),
        )))),
        cleanup: vec![Arc::new(Error::SharedFailure(original.clone()))],
    };
    assert!(std::ptr::eq(mapping_cause(&positive).unwrap(), &*original));
    for extra in [
        Error::MemoryMapping(std::io::Error::from_raw_os_error(libc::ENOMEM)),
        Error::MemoryMapping(std::io::Error::from_raw_os_error(libc::EACCES)),
        Error::UnexpectedVcpuExit("unrelated cleanup failure".to_owned()),
    ] {
        let negative = Error::WithCleanup {
            primary: original.clone(),
            cleanup: vec![original.clone(), Arc::new(extra)],
        };
        assert!(mapping_cause(&negative).is_none(), "{negative:?}");
    }
    for context in [
        Error::WorkerFailure {
            tid: 3,
            error: original.clone(),
        },
        Error::Cleanup {
            phase: "unexpected cleanup context",
            error: original.clone(),
        },
        Error::SignalEffects {
            cause: original.clone(),
            dequeues: Vec::new(),
            acknowledged_through: 0,
            publications: Vec::new(),
            raw_result: None,
            context: None,
        },
        Error::ExecWorkerTeardown(Box::new(Error::SharedFailure(original.clone()))),
    ] {
        let negative = Error::WithCleanup {
            primary: original.clone(),
            cleanup: vec![Arc::new(context)],
        };
        assert!(mapping_cause(&negative).is_none(), "{negative:?}");
    }
}

// Controls for https://github.com/rrnewton/reverie/issues/813. The support
// module has this same libtest prefix in unit and integration test binaries.
#[test]
fn bounded_alias_child_records_exact_completion() {
    const TEST: &str = "alias_failure::bounded_alias_child_records_exact_completion";
    if let Some(fault) = child(TEST) {
        // Resolve the fixture in the child but leave it dormant. This tests the
        // subprocess execution contract independently of KVM or fault stages.
        assert!(matches!(fault.case, Case::Reservation | Case::SecondExtent));
    }
}

#[test]
fn bounded_alias_child_rejects_zero_matched_tests() {
    const MISSING: &str = "__reverie_deliberately_nonexistent_alias_failure_test__";
    let rejected = std::panic::catch_unwind(|| {
        let _ = child(MISSING);
    })
    .expect_err("the alias child helper accepted a zero-match child");
    let message = rejected
        .downcast_ref::<String>()
        .expect("the alias child helper did not emit a diagnostic");
    let expected =
        format!("{MISSING}: alias child execution record mismatch; stage=1; exit_code=Some(0)");
    assert!(
        message.lines().any(|line| line == expected),
        "unexpected alias child refusal: {message}"
    );
    assert!(
        message
            .lines()
            .any(|line| line == "execution records: \"\""),
        "the zero-match child unexpectedly recorded an execution: {message}"
    );
    assert!(
        message.lines().any(|line| line == "running 0 tests"),
        "the rejected child did not report zero matched tests: {message}"
    );
    assert!(
        message
            .lines()
            .any(|line| line
                .starts_with("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; ")),
        "the rejected child did not finish a successful zero-test run: {message}"
    );
}

#[test]
fn bounded_alias_child_rejects_forged_stdout_without_execution_record() {
    const TEST: &str =
        "alias_failure::bounded_alias_child_rejects_forged_stdout_without_execution_record";
    if std::env::var("REVERIE_ALIAS_FAILURE_TEST").as_deref() == Ok(TEST) {
        let forged = format!(
            "\ntest {TEST} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        );
        // SAFETY: the buffer is valid for this synchronous host write.
        assert_eq!(
            unsafe { libc::write(libc::STDOUT_FILENO, forged.as_ptr().cast(), forged.len()) },
            forged.len() as isize
        );
        // Exit before libtest writes its separate completion record.
        std::process::exit(0);
    }
    let rejected = std::panic::catch_unwind(|| {
        let _ = child(TEST);
    })
    .expect_err("the alias child helper accepted stdout without an execution record");
    let message = rejected
        .downcast_ref::<String>()
        .expect("the alias child helper did not emit a diagnostic");
    let expected =
        format!("{TEST}: alias child execution record mismatch; stage=1; exit_code=Some(0)");
    assert!(
        message.lines().any(|line| line == expected),
        "unexpected alias child refusal: {message}"
    );
    assert!(
        message
            .lines()
            .any(|line| line == "execution records: \"\""),
        "the prematurely exited child unexpectedly recorded an execution: {message}"
    );
    assert!(
        message.lines().any(|line| line == "running 1 test"),
        "the rejected child did not select the named test: {message}"
    );
    let forged_completion = format!("test {TEST} ... ok");
    assert!(
        message.lines().any(|line| line == forged_completion),
        "the rejected child did not emit forged stdout completion: {message}"
    );
}

#[test]
fn mapping_collision_oracle_keeps_all_causes_and_context() {
    use std::sync::Arc;

    use crate::Error;

    let original = Arc::new(Error::MemoryMapping(std::io::Error::from_raw_os_error(
        libc::EEXIST,
    )));
    let direct = Error::SharedFailure(original.clone());
    assert!(mapping_cause(&direct).is_none());
    assert!(mapping_cause_for_errno(&direct, libc::ENOMEM).is_none());
    assert!(std::ptr::eq(
        mapping_collision_cause(&direct).unwrap(),
        &*original
    ));
    let positive = Error::WithCleanup {
        primary: Arc::new(Error::SharedFailure(Arc::new(Error::SharedFailure(
            original.clone(),
        )))),
        cleanup: vec![Arc::new(Error::SharedFailure(original.clone()))],
    };
    assert!(std::ptr::eq(
        mapping_collision_cause(&positive).unwrap(),
        &*original
    ));
    for extra in [
        Error::MemoryMapping(std::io::Error::from_raw_os_error(libc::EEXIST)),
        Error::MemoryMapping(std::io::Error::from_raw_os_error(libc::ENOMEM)),
        Error::UnexpectedVcpuExit("unrelated cleanup failure".to_owned()),
    ] {
        let negative = Error::WithCleanup {
            primary: original.clone(),
            cleanup: vec![original.clone(), Arc::new(extra)],
        };
        assert!(mapping_collision_cause(&negative).is_none(), "{negative:?}");
    }
    for context in [
        Error::WorkerFailure {
            tid: 3,
            error: original.clone(),
        },
        Error::Cleanup {
            phase: "unexpected cleanup context",
            error: original.clone(),
        },
        Error::SignalEffects {
            cause: original.clone(),
            dequeues: Vec::new(),
            acknowledged_through: 0,
            publications: Vec::new(),
            raw_result: None,
            context: None,
        },
        Error::ExecWorkerTeardown(Box::new(Error::SharedFailure(original.clone()))),
    ] {
        let negative = Error::WithCleanup {
            primary: original.clone(),
            cleanup: vec![Arc::new(context)],
        };
        assert!(mapping_collision_cause(&negative).is_none(), "{negative:?}");
    }
}

#[test]
fn mapping_unexpected_address_oracle_keeps_all_causes_and_context() {
    use std::sync::Arc;

    use crate::Error;

    let original = Arc::new(Error::MemoryMapping(std::io::Error::other(
        UNEXPECTED_ADDRESS,
    )));
    let direct = Error::SharedFailure(original.clone());
    assert!(mapping_cause(&direct).is_none());
    assert!(mapping_cause_for_errno(&direct, libc::ENOMEM).is_none());
    assert!(std::ptr::eq(
        mapping_unexpected_address_cause(&direct).unwrap(),
        &*original
    ));
    let positive = Error::WithCleanup {
        primary: Arc::new(Error::SharedFailure(Arc::new(Error::SharedFailure(
            original.clone(),
        )))),
        cleanup: vec![Arc::new(Error::SharedFailure(original.clone()))],
    };
    assert!(std::ptr::eq(
        mapping_unexpected_address_cause(&positive).unwrap(),
        &*original
    ));
    for extra in [
        Error::MemoryMapping(std::io::Error::other(UNEXPECTED_ADDRESS)),
        Error::MemoryMapping(std::io::Error::from_raw_os_error(libc::EACCES)),
        Error::MemoryMapping(std::io::Error::other("a different protocol error")),
        Error::MemoryMapping(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            UNEXPECTED_ADDRESS,
        )),
        Error::UnexpectedVcpuExit("unrelated cleanup failure".to_owned()),
    ] {
        let negative = Error::WithCleanup {
            primary: original.clone(),
            cleanup: vec![original.clone(), Arc::new(extra)],
        };
        assert!(
            mapping_unexpected_address_cause(&negative).is_none(),
            "{negative:?}"
        );
    }
    for context in [
        Error::WorkerFailure {
            tid: 3,
            error: original.clone(),
        },
        Error::Cleanup {
            phase: "unexpected cleanup context",
            error: original.clone(),
        },
        Error::SignalEffects {
            cause: original.clone(),
            dequeues: Vec::new(),
            acknowledged_through: 0,
            publications: Vec::new(),
            raw_result: None,
            context: None,
        },
        Error::ExecWorkerTeardown(Box::new(Error::SharedFailure(original.clone()))),
    ] {
        let negative = Error::WithCleanup {
            primary: original.clone(),
            cleanup: vec![Arc::new(context)],
        };
        assert!(
            mapping_unexpected_address_cause(&negative).is_none(),
            "{negative:?}"
        );
    }
}

#[test]
fn atomic_alias_cause_oracle_requires_exact_context_ranges_and_identity() {
    use std::sync::Arc;

    use crate::Error;
    const BASE: usize = 0x10000;
    const ID: usize = 17;
    let addresses = AliasAddresses {
        base: BASE,
        length: 3 * 4096,
        wrong: 0,
        ambiguous: BASE + 2 * 4096,
        operation: 1,
    };
    let expected = CaseCause::for_case(Case::ConstructionCleanup, addresses, Some(ID)).unwrap();
    let mapping = Arc::new(Error::MemoryMapping(std::io::Error::from_raw_os_error(
        libc::ENOMEM,
    )));
    let wrapped = Arc::new(Error::Cleanup {
        phase: AMBIGUOUS_PHASE,
        error: mapping.clone(),
    });
    let cleanup = Arc::new(Error::WriteAliasCleanup {
        source: std::io::Error::from_raw_os_error(libc::ENOMEM),
        address: BASE,
        length: 2 * 4096,
        retention_id: ID,
    });
    let positive = Error::WithCleanup {
        primary: wrapped.clone(),
        cleanup: vec![cleanup.clone()],
    };
    assert!(std::ptr::eq(
        alias_case_cause(&positive, expected).unwrap(),
        &*mapping
    ));
    let repeated = Error::WithCleanup {
        primary: Arc::new(Error::SharedFailure(wrapped.clone())),
        cleanup: vec![wrapped.clone(), cleanup.clone(), cleanup.clone()],
    };
    assert!(std::ptr::eq(
        alias_case_cause(&repeated, expected).unwrap(),
        &*mapping
    ));
    // Same diagnostic values in a different allocation do not preserve cause identity.
    for extra in [
        Error::Cleanup {
            phase: AMBIGUOUS_PHASE,
            error: Arc::new(Error::MemoryMapping(std::io::Error::from_raw_os_error(
                libc::ENOMEM,
            ))),
        },
        Error::WriteAliasCleanup {
            source: std::io::Error::from_raw_os_error(libc::ENOMEM),
            address: BASE,
            length: 2 * 4096,
            retention_id: ID,
        },
        Error::UnexpectedVcpuExit("unrelated cleanup".to_owned()),
        Error::WorkerFailure {
            tid: 3,
            error: mapping.clone(),
        },
        Error::Cleanup {
            phase: "unrelated cleanup context",
            error: mapping.clone(),
        },
        Error::ExecWorkerTeardown(Box::new(Error::SharedFailure(mapping.clone()))),
    ] {
        let negative = Error::WithCleanup {
            primary: wrapped.clone(),
            cleanup: vec![cleanup.clone(), Arc::new(extra)],
        };
        assert!(
            alias_case_cause(&negative, expected).is_none(),
            "{negative:?}"
        );
    }
    for primary in [
        mapping.clone(),
        Arc::new(Error::Cleanup {
            phase: "wrong phase",
            error: mapping.clone(),
        }),
        Arc::new(Error::Cleanup {
            phase: AMBIGUOUS_PHASE,
            error: wrapped.clone(),
        }),
        Arc::new(Error::Cleanup {
            phase: AMBIGUOUS_PHASE,
            error: Arc::new(Error::MemoryMapping(std::io::Error::from_raw_os_error(
                libc::EACCES,
            ))),
        }),
    ] {
        let negative = Error::WithCleanup {
            primary,
            cleanup: vec![cleanup.clone()],
        };
        assert!(
            alias_case_cause(&negative, expected).is_none(),
            "{negative:?}"
        );
    }
    for (address, length, retention_id, errno) in [
        (BASE + 4096, 8192, ID, libc::ENOMEM),
        (BASE, 4096, ID, libc::ENOMEM),
        (BASE, 8192, 0, libc::ENOMEM),
        (BASE, 8192, ID + 1, libc::ENOMEM),
        (BASE, 8192, ID, libc::EACCES),
    ] {
        let negative = Error::WithCleanup {
            primary: wrapped.clone(),
            cleanup: vec![Arc::new(Error::WriteAliasCleanup {
                source: std::io::Error::from_raw_os_error(errno),
                address,
                length,
                retention_id,
            })],
        };
        assert!(
            alias_case_cause(&negative, expected).is_none(),
            "{negative:?}"
        );
    }
    assert!(alias_case_cause(&Error::SharedFailure(wrapped.clone()), expected).is_none());
    let reversed = Error::WithCleanup {
        primary: cleanup,
        cleanup: vec![wrapped.clone()],
    };
    assert!(
        alias_case_cause(&reversed, expected).is_none(),
        "construction cause lost precedence"
    );
    let plain = CaseCause::for_case(Case::Reservation, addresses, None).unwrap();
    assert!(alias_case_cause(&Error::SharedFailure(wrapped), plain).is_none());
    assert!(CaseCause::for_case(Case::AtomicCollision, addresses, None).is_none());
}

#[test]
fn atomic_alias_cleanup_primary_and_wrong_address_oracles_are_exact() {
    use std::sync::Arc;

    use crate::Error;
    const BASE: usize = 0x20000;
    const ID: usize = 29;
    let addresses = AliasAddresses {
        base: BASE,
        length: 3 * 4096,
        wrong: 0x40000,
        ambiguous: BASE + 2 * 4096,
        operation: 1,
    };
    for case in [
        Case::CleanupAfterSuccess,
        Case::PersistentCleanup,
        Case::CleanupAtEof,
    ] {
        let expected = CaseCause::for_case(case, addresses, Some(ID)).unwrap();
        let original = Arc::new(Error::WriteAliasCleanup {
            source: std::io::Error::from_raw_os_error(libc::ENOMEM),
            address: BASE,
            length: 3 * 4096,
            retention_id: ID,
        });
        let repeated = Error::WithCleanup {
            primary: original.clone(),
            cleanup: vec![original.clone()],
        };
        assert!(std::ptr::eq(
            alias_case_cause(&repeated, expected).unwrap(),
            &*original
        ));
        let context = Error::Cleanup {
            phase: AMBIGUOUS_PHASE,
            error: original,
        };
        assert!(alias_case_cause(&context, expected).is_none());
        let wrong_kind = Error::MemoryMapping(std::io::Error::from_raw_os_error(libc::ENOMEM));
        assert!(alias_case_cause(&wrong_kind, expected).is_none());
    }
    let expected = CaseCause::for_case(Case::WrongAddress, addresses, None).unwrap();
    let original = Arc::new(Error::MemoryMapping(std::io::Error::other(
        UNEXPECTED_ADDRESS,
    )));
    let positive = Error::Cleanup {
        phase: AMBIGUOUS_PHASE,
        error: original.clone(),
    };
    assert!(std::ptr::eq(
        alias_case_cause(&positive, expected).unwrap(),
        &*original
    ));
    for wrong in [
        std::io::Error::from_raw_os_error(libc::EACCES),
        std::io::Error::from_raw_os_error(libc::ENOMEM),
        std::io::Error::other(
            "MAP_FIXED_NOREPLACE installed a writable alias at an unexpected address",
        ),
        std::io::Error::other("another mapping protocol error"),
    ] {
        let negative = Error::Cleanup {
            phase: AMBIGUOUS_PHASE,
            error: Arc::new(Error::MemoryMapping(wrong)),
        };
        assert!(
            alias_case_cause(&negative, expected).is_none(),
            "{negative:?}"
        );
    }
}
