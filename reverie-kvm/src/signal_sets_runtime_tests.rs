//! `Guest::signal_sets` on a KVM guest is the executor's answer, through the
//! guest and through `IntoGuest`, for the thread ID the Tool names, and an
//! adapter that keeps no signal state does not provide it. Nothing is
//! executed or signalled to answer it.

use std::sync::atomic::AtomicU64;

use reverie::FactError;
use reverie::SignalSets;

use super::*;

#[derive(Default)]
struct Lower;
#[reverie::tool]
impl Tool for Lower {
    type GlobalState = ();
    type ThreadState = ();
}
#[derive(Default)]
struct Upper(Lower);
impl AsMut<Lower> for Upper {
    fn as_mut(&mut self) -> &mut Lower {
        &mut self.0
    }
}
#[reverie::tool]
impl Tool for Upper {
    type GlobalState = ();
    type ThreadState = Box<()>;
}

/// An adapter that takes every default, as a caller-supplied executor does.
struct NoSignalState;
#[reverie::provider]
impl LinuxProvider for NoSignalState {
    type Context = GuestMemory;
    type Plan = crate::executor::StagedProcessAction;
    type Error = crate::Error;

    async fn execute(
        &mut self,
        _: reverie::Tid,
        _: &ProviderRequest,
        _: &mut GuestMemory,
    ) -> Result<ProviderOutcome> {
        panic!("a fact query executed a syscall")
    }
}
impl LinuxEmuSignalControl for NoSignalState {}
impl LinuxEmuMemoryMap for NoSignalState {}
impl GuestSyscallExecutor<Upper> for NoSignalState {
    fn read_clock(&self) -> Result<u64> {
        panic!("a fact query read a clock")
    }
}

/// An adapter that answers for thread 7 and counts its queries.
struct Reporting {
    queries: AtomicU64,
}
#[reverie::provider]
impl LinuxProvider for Reporting {
    type Context = GuestMemory;
    type Plan = crate::executor::StagedProcessAction;
    type Error = crate::Error;

    async fn execute(
        &mut self,
        _: reverie::Tid,
        _: &ProviderRequest,
        _: &mut GuestMemory,
    ) -> Result<ProviderOutcome> {
        panic!("a fact query executed a syscall")
    }
}
impl LinuxEmuSignalControl for Reporting {}
impl LinuxEmuMemoryMap for Reporting {}
impl GuestSyscallExecutor<Upper> for Reporting {
    fn read_clock(&self) -> Result<u64> {
        panic!("a fact query read a clock")
    }

    fn signal_sets(&self, tid: Pid) -> std::result::Result<SignalSets, FactError> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        match tid.as_raw() {
            7 => Ok(reported()),
            _ => Err(FactError::Errno(Errno::ESRCH)),
        }
    }
}

/// Distinct sets, so that an answer in the wrong field shows.
fn reported() -> SignalSets {
    SignalSets::new(0x200, 0x800, 0x4002, 0x1, 0x4000)
}

/// Answers `signal_sets` for threads 7 and 8 through a guest of thread 1 on
/// `executor`, directly and through `IntoGuest`, with no other effect.
fn query(
    executor: &mut dyn GuestSyscallExecutor<Upper>,
) -> [std::result::Result<SignalSets, FactError>; 4] {
    let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
    let mut state = Box::new(());
    let subscriptions = Subscription::none();
    let signal = Arc::new(Mutex::new(None));
    let starts = Arc::new(Mutex::new(Vec::new()));
    let answers = {
        let mut guest = KvmGuest::<Upper>::new(
            Pid::from_raw(1),
            Pid::from_raw(1),
            Arc::new(Upper::default()),
            memory.clone(),
            &[],
            &crate::runtime::ZEROED_USER_REGISTERS,
            &mut state,
            executor,
            &(),
            None,
            &(),
            &subscriptions,
            signal.clone(),
            starts.clone(),
            crate::bootstrap::TOOL_STACK_TOP,
            Arc::new(AtomicBool::new(false)),
        );
        let direct = [
            guest.signal_sets(Pid::from_raw(7)),
            guest.signal_sets(Pid::from_raw(8)),
        ];
        let wrapped = guest.into_guest();
        [
            direct[0],
            direct[1],
            <_ as Guest<Lower>>::signal_sets(&wrapped, Pid::from_raw(7)),
            <_ as Guest<Lower>>::signal_sets(&wrapped, Pid::from_raw(8)),
        ]
    };
    assert!(signal.lock().unwrap().is_none());
    assert!(starts.lock().unwrap().is_empty());
    let mut bytes = [0; 64];
    memory.read(0, &mut bytes).unwrap();
    assert_eq!(bytes, [0; 64]);
    answers
}

#[test]
fn a_guest_reports_its_executors_signal_sets() {
    let mut executor = Reporting {
        queries: AtomicU64::new(0),
    };
    let esrch = Err(FactError::Errno(Errno::ESRCH));
    assert_eq!(
        query(&mut executor),
        [Ok(reported()), esrch, Ok(reported()), esrch]
    );
    assert_eq!(executor.queries.load(Ordering::SeqCst), 4);
}

#[test]
fn an_adapter_without_signal_state_does_not_provide_it() {
    let not_provided = Err(FactError::NotProvided);
    assert_eq!(
        query(&mut NoSignalState),
        [not_provided, not_provided, not_provided, not_provided]
    );
}
