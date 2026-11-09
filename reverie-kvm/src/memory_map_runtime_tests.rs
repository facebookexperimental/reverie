//! `Guest::memory_map` on a KVM guest is the executor's answer, through the
//! guest and through `IntoGuest`, for the thread ID the Tool names, and an
//! adapter that keeps no record of the address space does not provide it.
//! Nothing is executed or signalled to answer it.

use std::sync::atomic::AtomicU64;

use reverie::FactError;
use reverie::MappingBacking;
use reverie::MappingFact;
use reverie::MemoryMap;

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
struct NoMap;
#[reverie::provider]
impl LinuxProvider for NoMap {
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
impl LinuxEmuSignalControl for NoMap {}
impl LinuxEmuMemoryMap for NoMap {}
impl GuestSyscallExecutor<Upper> for NoMap {
    fn read_clock(&self) -> Result<u64> {
        panic!("a fact query read a clock")
    }
}

/// The map [`Reporting`] answers for thread 7: a stack, not complete.
fn reported_map() -> MemoryMap {
    MemoryMap::new(
        vec![
            MappingFact::new(
                0x7fff_ff80_0000,
                0x7fff_ffff_f000,
                (libc::PROT_READ | libc::PROT_WRITE) as u32,
                false,
                0,
                MappingBacking::Stack,
            )
            .unwrap(),
        ],
        false,
    )
    .unwrap()
}

/// An adapter that answers for thread 7, and counts its queries.
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

    fn memory_map(&self, tid: Pid) -> std::result::Result<MemoryMap, FactError> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        match tid.as_raw() {
            7 => Ok(reported_map()),
            8 => Err(FactError::NotProvided),
            _ => Err(FactError::Errno(Errno::ESRCH)),
        }
    }
}

/// The threads asked about: 7, 8 and 9.
const ASKED: [i32; 3] = [7, 8, 9];

/// Answers `memory_map` for [`ASKED`] through a guest of thread 1 on
/// `executor`, directly and then through `IntoGuest`, with no other effect.
fn query(
    executor: &mut dyn GuestSyscallExecutor<Upper>,
) -> Vec<std::result::Result<MemoryMap, FactError>> {
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
        let mut answers: Vec<_> = ASKED
            .iter()
            .map(|&tid| guest.memory_map(Pid::from_raw(tid)))
            .collect();
        let wrapped = guest.into_guest();
        answers.extend(
            ASKED
                .iter()
                .map(|&tid| <_ as Guest<Lower>>::memory_map(&wrapped, Pid::from_raw(tid))),
        );
        answers
    };
    assert!(signal.lock().unwrap().is_none());
    assert!(starts.lock().unwrap().is_empty());
    let mut bytes = [0; 64];
    memory.read(0, &mut bytes).unwrap();
    assert_eq!(bytes, [0; 64]);
    answers
}

#[test]
fn a_guest_reports_its_executors_map() {
    let mut executor = Reporting {
        queries: AtomicU64::new(0),
    };
    let reported = [
        Ok(reported_map()),
        Err(FactError::NotProvided),
        Err(FactError::Errno(Errno::ESRCH)),
    ];
    assert_eq!(query(&mut executor), [reported.clone(), reported].concat());
    assert_eq!(executor.queries.load(Ordering::SeqCst), 6);
}

#[test]
fn an_adapter_without_a_map_does_not_provide_it() {
    assert_eq!(query(&mut NoMap), vec![Err(FactError::NotProvided); 6]);
}
