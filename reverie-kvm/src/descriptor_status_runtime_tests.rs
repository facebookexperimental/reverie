//! `Guest::descriptor_status` on a KVM guest is the executor's answer, through
//! the guest and through `IntoGuest`, and an adapter that keeps no descriptor
//! table does not provide it. Nothing is executed or signalled to answer it.

use std::sync::atomic::AtomicU64;

use reverie::DescriptorStatus;
use reverie::FactError;

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
struct NoTable;
#[reverie::provider]
impl LinuxProvider for NoTable {
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
impl LinuxEmuSignalControl for NoTable {}
impl LinuxEmuMemoryMap for NoTable {}
impl GuestSyscallExecutor<Upper> for NoTable {
    fn read_clock(&self) -> Result<u64> {
        panic!("a fact query read a clock")
    }
}

/// An adapter that answers descriptor 7 and counts its queries.
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

    fn descriptor_status(&self, fd: i32) -> std::result::Result<DescriptorStatus, FactError> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        match fd {
            7 => reported(),
            _ => Err(FactError::Errno(Errno::EBADF)),
        }
    }
}

fn reported() -> std::result::Result<DescriptorStatus, FactError> {
    DescriptorStatus::from_fdinfo(b"pos:\t0\nflags:\t02\neventfd-count:                9\n")
}

/// Answers `descriptor_status` for descriptors 7 and 8 through a guest on
/// `executor`, directly and through `IntoGuest`, with no other effect.
fn query(
    executor: &mut dyn GuestSyscallExecutor<Upper>,
) -> [std::result::Result<DescriptorStatus, FactError>; 4] {
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
        let direct = [guest.descriptor_status(7), guest.descriptor_status(8)];
        let wrapped = guest.into_guest();
        [
            direct[0].clone(),
            direct[1].clone(),
            <_ as Guest<Lower>>::descriptor_status(&wrapped, 7),
            <_ as Guest<Lower>>::descriptor_status(&wrapped, 8),
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
fn a_guest_reports_its_executors_descriptor_status() {
    let mut executor = Reporting {
        queries: AtomicU64::new(0),
    };
    let ebadf = Err(FactError::Errno(Errno::EBADF));
    assert_eq!(
        query(&mut executor),
        [reported(), ebadf.clone(), reported(), ebadf]
    );
    assert_eq!(reported().unwrap().eventfd_count, Some(9));
    assert_eq!(executor.queries.load(Ordering::SeqCst), 4);
}

#[test]
fn an_adapter_without_a_descriptor_table_does_not_provide_it() {
    let not_provided = Err(FactError::NotProvided);
    assert_eq!(
        query(&mut NoTable),
        [
            not_provided.clone(),
            not_provided.clone(),
            not_provided.clone(),
            not_provided
        ]
    );
}
