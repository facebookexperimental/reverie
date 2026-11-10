//! `Guest::link_path` on a KVM guest is the executor's answer, through the
//! guest and through `IntoGuest`, for the thread ID and the link the Tool
//! names, and an adapter that keeps no descriptor table, image or working
//! directory does not provide it. Nothing is executed or signalled to answer
//! it.

use std::sync::atomic::AtomicU64;

use reverie::FactError;
use reverie::LinkPath;
use reverie::PathLink;

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
struct NoLinks;
#[reverie::provider]
impl LinuxProvider for NoLinks {
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
impl LinuxEmuSignalControl for NoLinks {}
impl LinuxEmuMemoryMap for NoLinks {}
impl GuestSyscallExecutor<Upper> for NoLinks {
    fn read_clock(&self) -> Result<u64> {
        panic!("a fact query read a clock")
    }
}

/// An adapter that answers for thread 7's descriptor 3 and its image, and
/// counts its queries.
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

    fn link_path(&self, tid: Pid, link: PathLink) -> std::result::Result<LinkPath, FactError> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        match (tid.as_raw(), link) {
            (7, PathLink::Descriptor(3)) => LinkPath::from_readlink(b"pipe:[42]"),
            (7, PathLink::Executable) => LinkPath::from_readlink(b"/bin/true"),
            (7, _) => Err(FactError::Errno(Errno::EBADF)),
            _ => Err(FactError::Errno(Errno::ESRCH)),
        }
    }
}

/// The links asked about, by thread: thread 7's descriptor 3, its image, its
/// descriptor 4, and thread 8's descriptor 3.
const ASKED: [(i32, PathLink); 4] = [
    (7, PathLink::Descriptor(3)),
    (7, PathLink::Executable),
    (7, PathLink::Descriptor(4)),
    (8, PathLink::Descriptor(3)),
];

/// Answers `link_path` for [`ASKED`] through a guest of thread 1 on
/// `executor`, directly and then through `IntoGuest`, with no other effect.
fn query(
    executor: &mut dyn GuestSyscallExecutor<Upper>,
) -> Vec<std::result::Result<LinkPath, FactError>> {
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
            .map(|&(tid, link)| guest.link_path(Pid::from_raw(tid), link))
            .collect();
        let wrapped = guest.into_guest();
        answers.extend(ASKED.iter().map(|&(tid, link)| {
            <_ as Guest<Lower>>::link_path(&wrapped, Pid::from_raw(tid), link)
        }));
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
fn a_guest_reports_its_executors_links() {
    let mut executor = Reporting {
        queries: AtomicU64::new(0),
    };
    let reported = [
        LinkPath::from_readlink(b"pipe:[42]"),
        LinkPath::from_readlink(b"/bin/true"),
        Err(FactError::Errno(Errno::EBADF)),
        Err(FactError::Errno(Errno::ESRCH)),
    ];
    assert_eq!(query(&mut executor), [reported.clone(), reported].concat());
    assert_eq!(executor.queries.load(Ordering::SeqCst), 8);
}

#[test]
fn an_adapter_without_links_does_not_provide_them() {
    assert_eq!(query(&mut NoLinks), vec![Err(FactError::NotProvided); 8]);
}
