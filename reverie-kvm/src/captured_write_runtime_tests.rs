/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::sync::atomic::AtomicU64;

use reverie::CallbackSignalSite;
use reverie::SignalProcessId;
use reverie::syscalls::Write;

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

struct Unsupported;
impl GuestSyscallExecutor<Upper> for Unsupported {
    fn read_clock(&self) -> Result<u64> {
        panic!("capability query read a clock")
    }
    fn execute(&mut self, _: &SyscallRequest, _: &GuestMemory) -> Result<i64> {
        panic!("capability query executed a syscall")
    }
}
struct Capable {
    call: Write,
    site: CallbackSignalSite,
    queries: AtomicU64,
}
impl GuestSyscallExecutor<Upper> for Capable {
    fn read_clock(&self) -> Result<u64> {
        panic!("capability query read a clock")
    }
    fn execute(&mut self, _: &SyscallRequest, _: &GuestMemory) -> Result<i64> {
        panic!("capability query executed a syscall")
    }
    fn captured_write_signal_site(&self, call: Write) -> Option<CallbackSignalSite> {
        assert_eq!(call, self.call);
        self.queries.fetch_add(1, Ordering::SeqCst);
        Some(self.site)
    }
}

#[test]
fn captured_write_query_default_adapter_and_nested_guards_have_no_effects() {
    let call = Write::from(reverie::syscalls::SyscallArgs::new(2, 0x1234, 9, 4, 5, 6));
    let site = CallbackSignalSite {
        process: SignalProcessId {
            tgid: Pid::from_raw(1),
            generation: 7,
        },
        tid: Pid::from_raw(1),
        task_generation: 8,
        callback_nonce: 9,
        boundary_nonce: 9,
    };
    assert_eq!(Unsupported.captured_write_signal_site(call), None);
    let mut executor = Capable {
        call,
        site,
        queries: AtomicU64::new(0),
    };
    let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
    let mut state = Box::new(());
    let subscriptions = Subscription::none();
    let signal = Arc::new(Mutex::new(None));
    let starts = Arc::new(Mutex::new(Vec::new()));
    let stack = Arc::new(AtomicBool::new(false));
    {
        let mut guest = KvmGuest::<Upper>::new(
            Pid::from_raw(1),
            Pid::from_raw(1),
            Arc::new(Upper::default()),
            memory.clone(),
            &[],
            unsafe { std::mem::zeroed() },
            &mut state,
            &mut executor,
            &(),
            None,
            &(),
            &subscriptions,
            signal.clone(),
            starts.clone(),
            crate::bootstrap::TOOL_STACK_TOP,
            stack.clone(),
        );
        assert_eq!(guest.captured_write_signal_site(call), Some(site));
        assert_eq!(
            <_ as Guest<Lower>>::captured_write_signal_site(&guest.into_guest(), call),
            Some(site)
        );
        guest.notifying_dequeue = true;
        assert_eq!(guest.captured_write_signal_site(call), None);
        guest.notifying_dequeue = false;
        guest.observation_lease = Some(reverie::ParkedObservationLease { nonce: 1 });
        assert_eq!(guest.captured_write_signal_site(call), None);
        guest.observation_lease = None;
        stack.store(true, Ordering::Release);
        assert_eq!(guest.captured_write_signal_site(call), None);
        stack.store(false, Ordering::Release);
        assert_eq!(guest.captured_write_signal_site(call), Some(site));
    }
    assert_eq!(executor.queries.load(Ordering::SeqCst), 3);
    assert!(signal.lock().unwrap().is_none());
    assert!(starts.lock().unwrap().is_empty());
    let mut bytes = [0; 64];
    memory.read(0, &mut bytes).unwrap();
    assert_eq!(bytes, [0; 64]);
}
