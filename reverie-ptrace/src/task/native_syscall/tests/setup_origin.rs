/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

//! Concrete setup descriptors, separate from the unchanged Application oracle.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupKind {
    HostVdso {
        base: u64,
        len: u64,
    },
    #[cfg(target_arch = "x86_64")]
    Canonical,
}

#[derive(Debug, Clone)]
pub(super) struct SetupSeen {
    target: bool,
    kind: SetupKind,
    call: NativeSyscallCall,
    event: NativeSyscallEvent,
}

#[derive(Debug)]
struct SetupCookie {
    target: bool,
    kind: SetupKind,
}

impl NativeSyscallObserver for SetupCookie {
    fn observe(
        &self,
        call: &NativeSyscallCall,
        event: NativeSyscallEvent,
        _: Option<&dyn NativeSyscallFacts>,
    ) -> Result<(), Error> {
        evidence().lock().unwrap().setup_events.push(SetupSeen {
            target: self.target,
            kind: self.kind,
            call: call.clone(),
            event,
        });
        Ok(())
    }
}

/// The actual owned task's kernel mapping identifies the host-vDSO range.
/// A syscall number alone never exempts an Application call from its oracle.
pub(super) fn observe(
    pid: Pid,
    call: &NativeSyscallCall,
) -> Option<Arc<dyn NativeSyscallObserver>> {
    let target = evidence().lock().unwrap().setup_target;
    #[cfg(target_arch = "x86_64")]
    if call.args[0] == reverie::vdso::CANONICAL_VDSO_ADDRESS
        && (call.number == Sysno::mmap as u64 || call.number == Sysno::mprotect as u64)
    {
        assert!(target, "canonical mapping belongs to the actual exec image");
        assert_private(call);
        return Some(Arc::new(SetupCookie {
            target,
            kind: SetupKind::Canonical,
        }));
    }
    if call.number != Sysno::mprotect as u64 {
        return None;
    }
    let mappings = procfs::process::Process::new(pid.as_raw())
        .expect("live owned setup task")
        .maps()
        .expect("actual setup mappings");
    let vdso = mappings
        .0
        .iter()
        .find(|mapping| mapping.pathname == procfs::process::MMapPath::Vdso)
        .expect("clock-subscription control requires a native vDSO");
    if call.args[0] != vdso.address.0 {
        return None;
    }
    assert_private(call);
    Some(Arc::new(SetupCookie {
        target,
        kind: SetupKind::HostVdso {
            base: vdso.address.0,
            len: vdso.address.1 - vdso.address.0,
        },
    }))
}

fn assert_private(call: &NativeSyscallCall) {
    assert_eq!(call.purpose, NativeSyscallPurpose::BackendPrivate);
    assert!(!call.operation_bound);
    assert!(call.input_receipt.is_none());
    assert!(call.staged_image.is_none());
    assert_eq!(
        call.abi,
        NativeSyscallAbi::Linux {
            #[cfg(target_arch = "x86_64")]
            audit_arch: 0xc000_003e,
            #[cfg(target_arch = "aarch64")]
            audit_arch: 0xc000_00b7,
        }
    );
}

fn assert_pair(events: &[&SetupSeen], number: Sysno, args: [u64; 6], result: i64) {
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event, NativeSyscallEvent::ResumeIssued);
    assert_eq!(
        events[1].event,
        NativeSyscallEvent::NativeResult(Ok(result))
    );
    assert_eq!(events[0].call.id, events[1].call.id);
    for event in events {
        assert_private(&event.call);
        assert_eq!(event.call.number, number as u64);
        assert_eq!(event.call.args, args);
    }
}

pub(super) fn assert_complete_setup() {
    let events = evidence().lock().unwrap().setup_events.clone();
    for target in [false, true] {
        let host = events
            .iter()
            .filter(|event| {
                event.target == target && matches!(event.kind, SetupKind::HostVdso { .. })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            host.len(),
            4,
            "two actual host-vDSO protection calls: {events:?}"
        );
        let (base, len) = match host[0].kind {
            SetupKind::HostVdso { base, len } => (base, len),
            #[cfg(target_arch = "x86_64")]
            SetupKind::Canonical => unreachable!(),
        };
        assert!(
            host.iter()
                .all(|event| event.kind == (SetupKind::HostVdso { base, len }))
        );
        assert_pair(&host[..2], Sysno::mprotect, [base, len, 7, 0, 0, 0], 0);
        assert_pair(&host[2..], Sysno::mprotect, [base, len, 5, 0, 0, 0], 0);
        assert_ne!(host[0].call.id, host[2].call.id);
    }
    #[cfg(target_arch = "x86_64")]
    {
        let canonical = events
            .iter()
            .filter(|event| event.kind == SetupKind::Canonical)
            .collect::<Vec<_>>();
        assert_eq!(
            canonical.len(),
            4,
            "exact actual-exec mmap/mprotect pair: {events:?}"
        );
        assert!(canonical.iter().all(|event| event.target));
        let base = reverie::vdso::CANONICAL_VDSO_ADDRESS;
        let len = reverie::vdso::CANONICAL_VDSO_SIZE;
        assert_pair(
            &canonical[..2],
            Sysno::mmap,
            [
                base,
                len,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64,
                (-1i64) as u64,
                0,
            ],
            base as i64,
        );
        assert_pair(
            &canonical[2..],
            Sysno::mprotect,
            [
                base,
                len,
                (libc::PROT_READ | libc::PROT_EXEC) as u64,
                0,
                0,
                0,
            ],
            0,
        );
        assert_ne!(canonical[0].call.id, canonical[2].call.id);
    }
}
