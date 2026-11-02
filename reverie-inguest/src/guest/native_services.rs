/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Borrowed native mechanisms selected inside the common in-process Guest.
//! No Tool, allocator, thread state or lifecycle authority lives in this table.

use std::io;

use reverie::Pid;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::MemoryAccess;

use super::native_rpc::NativeInvocation;

/// Translate the current native machine context, returning nonzero on success.
pub type RegisterReader = unsafe extern "C" fn(usize, *mut libc::user_regs_struct) -> i32;
/// Update that context's integer registers, retaining native IP/FP/SIMD policy.
pub type RegisterWriter = unsafe extern "C" fn(usize, *const libc::user_regs_struct) -> i32;
/// The native owner's aligned, fault-checked atomic operation: 0 is success,
/// negative is the original errno, and a positive status is invalid.
pub type MemoryCompareExchange = unsafe extern "C" fn(usize, u32, u32, *mut u32) -> i32;

/// Actual native mechanism pointers, borrowed from the live image owner.
/// These select operations, not scheduling, image admission or Tool policy.
pub struct NativeServiceTable {
    /// The actual context translator.
    pub read_registers: RegisterReader,
    /// The actual context updater.
    pub write_registers: RegisterWriter,
    /// None keeps the existing unsupported atomic-memory result.
    pub compare_exchange_u32: Option<MemoryCompareExchange>,
    /// Actual controller admission/query operation, if this image has one.
    pub controller_capture: Option<ControllerCaptureControl>,
    /// A missing/lost provider remains explicitly unavailable, not ordinary memory.
    pub private_memory: Option<RuntimePrivateMemoryQuery>,
    /// The real fixed-buffer transaction with native restoration semantics.
    pub mapping_capture: Option<super::native_capture::MappingCapture>,
    /// Existing native fault-safe reader for stack inspection, when installed.
    pub read_memory: Option<MemoryReader>,
}

/// Facts sampled by the same native callback as the service context.
/// They describe the event; none authorizes initial/successor image entry.
pub struct NativeEventFacts<'callback> {
    /// Actual in-tree parent, or None for the admitted tree root.
    pub parent: Option<Pid>,
    /// Retired branches sampled at the native owner's existing boundary.
    pub branches: u64,
    /// Whether this image actually sends CPUID to the Tool.
    pub cpuid_interception: bool,
    /// Already qualified native spelling; Unknown remains unknown.
    pub pidfd_self_spelling: reverie::PidfdSelfSpelling,
    /// The actual application's auxiliary vector, not the native loader's.
    pub auxv: &'callback [(libc::c_ulong, libc::c_ulong)],
    /// Present only when observed at the actual initial instruction boundary.
    pub initial_stack: Option<u64>,
    /// Authentic owned siginfo, only during this signal's native continuation.
    pub signal_info: Option<[u8; reverie::SIGNAL_INFO_SIZE]>,
}

/// An observation point in the actual native Tool callback path.
/// These names carry no callback, lifecycle or image-entry permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEntryStage {
    /// Immediately before the real thread-start hook.
    StartEnter,
    /// After that hook completed successfully.
    StartComplete,
    /// Immediately before the real post-exec hook.
    PostExecEnter,
    /// After that hook completed successfully.
    PostExecComplete,
    /// Immediately before an actual native syscall Tool handler.
    Syscall,
}

/// Read-only inspection of this exact admitted native callback.
/// No writer, invoker, Tool/state reference or continuation escapes this view.
pub struct NativeEntryObservation<'observation, 'callback> {
    services: &'observation NativeServices<'callback>,
}

impl<'observation, 'callback> NativeEntryObservation<'observation, 'callback> {
    #[cfg(feature = "native-entry-observer")]
    pub(super) fn new(services: &'observation NativeServices<'callback>) -> Self {
        Self { services }
    }

    /// Preserve the actual native reader's status and sampled registers.
    pub fn read_registers(&self, registers: &mut libc::user_regs_struct) -> Result<i32, Errno> {
        self.services
            .invocation
            .ensure_current()
            .map_err(|_| Errno::ESTALE)?;
        Ok(unsafe {
            (self.services.table.read_registers)(self.services.invocation.context(), registers)
        })
    }

    /// Use the current callback's existing fault-aware memory implementation.
    /// Original short counts and errors are retained; no direct guest dereference.
    pub fn read_memory(&self, address: usize, output: &mut [u8]) -> Result<usize, Errno> {
        let address = Addr::from_raw(address).ok_or(Errno::EFAULT)?;
        self.services.memory().read(address, output)
    }
}

/// A live native callback's borrowed mechanisms and actual sampled facts.
pub struct NativeServices<'callback> {
    invocation: NativeInvocation<'callback>,
    table: &'callback NativeServiceTable,
    facts: NativeEventFacts<'callback>,
}

impl<'callback> NativeServices<'callback> {
    /// Select the actual image/task's services for this one callback.
    ///
    /// # Safety
    /// The native owner must validate the current table, task and image, and
    /// keep every pointer/fact live through all Tool futures and deferred
    /// native use. Register functions preserve the existing native integer,
    /// instruction-pointer, FP/SIMD and signal-context contracts. Atomic memory
    /// must be the real indivisible checked operation, never read-then-write.
    /// Construction does not enter a callback, grant private authority, or
    /// select an allocator/TLS implementation.
    pub unsafe fn from_admitted(
        invocation: NativeInvocation<'callback>,
        table: &'callback NativeServiceTable,
        facts: NativeEventFacts<'callback>,
    ) -> io::Result<Self> {
        invocation.ensure_current()?;
        Ok(Self {
            invocation,
            table,
            facts,
        })
    }

    /// The actual callback whose pointer is never cached by RPC.
    pub fn invocation(&self) -> NativeInvocation<'callback> {
        self.invocation
    }
    /// The original sampled event facts.
    pub fn facts(&self) -> &NativeEventFacts<'callback> {
        &self.facts
    }

    pub(super) fn regs(&self) -> Result<libc::user_regs_struct, Errno> {
        self.invocation
            .ensure_current()
            .map_err(|_| Errno::ESTALE)?;
        let mut regs = unsafe { core::mem::zeroed() };
        if unsafe { (self.table.read_registers)(self.invocation.context(), &mut regs) } == 0 {
            Err(Errno::EIO)
        } else {
            Ok(regs)
        }
    }

    pub(super) fn set_regs(&self, regs: &libc::user_regs_struct) -> Result<(), Errno> {
        self.invocation
            .ensure_current()
            .map_err(|_| Errno::ESTALE)?;
        if unsafe { (self.table.write_registers)(self.invocation.context(), regs) } == 0 {
            Err(Errno::EIO)
        } else {
            Ok(())
        }
    }

    pub(super) fn capture(&self) -> Option<super::native_capture::MappingCapture> {
        self.table.mapping_capture
    }

    pub(super) fn controller_fact(&self) -> Option<reverie::ControllerCaptureFact> {
        self.invocation.ensure_current().ok()?;
        let control = self.table.controller_capture?;
        let mut fact = NativeControllerCaptureFact::default();
        if unsafe { control(self.invocation.context(), 0, &mut fact) } != 1
            || fact.physical_pid <= 0
            || fact.physical_tid <= 0
            || fact.procfs_inode == 0
        {
            return None;
        }
        Some(reverie::ControllerCaptureFact {
            physical_pid: Pid::from_raw(fact.physical_pid),
            physical_tid: Pid::from_raw(fact.physical_tid),
            procfs_device: fact.procfs_device,
            procfs_inode: fact.procfs_inode,
        })
    }

    pub(super) fn acknowledge_tool_admission(&self) {
        if self.invocation.ensure_current().is_ok()
            && let Some(control) = self.table.controller_capture
        {
            let mut ignored = NativeControllerCaptureFact::default();
            // Failure keeps controller capture unavailable, without changing
            // the Tool hook's outcome or bypassing native admission.
            unsafe { control(self.invocation.context(), 1, &mut ignored) };
        }
    }

    pub(super) fn private_regions(&self) -> reverie::RuntimePrivateMemory {
        let snapshot = self.table.private_memory.and_then(|query| {
            self.invocation.ensure_current().ok()?;
            let mut native = NativePrivateMemorySnapshot::default();
            (unsafe { query(self.invocation.context(), std::ptr::null(), &mut native) } == 1)
                .then(|| decode_private_memory(native))
                .flatten()
        });
        match snapshot {
            Some(value) => reverie::RuntimePrivateMemory::Ready(value),
            None => reverie::RuntimePrivateMemory::Unavailable,
        }
    }

    pub(super) fn private_is_current(
        &self,
        snapshot: &reverie::RuntimePrivateMemorySnapshot,
    ) -> bool {
        let Some(query) = self.table.private_memory else {
            return false;
        };
        let Some(expected) = NativePrivateMemorySnapshot::from_shared(snapshot) else {
            return false;
        };
        if self.invocation.ensure_current().is_err() {
            return false;
        }
        let mut actual = NativePrivateMemorySnapshot::default();
        unsafe {
            query(self.invocation.context(), &expected, &mut actual) == 1 && actual == expected
        }
    }

    pub(super) fn read_word(&self, address: u64) -> Option<u64> {
        self.invocation.ensure_current().ok()?;
        let mut word = 0_u64;
        if let Some(read) = self.table.read_memory {
            (unsafe { read(address as usize, (&mut word as *mut u64).cast(), 8) } == 1)
                .then_some(word)
        } else {
            let address = Addr::from_raw(address as usize)?;
            (self
                .memory()
                .read(address, unsafe {
                    std::slice::from_raw_parts_mut((&mut word as *mut u64).cast(), 8)
                })
                .ok()?
                == 8)
                .then_some(word)
        }
    }

    pub(super) fn memory(&self) -> NativeMemory<'callback> {
        NativeMemory {
            invocation: self.invocation,
            table: self.table,
        }
    }
}

/// Native inspection uses the same one-shot kernel copy semantics as
/// LocalMemory, through this callback's real invoker. It retains no guest
/// references and never retries a partial transfer.
#[derive(Clone, Copy)]
pub(super) struct NativeMemory<'callback> {
    invocation: NativeInvocation<'callback>,
    table: &'callback NativeServiceTable,
}

#[repr(C)]
struct Iovec {
    base: usize,
    length: usize,
}

impl NativeMemory<'_> {
    fn copy(
        &self,
        number: i64,
        local: usize,
        local_count: usize,
        remote: usize,
        remote_count: usize,
    ) -> Result<usize, Errno> {
        // Like LocalMemory, obtain the current physical PID at each copy and
        // preserve the original native count/errno. The current-owner check
        // runs before either native syscall and before any guest effect.
        self.invocation
            .ensure_current()
            .map_err(|_| Errno::ESTALE)?;
        let pid = unsafe {
            self.invocation.invoke(
                libc::SYS_getpid,
                [0; 6],
                reverie::InjectionPurpose::Application,
            )
        };
        let pid = Errno::from_ret(pid as usize)?;
        let value = unsafe {
            self.invocation.invoke(
                number,
                [
                    pid as u64,
                    local as u64,
                    local_count as u64,
                    remote as u64,
                    remote_count as u64,
                    0,
                ],
                reverie::InjectionPurpose::Application,
            )
        };
        Errno::from_ret(value as usize)
    }
}

fn vectored_result(value: Result<usize, Errno>) -> Result<usize, Errno> {
    match value {
        Err(Errno::EFAULT) => Ok(0),
        value => value,
    }
}

impl MemoryAccess for NativeMemory<'_> {
    fn read_vectored(
        &self,
        from: &[io::IoSlice],
        to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        vectored_result(self.copy(
            libc::SYS_process_vm_readv,
            to.as_ptr() as usize,
            to.len(),
            from.as_ptr() as usize,
            from.len(),
        ))
    }
    fn write_vectored(
        &mut self,
        from: &[io::IoSlice],
        to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        vectored_result(self.copy(
            libc::SYS_process_vm_writev,
            from.as_ptr() as usize,
            from.len(),
            to.as_ptr() as usize,
            to.len(),
        ))
    }
    fn read<'a, A>(&self, address: A, bytes: &mut [u8]) -> Result<usize, Errno>
    where
        A: Into<Addr<'a, u8>>,
    {
        let address = address.into();
        if bytes.is_empty() {
            return Ok(0);
        }
        address
            .as_raw()
            .checked_add(bytes.len())
            .ok_or(Errno::EFAULT)?;
        let remote = Iovec {
            base: address.as_raw(),
            length: bytes.len(),
        };
        let local = Iovec {
            base: bytes.as_mut_ptr() as usize,
            length: bytes.len(),
        };
        self.copy(
            libc::SYS_process_vm_readv,
            &local as *const _ as usize,
            1,
            &remote as *const _ as usize,
            1,
        )
    }
    fn write(&mut self, address: AddrMut<u8>, bytes: &[u8]) -> Result<usize, Errno> {
        if bytes.is_empty() {
            return Ok(0);
        }
        address
            .as_raw()
            .checked_add(bytes.len())
            .ok_or(Errno::EFAULT)?;
        let remote = Iovec {
            base: address.as_raw(),
            length: bytes.len(),
        };
        let local = Iovec {
            base: bytes.as_ptr() as usize,
            length: bytes.len(),
        };
        self.copy(
            libc::SYS_process_vm_writev,
            &local as *const _ as usize,
            1,
            &remote as *const _ as usize,
            1,
        )
    }
    fn write_with_user_access(
        &mut self,
        address: AddrMut<u8>,
        bytes: &[u8],
    ) -> Result<usize, Errno> {
        match self.write(address, bytes)? {
            0 if !bytes.is_empty() => Err(Errno::EFAULT),
            copied => Ok(copied),
        }
    }
    fn compare_exchange_u32(
        &mut self,
        address: AddrMut<u32>,
        expected: u32,
        desired: u32,
    ) -> Result<u32, Errno> {
        self.invocation
            .ensure_current()
            .map_err(|_| Errno::ESTALE)?;
        let compare = self.table.compare_exchange_u32.ok_or(Errno::ENOSYS)?;
        let mut observed = 0;
        let status = unsafe { compare(address.as_raw(), expected, desired, &mut observed) };
        match status {
            0 => Ok(observed),
            value if value < 0 => Err(Errno::new(-value)),
            _ => Err(Errno::EPROTO),
        }
    }
}

/// Existing fault-safe native application-memory reader.
pub type MemoryReader = unsafe extern "C" fn(usize, *mut u8, usize) -> i32;

/// Fixed native controller fact. It contains observations, not admission.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeControllerCaptureFact {
    /// Actual operating-system process.
    pub physical_pid: i32,
    /// Actual operating-system task.
    pub physical_tid: i32,
    /// Device of the held proc identity.
    pub procfs_device: u64,
    /// Inode of the held proc identity.
    pub procfs_inode: u64,
}

/// Operation zero queries; operation one acknowledges the actual successful
/// Tool thread-start callback. Output bytes are initialized on every result.
pub type ControllerCaptureControl =
    unsafe extern "C" fn(usize, u32, *mut NativeControllerCaptureFact) -> i32;

/// Fixed eight-interval native ownership representation. Its token is checked
/// by the original producer; copying it creates no runtime authority.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativePrivateMemorySnapshot {
    /// Original authenticated table/slot/image tuple.
    pub owner: [u64; 4],
    /// Original non-reused ownership version.
    pub version: u64,
    /// One is ready, zero explicitly unavailable.
    pub state: u32,
    /// At most eight initialized intervals.
    pub count: u32,
    /// Original reservations and initialized image pages.
    pub ranges: [[u64; 2]; 8],
}

/// Null expected queries; nonnull expected validates that exact target token.
pub type RuntimePrivateMemoryQuery = unsafe extern "C" fn(
    usize,
    *const NativePrivateMemorySnapshot,
    *mut NativePrivateMemorySnapshot,
) -> i32;

const _: () = {
    assert!(std::mem::size_of::<NativeControllerCaptureFact>() == 24);
    assert!(std::mem::size_of::<NativePrivateMemorySnapshot>() == 176);
};

impl NativePrivateMemorySnapshot {
    pub(super) fn from_shared(snapshot: &reverie::RuntimePrivateMemorySnapshot) -> Option<Self> {
        if snapshot.regions.is_empty() || snapshot.regions.len() > 8 {
            return None;
        }
        let mut expected = Self {
            owner: snapshot.owner,
            version: snapshot.version,
            state: 1,
            count: snapshot.regions.len() as u32,
            ..Self::default()
        };
        for (range, region) in expected.ranges.iter_mut().zip(&snapshot.regions) {
            *range = [region.start, region.end];
        }
        Some(expected)
    }
}

fn decode_private_memory(
    native: NativePrivateMemorySnapshot,
) -> Option<reverie::RuntimePrivateMemorySnapshot> {
    if native.state != 1 || native.count == 0 || native.count > 8 || native.version == 0 {
        return None;
    }
    if native.ranges[native.count as usize..]
        .iter()
        .any(|range| *range != [0, 0])
    {
        return None;
    }
    let mut regions = Vec::with_capacity(native.count as usize);
    let mut previous_end = 0;
    for [start, end] in native.ranges[..native.count as usize].iter().copied() {
        if start >= end || start < previous_end {
            return None;
        }
        previous_end = end;
        regions.push(reverie::RuntimePrivateMemoryRegion { start, end });
    }
    Some(reverie::RuntimePrivateMemorySnapshot {
        owner: native.owner,
        version: native.version,
        regions,
    })
}
