//! Physical first-image preparation for the explicit private musl artifact.
//!
//! No function here redeems RPC admission or installs Detcore. These affine
//! views borrow the host's retained physical owner; they never own/unmap an
//! image and are not a second allocator, publication slot or readiness owner.
/// Finite same-owner private-libc bootstrap syscall relay.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub mod libc_relay;
/// Checked immutable scalar input representation.
pub mod mapped_scalar;

use mapped_scalar::ConsumerLayout;
use mapped_scalar::ProductionMappedInputs;
use reverie_loader::handoff::Bootstrap;
use reverie_loader::handoff::Registers;
use reverie_loader::handoff::View;

/// Exact scalar codec revision linked into this private consumer.
pub const MAPPED_INPUT_VERSION: u64 = reverie_loader::handoff::VERSION;
/// Exact scalar header bytes linked into this private consumer.
pub const MAPPED_INPUT_HEADER_BYTES: usize = reverie_loader::handoff::HEADER_BYTES;
/// Exact complete scalar input byte cap linked into this private consumer.
pub const MAPPED_INPUT_MAX_BYTES: usize = reverie_loader::handoff::MAX_BYTES;

use core::marker::PhantomData;
use core::ptr::NonNull;
use core::ptr::addr_of;
use core::ptr::addr_of_mut;

use super::InitialImageControl;
use super::NativeControl;
use super::PrivateCode;
use super::PrivateMap;
use crate::guest::tool_region::MappedImageBinding;
use crate::guest::tool_region::MappedImageExtent;
use crate::guest::tool_region::MappedImageLayout;
use crate::guest::tool_region::ToolRegion;

/// Actual retained page mapping, including its observed qualified protections.
/// This is a Rust view of the producer ledger, not a new wire format/authority.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct MappedMemory {
    /// Inclusive page boundary.
    pub start: usize,
    /// Exclusive page boundary.
    pub end: usize,
    /// Exact Linux protection bits of this mapping.
    pub protection: u64,
    /// Exact mapping flags recorded by the physical producer.
    pub flags: u64,
}

/// Exact executable extent from the qualified mapped ELF, not an IP allowlist.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct MappedCode {
    /// Inclusive code boundary.
    pub start: usize,
    /// Exclusive code boundary.
    pub end: usize,
}

/// Explicit borrowed physical entry inputs. Constructing this value is not
/// authority: only the unsafe capture contract can create an affine prelude.
/// All immutable records live in qualified retained read-only mappings.
pub struct MappedInitialInputs {
    scalar: ProductionMappedInputs<'static>,
    // Immutable native values, never promoted to RO/static references. Their
    // source bytes remain retained in scalar; capture/adoption use that source.
    layout: MappedImageLayout,
    control: NonNull<NativeControl>,
    packet: &'static [u8],
    input_fd: i32,
    resume: OriginalRegisters,
    original_pkru: u32,
    original_mask: u64,
    maps: Maps,
    prepared_tcb: usize,
    bootstrap_handler: usize,
    gate_reference: *const [u8; 4096],
}

struct OriginalRegisters {
    source: Registers<'static>,
    fs_base: u64,
    rsp: u64,
    rip: u64,
}

// No native object reference is derived from bytes. Failure in a previously
// validated immutable view is terminal, never panic/unwind or a fabricated item.
fn scalar_value<T>(value: Result<T, reverie_loader::handoff::Error>) -> T {
    match value {
        Ok(value) => value,
        Err(_) => crate::private_runtime::abort(),
    }
}
#[derive(Clone, Copy)]
struct Maps {
    view: View<'static>,
}
impl Maps {
    fn len(self) -> usize {
        scalar_value(self.view.table(0)).len()
    }
    fn iter(&self) -> impl ExactSizeIterator<Item = MappedMemory> + '_ {
        (0..self.len()).map(|i| {
            let m = scalar_value(self.view.map(i));
            MappedMemory {
                start: m.start as usize,
                end: m.end as usize,
                protection: m.protection,
                flags: m.flags,
            }
        })
    }
}
impl MappedInitialInputs {
    /// Decode actual permanent immutable scalar bytes, without adopting a
    /// mapping, dereferencing numeric pointers or granting capture authority.
    /// The unsafe capture caller must establish the retained physical origin.
    pub fn decode(bytes: &'static [u8]) -> Result<Self, i32> {
        let scalar = ProductionMappedInputs::decode(
            bytes,
            ConsumerLayout {
                free_band: crate::guest::tool_region::scalar_free_band(),
                region: reverie_loader::handoff::Extent {
                    start: crate::guest::tool_region::BASE as u64,
                    end: crate::guest::tool_region::END as u64,
                },
                control_bytes: size_of::<NativeControl>() as u64,
                relay_bytes: size_of::<libc_relay::RelayStorage>() as u64,
                control_align: align_of::<NativeControl>() as u64,
                relay_align: align_of::<libc_relay::RelayStorage>() as u64,
            },
        )
        .map_err(|_| libc::EINVAL)?;
        let v = scalar.view();
        let s = |i| v.scalar(i).map_err(|_| libc::EINVAL);
        let source = v.registers();
        let resume = OriginalRegisters {
            source,
            fs_base: source.fs_base().map_err(|_| libc::EINVAL)?,
            rsp: source.rsp().map_err(|_| libc::EINVAL)?,
            rip: source.rip().map_err(|_| libc::EINVAL)?,
        };
        Ok(Self {
            layout: crate::guest::tool_region::scalar_layout(v)?,
            control: NonNull::new(s(1)? as *mut NativeControl).ok_or(libc::EINVAL)?,
            packet: v.table(3).map_err(|_| libc::EINVAL)?.bytes(),
            input_fd: i32::try_from(s(5)?).map_err(|_| libc::EINVAL)?,
            resume,
            original_pkru: u32::try_from(s(6)?).map_err(|_| libc::EINVAL)?,
            original_mask: s(7)?,
            maps: Maps { view: v },
            prepared_tcb: s(8)? as usize,
            bootstrap_handler: s(9)? as usize,
            gate_reference: s(10)? as *const [u8; 4096],
            scalar,
        })
    }
}

// Only the operands needed before real private TLS. This is a projection of
// the SAME immutable host-validated bytes, never a partial View or a new owner.
struct BootstrapInputs {
    wire: Bootstrap<'static>,
    layout: MappedImageLayout,
    control: NonNull<NativeControl>,
    packet: &'static [u8],
    input_fd: i32,
    resume: OriginalRegisters,
    original_pkru: u32,
    original_mask: u64,
    prepared_tcb: usize,
    bootstrap_handler: usize,
    gate_reference: *const [u8; 4096],
}
impl BootstrapInputs {
    fn project(bytes: &'static [u8]) -> Result<Self, i32> {
        let wire = Bootstrap::project(bytes, bytes.as_ptr() as u64).map_err(|_| libc::EINVAL)?;
        let scalar = |i| wire.scalar(i).map_err(|_| libc::EINVAL);
        let role = |i| -> Result<MappedImageExtent, i32> {
            let value = wire.role(i).map_err(|_| libc::EINVAL)?;
            let band = crate::guest::tool_region::scalar_free_band();
            if value.start < band.start
                || value.end > band.end
                || !value.start.is_multiple_of(4096)
                || !value.end.is_multiple_of(4096)
                || value
                    .start
                    .checked_add(3 * 4096)
                    .is_none_or(|end| end > value.end)
            {
                return Err(libc::EINVAL);
            }
            Ok(MappedImageExtent {
                start: usize::try_from(value.start).map_err(|_| libc::EINVAL)?,
                end: usize::try_from(value.end).map_err(|_| libc::EINVAL)?,
            })
        };
        let digest = |i| -> Result<[u8; 32], i32> {
            let words = wire.binding(i).map_err(|_| libc::EINVAL)?;
            let mut bytes = [0; 32];
            for (j, word) in words.into_iter().enumerate() {
                for k in 0..8 {
                    *bytes.get_mut(j * 8 + k).ok_or(libc::EINVAL)? = (word >> (k * 8)) as u8;
                }
            }
            Ok(bytes)
        };
        let layout = MappedImageLayout {
            binding: MappedImageBinding {
                launch: digest(0)?,
                loader: digest(1)?,
                runtime: digest(2)?,
                sources: digest(3)?,
                layout: digest(4)?,
            },
            stack: role(0)?,
            tls: role(1)?,
            signal_stack: role(2)?,
            handoff: role(3)?,
            state: role(4)?,
            owner_tid: i32::try_from(scalar(0)?).map_err(|_| libc::EINVAL)?,
        };
        let c = usize::try_from(scalar(1)?).map_err(|_| libc::EINVAL)?;
        let relay = usize::try_from(scalar(3)?).map_err(|_| libc::EINVAL)?;
        if layout.owner_tid <= 0
            || wire.address() != bytes.as_ptr() as u64
            || !inside(&layout.handoff, bytes.as_ptr() as usize, bytes.len())
            || scalar(2)? != size_of::<NativeControl>() as u64
            || scalar(4)? != size_of::<libc_relay::RelayStorage>() as u64
            || !c.is_multiple_of(align_of::<NativeControl>())
            || !relay.is_multiple_of(align_of::<libc_relay::RelayStorage>())
            || !inside(&layout.state, c, size_of::<NativeControl>())
            || !inside(&layout.state, relay, size_of::<libc_relay::RelayStorage>())
        {
            return Err(libc::EINVAL);
        }
        let source = wire.registers().map_err(|_| libc::EINVAL)?;
        Ok(Self {
            wire,
            layout,
            control: NonNull::new(c as *mut NativeControl).ok_or(libc::EINVAL)?,
            packet: wire.packet().map_err(|_| libc::EINVAL)?,
            input_fd: i32::try_from(scalar(5)?).map_err(|_| libc::EINVAL)?,
            resume: OriginalRegisters {
                source,
                fs_base: source.fs_base().map_err(|_| libc::EINVAL)?,
                rsp: source.rsp().map_err(|_| libc::EINVAL)?,
                rip: source.rip().map_err(|_| libc::EINVAL)?,
            },
            original_pkru: u32::try_from(scalar(6)?).map_err(|_| libc::EINVAL)?,
            original_mask: scalar(7)?,
            prepared_tcb: usize::try_from(scalar(8)?).map_err(|_| libc::EINVAL)?,
            bootstrap_handler: usize::try_from(scalar(9)?).map_err(|_| libc::EINVAL)?,
            gate_reference: usize::try_from(scalar(10)?).map_err(|_| libc::EINVAL)?
                as *const [u8; 4096],
        })
    }
    fn maps(&self) -> impl ExactSizeIterator<Item = MappedMemory> + '_ {
        (0..scalar_value(self.wire.map_count())).map(|i| {
            let m = scalar_value(self.wire.map(i));
            MappedMemory {
                start: m.start as usize,
                end: m.end as usize,
                protection: m.protection,
                flags: m.flags,
            }
        })
    }
    fn codes(&self) -> impl ExactSizeIterator<Item = MappedCode> + '_ {
        (0..scalar_value(self.wire.code_count())).map(|i| {
            let c = scalar_value(self.wire.code(i));
            MappedCode {
                start: c.start as usize,
                end: c.end as usize,
            }
        })
    }
    // Same retained source AND unchanged copied operands. This is an association
    // check; immutability and same-generation custody remain physical premises.
    fn matches_full(&self, full: &MappedInitialInputs) -> bool {
        let source = full.scalar.view();
        let roles = |l: &MappedImageLayout| {
            [
                (l.stack.start, l.stack.end),
                (l.tls.start, l.tls.end),
                (l.signal_stack.start, l.signal_stack.end),
                (l.handoff.start, l.handoff.end),
                (l.state.start, l.state.end),
            ]
        };
        self.wire.bytes().as_ptr() == source.bytes().as_ptr()
            && self.wire.bytes().len() == source.bytes().len()
            && self.wire.address() == source.address()
            && roles(&self.layout) == roles(&full.layout)
            && self.layout.owner_tid == full.layout.owner_tid
            && self.layout.binding.launch == full.layout.binding.launch
            && self.layout.binding.loader == full.layout.binding.loader
            && self.layout.binding.runtime == full.layout.binding.runtime
            && self.layout.binding.sources == full.layout.binding.sources
            && self.layout.binding.layout == full.layout.binding.layout
            && self.control == full.control
            && self.packet.as_ptr() == full.packet.as_ptr()
            && self.packet.len() == full.packet.len()
            && self.input_fd == full.input_fd
            && self.resume.source.bytes().as_ptr() == full.resume.source.bytes().as_ptr()
            && self.resume.fs_base == full.resume.fs_base
            && self.resume.rsp == full.resume.rsp
            && self.resume.rip == full.resume.rip
            && self.original_pkru == full.original_pkru
            && self.original_mask == full.original_mask
            && self.prepared_tcb == full.prepared_tcb
            && self.bootstrap_handler == full.bootstrap_handler
            && self.gate_reference == full.gate_reference
    }
}

/// One captured physical image before real private libc/TLS initialization.
/// Not Send, Sync, Clone or Copy; its control has not been published.
pub struct CapturedMappedInitial {
    input: BootstrapInputs,
    _same_thread: PhantomData<*mut ()>,
}

/// Real private TLS/bootstrap and the sole existing ToolRegion are established.
/// Still no coordinator admission, installed Tool, lifecycle or Ready result.
pub struct MappedToolPrelude {
    input: MappedInitialInputs,
    region: &'static ToolRegion,
    _same_thread: PhantomData<*mut ()>,
}

fn inside(role: &MappedImageExtent, address: usize, bytes: usize) -> bool {
    role.start
        .checked_add(4096)
        .is_some_and(|first| address >= first)
        && role
            .end
            .checked_sub(4096)
            .is_some_and(|last| address.checked_add(bytes).is_some_and(|end| end <= last))
}
fn contains(map: MappedMemory, address: usize, bytes: usize, protection: u64) -> bool {
    map.protection == protection
        && address >= map.start
        && address.checked_add(bytes).is_some_and(|end| end <= map.end)
}
fn failed(value: i64) -> bool {
    (value as u64) >= (-4095_i64 as u64)
}
unsafe fn call(number: i64, args: [u64; 6]) -> i64 {
    // SAFETY: all callers have adopted the actual fixed gate first; scalar
    // arguments refer only to owned private stack/state and retained images.
    unsafe { crate::trap::raw_syscall6(number, args) }
}
fn startup_mask() -> u64 {
    !((1_u64 << (libc::SIGSYS - 1))
        | (1_u64 << (libc::SIGKILL - 1))
        | (1_u64 << (libc::SIGSTOP - 1)))
}

impl MappedInitialInputs {
    fn check_structure(&self) -> Result<(), i32> {
        crate::guest::tool_region::validate_mapped_scalar_layout(self.scalar.view())?;
        // Physical pointer origin remains checked above in the child. All
        // numeric structure/range checks use the SAME represented source.
        self.scalar.check_structure().map_err(|_| libc::EINVAL)?;
        Ok(())
    }
}

/// Capture the real original kernel state and spend the existing fixed-gate
/// publication, before any private libc/TLS/allocator or guest instruction.
///
/// # Safety
/// Only the independently qualified trusted entry of the original stopped
/// generation may call. Its host retains the successful exact no-replace full
/// reservation, sealed qualified loader/runtime, complete immutable mappings,
/// original EntryContext/xstate and actual pidfd/ChildOwner terminal wait owner.
/// The host's one-use transition is already consumed. All five roles and their
/// guards/protections are actual; descriptor/ledger/resume match that same birth.
/// The gate is immutable private RX and its admitted filter lineage is retained;
/// `gate_reference` is the independently emitted same-source read-only reference
/// required by the mapped gate adopter. The host validates these physical facts;
/// no local addresses, hashes or comparisons authenticate them.
/// Original FS/mask/registrations are unchanged, this is the sole leader on the
/// owned private stack, async execution is excluded until the mask is blocked,
/// and control is exclusive fresh zero storage with no Rust aliases. All input
/// references are valid immutable process-lifetime retained backing before call.
/// Every error, panic or abandonment is immediately terminal through the actual
/// owned raw route; retain every live mapping/FD until host-confirmed death.
/// No unwind, retry/reset, guest fallback, scalar-ready promotion or unmapping.
/// Caller retains this same fatal ownership across subsequent unsafe stages.
/// The host has run the complete shared numeric predicate on these SAME bytes
/// before mutation and enforced complete physical readback, RO/sealed backing
/// and original descriptor/generation custody before transfer. This boundary
/// only projects the operands needed before TLS; full child parsing happens
/// after real libc/FD cleanup and before adoption. Safe projection alone does
/// not establish any of this, and later validation cannot repair corruption.
pub unsafe fn capture(bytes: &'static [u8]) -> Result<CapturedMappedInitial, i32> {
    let input = BootstrapInputs::project(bytes)?;
    if super::active() {
        return Err(libc::EEXIST);
    }
    let rsp: usize;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags))
    };
    if !inside(&input.layout.stack, rsp, 1) {
        return Err(libc::EINVAL);
    }
    let c = input.control.as_ptr();
    let mut offset = 0;
    while offset < size_of::<NativeControl>() {
        // SAFETY: exclusive initially-zero state extent, checked above.
        if unsafe { c.cast::<u8>().add(offset).read_volatile() } != 0 {
            return Err(libc::EINVAL);
        }
        offset = offset.wrapping_add(1);
    }
    // SAFETY: full retained physical gate/reference contract above. After this
    // publication every raw syscall selects the SAME existing fixed gate.
    unsafe { crate::trap::adopt_mapped_initial_gate(&*input.gate_reference)? };
    let mut fs = 0_u64;
    let mut mask = 0_u64;
    let mut robust = 0_u64;
    let mut robust_len = 0_u64;
    let mut tsc = 0_i32;
    // SAFETY: actual gate plus exclusively owned scalar stack outputs.
    let (tid, pid, brk, fs_rc, mask_rc, robust_rc, clear_rc, tsc_rc) = unsafe {
        (
            call(libc::SYS_gettid, [0; 6]),
            call(libc::SYS_getpid, [0; 6]),
            call(libc::SYS_brk, [0; 6]),
            call(
                libc::SYS_arch_prctl,
                [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
            ),
            call(
                libc::SYS_rt_sigprocmask,
                [libc::SIG_SETMASK as u64, 0, (&raw mut mask) as u64, 8, 0, 0],
            ),
            call(
                libc::SYS_get_robust_list,
                [
                    0,
                    (&raw mut robust) as u64,
                    (&raw mut robust_len) as u64,
                    0,
                    0,
                    0,
                ],
            ),
            call(libc::SYS_set_tid_address, [0; 6]),
            call(
                libc::SYS_prctl,
                [libc::PR_GET_TSC as u64, (&raw mut tsc) as u64, 0, 0, 0, 0],
            ),
        )
    };
    if tid <= 0
        || tid != pid
        || tid != i64::from(input.layout.owner_tid)
        || failed(brk)
        || brk == 0
        || fs_rc != 0
        || fs != input.resume.fs_base
        || mask_rc != 0
        || mask != input.original_mask
        || robust_rc != 0
        || robust != 0
        || robust_len != 24
        || clear_rc != tid
        || tsc_rc != 0
        || !matches!(tsc, libc::PR_TSC_ENABLE | libc::PR_TSC_SIGSEGV)
    {
        return Err(libc::EINVAL);
    }
    let original_tsc = tsc as u64;
    let forced_mask = startup_mask();
    // SAFETY: scalar actual setters followed by genuine readbacks.
    if unsafe {
        call(
            libc::SYS_prctl,
            [
                libc::PR_SET_TSC as u64,
                libc::PR_TSC_ENABLE as u64,
                0,
                0,
                0,
                0,
            ],
        )
    } != 0
        || unsafe {
            call(
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_SETMASK as u64,
                    (&raw const forced_mask) as u64,
                    0,
                    8,
                    0,
                    0,
                ],
            )
        } != 0
    {
        return Err(libc::EINVAL);
    }
    tsc = 0;
    let mut observed_mask = 0_u64;
    if unsafe {
        call(
            libc::SYS_prctl,
            [libc::PR_GET_TSC as u64, (&raw mut tsc) as u64, 0, 0, 0, 0],
        )
    } != 0
        || tsc != libc::PR_TSC_ENABLE
        || unsafe {
            call(
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_SETMASK as u64,
                    0,
                    (&raw mut observed_mask) as u64,
                    8,
                    0,
                    0,
                ],
            )
        } != 0
        || observed_mask != forced_mask
    {
        return Err(libc::EINVAL);
    }
    macro_rules! put {
        ($field:ident, $value:expr) => {
            unsafe { addr_of_mut!((*c).$field).write_volatile($value) }
        };
    }
    // Integer/padding zero initialization is scalar and never invokes memset.
    let mut word = 0;
    while word < size_of::<NativeControl>() / 8 {
        unsafe { c.cast::<u64>().add(word).write_volatile(0) };
        word = word.wrapping_add(1);
    }
    put!(abi_version, 1);
    put!(byte_len, size_of::<NativeControl>() as u64);
    put!(guest_fs, fs);
    put!(guest_rsp, input.resume.rsp);
    put!(guest_ld_entry, input.resume.rip);
    put!(guest_pkru, input.original_pkru as u64);
    put!(kernel_mask, mask);
    put!(guest_resume_mask, mask & !(1_u64 << (libc::SIGSYS - 1)));
    put!(kernel_robust_head, robust);
    put!(kernel_robust_len, robust_len);
    put!(kernel_clear_tid, 0); // actual successful set_tid_address(0), never a getter
    put!(private_clear_tid, 0);
    put!(private_robust_head, robust);
    put!(private_robust_len, robust_len);
    put!(kernel_brk, brk as u64);
    put!(native_tid, tid as u64);
    put!(kernel_tsc, original_tsc);
    put!(private_stack_base, (input.layout.stack.start + 4096) as u64);
    put!(private_stack_end, (input.layout.stack.end - 4096) as u64);
    put!(init_input, input.packet.as_ptr() as u64);
    put!(init_input_len, input.packet.len() as u64);
    put!(init_input_fd, input.input_fd as u64);
    // Mapping envelope is the actual immutable handoff interior, not the old GNU page.
    put!(
        input_mapping_base,
        (input.layout.handoff.start + 4096) as u64
    );
    put!(input_mapping_end, (input.layout.handoff.end - 4096) as u64);
    for (index, map) in input.maps().enumerate() {
        let dest = unsafe { addr_of_mut!((*c).maps).cast::<PrivateMap>().add(index) };
        unsafe {
            addr_of_mut!((*dest).lo).write_volatile(map.start as u64);
            addr_of_mut!((*dest).hi).write_volatile(map.end as u64);
            addr_of_mut!((*dest).prot).write_volatile(map.protection);
            addr_of_mut!((*dest).flags).write_volatile(map.flags);
        }
    }
    for (index, code) in input.codes().enumerate() {
        let dest = unsafe { addr_of_mut!((*c).code).cast::<PrivateCode>().add(index) };
        unsafe {
            addr_of_mut!((*dest).lo).write_volatile(code.start as u64);
            addr_of_mut!((*dest).hi).write_volatile(code.end as u64);
        }
    }
    put!(
        private_map_count,
        scalar_value(input.wire.map_count()) as u64
    );
    put!(
        private_code_count,
        scalar_value(input.wire.code_count()) as u64
    );
    // GNU ld.so/runner/private-brk/native_config slots stay inactive zero. This
    // path never fabricates a private brk owner or allocates one. Final link must
    // exclude their legacy C readers; no runtime syscall policy is changed here.
    put!(native_state, 1);
    put!(phase, 1); // captured, loading; never ready
    Ok(CapturedMappedInitial {
        input,
        _same_thread: PhantomData,
    })
}

impl CapturedMappedInitial {
    /// Borrow the same physical control for the actual bootstrap relay installer.
    /// A raw pointer confers neither RPC admission nor permission to publish Ready.
    pub fn control(&self) -> NonNull<NativeControl> {
        self.input.control
    }

    /// Verify real post-libc state, then initialize/publish the sole ToolRegion.
    ///
    /// # Safety
    /// The same qualified entry completed genuine private __init_libc/TLS on the
    /// fixed backing, and the real relay/filter/altstack was installed. All actual
    /// successful registration setters were recorded by record_registration_result.
    /// DSR-created FDs are retired, without changing original descriptors/OFDs.
    /// No allocator, guest, callback or other owner has run; all capture's retained
    /// physical/terminal obligations still hold. No hidden private brk/TLS/maps
    /// exist. Every Err or abandoned token is terminal; never retry/reset/unmap.
    pub unsafe fn adopt_region(self) -> Result<MappedToolPrelude, i32> {
        // SAFETY: same affine capture, genuine libc/FD cleanup and same busy
        // exclusion; full parsing succeeds before any region publication.
        let full_input = unsafe { libc_relay::validate_after_libc(&self)? };
        let input = &full_input;
        let c = input.control.as_ptr();
        let read = |p: *const u64| unsafe { p.read_volatile() };
        if read(unsafe { addr_of!((*c).phase) }) != 1
            || read(unsafe { addr_of!((*c).native_state) }) != 1
            || read(unsafe { addr_of!((*c).runtime_ready) }) != 0
        {
            return Err(libc::EINVAL);
        }
        let mut fs = 0_u64;
        let mut mask = 0_u64;
        let mut head = 0_u64;
        let mut len = 0_u64;
        let mut action = crate::signal::KernelSigaction {
            handler: 0,
            flags: 0,
            restorer: 0,
            mask: 0,
        };
        let mut stack = libc::stack_t {
            ss_sp: core::ptr::null_mut(),
            ss_flags: 0,
            ss_size: 0,
        };
        let rsp: usize;
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags))
        };
        let (tid, pid, brk, fs_rc, mask_rc, action_rc, stack_rc, robust_rc) = unsafe {
            (
                call(libc::SYS_gettid, [0; 6]),
                call(libc::SYS_getpid, [0; 6]),
                call(libc::SYS_brk, [0; 6]),
                call(
                    libc::SYS_arch_prctl,
                    [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
                ),
                call(
                    libc::SYS_rt_sigprocmask,
                    [libc::SIG_SETMASK as u64, 0, (&raw mut mask) as u64, 8, 0, 0],
                ),
                call(
                    libc::SYS_rt_sigaction,
                    [libc::SIGSYS as u64, 0, (&raw mut action) as u64, 8, 0, 0],
                ),
                call(
                    libc::SYS_sigaltstack,
                    [0, (&raw mut stack) as u64, 0, 0, 0, 0],
                ),
                call(
                    libc::SYS_get_robust_list,
                    [0, (&raw mut head) as u64, (&raw mut len) as u64, 0, 0, 0],
                ),
            )
        };
        if tid <= 0
            || tid != pid
            || tid != i64::from(input.layout.owner_tid)
            || brk as u64 != read(unsafe { addr_of!((*c).kernel_brk) })
            || fs_rc != 0
            || fs != input.prepared_tcb as u64
            || !inside(&input.layout.tls, fs as usize, 1)
            || !inside(&input.layout.stack, rsp, 1)
            || mask_rc != 0
            || mask != startup_mask()
            || action_rc != 0
            || action.handler != input.bootstrap_handler as u64
            || action.restorer != crate::trap::FIXED_SIGNAL_RESTORER_ENTRY
            || action.flags
                != (libc::SA_SIGINFO | libc::SA_ONSTACK | crate::signal::SA_RESTORER) as u64
            || action.mask != 0
            || stack_rc != 0
            || stack.ss_flags != 0
            || stack.ss_sp as usize != input.layout.signal_stack.start + 4096
            || stack.ss_size
                != input.layout.signal_stack.end - input.layout.signal_stack.start - 8192
            || robust_rc != 0
            || len != 24
            || head != read(unsafe { addr_of!((*c).private_robust_head) })
            || len != read(unsafe { addr_of!((*c).private_robust_len) })
            || !input.maps.iter().any(|map| {
                contains(
                    map,
                    read(unsafe { addr_of!((*c).private_clear_tid) }) as usize,
                    4,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                )
            })
        {
            return Err(libc::EINVAL);
        }
        // SAFETY: real private TLS/stack/gate and full physical adoption contract.
        // All five roles/guards and the permanent image band are marked before
        // the one REGION publication; no constructor origin or fresh reserve.
        let region =
            unsafe { crate::guest::tool_region::adopt_mapped_scalar(input.scalar.view())? };
        unsafe {
            addr_of_mut!((*c).tool_fs).write_volatile(fs);
            addr_of_mut!((*c).bootstrap_handler).write_volatile(action.handler);
            addr_of_mut!((*c).bootstrap_restorer).write_volatile(action.restorer);
            addr_of_mut!((*c).bootstrap_stack_base).write_volatile(stack.ss_sp as u64);
            addr_of_mut!((*c).bootstrap_stack_end)
                .write_volatile((input.layout.signal_stack.end - 4096) as u64);
            addr_of_mut!((*c).phase).write_volatile(2);
        }
        Ok(MappedToolPrelude {
            input: full_input,
            region,
            _same_thread: PhantomData,
        })
    }
}

/// Retain only an actual successful private registration result on the same
/// physical control. Linux has no general clear-TID getter; never infer it.
///
/// # Safety
/// Called only by the retained qualified startup relay, for the real completed
/// syscall and exact arguments/result in this sole leader, before any later
/// registration setter or signal/guest/concurrent entry. `control` is the
/// original capture's exclusive valid pointer; no scalar mints this authority.
/// Errors remain terminal under that same retained owner.
pub unsafe fn record_registration_result(
    control: NonNull<NativeControl>,
    nr: i64,
    args: [u64; 6],
    actual_result: i64,
) -> Result<(), i32> {
    if nr != libc::SYS_set_tid_address && nr != libc::SYS_set_robust_list {
        return Err(libc::EINVAL);
    }
    if failed(actual_result) {
        return Ok(());
    }
    let c = control.as_ptr();
    let read = |p: *const u64| unsafe { p.read_volatile() };
    if !matches!(read(unsafe { addr_of!((*c).phase) }), 1 | 2)
        || read(unsafe { addr_of!((*c).runtime_ready) }) != 0
        || read(unsafe { addr_of!((*c).native_state) }) != 1
    {
        return Err(libc::EINVAL);
    }
    let mut head = 0_u64;
    let mut len = 0_u64;
    let tid = unsafe { call(libc::SYS_gettid, [0; 6]) };
    let rc = unsafe {
        call(
            libc::SYS_get_robust_list,
            [0, (&raw mut head) as u64, (&raw mut len) as u64, 0, 0, 0],
        )
    };
    if tid <= 0
        || tid as u64 != read(unsafe { addr_of!((*c).native_tid) })
        || rc != 0
        || len != 24
        || (nr == libc::SYS_set_tid_address && actual_result != tid)
        || (nr == libc::SYS_set_robust_list
            && (actual_result != 0 || head != args[0] || len != args[1]))
    {
        return Err(libc::EINVAL);
    }
    unsafe {
        addr_of_mut!((*c).private_robust_head).write_volatile(head);
        addr_of_mut!((*c).private_robust_len).write_volatile(len);
        if nr == libc::SYS_set_tid_address {
            addr_of_mut!((*c).private_clear_tid).write_volatile(args[0]);
        }
    }
    Ok(())
}

impl MappedToolPrelude {
    /// Enable the same retained relay for genuine Tool startup, once, after
    /// real libc/FD cleanup and adoption. No RPC, global control or Ready is
    /// published. Only exact retained table8 instruction boundaries qualify.
    /// # Safety
    /// The sole stopped-generation owner retains all capture/adoption proofs;
    /// every table8 PC is independently qualified from this exact immutable
    /// final ELF/source instruction boundary, not a byte scan or guessed range.
    /// All reachable code is trusted Tool startup with no guest/callback entry.
    /// Original bootstrap signal stack/mask stay installed during this stage.
    /// Errors/abandonment remain terminal; never retry or reset the relay.
    pub unsafe fn enable_tool_init(self) -> Result<Self, i32> {
        unsafe {
            libc_relay::tool_init::enable(&self)?;
        }
        Ok(self)
    }
    /// Same control pointer for the genuine ordinary InitialImage bridge.
    pub fn control(&self) -> NonNull<NativeControl> {
        self.input.control
    }
    /// Exact immutable ordinary HLNI packet for real schema/RPC redemption.
    pub fn packet(&self) -> &[u8] {
        self.input.packet
    }
    /// Real sole native leader, physically captured before libc startup.
    pub fn native_tid(&self) -> i32 {
        self.input.layout.owner_tid
    }
    /// Original exact registers; never a request to restore the saved stack bytes.
    pub fn original_registers(&self) -> libc::user_regs_struct {
        scalar_value(mapped_scalar::native_registers(self.input.resume.source))
    }
    /// Original immutable scalar register source; no stack snapshot is restored.
    pub fn original_register_words(&self) -> Registers<'static> {
        self.input.resume.source
    }
    /// Original stopped mask for the genuine final restoration protocol.
    pub fn original_signal_mask(&self) -> u64 {
        self.input.original_mask
    }
    /// Original exact PKRU projected from the retained stopped xstate.
    pub fn original_pkru(&self) -> u32 {
        self.input.original_pkru
    }
    /// Actual sealed input descriptor lease, retained by the physical caller.
    pub fn input_fd(&self) -> i32 {
        self.input.input_fd
    }

    /// Publish this same control only after actual one-use coordinator admission.
    /// Normally consumed via prepare_tool_mapped_initial_image, which arms the
    /// existing fatal guard BEFORE any fallible verification or client drop.
    ///
    /// # Safety
    /// Actual accepted-socket watched-birth InitialImage redemption, schema and
    /// Config checks completed for this exact physical launch and input. Caller
    /// retains an armed InitialImageAbortGuard through existing install/lifecycle/
    /// finish. No Guest ran; all capture/adoption physical obligations remain.
    /// This function establishes none of that external authority from fields.
    pub unsafe fn publish_authenticated(self) -> std::io::Result<InitialImageControl> {
        if super::active() || !core::ptr::eq(ToolRegion::reserve()?, self.region) {
            return Err(std::io::Error::other("mapped InitialImage owner differs"));
        }
        let c = self.input.control.as_ptr();
        let read = |p: *const u64| unsafe { p.read_volatile() };
        if read(unsafe { addr_of!((*c).abi_version) }) != 1
            || read(unsafe { addr_of!((*c).byte_len) }) != size_of::<NativeControl>() as u64
            || read(unsafe { addr_of!((*c).phase) }) != 2
            || read(unsafe { addr_of!((*c).runtime_ready) }) != 0
            || read(unsafe { addr_of!((*c).native_state) }) != 1
            || read(unsafe { addr_of!((*c).tool_fs) }) != self.input.prepared_tcb as u64
            || read(unsafe { addr_of!((*c).bootstrap_handler) })
                != self.input.bootstrap_handler as u64
        {
            return Err(std::io::Error::other("mapped InitialImage state differs"));
        }
        // Same actual filter-count, leader, FS, mask, handler/restorer and
        // alternate-stack verification as GNU, now after real allocator/TLS.
        unsafe { super::verify_bootstrap_signal(c)? };
        // The existing prepare_tool_mapped_initial_image already armed the
        // same fatal guard after actual accepted client redemption. Retire the
        // actual input exactly once before global publication/FD enumeration.
        unsafe { libc_relay::tool_init::retire_input(&self) }
            .map_err(std::io::Error::from_raw_os_error)?;
        super::publish_control_slot(c)?;
        Ok(InitialImageControl::new(c as usize))
    }
}
