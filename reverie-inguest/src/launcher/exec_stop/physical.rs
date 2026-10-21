//! Physical mapping/filter preparation of one retained initial image.
//! Preparation stops before any private-entry instruction. The separately unsafe
//! borrowed bootstrap observer is incomplete for ToolInit; it publishes no Ready,
//! grants no Guest release, and returns no initialized-runtime authority.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::unix::fs::FileExt;

use reverie_loader::artifact::RUNTIME_WINDOW;
use reverie_loader::artifact::TOOL_REGION;
use reverie_loader::handoff::Extent;
use reverie_loader::handoff::View;
use reverie_loader::image::Image;
use reverie_loader::image::Policy;
use reverie_loader::image::ValidatedImage;
use safeptrace::Stopped;

use super::ChildOwner;
use super::CleanupState;
use super::EntryContext;
use super::ExecBoundary;
use super::InitialExecStop;
use super::Result;
use super::inject::InjectedCall;
use super::inject::Injector;
use super::mapping_plan;
use super::mapping_plan::interior;

mod borrowed_entry;
pub use borrowed_entry::BootstrapEntryCoordinates;
pub use borrowed_entry::BootstrapTerminalStop;
pub use borrowed_entry::ObservationDomain;
pub use borrowed_entry::RcbGuestBoundary;
pub use borrowed_entry::RcbNestedBoundary;
pub use borrowed_entry::RcbNestedReturn;
pub use borrowed_entry::RcbObservation;
pub use borrowed_entry::RcbObservationCoordinates;
pub use borrowed_entry::RcbReturnBoundary;

/// Numeric preparation inputs, NOT image/source/entry qualification authority.
/// The only consuming operation is unsafe and retains all physical obligations.
/// Descriptors must already have been inherited by this actual PreparedExec.
pub struct Preparation<'fd> {
    /// Actual inherited runtime descriptor; required seals/bytes are checked locally.
    pub runtime_fd: BorrowedFd<'fd>,
    /// Exact immutable runtime file bytes; never reopened by a path.
    pub runtime_bytes: &'fd [u8],
    /// Address of the 96-byte target RO descriptor; structural checks only here.
    pub layout_address: u64,
    /// Actual handoff backing; seals, expected bytes and zero padding are checked.
    pub handoff_fd: BorrowedFd<'fd>,
    /// Complete wire bytes, excluding only zero file padding.
    pub handoff_bytes: &'fd [u8],
    /// Actual child address of the first byte of the RO handoff.
    pub handoff_address: u64,
    /// Actual retained input descriptor; preparation does not redeem admission.
    pub input_fd: BorrowedFd<'fd>,
    /// Shared ToolRegion layout free band; not initialized adoption or a new allocator.
    pub free_band: Extent,
    /// Eight-byte aligned temporary fprog/BPF slot in the zeroed State interior.
    /// Must not overlap NativeControl or RelayStorage; no handoff RW projection.
    pub filter_scratch: u64,
}

/// Actual preparation transcript plus confirmed child retirement. This proves
/// neither a runtime-entry instruction nor genuine initialization was executed.
#[derive(Debug)]
pub struct CancelledPreparation {
    /// Every completed injected syscall, including the successful final filter.
    pub injected_calls: Vec<InjectedCall>,
    /// Exact shared 23-instruction target-coordinate kernel recipe.
    pub filter_bytes: Vec<u8>,
    /// Actual original-owner terminal wait; confirmed is required for this type.
    pub cleanup: CleanupState,
}

/// Read-only actual context sampled immediately before full pure validation.
/// The stopped owner is still retained then. This record grants no task access,
/// mapping, entry, initialization or readiness, and survives terminal cleanup.
#[cfg(feature = "stage1a-probe")]
#[derive(Clone, Copy, Debug)]
pub struct PrevalidationObservation {
    /// Actual held task's registers in the existing exact 27-word codec.
    pub registers: [u64; 27],
    /// Actual held task's kernel signal mask before any preparation mutation.
    pub signal_mask: u64,
    /// Actual complete XSAVE equals the original retained EntryContext image.
    pub xstate_exact: bool,
}

/// A retained preparation stop. Private fields prevent raw stopped-task escape;
/// The unsafe borrowed bootstrap observer is separate from mapping and is NOT a
/// complete initializer observer. Only cancellation can consume this owner.
#[must_use = "cancel and retain unresolved ownership until actual terminal wait"]
pub struct PreparedMapping<'fd> {
    // Owner drops before source borrows; Drop is still only bounded best effort.
    owner: Box<ChildOwner<'fd>>,
    task: Option<Stopped>,
    entry: borrowed_entry::RetainedEntry,
    context: EntryContext,
    _boundary: ExecBoundary,
    _inputs: Preparation<'fd>,
    calls: Vec<InjectedCall>,
    filter: Vec<u8>,
    #[cfg(feature = "stage1a-probe")]
    prevalidation: Option<PrevalidationObservation>,
}
impl PreparedMapping<'_> {
    /// Duplicate the retained original clone pidfd for the existing coordinator
    /// admission. Same original ptracer and held-generation checks as the initial
    /// stop apply; no source proof, Ready, entry or wait ownership is returned.
    pub fn duplicate_birth_pidfd(&self) -> Result<std::os::fd::OwnedFd> {
        self.owner
            .duplicate_birth_pidfd(self.task.as_ref().ok_or("mapped_preparation_lost_stop")?)
    }

    /// Duplicate this held birth for an exact descriptor retained across exec.
    ///
    /// Uses the SAME original-owner, ptracer-thread, held-generation and borrowed
    /// PreparedExec descriptor rule as InitialExecStop. The caller must retain
    /// the original lease without unsafe close/replacement or concurrent offset
    /// mutation. Neither equal content/inode nor a different duplicate FD is
    /// accepted as that borrowed descriptor. No stop, injection, wait, entry or
    /// readiness capability is returned. Liveness can change after return.
    pub fn duplicate_birth_pidfd_for_inherited(
        &self,
        fd: BorrowedFd<'_>,
    ) -> Result<std::os::fd::OwnedFd> {
        self.owner.duplicate_birth_pidfd_for_inherited(
            self.task.as_ref().ok_or("mapped_preparation_lost_stop")?,
            fd,
        )
    }

    /// Observe actual cleanup state; no observation grants entry permission.
    pub fn cleanup(&self) -> CleanupState {
        self.owner.receipt.snapshot()
    }
    /// Attempt terminal cleanup without moving this mapping or its leases.
    /// The borrowed observer must be dropped first. A failure retains the same
    /// wait driver and actual stop for another cleanup-only attempt; no second
    /// wait owner is constructed. An error retains all state; inspect cleanup()
    /// for the original wait outcome, and retry only terminal cleanup. Success
    /// requires confirmed retirement, not Drop's bounded best effort.
    /// An unexpected child event additionally requires its retained child owner
    /// to be resolved; this bootstrap-only prototype does not implement that.
    pub fn retire_once(&mut self) -> Result<CleanupState> {
        self.entry.failed = true;
        self.owner.retire();
        let cleanup = self.cleanup();
        if self.entry.retains_child() {
            return Err("mapped_entry_unexpected_child_owner_retained".into());
        }
        if !cleanup.confirmed {
            return Err("mapped_entry_terminal_wait_unconfirmed".into());
        }
        Ok(cleanup)
    }

    /// Request bounded kill/wait. Unconfirmed retirement returns this complete
    /// owner with all source/descriptor borrows, not an extracted ChildOwner.
    pub fn cancel(mut self) -> std::result::Result<CancelledPreparation, Box<Self>> {
        let retired = self.retire_once().is_ok();
        let cleanup = self.cleanup();
        if !retired {
            return Err(Box::new(self));
        }
        Ok(CancelledPreparation {
            injected_calls: std::mem::take(&mut self.calls),
            filter_bytes: std::mem::take(&mut self.filter),
            cleanup,
        })
    }
}

/// A preparation failure, retaining the SAME child and all input borrows even
/// if partial mapping/filter installation or retirement was unconfirmed.
#[must_use = "retain failure and retry cleanup until confirmed; never fallback"]
pub struct PreparationFailure<'fd> {
    /// Original failure, never relabelled as a successful preparation.
    pub error: Box<dyn std::error::Error>,
    state: PreparedMapping<'fd>,
}
impl PreparationFailure<'_> {
    /// Snapshot real cleanup; a kill request alone does not confirm death.
    pub fn cleanup(&self) -> CleanupState {
        self.state.cleanup()
    }
    /// Repeat only bounded terminal cleanup, never mapping/launch/filter work.
    pub fn retry_cleanup(&mut self) -> bool {
        self.state.owner.retire();
        self.cleanup().confirmed
    }
}
impl std::fmt::Debug for PreparationFailure<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparationFailure")
            .field("error", &self.error)
            .field("cleanup", &self.cleanup())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub(super) struct TargetLayout {
    pub(super) control_bytes: u64,
    pub(super) control_align: u64,
    pub(super) relay_bytes: u64,
    pub(super) relay_align: u64,
    pub(super) gate: u64,
}
pub(super) fn target_recipe(gate: u64) -> Result<Vec<u8>> {
    // Numeric check only; actual source/descriptor/gate identity is external.
    if gate != RUNTIME_WINDOW.start + 4096 {
        return Err("mapped_filter_wrong_production_gate".into());
    }
    use crate::seccomp::SeccompFilter;
    use crate::seccomp::TrustedGate;
    let filter = SeccompFilter::for_trusted_gates_with_signal_return(
        TrustedGate {
            syscall_ip: gate + 0x80,
            return_ip: gate + 0x82,
        },
        TrustedGate {
            syscall_ip: gate + 0x200,
            return_ip: gate + 0x202,
        },
        Some(gate + 0x30b),
    )?;
    if filter.len() != 23 {
        return Err("mapped_filter_shared_recipe_changed".into());
    }
    Ok(filter.canonical_bytes())
}

// Exact Linux x86-64 sock_fprog: u16 len, six zero padding bytes, u64 pointer.
// No native pointer or libc struct representation is copied into child bytes.
pub(super) fn filter_staging(address: u64, program: &[u8]) -> Result<Vec<u8>> {
    if !address.is_multiple_of(8) || program.len() != 23 * 8 {
        return Err("mapped_filter_staging_shape".into());
    }
    let pointer = address
        .checked_add(16)
        .ok_or("mapped_filter_staging_overflow")?;
    pointer
        .checked_add(program.len() as u64)
        .ok_or("mapped_filter_staging_overflow")?;
    let mut staging = vec![0; 16];
    staging[..2].copy_from_slice(&23_u16.to_le_bytes());
    staging[8..16].copy_from_slice(&pointer.to_le_bytes());
    staging.extend_from_slice(program);
    Ok(staging)
}
fn wire<T>(value: std::result::Result<T, reverie_loader::handoff::Error>) -> Result<T> {
    value.map_err(|error| format!("mapped_preparation_wire: {error:?}").into())
}
fn overlap(a: u64, bytes: u64, b: u64, other: u64) -> bool {
    match (a.checked_add(bytes), b.checked_add(other)) {
        (Some(end), Some(other_end)) => a < other_end && b < end,
        _ => true,
    }
}
fn sealed_contents(fd: BorrowedFd<'_>, expected: &[u8], padded: u64) -> Result<()> {
    let seals = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GET_SEALS)?;
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    let stat = nix::sys::stat::fstat(fd)?;
    if seals & required != required
        || stat.st_size < 0
        || stat.st_size as u64 != padded
        || expected.len() as u64 > padded
        || padded > 512 * 1024 * 1024
    {
        return Err("mapped_preparation_sealed_file_identity".into());
    }
    let file = File::from(fd.try_clone_to_owned()?);
    let mut buffer = [0_u8; 8192];
    let mut offset = 0_u64;
    while offset < padded {
        let count = ((padded - offset) as usize).min(buffer.len());
        if file.read_at(&mut buffer[..count], offset)? != count {
            return Err("mapped_preparation_sealed_file_short_read".into());
        }
        for (i, actual) in buffer[..count].iter().enumerate() {
            let at = offset as usize + i;
            if *actual != expected.get(at).copied().unwrap_or(0) {
                return Err("mapped_preparation_sealed_file_bytes".into());
            }
        }
        offset += count as u64;
    }
    Ok(())
}
fn image_bytes<'a>(
    image: &ValidatedImage<'_>,
    bytes: &'a [u8],
    address: u64,
    length: u64,
    protection: u8,
) -> Result<&'a [u8]> {
    let end = address
        .checked_add(length)
        .ok_or("mapped_image_address_overflow")?;
    for load in image.segments() {
        let actual = u8::from(load.permissions.read)
            | (u8::from(load.permissions.write) << 1)
            | (u8::from(load.permissions.execute) << 2);
        let file_bytes = load.file.end - load.file.start;
        if actual == protection
            && load.memory.start <= address
            && end <= load.memory.start + file_bytes
        {
            let offset = load.file.start + address - load.memory.start;
            return bytes
                .get(offset as usize..(offset + length) as usize)
                .ok_or_else(|| "mapped_image_file_range".into());
        }
    }
    Err("mapped_image_missing_exact_protection_extent".into())
}
fn target_layout(image: &ValidatedImage<'_>, bytes: &[u8], address: u64) -> Result<TargetLayout> {
    let raw = image_bytes(image, bytes, address, 96, 1)?;
    decode_target_layout(raw)
}
// Same exact target descriptor decoder for physical preparation and the host
// copied-input bridge. A borrowed byte slice is not source/physical authority.
pub(super) fn decode_target_layout(raw: &[u8]) -> Result<TargetLayout> {
    if raw.len() != 96 {
        return Err("mapped_target_descriptor_mismatch".into());
    }
    let mut words = [0_u64; 12];
    for (word, chunk) in words.iter_mut().zip(raw.as_chunks::<8>().0.iter()) {
        *word = u64::from_le_bytes(*chunk);
    }
    if words[..6]
        != [
            u64::from_le_bytes(*b"HLMLAY01"),
            1,
            96,
            reverie_loader::handoff::VERSION,
            reverie_loader::handoff::HEADER_BYTES as u64,
            reverie_loader::handoff::MAX_BYTES as u64,
        ]
        || words[6] == 0
        || words[8] == 0
        || !words[7].is_power_of_two()
        || !words[9].is_power_of_two()
        || words[10] != RUNTIME_WINDOW.start + 4096
        || words[11] != words[10] + 0x7c
    {
        return Err("mapped_target_descriptor_mismatch".into());
    }
    Ok(TargetLayout {
        control_bytes: words[6],
        control_align: words[7],
        relay_bytes: words[8],
        relay_align: words[9],
        gate: words[10],
    })
}

impl<'fd> InitialExecStop<'fd> {
    /// Map the genuine private image, install the final filter, restore original
    /// context and STOP. This does not run its entry, install its relay or claim
    /// initialization. Only the existing explicit loader-private-runtime opt-in
    /// exposes this inactive preparation API; no backend/CLI is activated.
    ///
    /// # Safety
    /// The caller is the actual same-birth physical launch owner on its original
    /// ptracer OS thread, retaining external wall/CPU/memory/pid/output bounds.
    /// It retains the actual descriptor/backing lifetimes and immutable parent
    /// expected buffers, known filter lineage and genuine original xstate/PKRU.
    /// Sealing, structural validity, byte equality and ledger/role geometry are
    /// locally CHECKED fallible inputs, not caller-promised successful facts.
    /// This transition executes only the fixed injected syscall/INT3 pair at the
    /// original stopped PC. It never executes an instruction from these image
    /// bytes. Its structural checks are mapping evidence, NOT source, machine,
    /// pre-TLS, initializer or runtime-entry qualification.
    /// Any future entry/resume transition must separately require the genuine
    /// source/archive/member/final-code closure, entry/descriptor/gate/reference
    /// identities and the complete pre-TLS proof; this prepared stop grants none.
    /// All descriptor leases retain the actual objects inherited across this
    /// child's exec, and all parent byte buffers remain immutable; same FD number
    /// alone is not OFD/source authority. Caller owns sole-leader/unshared-FD state
    /// and excludes concurrent signal/FD/mapping/backing mutation, retaining known
    /// filter lineage. Original stack/context and secure aux/credentials are
    /// genuine. The input FD is the actual inherited,
    /// retained descriptor identified by the handoff; mapping does not connect,
    /// redeem or authenticate ordinary HLIINIT1 admission. Any future entry
    /// transition must separately require that admission and its actual RPC/Config
    /// owner. free_band comes from the shared ToolRegion layout contract; this
    /// mapping alone does not adopt it into an initialized allocator. No native
    /// scalar Ready or second allocator is supplied.
    /// Every error, panic/abandonment/unconfirmed cleanup is terminal; retain all
    /// physical source/backing/FD and any already-created RPC lifetimes until actual owned terminal wait,
    /// even after Drop's bounded best effort fails. Never retry preparation,
    /// unmap/reset/filter-stack/detach, release Guest or call a fixture runtime.
    pub unsafe fn prepare_mapping(
        self,
        inputs: Preparation<'fd>,
    ) -> std::result::Result<PreparedMapping<'fd>, Box<PreparationFailure<'fd>>> {
        let InitialExecStop {
            task,
            context,
            boundary,
            owner,
        } = self;
        let mut state = PreparedMapping {
            owner: Box::new(owner),
            task: Some(task),
            entry: borrowed_entry::RetainedEntry::default(),
            context,
            _boundary: boundary,
            _inputs: inputs,
            calls: Vec::new(),
            filter: Vec::new(),
            #[cfg(feature = "stage1a-probe")]
            prevalidation: None,
        };
        let result = (|| -> Result<()> {
            let inputs = &state._inputs;
            for fd in [inputs.runtime_fd, inputs.handoff_fd, inputs.input_fd] {
                if !state.owner._request.retains_descriptor(fd) {
                    return Err("mapped_preparation_descriptor_not_inherited".into());
                }
            }
            if inputs.runtime_bytes.is_empty() || inputs.runtime_bytes.len() > 512 * 1024 * 1024 {
                return Err("mapped_runtime_file_bound".into());
            }
            sealed_contents(
                inputs.runtime_fd,
                inputs.runtime_bytes,
                inputs.runtime_bytes.len() as u64,
            )?;
            let parsed =
                Image::parse(inputs.runtime_bytes).map_err(|e| format!("mapped_image: {e:?}"))?;
            let image = parsed
                .validate(&Policy {
                    window: RUNTIME_WINDOW,
                    allow_tls: true,
                })
                .map_err(|e| format!("mapped_image: {e:?}"))?;
            image
                .private_runtime_metadata()
                .map_err(|e| format!("mapped_tls: {e:?}"))?;
            let layout = target_layout(&image, inputs.runtime_bytes, inputs.layout_address)?;
            let view = wire(View::parse(inputs.handoff_bytes, inputs.handoff_address))?;
            if inputs.free_band.start < TOOL_REGION.start
                || inputs.free_band.end > RUNTIME_WINDOW.start
                || inputs.free_band.start >= inputs.free_band.end
            {
                return Err("mapped_free_band_outside_owned_data".into());
            }
            wire(view.validate_roles(inputs.free_band))?;
            let actual_free_band = crate::guest::tool_region::scalar_free_band();
            if inputs.free_band != actual_free_band {
                return Err("mapped_preparation_target_free_band".into());
            }
            #[cfg(feature = "stage1a-probe")]
            {
                let task = state.task.as_ref().ok_or("mapped_preparation_lost_stop")?;
                state.prevalidation = Some(PrevalidationObservation {
                    registers: super::register_words(&task.getregs()?),
                    signal_mask: task.getsigmask()?,
                    xstate_exact: task.getxstate()? == state.context.xstate,
                });
            }
            // Complete shared numeric checks precede EVERY child mutation,
            // including setsigmask. Host storage is not the child address.
            let _validated = wire(
                reverie_loader::mapped_inputs::ProductionMappedInputs::validate_at(
                    inputs.handoff_bytes,
                    inputs.handoff_address,
                    reverie_loader::mapped_inputs::ConsumerLayout {
                        free_band: actual_free_band,
                        region: Extent {
                            start: TOOL_REGION.start,
                            end: TOOL_REGION.end,
                        },
                        control_bytes: layout.control_bytes,
                        relay_bytes: layout.relay_bytes,
                        control_align: layout.control_align,
                        relay_align: layout.relay_align,
                    },
                ),
            )?;
            let handoff = interior(wire(view.role(3))?)?;
            if handoff.start != inputs.handoff_address
                || handoff.end - handoff.start
                    != (inputs.handoff_bytes.len() as u64).div_ceil(4096) * 4096
            {
                return Err("mapped_handoff_role_backing".into());
            }
            sealed_contents(
                inputs.handoff_fd,
                inputs.handoff_bytes,
                handoff.end - handoff.start,
            )?;
            if wire(view.registers().words())? != super::register_words(state.context.regs())
                || wire(view.scalar(7))? != state.context.signal_mask()
                || wire(view.scalar(0))? != state.owner.generation.pid().as_raw() as u64
                || wire(view.scalar(5))? != inputs.input_fd.as_raw_fd() as u64
            {
                return Err("mapped_preparation_original_birth_context".into());
            }
            let control = wire(view.scalar(1))?;
            let relay = wire(view.scalar(3))?;
            let owned_state = interior(wire(view.role(4))?)?;
            let staging = filter_staging(inputs.filter_scratch, &target_recipe(layout.gate)?)?;
            if wire(view.scalar(2))? != layout.control_bytes
                || wire(view.scalar(4))? != layout.relay_bytes
                || control % layout.control_align != 0
                || relay % layout.relay_align != 0
                || !owned_state.contains(control, layout.control_bytes)
                || !owned_state.contains(relay, layout.relay_bytes)
                || overlap(control, layout.control_bytes, relay, layout.relay_bytes)
                || !owned_state.contains(inputs.filter_scratch, staging.len() as u64)
                || overlap(
                    inputs.filter_scratch,
                    staging.len() as u64,
                    control,
                    layout.control_bytes,
                )
                || overlap(
                    inputs.filter_scratch,
                    staging.len() as u64,
                    relay,
                    layout.relay_bytes,
                )
            {
                return Err("mapped_preparation_state_layout".into());
            }
            let gate = image_bytes(&image, inputs.runtime_bytes, layout.gate, 4096, 5)?;
            let reference_address = wire(view.scalar(10))?;
            let reference = image_bytes(&image, inputs.runtime_bytes, reference_address, 4096, 1)?;
            if wire(view.scalar(11))? != 4096
                || overlap(layout.gate, 4096, reference_address, 4096)
                || gate != reference
            {
                return Err("mapped_preparation_independent_gate_reference".into());
            }
            // Plan from the same locally validated image and parsed roles,
            // never from the caller's proposed table0 rows. No kernel claim.
            let steps = mapping_plan::production_steps(
                &image,
                [
                    wire(view.role(0))?,
                    wire(view.role(1))?,
                    wire(view.role(2))?,
                    wire(view.role(3))?,
                    wire(view.role(4))?,
                ],
            )?;
            let task = state.task.take().ok_or("mapped_preparation_lost_stop")?;
            task.setsigmask(u64::MAX)?;
            let blocked = !((1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1)));
            if task.getsigmask()? != blocked {
                return Err("mapped_preparation_block_mask".into());
            }
            let mut injector = Injector::new(task)?;
            let mapped = (|| -> Result<()> {
                injector.reserve()?;
                injector.map_production_plan(&steps, inputs.runtime_fd, inputs.handoff_fd)?;
                let ledger = injector.mapping_ledger();
                if wire(view.table(0))?.len() != ledger.len() {
                    return Err("mapped_preparation_ledger_count".into());
                }
                for (i, actual) in ledger.iter().enumerate() {
                    let claimed = wire(view.map(i))?;
                    if *actual
                        != [
                            claimed.start,
                            claimed.end,
                            claimed.protection,
                            claimed.flags,
                        ]
                    {
                        return Err("mapped_preparation_ledger_identity".into());
                    }
                }
                state.filter = target_recipe(layout.gate)?;
                injector.install_filter_last(inputs.filter_scratch, &state.filter)
            })();
            // Keep partial transcript on EVERY failure, not just a good finish.
            state.calls = injector.calls.clone();
            mapped?;
            let (task, calls) = injector.finish()?;
            state.calls = calls;
            state.task = Some(task);
            // Only ptrace operations after filter install; no child syscall,
            // original guest instruction, entry invocation or writable input view.
            state
                .context
                .restore(state.task.as_ref().ok_or("mapped_preparation_lost_stop")?)?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(state),
            Err(error) => {
                state.owner.retire();
                Err(Box::new(PreparationFailure { error, state }))
            }
        }
    }
}

/// Owned read-only facts from the exact prepared stop; no resume authority.
#[cfg(feature = "stage1a-probe")]
pub struct PreparationObservation {
    /// Actual current complete register words.
    pub registers: [u64; 27],
    /// Actual current kernel thread signal mask.
    pub signal_mask: u64,
    /// Complete actual xstate equals the authentic original snapshot.
    pub xstate_exact: bool,
    /// Complete original stack VMA equals the authentic original snapshot.
    pub stack_exact: bool,
    /// Number of actual original stack bytes compared.
    pub stack_bytes: usize,
    /// Actual original entry bytes after restoration, for the probe's before join.
    pub entry_bytes: Vec<u8>,
    /// Actual runtime PT_LOAD memory equals file bytes followed by zero BSS.
    pub runtime_contents_exact: bool,
    /// Actual mapped handoff equals the retained immutable wire bytes.
    pub handoff_exact: bool,
    /// Bounded actual maps read at this same owned stop.
    pub maps: String,
    /// Bounded actual kernel status read at this same owned stop.
    pub status: String,
}
#[cfg(feature = "stage1a-probe")]
impl PreparedMapping<'_> {
    /// Re-read only this owned stop and return copied observations. No state,
    /// syscall, register, mask or memory modification; no stopped-task escape.
    pub fn diagnostic_observation(&self) -> Result<PreparationObservation> {
        use std::io::Read;
        let task = self.task.as_ref().ok_or("prepared diagnostic lost stop")?;
        let pid = task.pid().as_raw();
        let bounded_proc = |kind: &str| -> Result<String> {
            let mut raw = Vec::new();
            File::open(format!("/proc/{pid}/{kind}"))?
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut raw)?;
            if raw.len() > 4 * 1024 * 1024 {
                return Err("prepared diagnostic proc byte bound".into());
            }
            Ok(String::from_utf8(raw)?)
        };
        let parsed = Image::parse(self._inputs.runtime_bytes)
            .map_err(|e| format!("diagnostic ELF: {e:?}"))?;
        let image = parsed
            .validate(&Policy {
                window: RUNTIME_WINDOW,
                allow_tls: true,
            })
            .map_err(|e| format!("diagnostic image: {e:?}"))?;
        let mut runtime_contents_exact = true;
        for segment in image.segments() {
            let file_len = segment.file.end - segment.file.start;
            let mut offset = 0;
            while offset < segment.memory.end - segment.memory.start {
                let count = (segment.memory.end - segment.memory.start - offset).min(8192) as usize;
                let actual = super::trace::read(task, segment.memory.start + offset, count)?;
                for (i, byte) in actual.iter().enumerate() {
                    let relative = offset + i as u64;
                    let expected = if relative < file_len {
                        self._inputs.runtime_bytes[(segment.file.start + relative) as usize]
                    } else {
                        0
                    };
                    runtime_contents_exact &= *byte == expected;
                }
                offset += count as u64;
            }
        }
        Ok(PreparationObservation {
            registers: super::register_words(&task.getregs()?),
            signal_mask: task.getsigmask()?,
            xstate_exact: task.getxstate()? == self.context.xstate,
            stack_exact: super::trace::read(
                task,
                self.context.stack_start,
                self.context.stack_bytes.len(),
            )? == self.context.stack_bytes,
            stack_bytes: self.context.stack_bytes.len(),
            entry_bytes: super::trace::read(task, self.context.regs.rip, 16)?,
            runtime_contents_exact,
            handoff_exact: super::trace::read(
                task,
                self._inputs.handoff_address,
                self._inputs.handoff_bytes.len(),
            )? == self._inputs.handoff_bytes,
            maps: bounded_proc("maps")?,
            status: bounded_proc("status")?,
        })
    }
}
#[cfg(feature = "stage1a-probe")]
impl PreparationFailure<'_> {
    /// The actual prevalidation context, if preparation reached that boundary.
    /// No post-retirement task read, ownership or resume capability is exposed.
    pub fn diagnostic_prevalidation(&self) -> Option<PrevalidationObservation> {
        self.state.prevalidation
    }
    /// Copied partial real syscall transcript; grants no child capability.
    pub fn diagnostic_calls(&self) -> Vec<InjectedCall> {
        self.state.calls.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapped_filter_staging_is_exact_child_pointer_wire() {
        let recipe = target_recipe(RUNTIME_WINDOW.start + 4096).unwrap();
        let bytes = filter_staging(0x6000_0100_1000, &recipe).unwrap();
        assert_eq!(bytes.len(), 200);
        assert_eq!(&bytes[..8], &[23, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            0x6000_0100_1010
        );
        assert_eq!(&bytes[16..], recipe);
    }
    #[test]
    fn mapped_filter_refuses_host_legacy_gate_and_malformed_staging() {
        assert!(target_recipe(0x5000_0000_0000).is_err());
        assert!(target_recipe(RUNTIME_WINDOW.start).is_err());
        let recipe = target_recipe(RUNTIME_WINDOW.start + 4096).unwrap();
        assert!(filter_staging(1, &recipe).is_err());
        assert!(filter_staging(u64::MAX - 7, &recipe).is_err());
        assert!(filter_staging(4096, &recipe[..recipe.len() - 8]).is_err());
    }
    #[test]
    fn mapped_scratch_refuses_overflow_and_touching_live_state() {
        assert!(overlap(u64::MAX - 7, 16, 4096, 8));
        assert!(overlap(4096, 200, 4200, 64));
        assert!(!overlap(4096, 200, 4296, 64));
    }
}
