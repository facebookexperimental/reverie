//! Host-side copied input data. This does not construct an execution-eligible
//! handoff: complete source-qualified code/site/binding records and the actual
//! admitted HLIINIT1 packet still have no combined producer here.

use reverie_loader::artifact::RUNTIME_WINDOW;
use reverie_loader::artifact::TOOL_REGION;
use reverie_loader::handoff::Extent;
use reverie_loader::handoff::Map;
use reverie_loader::handoff::{self};
use reverie_loader::image::PrivateRuntimeMetadata;
use reverie_loader::image::ValidatedImage;
use reverie_loader::musl_tls;

use super::InitialExecStop;
use super::Result;
use super::initial_inputs::CapturedInitialInputs;
use super::initial_inputs::{self};
use super::initial_stack_inputs::PlacedInputs;
use super::initial_stack_inputs::PrivateImageAux;
use super::mapping_plan;
use super::physical;

/// Proposed numeric placement, not mapping, source or execution authority.
/// The enclosing host must retain the actual image, mapping/FD/buffer leases
/// and same stopped generation through any later physical transaction.
pub struct CopiedInputRequest {
    /// Proposed complete guarded stack/TLS/signal/handoff/state roles.
    pub roles: [Extent; 5],
    /// Proposed shared ToolRegion free band, checked against global windows.
    pub free_band: Extent,
    /// Actual 96-byte RO target descriptor address in the retained image.
    pub layout_address: u64,
    /// Proposed child address for copied argc/argv/envp/aux/strings/random.
    /// Leave the header and future record-table space before this address.
    pub copied_address: u64,
    /// Available copied payload capacity, entirely within the handoff interior.
    pub copied_capacity: usize,
    /// Proposed target NativeControl and RelayStorage addresses.
    pub control_address: u64,
    /// Proposed target RelayStorage address, separate from NativeControl.
    pub relay_address: u64,
    /// Proposed filter staging address, separate from both state objects.
    pub filter_scratch: u64,
}

/// Numeric locations into the returned copied payload; not child references.
#[derive(Clone, Copy, Debug)]
pub struct CopiedInputLocations {
    /// Actual copied argc, including zero when the original argv was empty.
    pub argc: u64,
    /// Copied argv vector address, including its original NULL terminator.
    pub argv: u64,
    /// Copied environment vector address.
    pub envp: u64,
    /// Environment word count, including its final NULL.
    pub envp_words: u64,
    /// Raw aux vector immediately following the copied environment words.
    pub raw_aux: u64,
    /// Aux word count, including the final AT_NULL pair.
    pub raw_aux_words: u64,
    /// Eight-byte-aligned exact program name for eventual wire table6.
    /// An aligned duplicate does not rewrite argv or AT_EXECFN.
    pub program_name: u64,
    /// Program-name byte count including its original final NUL.
    pub program_name_bytes: u64,
    /// Actual copied original sixteen random bytes; never synthesized entropy.
    pub random: u64,
}

/// Owned copied inputs and derived numeric geometry, with no full wire, source
/// capability, mapping owner, admission, libc initialization or entry permission.
/// Successful construction does NOT prove the source-qualified records needed
/// by the eventual serializer/physical entry transaction.
pub struct CopiedInitialData {
    address: u64,
    placed: PlacedInputs,
    locations: CopiedInputLocations,
    metadata: PrivateRuntimeMetadata,
    tls: musl_tls::Plan,
    maps: Vec<Map>,
    target: physical::TargetLayout,
}
impl CopiedInitialData {
    /// Proposed first child byte address of this copied payload.
    pub fn address(&self) -> u64 {
        self.address
    }
    /// Immutable copied payload, not a complete scalar handoff.
    pub fn bytes(&self) -> &[u8] {
        &self.placed.bytes
    }
    /// Numeric copied locations; no address is dereferenced by this API.
    pub fn locations(&self) -> &CopiedInputLocations {
        &self.locations
    }
    /// Original captured aux values, before private PHDR/pointer substitution.
    pub fn original_aux(&self) -> impl ExactSizeIterator<Item = (u64, u64)> + '_ {
        self.placed
            .original_aux
            .iter()
            .map(|aux| (aux.kind, aux.value))
    }
    /// Same retained image's checked PHDR/TLS/stack projection; geometry only.
    pub fn image_metadata(&self) -> &PrivateRuntimeMetadata {
        &self.metadata
    }
    /// Shared numeric TLS geometry; not initialized TLS or a new arena owner.
    pub fn tls_geometry(&self) -> musl_tls::Plan {
        self.tls
    }
    /// Proposed table0 rows from the SAME planner consumed by the Injector.
    /// These are not successful-kernel mapping observations.
    pub fn planned_maps(&self) -> &[Map] {
        &self.maps
    }
    /// Target-compiled NativeControl byte count from the actual RO descriptor.
    pub fn control_bytes(&self) -> u64 {
        self.target.control_bytes
    }
    /// Target-compiled RelayStorage byte count from the actual RO descriptor.
    pub fn relay_bytes(&self) -> u64 {
        self.target.relay_bytes
    }
}

fn bounds<T>() -> Result<T> {
    Err("copied_input_data_bounds".into())
}
fn checked_extent(extent: Extent) -> Result<musl_tls::Extent> {
    Ok(musl_tls::Extent {
        start: usize::try_from(extent.start)?,
        bytes: usize::try_from(
            extent
                .end
                .checked_sub(extent.start)
                .ok_or("copied_input_data_bounds")?,
        )?,
    })
}
fn overlaps(a: Extent, b: Extent) -> bool {
    a.start < b.end && b.start < a.end
}

// Reuse the actual retained segment bytes, never a parallel file slice or a
// second ELF parser. The requested range must be initialized bytes, not BSS or
// rounded file-page padding. The actual descriptor decoder is shared below.
fn initialized_bytes<'a>(
    image: &ValidatedImage<'a>,
    address: u64,
    length: u64,
) -> Result<&'a [u8]> {
    let end = address
        .checked_add(length)
        .ok_or("copied_input_data_bounds")?;
    for load in image.segments() {
        let file_bytes = load
            .file
            .end
            .checked_sub(load.file.start)
            .ok_or("copied_input_data_bounds")?;
        let initialized_end = load
            .memory
            .start
            .checked_add(file_bytes)
            .ok_or("copied_input_data_bounds")?;
        if load.permissions.read
            && !load.permissions.write
            && !load.permissions.execute
            && load.memory.start <= address
            && end <= initialized_end
        {
            let offset = usize::try_from(address - load.memory.start)?;
            let end = offset
                .checked_add(usize::try_from(length)?)
                .ok_or("copied_input_data_bounds")?;
            return image
                .mapped_file_bytes(load)
                .map_err(|error| format!("copied_input_image: {error:?}"))?
                .get(offset..end)
                .ok_or_else(|| "copied_input_data_bounds".into());
        }
    }
    Err("copied_input_target_not_initialized_readonly".into())
}

// This is data-only interval validation, not another wire codec. The eventual
// complete serialized View must still pass its unchanged validate_roles check.
fn role_bounds(request: &CopiedInputRequest) -> Result<()> {
    let free = request.free_band;
    if free.start < TOOL_REGION.start || free.end > RUNTIME_WINDOW.start || free.start >= free.end {
        return bounds();
    }
    for (i, role) in request.roles.iter().copied().enumerate() {
        let length = role
            .end
            .checked_sub(role.start)
            .ok_or("copied_input_data_bounds")?;
        if !role.start.is_multiple_of(4096)
            || !role.end.is_multiple_of(4096)
            || !free.contains(role.start, length)
        {
            return bounds();
        }
        mapping_plan::interior(role)?;
        for earlier in &request.roles[..i] {
            if overlaps(role, *earlier) {
                return bounds();
            }
        }
    }
    Ok(())
}

fn build_data(
    image: &ValidatedImage<'_>,
    request: &CopiedInputRequest,
    original_page_size: u64,
    place: impl FnOnce(PrivateImageAux, u64, usize) -> Result<PlacedInputs>,
) -> Result<CopiedInitialData> {
    role_bounds(request)?;
    for load in image.segments() {
        let pages = load
            .pages()
            .map_err(|error| format!("copied_input_image: {error:?}"))?;
        if pages.start < RUNTIME_WINDOW.start || pages.end > RUNTIME_WINDOW.end {
            return bounds();
        }
    }
    let metadata = image
        .private_runtime_metadata()
        .map_err(|error| format!("copied_input_metadata: {error:?}"))?;
    let target =
        physical::decode_target_layout(initialized_bytes(image, request.layout_address, 96)?)?;
    let state = mapping_plan::interior(request.roles[4])?;
    let control = Extent {
        start: request.control_address,
        end: request
            .control_address
            .checked_add(target.control_bytes)
            .ok_or("copied_input_data_bounds")?,
    };
    let relay = Extent {
        start: request.relay_address,
        end: request
            .relay_address
            .checked_add(target.relay_bytes)
            .ok_or("copied_input_data_bounds")?,
    };
    let staging = physical::filter_staging(
        request.filter_scratch,
        &physical::target_recipe(target.gate)?,
    )?;
    let scratch = Extent {
        start: request.filter_scratch,
        end: request
            .filter_scratch
            .checked_add(u64::try_from(staging.len())?)
            .ok_or("copied_input_data_bounds")?,
    };
    if !request.control_address.is_multiple_of(target.control_align)
        || !request.relay_address.is_multiple_of(target.relay_align)
        || !state.contains(control.start, target.control_bytes)
        || !state.contains(relay.start, target.relay_bytes)
        || !state.contains(scratch.start, u64::try_from(staging.len())?)
        || overlaps(control, relay)
        || overlaps(control, scratch)
        || overlaps(relay, scratch)
    {
        return bounds();
    }
    let handoff = mapping_plan::interior(request.roles[3])?;
    let header_end = handoff
        .start
        .checked_add(u64::try_from(handoff::HEADER_BYTES)?)
        .ok_or("copied_input_data_bounds")?;
    let capacity = u64::try_from(request.copied_capacity)?;
    if request.copied_address < header_end
        || request.copied_capacity > handoff::MAX_BYTES
        || !handoff.contains(request.copied_address, capacity)
        || request
            .copied_address
            .checked_add(capacity)
            .and_then(|end| end.checked_sub(handoff.start))
            .is_none_or(|bytes| bytes > handoff::MAX_BYTES as u64)
    {
        return bounds();
    }
    let tls_backing = mapping_plan::interior(request.roles[1])?;
    let load = &metadata.tls.load;
    let file_length = load
        .file
        .end
        .checked_sub(load.file.start)
        .ok_or("copied_input_data_bounds")?;
    let file_end = load
        .memory
        .start
        .checked_add(file_length)
        .ok_or("copied_input_data_bounds")?;
    let tls = musl_tls::plan(
        checked_extent(Extent {
            start: TOOL_REGION.start,
            end: TOOL_REGION.end,
        })?,
        checked_extent(tls_backing)?,
        checked_extent(Extent {
            start: load.memory.start,
            end: load.memory.end,
        })?,
        checked_extent(Extent {
            start: load.memory.start,
            end: file_end,
        })?,
        musl_tls::Template {
            image: usize::try_from(metadata.tls.address)?,
            file_bytes: usize::try_from(metadata.tls.file_bytes)?,
            memory_bytes: usize::try_from(metadata.tls.memory_bytes)?,
            alignment: usize::try_from(metadata.tls.alignment)?,
        },
    )
    .map_err(|error| format!("copied_input_tls: {error:?}"))?;
    let steps = mapping_plan::production_steps(image, request.roles)?;
    let maps = mapping_plan::planned_ledger(&steps)?
        .into_iter()
        .map(|row| Map {
            start: row[0],
            end: row[1],
            protection: row[2],
            flags: row[3],
        })
        .collect();
    let private_image = PrivateImageAux {
        phdr: metadata.program_headers.start,
        phent: 56,
        phnum: u64::from(metadata.program_header_count),
        phdr_bytes: metadata
            .program_headers
            .end
            .checked_sub(metadata.program_headers.start)
            .ok_or("copied_input_data_bounds")?,
        page_size: original_page_size,
    };
    // This geometry maps with 4096-byte pages. Do not silently substitute the
    // host's page size or falsify the actual original aux value.
    if original_page_size != 4096 {
        return Err("copied_input_original_page_size".into());
    }
    let mut placed = place(
        private_image,
        request.copied_address,
        request.copied_capacity,
    )?;
    if placed.private_image != private_image {
        return Err("copied_input_private_image_projection_mismatch".into());
    }
    let env_bytes = placed
        .envp_words
        .checked_mul(8)
        .ok_or("copied_input_data_bounds")?;
    let aux_bytes = placed
        .raw_aux_words
        .checked_mul(8)
        .ok_or("copied_input_data_bounds")?;
    let argv_bytes = placed
        .argc
        .checked_add(1)
        .and_then(|words| words.checked_mul(8))
        .ok_or("copied_input_data_bounds")?;
    let payload_bytes = u64::try_from(placed.bytes.len())?;
    let payload = Extent {
        start: request.copied_address,
        end: request
            .copied_address
            .checked_add(payload_bytes)
            .ok_or("copied_input_data_bounds")?,
    };
    if payload_bytes > capacity
        || placed.envp.checked_add(env_bytes) != Some(placed.raw_aux)
        || !payload.contains(placed.envp, env_bytes)
        || !payload.contains(placed.raw_aux, aux_bytes)
        || !payload.contains(placed.argv, argv_bytes)
        || !payload.contains(placed.random, 16)
    {
        return bounds();
    }
    let name_start = usize::try_from(
        placed
            .program_name
            .checked_sub(request.copied_address)
            .ok_or("copied_input_data_bounds")?,
    )?;
    let name_end = name_start
        .checked_add(usize::try_from(placed.program_name_bytes)?)
        .ok_or("copied_input_data_bounds")?;
    let name = placed
        .bytes
        .get(name_start..name_end)
        .ok_or("copied_input_data_bounds")?;
    if name.last() != Some(&0) || name[..name.len() - 1].contains(&0) {
        return bounds();
    }
    let mut table_name = placed.program_name;
    if !table_name.is_multiple_of(8) {
        let name = name.to_vec();
        let at = placed
            .bytes
            .len()
            .checked_add(7)
            .map(|n| n & !7)
            .ok_or("copied_input_data_bounds")?;
        let end = at
            .checked_add(name.len())
            .ok_or("copied_input_data_bounds")?;
        if end > request.copied_capacity {
            return bounds();
        }
        placed.bytes.resize(at, 0);
        placed.bytes.extend_from_slice(&name);
        table_name = request
            .copied_address
            .checked_add(u64::try_from(at)?)
            .ok_or("copied_input_data_bounds")?;
    }
    let locations = CopiedInputLocations {
        argc: placed.argc,
        argv: placed.argv,
        envp: placed.envp,
        envp_words: placed.envp_words,
        raw_aux: placed.raw_aux,
        raw_aux_words: placed.raw_aux_words,
        program_name: table_name,
        program_name_bytes: placed.program_name_bytes,
        random: placed.random,
    };
    Ok(CopiedInitialData {
        address: request.copied_address,
        placed,
        locations,
        metadata,
        tls,
        maps,
        target,
    })
}

impl InitialExecStop<'_> {
    /// Assemble copied original inputs and same-image numeric geometry while
    /// borrowing the actual held stop. This returns NO complete handoff or entry
    /// capability. No child state, FD, filter, map or RPC admission is changed.
    ///
    /// Run on the original ptracer thread under the existing external deadline.
    /// Caller retains actual image/backing/mapping custody; equality snapshots
    /// cannot exclude concurrent external writers. Source-qualified complete
    /// records, real H admission/input sealing and all physical transitions
    /// remain separate unfinished work. This safe data API grants none of them.
    pub fn prepare_copied_inputs(
        &self,
        captured: &CapturedInitialInputs,
        image: &ValidatedImage<'_>,
        request: &CopiedInputRequest,
    ) -> Result<CopiedInitialData> {
        self.owner
            ._thread
            .as_ref()
            .ok_or("exec_stop_missing_original_ptracer")?
            .check_current()?;
        if !captured.matches_stop(self) {
            return Err("copied_input_foreign_capture".into());
        }
        initial_inputs::unchanged(self)?;
        let body = (|| {
            let page_size = captured
                .original_aux()
                .find(|(kind, _)| *kind == 6)
                .map(|(_, value)| value)
                .ok_or("copied_input_missing_original_page_size")?;
            build_data(
                image,
                request,
                page_size,
                |private_image, base, capacity| captured.place(private_image, base, capacity),
            )
        })();
        // Keep close-on-error as well: do not hide a lost original context behind
        // a numeric refusal or replace a primary data failure with close success.
        match (body, initial_inputs::unchanged(self)) {
            (Ok(data), Ok(())) => Ok(data),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(body), Err(close)) => Err(format!("{body}; copied_input_close: {close}").into()),
        }
    }
}

#[cfg(test)]
mod tests;
