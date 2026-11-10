// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! The HLSCAL01 handoff for one birth of an audited runtime image.
//!
//! The bytes are those of the embedder wire this was promoted from, for the
//! same inputs: the same header words, table order and alignment, and all-zero
//! binding digests (see [`claim`](super::claim): the handoff is unbound and
//! unqualified until real digests exist). HLSCAL01 version 1 is x86-64 only;
//! another target refuses by name.

use reverie_loader::artifact::TOOL_REGION;
use reverie_loader::handoff;
use reverie_loader::handoff::Extent;
use reverie_loader::image::ValidatedImage;

use super::super::CopiedInitialData;
use super::super::Result;
use super::AuditedRuntimeImage;
use super::PAGE;
use super::Placement;
use super::aligned;
use super::require;

/// The stopped birth's scalars the header records.
pub(super) struct WireContext {
    pub(super) pid: u64,
    pub(super) registers: [u64; 27],
    pub(super) mask: u64,
    pub(super) input_fd: u64,
    pub(super) pkru: u32,
}

/// A serialized handoff and the child address of its first byte.
pub(super) struct Wire {
    pub(super) bytes: Vec<u8>,
    pub(super) address: u64,
}

#[cfg(not(target_arch = "x86_64"))]
pub(super) fn build(
    _image: &AuditedRuntimeImage,
    _validated: &ValidatedImage<'_>,
    _copied: &CopiedInitialData,
    _packet: &[u8],
    _context: WireContext,
) -> Result<Wire> {
    Err("exec_stop_producer_arch_unsupported: HLSCAL01 version 1 is x86-64 only".into())
}

fn payload_words(data: &CopiedInitialData, address: u64, count: u64) -> Result<Vec<u64>> {
    let start = usize::try_from(address.checked_sub(data.address()).ok_or("copied offset")?)?;
    let length = usize::try_from(count.checked_mul(8).ok_or("copied words overflow")?)?;
    let end = start.checked_add(length).ok_or("copied end overflow")?;
    Ok(data
        .bytes()
        .get(start..end)
        .ok_or("copied words bounds")?
        .as_chunks::<8>()
        .0
        .iter()
        .map(|row| u64::from_le_bytes(*row))
        .collect())
}

fn payload_bytes(data: &CopiedInitialData, address: u64, length: u64) -> Result<&[u8]> {
    let start = usize::try_from(address.checked_sub(data.address()).ok_or("copied offset")?)?;
    let end = start
        .checked_add(usize::try_from(length)?)
        .ok_or("copied end overflow")?;
    data.bytes()
        .get(start..end)
        .ok_or_else(|| "copied bytes bounds".into())
}

#[cfg(target_arch = "x86_64")]
pub(super) fn build(
    image: &AuditedRuntimeImage,
    validated: &ValidatedImage<'_>,
    data: &CopiedInitialData,
    packet: &[u8],
    context: WireContext,
) -> Result<Wire> {
    let placement = Placement::fixed()?;
    let roles = &placement.roles;
    let descriptor = image.descriptor();
    let facts = image.facts();
    let address = roles[3].start.checked_add(PAGE).ok_or("handoff overflow")?;
    let length = usize::try_from(
        roles[3]
            .end
            .checked_sub(address)
            .and_then(|end| end.checked_sub(PAGE))
            .ok_or("handoff guards")?,
    )?;
    require(
        length <= handoff::MAX_BYTES && length >= 3 * PAGE as usize,
        "complete handoff needs header/table/payload space",
    )?;
    let mut bytes = vec![0; length];
    let at = usize::try_from(
        data.address()
            .checked_sub(address)
            .ok_or("payload offset")?,
    )?;
    let end = at
        .checked_add(data.bytes().len())
        .ok_or("payload overflow")?;
    bytes
        .get_mut(at..end)
        .ok_or("payload bounds")?
        .copy_from_slice(data.bytes());
    let metadata = data.image_metadata();
    let mut code = Vec::new();
    for load in validated.segments() {
        if load.permissions.read && load.permissions.execute && !load.permissions.write {
            let end = load
                .memory
                .start
                .checked_add(load.file.end - load.file.start)
                .ok_or("code end")?;
            code.push(handoff::Code {
                start: load.memory.start,
                end,
            });
        }
    }
    // Qualification already checked each site's role, number and bytes.
    let mut sites: Vec<handoff::SiteRecord> = facts
        .sites
        .iter()
        .map(|&[ip, post, number, operation]| handoff::SiteRecord {
            syscall_ip: ip,
            return_ip: post,
            number,
            operation,
        })
        .collect();
    sites.sort_unstable_by_key(|site| site.return_ip);
    let tool_init = &facts.ordinary_post_ips;
    let maps = data.planned_maps();
    let locations = data.locations();
    let env = payload_words(data, locations.envp, locations.envp_words)?;
    let aux = payload_words(data, locations.raw_aux, locations.raw_aux_words)?;
    let name = payload_bytes(data, locations.program_name, locations.program_name_bytes)?;
    let control = roles[4].start.checked_add(PAGE).ok_or("control overflow")?;
    let relay = aligned(
        control.checked_add(descriptor[6]).ok_or("relay overflow")?,
        descriptor[9],
    )?;
    let tls = &metadata.tls;
    let backing = data.tls_geometry().backing();
    let mut header = handoff::Header {
        prefix: [
            handoff::MAGIC,
            handoff::VERSION,
            length as u64,
            handoff::HEADER_BYTES as u64,
            0,
            0,
            0,
            0,
        ],
        // All zero: the handoff is unbound (claim::HANDOFF_BINDING_UNBOUND).
        binding: [[0; 4]; 5],
        roles: *roles,
        registers: context.registers,
        scalars: [
            context.pid,
            control,
            data.control_bytes(),
            relay,
            data.relay_bytes(),
            context.input_fd,
            u64::from(context.pkru),
            context.mask,
            data.tls_geometry().pthread().start as u64,
            facts.handler_address,
            facts.reference_address,
            PAGE,
            metadata.gnu_stack_bytes,
            facts.dev_null_address,
            0,
            0,
        ],
        tables: std::array::from_fn(|_| handoff::Table {
            offset: 0,
            count: 0,
            stride: 0,
        }),
        tls: [
            metadata.program_headers.start,
            56,
            u64::from(metadata.program_header_count),
            tls.address,
            tls.file_bytes,
            tls.memory_bytes,
            tls.alignment,
            backing.start as u64,
            backing.bytes as u64,
            tls.load.memory.start,
            tls.load.memory.end - tls.load.memory.start,
            tls.load.file.end - tls.load.file.start,
        ],
    };
    // Reserve complete metadata tables below the already placed copied payload.
    let mut cursor = handoff::HEADER_BYTES as u64;
    for (index, count, stride) in [
        (0, maps.len(), 32),
        (1, code.len(), 16),
        (2, sites.len(), 32),
        (3, packet.len(), 1),
        (7, 10, 1),
        (8, tool_init.len(), 8),
    ] {
        cursor = aligned(cursor, 8)?;
        header.tables[index] = handoff::Table {
            offset: cursor,
            count: count as u64,
            stride,
        };
        cursor = cursor
            .checked_add((count as u64).checked_mul(stride).ok_or("table size")?)
            .ok_or("table end")?;
    }
    require(cursor <= at as u64, "metadata would overlap copied payload")?;
    for (index, location, count, stride) in [
        (4, locations.envp, locations.envp_words, 8),
        (5, locations.raw_aux, locations.raw_aux_words, 8),
        (6, locations.program_name, locations.program_name_bytes, 1),
    ] {
        header.tables[index] = handoff::Table {
            offset: location.checked_sub(address).ok_or("table offset")?,
            count,
            stride,
        };
    }
    let tables = handoff::TableData {
        maps,
        code: &code,
        sites: &sites,
        packet,
        env: &env,
        aux: &aux,
        program_name: name,
        dev_null: b"/dev/null\0",
        tool_init,
    };
    handoff::serialize(&header, &tables, address, &mut bytes)
        .map_err(|e| format!("handoff serialize: {e:?}"))?;
    let expected = reverie_loader::mapped_inputs::ConsumerLayout {
        free_band: placement.free_band,
        region: Extent {
            start: TOOL_REGION.start,
            end: TOOL_REGION.end,
        },
        control_bytes: descriptor[6],
        relay_bytes: descriptor[8],
        control_align: descriptor[7],
        relay_align: descriptor[9],
    };
    // The unchanged complete production predicate, before any mapping.
    reverie_loader::mapped_inputs::ProductionMappedInputs::validate_at(&bytes, address, expected)
        .map_err(|e| format!("handoff refused by the production predicate: {e:?}"))?;
    let view =
        handoff::View::parse(&bytes, address).map_err(|e| format!("handoff parse: {e:?}"))?;
    require(
        view.table(3)
            .map_err(|e| format!("handoff packet table: {e:?}"))?
            .bytes()
            == packet,
        "serialized table 3 lost the packet",
    )?;
    Ok(Wire { bytes, address })
}
