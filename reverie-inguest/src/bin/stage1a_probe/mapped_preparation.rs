//! Nonexecuting physical preparation controls; never a runtime/admission wire.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;

use nix::fcntl::FcntlArg;
use nix::fcntl::SealFlag;
use nix::fcntl::fcntl;
use nix::sys::memfd::MFdFlags;
use nix::sys::memfd::memfd_create;
use reverie_inguest::launcher::exec_stop::CleanupReceipt;
use reverie_inguest::launcher::exec_stop::CopiedInitialData;
use reverie_inguest::launcher::exec_stop::CopiedInputRequest;
use reverie_inguest::launcher::exec_stop::ExecStop;
use reverie_inguest::launcher::exec_stop::PreparedExec;
use reverie_inguest::launcher::exec_stop::physical::Preparation;
use reverie_inguest::launcher::exec_stop::register_words;
use reverie_loader::artifact::RUNTIME_WINDOW;
use reverie_loader::artifact::TOOL_REGION;
use reverie_loader::handoff::Extent;
use reverie_loader::handoff::View;
use reverie_loader::handoff::{self};
use reverie_loader::image::Image;
use reverie_loader::image::Policy;
use reverie_loader::image::ValidatedImage;
use reverie_memory::Addr;
use reverie_memory::MemoryAccess;
use serde_json::Value;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;

use super::Result;
use super::cleanup_json;
const PAGE: u64 = 4096;
const INERT_PACKET: &[u8] = b"PREPARATION_ONLY_NOT_HLIINIT1";
const CASES: [&str; 9] = [
    "happy",
    "collision",
    "missing-runtime-seal",
    "wrong-ledger",
    "wrong-protection",
    "wrong-tcb",
    "wrong-operation",
    "wrong-handler",
    "wrong-aux",
];
fn early_numeric(case: &str) -> bool {
    matches!(
        case,
        "wrong-protection" | "wrong-tcb" | "wrong-operation" | "wrong-handler" | "wrong-aux"
    )
}

// Keep unresolved physical owners AND their callers' backing frames alive until
// the existing outer containment kills the complete subtree. Never return a
// counterfeit terminal receipt or free borrowed backing after failed cleanup.
fn hold_unconfirmed<T>(_owner: T) -> ! {
    eprintln!("UNCONFIRMED_RETIREMENT: retained owner/backing; waiting for outer containment");
    loop {
        std::thread::park();
    }
}
fn status_u64(status: &str, key: &str) -> Result<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .ok_or("missing kernel status field")?
        .trim()
        .parse()
        .map_err(Into::into)
}
fn map_covers(maps: &str, start: u64, end: u64, prot: u64) -> Result<bool> {
    let mut cursor = start;
    let expected = [
        if prot & 1 != 0 { b'r' } else { b'-' },
        if prot & 2 != 0 { b'w' } else { b'-' },
        if prot & 4 != 0 { b'x' } else { b'-' },
        b'p',
    ];
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (lo, hi) = fields
            .next()
            .ok_or("maps range")?
            .split_once('-')
            .ok_or("maps hyphen")?;
        let lo = u64::from_str_radix(lo, 16)?;
        let hi = u64::from_str_radix(hi, 16)?;
        let flags = fields.next().ok_or("maps permissions")?.as_bytes();
        if lo <= cursor && cursor < hi {
            if flags != expected {
                return Ok(false);
            }
            cursor = hi.min(end);
            if cursor == end {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn require(ok: bool, why: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(why.into()) }
}
fn number(input: &Value, key: &str) -> Result<u64> {
    input[key]
        .as_u64()
        .ok_or_else(|| format!("missing u64 {key}").into())
}
fn read_bound(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    require(bytes.len() <= max, "input byte bound")?;
    Ok(bytes)
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn exact_file(input: &Value, field: &str, max: usize) -> Result<Vec<u8>> {
    let path = input[field]["path"].as_str().ok_or("missing input path")?;
    let bytes = read_bound(Path::new(path), max)?;
    require(
        input[field]["sha256"].as_str() == Some(sha(&bytes).as_str()),
        "actual input SHA256 mismatch",
    )?;
    Ok(bytes)
}
fn memfd(bytes: &[u8], seal: bool) -> Result<File> {
    let mut file = File::from(memfd_create(
        c"mapped-preparation-control",
        MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
    )?);
    file.write_all(bytes)?;
    if seal {
        seal_file(&file)?;
    }
    Ok(file)
}
fn seal_file(file: &File) -> Result<()> {
    fcntl(
        file,
        FcntlArg::F_ADD_SEALS(
            SealFlag::F_SEAL_WRITE
                | SealFlag::F_SEAL_GROW
                | SealFlag::F_SEAL_SHRINK
                | SealFlag::F_SEAL_SEAL,
        ),
    )?;
    Ok(())
}
fn put(bytes: &mut [u8], word: usize, value: u64) {
    bytes[word * 8..word * 8 + 8].copy_from_slice(&value.to_le_bytes());
}
fn exact_ro(image: &ValidatedImage<'_>, bytes: &[u8], address: u64, len: usize) -> Result<Vec<u8>> {
    for segment in image.segments() {
        let file_bytes = segment.file.end - segment.file.start;
        if segment.permissions.read
            && !segment.permissions.write
            && !segment.permissions.execute
            && segment.memory.start <= address
            && address
                .checked_add(len as u64)
                .is_some_and(|end| end <= segment.memory.start + file_bytes)
        {
            let at = (segment.file.start + address - segment.memory.start) as usize;
            return Ok(bytes
                .get(at..at + len)
                .ok_or("RO descriptor file bytes")?
                .to_vec());
        }
    }
    Err("descriptor/reference must come from actual file-backed R-only segment".into())
}

/// Deliberately not a PreparedInitialImage or admission/source qualification.
/// The private Vec has no path to mapped entry; this module calls only prepare/cancel.
struct PreparationOnlyWire(Vec<u8>);
struct PreparationOnlyContext {
    pid: u64,
    regs: [u64; 27],
    mask: u64,
    input_fd: u64,
}
struct PreparationOnlyData<'a> {
    runtime: &'a [u8],
    input: &'a Value,
    roles: &'a [Extent; 5],
    descriptor: &'a [u64],
    reference: u64,
    copied: &'a CopiedInitialData,
    pkru: u32,
    free_band: Extent,
    case: &'a str,
}
// Exact initialized RX bytes from the SAME retained validated image. These
// observations are mapping-fixture data, not function/syscall qualification.
fn exact_rx<'a>(image: &ValidatedImage<'a>, address: u64, length: usize) -> Result<&'a [u8]> {
    let end = address
        .checked_add(length as u64)
        .ok_or("RX span overflow")?;
    for load in image.segments() {
        let initialized = image
            .mapped_file_bytes(load)
            .map_err(|e| format!("RX load: {e:?}"))?;
        if load.permissions.read
            && load.permissions.execute
            && !load.permissions.write
            && load.memory.start <= address
            && end
                <= load
                    .memory
                    .start
                    .checked_add(
                        load.file
                            .end
                            .checked_sub(load.file.start)
                            .ok_or("RX file size")?,
                    )
                    .ok_or("RX end overflow")?
        {
            let at = usize::try_from(address - load.memory.start)?;
            return initialized
                .get(at..at.checked_add(length).ok_or("RX offset overflow")?)
                .ok_or_else(|| "RX file bounds".into());
        }
    }
    Err("mapping-only observation outside initialized RX bytes".into())
}
fn aligned(value: u64, alignment: u64) -> Result<u64> {
    require(alignment.is_power_of_two(), "numeric alignment")?;
    Ok(value
        .checked_add(alignment - 1)
        .ok_or("alignment overflow")?
        & !(alignment - 1))
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
impl PreparationOnlyWire {
    fn build(
        image: &ValidatedImage<'_>,
        inputs: PreparationOnlyData<'_>,
        context: PreparationOnlyContext,
    ) -> Result<Self> {
        let PreparationOnlyData {
            runtime,
            input,
            roles,
            descriptor,
            reference,
            copied: data,
            pkru,
            free_band,
            case,
        } = inputs;
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
            "complete numeric fixture handoff needs header/table/payload space",
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
        let handler = number(&input["bootstrap"], "handler_address")?;
        let handler_len = usize::try_from(number(&input["bootstrap"], "handler_bytes")?)?;
        require(
            handler_len > 0 && handler_len <= 64 * 1024,
            "handler observation bounds",
        )?;
        require(
            input["bootstrap"]["handler_sha256"].as_str()
                == Some(sha(exact_rx(image, handler, handler_len)?).as_str()),
            "actual handler bytes",
        )?;
        let dev_null = number(&input["bootstrap"], "dev_null_address")?;
        require(
            exact_ro(image, runtime, dev_null, 10)? == b"/dev/null\0",
            "actual ELF dev-null literal",
        )?;
        let mut code = Vec::new();
        for load in image.segments() {
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
        let mut sites = Vec::new();
        let rows = input["bootstrap"]["sites"]
            .as_array()
            .ok_or("four measured bootstrap sites")?;
        require(rows.len() == 4, "exact four measured bootstrap sites")?;
        let mut seen = [false; 4];
        for row in rows {
            let row = row.as_array().ok_or("site row")?;
            require(row.len() == 4, "site row width")?;
            let mut values = [0; 4];
            for (out, value) in values.iter_mut().zip(row) {
                *out = value.as_u64().ok_or("site u64")?;
            }
            let [ip, post, number, operation] = values;
            let slot = match (operation, number) {
                (1, 158) => 0,
                (2, 218) => 1,
                (3, 7) => 2,
                (4, 2) => 3,
                _ => return Err("measured operation/number".into()),
            };
            require(!seen[slot], "duplicate measured role")?;
            seen[slot] = true;
            require(
                ip.checked_add(2) == Some(post) && exact_rx(image, ip, 2)? == [0x0f, 0x05],
                "actual syscall/post instruction bytes",
            )?;
            sites.push(handoff::SiteRecord {
                syscall_ip: ip,
                return_ip: post,
                number,
                operation,
            });
        }
        sites.sort_unstable_by_key(|site| site.return_ip);
        let tool_init = [number(&input["bootstrap"], "ordinary_post_ip")?];
        require(
            exact_rx(image, tool_init[0].checked_sub(2).ok_or("tool post")?, 2)? == [0x0f, 0x05],
            "actual ordinary syscall bytes, not ToolInit authorization",
        )?;
        let mut maps = data.planned_maps().to_vec();
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
            binding: [[0; 4]; 5], // Explicit numeric fixture; no digest is an authority claim.
            roles: *roles,
            registers: context.regs,
            scalars: [
                context.pid,
                control,
                data.control_bytes(),
                relay,
                data.relay_bytes(),
                context.input_fd,
                u64::from(pkru),
                context.mask,
                data.tls_geometry().pthread().start as u64,
                handler,
                reference,
                PAGE,
                metadata.gnu_stack_bytes,
                dev_null,
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
            (3, INERT_PACKET.len(), 1),
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
            maps: &maps,
            code: &code,
            sites: &sites,
            packet: INERT_PACKET,
            env: &env,
            aux: &aux,
            program_name: name,
            dev_null: b"/dev/null\0",
            tool_init: &tool_init,
        };
        handoff::serialize(&header, &tables, address, &mut bytes)
            .map_err(|e| format!("numeric fixture serialize: {e:?}"))?;
        let expected = reverie_loader::mapped_inputs::ConsumerLayout {
            free_band,
            region: Extent {
                start: TOOL_REGION.start,
                end: TOOL_REGION.end,
            },
            control_bytes: descriptor[6],
            relay_bytes: descriptor[8],
            control_align: descriptor[7],
            relay_align: descriptor[9],
        };
        // A negative starts only from a positive complete baseline. This currently
        // truthfully refuses V9's split RW load; see the named blocker in README.
        reverie_loader::mapped_inputs::ProductionMappedInputs::validate_at(
            &bytes, address, expected,
        )
        .map_err(|e| format!("complete numeric baseline refused: {e:?}"))?;
        match case {
            "wrong-ledger" => {
                // Preserve the original sorted row-zero protection mutation.
                // Its stack RW -> R remains numerically valid, but differs
                // from the actual successful mapped ledger after injection.
                maps[0].protection ^= libc::PROT_WRITE as u64;
                let offset = usize::try_from(header.tables[0].offset)?;
                put(&mut bytes, offset / 8 + 2, maps[0].protection);
            }
            "wrong-protection" => {
                // Select the actual control interval, never a guessed row.
                // The complete baseline already required its exact RW cover.
                let end = control
                    .checked_add(data.control_bytes())
                    .ok_or("control end")?;
                let matches: Vec<_> = maps
                    .iter()
                    .enumerate()
                    .filter(|(_, row)| {
                        row.start <= control && end <= row.end && row.protection == 3
                    })
                    .collect();
                require(matches.len() == 1, "unique actual RW control map")?;
                let (index, row) = matches[0];
                let offset = header.tables[0]
                    .offset
                    .checked_add((index as u64).checked_mul(32).ok_or("map row overflow")?)
                    .and_then(|n| n.checked_add(16))
                    .ok_or("map protection offset")?;
                put(
                    &mut bytes,
                    usize::try_from(offset)? / 8,
                    row.protection & !(libc::PROT_WRITE as u64),
                );
            }
            "wrong-tcb" => put(
                &mut bytes,
                65 + 8,
                header.scalars[8].checked_add(8).ok_or("TCB mutation")?,
            ),
            "wrong-operation" => {
                let offset = usize::try_from(header.tables[2].offset)?;
                put(&mut bytes, offset / 8 + 3, 99);
            }
            "wrong-handler" => put(&mut bytes, 65 + 9, reference),
            "wrong-aux" => {
                let offset = usize::try_from(header.tables[5].offset)?;
                let index = aux
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .position(|pair| pair[0] == 3)
                    .ok_or("actual AT_PHDR")?;
                put(&mut bytes, offset / 8 + index * 2 + 1, 0);
            }
            _ => {}
        }
        View::parse(&bytes, address).map_err(|e| format!("mutated fixture syntax: {e:?}"))?;
        Ok(Self(bytes))
    }
}

fn one_case(
    input: &Value,
    case: &str,
    runtime: &[u8],
    guest: &[OsString],
    row: &mut Value,
) -> Result<()> {
    let layout_address = number(input, "layout_address")?;
    let filter_scratch = number(input, "filter_scratch")?;
    let parsed = Image::parse(runtime).map_err(|e| format!("runtime ELF: {e:?}"))?;
    let image = parsed
        .validate(&Policy {
            window: RUNTIME_WINDOW,
            allow_tls: true,
        })
        .map_err(|e| format!("runtime: {e:?}"))?;
    image
        .private_runtime_metadata()
        .map_err(|e| format!("actual runtime metadata: {e:?}"))?;
    let descriptor = exact_ro(&image, runtime, layout_address, 96)?;
    let descriptor: Vec<_> = descriptor
        .as_chunks::<8>()
        .0
        .iter()
        .map(|v| u64::from_le_bytes(*v))
        .collect();
    require(
        descriptor[0] == u64::from_le_bytes(*b"HLMLAY01")
            && descriptor[1] == 1
            && descriptor[2] == 96
            && descriptor[3] == handoff::VERSION
            && descriptor[4] == handoff::HEADER_BYTES as u64
            && descriptor[5] == handoff::MAX_BYTES as u64
            && descriptor[6] > 0
            && descriptor[8] > 0
            && descriptor[7].is_power_of_two()
            && descriptor[9].is_power_of_two(),
        "actual target layout ABI",
    )?;
    let reference = number(input, "reference_address")?;
    exact_ro(&image, runtime, reference, 4096)?;
    let mut roles = [Extent { start: 0, end: 0 }; 5];
    for (i, role) in roles.iter_mut().enumerate() {
        let raw = input["roles"].get(i).ok_or("five role extents required")?;
        *role = Extent {
            start: raw[0].as_u64().ok_or("role start")?,
            end: raw[1].as_u64().ok_or("role end")?,
        };
    }
    require(
        input["roles"].as_array().is_some_and(|v| v.len() == 5),
        "exactly five roles",
    )?;
    // Source-bound shared ToolRegion layout: DATA_FIRST=1MiB/PAGE,
    // TOOL_BAND.0=65535. This is not evidence that adoption occurred.
    let free_band = Extent {
        start: TOOL_REGION.start + 1024 * 1024,
        end: TOOL_REGION.start + 65535 * PAGE,
    };
    for (i, role) in roles.iter().enumerate() {
        require(
            role.start % PAGE == 0
                && role.end % PAGE == 0
                && free_band.contains(
                    role.start,
                    role.end.checked_sub(role.start).ok_or("role underflow")?,
                )
                && role
                    .end
                    .checked_sub(role.start)
                    .is_some_and(|len| len >= 3 * PAGE),
            "bounded complete guarded role",
        )?;
        for earlier in &roles[..i] {
            require(
                role.end <= earlier.start || earlier.end <= role.start,
                "overlapping guarded roles",
            )?;
        }
    }
    let runtime_file = memfd(runtime, case != "missing-runtime-seal")?;
    // Inherit this actual OFD before exec; fill from authentic stopped registers
    // then seal it while the child remains stopped. No child reads this file.
    let handoff = memfd(&[], false)?;
    let input_file = memfd(INERT_PACKET, true)?;
    // A real same-OFD alias and an equal-content object were NOT inherited.
    let not_inherited_alias = input_file.try_clone()?;
    let not_inherited_equal = memfd(INERT_PACKET, true)?;
    let receipt = CleanupReceipt::default();
    let environment: Vec<_> = std::env::vars_os().collect();
    let launch = PreparedExec::new(
        Path::new(guest.first().ok_or("missing guest")?),
        guest,
        &environment,
        None,
        vec![runtime_file.as_fd(), handoff.as_fd(), input_file.as_fd()],
    )?;
    let stopped = match ExecStop::spawn(launch, receipt.clone()) {
        Ok(stopped) => stopped,
        Err(mut failure) => {
            if !failure.retry_cleanup() {
                hold_unconfirmed(failure);
            }
            row["cleanup"] = cleanup_json(&failure.cleanup());
            return Err(format!("actual spawn failure: {failure:?}").into());
        }
    };
    let setup = (|| -> Result<_> {
        let pid = stopped.pid().as_raw() as u64;
        let entry = stopped.entry();
        let mut original_entry = vec![0; 16];
        stopped.stopped().read_exact(
            Addr::from_raw(entry.regs().rip as usize).ok_or("null entry")?,
            &mut original_entry,
        )?;
        let original_regs = register_words(entry.regs());
        let original_stack_sha = sha(entry.stack_bytes());
        let original_mask = entry.signal_mask();
        let original_status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
        // SAFETY: EntryContext owns the complete unchanged real ptrace XSAVE
        // capture for this held generation. The existing outer lane pins this
        // command to a homogeneous compatible CPU domain; CPUID/XGETBV remain
        // permitted/stable. No fallback or mutation of captured XState occurs.
        let pkru =
            unsafe { entry.xstate().pkru() }.map_err(|e| format!("actual stopped PKRU: {e:?}"))?;
        let captured = stopped.capture_initial_inputs()?;
        let control = roles[4].start.checked_add(PAGE).ok_or("control overflow")?;
        let relay = aligned(
            control.checked_add(descriptor[6]).ok_or("relay overflow")?,
            descriptor[9],
        )?;
        let address = roles[3].start.checked_add(PAGE).ok_or("handoff overflow")?;
        let copied_address = address.checked_add(2 * PAGE).ok_or("copied address")?;
        let copied_capacity = usize::try_from(
            roles[3]
                .end
                .checked_sub(PAGE)
                .and_then(|end| end.checked_sub(copied_address))
                .ok_or("copied capacity")?,
        )?;
        let copied = stopped.prepare_copied_inputs(
            &captured,
            &image,
            &CopiedInputRequest {
                roles,
                free_band,
                layout_address,
                copied_address,
                copied_capacity,
                control_address: control,
                relay_address: relay,
                filter_scratch,
            },
        )?;
        let wire = PreparationOnlyWire::build(
            &image,
            PreparationOnlyData {
                runtime,
                input,
                roles: &roles,
                descriptor: &descriptor,
                reference,
                copied: &copied,
                pkru,
                free_band,
                case,
            },
            PreparationOnlyContext {
                pid,
                regs: original_regs,
                mask: original_mask,
                input_fd: input_file.as_raw_fd() as u64,
            },
        )?;
        let role_bytes = roles[3]
            .end
            .checked_sub(roles[3].start)
            .and_then(|v| v.checked_sub(2 * PAGE))
            .ok_or("handoff guards")?;
        require(
            role_bytes == (wire.0.len() as u64).div_ceil(PAGE) * PAGE,
            "handoff role must exactly fit wire rounded page",
        )?;
        handoff.write_all_at(&wire.0, 0)?;
        handoff.set_len(role_bytes)?;
        seal_file(&handoff)?;
        Ok((
            pid,
            original_entry,
            original_regs,
            original_stack_sha,
            original_mask,
            original_status,
            wire,
        ))
    })();
    let (
        pid,
        original_entry,
        original_regs,
        original_stack_sha,
        original_mask,
        original_status,
        wire,
    ) = match setup {
        Ok(value) => value,
        Err(error) => {
            match stopped.cancel() {
                Ok(cleanup) => row["cleanup"] = cleanup_json(&cleanup),
                Err(owner) => hold_unconfirmed(owner),
            }
            return Err(error);
        }
    };
    let preparation = Preparation {
        runtime_fd: runtime_file.as_fd(),
        runtime_bytes: runtime,
        layout_address,
        handoff_fd: handoff.as_fd(),
        handoff_bytes: &wire.0,
        handoff_address: roles[3].start + PAGE,
        input_fd: input_file.as_fd(),
        free_band,
        filter_scratch,
    };
    // SAFETY: This is the original same-thread ptracer owner with inherited
    // immutable OFDs, real context and filter lineage from ExecStop. Outer
    // run-host owns physical bounds. Inputs persist until confirmed death; no
    // image/guest entry is called and this private wire has no execution path.
    let prepared = unsafe { stopped.prepare_mapping(preparation) };
    *row = json!({"case":case,"pid":pid,"wire":"NOT_EXECUTION_ELIGIBLE","runtime_sha256":sha(runtime),
        "original_registers":original_regs,"original_mask":original_mask,"original_stack_sha256":original_stack_sha,
        "original_entry_bytes":original_entry,"status_before":original_status,
        "entry_instructions":0,"original_guest_instructions":0,"RPC":"NOT_RUN","Ready":"NOT_PROVEN"});
    match prepared {
        Ok(prepared) => {
            // Collect fallible custody observations, then ALWAYS cancel before
            // interpreting them. This is preparation-only, not RPC admission.
            let custody = (|| -> Result<()> {
                for fd in [runtime_file.as_fd(), handoff.as_fd(), input_file.as_fd()] {
                    let birth = prepared.duplicate_birth_pidfd_for_inherited(fd)?;
                    let flags = fcntl(&birth, FcntlArg::F_GETFD)?;
                    require(flags & libc::FD_CLOEXEC != 0, "custody pidfd not CLOEXEC")?;
                }
                for fd in [not_inherited_alias.as_fd(), not_inherited_equal.as_fd()] {
                    let error = prepared
                        .duplicate_birth_pidfd_for_inherited(fd)
                        .err()
                        .ok_or("unborrowed descriptor unexpectedly accepted")?;
                    require(
                        error.to_string() == "exec_stop_descriptor_not_inherited",
                        "unborrowed descriptor accepted or wrong refusal",
                    )?;
                }
                Ok(())
            })();
            let observation = prepared.diagnostic_observation();
            let cancelled = match prepared.cancel() {
                Ok(receipt) => receipt,
                Err(retained) => hold_unconfirmed(retained),
            };
            row["cleanup"] = cleanup_json(&cancelled.cleanup);
            row["injected_calls"] = json!(cancelled.injected_calls);
            row["filter_bytes"] = json!(cancelled.filter_bytes);
            require(
                case == "happy",
                "negative control unexpectedly prepared (retired)",
            )?;
            custody?;
            row["postmap_inherited_descriptor_custody"] = json!("CHECKED_ORIGINAL_REQUEST_ONLY");
            let observed = observation?;
            row["observed"] = json!({"registers":observed.registers,"signal_mask":observed.signal_mask,
                "xstate_exact":observed.xstate_exact,"stack_exact":observed.stack_exact,"stack_bytes":observed.stack_bytes,
                "entry_bytes":observed.entry_bytes,"maps":observed.maps,"status":observed.status,
                "runtime_contents_exact":observed.runtime_contents_exact,"handoff_exact":observed.handoff_exact});
            require(
                observed.registers == original_regs
                    && observed.signal_mask == original_mask
                    && observed.xstate_exact
                    && observed.stack_exact
                    && observed.entry_bytes == original_entry
                    && observed.runtime_contents_exact
                    && observed.handoff_exact,
                "actual full original stopped context did not match",
            )?;
            require(
                status_u64(&observed.status, "Seccomp:")? == 2
                    && status_u64(&observed.status, "NoNewPrivs:")? == 1
                    && status_u64(&observed.status, "Seccomp_filters:")?
                        == status_u64(&original_status, "Seccomp_filters:")? + 1,
                "actual kernel filter count/mode/NNP did not match",
            )?;
            for segment in image.segments() {
                let pages = segment.pages().map_err(|e| format!("pages: {e:?}"))?;
                let prot = u64::from(segment.permissions.read)
                    | (u64::from(segment.permissions.write) << 1)
                    | (u64::from(segment.permissions.execute) << 2);
                require(
                    map_covers(&observed.maps, pages.start, pages.end, prot)?,
                    "actual runtime VMA permissions",
                )?;
            }
            for (i, role) in roles.iter().enumerate() {
                require(
                    map_covers(&observed.maps, role.start, role.start + PAGE, 0)?
                        && map_covers(&observed.maps, role.end - PAGE, role.end, 0)?
                        && map_covers(
                            &observed.maps,
                            role.start + PAGE,
                            role.end - PAGE,
                            if i == 3 { 1 } else { 3 },
                        )?,
                    "actual guarded role VMA permissions",
                )?;
            }
            row["injected_calls"] = json!(cancelled.injected_calls);
            row["filter_bytes"] = json!(cancelled.filter_bytes);
            row["cleanup"] = cleanup_json(&cancelled.cleanup);
            require(
                cancelled.cleanup.confirmed && cancelled.filter_bytes.len() == 23 * 8,
                "filter/cancel evidence",
            )?;
            let calls = cancelled.injected_calls;
            let last = calls.last().ok_or("missing actual injected filter")?;
            require(
                last.0 == libc::SYS_seccomp as u64 && last.2 == 0,
                "last real injected syscall must be successful seccomp",
            )?;
            row["outcome"] = json!("PASS_PREPARATION_CANCEL_ONLY");
        }
        Err(mut failure) => {
            let error = failure.error.to_string();
            let calls = failure.diagnostic_calls();
            if !failure.retry_cleanup() {
                hold_unconfirmed(failure);
            }
            row["actual_refusal"] = json!(error);
            row["injected_calls"] = json!(calls);
            row["cleanup"] = cleanup_json(&failure.cleanup());
            let expected = match case {
                "collision" => "tool_region_collision",
                "missing-runtime-seal" => "mapped_preparation_sealed_file_identity",
                "wrong-ledger" => "mapped_preparation_ledger_identity",
                case if early_numeric(case) => "mapped_preparation_wire: Value",
                _ => return Err(format!("happy preparation refused: {error}").into()),
            };
            require(
                error.starts_with(expected) && failure.cleanup().confirmed,
                "wrong refusal or unconfirmed original-owner cleanup",
            )?;
            if early_numeric(case) {
                require(calls.is_empty(), "early numeric refusal injected a syscall")?;
                let snapshot = failure
                    .diagnostic_prevalidation()
                    .ok_or("missing actual prevalidation context")?;
                require(
                    snapshot.registers == original_regs
                        && snapshot.signal_mask == original_mask
                        && snapshot.xstate_exact,
                    "early numeric validation did not retain original actual context",
                )?;
                row["prevalidation_context"] = json!({"registers":snapshot.registers,
                    "signal_mask":snapshot.signal_mask,"xstate_exact":snapshot.xstate_exact,
                    "sample_cut":"ACTUAL_HELD_STOP_IMMEDIATELY_BEFORE_PURE_VALIDATION"});
                // Failure already retired the owner; never read /proc/PID or
                // infer postmortem current registers from this retained sample.
            }
            if case == "missing-runtime-seal" {
                require(calls.is_empty(), "unsealed runtime progressed into child")?;
            }
            if case == "collision" {
                require(
                    calls.last().is_some_and(|c| {
                        c.0 == libc::SYS_mmap as u64 && c.2 == (-libc::EEXIST as i64) as u64
                    }),
                    "collision lacked actual kernel EEXIST",
                )?;
            }
            if case == "wrong-ledger" {
                require(
                    !calls.is_empty() && !calls.iter().any(|c| c.0 == libc::SYS_seccomp as u64),
                    "ledger control must map then refuse before filter",
                )?;
            }
            row["outcome"] = json!("PASS_EXPECTED_REAL_REFUSAL_AND_CONFIRMED_RETIREMENT");
        }
    }
    Ok(())
}

pub(super) fn run(args: &[OsString]) -> Result<()> {
    require(
        args.len() >= 5 && args[3] == "--",
        "usage: --mapped-preparation-only INPUT.json REPORT.json -- /absolute/guest ...",
    )?;
    let input: Value = serde_json::from_slice(&read_bound(Path::new(&args[1]), 64 * 1024)?)?;
    require(
        input["mode"] == "PREPARATION_ONLY_NOT_EXECUTION_ELIGIBLE",
        "explicit nonexecuting input mode required",
    )?;
    let runtime = exact_file(&input, "runtime", 512 * 1024 * 1024)?;
    let collision = exact_file(&input, "collision_guest", 1024 * 1024)?;
    let collision_image = Image::parse(&collision).map_err(|e| format!("collision ELF: {e:?}"))?;
    let collision_image = collision_image
        .validate(&Policy {
            window: TOOL_REGION,
            allow_tls: false,
        })
        .map_err(|e| format!("collision PT_LOAD: {e:?}"))?;
    require(
        collision_image
            .segments()
            .any(|s| s.memory.start < TOOL_REGION.end && TOOL_REGION.start < s.memory.end),
        "actual collision ELF PT_LOAD must overlap ToolRegion",
    )?;
    let collision_guest = [OsString::from(
        input["collision_guest"]["path"]
            .as_str()
            .ok_or("collision path")?,
    )];
    let mut report = json!({"mode":"MAPPED_PREPARATION_ONLY","state":"FAIL","cases":[],"tests_expected":CASES.len(),
        "compiled_source_binding":option_env!("REVERIE_MAPPED_PREPARATION_SOURCE_BINDING").unwrap_or("UNBOUND"),
        "image_qualification":"NOT_PROVEN","runtime_entry_instructions":0,"original_guest_instructions":0,
        "scope":"INJECTED_SYSCALL_INT3_MAP_FILTER_RESTORE_CANCEL","RPC":"NOT_RUN","Ready":"NOT_PROVEN"});
    let outcome = (|| -> Result<()> {
        for case in CASES {
            let guest = if case == "collision" {
                &collision_guest[..]
            } else {
                &args[4..]
            };
            let mut row = json!({"case":case,"outcome":"FAIL"});
            let result = one_case(&input, case, &runtime, guest, &mut row);
            if let Err(error) = &result {
                row["outcome"] = json!("FAIL");
                row["error"] = json!(error.to_string());
            }
            report["cases"].as_array_mut().unwrap().push(row);
            result?;
        }
        report["state"] = json!("PASS_NINE_PREPARATION_ONLY_CONTROLS");
        Ok(())
    })();
    report["cases_attempted"] = json!(report["cases"].as_array().unwrap().len());
    report["cases_not_run"] = json!(
        CASES
            .into_iter()
            .skip(report["cases"].as_array().unwrap().len())
            .collect::<Vec<_>>()
    );
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Path::new(&args[2]))?;
    output.write_all(&serde_json::to_vec_pretty(&report)?)?;
    outcome
}
