use reverie_loader::image::Image;
use reverie_loader::image::Policy;

use super::*;
use crate::launcher::exec_stop::CleanupReceipt;
use crate::launcher::exec_stop::ExecStop;
use crate::launcher::exec_stop::PreparedExec;
use crate::launcher::exec_stop::initial_stack_inputs::ParsedInitial;

const STACK: u64 = 0x7000;

fn image_bytes() -> Vec<u8> {
    let base = RUNTIME_WINDOW.start;
    let mut bytes = vec![0; 8704];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[24..32].copy_from_slice(&(base + 4096).to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&6_u16.to_le_bytes());
    for (i, (kind, flags, offset, address, file, memory, align)) in [
        (1_u32, 4_u32, 0_u64, base, 4096_u64, 4096_u64, 4096_u64),
        (1, 5, 4096, base + 4096, 4096, 4096, 4096),
        (1, 6, 8192, base + 8192, 512, 4096, 4096),
        (7, 4, 8192, base + 8192, 16, 80, 8),
        (0x6474_e551, 6, 0, 0, 0, 8 * 1024 * 1024, 0),
        (6, 4, 64, base + 64, 336, 336, 8),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 64 + i * 56;
        bytes[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
        for (relative, value) in [
            (8, offset),
            (16, address),
            (32, file),
            (40, memory),
            (48, align),
        ] {
            bytes[at + relative..at + relative + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    for (i, word) in [
        u64::from_le_bytes(*b"HLMLAY01"),
        1,
        96,
        handoff::VERSION,
        handoff::HEADER_BYTES as u64,
        handoff::MAX_BYTES as u64,
        64,
        16,
        128,
        8,
        base + 4096,
        base + 4096 + 0x7c,
    ]
    .into_iter()
    .enumerate()
    {
        bytes[512 + i * 8..520 + i * 8].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn request() -> CopiedInputRequest {
    let free_band = crate::guest::tool_region::scalar_free_band();
    let base = free_band.start;
    let roles = core::array::from_fn(|i| Extent {
        start: base + i as u64 * 0x10000,
        end: base + i as u64 * 0x10000 + 0x8000,
    });
    CopiedInputRequest {
        free_band,
        layout_address: RUNTIME_WINDOW.start + 512,
        copied_address: roles[3].start + 8192,
        copied_capacity: 8192,
        control_address: roles[4].start + 4096,
        relay_address: roles[4].start + 5120,
        filter_scratch: roles[4].start + 8192,
        roles,
    }
}

fn original_stack(empty_argv: bool) -> (Vec<u8>, Vec<(u64, u64)>) {
    let aux = vec![
        (3, 0x400040),
        (4, 56),
        (5, 4),
        (6, 4096),
        (11, 1001),
        (12, 0),
        (13, 1002),
        (14, 0),
        (16, 0xffff_ffff_8000_0000),
        (23, 1),
        (25, STACK + 1120),
        (31, STACK + 1152),
    ];
    let mut words = if empty_argv {
        vec![0, 0]
    } else {
        vec![1, STACK + 1024, 0]
    };
    words.extend([STACK + 1040, 0]);
    for &(kind, value) in &aux {
        words.extend([kind, value]);
    }
    words.extend([0, 0]);
    let mut bytes = vec![0xcc; 2048];
    for (i, word) in words.into_iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    for (at, string) in [
        (1024, b"prog\0".as_slice()),
        (1040, b"X=Y\0"),
        (1152, b"/bin/prog\0"),
    ] {
        bytes[at..at + string.len()].copy_from_slice(string);
    }
    bytes[1120..1136].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    (bytes, aux)
}

fn data(
    image: &[u8],
    request: &CopiedInputRequest,
    stack: &[u8],
    page: u64,
) -> Result<CopiedInitialData> {
    let parsed_image = Image::parse(image).unwrap();
    let image = parsed_image
        .validate(&Policy {
            window: RUNTIME_WINDOW,
            allow_tls: true,
        })
        .unwrap();
    let original = ParsedInitial::parse(STACK, stack, STACK).unwrap();
    build_data(&image, request, page, |image, address, capacity| {
        original
            .copy_plan(image, &[], &[], capacity)
            .and_then(|plan| plan.place(address, u64::try_from(capacity).unwrap()))
            .map_err(|error| format!("copy fixture: {error:?}").into())
    })
}
fn at(data: &CopiedInitialData, address: u64, count: usize) -> &[u8] {
    let start = usize::try_from(address - data.address()).unwrap();
    &data.bytes()[start..start + count]
}
fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

#[test]
fn copies_actual_source_vectors_entropy_and_secure_aux_with_same_image_projection() {
    let (stack, aux) = original_stack(false);
    let before = stack.clone();
    let request = request();
    let data = data(&image_bytes(), &request, &stack, 4096).unwrap();
    let locations = data.locations();
    assert_eq!(stack, before);
    assert_eq!(data.original_aux().collect::<Vec<_>>(), aux);
    assert_eq!(locations.argc, 1);
    assert_eq!(at(&data, word(at(&data, locations.argv, 8)), 5), b"prog\0");
    assert_eq!(at(&data, word(at(&data, locations.envp, 8)), 4), b"X=Y\0");
    assert_eq!(locations.raw_aux, locations.envp + locations.envp_words * 8);
    assert_eq!(word(at(&data, locations.raw_aux - 8, 8)), 0);
    assert_eq!(at(&data, locations.random, 16), &before[1120..1136]);
    for (i, &(kind, original)) in aux.iter().enumerate() {
        let pair = at(&data, locations.raw_aux + i as u64 * 16, 16);
        assert_eq!(word(pair), kind);
        if kind == 31 {
            assert_eq!(at(&data, word(&pair[8..]), 10), b"/bin/prog\0");
        } else {
            assert_eq!(
                word(&pair[8..]),
                match kind {
                    3 => RUNTIME_WINDOW.start + 64,
                    4 => 56,
                    5 => 6,
                    25 => locations.random,
                    _ => original,
                }
            );
        }
    }
    assert_eq!(
        at(
            &data,
            locations.raw_aux + (locations.raw_aux_words - 2) * 8,
            16
        ),
        &[0; 16]
    );
    assert_eq!(
        data.image_metadata().program_headers,
        RUNTIME_WINDOW.start + 64..RUNTIME_WINDOW.start + 400
    );
    assert_eq!(data.control_bytes(), 64);
    assert_eq!(data.relay_bytes(), 128);
    assert_eq!(data.tls_geometry().module_bytes(), 80);
    assert_eq!(data.tls_geometry().total_bytes(), 304);
    assert_eq!(
        data.tls_geometry().pthread().start as u64,
        request.roles[1].start + 4096 + 104
    );
    // Three image maps, the allocator control prefix, and five bootstrap roles.
    assert_eq!(data.planned_maps().len(), 9);
    let prefix = crate::guest::tool_region::scalar_control_prefix();
    let actual_prefix = &data.planned_maps()[0];
    assert_eq!(actual_prefix.start, prefix.start);
    assert_eq!(actual_prefix.end, prefix.end);
    assert_eq!(
        actual_prefix.protection,
        (libc::PROT_READ | libc::PROT_WRITE) as u64
    );
    assert_eq!(
        actual_prefix.flags,
        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as u64
    );
    assert!(
        data.planned_maps()
            .iter()
            .all(|map| map.flags & libc::MAP_FIXED as u64 != 0)
    );
    assert_eq!(
        data.planned_maps().last().unwrap().start,
        RUNTIME_WINDOW.start + 8192
    );
}

#[test]
fn empty_original_argv_keeps_null_and_aligns_only_the_wire_name_copy() {
    let (stack, _) = original_stack(true);
    let request = request();
    let data = data(&image_bytes(), &request, &stack, 4096).unwrap();
    let locations = data.locations();
    assert_eq!(locations.argc, 0);
    assert_eq!(word(at(&data, locations.argv, 8)), 0);
    assert!(locations.program_name.is_multiple_of(8));
    assert_eq!(at(&data, locations.program_name, 10), b"/bin/prog\0");
    assert_ne!(locations.program_name, data.placed.program_name);
    assert_eq!(at(&data, data.placed.program_name, 10), b"/bin/prog\0");
}

#[test]
fn exact_payload_capacity_succeeds_and_one_byte_short_keeps_original_capacity_error() {
    let (stack, _) = original_stack(false);
    let image = image_bytes();
    let mut request = request();
    let bytes = data(&image, &request, &stack, 4096)
        .unwrap()
        .bytes()
        .to_vec();
    request.copied_capacity = bytes.len();
    assert_eq!(data(&image, &request, &stack, 4096).unwrap().bytes(), bytes);
    request.copied_capacity -= 1;
    let error = data(&image, &request, &stack, 4096).err().unwrap();
    assert_eq!(error.to_string(), "copy fixture: Capacity");
}

#[test]
fn descriptor_bss_padding_and_whole_guard_overlap_are_refused_before_copy() {
    let (stack, _) = original_stack(false);
    let image = image_bytes();
    let mut bad = request();
    bad.layout_address = RUNTIME_WINDOW.start + 4090; // crosses initialized RO bytes
    assert_eq!(
        data(&image, &bad, &stack, 4096).err().unwrap().to_string(),
        "copied_input_target_not_initialized_readonly"
    );
    let mut changed = image.clone();
    changed[512] ^= 1;
    assert_eq!(
        data(&changed, &request(), &stack, 4096)
            .err()
            .unwrap()
            .to_string(),
        "mapped_target_descriptor_mismatch"
    );
    let mut bad = request();
    // Only the two guards overlap; mapped interiors would not overlap.
    bad.roles[1] = Extent {
        start: bad.roles[0].end - 4096,
        end: bad.roles[0].end + 0x7000,
    };
    assert_eq!(
        data(&image, &bad, &stack, 4096).err().unwrap().to_string(),
        "copied_input_data_bounds"
    );
}

#[test]
fn copied_extent_state_overlap_page_size_and_role_overflow_refuse_without_normalization() {
    let (stack, _) = original_stack(false);
    let image = image_bytes();
    let mut bad = request();
    bad.copied_address = bad.roles[3].start + 4096; // overwrites fixed header area
    assert_eq!(
        data(&image, &bad, &stack, 4096).err().unwrap().to_string(),
        "copied_input_data_bounds"
    );
    let mut bad = request();
    bad.relay_address = bad.control_address;
    assert_eq!(
        data(&image, &bad, &stack, 4096).err().unwrap().to_string(),
        "copied_input_data_bounds"
    );
    assert_eq!(
        data(&image, &request(), &stack, 8192)
            .err()
            .unwrap()
            .to_string(),
        "copied_input_original_page_size"
    );
    let mut bad = request();
    bad.roles[0].end = u64::MAX;
    assert_eq!(
        data(&image, &bad, &stack, 4096).err().unwrap().to_string(),
        "copied_input_data_bounds"
    );
}

// Real held-stop source control, deliberately separate from the five pure data
// bodies. No injection, mapping, filter, private entry or guest instruction.
#[test]
fn genuine_captured_stop_uses_the_host_bridge_and_remains_unchanged_until_cancel() {
    let request = PreparedExec::new(
        std::path::Path::new("/bin/true"),
        &["copied-input-control".into()],
        &[("ORIGINAL".into(), "1".into())],
        None,
        vec![],
    )
    .unwrap();
    let stop = ExecStop::spawn(request, CleanupReceipt::default()).unwrap();
    let captured = stop.capture_initial_inputs().unwrap();
    let file = image_bytes();
    let parsed = Image::parse(&file).unwrap();
    let image = parsed
        .validate(&Policy {
            window: RUNTIME_WINDOW,
            allow_tls: true,
        })
        .unwrap();
    let data = stop
        .prepare_copied_inputs(&captured, &image, &self::request())
        .unwrap();
    assert_eq!(
        data.original_aux().collect::<Vec<_>>(),
        captured.original_aux().collect::<Vec<_>>()
    );
    assert_eq!(data.locations().argc, 1);
    assert_eq!(
        at(&data, word(at(&data, data.locations().envp, 8)), 11),
        b"ORIGINAL=1\0"
    );
    initial_inputs::unchanged(&stop).unwrap();
    let other_request = PreparedExec::new(
        std::path::Path::new("/bin/true"),
        &["foreign-copy-control".into()],
        &[],
        None,
        vec![],
    )
    .unwrap();
    let other = ExecStop::spawn(other_request, CleanupReceipt::default()).unwrap();
    assert_eq!(
        other
            .prepare_copied_inputs(&captured, &image, &self::request())
            .err()
            .unwrap()
            .to_string(),
        "copied_input_foreign_capture"
    );
    initial_inputs::unchanged(&other).unwrap();
    assert!(other.cancel().unwrap().confirmed);
    assert!(stop.cancel().unwrap().confirmed);
}
