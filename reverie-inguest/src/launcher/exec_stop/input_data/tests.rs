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

const CONFIG_DIGEST: [u8; 32] = [0x11u8; 32];
const STATE_DIGEST: [u8; 32] = [0x33u8; 32];
const NO_STATE_DIGEST: [u8; 32] = [0u8; 32];
const SUCCESSOR: InitPacketExpectation = InitPacketExpectation {
    birth_kind: InitPacketBirthKind::Successor,
    expected_config_digest: CONFIG_DIGEST,
    expected_state_digest: STATE_DIGEST,
};
const FIRST_IMAGE: InitPacketExpectation = InitPacketExpectation {
    birth_kind: InitPacketBirthKind::FirstImage,
    expected_config_digest: CONFIG_DIGEST,
    expected_state_digest: NO_STATE_DIGEST,
};

#[test]
fn init_packet_build_validate_round_trip() {
    let packet = build_init_packet(SUCCESSOR, b"birth-nonce").unwrap();
    // The packet bytes are exactly the loader codec's bytes.
    let decoded = reverie_loader::init_packet::decode(&packet).unwrap();
    assert!(decoded.state_expected());
    assert_eq!(decoded.expected_state_digest(), STATE_DIGEST);
    let successor = reverie_loader::init_packet::decode_successor(&packet).unwrap();
    assert_eq!(successor.expected_config_digest(), CONFIG_DIGEST);
    assert_eq!(successor.expected_state_digest(), STATE_DIGEST);
    assert_eq!(successor.redemption(), b"birth-nonce");

    let validated = validate_init_packet(&packet, SUCCESSOR).unwrap();
    assert!(validated.state_expected());
    assert_eq!(validated.expected_state_digest(), STATE_DIGEST);
    assert_eq!(validated.redemption(), b"birth-nonce");
    assert_eq!(validated.packet_bytes(), packet.as_slice());

    let packet = build_init_packet(FIRST_IMAGE, b"first-image").unwrap();
    let error = reverie_loader::init_packet::decode_successor(&packet).unwrap_err();
    assert_eq!(error.name(), "init_packet_state_not_expected");

    let validated = validate_init_packet(&packet, FIRST_IMAGE).unwrap();
    assert!(!validated.state_expected());
    assert_eq!(validated.expected_state_digest(), NO_STATE_DIGEST);
    assert_eq!(validated.packet_bytes(), packet.as_slice());
}

#[test]
fn init_packet_digest_mismatch_is_named_refusal() {
    let packet = build_init_packet(SUCCESSOR, b"nonce").unwrap();
    let error = validate_init_packet(
        &packet,
        InitPacketExpectation {
            expected_config_digest: [0x22u8; 32],
            ..SUCCESSOR
        },
    )
    .err()
    .unwrap()
    .to_string();
    assert_eq!(error, "init_packet_config_digest_mismatch");

    // A mismatch in any single digest byte must still refuse:
    // each comparison covers all 32 bytes, including byte 0 and
    // byte 31, either of which a shortened compare could skip.
    for i in 0..32 {
        let mut one_byte_off = CONFIG_DIGEST;
        one_byte_off[i] ^= 1;
        let error = validate_init_packet(
            &packet,
            InitPacketExpectation {
                expected_config_digest: one_byte_off,
                ..SUCCESSOR
            },
        )
        .err()
        .unwrap()
        .to_string();
        assert_eq!(error, "init_packet_config_digest_mismatch", "byte {i}");

        let mut one_byte_off = STATE_DIGEST;
        one_byte_off[i] ^= 1;
        let error = validate_init_packet(
            &packet,
            InitPacketExpectation {
                expected_state_digest: one_byte_off,
                ..SUCCESSOR
            },
        )
        .err()
        .unwrap()
        .to_string();
        assert_eq!(error, "init_packet_state_digest_mismatch", "byte {i}");
    }
}

#[test]
fn init_packet_birth_kind_mismatch_is_named_refusal() {
    // A successor packet presented for a first-image birth, and
    // the reverse, refuse host-side before any stamping.
    let successor = build_init_packet(SUCCESSOR, b"nonce").unwrap();
    let error = validate_init_packet(
        &successor,
        InitPacketExpectation {
            birth_kind: InitPacketBirthKind::FirstImage,
            ..SUCCESSOR
        },
    )
    .err()
    .unwrap()
    .to_string();
    assert_eq!(error, "init_packet_birth_kind_mismatch");

    let first_image = build_init_packet(FIRST_IMAGE, b"nonce").unwrap();
    let error = validate_init_packet(
        &first_image,
        InitPacketExpectation {
            birth_kind: InitPacketBirthKind::Successor,
            ..FIRST_IMAGE
        },
    )
    .err()
    .unwrap()
    .to_string();
    assert_eq!(error, "init_packet_birth_kind_mismatch");

    // Building a first-image packet with a nonzero state digest
    // is the same flag/digest inconsistency at encode time.
    let error = build_init_packet(
        InitPacketExpectation {
            expected_state_digest: STATE_DIGEST,
            ..FIRST_IMAGE
        },
        b"nonce",
    )
    .err()
    .unwrap()
    .to_string();
    assert_eq!(error, "init_packet_flags");
}

#[test]
fn init_packet_successor_zero_state_digest_is_named_refusal() {
    let zero_successor = InitPacketExpectation {
        expected_state_digest: NO_STATE_DIGEST,
        ..SUCCESSOR
    };
    let error = build_init_packet(zero_successor, b"nonce")
        .err()
        .unwrap()
        .to_string();
    assert_eq!(error, "init_packet_flags");

    let mut packet = build_init_packet(SUCCESSOR, b"nonce").unwrap();
    packet[48..80].fill(0);
    let error = validate_init_packet(&packet, zero_successor)
        .err()
        .unwrap()
        .to_string();
    assert_eq!(error, "init_packet_flags");
}

#[test]
fn init_packet_each_error_variant_is_a_named_refusal() {
    let valid = build_init_packet(SUCCESSOR, b"nonce").unwrap();
    let named = |packet: &[u8]| {
        validate_init_packet(packet, SUCCESSOR)
            .err()
            .unwrap()
            .to_string()
    };

    let mut packet = valid.clone();
    packet[7] ^= 1;
    assert_eq!(named(&packet), "init_packet_format");

    let mut packet = valid.clone();
    packet[8..10].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(named(&packet), "init_packet_version");

    let mut packet = valid.clone();
    packet[15] = 1;
    assert_eq!(named(&packet), "init_packet_reserved");

    let mut packet = valid.clone();
    packet[10] |= 0b0000_0010;
    assert_eq!(named(&packet), "init_packet_flags");

    // Declared length 0 and 257, each in an exact-fit buffer so the
    // refusal is the bound itself, not a length disagreement.
    let mut packet = valid.clone();
    packet[12..14].copy_from_slice(&0u16.to_le_bytes());
    packet.truncate(reverie_loader::init_packet::HEADER_LEN);
    assert_eq!(named(&packet), "init_packet_bounds");

    let mut packet = valid;
    packet.resize(reverie_loader::init_packet::HEADER_LEN + 257, 0xcd);
    packet[12..14].copy_from_slice(&257u16.to_le_bytes());
    assert_eq!(named(&packet), "init_packet_bounds");
}

#[test]
fn init_packet_malformed_is_named_refusal() {
    // The stage-1a probe placeholder is preparation-only data,
    // never an admitted init packet.
    let error = validate_init_packet(
        b"PREPARATION_ONLY_NOT_HLIINIT1",
        InitPacketExpectation {
            expected_config_digest: [0u8; 32],
            expected_state_digest: [0u8; 32],
            ..SUCCESSOR
        },
    )
    .err()
    .unwrap()
    .to_string();
    assert_eq!(error, "init_packet_format");

    // Ordinary-packet-shaped bytes (frozen plain bytes only; the
    // ordinary protocol is not decoded here) refuse under the
    // successor codec rather than being reinterpreted.
    let mut ordinary = vec![0u8; 128];
    ordinary[..8].copy_from_slice(b"HLIINIT1");
    let error = validate_init_packet(&ordinary, SUCCESSOR)
        .err()
        .unwrap()
        .to_string();
    assert_eq!(error, "init_packet_format");
}

const STAMP_ADDRESS: u64 = 0x10_0000;
const STAMP_BLOB_LEN: usize = 4096;

// Minimal complete HLSCAL01 blob inputs for the stamp helper:
// data only, with no mapping or source authority claimed.
struct StampFixture {
    header: handoff::Header,
    maps: Vec<Map>,
    code: Vec<handoff::Code>,
    sites: Vec<handoff::SiteRecord>,
    env: Vec<u64>,
    aux: Vec<u64>,
    tool_init: Vec<u64>,
}

impl StampFixture {
    fn tables(&self) -> handoff::TableData<'_> {
        handoff::TableData {
            maps: &self.maps,
            code: &self.code,
            sites: &self.sites,
            // Deliberately not the packet: the stamp helper must
            // write only the validated bytes, never this slice.
            packet: b"placeholder-not-stamped",
            env: &self.env,
            aux: &self.aux,
            program_name: b"prog\0",
            dev_null: b"/dev/null\0",
            tool_init: &self.tool_init,
        }
    }
}

fn stamp_fixture(packet_len: usize) -> StampFixture {
    let mut tables = core::array::from_fn(|_| handoff::Table {
        offset: 0,
        count: 0,
        stride: 0,
    });
    let mut cursor = handoff::HEADER_BYTES as u64;
    for (index, (count, stride)) in [
        (1u64, 32u64),
        (1, 16),
        (1, 32),
        (packet_len as u64, 1),
        (1, 8),
        (2, 8),
        (5, 1),
        (10, 1),
        (1, 8),
    ]
    .into_iter()
    .enumerate()
    {
        tables[index] = handoff::Table {
            offset: cursor,
            count,
            stride,
        };
        cursor = (cursor + count * stride).next_multiple_of(8);
    }
    assert!(cursor <= STAMP_BLOB_LEN as u64);
    let mut scalars = [0u64; 16];
    scalars[0] = 1;
    scalars[11] = 4096;
    scalars[13] = STAMP_ADDRESS + tables[7].offset;
    StampFixture {
        header: handoff::Header {
            prefix: [
                handoff::MAGIC,
                handoff::VERSION,
                STAMP_BLOB_LEN as u64,
                handoff::HEADER_BYTES as u64,
                0,
                0,
                0,
                0,
            ],
            binding: [[0; 4]; 5],
            roles: [Extent { start: 0, end: 0 }; 5],
            registers: [0; 27],
            scalars,
            tables,
            tls: [0; 12],
        },
        maps: vec![Map {
            start: 0,
            end: 0,
            protection: 0,
            flags: 0,
        }],
        code: vec![handoff::Code { start: 0, end: 0 }],
        sites: vec![handoff::SiteRecord {
            syscall_ip: 0x5000,
            return_ip: 0x5002,
            number: 158,
            operation: 1,
        }],
        env: vec![0],
        aux: vec![0, 0],
        tool_init: vec![0x5002],
    }
}

#[test]
fn stamp_init_packet_serializes_exactly_the_validated_bytes() {
    let packet = build_init_packet(SUCCESSOR, b"birth-nonce").unwrap();
    let fixture = stamp_fixture(packet.len());
    let mut bytes = vec![0u8; STAMP_BLOB_LEN];
    let validated = stamp_init_packet(
        &packet,
        SUCCESSOR,
        &fixture.header,
        fixture.tables(),
        STAMP_ADDRESS,
        &mut bytes,
    )
    .unwrap();
    assert_eq!(validated.packet_bytes(), packet.as_slice());
    let view = handoff::View::parse(&bytes, STAMP_ADDRESS).unwrap();
    assert_eq!(view.table(3).unwrap().bytes(), packet.as_slice());
    verify_serialized_init_packet(&bytes, STAMP_ADDRESS, &validated).unwrap();

    // Any later byte change inside table 3 is a named mismatch
    // at re-parse, never a silently different stamped packet.
    let offset = usize::try_from(view.table_address(3).unwrap() - STAMP_ADDRESS).unwrap();
    bytes[offset] ^= 1;
    let error = verify_serialized_init_packet(&bytes, STAMP_ADDRESS, &validated)
        .err()
        .unwrap()
        .to_string();
    assert_eq!(error, "init_packet_table3_mismatch");
}

#[test]
fn stamp_init_packet_refused_candidate_leaves_blob_unchanged() {
    let packet = build_init_packet(SUCCESSOR, b"birth-nonce").unwrap();
    let fixture = stamp_fixture(packet.len());
    let mut bytes = vec![0xeeu8; STAMP_BLOB_LEN];
    let error = stamp_init_packet(
        &packet,
        InitPacketExpectation {
            expected_config_digest: [0x22u8; 32],
            ..SUCCESSOR
        },
        &fixture.header,
        fixture.tables(),
        STAMP_ADDRESS,
        &mut bytes,
    )
    .err()
    .unwrap()
    .to_string();
    assert_eq!(error, "init_packet_config_digest_mismatch");
    assert!(bytes.iter().all(|byte| *byte == 0xee));
}

#[test]
fn stamp_init_packet_handoff_error_leaves_blob_unchanged() {
    let packet = build_init_packet(SUCCESSOR, b"birth-nonce").unwrap();
    let mut fixture = stamp_fixture(packet.len());
    fixture.header.tables[3].count = packet.len() as u64 + 1;
    let mut bytes = vec![0xeeu8; STAMP_BLOB_LEN];
    let error = stamp_init_packet(
        &packet,
        SUCCESSOR,
        &fixture.header,
        fixture.tables(),
        STAMP_ADDRESS,
        &mut bytes,
    )
    .err()
    .unwrap()
    .to_string();
    assert_eq!(error, "init_packet_stamp_handoff: Bounds");
    assert!(bytes.iter().all(|byte| *byte == 0xee));
}
