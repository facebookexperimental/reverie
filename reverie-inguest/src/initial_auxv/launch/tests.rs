// These controls exercise preparation and refusal, not a successful guest
// loader transfer. Only the actual bootstrap/readback path may produce a
// CompletedWrite; none of these tests constructs one.

use std::os::unix::fs::FileExt;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::*;

mod physical;

#[test]
fn seed_relocations_without_a_dynamic_segment_are_refused() {
    let mut image = elf(SEED).unwrap();
    assert!(image.dynamic.is_none());
    assert!(image.dynrelas.is_empty() && image.dynrels.is_empty());
    qualify_seed(&image).expect("the actual compiled interpreter needs no relocations");
    for kind in [
        goblin::elf::section_header::SHT_REL,
        goblin::elf::section_header::SHT_RELA,
        19, // ELF SHT_RELR
    ] {
        let index = image.section_headers.len();
        image.section_headers.push(goblin::elf::SectionHeader {
            sh_type: kind,
            sh_size: 24,
            ..Default::default()
        });
        assert!(
            qualify_seed(&image).is_err(),
            "a relocation section without PT_DYNAMIC must still be rejected: {kind}"
        );
        image.section_headers.truncate(index);
        qualify_seed(&image).unwrap();
    }
}

fn stock_loader() -> Held {
    let main = Held::open(Path::new("/bin/true")).expect("capture the real dynamic control ELF");
    let image = elf(&main.bytes).expect("parse dynamic control ELF");
    let path = Path::new(image.interpreter.expect("control has a stock interpreter"))
        .canonicalize()
        .expect("resolve stock interpreter");
    Held::open(&path).expect("capture real stock interpreter")
}

fn file_bytes(file: &File) -> Vec<u8> {
    let mut bytes = vec![0; file.metadata().unwrap().len() as usize];
    file.read_exact_at(&mut bytes, 0).unwrap();
    bytes
}

#[test]
fn birth_identity_accepts_truncated_unicode_comm_but_requires_exact_numeric_fields() {
    // A valid basename with fourteen ASCII bytes followed by é is truncated
    // by Linux's fifteen-byte comm payload after the first UTF-8 byte.
    let mut stat = b"42 (aaaaaaaaaaaaaa\xc3)".to_vec();
    for index in 0..26 {
        stat.push(b' ');
        stat.extend_from_slice(match index {
            0 => b"R",
            19 => b"12345",
            25 => b"987654321",
            _ => b"1",
        });
    }
    stat.push(b'\n');
    assert!(std::str::from_utf8(&stat).is_err());
    assert_eq!(parse_birth(42, &stat).unwrap(), (12345, 987654321));
    assert!(parse_birth(41, &stat).is_err());
    let mut malformed = stat.clone();
    let stack = malformed.len() - b"987654321\n".len();
    malformed[stack] = 0xff;
    assert!(parse_birth(42, &malformed).is_err());
    assert!(parse_birth(42, &stat[..stack]).is_err());
    assert!(parse_birth(42, b"42 (unterminated").is_err());
}

#[test]
fn source_built_seed_fits_the_stock_loader_without_changing_code() {
    let loader = stock_loader();
    let (span, alignment) = loader_span(&loader.bytes).expect("qualify real stock interpreter");
    let adapted = seed_for_loader(span, alignment).expect("qualify actual source-built seed");
    let original = elf(SEED).unwrap();
    let seed = elf(&adapted).unwrap();
    assert_eq!(seed.header.e_type, elf_header::ET_DYN);
    assert_eq!(seed.entry, original.entry);
    assert!(seed.interpreter.is_none());
    assert!(seed.libraries.is_empty());
    assert!(seed.dynrelas.is_empty() && seed.dynrels.is_empty() && seed.pltrelocs.is_empty());
    assert!(!seed.program_headers.iter().any(|p| p.p_type == ph::PT_TLS));
    let loads: Vec<_> = seed
        .program_headers
        .iter()
        .filter(|p| p.p_type == ph::PT_LOAD)
        .collect();
    let reservation = loads.last().unwrap();
    assert_eq!(reservation.p_flags, ph::PF_R | ph::PF_W);
    assert_eq!(reservation.p_vaddr + reservation.p_memsz, span);
    assert!(loads.iter().all(|p| p.p_align == alignment));
    assert!(original.program_headers.iter().any(|p| {
        p.p_type == ph::PT_LOAD
            && p.p_flags & ph::PF_X != 0
            && original.entry >= p.p_vaddr
            && original.entry < p.p_vaddr + p.p_filesz
    }));
    // The RX segment includes the ELF/program headers. Restore only the
    // explicitly permitted reservation/alignment fields for byte comparison;
    // every instruction, other header field and data byte must be unchanged.
    let mut unchanged = adapted.clone();
    let last_load = original
        .program_headers
        .iter()
        .rposition(|p| p.p_type == ph::PT_LOAD)
        .unwrap();
    for (index, load) in original.program_headers.iter().enumerate() {
        if load.p_type != ph::PT_LOAD {
            continue;
        }
        let offset = original.header.e_phoff as usize + index * 56;
        unchanged[offset + 48..offset + 56].copy_from_slice(&SEED[offset + 48..offset + 56]);
        if index == last_load {
            unchanged[offset + 40..offset + 48].copy_from_slice(&SEED[offset + 40..offset + 48]);
        }
    }
    assert_eq!(unchanged, SEED);
    assert!(seed_for_loader(0, alignment).is_err());
}

#[test]
fn stock_loader_qualification_rejects_wrong_type_entry_and_load_extents() {
    let loader = stock_loader();
    let image = elf(&loader.bytes).unwrap();
    let load_index = image
        .program_headers
        .iter()
        .position(|p| p.p_type == ph::PT_LOAD && p.p_flags & ph::PF_X != 0)
        .unwrap();
    let offset = image.header.e_phoff as usize + load_index * 56;
    let mut wrong_type = loader.bytes.clone();
    wrong_type[16..18].copy_from_slice(&elf_header::ET_EXEC.to_le_bytes());
    let mut missing_entry = loader.bytes.clone();
    put_u64(&mut missing_entry, 24, u64::MAX);
    let mut writable_code = loader.bytes.clone();
    writable_code[offset + 4..offset + 8]
        .copy_from_slice(&(ph::PF_R | ph::PF_W | ph::PF_X).to_le_bytes());
    let mut oversized_file = loader.bytes.clone();
    put_u64(
        &mut oversized_file,
        offset + 32,
        image.program_headers[load_index].p_memsz + 1,
    );
    let mut overflowing_extent = loader.bytes.clone();
    put_u64(&mut overflowing_extent, offset + 40, u64::MAX);
    for (name, bad) in [
        ("non-interpreter ELF type", wrong_type),
        ("entry outside executable file bytes", missing_entry),
        ("writable executable mapping", writable_code),
        ("file bytes exceed memory extent", oversized_file),
        ("overflowing memory extent", overflowing_extent),
    ] {
        let error = loader_span(&bad).expect_err(name);
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{name}: {error}");
    }
}

#[test]
fn preparing_sealed_inputs_does_not_complete_a_pending_write() {
    let completed = Arc::new(AtomicUsize::new(0));
    let observed = completed.clone();
    let bytes = [0xa5; 16];
    let prepared = Prepared::prepare(
        b"exact opaque configuration\0bytes",
        PendingWrite::new(PathBuf::from("/bin/true"), bytes, move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("preparation must not invoke policy"))
        }),
    )
    .expect("prepare actual dynamic control");
    assert_eq!(
        prepared.token().config,
        <[u8; 32]>::from(Sha256::digest(b"exact opaque configuration\0bytes"))
    );
    let packet = file_bytes(&prepared.input.packet);
    check_header(&packet, PENDING_MAGIC, prepared.token()).unwrap();
    assert_eq!(&packet[80..96], &bytes);
    let path_len = u16::from_le_bytes(packet[120..122].try_into().unwrap()) as usize;
    assert_eq!(packet.len(), 128 + path_len);
    assert_eq!(
        &packet[128..],
        prepared.input.interpreter.as_bytes_with_nul()
    );
    let metadata = prepared.input.loader.metadata().unwrap();
    assert_eq!(u64_at(&packet, 96).unwrap(), metadata.dev());
    assert_eq!(u64_at(&packet, 104).unwrap(), metadata.ino());
    assert_eq!(u64_at(&packet, 112).unwrap(), metadata.len());
    assert_eq!(metadata.dev(), prepared.loader.device);
    assert_eq!(metadata.ino(), prepared.loader.inode);
    prepared.loader.verify(&prepared.input.loader).unwrap();
    let flags = unsafe { libc::fcntl(prepared.input.loader.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
    assert_eq!(
        unsafe {
            libc::pwrite(
                prepared.input.loader.as_raw_fd(),
                bytes.as_ptr().cast(),
                1,
                0,
            )
        },
        -1
    );
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    assert_eq!(file_bytes(&prepared.input.loader), prepared.loader.bytes);
    assert_eq!(file_bytes(&prepared.input._seed), prepared.seed_bytes);
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    let file = &prepared.input.packet;
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    assert_eq!(seals & required, required);
    assert_eq!(
        unsafe { libc::pwrite(file.as_raw_fd(), bytes.as_ptr().cast(), 1, 0) },
        -1
    );
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    // Anonymous sealed memfds cannot be bind-mounted as an ELF interpreter.
    // The actual mount source is an owned linked regular file, held read-only;
    // its path lifetime and byte identity, rather than seals, are the contract.
    let seed_path: PathBuf = prepared.input._seed_path.to_path_buf();
    let seed_metadata = std::fs::symlink_metadata(&seed_path).unwrap();
    assert!(seed_metadata.is_file() && !seed_metadata.file_type().is_symlink());
    assert_eq!(seed_metadata.nlink(), 1);
    assert_eq!(
        seed_metadata.dev(),
        prepared.input._seed.metadata().unwrap().dev()
    );
    assert_eq!(
        seed_metadata.ino(),
        prepared.input._seed.metadata().unwrap().ino()
    );
    let flags = unsafe { libc::fcntl(prepared.input._seed.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
    assert_eq!(
        unsafe {
            libc::pwrite(
                prepared.input._seed.as_raw_fd(),
                bytes.as_ptr().cast(),
                1,
                0,
            )
        },
        -1,
    );
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    assert_eq!(file_bytes(&prepared.input._seed), prepared.seed_bytes);
    drop(prepared);
    assert!(
        !seed_path.exists(),
        "owned interpreter mount source is removed on drop"
    );
    assert_eq!(completed.load(Ordering::SeqCst), 0);
}

#[test]
fn large_sparse_main_uses_bounded_headers_and_preserves_the_script_command() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("large-dynamic-image");
    std::fs::copy("/bin/true", &path).unwrap();
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    let size = 256 * 1024 * 1024;
    file.set_len(size).unwrap();
    drop(file);
    let main =
        MainImage::open(&path).expect("dynamic file larger than loader bound remains admitted");
    assert_eq!(main.metadata.len(), size);
    assert!(size > MAX_ELF as u64);
    assert!(main.headers.programs.len() <= 32 * 56);
    assert!(main.headers.interpreter.len() <= 4096);
    assert_eq!(main.headers.elf.len(), 64);
    main.verify(&File::open(&path).unwrap()).unwrap();

    // This checks preparation/installation only, not execution of the script.
    // The kernel still receives the script and its original argument vector.
    let script = directory.path().join("script");
    std::fs::write(&script, b"#!/bin/true\n").unwrap();
    let mut command = Command::new(&script);
    command
        .arg("unchanged argument")
        .current_dir(directory.path());
    let prepared = Prepared::prepare(
        b"resolved image control",
        PendingWrite::new(path, [1; 16], |_| {
            Err(io::Error::other(
                "no execution or completion in this control",
            ))
        }),
    )
    .unwrap();
    prepared.install(&mut command).unwrap();
    assert_eq!(command.get_program(), script.as_os_str());
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [std::ffi::OsStr::new("unchanged argument")]
    );
    assert_eq!(command.get_current_dir(), Some(directory.path()));
    assert_eq!(prepared.main.metadata.len(), size);
}

#[test]
fn main_image_refuses_replaced_inode_and_changed_headers() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("main");
    std::fs::copy("/bin/true", &path).unwrap();
    let main = MainImage::open(&path).unwrap();
    let replacement = directory.path().join("replacement");
    std::fs::copy(&path, &replacement).unwrap();
    assert!(
        main.verify(&File::open(&replacement).unwrap()).is_err(),
        "same ELF at different inode must refuse"
    );
    let writable = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    let changed_entry = main.headers.elf[24] ^ 1;
    writable.write_all_at(&[changed_entry], 24).unwrap();
    let changed = main_headers(&main.file, main.file.metadata().unwrap().len()).unwrap();
    assert_ne!(
        changed.elf, main.headers.elf,
        "exact header capture observes changed entry"
    );
    assert!(
        main.verify(&File::open(&path).unwrap()).is_err(),
        "changed captured executable must refuse"
    );
    // Bound the actual header reads independently of whole-file size.
    writable.write_all_at(&u64::MAX.to_le_bytes(), 32).unwrap();
    assert!(
        main_headers(&main.file, main.file.metadata().unwrap().len()).is_err(),
        "program-header offset must refuse before unbounded read"
    );
}

#[test]
fn held_original_file_refuses_writable_changed_and_retargeted_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("loader");
    std::fs::write(&path, b"captured original file").unwrap();
    let held = Held::open(&path).unwrap();
    held.verify(&held.file.try_clone().unwrap()).unwrap();
    let writable = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(
        held.verify(&writable).is_err(),
        "writable loader FD must refuse"
    );
    writable.write_all_at(b"X", 0).unwrap();
    assert!(
        held.verify(&held.file).is_err(),
        "same inode with changed bytes must refuse"
    );

    let held = Held::open(&path).unwrap();
    let replacement = directory.path().join("replacement");
    std::fs::write(&replacement, &held.bytes).unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    let retargeted = File::open(&path).unwrap();
    assert_ne!(retargeted.metadata().unwrap().ino(), held.inode);
    assert_eq!(
        file_bytes(&held.file),
        held.bytes,
        "held FD still names original inode"
    );
    assert!(
        held.verify(&retargeted).is_err(),
        "equal bytes at a replacement inode must refuse"
    );
}

#[test]
fn loader_maps_require_original_identity_path_offsets_and_private_permissions() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join(std::ffi::OsStr::from_bytes(b"loader-\xff\xfe"));
    std::fs::write(&path, stock_loader().bytes).unwrap();
    let loader = Held::open(&path).unwrap();
    let image = elf(&loader.bytes).unwrap();
    let base = 0x7000_0000_u64;
    let path = mapped_path(&loader.file).unwrap();
    let mut rows = Vec::new();
    for load in image
        .program_headers
        .iter()
        .filter(|p| p.p_type == ph::PT_LOAD && p.p_filesz != 0)
    {
        let start = base + (load.p_vaddr & !(PAGE - 1));
        let end = (base + load.p_vaddr + load.p_filesz + PAGE - 1) & !(PAGE - 1);
        let perms = format!(
            "{}{}{}p",
            if load.p_flags & ph::PF_R != 0 {
                'r'
            } else {
                '-'
            },
            if load.p_flags & ph::PF_W != 0 {
                'w'
            } else {
                '-'
            },
            if load.p_flags & ph::PF_X != 0 {
                'x'
            } else {
                '-'
            }
        );
        let mut row = format!(
            "{start:x}-{end:x} {perms} {:08x} {:02x}:{:02x} {}    ",
            load.p_offset & !(PAGE - 1),
            libc::major(loader.map_device),
            libc::minor(loader.map_device),
            loader.inode
        )
        .into_bytes();
        row.extend_from_slice(&path);
        row.push(b'\n');
        rows.push(row);
    }
    let maps = rows.concat();
    assert!(std::str::from_utf8(&maps).is_err());
    verify_loader_maps(&maps, &loader, base).unwrap();
    let first = &rows[0];
    let mut fields = first
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    for (field, wrong) in [
        (1, "r--s"),
        (2, "00001000"),
        (3, "00:00"),
        (4, "0"),
        (5, "/memfd:reverie-initial-auxv-loader"),
    ] {
        let original = fields[field].clone();
        fields[field] = wrong.as_bytes().to_vec();
        let mut bad = fields.join(b" ".as_slice());
        bad.push(b'\n');
        bad.extend_from_slice(&rows[1..].concat());
        assert!(
            verify_loader_maps(&bad, &loader, base).is_err(),
            "wrong map field {field} must refuse"
        );
        fields[field] = original;
    }
    assert!(
        verify_loader_maps(&rows[1..].concat(), &loader, base).is_err(),
        "missing mapping must refuse"
    );
}

#[test]
fn original_mapping_device_comes_from_the_held_fd_not_a_replaced_path() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join(std::ffi::OsStr::from_bytes(b"original loader\nimage\xff"));
    let original = stock_loader();
    std::fs::write(&path, &original.bytes).unwrap();
    let held = Held::open(&path).unwrap();
    assert_eq!(held.device, held.file.metadata().unwrap().dev());
    assert_eq!(
        original_mapping_device(&held.file, held.inode).unwrap(),
        held.map_device,
    );
    // Equal bytes and a pathname are insufficient: the observation must map
    // the retained descriptor, including when that pathname is replaced.
    let replacement = directory.path().join("replacement");
    std::fs::write(&replacement, &held.bytes).unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    let replacement = File::open(&path).unwrap();
    assert_ne!(replacement.metadata().unwrap().ino(), held.inode);
    assert!(original_mapping_device(&replacement, held.inode).is_err());
    assert_eq!(
        original_mapping_device(&held.file, held.inode).unwrap(),
        held.map_device,
        "capture must never reopen the replaced pathname",
    );
    assert!(held.verify(&replacement).is_err());
}

#[test]
fn bootstrap_v4_roundtrips_without_changing_legacy_tool_payloads() {
    let coordinator = Path::new("/tool.sock");
    let tool_data = b"opaque\0tool\xffdata";
    let token = Token {
        nonce: [0x35; 32],
        config: [0x7b; 32],
    };
    for stats in [None, Some(Path::new("/stats.sock"))] {
        for patching in [None, Some(true), Some(false)] {
            let fd = crate::bootstrap::create_preload_bootstrap_with_auxv(
                coordinator,
                stats,
                patching,
                tool_data,
                Some(token),
            )
            .unwrap();
            let decoded = crate::bootstrap::read_preload_bootstrap(fd.as_raw_fd())
                .unwrap()
                .expect("sealed V4 bootstrap");
            assert_eq!(decoded.coordinator, coordinator);
            assert_eq!(decoded.stats_coordinator.as_deref(), stats);
            assert_eq!(decoded.site_patching, patching);
            assert_eq!(decoded.tool_data, tool_data);
            assert_eq!(decoded.initial_auxv, Some(token));

            let legacy =
                crate::bootstrap::create_preload_bootstrap(coordinator, stats, patching, tool_data)
                    .unwrap();
            let legacy_packet = file_bytes(&File::from(legacy.try_clone().unwrap()));
            let decoded = crate::bootstrap::read_preload_bootstrap(legacy.as_raw_fd())
                .unwrap()
                .unwrap();
            assert_eq!(decoded.coordinator, coordinator);
            assert_eq!(decoded.stats_coordinator.as_deref(), stats);
            assert_eq!(decoded.site_patching, patching);
            assert_eq!(decoded.tool_data, tool_data);
            assert_eq!(decoded.initial_auxv, None);
            // Pin the old wire format, not merely encoder/decoder agreement.
            let version = if patching.is_some() {
                3
            } else if stats.is_some() {
                2
            } else {
                1
            };
            let magic = match version {
                1 => b"REVERIE-LI-V1\0\0\0",
                2 => b"REVERIE-LI-V2\0\0\0",
                _ => b"REVERIE-LI-V3\0\0\0",
            };
            let mut expected = magic.to_vec();
            expected.extend_from_slice(&(coordinator.as_os_str().len() as u16).to_le_bytes());
            if version > 1 {
                expected.extend_from_slice(
                    &(stats.map_or(0, |p| p.as_os_str().len()) as u16).to_le_bytes(),
                );
            }
            expected.extend_from_slice(&(tool_data.len() as u16).to_le_bytes());
            if let Some(patching) = patching {
                expected.push(if patching { 1 } else { 2 });
            }
            expected.extend_from_slice(coordinator.as_os_str().as_bytes());
            if let Some(stats) = stats {
                expected.extend_from_slice(stats.as_os_str().as_bytes());
            }
            expected.extend_from_slice(tool_data);
            assert_eq!(legacy_packet, expected);
        }
    }
}

#[test]
fn bootstrap_v4_rejects_invalid_lengths_and_selection_without_fallback() {
    let bootstrap = crate::bootstrap::create_preload_bootstrap_with_auxv(
        Path::new("/tool.sock"),
        None,
        Some(false),
        b"tool-data",
        Some(Token {
            nonce: [1; 32],
            config: [2; 32],
        }),
    )
    .unwrap();
    let packet = file_bytes(&File::from(bootstrap));
    for (name, index, value) in [
        ("missing coordinator", 16, 0),
        ("extra payload byte claimed", 20, 10),
        ("unknown patching selection", 22, 3),
    ] {
        let mut bad = packet.clone();
        bad[index] = value;
        let file = seal(c"bad-initial-auxv-bootstrap", &bad).unwrap();
        let result = crate::bootstrap::read_preload_bootstrap(file.as_raw_fd());
        assert!(
            result.is_err(),
            "{name} must not fall back to legacy startup"
        );
    }
}

fn socket_pair(passcred: bool) -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        },
        0
    );
    let receiver = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let sender = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    if passcred {
        let enabled: i32 = 1;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    receiver.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&enabled as *const i32).cast(),
                    core::mem::size_of::<i32>() as _,
                )
            },
            0
        );
    }
    (receiver, sender)
}

fn registered(fd: OwnedFd) -> AsyncFd<OwnedFd> {
    register_owned(fd).expect("register private nonblocking endpoint")
}

#[tokio::test(flavor = "current_thread")]
async fn seqpacket_transport_keeps_real_sender_credentials_and_eof_distinct() {
    let (receiver, sender) = socket_pair(true);
    let receiver = registered(receiver);
    let sender = registered(sender);
    let packet = b"not a completion proof";
    send(&sender, packet, None).await.unwrap();
    let (received, pid) = tokio::time::timeout(Duration::from_secs(3), receive(&receiver))
        .await
        .expect("packet reception is bounded")
        .unwrap();
    assert_eq!(received, packet);
    assert_eq!(pid, Some(std::process::id() as i32));
    drop(sender);
    let (received, pid) = tokio::time::timeout(Duration::from_secs(3), receive(&receiver))
        .await
        .expect("closed peer is observed")
        .unwrap();
    assert!(received.is_empty());
    assert_eq!(pid, None);
}

fn send_rights(fd: i32, bytes: &[u8], rights: &[i32]) {
    let length = core::mem::size_of_val(rights);
    let space = unsafe { libc::CMSG_SPACE(length as _) } as usize;
    let mut control = vec![0_u64; space.div_ceil(8)];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { core::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space;
    unsafe {
        let item = libc::CMSG_FIRSTHDR(&message);
        (*item).cmsg_level = libc::SOL_SOCKET;
        (*item).cmsg_type = libc::SCM_RIGHTS;
        (*item).cmsg_len = libc::CMSG_LEN(length as _) as usize;
        core::ptr::copy_nonoverlapping(rights.as_ptr(), libc::CMSG_DATA(item).cast(), rights.len());
    }
    assert_eq!(
        unsafe { libc::sendmsg(fd, &message, libc::MSG_NOSIGNAL) },
        bytes.len() as isize
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rejected_ancillary_and_truncated_packets_close_every_received_right() {
    for (rights_count, payload_len, expected) in [
        (1, 1, "unexpected ancillary data"),
        (64, 1, "truncated"),
        (1, 129 + MAX_STATE, "truncated"),
    ] {
        let (receiver, sender) = socket_pair(true);
        let receiver = registered(receiver);
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        let reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        send_rights(
            sender.as_raw_fd(),
            &vec![0x5a; payload_len],
            &vec![writer.as_raw_fd(); rights_count],
        );
        drop(writer);
        let error = tokio::time::timeout(Duration::from_secs(3), receive(&receiver))
            .await
            .expect("ancillary refusal is bounded")
            .expect_err("inbound descriptors are not permitted");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains(expected), "{error}");
        // Every transmitted right referenced this sole pipe writer. EOF proves
        // that both the parser and the kernel's CTRUNC cleanup closed them all;
        // a process-wide fd count would race unrelated tests.
        let mut byte = 0_u8;
        assert_eq!(
            unsafe { libc::read(reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) },
            0,
            "a rejected SCM_RIGHTS packet leaked a live pipe writer"
        );
    }
}

struct PacketChild(Child);

impl Drop for PacketChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn missing_partial_and_unproved_write_packets_never_invoke_tool_policy() {
    for name in [
        "missing",
        "short",
        "magic",
        "nonce",
        "config",
        "another pid",
        "partial write",
        "write error",
        "different bytes",
        "unproved executable",
    ] {
        let completed = Arc::new(AtomicUsize::new(0));
        let observed = completed.clone();
        let bytes = [0xa5; 16];
        let prepared = Prepared::prepare(
            b"protocol refusal control",
            PendingWrite::new(PathBuf::from("/bin/true"), bytes, move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("unproved write reached Tool policy"))
            }),
        )
        .unwrap();
        // A real child sends negative protocol inputs from its own PID. It is
        // not a bootstrap and does not claim a valid loader mapping or write.
        let mut child = PacketChild(
            Command::new("/bin/cat")
                .stdin(Stdio::piped())
                .stdout(Stdio::from(prepared.input.channel.try_clone().unwrap()))
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id() as i32;
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(
            pidfd >= 0,
            "hold actual child birth: {}",
            io::Error::last_os_error()
        );
        let birth = Birth {
            fd: unsafe { OwnedFd::from_raw_fd(pidfd as i32) },
            complete: false,
        };
        let mut packet = vec![0; 192];
        header(&mut packet, WRITE_MAGIC, prepared.token());
        put_u64(&mut packet, 80, pid as u64);
        put_u64(&mut packet, 88, pid as u64);
        packet[160..176].copy_from_slice(&bytes);
        put_u64(&mut packet, 176, 16);
        let expected = match name {
            "missing" => {
                packet.clear();
                "did not come from the spawned child"
            }
            "short" => {
                packet.truncate(79);
                "did not come from the spawned child"
            }
            "magic" | "nonce" | "config" => {
                let index = match name {
                    "magic" => 0,
                    "nonce" => 16,
                    _ => 48,
                };
                packet[index] ^= 1;
                "record identity, version or length differs"
            }
            "another pid" => {
                put_u64(&mut packet, 80, pid as u64 + 1);
                "partial or names another image"
            }
            "partial write" => {
                put_u64(&mut packet, 176, 15);
                "partial or names another image"
            }
            "write error" => {
                put_u64(&mut packet, 184, libc::EFAULT as u64);
                "partial or names another image"
            }
            "different bytes" => {
                packet[160] ^= 1;
                "partial or names another image"
            }
            "unproved executable" => "child executable or original stack differs",
            _ => unreachable!(),
        };
        let mut input = Some(child.0.stdin.take().unwrap());
        input.as_mut().unwrap().write_all(&packet).unwrap();
        if packet.is_empty() {
            // EOF, rather than a zero-length datagram, is the missing frame.
            drop(input.take());
        }
        let bootstrap = crate::bootstrap::create_preload_bootstrap(
            Path::new("/tool.sock"),
            None,
            None,
            b"unchanged opaque Tool input",
        )
        .unwrap();
        let result =
            tokio::time::timeout(Duration::from_secs(3), prepared.exchange(pid, bootstrap))
                .await
                .expect("negative exchange is bounded");
        let error = result.expect_err(name);
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{name}: {error}");
        assert!(error.to_string().contains(expected), "{name}: {error}");
        assert_eq!(completed.load(Ordering::SeqCst), 0, "{name}");
        drop(birth);
        drop(input);
        drop(child);
    }
}
