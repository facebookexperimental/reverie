//! Real seed/interpreter boundary controls, not stock-loader/Detcore readiness.
//!
//! The marker image has no Tool, constructor, seccomp policy or RNG. Every
//! CompletedWrite used here comes from production verify_write on a real child.

use std::ffi::OsStr;
use std::fs;
use std::fs::OpenOptions;
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;
use std::time::Instant;

use super::*;

const ISOLATED: &str = "REVERIE_INITIAL_AUXV_PHYSICAL_TEST";
const CHILD_LIMIT: Duration = Duration::from_secs(20);
const IO_LIMIT: Duration = Duration::from_secs(3);
const OUTPUT_LIMIT: usize = 4096;
// Four small argv entries, no environment, and no original-stack fixture work.
const ENTRY_STACK_LIMIT: usize = 1024 * 1024;
const ENTRY_WORDS: usize = 17;
const STATE: &[u8] = b"component-only-state";
const LOADER_MARKER: &[u8] = b"LOADER_ENTERED\n";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn record(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

/// Test-time compilers are bounded too; failed output is retained before panic.
fn command_output(mut command: Command, root: &Path, name: &str, limit: Duration) -> Vec<u8> {
    record(
        &root.join(format!("{name}.argv.txt")),
        format!("{command:?}\n").as_bytes(),
    );
    let log = root.join(format!("{name}.output.txt"));
    let output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&log)
        .unwrap();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::from(output));
    // SAFETY: the child only changes its own process group before exec. This
    // makes a timed-out compiler's assembler/linker part of the same cleanup.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().expect("spawn bounded fixture command");
    let start = Instant::now();
    let status = loop {
        if start.elapsed() >= limit || fs::metadata(&log).unwrap().len() > 1024 * 1024 {
            // The unreaped group leader still owns this process-group id.
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
            panic!(
                "fixture command exceeded its bound; retained {}",
                log.display()
            );
        }
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    record(
        &root.join(format!("{name}.status.txt")),
        format!("{status:?}\nwall={:?}\n", start.elapsed()).as_bytes(),
    );
    let bytes = fs::read(&log).unwrap();
    assert!(bytes.len() <= 1024 * 1024);
    assert!(
        status.success(),
        "{name}: {status:?}; {}",
        String::from_utf8_lossy(&bytes)
    );
    bytes
}

fn encoded_words(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

// Exact SeedEntryFrame/fixture-frame order, including the original RSP/flags.
fn entry_words(registers: &libc::user_regs_struct) -> [u64; ENTRY_WORDS] {
    [
        registers.rax,
        registers.rbx,
        registers.rcx,
        registers.rdx,
        registers.rsi,
        registers.rdi,
        registers.rbp,
        registers.rsp,
        registers.r8,
        registers.r9,
        registers.r10,
        registers.r11,
        registers.r12,
        registers.r13,
        registers.r14,
        registers.r15,
        registers.eflags,
    ]
}

fn traced_registers(pid: i32) -> libc::user_regs_struct {
    let mut registers: libc::user_regs_struct = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGS,
                pid,
                0,
                &mut registers as *mut libc::user_regs_struct,
            )
        },
        0
    );
    registers
}

fn traced_fp_registers(pid: i32) -> libc::user_fpregs_struct {
    let mut registers: libc::user_fpregs_struct = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { libc::ptrace(libc::PTRACE_GETFPREGS, pid, 0, &mut registers) },
        0
    );
    registers
}

fn fp_bytes(registers: &libc::user_fpregs_struct) -> &[u8] {
    assert_eq!(core::mem::size_of_val(registers), 512);
    // GETFPREGS populates this zero-initialized, all-integer x86-64 FXSAVE image.
    unsafe { core::slice::from_raw_parts(core::ptr::from_ref(registers).cast(), 512) }
}

fn architectural_fp(bytes: &[u8]) -> Vec<u8> {
    assert_eq!(bytes.len(), 512);
    // Compare every defined x87/SSE state byte. FXSAVE's reserved bytes and
    // MXCSR_MASK describe neither register state nor bootstrap-owned storage.
    let mut state = bytes[..5].to_vec();
    state.extend_from_slice(&bytes[6..28]);
    for slot in 0..8 {
        state.extend_from_slice(&bytes[32 + slot * 16..42 + slot * 16]);
    }
    state.extend_from_slice(&bytes[160..416]);
    state
}

fn auxv_value(auxv: &[u8], kind: u64) -> u64 {
    assert_eq!(auxv.len() % 16, 0);
    let values: Vec<_> = auxv
        .as_chunks::<16>()
        .0
        .iter()
        .filter(|row| u64::from_le_bytes(row[..8].try_into().unwrap()) == kind)
        .map(|row| u64::from_le_bytes(row[8..].try_into().unwrap()))
        .collect();
    assert_eq!(values.len(), 1, "unique actual kernel auxv key {kind}");
    assert_ne!(values[0], 0);
    values[0]
}

fn stack_interval(maps: &[u8], rsp: u64) -> (u64, u64) {
    let matches: Vec<_> = maps
        .split(|byte| *byte == b'\n')
        .filter_map(|mut row| {
            let range = map_field(&mut row)?;
            let permissions = map_field(&mut row)?;
            let (lo, hi) = range.split_once('-')?;
            let lo = u64::from_str_radix(lo, 16).ok()?;
            let hi = u64::from_str_radix(hi, 16).ok()?;
            if lo <= rsp && rsp < hi {
                assert_eq!(permissions, "rw-p", "actual initial kernel stack");
                Some((lo, hi))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(matches.len(), 1, "unique original stack mapping");
    matches[0]
}

fn linked_symbol(image: &Elf<'_>, name: &str) -> (u64, u64) {
    let symbols: Vec<_> = image
        .syms
        .iter()
        .filter(|symbol| image.strtab.get_at(symbol.st_name) == Some(name))
        .collect();
    assert_eq!(symbols.len(), 1, "unique linked symbol {name}");
    assert_ne!(symbols[0].st_shndx, 0, "defined linked symbol {name}");
    (symbols[0].st_value, symbols[0].st_size)
}

struct SeedLayout {
    data: u64,
    active_end: u64,
    frame: u64,
    stack: u64,
    stack_end: u64,
    transfer: u64,
}

impl SeedLayout {
    fn compiled() -> Self {
        // The adapted RW p_memsz covers the original loader envelope. Only
        // the source template and its linked active bounds describe scratch.
        let image = elf(SEED).unwrap();
        qualify_seed(&image).unwrap();
        let (frame, frame_size) = linked_symbol(&image, "seed_frame");
        let (transfer, transfer_size) = linked_symbol(&image, "seed_transfer_entry");
        assert_eq!(frame_size, (ENTRY_WORDS * 8) as u64);
        assert_eq!(transfer_size, 8);
        let layout = Self {
            data: linked_symbol(&image, "seed_data_start").0,
            active_end: linked_symbol(&image, "seed_image_active_end").0,
            frame,
            stack: linked_symbol(&image, "seed_stack").0,
            stack_end: linked_symbol(&image, "seed_stack_end").0,
            transfer,
        };
        assert_eq!(layout.data, linked_symbol(&image, "seed_code_end").0);
        assert!(layout.data > 0 && layout.data < layout.active_end);
        assert!(layout.active_end <= SCRATCH_BYTES as u64);
        assert_eq!(layout.data % PAGE, 0);
        assert_eq!(layout.active_end % PAGE, 0);
        assert_eq!(layout.frame % 8, 0);
        assert_eq!(layout.transfer % 8, 0);
        assert!(layout.data <= layout.frame);
        assert!(layout.frame.checked_add(frame_size).unwrap() <= layout.stack);
        assert!(layout.stack < layout.stack_end);
        assert!(layout.stack_end <= layout.transfer);
        assert!(layout.transfer.checked_add(8).unwrap() <= layout.active_end);
        let writable: Vec<_> = image
            .program_headers
            .iter()
            .filter(|load| load.p_type == ph::PT_LOAD && load.p_flags & ph::PF_W != 0)
            .collect();
        assert_eq!(writable.len(), 1);
        assert_eq!(writable[0].p_flags, ph::PF_R | ph::PF_W);
        assert_eq!(writable[0].p_vaddr, layout.data);
        let end = writable[0]
            .p_vaddr
            .checked_add(writable[0].p_memsz)
            .unwrap();
        assert!(end <= layout.active_end);
        assert_eq!((end + PAGE - 1) & !(PAGE - 1), layout.active_end);
        layout
    }
}

struct KernelEntry {
    words: [u64; ENTRY_WORDS],
    fp: Vec<u8>,
    stack_lo: u64,
    stack: Vec<u8>,
    auxv: Vec<u8>,
    base: u64,
    random: u64,
}

struct Fixtures {
    root: PathBuf,
    loader: PathBuf,
    main: PathBuf,
    checker: PathBuf,
}

impl Fixtures {
    fn build() -> Self {
        let target =
            PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").expect("owned target required"));
        assert!(
            target.is_absolute() && target.is_dir(),
            "use the existing bounded H target"
        );
        let parent = target.join("ci/initial-auxv-physical");
        fs::create_dir_all(&parent).unwrap();
        let root = tempfile::Builder::new()
            .prefix("attempt-")
            .tempdir_in(parent)
            .unwrap()
            .keep();
        eprintln!(
            "physical ordinary-seed component evidence {}",
            root.display()
        );
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        for (name, expected) in [
            (
                "initial_auxv_physical_peer.c",
                include_bytes!("../../../../tests/fixtures/initial_auxv_physical_peer.c")
                    .as_slice(),
            ),
            (
                "initial_auxv_physical_entry.S",
                include_bytes!("../../../../tests/fixtures/initial_auxv_physical_entry.S")
                    .as_slice(),
            ),
            (
                "initial_auxv_physical_loader.ld",
                include_bytes!("../../../../tests/fixtures/initial_auxv_physical_loader.ld")
                    .as_slice(),
            ),
            (
                "initial_auxv_physical_main.c",
                include_bytes!("../../../../tests/fixtures/initial_auxv_physical_main.c")
                    .as_slice(),
            ),
        ] {
            let actual = fs::read(fixtures.join(name)).unwrap();
            assert_eq!(
                actual, expected,
                "fixture source changed since this test was compiled"
            );
            record(&root.join(name), &actual);
        }
        let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
        let mut version = Command::new(&compiler);
        version.arg("--version");
        command_output(version, &root, "cc-version", Duration::from_secs(10));
        let loader = root.join("marker-loader.so");
        let checker = root.join("fd-checker");
        let main = root.join("dynamic-main");
        let common = [
            "-O2",
            "-g0",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-fno-unwind-tables",
            "-nostdlib",
            "-Wl,--build-id=none",
            "-Wl,-z,noexecstack",
        ];
        let peer = root.join("initial_auxv_physical_peer.c");
        let entry = root.join("initial_auxv_physical_entry.S");
        let mut build = Command::new(&compiler);
        build
            .args(common)
            .args(["-shared", "-fPIC", "-Wl,-Bsymbolic"])
            .arg(format!(
                "-Wl,-T,{}",
                root.join("initial_auxv_physical_loader.ld").display()
            ))
            .arg(&peer)
            .arg(&entry)
            .arg("-o")
            .arg(&loader);
        command_output(build, &root, "loader-build", Duration::from_secs(30));
        let mut build = Command::new(&compiler);
        build
            .args(common)
            .args(["-DFD_CHECKER", "-static", "-no-pie", "-Wl,-e,_start"])
            .arg(&peer)
            .arg(&entry)
            .arg("-o")
            .arg(&checker);
        command_output(build, &root, "checker-build", Duration::from_secs(30));
        let mut build = Command::new(&compiler);
        build
            .args([
                "-O2",
                "-g0",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wl,--build-id=none",
            ])
            .arg(format!("-Wl,--dynamic-linker={}", loader.display()))
            .arg(root.join("initial_auxv_physical_main.c"))
            .arg("-o")
            .arg(&main);
        command_output(build, &root, "main-build", Duration::from_secs(30));
        for path in [&loader, &main, &checker] {
            let bytes = fs::read(path).unwrap();
            assert!(bytes.len() < MAX_ELF);
            let image = elf(&bytes).unwrap();
            assert!(image.program_headers.iter().all(|p| p.p_type != ph::PT_TLS));
            record(
                &path.with_extension("identity.txt"),
                format!(
                    "path={}\nbytes={}\nsha256={:x}\nentry={:#x}\n",
                    path.display(),
                    bytes.len(),
                    Sha256::digest(&bytes),
                    image.entry,
                )
                .as_bytes(),
            );
            if path == &loader {
                let (span, alignment) = loader_span(&bytes).unwrap();
                seed_for_loader(span, alignment).unwrap();
                assert!(image.libraries.is_empty());
                assert!(
                    image.dynrelas.is_empty()
                        && image.dynrels.is_empty()
                        && image.pltrelocs.is_empty()
                );
                assert!(image.syms.iter().all(|s| s.st_shndx != 0 || s.st_name == 0));
            } else if path == &main {
                assert_eq!(image.interpreter, loader.to_str());
            } else {
                assert!(image.interpreter.is_none());
            }
        }
        record(&root.join("scope.txt"), b"Test-only marker/protocol components; no stock-loader, Tool, Detcore or full runtime readiness claim.\n");
        Self {
            root,
            loader,
            main,
            checker,
        }
    }

    fn spawn(&self, name: &str, mode: u8) -> (Prepared, PhysicalChild, Arc<AtomicUsize>) {
        self.spawn_inner(name, mode, false, false)
    }

    fn spawn_inner(
        &self,
        name: &str,
        mode: u8,
        trace_entry: bool,
        keep_stopped: bool,
    ) -> (Prepared, PhysicalChild, Arc<AtomicUsize>) {
        assert!(!keep_stopped || trace_entry);
        let dir = self.root.join(name);
        fs::create_dir(&dir).unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let completion_dir = dir.clone();
        let prepared = Prepared::prepare(
            b"physical component configuration",
            PendingWrite::new(self.main.clone(), [0xa5; 16], move |image| {
                // This callback only counts real production-authenticated
                // writes. Its bytes are expressly not Detcore Tool state.
                assert_eq!(image.bytes(), [0xa5; 16]);
                assert!(image.pid() > 0 && image.start_time_ticks() > 0 && image.target() > 0);
                assert_eq!(observed.fetch_add(1, Ordering::SeqCst), 0);
                record(
                    &completion_dir.join("authenticated-write.txt"),
                    format!("{image:?}\n").as_bytes(),
                );
                record(
                    &completion_dir.join("authenticated.maps.txt"),
                    &fs::read(format!("/proc/{}/maps", image.pid())).unwrap(),
                );
                record(
                    &completion_dir.join("authenticated.auxv.bin"),
                    &fs::read(format!("/proc/{}/auxv", image.pid())).unwrap(),
                );
                Ok(STATE.to_vec())
            }),
        )
        .unwrap();
        assert_eq!(
            prepared.input.interpreter.to_bytes(),
            self.loader.as_os_str().as_bytes()
        );
        record(
            &dir.join("token.txt"),
            hex(&prepared.token().encode()).as_bytes(),
        );
        record(
            &dir.join("seed.sha256"),
            format!("{:x}\n", Sha256::digest(&prepared.seed_bytes)).as_bytes(),
        );
        let err_path = dir.join("stderr.txt");
        let err = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&err_path)
            .unwrap();
        let mut command = Command::new(&self.main);
        command
            .arg(mode.to_string())
            .arg(hex(&prepared.token().encode()))
            .arg(&self.checker)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(err));
        prepared
            .install(&mut command)
            .expect("actual private mount/install; EPERM is not a skip");
        if trace_entry {
            // SAFETY: observation only in this test child. Stop at successful
            // kernel exec before the interpreter executes any instruction.
            unsafe {
                command.pre_exec(|| {
                    if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        record(&dir.join("argv.txt"), format!("{command:?}\n").as_bytes());
        let mut child = command
            .spawn()
            .expect("real kernel interpreter launch must succeed");
        drop(command); // Drop the parent's pre_exec Arc/child-endpoint copy.
        let pid = child.id() as i32;
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if pidfd < 0 {
            let error = io::Error::last_os_error();
            let _ = child.kill();
            let _ = child.wait();
            panic!("hold child pidfd: {error}");
        }
        let stdout: OwnedFd = child.stdout.take().unwrap().into();
        set_nonblocking(stdout.as_raw_fd());
        record(&dir.join("child.txt"), format!("pid={pid}\n").as_bytes());
        let mut observed = PhysicalChild {
            child,
            pidfd: unsafe { OwnedFd::from_raw_fd(pidfd as i32) },
            stdout: File::from(stdout),
            bytes: Vec::new(),
            dir,
            err_path,
            entry: None,
        };
        if trace_entry {
            observed.entry = Some(stopped_interpreter(
                &prepared,
                pid,
                &observed.dir,
                keep_stopped,
                mode == 6,
            ));
        }
        (prepared, observed, count)
    }
}

fn stopped_interpreter(
    prepared: &Prepared,
    pid: i32,
    dir: &Path,
    keep_stopped: bool,
    sentinels: bool,
) -> KernelEntry {
    let start = Instant::now();
    let mut status = 0;
    loop {
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED | libc::WNOHANG) };
        assert!(got >= 0, "wait for actual interpreter exec stop");
        if got == pid {
            break;
        }
        assert!(start.elapsed() < IO_LIMIT, "kernel exec stop is bounded");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
    let mut registers = traced_registers(pid);
    let mut fp = traced_fp_registers(pid);
    record(&dir.join("exec-stop.kernel-fp.bin"), fp_bytes(&fp));
    record(
        &dir.join("exec-stop.kernel-gp.bin"),
        &encoded_words(&entry_words(&registers)),
    );
    let auxv = fs::read(format!("/proc/{pid}/auxv")).unwrap();
    let base = auxv_value(&auxv, libc::AT_BASE);
    let random = auxv_value(&auxv, libc::AT_RANDOM);
    assert_eq!(
        registers.rip,
        base + elf(&prepared.seed_bytes).unwrap().entry
    );
    if sentinels {
        // Distinguish all sixteen XMM registers and non-default rounding modes.
        // The untouched kernel-entry case remains independently required.
        for (index, word) in fp.xmm_space.iter_mut().enumerate() {
            *word = 0x5a00_0001 + index as u32 * 0x0101;
        }
        fp.cwd = (fp.cwd & !0x0c00) | 0x0800;
        fp.mxcsr = (fp.mxcsr & !0x6000) | 0x4000;
        let expected_fp = architectural_fp(fp_bytes(&fp));
        assert_eq!(
            unsafe { libc::ptrace(libc::PTRACE_SETFPREGS, pid, 0, &fp) },
            0
        );
        fp = traced_fp_registers(pid);
        assert_eq!(architectural_fp(fp_bytes(&fp)), expected_fp);
        // Separate controlled-entry case: distinguish every GP slot, and
        // require restoration of DF/OF/CF/AF as well as the kernel's flags.
        // The untouched kernel-entry case remains independently required.
        registers.rax = 0x1101_0101_0101_0101;
        registers.rbx = 0x2202_0202_0202_0202;
        registers.rcx = 0x3303_0303_0303_0303;
        registers.rdx = 0x4404_0404_0404_0404;
        registers.rsi = 0x5505_0505_0505_0505;
        registers.rdi = 0x6606_0606_0606_0606;
        registers.rbp = 0x7707_0707_0707_0707;
        registers.r8 = 0x8808_0808_0808_0808;
        registers.r9 = 0x9909_0909_0909_0909;
        registers.r10 = 0xaa0a_0a0a_0a0a_0a0a;
        registers.r11 = 0xbb0b_0b0b_0b0b_0b0b;
        registers.r12 = 0xcc0c_0c0c_0c0c_0c0c;
        registers.r13 = 0xdd0d_0d0d_0d0d_0d0d;
        registers.r14 = 0xee0e_0e0e_0e0e_0e0e;
        registers.r15 = 0xff0f_0f0f_0f0f_0f0f;
        registers.eflags |= (1 << 10) | (1 << 11) | (1 << 0) | (1 << 4);
        let expected = entry_words(&registers);
        assert_eq!(
            unsafe {
                libc::ptrace(
                    libc::PTRACE_SETREGS,
                    pid,
                    0,
                    &registers as *const libc::user_regs_struct,
                )
            },
            0
        );
        registers = traced_registers(pid);
        assert_eq!(entry_words(&registers), expected, "actual sentinel state");
        assert_eq!(
            registers.rip,
            base + elf(&prepared.seed_bytes).unwrap().entry
        );
    }
    let maps = fs::read(format!("/proc/{pid}/maps")).unwrap();
    let (stack_lo, stack_hi) = stack_interval(&maps, registers.rsp);
    let stack_len = usize::try_from(stack_hi - stack_lo).unwrap();
    assert!(stack_len > 0 && stack_len <= ENTRY_STACK_LIMIT);
    assert!(random >= stack_lo && random.checked_add(16).unwrap() <= stack_hi);
    let mut stack = vec![0; stack_len];
    remote(pid, stack_lo as usize, &mut stack).unwrap();
    record(&dir.join("exec-stop.maps.txt"), &maps);
    record(&dir.join("exec-stop.auxv.bin"), &auxv);
    record(&dir.join("exec-stop.stack.bin"), &stack);
    record(&dir.join("exec-stop.fp.bin"), fp_bytes(&fp));
    record(
        &dir.join("exec-stop.gp.bin"),
        &encoded_words(&entry_words(&registers)),
    );
    record(
        &dir.join("exec-stop.stack-range.txt"),
        format!(
            "lo={stack_lo:#x}\nhi={stack_hi:#x}\nrsp={:#x}\nat_random={random:#x}\nsentinels={sentinels}\n",
            registers.rsp,
        )
        .as_bytes(),
    );
    // Characterize the kernel's actual interpreter-file write-open lifetime.
    // Unlike the main executable this is not assumed to have permanent
    // ETXTBSY protection. Opening succeeds or fails without writing any byte.
    let path: &Path = prepared.input._seed_path.as_ref();
    let before = fs::metadata(path).unwrap();
    let observation = match OpenOptions::new().write(true).open(path) {
        Ok(file) => {
            let actual = file.metadata().unwrap();
            assert_eq!((actual.dev(), actual.ino()), (before.dev(), before.ino()));
            drop(file);
            "write_open=allowed; no permanent interpreter write exclusion claimed\n".to_owned()
        }
        Err(error) => {
            assert_eq!(
                error.raw_os_error(),
                Some(libc::ETXTBSY),
                "unexpected write-open failure"
            );
            "write_open=ETXTBSY at exact interpreter entry only\n".to_owned()
        }
    };
    assert_eq!(file_bytes(&prepared.input._seed), prepared.seed_bytes);
    assert_eq!(fs::read(path).unwrap(), prepared.seed_bytes);
    record(
        &dir.join("exec-stop.seed-lifetime.txt"),
        format!(
            "rip={:#x}\nat_base={:#x}\nseed_device={}\nseed_inode={}\n{observation}",
            registers.rip,
            base,
            before.dev(),
            before.ino(),
        )
        .as_bytes(),
    );
    if !keep_stopped {
        assert_eq!(unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) }, 0);
    }
    KernelEntry {
        words: entry_words(&registers),
        fp: architectural_fp(fp_bytes(&fp)),
        stack_lo,
        stack,
        auxv,
        base,
        random,
    }
}

fn set_nonblocking(fd: i32) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
}

struct PhysicalChild {
    child: Child,
    pidfd: OwnedFd,
    stdout: File,
    bytes: Vec<u8>,
    dir: PathBuf,
    err_path: PathBuf,
    entry: Option<KernelEntry>,
}

impl PhysicalChild {
    fn drain(&mut self) {
        loop {
            let mut buffer = [0; 256];
            match self.stdout.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    self.bytes.extend_from_slice(&buffer[..n]);
                    assert!(self.bytes.len() <= OUTPUT_LIMIT, "fixture output bound");
                    fs::write(self.dir.join("stdout.txt"), &self.bytes).unwrap();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => panic!("read physical marker: {error}"),
            }
        }
        assert!(fs::metadata(&self.err_path).unwrap().len() <= OUTPUT_LIMIT as u64);
    }

    fn quiet(&mut self) {
        self.drain();
        assert!(
            self.bytes.is_empty(),
            "loader entered before GO: {:?}",
            self.bytes
        );
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "seed must really be paused and alive"
        );
    }

    async fn wait(&mut self) -> ExitStatus {
        let status = tokio::time::timeout(CHILD_LIMIT, async {
            loop {
                self.drain();
                if let Some(status) = self.child.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("physical child must finish within existing fixture backstop");
        self.drain();
        fs::write(self.dir.join("stdout.txt"), &self.bytes).unwrap();
        record(
            &self.dir.join("status.txt"),
            format!("{status:?}\n").as_bytes(),
        );
        status
    }
}

impl Drop for PhysicalChild {
    fn drop(&mut self) {
        // SAFETY: this pidfd is a private handle to the actual unreaped child,
        // never an unrelated process whose numeric PID might have been reused.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                0,
                0,
            )
        };
        let _ = self.child.wait();
    }
}

struct Peer {
    pid: i32,
    channel: Option<AsyncFd<OwnedFd>>,
    main: MainImage,
    loader: Held,
    seed: Vec<u8>,
    token: Token,
    birth: Birth,
}

impl Peer {
    fn new(prepared: Prepared, child: &PhysicalChild) -> Self {
        let Prepared {
            input,
            channel,
            main,
            loader,
            seed_bytes,
            pending,
            token,
        } = prepared;
        drop(input); // EOF must not be masked by a parent copy of the child peer.
        drop(pending);
        set_nonblocking(channel.as_raw_fd());
        let fd = child.pidfd.try_clone().unwrap();
        Self {
            pid: child.child.id() as i32,
            channel: Some(register_owned(channel).unwrap()),
            main,
            loader,
            seed: seed_bytes,
            token,
            birth: Birth {
                fd,
                complete: false,
            },
        }
    }

    async fn ack(&self, child: &mut PhysicalChild) -> Vec<u8> {
        let (bytes, pid) = tokio::time::timeout(IO_LIMIT, receive(self.channel.as_ref().unwrap()))
            .await
            .expect("real seed WRITE is bounded")
            .expect("real seed sends a complete WRITE");
        assert_eq!(pid, Some(self.pid));
        assert_eq!(bytes.len(), 192);
        check_header(&bytes, WRITE_MAGIC, self.token).unwrap();
        assert_eq!(u64_at(&bytes, 80).unwrap(), self.pid as u64);
        assert_eq!(u64_at(&bytes, 88).unwrap(), self.pid as u64);
        assert_eq!(&bytes[160..176], &[0xa5; 16]);
        assert_eq!(u64_at(&bytes, 176).unwrap(), 16);
        assert_eq!(u64_at(&bytes, 184).unwrap(), 0);
        record(&child.dir.join("actual-write.bin"), &bytes);
        record(
            &child.dir.join("maps.txt"),
            &fs::read(format!("/proc/{}/maps", self.pid)).unwrap(),
        );
        record(
            &child.dir.join("auxv.bin"),
            &fs::read(format!("/proc/{}/auxv", self.pid)).unwrap(),
        );
        child.quiet();
        bytes
    }

    fn verify(&self, bytes: &[u8], child: &PhysicalChild) -> CompletedWrite {
        let completed = verify_write(self.pid, bytes, &self.main, &self.loader, &self.seed)
            .expect("real seed/stack/file-backing/readback must qualify");
        assert_eq!(completed.bytes(), [0xa5; 16]);
        record(
            &child.dir.join("physical-write.txt"),
            format!("{completed:?}\n").as_bytes(),
        );
        completed
    }

    async fn go(&self, packet: &[u8], fd: Option<i32>) {
        tokio::time::timeout(IO_LIMIT, send(self.channel.as_ref().unwrap(), packet, fd))
            .await
            .expect("GO send bounded")
            .unwrap();
    }
}

fn bootstrap(token: Token) -> OwnedFd {
    // A genuine sealed V4 packet, explicitly not an installed coordinator or
    // Tool. Only the component marker peer receives this unconnected address.
    crate::bootstrap::create_preload_bootstrap_with_auxv(
        Path::new("/component-only-no-tool.sock"),
        None,
        Some(false),
        b"component",
        Some(token),
    )
    .unwrap()
}

async fn retirement_controls(fixtures: &Fixtures) {
    let layout = SeedLayout::compiled();
    for (name, mode) in [("retired-kernel-entry", 5), ("retired-sentinel-entry", 6)] {
        let (prepared, mut child, count) = fixtures.spawn_inner(name, mode, true, false);
        let entry = child.entry.take().expect("actual pre-seed exec snapshot");
        let mut peer = Peer::new(prepared, &child);
        let write = peer.ack(&mut child).await;
        let completed = peer.verify(&write, &child);
        assert_eq!(completed.target() as u64, entry.random);
        let writable_start = (SCRATCH_BASE as u64).checked_add(layout.data).unwrap();
        let writable_len = usize::try_from(layout.active_end - layout.data).unwrap();
        let mut before = vec![0; writable_len];
        remote(peer.pid, writable_start as usize, &mut before).unwrap();
        record(&child.dir.join("seed-rw.before-go.bin"), &before);
        assert!(
            before.iter().any(|byte| *byte != 0),
            "the actual waiting seed contains live private state before GO"
        );
        let mut go = [0; 96];
        header(&mut go, GO_MAGIC, peer.token);
        let input = bootstrap(peer.token);
        record(&child.dir.join("sent-go.bin"), &go);
        peer.go(&go, Some(input.as_raw_fd())).await;
        drop(input);

        // The fixture captured every GP/flag before its first marker and uses
        // only its own stack. It never touches seed storage. Hold STATE here,
        // before any Rust consumer or Tool, for complete transfer readback.
        let (take, sender) =
            tokio::time::timeout(IO_LIMIT, receive(peer.channel.as_ref().unwrap()))
                .await
                .expect("fixture entry audit barrier is bounded")
                .unwrap();
        assert_eq!(sender, Some(peer.pid));
        assert_eq!(take.len(), 96);
        check_header(&take, TAKE_MAGIC, peer.token).unwrap();
        assert_eq!(u64_at(&take, 80).unwrap(), peer.pid as u64);
        assert_eq!(u64_at(&take, 88).unwrap(), 0);
        record(&child.dir.join("actual-take.bin"), &take);
        child.drain();
        assert_eq!(child.bytes, LOADER_MARKER);
        assert!(fs::read(&child.err_path).unwrap().is_empty());

        let loader = elf(&peer.loader.bytes).unwrap();
        let (fixture_frame, fixture_frame_size) =
            linked_symbol(&loader, "initial_auxv_fixture_frame");
        assert_eq!(fixture_frame_size, (ENTRY_WORDS * 8) as u64);
        let mut frame = [0; ENTRY_WORDS * 8];
        remote(
            peer.pid,
            entry.base.checked_add(fixture_frame).unwrap() as usize,
            &mut frame,
        )
        .unwrap();
        record(&child.dir.join("loader-entry.gp.bin"), &frame);
        let words: [u64; ENTRY_WORDS] = std::array::from_fn(|index| {
            u64::from_le_bytes(frame[index * 8..(index + 1) * 8].try_into().unwrap())
        });
        assert_eq!(words, entry.words, "all original GP/RSP/RFLAGS restored");

        let (fixture_fp, fixture_fp_size) = linked_symbol(&loader, "initial_auxv_fixture_fp");
        assert_eq!(fixture_fp_size, 512);
        let mut fp = [0; 512];
        remote(
            peer.pid,
            entry.base.checked_add(fixture_fp).unwrap() as usize,
            &mut fp,
        )
        .unwrap();
        record(&child.dir.join("loader-entry.fp.bin"), &fp);
        assert_eq!(
            architectural_fp(&fp),
            entry.fp,
            "all original x87/MXCSR/XMM state preserved"
        );

        let loader_entry = entry.base.checked_add(loader.entry).unwrap();
        let mut retired = vec![0; writable_len];
        remote(peer.pid, writable_start as usize, &mut retired).unwrap();
        record(&child.dir.join("seed-rw.retired.bin"), &retired);
        let mut expected = vec![0; writable_len];
        let operand = usize::try_from(layout.transfer - layout.data).unwrap();
        expected[operand..operand + 8].copy_from_slice(&loader_entry.to_le_bytes());
        record(&child.dir.join("seed-rw.expected.bin"), &expected);
        assert_eq!(
            retired
                .iter()
                .zip(&expected)
                .position(|(actual, expected)| actual != expected),
            None,
            "every active RW byte is zero except the exact public loader-entry word; raw snapshots retained"
        );
        let frame_start = usize::try_from(layout.frame - layout.data).unwrap();
        let stack_start = usize::try_from(layout.stack - layout.data).unwrap();
        let stack_end = usize::try_from(layout.stack_end - layout.data).unwrap();
        assert!(
            retired[frame_start..frame_start + ENTRY_WORDS * 8]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(
            retired[stack_start..stack_end]
                .iter()
                .all(|byte| *byte == 0)
        );

        let maps = fs::read(format!("/proc/{}/maps", peer.pid)).unwrap();
        record(&child.dir.join("loader-entry.maps.txt"), &maps);
        assert_eq!(
            stack_interval(&maps, entry.words[7]),
            (entry.stack_lo, entry.stack_lo + entry.stack.len() as u64),
            "original kernel stack mapping unchanged"
        );
        let auxv = fs::read(format!("/proc/{}/auxv", peer.pid)).unwrap();
        record(&child.dir.join("loader-entry.auxv.bin"), &auxv);
        assert_eq!(auxv, entry.auxv, "complete raw kernel auxv unchanged");
        let mut stack = vec![0; entry.stack.len()];
        remote(peer.pid, entry.stack_lo as usize, &mut stack).unwrap();
        record(&child.dir.join("loader-entry.stack.bin"), &stack);
        let mut expected_stack = entry.stack;
        let random = usize::try_from(entry.random - entry.stack_lo).unwrap();
        expected_stack[random..random + 16].fill(0xa5);
        record(
            &child.dir.join("loader-entry.stack.expected.bin"),
            &expected_stack,
        );
        assert_eq!(
            stack
                .iter()
                .zip(&expected_stack)
                .position(|(actual, expected)| actual != expected),
            None,
            "entire original kernel stack unchanged except exactly AT_RANDOM16"
        );
        stack_auxv(
            peer.pid,
            entry.words[7] as usize,
            completed.target(),
            &auxv,
            u64_at(&write, 104).unwrap() as usize,
            u64_at(&write, 152).unwrap() as usize,
        )
        .unwrap();
        record(
            &child.dir.join("retirement-audit.txt"),
            format!(
                "rw_start={writable_start:#x}\nrw_bytes={writable_len}\nframe={:#x}\nframe_bytes={}\nseed_stack={:#x}..{:#x}\npublic_entry_word={:#x}\npublic_entry_value={loader_entry:#x}\noriginal_stack_bytes={}\nall_private_rw_zero=true\nall_gp_rsp_rflags_exact=true\noriginal_stack_exact_except_at_random16=true\nraw_and_stack_auxv_exact=true\n",
                SCRATCH_BASE as u64 + layout.frame,
                ENTRY_WORDS * 8,
                SCRATCH_BASE as u64 + layout.stack,
                SCRATCH_BASE as u64 + layout.stack_end,
                SCRATCH_BASE as u64 + layout.transfer,
                expected_stack.len(),
            )
            .as_bytes(),
        );

        let mut response = vec![0; 128 + STATE.len()];
        header(&mut response, STATE_MAGIC, peer.token);
        put_u64(&mut response, 80, peer.pid as u64);
        put_u64(&mut response, 88, completed.start_time_ticks());
        put_u64(&mut response, 96, completed.target() as u64);
        put_u64(&mut response, 104, 16);
        response[112..128].copy_from_slice(&completed.bytes());
        response[128..].copy_from_slice(STATE);
        record(&child.dir.join("sent-state.bin"), &response);
        tokio::time::timeout(
            IO_LIMIT,
            send(peer.channel.as_ref().unwrap(), &response, None),
        )
        .await
        .expect("audited fixture's one STATE response is bounded")
        .unwrap();
        let (end, sender) = tokio::time::timeout(IO_LIMIT, receive(peer.channel.as_ref().unwrap()))
            .await
            .expect("audited fixture consumes its endpoint once")
            .unwrap();
        assert!(end.is_empty() && sender.is_none());
        assert_eq!(child.wait().await.code(), Some(42));
        assert_eq!(child.bytes, b"LOADER_ENTERED\nSTATE_ONCE\n");
        assert_eq!(fs::read(&child.err_path).unwrap(), response);
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "no Tool policy in audit peer"
        );
        drop(peer.channel.take());
        eprintln!("physical control {name}: complete (entry/scrub component only)");
    }
}

async fn go_controls(fixtures: &Fixtures) {
    for name in [
        "held-valid",
        "missing",
        "short",
        "wrong-config",
        "no-right",
        "unsealed-right",
        "oversized",
        "two-rights",
    ] {
        let (prepared, mut child, count) =
            fixtures.spawn_inner(name, 0, name == "held-valid", false);
        let peer = Peer::new(prepared, &child);
        let bytes = peer.ack(&mut child).await;
        peer.verify(&bytes, &child);
        let input = bootstrap(peer.token);
        let mut go = vec![0; 96];
        header(&mut go, GO_MAGIC, peer.token);
        if name == "missing" {
            let mut peer = peer;
            drop(peer.channel.take());
            assert_eq!(child.wait().await.code(), Some(28));
        } else {
            let mut selected = Some(input.as_raw_fd());
            let ordinary;
            match name {
                "short" => {
                    go.pop();
                }
                "wrong-config" => {
                    go[48] ^= 1;
                }
                "no-right" => {
                    selected = None;
                }
                "unsealed-right" => {
                    ordinary = File::open(&fixtures.main).unwrap();
                    selected = Some(ordinary.as_raw_fd());
                }
                "oversized" => {
                    go.push(0);
                }
                _ => {}
            }
            record(&child.dir.join("sent-go.bin"), &go);
            if name == "two-rights" {
                send_rights(
                    peer.channel.as_ref().unwrap().get_ref().as_raw_fd(),
                    &go,
                    &[input.as_raw_fd(), input.as_raw_fd()],
                );
            } else {
                peer.go(&go, selected).await;
            }
            let expected = if name == "held-valid" { 42 } else { 28 };
            assert_eq!(child.wait().await.code(), Some(expected), "{name}");
        }
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "manual GO control invokes no Tool policy"
        );
        assert_eq!(
            child.bytes.as_slice(),
            if name == "held-valid" {
                LOADER_MARKER
            } else {
                b""
            },
            "{name}"
        );
        eprintln!("physical control {name}: complete (component, not Tool readiness)");
    }

    // Both tokens originate from actual installed seeds, not manufactured
    // successful write records. Replay the first launch's GO into the second.
    let (a, mut first, ca) = fixtures.spawn("stale-origin", 0);
    let a = Peer::new(a, &first);
    let ack = a.ack(&mut first).await;
    a.verify(&ack, &first);
    let (b, mut second, cb) = fixtures.spawn("stale-recipient", 0);
    let b = Peer::new(b, &second);
    let ack = b.ack(&mut second).await;
    b.verify(&ack, &second);
    assert_ne!(a.token, b.token);
    let mut stale = [0; 96];
    header(&mut stale, GO_MAGIC, a.token);
    let input = bootstrap(a.token);
    record(&second.dir.join("sent-go.bin"), &stale);
    b.go(&stale, Some(input.as_raw_fd())).await;
    assert_eq!(second.wait().await.code(), Some(28));
    assert!(second.bytes.is_empty());
    // Keep the endpoint open until precise pidfd cancellation is observed.
    // Closing it first would let the seed refuse EOF before the kill.
    drop(a.birth);
    assert_eq!(first.wait().await.signal(), Some(libc::SIGKILL));
    assert!(first.bytes.is_empty());
    assert_eq!(ca.load(Ordering::SeqCst) + cb.load(Ordering::SeqCst), 0);

    // Observe the new image before owner cancellation can race its first
    // instruction. This separate manual-peer component proves actual CLOEXEC;
    // the production-server case below independently proves EOF refusal.
    let (prepared, mut child, count) = fixtures.spawn("later-exec-fd-closure", 4);
    let mut peer = Peer::new(prepared, &child);
    let ack = peer.ack(&mut child).await;
    peer.verify(&ack, &child);
    let before = read_birth(peer.pid).unwrap().0;
    let mut go = [0; 96];
    header(&mut go, GO_MAGIC, peer.token);
    let input = bootstrap(peer.token);
    peer.go(&go, Some(input.as_raw_fd())).await;
    let (end, sender) = tokio::time::timeout(IO_LIMIT, receive(peer.channel.as_ref().unwrap()))
        .await
        .expect("actual exec closes the old peer")
        .unwrap();
    assert!(
        end.is_empty() && sender.is_none(),
        "exec cannot redeem the old launch"
    );
    assert_eq!(child.wait().await.code(), Some(43));
    assert_eq!(
        child.bytes,
        b"LOADER_ENTERED\nCLOEXEC_ARMED\nEXEC_ENTERED\nSTALE_FDS_CLOSED\n"
    );
    // The exact child/pidfd and qualified static checker identify this actual
    // exec. Do not pretend start_time changes across an exec in the same PID.
    record(
        &child.dir.join("before-exec-birth.txt"),
        format!("{before}\n").as_bytes(),
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
    drop(peer.channel.take());

    let (prepared, mut child, count) = fixtures.spawn("physical-readback-tamper", 0);
    let peer = Peer::new(prepared, &child);
    let ack = peer.ack(&mut child).await;
    let completed = peer.verify(&ack, &child);
    let changed = [0x5a];
    let local = libc::iovec {
        iov_base: changed.as_ptr().cast_mut().cast(),
        iov_len: 1,
    };
    let remote = libc::iovec {
        iov_base: completed.target() as *mut _,
        iov_len: 1,
    };
    // A deliberate owned-child mutation after its actual ACK. This does not
    // pretend to interrupt a CPU store or construct a successful proof.
    assert_eq!(
        unsafe { libc::process_vm_writev(peer.pid, &local, 1, &remote, 1, 0) },
        1
    );
    let error = verify_write(peer.pid, &ack, &peer.main, &peer.loader, &peer.seed)
        .expect_err("actual changed byte must refuse before GO");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(
        error.to_string().contains("write or birth changed"),
        "{error}"
    );
    record(&child.dir.join("refusal.txt"), error.to_string().as_bytes());
    child.quiet();
    // Exercise owner cancellation, retaining the peer so EOF cannot win.
    drop(peer.birth);
    assert_eq!(child.wait().await.signal(), Some(libc::SIGKILL));
    assert!(child.bytes.is_empty());
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

async fn server_controls(fixtures: &Fixtures) {
    for (name, mode, error) in [
        ("server-one-redemption", 1, None),
        ("server-duplicate-take", 2, Some("redeemed more than once")),
        (
            "server-duplicate-write",
            3,
            Some("redemption is absent or from another child"),
        ),
        (
            "server-missing-take",
            0,
            Some("redemption is absent or from another child"),
        ),
        (
            "server-later-exec",
            4,
            Some("redemption is absent or from another child"),
        ),
    ] {
        let (prepared, mut child, count) = fixtures.spawn(name, mode);
        let token = prepared.token();
        let future = prepared.serve(child.child.id(), bootstrap(token)).unwrap();
        let result = tokio::time::timeout(CHILD_LIMIT, future)
            .await
            .expect("one-use server bounded");
        match error {
            None => assert!(result.is_ok(), "{name}: {result:?}"),
            Some(expected) => {
                let error = result.expect_err(name);
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(error.to_string().contains(expected), "{name}: {error}");
                record(&child.dir.join("refusal.txt"), error.to_string().as_bytes());
            }
        }
        let status = child.wait().await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "exactly one authenticated write, {name}"
        );
        assert!(
            child.bytes.starts_with(LOADER_MARKER),
            "real GO must precede entry, {name}: {:?}",
            child.bytes
        );
        assert!(
            !child
                .bytes
                .windows(b"SECOND_STATE".len())
                .any(|w| w == b"SECOND_STATE")
        );
        let state = fs::read(&child.err_path).unwrap();
        if mode == 1 || mode == 2 {
            assert_eq!(state.len(), 128 + STATE.len());
            check_header(&state, STATE_MAGIC, token).unwrap();
            assert_eq!(u64_at(&state, 80).unwrap(), child.child.id() as u64);
            assert!(u64_at(&state, 88).unwrap() > 0);
            assert!(u64_at(&state, 96).unwrap() > 0);
            assert_eq!(u64_at(&state, 104).unwrap(), 16);
            assert_eq!(&state[112..128], &[0xa5; 16]);
            assert_eq!(&state[128..], STATE);
        } else {
            assert!(state.is_empty(), "no STATE delivered in {name}");
        }
        if mode == 4 {
            // Closing CLOEXEC produces EOF before the new image is scheduled;
            // the production owner must kill it, and may win that race. All
            // accepted prefixes end at a complete atomic marker write. The
            // separate manual-peer case requires the full FD-checker proof.
            assert!(
                [
                    b"LOADER_ENTERED\nCLOEXEC_ARMED\n".as_slice(),
                    b"LOADER_ENTERED\nCLOEXEC_ARMED\nEXEC_ENTERED\n".as_slice(),
                    b"LOADER_ENTERED\nCLOEXEC_ARMED\nEXEC_ENTERED\nSTALE_FDS_CLOSED\n".as_slice(),
                ]
                .contains(&child.bytes.as_slice()),
                "{name}: {:?}",
                child.bytes
            );
            assert!(status.signal() == Some(libc::SIGKILL) || status.code() == Some(43));
        } else {
            let expected = if mode == 1 || mode == 2 {
                b"LOADER_ENTERED\nSTATE_ONCE\n".as_slice()
            } else {
                LOADER_MARKER
            };
            assert_eq!(child.bytes, expected, "{name}: {status:?}");
        }
        if mode == 1 || mode == 0 {
            assert_eq!(status.code(), Some(42));
        }
        eprintln!("physical server {name}: complete (component state only)");
    }

    // Dropping even an unpolled future owns and cancels the precise child.
    // An unrelated child remains alive, so numeric process/group mistakes do
    // not silently satisfy the cancellation assertion.
    let mut unrelated = PacketChild(
        Command::new("/bin/sleep")
            .env_clear()
            .arg("30")
            .spawn()
            .unwrap(),
    );
    let (prepared, mut child, count) = fixtures.spawn("server-cancelled", 0);
    let token = prepared.token();
    let future = prepared.serve(child.child.id(), bootstrap(token)).unwrap();
    drop(future);
    assert_eq!(child.wait().await.signal(), Some(libc::SIGKILL));
    assert!(child.bytes.is_empty());
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert!(unrelated.0.try_wait().unwrap().is_none());

    // A successful kernel exec stop holds the actual seed before its first
    // instruction, so this first poll is provably before WRITE/ACK, not a
    // scheduling guess. Cancellation must kill before closing the exchange.
    let (prepared, mut child, count) =
        fixtures.spawn_inner("server-cancelled-after-poll", 0, true, true);
    child.quiet();
    let token = prepared.token();
    let future = prepared.serve(child.child.id(), bootstrap(token)).unwrap();
    let mut future = Box::pin(future);
    std::future::poll_fn(|cx| {
        assert!(
            std::future::Future::poll(future.as_mut(), cx).is_pending(),
            "stopped seed cannot have sent its WRITE"
        );
        std::task::Poll::Ready(())
    })
    .await;
    record(
        &child.dir.join("pending-before-ack.txt"),
        b"Actual seed held at kernel exec entry; server polled Pending before WRITE.\n",
    );
    drop(future);
    assert_eq!(child.wait().await.signal(), Some(libc::SIGKILL));
    assert!(child.bytes.is_empty());
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert!(unrelated.0.try_wait().unwrap().is_none());
}

#[test]
fn real_seed_go_and_one_use_handoffs_run_before_the_fixture_loader() {
    let name = std::thread::current().name().unwrap().to_owned();
    if let Some(marker) = std::env::var_os(ISOLATED) {
        assert_eq!(marker.as_os_str(), OsStr::new(&name));
    } else {
        // Re-exec, never fork a multithreaded libtest into Rust fixture work.
        // The one selected child has no Tokio runtime when Container clones.
        let target = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").expect("owned target"));
        let root = target.join("ci/initial-auxv-physical");
        fs::create_dir_all(&root).unwrap();
        let isolation = tempfile::Builder::new()
            .prefix("isolation-")
            .tempdir_in(root)
            .unwrap()
            .keep();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([name.as_str(), "--exact", "--test-threads=1", "--nocapture"])
            .env(ISOLATED, &name);
        let bytes = command_output(
            command,
            &isolation,
            "isolated-test",
            Duration::from_secs(300),
        );
        assert!(
            String::from_utf8_lossy(&bytes).contains("1 passed; 0 failed;"),
            "isolated body must actually execute"
        );
        return;
    }
    let result = reverie::process::Container::new()
        .unshare(reverie::process::Namespace::USER | reverie::process::Namespace::MOUNT)
        .map_root()
        .run(|| {
            // Required namespace/ptrace/process_vm facilities fail normally;
            // there is no EPERM/ENOSYS early return or capability skip.
            let fixtures = Fixtures::build();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                go_controls(&fixtures).await;
                server_controls(&fixtures).await;
                retirement_controls(&fixtures).await;
            });
            true
        });
    assert_eq!(
        result,
        Ok(true),
        "real namespaced physical controls must all execute"
    );
}
