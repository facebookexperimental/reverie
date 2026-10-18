//! Physical ownership for the ordinary preload's early auxv write.
//!
//! This is part of the existing preload launcher. It creates no Tool or RPC
//! server and owns no deterministic policy. Every claimed completion is joined
//! to the child that launcher actually spawned, before the interpreter runs.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use goblin::elf::Elf;
use goblin::elf::header as elf_header;
use goblin::elf::program_header as ph;
use sha2::Digest;
use sha2::Sha256;
use tokio::io::unix::AsyncFd;

use super::*;

const PAGE: u64 = 4096;
const MAX_ELF: usize = 16 * 1024 * 1024;
const SEED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/initial-auxv-seed.elf"));

/// Tool-prepared bytes and the consuming completion callback. Constructing
/// this input does not assert that any process or memory write exists.
pub struct PendingWrite {
    expected_image: PathBuf,
    bytes: [u8; 16],
    complete: Box<dyn FnOnce(CompletedWrite) -> io::Result<Vec<u8>> + Send>,
}

impl PendingWrite {
    /// Retain Tool policy until the launcher observes the actual write.
    /// `expected_image` is the caller's already-resolved actual ELF, including
    /// kernel-script resolution. It does not replace the original command.
    pub fn new(
        expected_image: PathBuf,
        bytes: [u8; 16],
        complete: impl FnOnce(CompletedWrite) -> io::Result<Vec<u8>> + Send + 'static,
    ) -> Self {
        Self {
            expected_image,
            bytes,
            complete: Box::new(complete),
        }
    }
}

// The ordinary main executable is not subject to the loader's image-size
// bound. Only the ELF header, program headers and PT_INTERP are captured; at
// ACK its actual /proc/PID/exe is joined to this held inode and exact headers.
// Linux's active executable write exclusion is the ordinary exec premise,
// rather than a claim that opening a read-only descriptor freezes a file.
struct MainImage {
    file: File,
    metadata: std::fs::Metadata,
    headers: MainHeaders,
}

#[derive(PartialEq, Eq)]
struct MainHeaders {
    elf: [u8; 64],
    programs: Vec<u8>,
    interpreter: Vec<u8>,
}

fn same_main_metadata(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.is_file()
        && b.is_file()
        && a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mode() == b.mode()
        && a.nlink() == b.nlink()
        && file_stamp(a) == file_stamp(b)
}

fn main_headers(file: &File, length: u64) -> io::Result<MainHeaders> {
    let read = |offset: u64, size: usize| -> io::Result<Vec<u8>> {
        if offset
            .checked_add(size as u64)
            .is_none_or(|end| end > length)
        {
            return Err(invalid("initial auxv main ELF header range exceeds file"));
        }
        let mut bytes = vec![0; size];
        file.read_exact_at(&mut bytes, offset)?;
        Ok(bytes)
    };
    let header: [u8; 64] = read(0, 64)?.try_into().unwrap();
    let word = |at: usize| u16::from_le_bytes([header[at], header[at + 1]]);
    if &header[..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || !matches!(word(16), elf_header::ET_EXEC | elf_header::ET_DYN)
        || word(18) != elf_header::EM_X86_64
        || header[20..24] != 1_u32.to_le_bytes()
        || word(52) != 64
        || word(54) != 56
        || word(56) == 0
        || word(56) > 32
    {
        return Err(invalid(
            "initial auxv main requires bounded Linux x86-64 ELF headers",
        ));
    }
    let offset = u64_at(&header, 32)?;
    if offset > 65536 {
        return Err(invalid(
            "initial auxv main program-header offset exceeds bound",
        ));
    }
    let programs = read(offset, usize::from(word(56)) * 56)?;
    let mut interpreter = None;
    for program in programs.as_chunks::<56>().0 {
        if u32::from_le_bytes(program[..4].try_into().unwrap()) != ph::PT_INTERP {
            continue;
        }
        let size = u64_at(program, 32)?;
        if interpreter.is_some() || !(2..=4096).contains(&size) {
            return Err(invalid(
                "initial auxv main interpreter is duplicated or exceeds bound",
            ));
        }
        let bytes = read(u64_at(program, 8)?, size as usize)?;
        if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
            return Err(invalid("initial auxv main interpreter path is malformed"));
        }
        interpreter = Some(bytes);
    }
    Ok(MainHeaders {
        elf: header,
        programs,
        interpreter: interpreter
            .ok_or_else(|| invalid("initial auxv requires a dynamic initial image"))?,
    })
}

impl MainImage {
    fn open(path: &Path) -> io::Result<Self> {
        // A pathname can be replaced between admission and open. Nonblocking
        // open lets the regular-file check refuse a FIFO instead of waiting
        // for a writer; it has no effect on the admitted regular file.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(invalid("initial auxv main image is not a regular file"));
        }
        let headers = main_headers(&file, metadata.len())?;
        if !same_main_metadata(&metadata, &file.metadata()?) {
            return Err(invalid("initial auxv main image changed during capture"));
        }
        Ok(Self {
            file,
            metadata,
            headers,
        })
    }

    fn verify(&self, actual: &File) -> io::Result<()> {
        let before = actual.metadata()?;
        let flags = unsafe { libc::fcntl(actual.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || flags & libc::O_ACCMODE != libc::O_RDONLY
            || !same_main_metadata(&self.metadata, &self.file.metadata()?)
            || !same_main_metadata(&self.metadata, &before)
            || self.headers != main_headers(actual, before.len())?
            || !same_main_metadata(&self.metadata, &actual.metadata()?)
            || !same_main_metadata(&self.metadata, &self.file.metadata()?)
        {
            return Err(invalid(
                "initial auxv child executable or original stack differs",
            ));
        }
        Ok(())
    }
}

// This is a finite authenticated handoff snapshot, not permanent inode
// immutability: the original file retains ordinary kernel-loader mutation
// semantics after transfer. Its open descriptor pins identity, not content.
struct Held {
    file: File,
    bytes: Vec<u8>,
    device: u64,
    // The VMA's kernel device need not equal the descriptor's stat device.
    // Capture it from a real mapping of this exact retained file description.
    map_device: u64,
    inode: u64,
    stamp: (i64, i64, i64, i64),
}

fn file_stamp(metadata: &std::fs::Metadata) -> (i64, i64, i64, i64) {
    (
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

impl Held {
    fn open(path: &Path) -> io::Result<Self> {
        // A pathname can be replaced between admission and open. Nonblocking
        // open lets the regular-file check refuse a FIFO instead of waiting
        // for a writer; it has no effect on the admitted regular file.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(path)?;
        let before = file.metadata()?;
        if !before.is_file() || before.len() > MAX_ELF as u64 {
            return Err(invalid("initial auxv ELF is not a bounded regular file"));
        }
        let mut bytes = Vec::new();
        (&file).take(MAX_ELF as u64 + 1).read_to_end(&mut bytes)?;
        let map_device = original_mapping_device(&file, before.ino())?;
        let after = file.metadata()?;
        if bytes.len() as u64 != before.len()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(invalid("initial auxv ELF changed during capture"));
        }
        Ok(Self {
            file,
            bytes,
            device: before.dev(),
            map_device,
            inode: before.ino(),
            stamp: file_stamp(&before),
        })
    }

    fn verify(&self, file: &File) -> io::Result<()> {
        let before = file.metadata()?;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || flags & libc::O_ACCMODE != libc::O_RDONLY
            || !before.is_file()
            || before.dev() != self.device
            || before.ino() != self.inode
            || before.len() != self.bytes.len() as u64
            || file_stamp(&before) != self.stamp
        {
            return Err(invalid(
                "initial auxv held file identity or read-only access changed",
            ));
        }
        let mut actual = vec![0; self.bytes.len()];
        file.read_exact_at(&mut actual, 0)?;
        let after = file.metadata()?;
        if after.dev() != self.device
            || after.ino() != self.inode
            || after.len() != before.len()
            || file_stamp(&after) != self.stamp
            || actual != self.bytes
        {
            return Err(invalid("initial auxv held file content changed"));
        }
        Ok(())
    }
}

// Tokio 1.53.1 (the consumer lock) lacks register. Keep compatibility through
// new, but accept only this uniquely owned, stable descriptor, never generic
// AsRawFd values whose descriptor could close or change during registration.
#[allow(deprecated)]
fn register_owned(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    AsyncFd::new(fd)
}

fn seal(name: &std::ffi::CStr, bytes: &[u8]) -> io::Result<File> {
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn elf(bytes: &[u8]) -> io::Result<Elf<'_>> {
    let elf = Elf::parse(bytes).map_err(|_| invalid("initial auxv ELF is malformed"))?;
    if !elf.is_64
        || !elf.little_endian
        || elf.header.e_machine != elf_header::EM_X86_64
        || elf.header.e_phnum > 32
        || elf.header.e_phoff > 65536
        || elf.header.e_phentsize != 56
    {
        return Err(invalid("initial auxv requires a bounded Linux x86-64 ELF"));
    }
    Ok(elf)
}

fn loader_span(bytes: &[u8]) -> io::Result<(u64, u64)> {
    let elf = elf(bytes)?;
    if elf.header.e_type != elf_header::ET_DYN || elf.interpreter.is_some() {
        return Err(invalid(
            "initial auxv requires a dynamic system interpreter",
        ));
    }
    let mut end = 0;
    let mut alignment = PAGE;
    let mut entry = false;
    let mut first = true;
    for load in elf
        .program_headers
        .iter()
        .filter(|load| load.p_type == ph::PT_LOAD)
    {
        let lo = load.p_vaddr & !(PAGE - 1);
        let hi = load
            .p_vaddr
            .checked_add(load.p_memsz)
            .and_then(|v| v.checked_add(PAGE - 1))
            .map(|v| v & !(PAGE - 1))
            .ok_or_else(|| invalid("initial auxv loader span overflows"))?;
        let file_end = load
            .p_offset
            .checked_add(load.p_filesz)
            .ok_or_else(|| invalid("initial auxv loader file span overflows"))?;
        if (first && lo != 0)
            || lo < end
            || hi <= lo
            || hi > MAX_ELF as u64
            || load.p_filesz > load.p_memsz
            || file_end > bytes.len() as u64
            || load.p_vaddr % PAGE != load.p_offset % PAGE
            || load.p_flags & (ph::PF_W | ph::PF_X) == ph::PF_W | ph::PF_X
            || (load.p_align > 1
                && (!load.p_align.is_power_of_two()
                    || load.p_vaddr % load.p_align != load.p_offset % load.p_align))
        {
            return Err(invalid("initial auxv loader mapping is unsupported"));
        }
        entry |= load.p_flags & ph::PF_X != 0
            && elf.entry >= load.p_vaddr
            && elf.entry < load.p_vaddr + load.p_filesz;
        alignment = alignment.max(load.p_align);
        end = hi;
        first = false;
    }
    if first || !entry || alignment > MAX_ELF as u64 {
        return Err(invalid(
            "initial auxv loader has no qualified entry or span",
        ));
    }
    Ok((end, alignment))
}

// Only the source-built seed's final writable PT_LOAD reservation is adapted
// to the held loader. No code, pointer, entry or requested callback is patched.
fn qualify_seed(image: &Elf<'_>) -> io::Result<()> {
    // This deliberately has no PT_DYNAMIC, so dynamic relocation iterators
    // alone miss a compiler's allocated .rela.dyn section. Inspect section
    // types too, including the ELF ABI's packed relative relocation type.
    const SHT_RELR: u32 = 19;
    if image.header.e_type != elf_header::ET_DYN
        || image.interpreter.is_some()
        || !image.libraries.is_empty()
        || !image.dynrelas.is_empty()
        || !image.dynrels.is_empty()
        || !image.pltrelocs.is_empty()
        || image.section_headers.iter().any(|section| {
            section.sh_size != 0
                && matches!(
                    section.sh_type,
                    goblin::elf::section_header::SHT_REL
                        | goblin::elf::section_header::SHT_RELA
                        | SHT_RELR
                )
        })
        || image.syms.iter().any(|s| s.st_shndx == 0 && s.st_name != 0)
        || image
            .dynsyms
            .iter()
            .any(|s| s.st_shndx == 0 && s.st_name != 0)
    {
        return Err(invalid("compiled initial auxv seed is not relocation-free"));
    }
    Ok(())
}

fn seed_for_loader(span: u64, alignment: u64) -> io::Result<Vec<u8>> {
    let image = elf(SEED)?;
    qualify_seed(&image)?;
    let loads = image
        .program_headers
        .iter()
        .enumerate()
        .filter(|(_, p)| p.p_type == ph::PT_LOAD)
        .collect::<Vec<_>>();
    let Some((last_index, last)) = loads.last().copied() else {
        return Err(invalid("compiled initial auxv seed has no load extent"));
    };
    if loads[0].1.p_vaddr != 0
        || last.p_flags != (ph::PF_R | ph::PF_W)
        || last
            .p_vaddr
            .checked_add(last.p_memsz)
            .is_none_or(|end| end > span)
        || loads
            .iter()
            .any(|(_, p)| p.p_flags & (ph::PF_W | ph::PF_X) == ph::PF_W | ph::PF_X)
        || image.program_headers.iter().any(|p| p.p_type == ph::PT_TLS)
    {
        return Err(invalid(
            "compiled initial auxv seed does not fit the held loader",
        ));
    }
    let mut bytes = SEED.to_vec();
    let offset = image.header.e_phoff as usize + last_index * 56;
    put_u64(&mut bytes, offset + 40, span - last.p_vaddr);
    // The kernel uses the maximum PT_LOAD alignment to choose the same kind
    // of interpreter bias as it would for the retained stock interpreter.
    for (index, _) in loads {
        let offset = image.header.e_phoff as usize + index * 56;
        put_u64(&mut bytes, offset + 48, alignment);
    }
    Ok(bytes)
}

struct ChildInputs {
    loader: File,
    packet: File,
    channel: OwnedFd,
    _seed: File,
    _seed_path: tempfile::TempPath,
    interpreter: CString,
    seed_path: CString,
}

/// Prepared physical launch, still unable to claim a completed write.
pub(crate) struct Prepared {
    input: Arc<ChildInputs>,
    channel: OwnedFd,
    main: MainImage,
    loader: Held,
    seed_bytes: Vec<u8>,
    pending: PendingWrite,
    token: Token,
}

impl Prepared {
    pub(crate) fn prepare(config: &[u8], pending: PendingWrite) -> io::Result<Self> {
        // The command may be a kernel script. Its resolved ELF comes from the
        // existing Tool policy; this mechanism does not parse scripts or alter
        // the executable/argv that the kernel will receive.
        let main = MainImage::open(&pending.expected_image)?;
        let interpreter = Path::new(std::ffi::OsStr::from_bytes(
            &main.headers.interpreter[..main.headers.interpreter.len() - 1],
        ))
        .canonicalize()?;
        let loader = Held::open(&interpreter)?;
        let (span, alignment) = loader_span(&loader.bytes)?;
        let seed_bytes = seed_for_loader(span, alignment)?;
        // Linux cannot bind-mount an anonymous memfd (EINVAL). Keep a linked
        // private regular inode through exec, close its writable description,
        // and authenticate the bound inode against its read-only descriptor.
        // The owner checks the actual relocated RX bytes before allowing
        // transfer. This is not a seal or
        // a promise against a hostile process with the coordinator's authority.
        let mut seed_file = tempfile::Builder::new()
            .prefix("reverie-initial-auxv-")
            .tempfile_in("/tmp")?;
        seed_file.write_all(&seed_bytes)?;
        seed_file
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o500))?;
        let seed_path_owner = seed_file.into_temp_path();
        let seed = File::open(&seed_path_owner)?;
        // Map the original file so the loader keeps its kernel file identity.
        // Captured bytes remain the independent handoff readback oracle.
        let held_loader = loader.file.try_clone()?;
        loader.verify(&held_loader)?;
        let mut nonce = [0; 32];
        if unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) }
            != nonce.len() as isize
        {
            return Err(io::Error::last_os_error());
        }
        let token = Token {
            nonce,
            config: Sha256::digest(config).into(),
        };
        let interpreter = CString::new(interpreter.as_os_str().as_bytes())
            .map_err(|_| invalid("initial auxv interpreter contains NUL"))?;
        let path = interpreter.as_bytes_with_nul();
        if path.len() > 4096 {
            return Err(invalid("initial auxv interpreter path exceeds bound"));
        }
        let mut packet = vec![0; 128 + path.len()];
        header(&mut packet, PENDING_MAGIC, token);
        packet[80..96].copy_from_slice(&pending.bytes);
        let metadata = held_loader.metadata()?;
        put_u64(&mut packet, 96, metadata.dev());
        put_u64(&mut packet, 104, metadata.ino());
        put_u64(&mut packet, 112, metadata.len());
        packet[120..122].copy_from_slice(&(path.len() as u16).to_le_bytes());
        packet[128..].copy_from_slice(path);
        let packet = seal(c"reverie-initial-auxv-input", &packet)?;
        let mut fds = [-1; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let channel = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let child_channel = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let enabled: i32 = 1;
        if unsafe {
            libc::setsockopt(
                channel.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&enabled as *const i32).cast(),
                4,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // Resolve the linked source through the child's new mount namespace.
        // A /proc/self/fd path would retain the parent's mount object and
        // Linux rejects that cross-namespace bind with EINVAL.
        let seed_path = CString::new(seed_path_owner.as_os_str().as_bytes())
            .map_err(|_| invalid("initial auxv seed path contains NUL"))?;
        Ok(Self {
            input: Arc::new(ChildInputs {
                loader: held_loader,
                packet,
                channel: child_channel,
                _seed: seed,
                _seed_path: seed_path_owner,
                interpreter,
                seed_path,
            }),
            channel,
            main,
            loader,
            seed_bytes,
            pending,
            token,
        })
    }

    pub(crate) fn token(&self) -> Token {
        self.token
    }

    pub(crate) fn install(&self, command: &mut std::process::Command) -> io::Result<()> {
        let input = self.input.clone();
        // Child-only namespace setup. It never changes the coordinator's or
        // another run's interpreter, and invokes no post-fork allocator.
        unsafe {
            command.pre_exec(move || {
                for fd in [LOADER_FD, INPUT_FD, CHANNEL_FD] {
                    if libc::fcntl(fd, libc::F_GETFD) != -1
                        || io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
                    {
                        return Err(io::Error::from_raw_os_error(libc::EBUSY));
                    }
                }
                if libc::unshare(libc::CLONE_NEWNS) != 0
                    || libc::mount(
                        core::ptr::null(),
                        c"/".as_ptr(),
                        core::ptr::null(),
                        (libc::MS_REC | libc::MS_PRIVATE) as _,
                        core::ptr::null(),
                    ) != 0
                    || libc::mount(
                        input.seed_path.as_ptr(),
                        input.interpreter.as_ptr(),
                        core::ptr::null(),
                        libc::MS_BIND as _,
                        core::ptr::null(),
                    ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                // The path is only a way to perform the bind. Authenticate the
                // actual bound inode against the held source, before exec can
                // read it. No post-fork allocation or pathname-only trust.
                let bound =
                    libc::open(input.interpreter.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                if bound < 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut expected = core::mem::MaybeUninit::<libc::stat>::uninit();
                let mut actual = core::mem::MaybeUninit::<libc::stat>::uninit();
                if libc::fstat(input._seed.as_raw_fd(), expected.as_mut_ptr()) != 0
                    || libc::fstat(bound, actual.as_mut_ptr()) != 0
                {
                    let error = io::Error::last_os_error();
                    libc::close(bound);
                    return Err(error);
                }
                if libc::close(bound) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let expected = expected.assume_init();
                let actual = actual.assume_init();
                if expected.st_dev != actual.st_dev
                    || expected.st_ino != actual.st_ino
                    || expected.st_size != actual.st_size
                    || expected.st_mode != actual.st_mode
                {
                    return Err(io::Error::from_raw_os_error(libc::ESTALE));
                }
                for (source, target) in [
                    (input.loader.as_raw_fd(), LOADER_FD),
                    (input.packet.as_raw_fd(), INPUT_FD),
                    (input.channel.as_raw_fd(), CHANNEL_FD),
                ] {
                    if libc::dup3(source, target, 0) != target {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        Ok(())
    }

    pub(crate) fn serve(
        self,
        pid: u32,
        bootstrap: OwnedFd,
    ) -> io::Result<impl std::future::Future<Output = io::Result<()>>> {
        let pid = i32::try_from(pid).map_err(|_| invalid("initial auxv child pid overflows"))?;
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let birth = Birth {
            fd: unsafe { OwnedFd::from_raw_fd(fd as i32) },
            complete: false,
        };
        let inner = async move {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                self.exchange(pid, bootstrap),
            )
            .await;
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "initial auxv write or constructor redemption did not complete",
                )),
            }
        };
        Ok(Startup {
            birth,
            inner: Box::pin(inner),
        })
    }

    async fn exchange(self, pid: i32, bootstrap: OwnedFd) -> io::Result<()> {
        // The parent must not retain the child's endpoint: EOF is one of the
        // protocol's failure/completion observations.
        drop(self.input);
        let flags = unsafe { libc::fcntl(self.channel.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe {
                libc::fcntl(
                    self.channel.as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                )
            } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: this OwnedFd is private to AsyncFd for its whole lifetime;
        // no code closes or replaces the borrowed descriptor.
        let channel = register_owned(self.channel)?;
        let (write, sender) = receive(&channel).await?;
        if sender != Some(pid) || write.len() != 192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "initial auxv write did not come from the spawned child: expected pid {pid}, received pid {sender:?}, {} bytes",
                    write.len()
                ),
            ));
        }
        check_header(&write, WRITE_MAGIC, self.token)?;
        if u64_at(&write, 80)? != pid as u64
            || u64_at(&write, 88)? != pid as u64
            || u64_at(&write, 176)? != 16
            || u64_at(&write, 184)? != 0
            || write[160..176] != self.pending.bytes
        {
            return Err(invalid(
                "initial auxv write is partial or names another image",
            ));
        }
        let image = verify_write(pid, &write, &self.main, &self.loader, &self.seed_bytes)?;
        // Invoke policy only after the real readback and birth/ELF joins. The
        // consuming callback cannot be retried even when delivery later fails.
        let state = (self.pending.complete)(image)?;
        if state.is_empty() || state.len() > MAX_STATE {
            return Err(invalid(
                "completed initial auxv Tool input exceeds its bound",
            ));
        }
        let mut go = [0; 96];
        header(&mut go, GO_MAGIC, self.token);
        self.loader.verify(&self.loader.file)?;
        send(&channel, &go, Some(bootstrap.as_raw_fd())).await?;
        drop(bootstrap);
        let (take, sender) = receive(&channel).await?;
        if sender != Some(pid) || take.len() != 96 {
            return Err(invalid(
                "initial auxv constructor redemption is absent or from another child",
            ));
        }
        check_header(&take, TAKE_MAGIC, self.token)?;
        if u64_at(&take, 80)? != pid as u64
            || u64_at(&take, 88)? != 0
            || read_birth(pid)?.0 != image.start_time_ticks
        {
            return Err(invalid(
                "initial auxv constructor redemption is stale or duplicate",
            ));
        }
        let mut response = vec![0; 128 + state.len()];
        header(&mut response, STATE_MAGIC, self.token);
        put_u64(&mut response, 80, pid as u64);
        put_u64(&mut response, 88, image.start_time_ticks);
        put_u64(&mut response, 96, image.target as u64);
        put_u64(&mut response, 104, 16);
        response[112..128].copy_from_slice(&image.bytes);
        response[128..].copy_from_slice(&state);
        send(&channel, &response, None).await?;
        let (end, sender) = receive(&channel).await?;
        if !end.is_empty() || sender.is_some() {
            return Err(invalid(
                "initial auxv completion was redeemed more than once",
            ));
        }
        Ok(())
    }
}

// An async block's capture destruction order is not a cancellation protocol.
// This owner sends SIGKILL through the held pidfd before dropping the inner
// future, even when it was never polled or holds an in-progress exchange.
struct Startup<F> {
    birth: Birth,
    inner: std::pin::Pin<Box<F>>,
}

impl<F: std::future::Future<Output = io::Result<()>>> std::future::Future for Startup<F> {
    type Output = io::Result<()>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        let result = this.inner.as_mut().poll(cx);
        if matches!(&result, std::task::Poll::Ready(Ok(()))) {
            this.birth.release();
        }
        result
    }
}

impl<F> Drop for Startup<F> {
    fn drop(&mut self) {
        self.birth.cancel();
    }
}

struct Birth {
    fd: OwnedFd,
    complete: bool,
}

impl Birth {
    fn release(&mut self) {
        self.complete = true;
    }

    fn cancel(&mut self) {
        if !self.complete {
            self.complete = true;
            // Never address a recycled numeric pid. A failed or cancelled
            // startup addresses only this held child. Startup orders cancellation
            // before dropping the still-pending protocol future.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.fd.as_raw_fd(),
                    libc::SIGKILL,
                    core::ptr::null::<u8>(),
                    0,
                );
            }
        }
    }
}

impl Drop for Birth {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn bounded(path: impl AsRef<Path>, maximum: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(invalid("initial auxv observation exceeds bound"));
    }
    Ok(bytes)
}

fn read_birth(pid: i32) -> io::Result<(u64, usize)> {
    let bytes = bounded(format!("/proc/{pid}/stat"), 4096)?;
    parse_birth(pid, &bytes)
}

fn parse_birth(pid: i32, bytes: &[u8]) -> io::Result<(u64, usize)> {
    // Linux comm is an arbitrary byte sequence and may end partway through a
    // UTF-8 character at TASK_COMM_LEN. Only the numeric columns are text.
    let close = bytes
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or_else(|| invalid("initial auxv stat is incomplete"))?;
    let (prefix, rest) = (&bytes[..close], &bytes[close + 1..]);
    if prefix
        .split(|byte| *byte == b' ')
        .next()
        .and_then(|n| std::str::from_utf8(n).ok())
        .and_then(|n| n.parse::<i32>().ok())
        != Some(pid)
    {
        return Err(invalid("initial auxv stat pid differs"));
    }
    let fields = rest
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let value = |i: usize| {
        fields
            .get(i)
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| invalid("initial auxv stat field is absent"))
    };
    // Field 3 begins `rest`: starttime is field 22; startstack is field 28.
    let birth = value(19)?;
    let stack = value(25)?;
    if birth == 0 || stack == 0 {
        return Err(invalid("initial auxv birth or stack is zero"));
    }
    Ok((birth, stack as usize))
}

fn remote(pid: i32, address: usize, bytes: &mut [u8]) -> io::Result<()> {
    if address == 0 || address.checked_add(bytes.len()).is_none() {
        return Err(invalid("initial auxv remote range overflows"));
    }
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let other = libc::iovec {
        iov_base: address as *mut _,
        iov_len: bytes.len(),
    };
    let count = unsafe { libc::process_vm_readv(pid, &local, 1, &other, 1, 0) };
    if count != bytes.len() as isize {
        return Err(invalid("initial auxv physical readback was incomplete"));
    }
    Ok(())
}

fn stack_auxv(
    pid: i32,
    rsp: usize,
    target: usize,
    expected: &[u8],
    claimed: usize,
    base_slot: usize,
) -> io::Result<()> {
    let maps = bounded(format!("/proc/{pid}/maps"), 65536)?;
    let mut stack = None;
    for mut row in maps
        .strip_suffix(b"\n")
        .unwrap_or(&maps)
        .split(|byte| *byte == b'\n')
    {
        let range = map_field(&mut row).and_then(|r| r.split_once('-'));
        if let Some((lo, hi)) = range {
            let lo = usize::from_str_radix(lo, 16)
                .map_err(|_| invalid("initial auxv map start is malformed"))?;
            let hi = usize::from_str_radix(hi, 16)
                .map_err(|_| invalid("initial auxv map end is malformed"))?;
            if lo <= rsp
                && rsp < hi
                && (map_field(&mut row) != Some("rw-p") || stack.replace((lo, hi)).is_some())
            {
                return Err(invalid(
                    "initial auxv stack is not one private readable writable mapping",
                ));
            }
        }
    }
    let (_, top) = stack.ok_or_else(|| invalid("initial auxv original stack mapping is absent"))?;
    let word = |address: usize| -> io::Result<usize> {
        if address < rsp || address.checked_add(8).is_none_or(|end| end > top) {
            return Err(invalid("initial auxv stack table exceeds its mapping"));
        }
        let mut bytes = [0; 8];
        remote(pid, address, &mut bytes)?;
        Ok(u64::from_ne_bytes(bytes) as usize)
    };
    let argc = word(rsp)?;
    if argc > 256 {
        return Err(invalid("initial auxv argc exceeds bound"));
    }
    let mut at = rsp + 8;
    for _ in 0..argc {
        if word(at)? == 0 {
            return Err(invalid("initial auxv argv ends early"));
        }
        at += 8;
    }
    if word(at)? != 0 {
        return Err(invalid("initial auxv argv has no terminator"));
    }
    at += 8;
    let mut terminated = false;
    for _ in 0..=4096 {
        let value = word(at)?;
        at += 8;
        if value == 0 {
            terminated = true;
            break;
        }
    }
    if !terminated || at != claimed {
        return Err(invalid("initial auxv vector location differs"));
    }
    let mut actual = Vec::new();
    let mut found_base = None;
    terminated = false;
    for _ in 0..64 {
        let key = word(at)? as u64;
        let value = word(at + 8)? as u64;
        actual.extend_from_slice(&key.to_ne_bytes());
        actual.extend_from_slice(&value.to_ne_bytes());
        if key == libc::AT_BASE && found_base.replace(at + 8).is_some() {
            return Err(invalid("initial auxv contains duplicate interpreter bases"));
        }
        at += 16;
        if key == libc::AT_NULL {
            terminated = value == 0;
            break;
        }
    }
    if !terminated
        || found_base != Some(base_slot)
        || expected.get(..actual.len()) != Some(actual.as_slice())
        || expected
            .get(actual.len()..)
            .is_none_or(|tail| tail.iter().any(|b| *b != 0))
        || target < at
        || target.checked_add(16).is_none_or(|end| end > top)
    {
        return Err(invalid(
            "initial auxv stack differs from the kernel table or target extent",
        ));
    }
    Ok(())
}

fn map_field<'a>(row: &mut &'a [u8]) -> Option<&'a str> {
    *row = row.trim_ascii_start();
    let end = row
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(row.len());
    let field = &row[..end];
    *row = &row[end..];
    // Decode only maps' ASCII header fields, leaving pathname bytes intact.
    (!field.is_empty() && field.is_ascii())
        .then(|| std::str::from_utf8(field).expect("ASCII map field"))
}

fn mapped_path(file: &File) -> io::Result<Vec<u8>> {
    let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    // maps escapes newline in a pathname; spaces are actual pathname bytes.
    let path = path.as_os_str().as_bytes();
    let mut expected_path = Vec::new();
    for byte in path {
        if *byte == b'\n' {
            expected_path.extend_from_slice(b"\\012");
        } else {
            expected_path.push(*byte);
        }
    }
    Ok(expected_path)
}

struct ReadOnlyFileMapping(*mut libc::c_void);

impl Drop for ReadOnlyFileMapping {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns the exact PAGE mapping returned by
        // mmap below, and never exposes ownership or unmaps it elsewhere.
        unsafe { libc::munmap(self.0, PAGE as usize) };
    }
}

fn original_mapping_device(file: &File, inode: u64) -> io::Result<u64> {
    // SAFETY: request a fresh private read-only mapping from the retained FD,
    // never a caller-selected address. No mapped byte is dereferenced, so this
    // observation neither executes code nor reads beyond a short file's EOF.
    let address = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            PAGE as usize,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if address == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let mapping = ReadOnlyFileMapping(address);
    let start = mapping.0 as usize as u64;
    let end = start
        .checked_add(PAGE)
        .ok_or_else(|| invalid("initial auxv original mapping range overflows"))?;
    let expected_path = mapped_path(file)?;
    let bytes = bounded("/proc/self/maps", 65536)?;
    let mut found = None;
    for mut row in bytes
        .strip_suffix(b"\n")
        .unwrap_or(&bytes)
        .split(|byte| *byte == b'\n')
    {
        let (lo, hi) = map_field(&mut row)
            .and_then(|v| v.split_once('-'))
            .ok_or_else(|| invalid("initial auxv original map range is malformed"))?;
        let lo = u64::from_str_radix(lo, 16)
            .map_err(|_| invalid("initial auxv original map start is malformed"))?;
        let hi = u64::from_str_radix(hi, 16)
            .map_err(|_| invalid("initial auxv original map end is malformed"))?;
        if lo >= hi {
            return Err(invalid("initial auxv original map range is empty"));
        }
        if hi <= start || lo >= end {
            continue;
        }
        let perms = map_field(&mut row);
        let offset = map_field(&mut row).and_then(|v| u64::from_str_radix(v, 16).ok());
        let device = map_field(&mut row)
            .and_then(|v| v.split_once(':'))
            .and_then(|(major, minor)| {
                Some(libc::makedev(
                    u32::from_str_radix(major, 16).ok()?,
                    u32::from_str_radix(minor, 16).ok()?,
                ))
            });
        let actual_inode = map_field(&mut row).and_then(|v| v.parse::<u64>().ok());
        if lo > start
            || hi < end
            || perms != Some("r--p")
            || offset.and_then(|v| v.checked_add(start - lo)) != Some(0)
            || actual_inode != Some(inode)
            || row.trim_ascii_start() != expected_path
            || found.is_some()
        {
            return Err(invalid(
                "initial auxv original mapping differs from the retained file",
            ));
        }
        found =
            Some(device.ok_or_else(|| invalid("initial auxv original map device is malformed"))?);
    }
    found.ok_or_else(|| invalid("initial auxv original file mapping is absent"))
}

fn verify_loader_maps(maps: &[u8], loader: &Held, base: u64) -> io::Result<()> {
    let expected_path = mapped_path(&loader.file)?;
    let image = elf(&loader.bytes)?;
    for load in image
        .program_headers
        .iter()
        .filter(|p| p.p_type == ph::PT_LOAD && p.p_filesz != 0)
    {
        let start = base
            .checked_add(load.p_vaddr & !(PAGE - 1))
            .ok_or_else(|| invalid("initial auxv map address overflows"))?;
        let end = base
            .checked_add(load.p_vaddr)
            .and_then(|v| v.checked_add(load.p_filesz))
            .and_then(|v| v.checked_add(PAGE - 1))
            .map(|v| v & !(PAGE - 1))
            .ok_or_else(|| invalid("initial auxv map extent overflows"))?;
        let permissions = [
            if load.p_flags & ph::PF_R != 0 {
                b'r'
            } else {
                b'-'
            },
            if load.p_flags & ph::PF_W != 0 {
                b'w'
            } else {
                b'-'
            },
            if load.p_flags & ph::PF_X != 0 {
                b'x'
            } else {
                b'-'
            },
            b'p',
        ];
        let mut cursor = start;
        for mut row in maps
            .strip_suffix(b"\n")
            .unwrap_or(maps)
            .split(|byte| *byte == b'\n')
        {
            let Some((lo, hi)) = map_field(&mut row).and_then(|v| v.split_once('-')) else {
                return Err(invalid("initial auxv loader map range is malformed"));
            };
            let lo = u64::from_str_radix(lo, 16)
                .map_err(|_| invalid("initial auxv map start is malformed"))?;
            let hi = u64::from_str_radix(hi, 16)
                .map_err(|_| invalid("initial auxv map end is malformed"))?;
            if lo >= hi {
                return Err(invalid("initial auxv loader map range is empty"));
            }
            if hi <= cursor || lo >= end {
                continue;
            }
            let perms = map_field(&mut row);
            let offset = map_field(&mut row).and_then(|v| u64::from_str_radix(v, 16).ok());
            let device = map_field(&mut row)
                .and_then(|v| v.split_once(':'))
                .and_then(|(major, minor)| {
                    Some(libc::makedev(
                        u32::from_str_radix(major, 16).ok()?,
                        u32::from_str_radix(minor, 16).ok()?,
                    ))
                });
            let inode = map_field(&mut row).and_then(|v| v.parse::<u64>().ok());
            let expected_offset = (load.p_offset & !(PAGE - 1)).checked_add(cursor - start);
            if lo > cursor
                || perms.map(str::as_bytes) != Some(permissions.as_slice())
                || device != Some(loader.map_device)
                || inode != Some(loader.inode)
                || offset.and_then(|v| v.checked_add(cursor - lo)) != expected_offset
                || row.trim_ascii_start() != expected_path
            {
                return Err(invalid(
                    "initial auxv loader mapping differs from original file backing",
                ));
            }
            cursor = hi.min(end);
            if cursor == end {
                break;
            }
        }
        if cursor != end {
            return Err(invalid(
                "initial auxv original loader file mapping is incomplete",
            ));
        }
    }
    Ok(())
}

fn verify_write(
    pid: i32,
    reply: &[u8],
    main: &MainImage,
    loader: &Held,
    seed: &[u8],
) -> io::Result<CompletedWrite> {
    let before = read_birth(pid)?;
    let exe = File::open(format!("/proc/{}/exe", pid))?;
    main.verify(&exe)?;
    if u64_at(reply, 96)? != before.1 as u64 {
        return Err(invalid(
            "initial auxv child executable or original stack differs",
        ));
    }
    let auxv = bounded(format!("/proc/{}/auxv", pid), 4096)?;
    if auxv.len() % 16 != 0 {
        return Err(invalid("initial auxv kernel table is partial"));
    }
    let mut target = None;
    let mut base = None;
    let mut end = false;
    for row in auxv.as_chunks::<16>().0 {
        let key = u64_at(row, 0)?;
        let value = u64_at(row, 8)?;
        if key == libc::AT_NULL {
            end = value == 0;
            break;
        }
        if (key == libc::AT_RANDOM && target.replace(value).is_some())
            || (key == libc::AT_BASE && base.replace(value).is_some())
        {
            return Err(invalid("initial auxv kernel table contains duplicate keys"));
        }
    }
    let target = target
        .filter(|p| *p != 0)
        .ok_or_else(|| invalid("initial auxv target is missing"))?;
    let base = base
        .filter(|p| *p != 0)
        .ok_or_else(|| invalid("initial auxv interpreter base is missing"))?;
    let (span, _) = loader_span(&loader.bytes)?;
    let loader_elf = elf(&loader.bytes)?;
    if !end
        || u64_at(reply, 112)? != target
        || u64_at(reply, 120)? != base
        || u64_at(reply, 128)?
            != base
                .checked_add(span)
                .ok_or_else(|| invalid("initial auxv loader extent overflows"))?
        || u64_at(reply, 136)? != base
        || u64_at(reply, 144)? != base + loader_elf.entry
    {
        return Err(invalid(
            "initial auxv loader or target differs from the actual kernel table",
        ));
    }
    stack_auxv(
        pid,
        before.1,
        target as usize,
        &auxv,
        u64_at(reply, 104)? as usize,
        u64_at(reply, 152)? as usize,
    )?;
    // Authenticate the original file around actual executable readback. An
    // open read-only FD does not promise permanent content immutability.
    loader.verify(&loader.file)?;
    let maps = bounded(format!("/proc/{}/maps", pid), 65536)?;
    verify_loader_maps(&maps, loader, base)?;
    // Verify executable source bytes in both the waiting bootstrap and the
    // held loader. Writable bootstrap state is intentionally not a code proof.
    for (file, bias) in [(seed, SCRATCH_BASE as u64), (loader.bytes.as_slice(), base)] {
        let image = elf(file)?;
        for load in image
            .program_headers
            .iter()
            .filter(|p| p.p_type == ph::PT_LOAD && p.p_flags & ph::PF_X != 0)
        {
            let offset = load.p_offset as usize;
            let size = load.p_filesz as usize;
            let source = file
                .get(
                    offset
                        ..offset
                            .checked_add(size)
                            .ok_or_else(|| invalid("initial auxv code span overflows"))?,
                )
                .ok_or_else(|| invalid("initial auxv source code is incomplete"))?;
            let mut actual = vec![0; size];
            remote(
                pid,
                bias.checked_add(load.p_vaddr)
                    .ok_or_else(|| invalid("initial auxv code address overflows"))?
                    as usize,
                &mut actual,
            )?;
            if source != actual {
                return Err(invalid(
                    "initial auxv executed mapping differs from qualified source",
                ));
            }
        }
    }
    loader.verify(&loader.file)?;
    let mut bytes = [0; 16];
    remote(pid, target as usize, &mut bytes)?;
    if bytes != reply[160..176] || read_birth(pid)? != before {
        return Err(invalid(
            "initial auxv write or birth changed during authentication",
        ));
    }
    Ok(CompletedWrite {
        pid,
        start_time_ticks: before.0,
        target: target as usize,
        bytes,
    })
}

async fn receive(channel: &AsyncFd<OwnedFd>) -> io::Result<(Vec<u8>, Option<i32>)> {
    loop {
        let mut ready = channel.readable().await?;
        match ready.try_io(|fd| {
            let mut bytes = vec![0; 128 + MAX_STATE];
            let mut control = [0_u64; 16];
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            let mut message: libc::msghdr = unsafe { core::mem::zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = core::mem::size_of_val(&control);
            let count = unsafe {
                libc::recvmsg(
                    fd.get_ref().as_raw_fd(),
                    &mut message,
                    libc::MSG_CMSG_CLOEXEC,
                )
            };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            // Consume every delivered descriptor even for a rejected packet.
            // MSG_CTRUNC closes excess rights in the kernel, but the rights
            // that fit the ancillary buffer are now owned by this process.
            let mut sender = None;
            let mut unexpected = false;
            unsafe {
                let mut item = libc::CMSG_FIRSTHDR(&message);
                while !item.is_null() {
                    if (*item).cmsg_level == libc::SOL_SOCKET
                        && (*item).cmsg_type == libc::SCM_RIGHTS
                    {
                        let header = libc::CMSG_LEN(0) as usize;
                        let length = (*item).cmsg_len.saturating_sub(header);
                        for index in 0..length / core::mem::size_of::<i32>() {
                            let received = *libc::CMSG_DATA(item).cast::<i32>().add(index);
                            drop(OwnedFd::from_raw_fd(received));
                        }
                        unexpected = true;
                    } else if (*item).cmsg_level == libc::SOL_SOCKET
                        && (*item).cmsg_type == libc::SCM_CREDENTIALS
                        && (*item).cmsg_len
                            == libc::CMSG_LEN(core::mem::size_of::<libc::ucred>() as _) as usize
                        && sender.is_none()
                    {
                        sender = Some((*libc::CMSG_DATA(item).cast::<libc::ucred>()).pid);
                    } else {
                        unexpected = true;
                    }
                    item = libc::CMSG_NXTHDR(&message, item);
                }
            }
            if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
                return Err(invalid("initial auxv packet was truncated"));
            }
            if unexpected {
                return Err(invalid("initial auxv packet has unexpected ancillary data"));
            }
            bytes.truncate(count as usize);
            Ok((bytes, sender))
        }) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

async fn send(channel: &AsyncFd<OwnedFd>, bytes: &[u8], descriptor: Option<i32>) -> io::Result<()> {
    loop {
        let mut ready = channel.writable().await?;
        match ready.try_io(|fd| {
            let mut iov = libc::iovec {
                iov_base: bytes.as_ptr().cast_mut().cast(),
                iov_len: bytes.len(),
            };
            let mut control = [0_u64; 3];
            let mut message: libc::msghdr = unsafe { core::mem::zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            if let Some(descriptor) = descriptor {
                unsafe {
                    message.msg_control = control.as_mut_ptr().cast();
                    message.msg_controllen = libc::CMSG_SPACE(4) as usize;
                    let item = libc::CMSG_FIRSTHDR(&message);
                    (*item).cmsg_level = libc::SOL_SOCKET;
                    (*item).cmsg_type = libc::SCM_RIGHTS;
                    (*item).cmsg_len = libc::CMSG_LEN(4) as usize;
                    *libc::CMSG_DATA(item).cast::<i32>() = descriptor;
                }
            }
            let count =
                unsafe { libc::sendmsg(fd.get_ref().as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            if count as usize != bytes.len() {
                return Err(invalid("initial auxv packet send was partial"));
            }
            Ok(())
        }) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests;
