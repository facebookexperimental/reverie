//! Execute the production x86 wrappers and Rust child-return helpers against a
//! scratch continuation, displaced instruction, and full red-zone sentinel.

#![cfg(target_arch = "x86_64")]

use std::ffi::CString;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie_sabre::ffi;

static NEXT: AtomicUsize = AtomicUsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());

type Router = unsafe extern "C" fn(i32, *mut libc::c_void, *mut u64) -> libc::c_long;
type Probe = unsafe extern "C" fn(i32, i32, libc::c_ulong, Option<Router>) -> i32;

struct Library {
    handle: *mut libc::c_void,
    run: Probe,
}

impl Library {
    fn build() -> Self {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture = manifest.join("tests/fixtures/syscall_frame");
        let vendor = manifest.join("vendor/sabre");
        let output = std::env::temp_dir().join(format!(
            "reverie-sabre-frame-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&output).expect("create private ABI fixture directory");
        let library = output.join("frame_probe.so");
        let mut command = Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()));
        command.args([
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-omit-frame-pointer",
            "-fPIC",
            "-shared",
            "-Wl,-Bsymbolic",
            "-Wl,-z,defs",
            "-DFRAME_PROBE_LIBRARY",
        ]);
        command.arg("-I").arg(&fixture);
        command.arg("-I").arg(vendor.join("includes"));
        command.arg("-I").arg(vendor.join("includes/arch"));
        for file in [
            fixture.join("frame_probe.c"),
            fixture.join("frame_probe.S"),
            vendor.join("arch/x86_64/handle_syscall.S"),
            vendor.join("arch/x86_64/handle_syscall_loader.s"),
            vendor.join("arch/x86_64/syscall_stackframe.c"),
            vendor.join("plugin_api/arch/x86_64/vfork_return_from_child.s"),
            manifest.join("src/ffi/recursion_protector.c"),
        ] {
            command.arg(file);
        }
        command.arg("-o").arg(&library);
        let result = command
            .output()
            .expect("compile actual SaBRe frame producers");
        std::fs::write(output.join("compile.stdout"), &result.stdout).unwrap();
        std::fs::write(output.join("compile.stderr"), &result.stderr).unwrap();
        eprintln!("ABI fixture retained at {}", output.display());
        assert!(result.status.success(), "{command:?}: {result:?}");
        let path = CString::new(library.as_os_str().as_encoded_bytes()).unwrap();
        unsafe {
            let handle = libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
            assert!(!handle.is_null(), "load compiled ABI fixture");
            let symbol = libc::dlsym(handle, c"frame_probe_run".as_ptr());
            assert!(!symbol.is_null(), "resolve ABI fixture entry");
            Self {
                handle,
                run: std::mem::transmute::<*mut libc::c_void, Probe>(symbol),
            }
        }
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            libc::dlclose(self.handle);
        }
    }
}

unsafe extern "C" fn route(mode: i32, raw: *mut libc::c_void, output: *mut u64) -> libc::c_long {
    let frame = &*raw.cast::<ffi::syscall_stackframe>();
    // The C fixture obtains its return through the actual C accessor. These
    // independently observed Rust fields must name the same live frame slots.
    *output.add(32) = frame.ret as u64;
    *output.add(33) = frame.fake_ret as u64;
    *output.add(34) = raw as u64 + std::mem::size_of::<ffi::syscall_stackframe>() as u64 + 0x80;
    match mode {
        0 => 0x55,
        1 => ffi::fork_syscall(
            libc::SIGCHLD as usize,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            frame,
            usize::MAX as u64,
        ) as libc::c_long,
        2 => ffi::vfork_return_from_child(frame),
        _ => libc::_exit(97),
    }
}

fn exercise(mode: i32) {
    // A forked child exits inside the C fixture after writing its fixed-size
    // capture; only the original parent returns to libtest. No broad wait or
    // process cleanup domain is adopted, even under concurrent cargo test.
    let _guard = SERIAL.lock().unwrap();
    let fixture = Library::build();
    for loader in [0, 1] {
        for flags in [0x647, 0xa96] {
            let result = unsafe { (fixture.run)(mode, loader, flags, Some(route)) };
            assert_eq!(result, 0, "mode={mode}, loader={loader}, flags={flags:#x}");
        }
    }
}

#[test]
fn rust_frame_matches_both_actual_wrapper_entries() {
    exercise(0);
}

#[test]
fn fork_child_runs_scratch_and_preserves_flags_stack_and_red_zone() {
    exercise(1);
}

#[test]
fn vfork_return_restores_the_same_actual_frame() {
    exercise(2);
}
