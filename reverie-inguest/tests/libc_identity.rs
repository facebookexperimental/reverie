/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `record_libc_identity` must find the C library the process actually runs
//! on, which the loader chooses by `DT_SONAME`, not by file name, and must
//! find it without running code the program can substitute. Each case re-runs
//! this test binary with `LD_PRELOAD` arranging the libraries; the re-run
//! process records the identity, checks that the C library's own signal
//! restorer is accepted and that recording left the C library's heap as it
//! was, and reports which file it actually runs the C library from and which
//! of the preloaded files it mapped, so a preload the loader ignored cannot
//! pass for one it used.
//!
//! - the process's own C library;
//! - a copy of it named `libc-custom.so` (the loader uses it as the C library);
//! - that copy and an unrelated library named `helper/libc.so.6`;
//! - a preloaded `dl_iterate_phdr` that allocates and delegates;
//! - a preloaded `dl_iterate_phdr` that reports a fake C library (an object
//!   named `libc.so.6` with `DT_SONAME` `libc.so.6` whose code is its own) and
//!   hides the real one;
//! - a preloaded `sysconf` that allocates and delegates (the run also takes
//!   the page size and binds an in-guest branch counter, the other start-up
//!   steps that once asked `sysconf`);
//! - a second copy of the C library loaded into a `dlmopen` namespace;
//! - an executable alias mapping of the C library's file.
//!
//! The report also counts the executable mappings of the C library's file,
//! so the last two cases prove their setup took effect.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

const CHILD: &str = "REVERIE_TEST_LIBC_IDENTITY_CHILD";
/// What the re-run process sets up first: `dlmopen:<library>` or
/// `alias:<file>`.
const SETUP: &str = "REVERIE_TEST_LIBC_IDENTITY_SETUP";
const TEST: &str = "libc_identity_follows_the_loader_not_file_names_or_interposers";

extern "C" fn ignore(_signal: libc::c_int) {}

/// The file and identity of the mapping containing `address`, from
/// `/proc/self/maps`.
fn mapping_file(address: u64) -> Option<(String, String)> {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    maps.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (start, end) = fields.first()?.split_once('-')?;
        let range = u64::from_str_radix(start, 16).ok()?..u64::from_str_radix(end, 16).ok()?;
        (range.contains(&address) && fields.len() >= 6)
            .then(|| (fields[5].to_owned(), format!("{} {}", fields[3], fields[4])))
    })
}

/// The restorer glibc's `sigaction` installs: an address in the C library the
/// process actually runs.
fn glibc_restorer() -> u64 {
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = ignore as *const () as usize;
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR1, &action, core::ptr::null_mut()) },
        0
    );
    let mut installed = reverie_inguest::signal::KernelSigaction::default();
    unsafe { reverie_inguest::signal::raw_sigaction(libc::SIGUSR1, None, Some(&mut installed)) }
        .unwrap();
    installed.restorer
}

/// In the re-run process: set up, record the identity and report.
fn child_report() {
    match std::env::var(SETUP)
        .ok()
        .as_deref()
        .and_then(|setup| setup.split_once(':'))
    {
        Some(("dlmopen", library)) => {
            let library = std::ffi::CString::new(library).unwrap();
            let handle =
                unsafe { libc::dlmopen(libc::LM_ID_NEWLM, library.as_ptr(), libc::RTLD_NOW) };
            assert!(!handle.is_null(), "dlmopen failed");
        }
        Some(("alias", file)) => {
            let file = std::fs::File::open(file).unwrap();
            let length = file.metadata().unwrap().len() as usize;
            let alias = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    length,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_PRIVATE,
                    std::os::fd::AsRawFd::as_raw_fd(&file),
                    0,
                )
            };
            assert_ne!(alias, libc::MAP_FAILED);
        }
        Some(other) => panic!("unknown setup {other:?}"),
        None => {}
    }
    // How often a preloaded wrapper ran, counted around the start-up steps.
    let counter = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"reverie_test_interposer_calls".as_ptr(),
        )
    }
    .cast::<u32>();
    let calls = || {
        if counter.is_null() {
            0
        } else {
            unsafe { counter.read_volatile() }
        }
    };
    let calls_before = calls();
    // SAFETY: mallinfo2 only reads the allocator's statistics.
    let before = unsafe { libc::mallinfo2() };
    let recorded = reverie_inguest::guest::restorer::record_libc_identity();
    let after = unsafe { libc::mallinfo2() };
    let heap_unchanged = (before.arena, before.uordblks, before.hblkhd)
        == (after.arena, after.uordblks, after.hblkhd);
    // The other start-up steps that asked sysconf. Their own Rust allocations
    // use this test binary's ordinary allocator, so the heap is not compared
    // across them; the wrapper's call count is.
    reverie_inguest::guest::support::page_size().unwrap();
    // The branch counter exists only with the rcb-clock feature; every other
    // case runs without it.
    #[cfg(feature = "rcb-clock")]
    reverie_inguest::guest::clock::initialize_rcb_clock().unwrap();
    let interposer_calls = calls() - calls_before;
    let restorer = glibc_restorer();
    let accepted = unsafe { reverie_inguest::guest::restorer::glibc_restorer_accepted(restorer) };
    let (libc_file, libc_identity) = mapping_file(restorer).unwrap_or_default();
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let preloaded = std::env::var("LD_PRELOAD").unwrap_or_default();
    let mapped = preloaded
        .split(' ')
        .filter(|path| !path.is_empty())
        .map(|path| maps.contains(path))
        .collect::<Vec<_>>();
    // Executable mappings of the C library's file (device and inode).
    let libc_executable_mappings = maps
        .lines()
        .filter(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            fields.len() >= 5
                && fields[1].as_bytes().get(2) == Some(&b'x')
                && format!("{} {}", fields[3], fields[4]) == libc_identity
        })
        .count();
    let recorded = match recorded {
        Ok(()) => "recorded".to_owned(),
        Err(error) => format!("refused ({error})"),
    };
    println!(
        "identity: {recorded} accepted={accepted} heap_unchanged={heap_unchanged} \
         interposer_calls={interposer_calls} preloads_mapped={mapped:?} \
         libc_executable_mappings={libc_executable_mappings} libc_file={libc_file}"
    );
}

fn run_child(preload: &[&Path]) -> String {
    run_child_with(preload, None)
}

fn run_child_with(preload: &[&Path], setup: Option<String>) -> String {
    let preload = preload
        .iter()
        .map(|path| path.to_str().unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .env("LD_PRELOAD", &preload)
        // One malloc arena, so mallinfo2 (which reports the main arena)
        // sees allocations made on the harness's test thread too.
        .env("MALLOC_ARENA_MAX", "1")
        .env(SETUP, setup.unwrap_or_default())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(output.status.success(), "LD_PRELOAD={preload}: {output:?}");
    // The harness prints the report after the test's name, on its line.
    stdout
        .lines()
        .find_map(|line| {
            line.find("identity: ")
                .map(|start| line[start..].to_owned())
        })
        .unwrap_or_else(|| panic!("LD_PRELOAD={preload}: no report in {stdout}"))
}

fn compile_library(source: &str, library: &Path) {
    let source_path = library.with_extension("c");
    std::fs::write(&source_path, source).unwrap();
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let output = Command::new(compiler)
        .args(["-O2", "-Wall", "-Werror", "-shared", "-fPIC", "-o"])
        .arg(library)
        .arg(&source_path)
        .arg("-ldl")
        .output()
        .expect("failed to run the C compiler");
    assert!(output.status.success(), "{output:?}");
}

/// Allocates through the C library's malloc on every call, then delegates.
const ALLOCATING_WRAPPER: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdlib.h>
typedef int (*callback_t)(struct dl_phdr_info *, size_t, void *);
/* Exported, so the compiler cannot drop the allocations as unused. */
void *reverie_test_kept[64];
unsigned reverie_test_interposer_calls;
int dl_iterate_phdr(callback_t callback, void *data) {
    reverie_test_kept[reverie_test_interposer_calls++ % 64] = malloc(4096);
    int (*real)(callback_t, void *) = (int (*)(callback_t, void *))dlsym(RTLD_NEXT, "dl_iterate_phdr");
    return real(callback, data);
}
"#;

/// Reports a fake C library first (named libc.so.6, DT_SONAME libc.so.6, its
/// executable segment this library's own code) and hides the real one.
const FAKE_IDENTITY_WRAPPER: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <string.h>
typedef int (*callback_t)(struct dl_phdr_info *, size_t, void *);
static struct {
    ElfW(Dyn) dyn[3];
    char strings[16];
} fake = {{{DT_STRTAB, {0}}, {DT_SONAME, {1}}, {DT_NULL, {0}}}, "\0libc.so.6"};
static ElfW(Phdr) headers[3];
void reverie_test_fake_libc_code(void) {}
unsigned reverie_test_interposer_calls;
struct relay {
    callback_t callback;
    void *data;
};
static int hide_libc(struct dl_phdr_info *info, size_t size, void *data) {
    struct relay *relay = data;
    if (info->dlpi_name != NULL && strstr(info->dlpi_name, "libc") != NULL) {
        return 0;
    }
    return relay->callback(info, size, relay->data);
}
int dl_iterate_phdr(callback_t callback, void *data) {
    reverie_test_interposer_calls++;
    fake.dyn[0].d_un.d_ptr = (ElfW(Addr))fake.strings;
    headers[0] = (ElfW(Phdr)){.p_type = PT_LOAD, .p_flags = PF_R | PF_X,
                              .p_vaddr = (ElfW(Addr))reverie_test_fake_libc_code, .p_memsz = 16};
    headers[1] = (ElfW(Phdr)){.p_type = PT_LOAD, .p_flags = PF_R,
                              .p_vaddr = (ElfW(Addr))&fake, .p_memsz = sizeof fake};
    headers[2] = (ElfW(Phdr)){.p_type = PT_DYNAMIC, .p_flags = PF_R,
                              .p_vaddr = (ElfW(Addr))fake.dyn, .p_memsz = sizeof fake.dyn};
    struct dl_phdr_info info;
    memset(&info, 0, sizeof info);
    info.dlpi_name = "/fake/libc.so.6";
    info.dlpi_phdr = headers;
    info.dlpi_phnum = 3;
    int result = callback(&info, sizeof info, data);
    if (result != 0) {
        return result;
    }
    int (*real)(callback_t, void *) = (int (*)(callback_t, void *))dlsym(RTLD_NEXT, "dl_iterate_phdr");
    struct relay relay = {callback, data};
    return real(hide_libc, &relay);
}
"#;

/// Allocates through the C library's malloc on every call, then delegates.
const ALLOCATING_SYSCONF: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
void *reverie_test_kept[64];
unsigned reverie_test_interposer_calls;
long sysconf(int name) {
    reverie_test_kept[reverie_test_interposer_calls++ % 64] = malloc(4096);
    long (*real)(int) = (long (*)(int))dlsym(RTLD_NEXT, "sysconf");
    return real(name);
}
"#;

#[test]
fn libc_identity_follows_the_loader_not_file_names_or_interposers() {
    if std::env::var_os(CHILD).is_some() {
        child_report();
        return;
    }
    // LD_PRELOAD separates entries with spaces and colons, so the copies must
    // live where neither appears; refuse rather than run cases the loader
    // would silently ignore.
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("libc-identity-{}", std::process::id()));
    let spelled = directory.to_str().expect("a UTF-8 scratch path");
    assert!(
        !spelled.contains([' ', ':', '\t', '\n']),
        "LD_PRELOAD cannot name files under {spelled}"
    );
    struct RemoveOnDrop(PathBuf);
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = RemoveOnDrop(directory.clone());
    std::fs::create_dir_all(directory.join("helper")).unwrap();

    // The C library this process runs: the file whose code holds glibc's
    // restorer, whatever it is named.
    let (libc, _) = mapping_file(glibc_restorer()).expect("the restorer is in a file mapping");
    // Any other shared library this process maps, with a DT_SONAME of its own.
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let other = maps
        .lines()
        .filter_map(|line| line.split_whitespace().nth(5))
        .find(|path| {
            path.starts_with('/')
                && *path != libc
                && path.contains(".so")
                && !Path::new(path)
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("ld-"))
        })
        .expect("this process maps another shared library")
        .to_owned();
    let renamed = directory.join("libc-custom.so");
    std::fs::copy(&libc, &renamed).unwrap();
    let impostor = directory.join("helper/libc.so.6");
    std::fs::copy(&other, &impostor).unwrap();
    let allocating = directory.join("allocating-dl-iterate-phdr.so");
    compile_library(ALLOCATING_WRAPPER, &allocating);
    let fake = directory.join("fake-libc-dl-iterate-phdr.so");
    compile_library(FAKE_IDENTITY_WRAPPER, &fake);
    let sysconf = directory.join("allocating-sysconf.so");
    compile_library(ALLOCATING_SYSCONF, &sysconf);

    let expect_mappings = |preloads: &str, mappings: usize, file: &dyn std::fmt::Display| {
        format!(
            "identity: recorded accepted=true heap_unchanged=true interposer_calls=0 \
             preloads_mapped={preloads} libc_executable_mappings={mappings} libc_file={file}"
        )
    };
    let expect = |preloads: &str, file: &dyn std::fmt::Display| expect_mappings(preloads, 1, file);
    assert_eq!(run_child(&[]), expect("[]", &libc));
    assert_eq!(
        run_child(&[&renamed]),
        expect("[true]", &renamed.display()),
        "copy of {libc}"
    );
    assert_eq!(
        run_child(&[&renamed, &impostor]),
        expect("[true, true]", &renamed.display()),
        "impostor is a copy of {other}"
    );
    assert_eq!(run_child(&[&allocating]), expect("[true]", &libc));
    assert_eq!(run_child(&[&fake]), expect("[true]", &libc));
    assert_eq!(run_child(&[&sysconf]), expect("[true]", &libc));
    assert_eq!(
        run_child_with(&[], Some(format!("dlmopen:{other}"))),
        expect_mappings("[]", 2, &libc),
        "a copy of {libc} in a dlmopen namespace"
    );
    assert_eq!(
        run_child_with(&[], Some(format!("alias:{libc}"))),
        expect_mappings("[]", 2, &libc),
        "an executable alias of {libc}"
    );
}
