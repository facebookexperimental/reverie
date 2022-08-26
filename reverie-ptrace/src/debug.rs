/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 * Copyright (c) 2020-, Meta Platforms, Inc. and affiliates.
 *
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

//! convenient functions for debugging tracees

use core::fmt;

use nix::sys::ptrace;
use nix::sys::signal;
use reverie::syscalls::Addr;
use reverie::syscalls::MemoryAccess;
use reverie::Pid;
use safeptrace::Stopped;
use tracing::debug;

// TODO: could check whether or not stack is valid
fn show_stackframe(tid: Pid, stack: u64, top_size: usize, bot_size: usize) -> String {
    let mut text = String::new();
    if stack < top_size as u64 {
        return text;
    }
    let sp_top = stack - top_size as u64;
    let sp_bot = stack + bot_size as u64;
    let mut sp = sp_top;

    while sp <= sp_bot {
        match ptrace::read(tid.into(), sp as ptrace::AddressType) {
            Err(_) => break,
            Ok(x) => {
                if sp == stack {
                    text += &format!(" => {:12x}: {:16x}\n", sp, x);
                } else {
                    text += &format!("    {:12x}: {:16x}\n", sp, x);
                }
            }
        }
        sp += 8;
    }
    text
}

fn show_user_regs(regs: &libc::user_regs_struct) -> String {
    let mut res = String::new();

    res += &format!(
        "rax {:16x} rbx {:16x} rcx {:16x} rdx {:16x}\n",
        regs.rax, regs.rbx, regs.rcx, regs.rdx
    );
    res += &format!(
        "rsi {:16x} rdi {:16x} rbp {:16x} rsp {:16x}\n",
        regs.rsi, regs.rdi, regs.rbp, regs.rsp
    );
    res += &format!(
        " r8 {:16x}  r9 {:16x} r10 {:16x} r11 {:16x}\n",
        regs.r8, regs.r9, regs.r10, regs.r11
    );
    res += &format!(
        "r12 {:16x} r13 {:16x} r14 {:16x} r15 {:16x}\n",
        regs.r12, regs.r13, regs.r14, regs.r15
    );
    res += &format!("rip {:16x} eflags {:16x}\n", regs.rip, regs.eflags);
    res += &format!(
        "cs {:x} ss {:x} ds {:x} es {:x}\nfs {:x} gs {:x}",
        regs.cs, regs.ss, regs.ds, regs.es, regs.fs, regs.gs
    );
    res
}

fn show_proc_maps(maps: &procfs::process::MemoryMap) -> String {
    use procfs::process::MMapPath;
    let mut res = String::new();
    let fp = match &maps.pathname {
        MMapPath::Path(path) => String::from(path.to_str().unwrap_or("")),
        MMapPath::Vdso => String::from("[vdso]"),
        MMapPath::Vvar => String::from("[vvar]"),
        MMapPath::Vsyscall => String::from("[vsyscall]"),
        MMapPath::Stack => String::from("[stack]"),
        MMapPath::Other(s) => s.clone(),
        _ => String::from(""),
    };
    let s = format!(
        "{:x}-{:x} {} {:08x} {:02x}:{:02x} {}",
        maps.address.0, maps.address.1, maps.perms, maps.offset, maps.dev.0, maps.dev.1, maps.inode
    );
    res.push_str(&s);
    (0..=72 - s.len()).for_each(|_| res.push(' '));
    res.push_str(&fp);
    res
}

fn task_rip_is_valid(pid: Pid, rip: u64) -> bool {
    let mut has_valid_rip = None;
    if let Ok(mapping) = procfs::process::Process::new(pid.as_raw()).and_then(|p| p.maps()) {
        has_valid_rip = mapping
            .iter()
            .find(|e| e.perms.contains('x') && e.address.0 <= rip && e.address.1 > rip + 0x10)
            .cloned();
    }
    has_valid_rip.is_some()
}

// XXX: should limit nb calls to procfs.
/// show task fault context
pub fn show_fault_context(task: &Stopped, sig: signal::Signal) {
    let regs = task.getregs().unwrap();
    let siginfo = task.getsiginfo().unwrap();
    debug!(
        "{:?} got {:?} si_errno: {}, si_code: {}, regs\n{}",
        task,
        sig,
        siginfo.si_errno,
        siginfo.si_code,
        show_user_regs(&regs)
    );

    debug!(
        "stackframe from rsp@{:x}\n{}",
        regs.rsp,
        show_stackframe(task.pid(), regs.rsp, 0x40, 0x80)
    );

    if task_rip_is_valid(task.pid(), regs.rip) {
        if let Some(addr) = Addr::from_raw(regs.rip as usize) {
            let mut buf: [u8; 16] = [0; 16];
            if task.read_exact(addr, &mut buf).is_ok() {
                debug!("insn @{:x?} = {:02x?}", addr, buf);
            }
        }
    } else {
        debug!("insn @{:x?} = <invalid rip>", regs.rip);
    }

    procfs::process::Process::new(task.pid().as_raw())
        .and_then(|p| p.maps())
        .unwrap_or_else(|_| Vec::new())
        .iter()
        .for_each(|e| {
            debug!("{}", show_proc_maps(e));
        });
}

/// As a debugging aid, dump the current state of the guest in a readbale format.
/// If an optional snapshot of an earlier register state is provided, the results
/// will be printed a DIFF from that previous state.
pub fn log_guest_state(context_msg: &str, tid: Pid, old_regs: &Option<libc::user_regs_struct>) {
    // TODO: could certainly derive this "diffing" functionality as a macro if
    // there is a library for that.
    let hdr = format!("{}: guest state (tid {}) has ...", context_msg, tid);
    let cur = ptrace::getregs(tid.into()).unwrap();
    match old_regs {
        None => debug!("{} regs = {:?}", hdr, cur),
        Some(old) => {
            let mut msg = String::from("   DIFF in regs from prev (new/old): ");
            let len1 = msg.len();
            if cur.r15 != old.r15 {
                msg.push_str(&format!("r15: {}/{}  ", cur.r15, old.r15));
            }
            if cur.r14 != old.r14 {
                msg.push_str(&format!("r14: {}/{}  ", cur.r14, old.r14));
            }
            if cur.r13 != old.r13 {
                msg.push_str(&format!("r13: {}/{}  ", cur.r13, old.r13));
            }
            if cur.r12 != old.r12 {
                msg.push_str(&format!("r12: {}/{}  ", cur.r12, old.r12));
            }
            if cur.rbp != old.rbp {
                msg.push_str(&format!("rbp: {}/{}  ", cur.rbp, old.rbp));
            }
            if cur.rbx != old.rbx {
                msg.push_str(&format!("rbx: {}/{}  ", cur.rbx, old.rbx));
            }
            if cur.r11 != old.r11 {
                msg.push_str(&format!("r11: {}/{}  ", cur.r11, old.r11));
            }
            if cur.r10 != old.r10 {
                msg.push_str(&format!("r10: {}/{}  ", cur.r10, old.r10));
            }
            if cur.r9 != old.r9 {
                msg.push_str(&format!("r9: {}/{}  ", cur.r9, old.r9));
            }
            if cur.r8 != old.r8 {
                msg.push_str(&format!("r8: {}/{}  ", cur.r8, old.r8));
            }
            if cur.rax != old.rax {
                msg.push_str(&format!("rax: {}/{}  ", cur.rax, old.rax));
            }
            if cur.rcx != old.rcx {
                msg.push_str(&format!("rcx: {}/{}  ", cur.rcx, old.rcx));
            }
            if cur.rdx != old.rdx {
                msg.push_str(&format!("rdx: {}/{}  ", cur.rdx, old.rdx));
            }
            if cur.rsi != old.rsi {
                msg.push_str(&format!("rsi: {}/{}  ", cur.rsi, old.rsi));
            }
            if cur.rdi != old.rdi {
                msg.push_str(&format!("rdi: {}/{}  ", cur.rdi, old.rdi));
            }
            if cur.orig_rax != old.orig_rax {
                msg.push_str(&format!("orig_rax: {}/{}  ", cur.orig_rax, old.orig_rax));
            }
            if cur.rip != old.rip {
                msg.push_str(&format!("rip: {}/{}  ", cur.rip, old.rip));
            }
            if cur.cs != old.cs {
                msg.push_str(&format!("cs: {}/{}  ", cur.cs, old.cs));
            }
            if cur.eflags != old.eflags {
                msg.push_str(&format!("eflags: {}/{}  ", cur.eflags, old.eflags));
            }
            if cur.rsp != old.rsp {
                msg.push_str(&format!("rsp: {}/{}  ", cur.rsp, old.rsp));
            }
            if cur.ss != old.ss {
                msg.push_str(&format!("ss: {}/{}  ", cur.ss, old.ss));
            }
            if cur.fs_base != old.fs_base {
                msg.push_str(&format!("fs_base: {}/{}  ", cur.fs_base, old.fs_base));
            }
            if cur.gs_base != old.gs_base {
                msg.push_str(&format!("gs_base: {}/{}  ", cur.gs_base, old.gs_base));
            }
            if cur.ds != old.ds {
                msg.push_str(&format!("ds: {}/{}  ", cur.ds, old.ds));
            }
            if cur.es != old.es {
                msg.push_str(&format!("es: {}/{}  ", cur.es, old.es));
            }
            if cur.fs != old.fs {
                msg.push_str(&format!("fs: {}/{}  ", cur.fs, old.fs));
            }
            if cur.gs != old.gs {
                msg.push_str(&format!("gs: {}/{}  ", cur.gs, old.gs));
            }
            if msg.len() == len1 {
                debug!("{} NO differences from prev register state.", hdr)
            } else {
                debug!("{} {}", hdr, msg);
            }
        }
    }
}
