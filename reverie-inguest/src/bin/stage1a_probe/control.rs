/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Bytewise host side of the test ABI: no borrowed reference into memory a
//! running child can change, and no transmute of Rust struct padding.

use std::fs::File;
use std::io::Read;
use std::mem::offset_of;
use std::os::unix::fs::FileExt;

use safeptrace::Regs;
use serde_json::Value;
use serde_json::json;

use super::Result;
use super::protocol::*;

pub fn initialize(
    file: &File,
    regs: &Regs,
    mask: u64,
    runtime: u64,
    fds: &[i32],
) -> Result<[u64; 2]> {
    if fds.len() > 8 || fds.iter().any(|fd| *fd <= 2) {
        return Err("loader refused: invalid inherited bootstrap descriptor set".into());
    }
    let mut page = [0_u8; CONTROL_BYTES];
    let put64 = |page: &mut [u8], offset, value: u64| {
        page[offset..offset + 8].copy_from_slice(&value.to_le_bytes())
    };
    let put32 = |page: &mut [u8], offset, value: u32| {
        page[offset..offset + 4].copy_from_slice(&value.to_le_bytes())
    };
    let mut nonce_bytes = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut nonce_bytes)?;
    let nonce = [
        u64::from_le_bytes(nonce_bytes[..8].try_into()?),
        u64::from_le_bytes(nonce_bytes[8..].try_into()?),
    ];
    macro_rules! put {
        ($name:ident, $value:expr) => {
            put64(&mut page, offset_of!(ProbeControlV1, $name), $value);
        };
    }
    put!(magic, CONTROL_MAGIC);
    put32(
        &mut page,
        offset_of!(ProbeControlV1, abi_version),
        ABI_VERSION,
    );
    put32(
        &mut page,
        offset_of!(ProbeControlV1, bytes),
        CONTROL_BYTES as u32,
    );
    page[offset_of!(ProbeControlV1, nonce)..offset_of!(ProbeControlV1, nonce) + 16]
        .copy_from_slice(&nonce_bytes);
    put!(runtime_entry, runtime);
    put!(guest_rip, regs.rip);
    put!(guest_rsp, regs.rsp);
    put!(guest_fs, regs.fs_base);
    put!(guest_gs, regs.gs_base);
    put!(guest_sigmask, mask);
    put!(runtime_stack_lo, STACK_BOTTOM);
    put!(runtime_stack_hi, STACK_TOP);
    put!(altstack_lo, ALTSTACK_BOTTOM);
    put!(altstack_hi, ALTSTACK_TOP);
    put!(journal_base, JOURNAL_ADDRESS);
    put!(journal_capacity, EVENT_CAPACITY);
    put32(
        &mut page,
        offset_of!(ProbeControlV1, fd_count),
        fds.len() as u32,
    );
    for index in 0..8 {
        put32(
            &mut page,
            offset_of!(ProbeControlV1, fds) + index * 4,
            fds.get(index).copied().unwrap_or(-1) as u32,
        );
    }
    file.write_all_at(&page, 0)?;
    Ok(nonce)
}

pub fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or("short control record")?
            .try_into()?,
    ))
}

pub fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("short control record")?
            .try_into()?,
    ))
}

pub fn page(file: &File) -> Result<[u8; CONTROL_BYTES]> {
    let mut page = [0; CONTROL_BYTES];
    file.read_exact_at(&mut page, 0)?;
    Ok(page)
}

pub fn ready(file: &File, nonce: [u64; 2]) -> Result<u64> {
    let page = page(file)?;
    let phase = u32_at(&page, offset_of!(ProbeControlV1, phase))?;
    let error = u32_at(&page, offset_of!(ProbeControlV1, error))?;
    let controls = u64_at(&page, offset_of!(ProbeControlV1, controls))?;
    let ready_nonce = [
        u64_at(&page, offset_of!(ProbeControlV1, ready_nonce))?,
        u64_at(&page, offset_of!(ProbeControlV1, ready_nonce) + 8)?,
    ];
    if phase != PHASE_TEST_CONTROLS_READY
        || error != ERROR_NONE
        || controls != REQUIRED_CONTROLS
        || ready_nonce != nonce
    {
        return Err(format!("loader refused: incomplete test-runtime readiness (phase={phase}, error={error}, controls={controls:#x})").into());
    }
    let (events, _) = events(file)?;
    if events
        .iter()
        .any(|e| e["flags"].as_u64().unwrap_or(0) & FLAG_GUEST as u64 != 0)
    {
        return Err("loader refused: guest event before release".into());
    }
    let self_test = |kind: u32| {
        events
            .iter()
            .filter(move |event| event["kind"] == kind && event["flags"] == FLAG_SELF_TEST)
    };
    if !self_test(EVENT_CPUID).any(|event| {
        event["nr_or_opcode"] == MAGIC_CPUID_LEAF && event["results"] == json!(CPUID_REPLY)
    }) || !self_test(EVENT_RDTSC).any(|event| event["results"][0] == TSC_REPLY)
        || !self_test(EVENT_RDTSCP)
            .any(|event| event["results"][0] == TSC_REPLY && event["results"][1] == TSC_AUX_REPLY)
    {
        return Err("loader refused: missing CPUID/RDTSC/RDTSCP interception evidence".into());
    }
    let entered = self_test(EVENT_SYSCALL_ENTER).any(|event| {
        event["nr_or_opcode"] == libc::SYS_gettid && event["ip"] == LOADER_GETTID_POST_IP
    });
    let returned = self_test(EVENT_SYSCALL_RETURN).any(|event| {
        event["nr_or_opcode"] == libc::SYS_gettid
            && event["ip"] == LOADER_GETTID_POST_IP
            && event["results"][0]
                .as_u64()
                .is_some_and(|tid| tid > 0 && tid <= i32::MAX as u64)
    });
    if !entered || !returned {
        return Err("loader refused: missing trapped-syscall entry/return evidence".into());
    }
    Ok(controls)
}

pub fn events(file: &File) -> Result<(Vec<Value>, Value)> {
    let page = page(file)?;
    let reserved = u64_at(&page, offset_of!(ProbeControlV1, events_reserved))?;
    let committed = u64_at(&page, offset_of!(ProbeControlV1, events_committed))?;
    let overflow = u64_at(&page, offset_of!(ProbeControlV1, overflow))?;
    if reserved != committed || committed > EVENT_CAPACITY || overflow != 0 {
        return Err(format!("loader refused: incomplete journal (reserved={reserved}, committed={committed}, overflow={overflow})").into());
    }
    let mut events = Vec::with_capacity(committed as usize);
    for index in 0..committed {
        let mut bytes = [0; EVENT_BYTES];
        file.read_exact_at(
            &mut bytes,
            CONTROL_BYTES as u64 + index * EVENT_BYTES as u64,
        )?;
        let seq = u64_at(&bytes, offset_of!(ProbeEventV1, seq))?;
        let commit = u64_at(&bytes, offset_of!(ProbeEventV1, commit))?;
        if seq != index || commit != index + 1 {
            return Err(
                format!("loader refused: journal slot {index} not committed in order").into(),
            );
        }
        let args = (0..6)
            .map(|n| u64_at(&bytes, offset_of!(ProbeEventV1, args) + n * 8))
            .collect::<Result<Vec<_>>>()?;
        let results = (0..4)
            .map(|n| u64_at(&bytes, offset_of!(ProbeEventV1, results) + n * 8))
            .collect::<Result<Vec<_>>>()?;
        events.push(json!({
            "seq":seq, "commit":commit,
            "kind":u32_at(&bytes, offset_of!(ProbeEventV1, kind))?,
            "flags":u32_at(&bytes, offset_of!(ProbeEventV1, flags))?,
            "ip":u64_at(&bytes, offset_of!(ProbeEventV1, ip))?,
            "sp":u64_at(&bytes, offset_of!(ProbeEventV1, sp))?,
            "nr_or_opcode":u64_at(&bytes, offset_of!(ProbeEventV1, nr_or_opcode))?,
            "args":args, "results":results,
        }));
    }
    Ok((
        events,
        json!({
            "runtime_phase":u32_at(&page, offset_of!(ProbeControlV1, phase))?,
            "runtime_error":u32_at(&page, offset_of!(ProbeControlV1, error))?,
            "controls":u64_at(&page, offset_of!(ProbeControlV1, controls))?,
            "events_reserved":reserved, "events_committed":committed, "overflow":overflow,
        }),
    ))
}

/// Shared observations are writable, but cannot resize. They are not image
/// authority and are never mapped executable. The child closes this FD before
/// guest entry; the parent retains it to read the complete record after exit.
pub fn observation_file(length: u64) -> Result<File> {
    let file = File::from(nix::sys::memfd::memfd_create(
        c"reverie-stage1a-observations",
        nix::sys::memfd::MFdFlags::MFD_CLOEXEC | nix::sys::memfd::MFdFlags::MFD_ALLOW_SEALING,
    )?);
    file.set_len(length)?;
    nix::fcntl::fcntl(
        &file,
        nix::fcntl::FcntlArg::F_ADD_SEALS(
            nix::fcntl::SealFlag::F_SEAL_GROW
                | nix::fcntl::SealFlag::F_SEAL_SHRINK
                | nix::fcntl::SealFlag::F_SEAL_SEAL,
        ),
    )?;
    Ok(file)
}
