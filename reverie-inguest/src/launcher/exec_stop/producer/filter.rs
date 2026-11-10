// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! Proof that the installed filter traps every syscall of a runtime image
//! except its gate's own.
//!
//! The filter the physical preparation installs compares only the
//! architecture, the syscall number and the two instruction-pointer words, and
//! only for equality. For such a program the verdict depends only on which of
//! the program's own constants each loaded word equals. Evaluating it on every
//! combination of those constants, plus one value equal to none of them,
//! therefore yields its complete ALLOW set. The evaluator refuses any other
//! instruction, so the decision is never partial.
//!
//! Against that set the proof requires:
//! - a foreign architecture is never allowed;
//! - every allowed instruction pointer is a specific address inside the gate
//!   page (no "any address" allowance);
//! - the instruction pointer after every declared site traps, for every
//!   syscall number;
//! - so every `0f 05` pair of the image, decoded or inside another
//!   instruction, traps unless it ends at an allowed address in the gate page.

use std::collections::BTreeSet;
use std::ops::Range;

use super::super::Result;
use super::require;

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const RET_K: u16 = 0x06;
const ALLOW: u32 = 0x7fff_0000;
const ARCH: u32 = 4;
const NR: u32 = 0;
const IP_LOW: u32 = 8;
const IP_HIGH: u32 = 12;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

#[derive(Clone, Copy)]
struct Instruction {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

fn decode(program: &[u8]) -> Result<Vec<Instruction>> {
    require(
        !program.is_empty() && program.len().is_multiple_of(8),
        "filter proof: program is not whole instructions",
    )?;
    let instructions: Vec<Instruction> = program
        .as_chunks::<8>()
        .0
        .iter()
        .map(|raw| Instruction {
            code: u16::from_le_bytes([raw[0], raw[1]]),
            jt: raw[2],
            jf: raw[3],
            k: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
        })
        .collect();
    for (at, instruction) in instructions.iter().enumerate() {
        match instruction.code {
            LD_W_ABS => require(
                [NR, ARCH, IP_LOW, IP_HIGH].contains(&instruction.k),
                "filter proof: load of a field other than nr, arch or ip",
            )?,
            JEQ_K => require(
                at + 1 + usize::from(instruction.jt.max(instruction.jf)) < instructions.len(),
                "filter proof: jump past the program",
            )?,
            RET_K => {}
            _ => return Err("filter proof: instruction other than ld, jeq or ret".into()),
        }
    }
    require(
        instructions.last().map(|last| last.code) == Some(RET_K),
        "filter proof: program does not end in ret",
    )?;
    Ok(instructions)
}

fn run(program: &[Instruction], arch: u32, nr: u32, ip: u64) -> Result<u32> {
    let mut accumulator = 0;
    let mut pc = 0;
    while let Some(instruction) = program.get(pc) {
        match instruction.code {
            LD_W_ABS => {
                accumulator = match instruction.k {
                    NR => nr,
                    ARCH => arch,
                    IP_LOW => ip as u32,
                    _ => (ip >> 32) as u32,
                }
            }
            JEQ_K => {
                pc += usize::from(if accumulator == instruction.k {
                    instruction.jt
                } else {
                    instruction.jf
                });
            }
            _ => return Ok(instruction.k),
        }
        pc += 1;
    }
    Err("filter proof: program fell off its end".into())
}

/// The syscall numbers the filter allows at one instruction pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllowedNumbers {
    /// Every number except these.
    AllExcept(Vec<u32>),
    /// Only these numbers.
    Only(Vec<u32>),
}

/// What the filter proof established for one image.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FilterCoverage {
    /// Every instruction pointer the filter allows, with its numbers: the
    /// filter's complete ALLOW set, in address order.
    pub allowed: Vec<(u64, AllowedNumbers)>,
    /// Byte-wise `0f 05` pairs in the executable pages, at any alignment.
    pub encodings: u64,
    /// Of those, the pairs whose following address traps for every number.
    pub trapped_encodings: u64,
    /// Declared sites whose following address traps for every number.
    pub trapped_declared_sites: u64,
}

/// Prove `program` (canonical 8-byte `sock_filter` instructions) against the
/// image's executable `runs`, its `gate` page and its `declared` sites.
pub(super) fn prove(
    program: &[u8],
    runs: &[super::Run],
    gate: &Range<u64>,
    declared: &[u64],
) -> Result<FilterCoverage> {
    let instructions = decode(program)?;
    let mut constants: BTreeSet<u32> = instructions
        .iter()
        .filter(|instruction| instruction.code == JEQ_K)
        .map(|instruction| instruction.k)
        .collect();
    // One value equal to no constant stands for every such value.
    let other = (0..=u32::MAX)
        .find(|value| !constants.contains(value))
        .ok_or("filter proof: no free value")?;
    constants.insert(other);
    for &nr in &constants {
        for &high in &constants {
            for &low in &constants {
                let ip = (u64::from(high) << 32) | u64::from(low);
                require(
                    run(&instructions, other ^ AUDIT_ARCH_X86_64 ^ 1, nr, ip)? != ALLOW
                        || other ^ AUDIT_ARCH_X86_64 ^ 1 == AUDIT_ARCH_X86_64,
                    "filter proof: a foreign architecture is allowed",
                )?;
            }
        }
    }
    let mut allowed: Vec<(u64, u32)> = Vec::new();
    for &nr in &constants {
        for &high in &constants {
            for &low in &constants {
                let ip = (u64::from(high) << 32) | u64::from(low);
                if run(&instructions, AUDIT_ARCH_X86_64, nr, ip)? != ALLOW {
                    continue;
                }
                require(
                    high != other && low != other,
                    "filter proof: an unspecific instruction pointer is allowed",
                )?;
                require(
                    gate.contains(&ip),
                    "filter proof: an allowed instruction pointer is outside the gate page",
                )?;
                allowed.push((ip, nr));
            }
        }
    }
    let mut coverage = FilterCoverage::default();
    let mut ips: Vec<u64> = allowed.iter().map(|&(ip, _)| ip).collect();
    ips.sort_unstable();
    ips.dedup();
    for ip in ips {
        let at: BTreeSet<u32> = allowed
            .iter()
            .filter(|&&(address, _)| address == ip)
            .map(|&(_, nr)| nr)
            .collect();
        let numbers = if at.contains(&other) {
            AllowedNumbers::AllExcept(
                constants
                    .iter()
                    .copied()
                    .filter(|nr| !at.contains(nr))
                    .collect(),
            )
        } else {
            AllowedNumbers::Only(at.into_iter().collect())
        };
        coverage.allowed.push((ip, numbers));
    }
    let allowed_at = |ip: u64| allowed.iter().any(|&(at, _)| at == ip);
    let declared: BTreeSet<u64> = declared.iter().copied().collect();
    for &site in &declared {
        let after = site.checked_add(2).ok_or("filter proof: site overflow")?;
        if allowed_at(after) {
            return Err(format!(
                "filter proof: declared site {site:#x} is not trapped by the filter"
            )
            .into());
        }
        coverage.trapped_declared_sites += 1;
    }
    for run in runs {
        let start = run.start;
        for (offset, pair) in run.bytes.windows(2).enumerate() {
            if pair != [0x0f, 0x05] {
                continue;
            }
            coverage.encodings += 1;
            let after = start + offset as u64 + 2;
            if allowed_at(after) {
                require(
                    gate.contains(&after),
                    "filter proof: an allowed encoding ends outside the gate page",
                )?;
            } else {
                coverage.trapped_encodings += 1;
            }
        }
    }
    Ok(coverage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp::SeccompFilter;
    use crate::seccomp::TrustedGate;

    const GATE: u64 = 0x6000_e100_1000;

    fn recipe(second: u64) -> Vec<u8> {
        SeccompFilter::for_trusted_gates_with_signal_return(
            TrustedGate {
                syscall_ip: GATE + 0x80,
                return_ip: GATE + 0x82,
            },
            TrustedGate {
                syscall_ip: second,
                return_ip: second + 2,
            },
            Some(GATE + 0x30b),
        )
        .unwrap()
        .canonical_bytes()
    }

    fn runs() -> Vec<super::super::Run> {
        let mut gate = vec![0xcc_u8; 4096];
        for at in [0x80, 0x200, 0x309] {
            gate[at..at + 2].copy_from_slice(&[0x0f, 0x05]);
        }
        let mut text = vec![0xcc_u8; 4096];
        // A decoded site at +0x10 and a pair inside `jne rel32` at +0x22.
        text[0x10..0x12].copy_from_slice(&[0x0f, 0x05]);
        text[0x20..0x26].copy_from_slice(&[0x0f, 0x85, 0x0f, 0x05, 0, 0]);
        gate.extend_from_slice(&text);
        vec![super::super::Run {
            start: GATE,
            bytes: gate,
            boundaries: Vec::new(),
        }]
    }

    #[test]
    fn the_mapped_recipe_allows_only_the_gate_and_traps_every_other_encoding() {
        let program = recipe(GATE + 0x200);
        let coverage = prove(
            &program,
            &runs(),
            &(GATE..GATE + 4096),
            &[GATE + 4096 + 0x10],
        )
        .unwrap();
        let sigreturn = libc::SYS_rt_sigreturn as u32;
        let gate = |ip| (ip, AllowedNumbers::AllExcept(vec![sigreturn]));
        assert_eq!(
            coverage.allowed,
            vec![
                gate(GATE + 0x80),
                gate(GATE + 0x82),
                gate(GATE + 0x200),
                gate(GATE + 0x202),
                (GATE + 0x30b, AllowedNumbers::Only(vec![sigreturn])),
            ]
        );
        assert_eq!(coverage.encodings, 5);
        // The text site and the pair inside the `jne` trap; the three gate
        // encodings end at allowed addresses.
        assert_eq!(coverage.trapped_encodings, 2);
        assert_eq!(coverage.trapped_declared_sites, 1);
    }

    #[test]
    fn a_declared_site_the_filter_does_not_trap_is_refused() {
        // A filter whose second gate is the declared text site.
        let site = GATE + 4096 + 0x10;
        let error = prove(&recipe(site), &runs(), &(GATE..GATE + 8192), &[site])
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            format!("filter proof: declared site {site:#x} is not trapped by the filter")
        );
    }

    #[test]
    fn an_allowed_address_outside_the_gate_page_is_refused() {
        let error = prove(
            &recipe(GATE + 4096 + 0x10),
            &runs(),
            &(GATE..GATE + 4096),
            &[],
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "filter proof: an allowed instruction pointer is outside the gate page"
        );
    }

    #[test]
    fn programs_the_proof_cannot_decide_are_refused() {
        let program = recipe(GATE + 0x200);
        // JSET (0x45) is not an equality test.
        let mut jset = program.clone();
        jset[8 * 4..8 * 4 + 2].copy_from_slice(&0x45_u16.to_le_bytes());
        // A load of a syscall argument.
        let mut argument = program.clone();
        argument[8 * 3 + 4..8 * 3 + 8].copy_from_slice(&16_u32.to_le_bytes());
        for (program, why) in [
            (jset, "filter proof: instruction other than ld, jeq or ret"),
            (
                argument,
                "filter proof: load of a field other than nr, arch or ip",
            ),
            (
                program[..program.len() - 3].to_vec(),
                "filter proof: program is not whole instructions",
            ),
        ] {
            assert_eq!(
                prove(&program, &runs(), &(GATE..GATE + 4096), &[])
                    .unwrap_err()
                    .to_string(),
                why
            );
        }
    }

    #[test]
    fn an_allow_for_any_address_is_refused() {
        // ld arch; jeq x86_64 else kill; ret allow.
        let mut program = Vec::new();
        for (code, jt, jf, k) in [
            (LD_W_ABS, 0_u8, 0_u8, ARCH),
            (JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
            (RET_K, 0, 0, 0x8000_0000),
            (RET_K, 0, 0, ALLOW),
        ] {
            program.extend_from_slice(&code.to_le_bytes());
            program.extend_from_slice(&[jt, jf]);
            program.extend_from_slice(&k.to_le_bytes());
        }
        assert_eq!(
            prove(&program, &runs(), &(GATE..GATE + 4096), &[])
                .unwrap_err()
                .to_string(),
            "filter proof: an unspecific instruction pointer is allowed"
        );
    }
}
