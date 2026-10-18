/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Checked observations of Linux's `PTRACE_GET_SYSCALL_INFO` replies.

use thiserror::Error;

use crate::Stopped;

// Linux UAPI's request number and native-endian wire layout. Keep this small
// byte buffer independent of libc's GNU-only union definition. The kernel
// returns the active member's used length, not sizeof(the whole union).
const PTRACE_GET_SYSCALL_INFO: usize = 0x420e;
const HEADER_SIZE: usize = 24;
const BUFFER_SIZE: usize = 88;
const ENTRY_SIZE: usize = 80;
const EXIT_SIZE: usize = 33;
const SECCOMP_SIZE: usize = 84;

/// One observation of a stopped tracee's current syscall state.
///
/// This does not advance the tracee or infer an entry/exit phase from previous
/// stops. In particular, callers must check [`Self::operation`] rather than
/// treat every [`crate::Event::Syscall`] as a syscall exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallInfo {
    /// Linux audit architecture identifier, retained without host inference.
    pub architecture: u32,
    /// Kernel-reported instruction pointer (after `syscall` on x86-64).
    pub instruction_pointer: u64,
    /// Kernel-reported user stack pointer.
    pub stack_pointer: u64,
    /// The number of bytes the kernel reported for this observation.
    pub kernel_size: usize,
    /// The active operation and its fully returned fields.
    pub operation: SyscallInfoOp,
}

/// The active member of a `PTRACE_GET_SYSCALL_INFO` reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallInfoOp {
    /// The stop has no syscall operation to report.
    ///
    /// This is a successful kernel observation, not a fallback for unsupported
    /// requests or malformed replies. Without `PTRACE_O_TRACESYSGOOD`, Linux
    /// can also report this at syscall entry/exit stops.
    None,
    /// The tracee is stopped at syscall entry.
    Entry {
        /// The syscall number in the tracee's ABI.
        number: u64,
        /// The six syscall arguments in the tracee's ABI.
        arguments: [u64; 6],
    },
    /// The tracee is stopped at syscall exit.
    Exit {
        /// The signed return value supplied by the kernel, including errors.
        return_value: i64,
        /// The kernel's explicit indication that this is an error return.
        is_error: bool,
    },
    /// The tracee is stopped at a `PTRACE_EVENT_SECCOMP` event.
    Seccomp {
        /// The syscall number in the tracee's ABI.
        number: u64,
        /// The six syscall arguments in the tracee's ABI.
        arguments: [u64; 6],
        /// The `SECCOMP_RET_DATA` associated with the event.
        ret_data: u32,
    },
}

/// A syscall-info request failed or returned an unsupported observation.
///
/// Existing tracee-death and errno information remains available through
/// [`Self::Trace`]; unsupported requests are never converted to
/// [`SyscallInfoOp::None`].
#[derive(Error, Debug, Eq, PartialEq)]
pub enum SyscallInfoError {
    /// The generation-bound ptrace request failed.
    #[error(transparent)]
    Trace(#[from] crate::Error),
    /// The kernel did not return all bytes required by the active operation.
    #[error("short PTRACE_GET_SYSCALL_INFO reply: {reported} bytes, need {required}")]
    Truncated {
        /// The size reported by the kernel.
        reported: usize,
        /// The minimum complete size for this operation.
        required: usize,
    },
    /// The kernel reported more bytes than this request's buffer can hold.
    #[error("oversized PTRACE_GET_SYSCALL_INFO reply: {reported} bytes, capacity {capacity}")]
    Oversized {
        /// The size reported by the kernel.
        reported: usize,
        /// The capacity supplied to the kernel.
        capacity: usize,
    },
    /// The kernel reported an operation this API cannot interpret.
    #[error("unknown PTRACE_GET_SYSCALL_INFO operation {operation}")]
    UnknownOperation {
        /// The raw operation byte.
        operation: u8,
    },
    /// The exit operation's `is_error` byte was neither zero nor one.
    #[error("invalid PTRACE_GET_SYSCALL_INFO is_error byte {value}")]
    InvalidErrorFlag {
        /// The raw error-indicator byte.
        value: u8,
    },
}

impl Stopped {
    /// Observe the current stop with `PTRACE_GET_SYSCALL_INFO` (Linux 5.3+).
    ///
    /// Set `PTRACE_O_TRACESYSGOOD` before resuming toward syscall stops. The
    /// returned operation distinguishes entry, exit, seccomp and non-syscall
    /// stops; the caller must still verify the expected phase, architecture
    /// and instruction/stack pointers. This request does not resume the tracee.
    /// Unknown operations and incomplete replies are named errors.
    pub fn getsyscallinfo(&self) -> Result<SyscallInfo, SyscallInfoError> {
        let mut bytes = [0_u8; BUFFER_SIZE];
        let reported = self
            .1
            .on_held_tid(|| {
                // SAFETY: the initialized writable byte array remains live for
                // this request, and the kernel receives its exact capacity and
                // does not retain the pointer. The existing generation checks
                // enclose the request, which may fail if the stop died. No Rust
                // union or uninitialized field is read; the decoder checks the
                // returned active-member length before interpreting its fields.
                unsafe {
                    syscalls::syscall!(
                        syscalls::Sysno::ptrace,
                        PTRACE_GET_SYSCALL_INFO,
                        self.0.as_raw(),
                        bytes.len(),
                        bytes.as_mut_ptr()
                    )
                }
            })
            .map_err(|error| SyscallInfoError::Trace(self.map_err(error)))?;
        decode(&bytes, reported)
    }
}

fn decode(bytes: &[u8; BUFFER_SIZE], reported: usize) -> Result<SyscallInfo, SyscallInfoError> {
    if reported > bytes.len() {
        return Err(SyscallInfoError::Oversized {
            reported,
            capacity: bytes.len(),
        });
    }
    require_size(reported, HEADER_SIZE)?;
    let operation = bytes[0];
    let required = match operation {
        0 => HEADER_SIZE,
        1 => ENTRY_SIZE,
        2 => EXIT_SIZE,
        3 => SECCOMP_SIZE,
        _ => return Err(SyscallInfoError::UnknownOperation { operation }),
    };
    require_size(reported, required)?;

    // All selected fields lie within the length checked above. Header bytes
    // 1..4 are reserved/flags space and are not interpreted as observation data.
    let operation = match operation {
        0 => SyscallInfoOp::None,
        1 => SyscallInfoOp::Entry {
            number: read_u64(bytes, 24),
            arguments: read_arguments(bytes),
        },
        2 => SyscallInfoOp::Exit {
            return_value: i64::from_ne_bytes(bytes[24..32].try_into().unwrap()),
            is_error: match bytes[32] {
                0 => false,
                1 => true,
                value => return Err(SyscallInfoError::InvalidErrorFlag { value }),
            },
        },
        3 => SyscallInfoOp::Seccomp {
            number: read_u64(bytes, 24),
            arguments: read_arguments(bytes),
            ret_data: u32::from_ne_bytes(bytes[80..84].try_into().unwrap()),
        },
        _ => unreachable!("the operation was checked above"),
    };
    Ok(SyscallInfo {
        architecture: u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
        instruction_pointer: read_u64(bytes, 8),
        stack_pointer: read_u64(bytes, 16),
        kernel_size: reported,
        operation,
    })
}

fn require_size(reported: usize, required: usize) -> Result<(), SyscallInfoError> {
    if reported < required {
        Err(SyscallInfoError::Truncated { reported, required })
    } else {
        Ok(())
    }
}

fn read_u64(bytes: &[u8; BUFFER_SIZE], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_arguments(bytes: &[u8; BUFFER_SIZE]) -> [u64; 6] {
    std::array::from_fn(|index| read_u64(bytes, 32 + index * 8))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(operation: u8) -> [u8; BUFFER_SIZE] {
        let mut bytes = [0_u8; BUFFER_SIZE];
        bytes[0] = operation;
        // Preserve an opaque architecture value rather than assuming x86-64.
        bytes[4..8].copy_from_slice(&0x1234_5678_u32.to_ne_bytes());
        bytes[8..16].copy_from_slice(&0x6000_e000_0042_u64.to_ne_bytes());
        bytes[16..24].copy_from_slice(&0x7fff_1234_5678_u64.to_ne_bytes());
        bytes
    }

    #[test]
    fn complete_kernel_operations_retain_all_fields() {
        let none = decode(&header(0), HEADER_SIZE).unwrap();
        assert_eq!(none.architecture, 0x1234_5678);
        assert_eq!(none.instruction_pointer, 0x6000_e000_0042);
        assert_eq!(none.stack_pointer, 0x7fff_1234_5678);
        assert_eq!(none.kernel_size, HEADER_SIZE);
        assert_eq!(none.operation, SyscallInfoOp::None);

        let number = 0x1234_5678_9abc_def0_u64;
        let arguments = [0, 1, u64::MAX, 0x1122_3344_5566_7788, 1 << 63, 4096];
        let mut entry = header(1);
        entry[24..32].copy_from_slice(&number.to_ne_bytes());
        for (index, argument) in arguments.iter().enumerate() {
            let start = 32 + index * 8;
            entry[start..start + 8].copy_from_slice(&argument.to_ne_bytes());
        }
        let info = decode(&entry, ENTRY_SIZE).unwrap();
        assert_eq!(info.kernel_size, ENTRY_SIZE);
        assert_eq!(info.operation, SyscallInfoOp::Entry { number, arguments });

        let mut exit = header(2);
        exit[24..32].copy_from_slice(&(-13_i64).to_ne_bytes());
        exit[32] = 1;
        assert_eq!(
            decode(&exit, EXIT_SIZE).unwrap().operation,
            SyscallInfoOp::Exit {
                return_value: -13,
                is_error: true,
            }
        );
        exit[24..32].copy_from_slice(&0_i64.to_ne_bytes());
        exit[32] = 0;
        assert_eq!(
            decode(&exit, EXIT_SIZE).unwrap().operation,
            SyscallInfoOp::Exit {
                return_value: 0,
                is_error: false,
            }
        );

        let mut seccomp = entry;
        seccomp[0] = 3;
        seccomp[80..84].copy_from_slice(&0xabcd_1234_u32.to_ne_bytes());
        assert_eq!(
            decode(&seccomp, SECCOMP_SIZE).unwrap().operation,
            SyscallInfoOp::Seccomp {
                number,
                arguments,
                ret_data: 0xabcd_1234,
            }
        );
    }

    #[test]
    fn every_incomplete_operation_is_refused() {
        for (operation, required) in [
            (0, HEADER_SIZE),
            (1, ENTRY_SIZE),
            (2, EXIT_SIZE),
            (3, SECCOMP_SIZE),
        ] {
            let bytes = header(operation);
            for reported in 0..required {
                assert_eq!(
                    decode(&bytes, reported),
                    Err(SyscallInfoError::Truncated {
                        reported,
                        required: if reported < HEADER_SIZE {
                            HEADER_SIZE
                        } else {
                            required
                        },
                    })
                );
            }
        }
    }

    #[test]
    fn oversized_and_unknown_operations_are_refused() {
        assert_eq!(
            decode(&header(0), BUFFER_SIZE + 1),
            Err(SyscallInfoError::Oversized {
                reported: BUFFER_SIZE + 1,
                capacity: BUFFER_SIZE,
            })
        );
        assert_eq!(
            decode(&header(0xff), HEADER_SIZE),
            Err(SyscallInfoError::UnknownOperation { operation: 0xff })
        );
    }

    #[test]
    fn exit_error_indicator_must_be_boolean() {
        for value in [2, u8::MAX] {
            let mut exit = header(2);
            exit[32] = value;
            assert_eq!(
                decode(&exit, EXIT_SIZE),
                Err(SyscallInfoError::InvalidErrorFlag { value })
            );
        }
    }
}
