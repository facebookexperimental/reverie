/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::fmt;

/// Contains information about a syscall, including its parameters.
pub struct SyscallInfo {
    pub num: usize,
    pub name: String,
    pub params: Vec<(String, String)>,
}

impl fmt::Display for SyscallInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:>3} => {}({})",
            self.num,
            self.name,
            self.params
                .iter()
                .map(|(t, a)| format!("{} {}", t, a))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl SyscallInfo {
    pub fn display_as_rust(&self) -> RustSyscall {
        RustSyscall(self)
    }
}

pub struct RustSyscall<'a>(&'a SyscallInfo);

impl<'a> fmt::Display for RustSyscall<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let params = self
            .0
            .params
            .iter()
            .map(|(t, a)| RustParam::new(t, a))
            .collect::<Vec<_>>();

        let name = translate_syscall(&self.0.name);

        writeln!(
            f,
            "/// See [{name}(2)](http://man7.org/linux/man-pages/man2/{name}.2.html)\n\
            /// for more info on this syscall.",
            name = name
        )?;
        writeln!(f, "#[inline(always)]")?;

        writeln!(
            f,
            "pub unsafe fn sys_{}({}) -> Result<i64, Errno> {{",
            name,
            params
                .iter()
                .map(|p| format!("{}", p))
                .collect::<Vec<_>>()
                .join(", ")
        )?;

        let idents = params
            .iter()
            .map(|p| format!("{} as u64", p.ident))
            .collect::<Vec<_>>()
            .join(", ");

        if params.is_empty() {
            writeln!(f, "    syscall0(Sysno::{})", name)?;
        } else {
            writeln!(
                f,
                "    syscall{}(Sysno::{}, {})",
                params.len(),
                name,
                idents
            )?;
        }

        writeln!(f, "}}")
    }
}

/// Format a parameter as a Rust parameter.
struct RustParam<'a> {
    /// The type of the parameter.
    ty: &'a str,
    /// The identifier of the parameter.
    ident: &'a str,
}

impl<'a> RustParam<'a> {
    pub fn new(ty: &'a str, ident: &'a str) -> Self {
        let ident = translate_ident(ident);
        Self { ty, ident }
    }
}

impl<'a> fmt::Display for RustParam<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.ident, to_rust_type(self.ident, self.ty))
    }
}

fn translate_syscall(name: &str) -> &str {
    let name = name.strip_prefix("sys_").unwrap_or(name);

    match name {
        "newstat" => "stat",
        "newfstat" => "fstat",
        "newlstat" => "lstat",
        "sendfile64" => "sendfile",
        "sysctl" => "_sysctl",
        "umount" => "umount2",
        "newuname" => "uname",
        _ => name,
    }
}

fn translate_ident(ident: &str) -> &str {
    match ident {
        "type" => "r#type",
        "usize" => "size",
        _ => ident,
    }
}

/// Converts this type to a Rust type if possible.
fn to_rust_type(ident: &str, ty: &str) -> &'static str {
    match ty {
        "char *" => match ident {
            "buf" => "*mut u8",
            _ => "*mut libc::c_char",
        },
        "const char *" => match ident {
            "buf" => "*const u8",
            _ => "*const libc::c_char",
        },
        "unsigned char *" => "*mut u8",
        "const unsigned char *" => "*const u8",
        "int" => "i32",
        "int *" => "*mut i32",
        "const int *" => "*const i32",
        "u32" => "u32",
        "u32 *" => "*mut u32",
        "__u64" => "u64",
        "__s32" => "i32",
        "long" => "i64",
        "unsigned" => "u32",
        "unsigned *" => "*mut u32",
        "unsigned int" => "u32",
        "unsigned int *" => "*mut u32",
        "size_t" => "usize",
        "size_t *" => "*mut usize",
        "unsigned long" => "u64",
        "unsigned long *" => "*mut u64",
        "const unsigned long *" => "*const u64",
        "umode_t" => "libc::mode_t",
        "struct stat *" => "*mut libc::stat",
        "struct pollfd *" => "*mut libc::pollfd",
        "off_t" => "libc::off_t",
        "const struct sigaction *" => "*const libc::sigaction",
        "struct sigaction *" => "*mut libc::sigaction",
        "sigset_t *" => "*mut libc::sigset_t",
        "const sigset_t *" => "*const libc::sigset_t",
        "siginfo_t *" => "*mut libc::siginfo_t",
        "struct siginfo *" => "*mut libc::siginfo_t",
        "loff_t" => "libc::loff_t",
        "loff_t *" => "*mut libc::loff_t",
        "const struct iovec *" => "*const libc::iovec",
        "fd_set *" => "*mut libc::fd_set",
        "struct __kernel_old_timeval *" => "*mut libc::timeval",
        "key_t" => "libc::key_t",
        "struct shmid_ds *" => "*mut libc::shmid_ds",
        "struct __kernel_timespec *" => "*mut libc::timespec",
        "const struct __kernel_timespec *" => "*const libc::timespec",
        "struct __kernel_old_itimerval *" => "*mut libc::itimerval",
        "struct sockaddr *" => "*mut libc::sockaddr",
        "void *" => "*mut libc::c_void",
        "const void *" => "*const libc::c_void",
        "const void * *" => "*mut *const libc::c_void",
        "struct user_msghdr *" => "*mut libc::msghdr",
        "const char *const *" => "*const *const libc::c_char",
        "pid_t" => "libc::pid_t",
        "struct rusage *" => "*mut libc::rusage",
        "struct new_utsname *" => "*mut libc::utsname",
        "struct sembuf *" => "*mut libc::sembuf",
        "struct msgbuf *" => "*mut libc::c_void",
        "struct msqid_ds *" => "*mut libc::msqid_ds",
        "struct linux_dirent *" => "*mut libc::dirent",
        "struct linux_dirent64 *" => "*mut libc::dirent64",
        "uid_t" => "libc::uid_t",
        "uid_t *" => "*mut libc::uid_t",
        "gid_t" => "libc::gid_t",
        "gid_t *" => "*mut libc::gid_t",
        "struct timezone *" => "*mut libc::timezone",
        "struct rlimit *" => "*mut libc::rlimit",
        "struct rlimit64 *" => "*mut libc::rlimit64",
        "const struct rlimit64 *" => "*const libc::rlimit64",
        "struct sysinfo *" => "*mut libc::sysinfo",
        "struct tms *" => "*mut libc::tms",
        // FIXME: See https://man7.org/linux/man-pages/man2/capget.2.html for
        // the definition of cap_user_header_t and cap_user_data_t.
        "cap_user_header_t" => "*mut libc::c_void",
        "cap_user_data_t" => "*mut libc::c_void",
        "const cap_user_data_t" => "*const libc::c_void",
        "stack_t *" => "*mut libc::stack_t",
        "const stack_t *" => "*const libc::stack_t",
        "struct utimbuf *" => "*mut libc::utimbuf",
        // FIXME: This should be using libc::ustat, but that doesn't exist yet.
        "struct ustat *" => "*mut libc::c_void",
        "struct statfs *" => "*mut libc::statfs",
        "struct sched_param *" => "*mut libc::sched_param",
        // FIXME: No equivalent exists. See
        // https://man7.org/linux/man-pages/man2/sysctl.2.html for definition.
        "struct __sysctl_args *" => "*mut libc::c_void",
        "struct __kernel_timex *" => "*mut libc::timex",
        "qid_t" => "i32",
        "__kernel_old_time_t *" => "*mut libc::time_t",
        // aio_context_t is defined as a simple `unsigned long`.
        "aio_context_t *" => "*mut u64",
        "aio_context_t" => "u64",
        // FIXME: io_event is defined at
        // https://elixir.bootlin.com/linux/v5.16.11/source/include/uapi/linux/aio_abi.h#L60.
        "struct io_event *" => "*mut libc::c_void",
        // FIXME: See https://man7.org/linux/man-pages/man2/io_submit.2.html for
        // definition of iocb.
        "struct iocb * *" => "*mut *mut libc::c_void",
        "struct iocb *" => "*mut libc::c_void",
        "const clockid_t" => "libc::clockid_t",
        "struct sigevent *" => "*mut libc::sigevent",
        "const struct sigevent *" => "*mut libc::sigevent",
        "timer_t *" => "*mut i32",
        "timer_t" => "i32",
        "const struct __kernel_itimerspec *" => "*const libc::itimerspec",
        "struct __kernel_itimerspec *" => "*mut libc::itimerspec",
        "struct epoll_event *" => "*mut libc::epoll_event",
        "struct mq_attr *" => "*mut libc::mq_attr",
        "const struct mq_attr *" => "*const libc::mq_attr",
        "mqd_t" => "libc::mqd_t",
        // FIXME: See https://man7.org/linux/man-pages/man2/kexec_load.2.html
        // for definition of kexec_segment.
        "struct kexec_segment *" => "*mut libc::c_void",
        "key_serial_t" => "i32",
        // FIXME: robust_list_head is defined at
        // https://elixir.bootlin.com/linux/v5.16.11/source/include/uapi/linux/futex.h#L97
        "struct robust_list_head *" => "*mut libc::c_void",
        "struct robust_list_head * *" => "*mut *mut libc::c_void",
        // FIXME: perf_event_attr is a big struct and no definition in libc
        // exists. For real definiton, see
        // https://man7.org/linux/man-pages/man2/perf_event_open.2.html.
        "struct perf_event_attr *" => "*mut libc::c_void",
        "struct mmsghdr *" => "*mut libc::mmsghdr",
        // FIXME: See
        // https://man7.org/linux/man-pages/man2/name_to_handle_at.2.html for
        // definition of file_handle.
        "struct file_handle *" => "*mut libc::c_void",
        // NOTE: getcpu_cache is an opaque type and should never be accessed by
        // user code.
        "struct getcpu_cache *" => "*mut libc::c_void",
        // FIXME: For definition of sched_attr, see:
        // https://elixir.bootlin.com/linux/v5.16.11/source/include/uapi/linux/sched/types.h#L102
        "struct sched_attr *" => "*mut libc::c_void",
        // FIXME: For definition of bpf_attr, see:
        // https://man7.org/linux/man-pages/man2/bpf.2.html
        "union bpf_attr *" => "*mut libc::c_void",
        "rwf_t" => "i32",
        "struct statx *" => "*mut libc::statx",
        // FIXME: For definition of __aio_sigset, see:
        // https://elixir.bootlin.com/linux/v5.16.11/source/fs/aio.c#L2216
        "const struct __aio_sigset *" => "*mut libc::c_void",
        // FIXME: For definition of rseq, see:
        // https://elixir.bootlin.com/linux/v5.16.11/source/include/uapi/linux/rseq.h#L62
        "struct rseq *" => "*mut libc::c_void",
        // FIXME: For definitino of io_uring_params, see:
        // https://elixir.bootlin.com/linux/v5.16.11/source/include/uapi/linux/io_uring.h#L265
        "struct io_uring_params *" => "*mut libc::c_void",
        // FIXME: This is used by the clone3 syscall and libc doesn't have this
        // yet. For the definition of clone_args, see:
        // https://elixir.bootlin.com/linux/v5.16.11/source/include/uapi/linux/sched.h#L92
        "struct clone_args *" => "*mut libc::c_void",
        // FIXME: This is used by the openat2 syscall and libc doesn't have this
        // yet. For the definition of open_how, see:
        // https://elixir.bootlin.com/linux/v5.16.11/source/include/uapi/linux/openat2.h#L19
        "struct open_how *" => "*mut libc::c_void",
        _ => panic!(
            "Don't know how to convert this syscall parameter to Rust: {} {}",
            ident, ty
        ),
    }
}
