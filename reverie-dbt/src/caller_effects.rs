/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

use std::sync::Mutex;

use reverie::syscalls::Errno;

use crate::caller_abi::TerminalAdmission;
use crate::caller_abi::TerminalFact;

#[derive(Clone, Copy, Debug)]
enum State {
    Open,
    Refused(&'static str),
    Established(TerminalFact),
}

/// Lives for the admitted thread, including memory handles kept by its Tool.
/// It owns no Tool, thread state, endpoint, or pointer to a callback's Guest.
#[derive(Debug)]
pub(crate) struct CallerEffects {
    context: usize,
    pid: i32,
    tid: i32,
    image: u64,
    admit: TerminalAdmission,
    state: Mutex<State>,
}

impl CallerEffects {
    pub(crate) fn new(
        context: usize,
        pid: i32,
        tid: i32,
        image: u64,
        admit: TerminalAdmission,
    ) -> Self {
        Self {
            context,
            pid,
            tid,
            image,
            admit,
            state: Mutex::new(State::Open),
        }
    }

    pub(crate) fn stopped(&self) -> bool {
        !matches!(*self.state.lock().unwrap(), State::Open)
    }

    pub(crate) fn check_memory(&self) -> Result<(), Errno> {
        if self.stopped() {
            Err(Errno::ESRCH)
        } else {
            Ok(())
        }
    }

    pub(crate) fn refusal(&self) -> Option<&'static str> {
        match *self.state.lock().unwrap() {
            State::Refused(reason) => Some(reason),
            _ => None,
        }
    }

    pub(crate) fn ending(&self) -> Option<TerminalFact> {
        match *self.state.lock().unwrap() {
            State::Established(fact) => Some(fact),
            _ => None,
        }
    }

    pub(crate) fn refuse(&self, reason: &'static str) {
        let mut state = self.state.lock().unwrap();
        if matches!(*state, State::Open) {
            *state = State::Refused(reason);
        }
    }

    pub(crate) fn admit_exit(&self, sysno: i64, args: [u64; 6]) {
        if self.stopped() {
            return;
        }
        let mut fact = TerminalFact::default();
        // No Rust state lock is held across native admission. The caller domain
        // admits exactly one application thread; native verifies that context.
        let result = unsafe { (self.admit)(self.context, sysno, args.as_ptr(), &mut fact) };
        if result != 1
            || !fact.matches_owner(self.context, self.pid, self.tid, self.image)
            || fact.sysno != sysno
            || fact.args != args
            || fact.origin != 2
        {
            self.refuse("caller-terminal-admission-refused");
            return;
        }
        let mut state = self.state.lock().unwrap();
        if matches!(*state, State::Open) {
            *state = State::Established(fact);
        }
    }

    /// Close retained handles for an original exit admitted by native. The
    /// exact existing deferred ending is accepted without replacing it.
    pub(crate) fn establish_final(&self, fact: TerminalFact) -> bool {
        if !fact.matches_owner(self.context, self.pid, self.tid, self.image) {
            return false;
        }
        let mut state = self.state.lock().unwrap();
        match *state {
            State::Established(existing) => existing == fact,
            State::Open if fact.origin == 1 => {
                *state = State::Established(fact);
                true
            }
            State::Open | State::Refused(_) => false,
        }
    }
}

/// Operations that cannot be forwarded within the admitted caller domain.
pub(crate) fn unsupported_operation(number: i64, args: &[u64; 6], returning: bool) -> bool {
    matches!(
        number,
        libc::SYS_clone
            | libc::SYS_clone3
            | libc::SYS_fork
            | libc::SYS_vfork
            | libc::SYS_execve
            | libc::SYS_execveat
            | libc::SYS_seccomp
            | libc::SYS_ptrace
            | libc::SYS_kill
            | libc::SYS_tkill
            | libc::SYS_tgkill
            | libc::SYS_rt_sigqueueinfo
            | libc::SYS_rt_tgsigqueueinfo
            | libc::SYS_pidfd_send_signal
            | libc::SYS_unshare
            | libc::SYS_setns
            | libc::SYS_setsid
            | libc::SYS_setpgid
            | libc::SYS_setuid
            | libc::SYS_setgid
            | libc::SYS_setreuid
            | libc::SYS_setregid
            | libc::SYS_setresuid
            | libc::SYS_setresgid
            | libc::SYS_setfsuid
            | libc::SYS_setfsgid
            | libc::SYS_setgroups
            | libc::SYS_capset
    ) || (number == libc::SYS_prctl
        && matches!(
            args[0] as i32,
            libc::PR_SET_SECCOMP | libc::PR_SET_PTRACER | libc::PR_SET_NO_NEW_PRIVS
        ))
        || (returning && matches!(number, libc::SYS_exit | libc::SYS_exit_group))
}
