//! The lifecycle fixtures own one process group until its final cleanup signal.

use std::cell::RefCell;
use std::io;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::rc::Rc;
use std::time::Duration;
use std::time::Instant;

// These record actual kill(2) calls, including unsuccessful calls. In
// particular, an extra ESRCH after reap must not disappear from the control.
pub type SignalAttempt = (i32, i32, Option<i32>);

struct OwnedFixture {
    child: Option<Child>,
    group_owned: bool,
    signals: Rc<RefCell<Vec<SignalAttempt>>>,
}

impl OwnedFixture {
    fn exited(&mut self) -> io::Result<bool> {
        let Some(child) = self.child.as_ref() else {
            return Ok(true);
        };
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        loop {
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    child.id(),
                    &raw mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == 0 {
                return Ok(unsafe { info.si_pid() } != 0);
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // ECHILD can mean an external reaper consumed the identity. Other
            // unexpected wait errors do not establish ownership either. Never
            // signal a stored numeric group after losing this wait proof.
            self.group_owned = false;
            self.child.take();
            return Err(io::Error::other(format!(
                "fixture wait ownership lost; cleanup unconfirmed: {error}"
            )));
        }
    }

    fn signal_group(&mut self) -> io::Result<()> {
        if !self.group_owned {
            return Ok(());
        }
        let group = -(self.child.as_ref().expect("unreaped leader").id() as i32);
        // Consume this permission before the syscall, and never reacquire it
        // from a cached PID. The unreaped leader prevents group-ID reuse here.
        self.group_owned = false;
        let result = unsafe { libc::kill(group, libc::SIGKILL) };
        let error = (result != 0).then(io::Error::last_os_error);
        self.signals.borrow_mut().push((
            group,
            result,
            error.as_ref().and_then(io::Error::raw_os_error),
        ));
        match error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for OwnedFixture {
    fn drop(&mut self) {
        if self.child.is_none() {
            return;
        }
        // A deadline/error path also checks ownership before signalling. No
        // blocking pipe reads or fresh cleanup deadline are introduced here.
        let exited = match self.exited() {
            Ok(exited) => exited,
            Err(error) => {
                eprintln!("{error}");
                return;
            }
        };
        if let Err(error) = self.signal_group() {
            eprintln!("fixture group cleanup failed: {error}");
        }
        let Some(mut child) = self.child.take() else {
            return;
        };
        if exited {
            // WNOWAIT has already observed this exit; this consumes it.
            if let Err(error) = child.wait() {
                eprintln!("fixture reap failed: {error}");
            }
        } else {
            // A killed task can remain uninterruptible in the kernel. A failed
            // test must still return at its original deadline. Retain actual
            // child ownership in a reaper, never report this as completed
            // cleanup, and never send another numeric group signal there.
            eprintln!("fixture cleanup pending after failure; retaining child reaper");
            std::thread::spawn(move || {
                if let Err(error) = child.wait() {
                    eprintln!("fixture retained reap failed: {error}");
                }
            });
        }
    }
}

fn nonblocking(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn drain(reader: &mut impl Read, bytes: &mut Vec<u8>) -> io::Result<bool> {
    let mut buffer = [0; 4096];
    // Bound each pass too: a continuously writable pipe cannot prevent the
    // caller from checking the one deadline or servicing the other pipe.
    for _ in 0..16 {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(length) => bytes.extend_from_slice(&buffer[..length]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

pub fn run(mut command: Command, bound: Duration) -> io::Result<(Output, Vec<SignalAttempt>)> {
    let deadline = Instant::now() + bound;
    let child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let signals = Rc::new(RefCell::new(Vec::new()));
    let mut fixture = OwnedFixture {
        child: Some(child),
        group_owned: true,
        signals: signals.clone(),
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = (|| {
        let child = fixture.child.as_mut().unwrap();
        let mut out = child.stdout.take().unwrap();
        let mut err = child.stderr.take().unwrap();
        nonblocking(out.as_raw_fd())?;
        nonblocking(err.as_raw_fd())?;
        let mut status = None;
        let mut out_closed = false;
        let mut err_closed = false;
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("fixture exceeded its original {bound:?} deadline"),
                ));
            }
            if !out_closed {
                out_closed = drain(&mut out, &mut stdout)?;
            }
            if !err_closed {
                err_closed = drain(&mut err, &mut stderr)?;
            }
            if status.is_none() && fixture.exited()? {
                fixture.signal_group()?;
                // Signal while the leader is still ours; only now consume its
                // wait status and disarm Drop. Descendants may still hold pipes.
                status = Some(fixture.child.take().unwrap().wait()?);
            }
            if let (true, Some(status)) = (out_closed && err_closed, status) {
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    })();
    drop(fixture);
    let attempts = Rc::try_unwrap(signals).unwrap().into_inner();
    match result {
        Ok(status) => Ok((
            Output {
                status,
                stdout,
                stderr,
            },
            attempts,
        )),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("{error}; signals={attempts:?}; stdout={stdout:?}; stderr={stderr:?}"),
        )),
    }
}
