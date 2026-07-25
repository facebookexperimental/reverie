use std::process;

const CHILD_MESSAGE: &[u8] = b"fork child reached guest code\n";

fn main() {
    let mode = std::env::args_os().nth(1);
    if mode.as_deref() == Some(std::ffi::OsStr::new("--unsafe-clone")) {
        probe_unsafe_clone();
        return;
    }
    let raw_fork = mode.as_deref() == Some(std::ffi::OsStr::new("--raw-fork"));
    let child = unsafe {
        if raw_fork {
            libc::syscall(libc::SYS_fork) as libc::pid_t
        } else {
            libc::fork()
        }
    };
    if child < 0 {
        eprintln!("fork failed: {}", std::io::Error::last_os_error());
        process::exit(1);
    }

    if child == 0 {
        unsafe {
            libc::write(
                libc::STDOUT_FILENO,
                CHILD_MESSAGE.as_ptr().cast(),
                CHILD_MESSAGE.len(),
            );
            libc::_exit(0);
        }
    }

    let mut status = 0;
    if unsafe { libc::waitpid(child, &mut status, 0) } != child {
        eprintln!("waitpid failed: {}", std::io::Error::last_os_error());
        process::exit(1);
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        eprintln!("child status was {status}");
        process::exit(1);
    }

    println!("fork parent observed child {child}");
}

fn probe_unsafe_clone() {
    let flags = libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD;
    let result = unsafe { libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0) };
    if result == 0 {
        unsafe {
            libc::_exit(90);
        }
    }
    if result >= 0 {
        eprintln!("unsafe clone unexpectedly created child {result}");
        process::exit(1);
    }
    println!(
        "unsafe clone rejected: {}",
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    );
}
