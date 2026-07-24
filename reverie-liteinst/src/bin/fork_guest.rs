use std::process;

const CHILD_MESSAGE: &[u8] = b"fork child reached guest code\n";

fn main() {
    let child = unsafe { libc::fork() };
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
