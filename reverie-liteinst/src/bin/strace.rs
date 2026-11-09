use std::env;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use std::process::{self};

use reverie_liteinst::PreloadTool;
use reverie_liteinst::configure_command;

fn main() {
    let mut arguments = env::args_os();
    let _launcher = arguments.next();
    let Some(program) = arguments.next() else {
        eprintln!("usage: reverie-liteinst-strace PROGRAM [ARG]...");
        process::exit(2);
    };

    let mut command = Command::new(program);
    command.args(arguments);
    if let Err(error) = configure_command(&mut command, PreloadTool::Strace) {
        eprintln!("reverie-liteinst-strace: {error}");
        process::exit(2);
    }

    let status = match command.status() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("reverie-liteinst-strace: failed to launch guest: {error}");
            process::exit(1);
        }
    };

    if let Some(code) = status.code() {
        process::exit(code);
    }
    if let Some(signal) = status.signal() {
        eprintln!("reverie-liteinst-strace: guest terminated by signal {signal}");
        process::exit(128 + signal);
    }
    process::exit(1);
}
