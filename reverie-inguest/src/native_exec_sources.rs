//! Content identity of the declared compiled native runtime inputs.
//!
//! This digest neither authenticates ELF bytes nor proves installer, dispatch,
//! writer exclusion, successful kernel exec or a complete dependency closure.
//! The actual artifact producer and native admission owner supply those proofs.

use sha2::Digest;
use sha2::Sha256;

/// SHA256 over versioned, length-delimited logical names and actual source bytes.
/// Both coordinator and in-guest consumer call this same compiled definition.
pub fn digest() -> [u8; 32] {
    digest_inputs(inputs())
}

fn inputs() -> &'static [(&'static str, &'static [u8])] {
    &[
        (
            "rv/native_exec_sources.rs",
            include_bytes!("native_exec_sources.rs"),
        ),
        (
            "rv/guest/exec_private.rs",
            include_bytes!("guest/exec_private.rs"),
        ),
        (
            "rv/guest/exec_private/native_io.rs",
            include_bytes!("guest/exec_private/native_io.rs"),
        ),
        (
            "rv/guest/native_exec.rs",
            include_bytes!("guest/native_exec.rs"),
        ),
        (
            "rv/guest/native_exec_arguments.rs",
            include_bytes!("guest/native_exec_arguments.rs"),
        ),
        (
            "rv/guest/native_exec_fds.rs",
            include_bytes!("guest/native_exec_fds.rs"),
        ),
        (
            "rv/guest/native_exec_mappings.rs",
            include_bytes!("guest/native_exec_mappings.rs"),
        ),
        ("rv/guest/host.rs", include_bytes!("guest/host.rs")),
        ("rv/guest/mod.rs", include_bytes!("guest/mod.rs")),
        (
            "rv/guest/native_capture.rs",
            include_bytes!("guest/native_capture.rs"),
        ),
        (
            "rv/guest/native_copied.rs",
            include_bytes!("guest/native_copied.rs"),
        ),
        (
            "rv/guest/native_entry.rs",
            include_bytes!("guest/native_entry.rs"),
        ),
        (
            "rv/guest/native_exit.rs",
            include_bytes!("guest/native_exit.rs"),
        ),
        (
            "rv/guest/native_initialize.rs",
            include_bytes!("guest/native_initialize.rs"),
        ),
        (
            "rv/guest/native_linux.rs",
            include_bytes!("guest/native_linux.rs"),
        ),
        (
            "rv/guest/native_rpc.rs",
            include_bytes!("guest/native_rpc.rs"),
        ),
        (
            "rv/guest/native_services.rs",
            include_bytes!("guest/native_services.rs"),
        ),
        (
            "rv/guest/native_state.rs",
            include_bytes!("guest/native_state.rs"),
        ),
        (
            "rv/guest/tool_install.rs",
            include_bytes!("guest/tool_install.rs"),
        ),
        (
            "rv/core/tool_configuration.rs",
            include_bytes!("../../reverie/src/tool_configuration.rs"),
        ),
        (
            "rv/core/tool_process.rs",
            include_bytes!("../../reverie/src/tool_process.rs"),
        ),
        (
            "rv/core/tool_outcome.rs",
            include_bytes!("../../reverie/src/tool_outcome.rs"),
        ),
        ("rv/tool_host.rs", include_bytes!("tool_host.rs")),
        (
            "rv/guest/host_linux.rs",
            include_bytes!("guest/host_linux.rs"),
        ),
        ("rv/guest/event.rs", include_bytes!("guest/event.rs")),
        ("rv/guest/rpc.rs", include_bytes!("guest/rpc.rs")),
        (
            "rv/guest/rpc/native.rs",
            include_bytes!("guest/rpc/native.rs"),
        ),
        (
            "rv/guest/rpc/stream.rs",
            include_bytes!("guest/rpc/stream.rs"),
        ),
        (
            "rv/guest/installed_tool.rs",
            include_bytes!("guest/installed_tool.rs"),
        ),
        (
            "rv/guest/successor_image_guest.rs",
            include_bytes!("guest/successor_image_guest.rs"),
        ),
        (
            "rv/guest/continuation.rs",
            include_bytes!("guest/continuation.rs"),
        ),
        ("rv/guest/protect.rs", include_bytes!("guest/protect.rs")),
        ("rv/stats.rs", include_bytes!("stats.rs")),
        (
            "rv/stats/native_exec.rs",
            include_bytes!("stats/native_exec.rs"),
        ),
        ("rv/seccomp.rs", include_bytes!("seccomp.rs")),
        ("rv/trap.rs", include_bytes!("trap.rs")),
        (
            "rv/guest/tool_region_constructor.rs",
            include_bytes!("guest/tool_region_constructor.rs"),
        ),
        (
            "rv/trap/fixed_gates.rs",
            include_bytes!("trap/fixed_gates.rs"),
        ),
        (
            "rv/transport/lib.rs",
            include_bytes!("../../reverie-rpc-transport/src/lib.rs"),
        ),
        (
            "rv/transport/server.rs",
            include_bytes!("../../reverie-rpc-transport/src/server.rs"),
        ),
        (
            "rv/transport/blocking_client.rs",
            include_bytes!("../../reverie-rpc-transport/src/blocking_client.rs"),
        ),
        (
            "rv/transport/tool_activation.rs",
            include_bytes!("../../reverie-rpc-transport/src/tool_activation.rs"),
        ),
        (
            "rv/transport/successor.rs",
            include_bytes!("../../reverie-rpc-transport/src/successor.rs"),
        ),
        (
            "rv/transport/codec.rs",
            include_bytes!("../../reverie-rpc-transport/src/codec.rs"),
        ),
        (
            "rv/liteinst/tool_host.rs",
            include_bytes!("../../reverie-liteinst/src/tool_host.rs"),
        ),
        (
            "rv/liteinst/runtime.rs",
            include_bytes!("../../reverie-liteinst/src/runtime.rs"),
        ),
        (
            "rv/liteinst/native_exec_state.rs",
            include_bytes!("../../reverie-liteinst/src/native_exec_state.rs"),
        ),
        (
            "rv/bootstrap/private-bootstrap.c",
            include_bytes!("../native_exec/private-bootstrap.c"),
        ),
        (
            "rv/bootstrap/private-runner.c",
            include_bytes!("../native_exec/private-runner.c"),
        ),
        (
            "rv/bootstrap/private-control.h",
            include_bytes!("../native_exec/private-control.h"),
        ),
        (
            "rv/bootstrap/private-entry.S",
            include_bytes!("../native_exec/private-entry.S"),
        ),
        (
            "rv/bootstrap/private-fs.S",
            include_bytes!("../native_exec/private-fs.S"),
        ),
        (
            "rv/bootstrap/private-kernel-state.c",
            include_bytes!("../native_exec/private-kernel-state.c"),
        ),
        (
            "rv/bootstrap/private-maps.c",
            include_bytes!("../native_exec/private-maps.c"),
        ),
        (
            "rv/bootstrap/private-bootstrap.ld",
            include_bytes!("../native_exec/private-bootstrap.ld"),
        ),
        (
            "rv/launcher/native.rs",
            include_bytes!("launcher/native.rs"),
        ),
        (
            "rv/launcher/native_frontend.rs",
            include_bytes!("launcher/native_frontend.rs"),
        ),
        (
            "rv/process/lib.rs",
            include_bytes!("../../reverie-process/src/lib.rs"),
        ),
        (
            "rv/process/builder.rs",
            include_bytes!("../../reverie-process/src/builder.rs"),
        ),
        (
            "rv/process/spawn.rs",
            include_bytes!("../../reverie-process/src/spawn.rs"),
        ),
    ]
}

fn digest_inputs(inputs: &[(&str, &[u8])]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"Reverie declared native inputs v1\0");
    for (name, bytes) in inputs {
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_sources_invalidate_the_native_identity() {
        let original = inputs();
        assert_eq!(digest_inputs(original), digest());
        for (name, expected) in [
            (
                "rv/guest/tool_install.rs",
                include_bytes!("guest/tool_install.rs").as_slice(),
            ),
            (
                "rv/core/tool_configuration.rs",
                include_bytes!("../../reverie/src/tool_configuration.rs").as_slice(),
            ),
            (
                "rv/core/tool_process.rs",
                include_bytes!("../../reverie/src/tool_process.rs").as_slice(),
            ),
            (
                "rv/core/tool_outcome.rs",
                include_bytes!("../../reverie/src/tool_outcome.rs").as_slice(),
            ),
            ("rv/tool_host.rs", include_bytes!("tool_host.rs").as_slice()),
            ("rv/guest/mod.rs", include_bytes!("guest/mod.rs").as_slice()),
            (
                "rv/guest/native_capture.rs",
                include_bytes!("guest/native_capture.rs").as_slice(),
            ),
            (
                "rv/guest/native_copied.rs",
                include_bytes!("guest/native_copied.rs").as_slice(),
            ),
            (
                "rv/guest/native_entry.rs",
                include_bytes!("guest/native_entry.rs").as_slice(),
            ),
            (
                "rv/guest/native_exit.rs",
                include_bytes!("guest/native_exit.rs").as_slice(),
            ),
            (
                "rv/guest/native_initialize.rs",
                include_bytes!("guest/native_initialize.rs").as_slice(),
            ),
            (
                "rv/guest/native_linux.rs",
                include_bytes!("guest/native_linux.rs").as_slice(),
            ),
            (
                "rv/guest/native_rpc.rs",
                include_bytes!("guest/native_rpc.rs").as_slice(),
            ),
            (
                "rv/guest/native_services.rs",
                include_bytes!("guest/native_services.rs").as_slice(),
            ),
            (
                "rv/guest/native_state.rs",
                include_bytes!("guest/native_state.rs").as_slice(),
            ),
            (
                "rv/transport/lib.rs",
                include_bytes!("../../reverie-rpc-transport/src/lib.rs").as_slice(),
            ),
            (
                "rv/transport/tool_activation.rs",
                include_bytes!("../../reverie-rpc-transport/src/tool_activation.rs").as_slice(),
            ),
        ] {
            let matches: Vec<_> = original
                .iter()
                .enumerate()
                .filter(|(_, (actual, _))| *actual == name)
                .collect();
            assert_eq!(matches.len(), 1, "native input {name}");
            let (index, (_, bytes)) = matches[0];
            assert_eq!(*bytes, expected);
            let mut changed = bytes.to_vec();
            changed[0] ^= 1;
            let mut mutated = original.to_vec();
            mutated[index].1 = &changed;
            assert_ne!(digest_inputs(&mutated), digest(), "native input {name}");
        }
    }
}
