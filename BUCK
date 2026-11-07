load("@fbcode_macros//build_defs:sanitizers.bzl", "sanitizers")
load("@fbsource//tools/build_defs:fb_native_wrapper.bzl", "fb_native")
load("@fbsource//tools/build_defs:rust_binary.bzl", "rust_binary")
load("@fbsource//tools/build_defs:rust_library.bzl", "rust_library")
load("@fbsource//tools/build_defs:rust_unittest.bzl", "rust_unittest")
load("@fbsource//tools/build_defs:selects.bzl", "selects")

oncall("hermit")

# Keep registry metadata in the source of the autocargo manifests as well.
# Public package names differ from two internal target names. A BUCK file may
# not define functions (Buck2 rejects `def` outside .bzl files), so each target
# extends this shared table with its own documentation URL through dict().
_PUBLIC_CRATE_METADATA = {
    "version": "0.5.4",
    "readme": "README.md",
    "homepage": "https://hermetic-infra.org",
    "keywords": ["linux", "instrumentation", "hermit"],
    "categories": ["development-tools::debugging", "os::linux-apis"],
}

# Some tests don't work when a sanitizer is in use (i.e., with @mode/dev). This
# makes it easy to conditionally compile them with `#[cfg(not(sanitized))]`.
sanitized_feature = selects.apply(
    sanitizers.get_sanitizer_v2(),
    lambda san: ["--cfg=sanitized"] if san else [],
)

rust_library(
    name = "reverie",
    srcs = glob(["reverie/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-core"),
            "features": {"default": [], "perf-fixture": []},
            "dependencies_override": {"dev-dependencies": {"tracing-subscriber": {"features": ["env-filter"]}}},
        },
        "cargo_toml_dir": "reverie",
    },
    # Same core crate identity; inert resource helpers, no eager activation.
    features = ["perf-fixture"],
    test_rustc_flags = sanitized_feature,
    test_deps = ["fbsource//third-party/rust:tracing-subscriber"],
    deps = [
        "fbsource//third-party/rust:addr2line",
        "fbsource//third-party/rust:anyhow",
        "fbsource//third-party/rust:async-trait",
        "fbsource//third-party/rust:bitflags",
        "fbsource//third-party/rust:byteorder",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:linked-hash-map",
        "fbsource//third-party/rust:memmap2",
        "fbsource//third-party/rust:never-say-never",
        "fbsource//third-party/rust:nix",
        "fbsource//third-party/rust:object",
        "fbsource//third-party/rust:perf-event-open-sys",
        "fbsource//third-party/rust:procfs",
        "fbsource//third-party/rust:raw-cpuid",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:syscalls",
        "fbsource//third-party/rust:thiserror",
        "fbsource//third-party/rust:tracing",
        "fbsource//third-party/rust:typed-arena",
        ":reverie-process",
        ":reverie-syscalls",
    ],
)

# NOTE: This crate should not depend on any other Reverie crate. It should
# remain a generic way of spawning processes.
rust_library(
    name = "reverie-process",
    srcs = glob(["reverie-process/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-process"),
            "dependencies_override": {
                "dependencies": {
                    "bitflags": {
                        "features": [
                            "serde",
                        ]
                    },
                },
            },
            "features": {
                "default": [],
                "nightly": [],
            },
            "lints": {
                "rust": {
                    "unexpected_cfgs": {
                        "check-cfg": ["cfg(sanitized)"],
                        "level": "warn",
                    },
                },
            },
        },
        "cargo_toml_dir": "reverie-process",
        "edge_features": [],
    },
    features = ["nightly"],
    test_deps = [
        "fbsource//third-party/rust:num_cpus",
        "fbsource//third-party/rust:raw-cpuid",
        "fbsource//third-party/rust:tempfile",
    ],
    test_rustc_flags = sanitized_feature,
    deps = [
        "fbsource//third-party/rust:bincode",
        "fbsource//third-party/rust:bitflags",
        "fbsource//third-party/rust:colored",
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:nix",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:syscalls",
        "fbsource//third-party/rust:thiserror",
        "fbsource//third-party/rust:tokio",
    ],
)

rust_library(
    name = "reverie-util",
    srcs = glob(["reverie-util/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-utils"),
        },
        "cargo_toml_dir": "reverie-util",
    },
    deps = [
        "fbsource//third-party/rust:anyhow",
        "fbsource//third-party/rust:chrono",
        "fbsource//third-party/rust:clap",
        "fbsource//third-party/rust:tracing",
        "fbsource//third-party/rust:tracing-appender",
        "fbsource//third-party/rust:tracing-subscriber",
        ":reverie",
    ],
)

rust_library(
    name = "reverie-ptrace",
    srcs = glob(["reverie-ptrace/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-ptrace", build = "build.rs"),
            "dependencies_override": {
                "build-dependencies": {"pkg-config": {"version": "0.3"}},
                "dev-dependencies": {"reverie": {"package": "reverie-core", "features": ["perf-fixture"]}},
                "dependencies": {
                    "safeptrace": {
                        "features": [
                            "notifier",
                            "memory",
                        ]
                    },
                },
            },
            "features": {"default": [], "nightly": [], "rcb-observation": []},
            "test": [
                {"name": "first_instruction_cpuid", "path": "../tests/first_instruction_cpuid.rs"},
                {"name": "convert", "path": "../tests/convert.rs"},
                {"name": "vfork", "path": "../tests/vfork.rs"},
            ],
        },
        "cargo_toml_dir": "reverie-ptrace",
        "edge_features": [],
    },
    features = ["nightly"],
    test_deps = [
        "fbsource//third-party/rust:test-case",
    ],
    test_env = {
        # Disable leak detection for the `exit_status::test::propagate_exit`
        # test. The test does an early exit post-fork which invokes the ASAN
        # atexit handler code. The Rust test harness never has a chance to
        # deallocate its own stuff, so the ASAN atexit handler produces the
        # wrong exit code and thus causes the test to fail.
        "ASAN_OPTIONS": "detect_leaks=0",
    },
    test_rustc_flags = sanitized_feature,
    deps = [
        "fbsource//third-party/libunwind:unwind-ptrace",  # Used for getting remote backtraces.
        "fbsource//third-party/rust:anyhow",
        "fbsource//third-party/rust:async-trait",
        "fbsource//third-party/rust:bincode",
        "fbsource//third-party/rust:bytes",
        "fbsource//third-party/rust:close-err",
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:iced-x86",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:nix",
        "fbsource//third-party/rust:num-traits",
        "fbsource//third-party/rust:paste",
        "fbsource//third-party/rust:perf-event-open-sys",
        "fbsource//third-party/rust:procfs",
        "fbsource//third-party/rust:raw-cpuid",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:thiserror",
        "fbsource//third-party/rust:tokio",
        "fbsource//third-party/rust:tokio-stream",
        "fbsource//third-party/rust:tracing",
        "fbsource//third-party/rust:tracing-subscriber",
        "fbsource//third-party/rust:unwind",
        ":reverie",
        ":safeptrace",
    ],
)

rust_library(
    name = "reverie-test-support",
    srcs = glob(["reverie-test-support/src/**/*.rs"]),
    features = ["nightly"],
    autocargo = {
        "cargo_toml_config": {
            "package": {
                "version": "0.5.4",
                "description": "Command helpers for generic Reverie conformance tests.",
                "publish": False,
            },
            "features": {
                "nightly": ["reverie-ptrace/nightly"],
            },
            "test": [
                {"name": "basics", "path": "../tests/basics.rs"},
                {"name": "exit", "path": "../tests/exit.rs"},
                {"name": "stat", "path": "../tests/stat.rs"},
                {"name": "vdso", "path": "../tests/vdso.rs"},
                {"name": "inject_then_tail", "path": "../tests/inject_then_tail.rs"},
                {"name": "at_random", "path": "../tests/at_random.rs"},
                {"name": "initial_stack_pointer", "path": "../tests/initial_stack_pointer.rs"},
                {"name": "thread_start", "path": "../tests/thread_start.rs"},
                {"name": "stack", "path": "../tests/stack.rs"},
                {"name": "suppression", "path": "../tests/suppression.rs"},
            ],
            "bin": [
                {"name": "stat-rust-command-guest", "path": "../tests/fixtures/stat-rust-command.rs", "test": False, "bench": False},
            {
                "name": "exit-rust-command-guest",
                "path": "../tests/fixtures/exit-rust-command.rs",
                "test": False,
                "bench": False,
            }, {
                "name": "basics-rust-command-guest",
                "path": "../tests/fixtures/basics-rust-command.rs",
                "test": False,
                "bench": False,
            }, {
                "name": "vdso-rust-command-guest",
                "path": "../tests/fixtures/vdso-rust-command.rs",
                "test": False,
                "bench": False,
            }, {
                "name": "inject-then-tail-rust-command-guest",
                "path": "../tests/fixtures/inject-then-tail-rust-command.rs",
                "test": False,
                "bench": False,
            }, {
                "name": "at-random-rust-command-guest",
                "path": "../tests/fixtures/at-random-rust-command.rs",
                "test": False,
                "bench": False,
            }, {
                "name": "thread-start-rust-command-guest",
                "path": "../tests/fixtures/thread-start-rust-command.rs",
                "test": False,
                "bench": False,
            }, {
                "name": "stack-rust-command-guest",
                "path": "../tests/fixtures/stack-rust-command.rs",
                "test": False,
                "bench": False,
            }, {
                "name": "suppression-rust-command-guest",
                "path": "../tests/fixtures/suppression-rust-command.rs",
                "test": False,
                "bench": False,
            }],
            "dependencies_override": {
                "dependencies": {
                    "nix": {"features": ["fs", "process", "signal"]},
                },
                "dev-dependencies": {
                    "serde": {"features": ["derive"]},
                },
            },
            "lints": {
                "rust": {
                    "unexpected_cfgs": {
                        "check-cfg": ["cfg(sanitized)"],
                        "level": "warn",
                    },
                },
            },
        },
        "cargo_toml_dir": "reverie-test-support",
    },
    test_deps = [
        "fbsource//third-party/rust:close-err",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:tempfile",
        "fbsource//third-party/rust:tracing",
        ":reverie-ptrace",
    ],
    deps = [
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:nix",
        "fbsource//third-party/rust:syscalls",
        ":reverie",
        ":reverie-ptrace",
    ],
)

# First-party command guests: explicit native producers for the same Cargo bin entries.
# env below is compile-time rustc input (env!), not a guessed runtime path.

rust_binary(
    name = "basics-rust-command-guest",
    srcs = [
        "tests/fixtures/basics-rust-command.rs",
        "tests/support/basics_rust_guest.rs",
    ],
    crate_root = "tests/fixtures/basics-rust-command.rs",
    unittests = False,
    deps = [
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:nix",
    ],
)

rust_binary(
    name = "exit-rust-command-guest",
    srcs = [
        "tests/fixtures/exit-rust-command.rs",
        "tests/support/exit_rust_guest.rs",
    ],
    crate_root = "tests/fixtures/exit-rust-command.rs",
    unittests = False,
    deps = [
        "fbsource//third-party/rust:libc",
    ],
)

rust_binary(
    name = "stat-rust-command-guest",
    srcs = [
        "tests/fixtures/stat-rust-command.rs",
        "tests/support/stat_rust_guest.rs",
    ],
    crate_root = "tests/fixtures/stat-rust-command.rs",
    unittests = False,
    deps = [
        "fbsource//third-party/rust:libc",
    ],
)

rust_binary(
    name = "vdso-rust-command-guest",
    srcs = [
        "tests/fixtures/vdso-rust-command.rs",
        "tests/support/vdso_rust_guest.rs",
    ],
    crate_root = "tests/fixtures/vdso-rust-command.rs",
    unittests = False,
    deps = [
        "fbsource//third-party/rust:libc",
    ],
)

rust_binary(
    name = "inject-then-tail-rust-command-guest",
    srcs = [
        "tests/fixtures/inject-then-tail-rust-command.rs",
        "tests/support/inject_then_tail_rust_guest.rs",
        "tests/tool_fixtures/inject_then_tail_constants.rs",
    ],
    crate_root = "tests/fixtures/inject-then-tail-rust-command.rs",
    unittests = False,
    deps = [
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:nix",
        ":reverie",
    ],
)

rust_binary(
    name = "at-random-rust-command-guest",
    srcs = [
        "tests/fixtures/at-random-rust-command.rs",
        "tests/support/at_random_rust_guest.rs",
        "tests/tool_fixtures/at_random_constants.rs",
    ],
    crate_root = "tests/fixtures/at-random-rust-command.rs",
    unittests = False,
    deps = [
        "fbsource//third-party/rust:libc",
    ],
)

rust_binary(
    name = "stack-rust-command-guest",
    srcs = [
        "tests/fixtures/stack-rust-command.rs",
        "tests/support/stack_rust_guest.rs",
    ],
    crate_root = "tests/fixtures/stack-rust-command.rs",
    unittests = False,
    deps = [
        "fbsource//third-party/rust:libc",
    ],
)

rust_binary(
    name = "thread-start-rust-command-guest",
    srcs = [
        "tests/fixtures/thread-start-rust-command.rs",
        "tests/support/thread_start_guest.rs",
    ],
    crate_root = "tests/fixtures/thread-start-rust-command.rs",
    unittests = False,
    deps = [],
)

rust_binary(
    name = "suppression-rust-command-guest",
    srcs = [
        "tests/fixtures/suppression-rust-command.rs",
        "tests/support/suppression_rust_guest.rs",
    ],
    crate_root = "tests/fixtures/suppression-rust-command.rs",
    unittests = False,
    deps = [
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:syscalls",
    ],
)

rust_unittest(
    name = "generic-basics",
    srcs = [
        "tests/basics.rs",
        "tests/support/basics_commands.rs",
        "tests/support/basics_rust_guest.rs",
        "tests/tool_fixtures/basics.rs",
    ],
    crate_root = "tests/basics.rs",
    features = ["nightly"],
    rustc_flags = sanitized_feature,
    env = {
        "CARGO_BIN_EXE_basics-rust-command-guest": "$(location :basics-rust-command-guest)",
    },
    deps = [
        "fbsource//third-party/rust:close-err",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:nix",
        "fbsource//third-party/rust:serde",
        ":reverie",
        ":reverie-ptrace",
        ":reverie-test-support",
    ],
)

rust_unittest(
    name = "generic-exit",
    srcs = [
        "tests/exit.rs",
        "tests/fixtures/exit-command.S",
        "tests/support/exit_command.rs",
        "tests/support/exit_rust_guest.rs",
        "tests/tool_fixtures/exit.rs",
    ],
    crate_root = "tests/exit.rs",
    rustc_flags = sanitized_feature,
    env = {
        "CARGO_BIN_EXE_exit-rust-command-guest": "$(location :exit-rust-command-guest)",
    },
    deps = [
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:tempfile",
        ":reverie",
        ":reverie-ptrace",
        ":reverie-test-support",
    ],
)

rust_unittest(
    name = "generic-stat",
    srcs = [
        "tests/stat.rs",
        "tests/fixtures/stat-command.c",
        "tests/fixtures/statx-command.c",
        "tests/support/stat_command.rs",
        "tests/support/stat_rust_guest.rs",
        "tests/tool_fixtures/stat.rs",
    ],
    crate_root = "tests/stat.rs",
    rustc_flags = sanitized_feature,
    env = {
        "CARGO_BIN_EXE_stat-rust-command-guest": "$(location :stat-rust-command-guest)",
    },
    deps = [
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:tempfile",
        ":reverie",
        ":reverie-ptrace",
        ":reverie-test-support",
    ],
)

rust_unittest(
    name = "generic-vdso",
    srcs = [
        "tests/vdso.rs",
        "tests/fixtures/vdso-command.c",
        "tests/support/vdso_command.rs",
        "tests/support/vdso_rust_guest.rs",
        "tests/tool_fixtures/vdso.rs",
    ],
    crate_root = "tests/vdso.rs",
    rustc_flags = sanitized_feature,
    env = {
        "CARGO_BIN_EXE_vdso-rust-command-guest": "$(location :vdso-rust-command-guest)",
    },
    deps = [
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:tempfile",
        ":reverie",
        ":reverie-ptrace",
        ":reverie-test-support",
    ],
)

rust_unittest(
    name = "generic-inject-then-tail",
    srcs = [
        "tests/inject_then_tail.rs",
        "tests/fixtures/inject-then-tail-command.c",
        "tests/support/inject_then_tail_command.rs",
        "tests/tool_fixtures/inject_then_tail.rs",
        "tests/tool_fixtures/inject_then_tail_constants.rs",
    ],
    crate_root = "tests/inject_then_tail.rs",
    rustc_flags = sanitized_feature,
    env = {
        "CARGO_BIN_EXE_inject-then-tail-rust-command-guest": "$(location :inject-then-tail-rust-command-guest)",
    },
    deps = [
        "fbsource//third-party/rust:tempfile",
        "fbsource//third-party/rust:tracing",
        ":reverie",
        ":reverie-test-support",
    ],
)

rust_unittest(
    name = "generic-thread-start",
    srcs = [
        "tests/thread_start.rs",
        "tests/support/thread_start_guest.rs",
        "tests/tool_fixtures/thread_start.rs",
        "tests/tool_fixtures/thread_start_tail.rs",
        "tests/tool_fixtures/thread_start_tail_witness.rs",
    ],
    crate_root = "tests/thread_start.rs",
    rustc_flags = sanitized_feature,
    env = {
        "CARGO_BIN_EXE_thread-start-rust-command-guest": "$(location :thread-start-rust-command-guest)",
    },
    deps = [
        ":reverie",
        ":reverie-ptrace",
        ":reverie-test-support",
    ],
)

rust_unittest(
    name = "generic-initial-stack-pointer",
    srcs = [
        "tests/initial_stack_pointer.rs",
        "tests/tool_fixtures/initial_stack_pointer.rs",
    ],
    crate_root = "tests/initial_stack_pointer.rs",
    rustc_flags = sanitized_feature,
    deps = [
        "fbsource//third-party/rust:serde",
        ":reverie",
        ":reverie-test-support",
    ],
)

rust_unittest(
    name = "generic-at-random",
    srcs = [
        "tests/at_random.rs",
        "tests/fixtures/at-random-command.c",
        "tests/support/at_random_command.rs",
        "tests/tool_fixtures/at_random.rs",
        "tests/tool_fixtures/at_random_constants.rs",
    ],
    crate_root = "tests/at_random.rs",
    rustc_flags = sanitized_feature,
    env = {
        "CARGO_BIN_EXE_at-random-rust-command-guest": "$(location :at-random-rust-command-guest)",
    },
    deps = [
        "fbsource//third-party/rust:tempfile",
        ":reverie",
        ":reverie-test-support",
    ],
)

rust_unittest(
    name = "generic-stack",
    srcs = [
        "tests/stack.rs",
        "tests/support/stack_rust_guest.rs",
        "tests/tool_fixtures/stack.rs",
    ],
    crate_root = "tests/stack.rs",
    rustc_flags = sanitized_feature,
    env = {
        "CARGO_BIN_EXE_stack-rust-command-guest": "$(location :stack-rust-command-guest)",
    },
    deps = [
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:nix",
        ":reverie",
        ":reverie-ptrace",
        ":reverie-test-support",
    ],
)

rust_unittest(
    name = "generic-suppression",
    srcs = [
        "tests/suppression.rs",
        "tests/support/suppression_rust_guest.rs",
        "tests/tool_fixtures/suppression.rs",
    ],
    crate_root = "tests/suppression.rs",
    rustc_flags = sanitized_feature,
    env = {
        "CARGO_BIN_EXE_suppression-rust-command-guest": "$(location :suppression-rust-command-guest)",
    },
    deps = [
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:syscalls",
        ":reverie",
        ":reverie-ptrace",
        ":reverie-test-support",
    ],
)

rust_library(
    name = "reverie-syscalls",
    srcs = glob(["reverie-syscalls/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-syscalls"),
            "dependencies_override": {
                "dependencies": {
                    "linux-raw-sys": {"default-features": False, "features": ["std", "general", "system", "net"]},
                    "bitflags": {
                        "features": [
                            "serde",
                        ]
                    },
                },
            },
        },
        "cargo_toml_dir": "reverie-syscalls",
    },
    deps = [
        "fbsource//third-party/rust:bitflags",
        "fbsource//third-party/rust:derive_more",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:linux-raw-sys",
        "fbsource//third-party/rust:nix",
        "fbsource//third-party/rust:paste",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:syscalls",
        ":reverie-memory",
    ],
)

rust_library(
    name = "reverie-memory",
    srcs = glob(["reverie-memory/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-memory"),
        },
        "cargo_toml_dir": "reverie-memory",
    },
    deps = [
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:syscalls",
    ],
)

rust_library(
    name = "reverie-rpc-transport",
    srcs = glob(["reverie-rpc-transport/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-rpc-transport"),
        },
        "cargo_toml_dir": "reverie-rpc-transport",
    },
    test_deps = [
        "fbsource//third-party/rust:tokio",
    ],
    deps = [
        "fbsource//third-party/rust:async-trait",
        "fbsource//third-party/rust:bincode",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:sha2",
        "fbsource//third-party/rust:thiserror",
        "fbsource//third-party/rust:tokio",
        ":reverie",
    ],
)

rust_library(
    name = "reverie-loader",
    srcs = glob(["reverie-loader/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": {
                "version": "0.5.4",
                "description": "Hermit's in-guest loader: validation of the fixed-address loader and runtime images, and the loader's initialization stages.",
                "publish": False,
            },
        },
        "cargo_toml_dir": "reverie-loader",
    },
    deps = [],
)

rust_library(
    name = "reverie-inguest",
    srcs = glob(
        ["reverie-inguest/src/**/*.rs"],
        exclude = ["reverie-inguest/src/bin/**"],
    ),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-inguest"),
            "dependencies_override": {
                "dependencies": {
                    "nix": {"optional": True, "features": ["fs", "process", "signal"]},
                    "reverie-loader": {"optional": True},
                    "reverie-memory": {"optional": True},
                    "safeptrace": {"optional": True, "features": ["memory", "notifier"]},
                    "tempfile": {"optional": True},
                    "tokio": {"optional": True, "features": ["macros", "net", "rt", "time"]},
                    "tracing": {"optional": True},
                },
                "dev-dependencies": {
                    "iced-x86": {"default-features": False, "features": ["std", "decoder"]},
                    "tokio": {"features": ["test-util"]},
                },
            },
            "features": {
                "coordinator-rpc": [
                    "serde",
                    "bincode",
                    "reverie",
                    "reverie-rpc-transport",
                ],
                "default": ["preload-constructor"],
                "exec-stop": ["launcher", "dep:reverie-loader", "dep:safeptrace", "dep:reverie-memory", "dep:nix"],
                "fixed-syscall-gates": [],
                "exec-private-init": ["fixed-syscall-gates"],
                "loader-private-runtime": ["exec-private-init", "dep:reverie-loader"],
                "launcher": ["coordinator-rpc", "dep:tempfile", "dep:tokio", "dep:tracing"],
                "preload-constructor": [],
                "rcb-clock": [
                    "reverie",
                ],
            },
        },
        "cargo_toml_dir": "reverie-inguest",
    },
    features = [
        "coordinator-rpc",
        "exec-stop",
        "exec-private-init",
        "fixed-syscall-gates",
        "launcher",
        "loader-private-runtime",
        "rcb-clock",
    ],
    test_deps = [
        "fbsource//third-party/rust:iced-x86",
        "fbsource//third-party/rust:tokio",
        "fbsource//third-party/rust:tracing-subscriber",
    ],
    deps = [
        "fbsource//third-party/rust:bincode",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:nix",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:syscalls",
        "fbsource//third-party/rust:tempfile",
        "fbsource//third-party/rust:tokio",
        "fbsource//third-party/rust:tracing",
        ":reverie",
        ":reverie-loader",
        ":reverie-memory",
        ":reverie-rpc-transport",
        ":reverie-syscalls",
        ":safeptrace",
    ],
)

rust_library(
    name = "reverie-liteinst",
    srcs = glob(["reverie-liteinst/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-liteinst"),
            "features": {
                "default": ["preload-constructor"],
                "preload-constructor": [],
            },
        },
        "cargo_toml_dir": "reverie-liteinst",
    },
    test_deps = [
        "fbsource//third-party/rust:tracing-subscriber",
    ],
    deps = [
        "fbsource//third-party/rust:bincode",
        "fbsource//third-party/rust:iced-x86",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:liteinst",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:tempfile",
        "fbsource//third-party/rust:tokio",
        "fbsource//third-party/rust:tracing",
        ":reverie",
        ":reverie-inguest",
        ":reverie-rpc-transport",
    ],
)

rust_library(
    name = "reverie-kvm-core",
    srcs = glob(["reverie-kvm-core/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-kvm-core"),
            "features": {
                "default": [],
                "native-test-support": [],
                "test-support": [],
            },
            "lints": {
                "rust": {
                    "unexpected_cfgs": {
                        "check-cfg": ["cfg(reverie_kvm_scratch_probe)"],
                        "level": "warn",
                    },
                },
            },
        },
        "cargo_toml_dir": "reverie-kvm-core",
    },
    deps = [
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:kvm-bindings",
        "fbsource//third-party/rust:kvm-ioctls",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:thiserror",
        ":reverie",
    ],
)

rust_library(
    name = "reverie-linux-provider",
    srcs = glob(["reverie-linux-provider/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-linux-provider"),
        },
        "cargo_toml_dir": "reverie-linux-provider",
    },
    deps = [
        ":reverie",
    ],
)

fb_native.cxx_library(
    name = "reverie-linuxemu-terminal-read",
    srcs = ["reverie-linuxemu/src/terminal_read.c"],
    headers = {"terminal_read.h": "reverie-linuxemu/src/terminal_read.h"},
    compiler_flags = ["-std=c11", "-pthread", "-fexceptions"],
    exported_linker_flags = ["-pthread"],
)

rust_library(
    name = "reverie-linuxemu",
    srcs = glob(["reverie-linuxemu/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-linuxemu", build = "build.rs"),
            "dependencies_override": {
                "build-dependencies": {"cc": {"version": "1.5.1"}},
                "dev-dependencies": {"reverie-kvm-core": {"features": ["test-support"]}},
            },
            "features": {
                "default": [],
                "native-test-support": ["reverie-kvm-core/native-test-support"],
                "test-support": ["reverie-kvm-core/test-support"],
            },
        },
        "cargo_toml_dir": "reverie-linuxemu",
    },
    deps = [
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:kvm-bindings",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:thiserror",
        ":reverie",
        ":reverie-kvm-core",
        ":reverie-linuxemu-terminal-read",
    ],
)

rust_library(
    name = "reverie-kvm",
    srcs = glob(["reverie-kvm/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-kvm"),
            "dependencies_override": {
                "dev-dependencies": {
                    "reverie-kvm-core": {"features": ["test-support"]},
                    "reverie-linuxemu": {"features": ["test-support"]},
                },
            },
            "features": {
                "default": [],
                "native-test-support": [
                    "reverie-kvm-core/native-test-support",
                    "reverie-linuxemu/native-test-support",
                ],
            },
        },
        "cargo_toml_dir": "reverie-kvm",
    },
    deps = [
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:iced-x86",
        "fbsource//third-party/rust:kvm-bindings",
        "fbsource//third-party/rust:kvm-ioctls",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:perf-event-open-sys",
        "fbsource//third-party/rust:thiserror",
        ":reverie",
        ":reverie-kvm-core",
        ":reverie-linuxemu",
    ],
)

rust_library(
    name = "safeptrace",
    srcs = glob(["safeptrace/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/safeptrace"),
            "features": {
                "default": [],
                "memory": ["reverie-memory"],
                "notifier": [],
            },
            "lints": {
                "rust": {
                    "unexpected_cfgs": {
                        "check-cfg": ["cfg(sanitized)"],
                        "level": "warn",
                    },
                },
            },
        },
        "cargo_toml_dir": "safeptrace",
    },
    features = [
        "notifier",
        "memory",
    ],
    test_deps = [
        "fbsource//third-party/rust:quickcheck",
        "fbsource//third-party/rust:quickcheck_macros",
        "fbsource//third-party/rust:tokio",
    ],
    test_rustc_flags = sanitized_feature,
    deps = [
        "fbsource//third-party/rust:bitflags",
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:nix",
        "fbsource//third-party/rust:parking_lot",
        "fbsource//third-party/rust:syscalls",
        "fbsource//third-party/rust:thiserror",
        ":reverie-memory",
        ":reverie-process",
    ],
)

