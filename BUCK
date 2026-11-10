load(
    "@fbcode//hermetic_infra/reverie/fb-only:defs.bzl",
    "DOWNSTREAM_TEST_VISIBILITY",
    "downstream_source_exports",
    "excluded_paths_test",
    "gated_test",
    "run_gated_only",
)
load("@fbcode//hermetic_infra/reverie/fb-only/rpc_compat:defs.bzl", "rpc_transport_library")
load("@fbcode_macros//build_defs:cpp_library.bzl", "cpp_library")
load("@fbcode_macros//build_defs:native_rules.bzl", "buck_filegroup")
load("@fbcode_macros//build_defs:sanitizers.bzl", "sanitizers")
load("@fbsource//tools/build_defs:rust_binary.bzl", "rust_binary")
load("@fbsource//tools/build_defs:rust_library.bzl", "rust_library")
load("@fbsource//tools/build_defs:rust_unittest.bzl", "rust_unittest")
load("@fbsource//tools/build_defs:selects.bzl", "selects")

oncall("hermit")

# Fails if an upstream path that is never imported (see the list) is present.
excluded_paths_test()

# Reverie sources that a downstream user's integration tests include by path.
downstream_source_exports()

# Some tests don't work when a sanitizer is in use (i.e., with @mode/dev). This
# makes it easy to conditionally compile them with `#[cfg(not(sanitized))]`.
sanitized_feature = selects.apply(
    sanitizers.get_sanitizer_v2(),
    lambda san: ["--cfg=sanitized"] if san else [],
)

# The AddressSanitizer runtime only: the sanitizers whose link flags include
# -fsanitize=address (sanitizers.bzl decides ASAN_OPTIONS for exactly these).
# get_sanitizer_v2() is None when default_asan_ubsan[disabled] turns dev's
# default ASan off. ASan's fixed shadow reservation [0x7fff7000,
# 0x10007fff8000) and its pthread_create interceptor, which holds a lock across
# clone3, make ten Reverie tests infeasible; `#[cfg_attr(reverie_asan, ignore)]`
# names the mechanism on each, and their feasible assertions run in separate
# tests in every mode.
reverie_asan_feature = selects.apply(
    sanitizers.get_sanitizer_v2(),
    lambda san: (
        ["--cfg=reverie_asan"]
        if san
        in [
            "address",
            "address-undefined",
            "address-undefined-dev",
            "more-address-undefined-leak",
        ]
        else []
    ),
)

rust_library(
    name = "reverie",
    srcs = glob(["reverie/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "features": {
                "default": [],
                "perf-fixture": [],
            },
            "package": {
                "description": "Deterministic user-space syscall and signal interception runtime — the core Reverie process-instrumentation framework.",
                "name": "reverie-core",
            },
        },
        "cargo_toml_dir": "reverie",
    },
    test_deps = [
        "fbsource//third-party/rust:serde_json",
        "fbsource//third-party/rust:tracing-subscriber",
    ],
    # Run by :reverie-unittest-gated (fb-only/gated_tests).
    test_labels = run_gated_only(),
    test_rustc_flags = sanitized_feature,
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

gated_test(
    name = "reverie-unittest-gated",
    test = "//hermetic_infra/reverie:reverie-unittest",
)

# reverie with upstream's `perf-fixture` feature, as reverie-ptrace's Cargo
# dev-dependency declares it. Only :reverie-ptrace-unittest uses it.
rust_library(
    name = "reverie-perf-fixture",
    srcs = glob(["reverie/src/**/*.rs"]),
    autocargo = {"ignore_rule": True},
    crate = "reverie",
    crate_root = "reverie/src/lib.rs",
    features = ["perf-fixture"],
    unittests = False,
    visibility = [":reverie-ptrace-unittest"],
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
                        "check-cfg": [
                            "cfg(reverie_asan)",
                            "cfg(sanitized)",
                        ],
                        "level": "warn",
                    },
                },
            },
            "package": {
                "description": "Deterministic async process spawning and management for the Reverie framework.",
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
    # Run by :reverie-process-unittest-gated (fb-only/gated_tests).
    test_labels = run_gated_only(),
    test_rustc_flags = sanitized_feature + reverie_asan_feature,
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

gated_test(
    name = "reverie-process-unittest-gated",
    env = {},
    test = "//hermetic_infra/reverie:reverie-process-unittest",
)

# Command helpers for Reverie's generic conformance tests (tests/BUCK).
rust_library(
    name = "reverie-test-support",
    srcs = glob(["reverie-test-support/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "features": {
                "nightly": ["reverie-ptrace/nightly"],
            },
            "package": {
                "description": "Command helpers for generic Reverie conformance tests.",
                "publish": False,
            },
        },
        "cargo_toml_dir": "reverie-test-support",
    },
    features = ["nightly"],
    named_deps = {"reverie": ":reverie"},
    deps = [
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:nix",
        "fbsource//third-party/rust:syscalls",
        ":reverie-ptrace",
    ],
)

rust_library(
    name = "reverie-util",
    srcs = glob(["reverie-util/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": {
                "description": "Shared utility helpers for the Reverie instrumentation framework.",
            },
        },
        "cargo_toml_dir": "reverie-util",
    },
    named_deps = {"reverie": ":reverie"},
    deps = [
        "fbsource//third-party/rust:anyhow",
        "fbsource//third-party/rust:chrono",
        "fbsource//third-party/rust:clap",
        "fbsource//third-party/rust:tracing",
        "fbsource//third-party/rust:tracing-appender",
        "fbsource//third-party/rust:tracing-subscriber",
    ],
)

rust_library(
    name = "reverie-ptrace",
    srcs = glob(["reverie-ptrace/src/**/*.rs"]),
    autocargo = {
        # Cargo keeps running the lib tests; Buck runs them in
        # :reverie-ptrace-unittest.
        "cargo_target_config": {
            "doctest": True,
            "test": True,
        },
        "cargo_toml_config": {
            "dependencies_override": {
                "dependencies": {
                    "safeptrace": {
                        "features": [
                            "notifier",
                            "memory",
                        ]
                    },
                },
                "dev-dependencies": {
                    "reverie": {
                        "features": ["perf-fixture"],
                    },
                },
            },
            # Match upstream's test-only perf feature and native unittest deps.
            "extra_buck_dependencies": {
                "dev-dependencies": [
                    ("reverie", ":reverie"),
                    "fbsource//third-party/rust:goblin",
                    "fbsource//third-party/rust:test-case",
                ],
            },
            "features": {
                "default": [],
                "nightly": [],
                "rcb-observation": [],
            },
            "lints": {
                "rust": {
                    "unexpected_cfgs": {
                        "check-cfg": ["cfg(reverie_asan)"],
                        "level": "warn",
                    },
                },
            },
            "package": {
                # Upstream's build.rs asks pkg-config for libunwind-ptrace's
                # link flags; Buck supplies libunwind, and the fbsource Cargo
                # check doesn't link.
                "build": False,
                "description": "ptrace-based execution backend for the Reverie instrumentation framework.",
            },
        },
        "cargo_toml_dir": "reverie-ptrace",
        "edge_features": [],
    },
    # As upstream's BUCK: clears libtest's thread-local output capture in
    # forked function guests, so their stdout reaches the tracer.
    features = ["nightly"],
    named_deps = {"reverie": ":reverie"},
    # Built by :reverie-ptrace-unittest below, on x86_64 only.
    unittests = False,
    deps = [
        "fbsource//third-party/libunwind:unwind-ptrace",  # Used for getting remote backtraces.
        "fbsource//third-party/rust:anyhow",
        "fbsource//third-party/rust:async-trait",
        "fbsource//third-party/rust:bincode",
        "fbsource//third-party/rust:bytes",
        "fbsource//third-party/rust:close-err",
        "fbsource//third-party/rust:futures",
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
        ":safeptrace",
    ],
)

# The library's unit tests. Upstream runs them on x86_64 only: several use
# x86_64-only syscalls (libc::SYS_pause has no aarch64 number), so they don't
# build for aarch64. The library itself still builds everywhere.
rust_unittest(
    name = "reverie-ptrace-unittest",
    srcs = glob([
        "reverie-ptrace/src/**/*.rs",
        "reverie-ptrace/tests/sigtrap_steps/**/*.rs",
    ])
    + [
        "reverie-ptrace/tests/fixtures/ptrace_seccomp_filter_all_syscalls.txt",
        "reverie-ptrace/tests/fixtures/ptrace_seccomp_filter_no_syscalls.txt",
    ],
    autocargo = {"ignore_rule": True},
    crate = "reverie_ptrace",
    crate_root = "reverie-ptrace/src/lib.rs",
    env = {
        # Disable leak detection for the `exit_status::test::propagate_exit`
        # test. The test does an early exit post-fork which invokes the ASAN
        # atexit handler code. The Rust test harness never has a chance to
        # deallocate its own stuff, so the ASAN atexit handler produces the
        # wrong exit code and thus causes the test to fail.
        "ASAN_OPTIONS": "detect_leaks=0",
        "CARGO_MANIFEST_DIR": "$(location :ptrace-test-fixtures)",
    },
    features = ["nightly"],
    # Run by :reverie-ptrace-unittest-gated (fb-only/gated_tests).
    labels = run_gated_only(),
    named_deps = {"reverie": ":reverie-perf-fixture"},
    resources = [":ptrace-test-fixtures"],
    # Keep runtime env! paths project-relative across remote compilation.
    # rustc_action applies --env-set after canonicalizing path environment.
    rustc_flags = sanitized_feature
    + reverie_asan_feature
    + [
        "--env-set=CARGO_MANIFEST_DIR=$(location :ptrace-test-fixtures)",
    ],
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
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
        "fbsource//third-party/rust:test-case",
        "fbsource//third-party/rust:thiserror",
        "fbsource//third-party/rust:tokio",
        "fbsource//third-party/rust:tokio-stream",
        "fbsource//third-party/rust:tracing",
        "fbsource//third-party/rust:tracing-subscriber",
        "fbsource//third-party/rust:unwind",
        ":safeptrace",
    ],
)

gated_test(
    name = "reverie-ptrace-unittest-gated",
    env = {
        "ASAN_OPTIONS": "detect_leaks=0",
        "CARGO_MANIFEST_DIR": "$(location :ptrace-test-fixtures)",
    },
    labels = ["buck2_run_from_project_root"],
    test = "//hermetic_infra/reverie:reverie-ptrace-unittest",
)

rust_library(
    name = "reverie-syscalls",
    srcs = glob(["reverie-syscalls/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "dependencies_override": {
                "dependencies": {
                    "bitflags": {
                        "features": [
                            "serde",
                        ]
                    },
                    "linux-raw-sys": {
                        "features": [
                            "general",
                            "net",
                            "no_std",
                        ],
                    },
                },
            },
            "package": {
                "description": "Strongly-typed Linux syscall representations and (de)serialization for the Reverie framework.",
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
            "package": {
                "description": "Guest-memory access primitives for the Reverie instrumentation framework.",
            },
        },
        "cargo_toml_dir": "reverie-memory",
    },
    test_deps = ["fbsource//third-party/rust:libc"],
    deps = [
        "fbsource//third-party/rust:syscalls",
    ],
)

rust_library(
    name = "safeptrace",
    srcs = glob(["safeptrace/src/**/*.rs"]) + ["safeptrace/src/retired_tid_fixture.c"],
    autocargo = {
        "cargo_toml_config": {
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
            "package": {
                "description": "Safe, ergonomic Rust wrappers around the Linux ptrace(2) API.",
            },
        },
        "cargo_toml_dir": "safeptrace",
    },
    features = [
        "notifier",
        "memory",
    ],
    test_deps = [
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:quickcheck",
        "fbsource//third-party/rust:quickcheck_macros",
        "fbsource//third-party/rust:tokio",
    ],
    # Run by :safeptrace-unittest-gated (fb-only/gated_tests).
    test_labels = run_gated_only(),
    test_rustc_flags = sanitized_feature,
    deps = [
        "fbsource//third-party/rust:bitflags",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:nix",
        "fbsource//third-party/rust:parking_lot",
        "fbsource//third-party/rust:syscalls",
        "fbsource//third-party/rust:thiserror",
        ":reverie-memory",
        ":reverie-process",
    ],
)

gated_test(
    name = "safeptrace-unittest-gated",
    env = {},
    test = "//hermetic_infra/reverie:safeptrace-unittest",
)

cpp_library(
    name = "reverie-linuxemu-terminal-read",
    srcs = ["reverie-linuxemu/src/terminal_read.c"],
    headers = ["reverie-linuxemu/src/terminal_read.h"],
    compiler_flags = ["-std=c11", "-pthread", "-fexceptions"],
    exported_linker_flags = ["-pthread"],
)

rust_library(
    name = "reverie-linuxemu",
    srcs = glob([
        "reverie-linuxemu/src/**/*.rs",
        # src/lib.rs path-includes the shared broker test adapter in its tests.
        "reverie-linuxemu/tests/support/**/*.rs",
    ]),
    autocargo = {
        "cargo_toml_config": {
            # Buck compiles terminal_read.c through
            # :reverie-linuxemu-terminal-read; only Cargo runs build.rs.
            "extra_buck_dependencies": {
                "build-dependencies": [
                    "fbsource//third-party/rust:cc",
                ],
            },
            "features": {
                "default": [],
                "native-test-support": [],
                "test-support": [],
            },
            "package": {
                "build": "build.rs",
                "description": "Linux syscall emulation for the Reverie KVM backend.",
            },
        },
        "cargo_toml_dir": "reverie-linuxemu",
    },
    named_deps = {"reverie": ":reverie"},
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    # Built by :reverie-linuxemu-unittest, against the test-support variant.
    unittests = False,
    deps = [
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:kvm-bindings",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:thiserror",
        "fbsource//third-party/rust:tracing",
        ":reverie-kvm-core",
        ":reverie-linuxemu-terminal-read",
    ],
)

rust_library(
    name = "reverie-kvm",
    srcs = glob([
        "reverie-kvm/src/**/*.rs",
        # src/lib.rs path-includes reverie-linuxemu's broker test adapter.
        "reverie-linuxemu/tests/support/**/*.rs",
    ]),
    autocargo = {
        "cargo_toml_config": {
            "dependencies_override": {
                "dependencies": {
                    "futures": {
                        "features": [
                            "async-await",
                        ],
                    },
                    "goblin": {
                        "features": [
                            "elf32",
                            "elf64",
                            "endian_fd",
                        ],
                    },
                },
            },
            "features": {
                "default": [],
                "native-test-support": [],
            },
            "lints": {
                "rust": {
                    "unexpected_cfgs": {
                        "check-cfg": ["cfg(reverie_kvm_scratch_probe)"],
                        "level": "warn",
                    },
                },
            },
            "package": {
                "description": "KVM-based execution backend for the Reverie instrumentation framework.",
            },
        },
        "cargo_toml_dir": "reverie-kvm",
        "edge_features": [],
    },
    features = [],
    named_deps = {"reverie": ":reverie"},
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    # Built by :reverie-kvm-unittest, against the test-support variants.
    unittests = False,
    deps = [
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:iced-x86",
        "fbsource//third-party/rust:kvm-bindings",
        "fbsource//third-party/rust:kvm-ioctls",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:perf-event-open-sys",
        "fbsource//third-party/rust:thiserror",
        ":reverie-kvm-core",
        ":reverie-linuxemu",
    ],
)

# Upstream's KVM unit tests use helpers that reverie-kvm-core and
# reverie-linuxemu compile only for their own tests or under `test-support`,
# which Cargo turns on through reverie-kvm's dev-dependencies. Buck builds a
# crate once, so the unit tests link these variants instead.
rust_library(
    name = "reverie-kvm-core-test-support",
    srcs = glob([
        "reverie-kvm-core/src/**/*.rs",
        "reverie-kvm-core/tests/**",
    ]),
    autocargo = {"ignore_rule": True},
    crate = "reverie_kvm_core",
    crate_root = "reverie-kvm-core/src/lib.rs",
    features = ["test-support"],
    named_deps = {"reverie": ":reverie"},
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    unittests = False,
    deps = [
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:kvm-bindings",
        "fbsource//third-party/rust:kvm-ioctls",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:thiserror",
    ],
)

rust_library(
    name = "reverie-linuxemu-test-support",
    srcs = glob([
        "reverie-linuxemu/src/**/*.rs",
        "reverie-linuxemu/tests/support/**/*.rs",
    ]),
    autocargo = {"ignore_rule": True},
    crate = "reverie_linuxemu",
    crate_root = "reverie-linuxemu/src/lib.rs",
    features = ["test-support"],
    named_deps = {"reverie": ":reverie"},
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    unittests = False,
    deps = [
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:kvm-bindings",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:thiserror",
        "fbsource//third-party/rust:tracing",
        ":reverie-kvm-core-test-support",  # @manual name:reverie_kvm_core
        ":reverie-linuxemu-terminal-read",
    ],
)

rust_unittest(
    name = "reverie-kvm-unittest",
    srcs = glob([
        "reverie-kvm/src/**/*.rs",
        "reverie-kvm/tests/fixtures/**",
        "reverie-kvm/tests/support/**/*.rs",
        "reverie-linuxemu/tests/support/**/*.rs",
    ]),
    autocargo = {"ignore_rule": True},
    crate = "reverie_kvm",
    crate_root = "reverie-kvm/src/lib.rs",
    env = {
        "CARGO_MANIFEST_DIR": "$(location :kvm-signal-abi-fixtures)",
        "CARGO_PKG_NAME": "reverie-kvm",
    },
    # Run by :reverie-kvm-unittest-gated (fb-only/gated_tests).
    labels = run_gated_only(),
    named_deps = {"reverie": ":reverie"},
    resources = [
        ":kvm-signal-abi-fixtures",
        ":reverie-kvm-broker-test-launcher",
    ],
    run_env = {
        "REVERIE_KVM_SIGNAL_ABI_FIXTURES": "$(location :kvm-signal-abi-fixtures)",
        # The broker-routed library tests re-run themselves under Cargo's
        # ordinary-main launcher bin (tests/support/broker_library_tests.rs).
        "REVERIE_KVM_TEST_BROKER_LAUNCHER": "$(location :reverie-kvm-broker-test-launcher)",
        "REVERIE_REQUIRE_KVM": "1",
    },
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    deps = [
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:iced-x86",
        "fbsource//third-party/rust:io-uring",
        "fbsource//third-party/rust:kvm-bindings",
        "fbsource//third-party/rust:kvm-ioctls",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:perf-event-open-sys",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:thiserror",
        ":reverie-kvm-core-test-support",  # @manual name:reverie_kvm_core
        ":reverie-linuxemu-test-support",
    ],
)

# reverie-linuxemu's own unit tests: CI builds them; they need /dev/kvm and
# upstream's source tree to run, which Cargo provides.
rust_unittest(
    name = "reverie-linuxemu-unittest",
    srcs = glob([
        "reverie-linuxemu/src/**/*.rs",
        "reverie-linuxemu/tests/**",
    ]),
    # The system allocator, as in the Cargo build.
    # host_resources_tests.rs lowers RLIMIT_AS to a margin above the process's
    # address space and expects an exec's 64 MiB image buffer to need new
    # address space. fbcode's default jemalloc keeps the 64 MiB the test freed
    # mapped and hands it back, so the exec fails at a later reservation.
    allocator = "malloc",
    autocargo = {"ignore_rule": True},
    crate = "reverie_linuxemu",
    crate_root = "reverie-linuxemu/src/lib.rs",
    env = {
        "CARGO_MANIFEST_DIR": "hermetic_infra/reverie/reverie-linuxemu",
        "CARGO_PKG_NAME": "reverie-linuxemu",
    },
    labels = run_gated_only(),
    named_deps = {"reverie": ":reverie"},
    resources = [":reverie-kvm-broker-test-launcher"],
    run_env = {
        # The broker-routed library tests re-run themselves under Cargo's
        # ordinary-main launcher bin (tests/support/broker_library_tests.rs).
        "REVERIE_KVM_TEST_BROKER_LAUNCHER": "$(location :reverie-kvm-broker-test-launcher)",
    },
    # vm_flags_tests.rs reads upstream's source tree through env!, the
    # compile-time CARGO_MANIFEST_DIR. rustc_action applies --env-set after
    # canonicalizing path environment, so a remote compile keeps it relative,
    # as the run-time value is.
    rustc_flags = ["--env-set=CARGO_MANIFEST_DIR=hermetic_infra/reverie/reverie-linuxemu"],
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    deps = [
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:kvm-bindings",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:thiserror",
        "fbsource//third-party/rust:tracing",
        ":reverie-kvm-core-test-support",  # @manual name:reverie_kvm_core
        ":reverie-linuxemu-terminal-read",
    ],
)

gated_test(
    name = "reverie-kvm-unittest-gated",
    env = {"CARGO_MANIFEST_DIR": "$(location :kvm-signal-abi-fixtures)"},
    test = "//hermetic_infra/reverie:reverie-kvm-unittest",
)

gated_test(
    name = "reverie-linuxemu-unittest-gated",
    env = {
        "REVERIE_KVM_TEST_BROKER_LAUNCHER": "$(location :reverie-kvm-broker-test-launcher)",
    },
    # Measures the native socket-name copyout order for the two
    # socket_query_copyout_name_* cases (gates.bzl); 0.5.5 moved the executor
    # tests from reverie-kvm into reverie-linuxemu.
    native_abi_probe = True,
    test = "//hermetic_infra/reverie:reverie-linuxemu-unittest",
)

rust_library(
    name = "reverie-kvm-core",
    srcs = glob(["reverie-kvm-core/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": {
                "description": "Lowest layer of the Reverie KVM backend: its error type and guest address map.",
            },
        },
        "cargo_toml_dir": "reverie-kvm-core",
    },
    named_deps = {"reverie": ":reverie"},
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    # src/lib.rs path-includes tests/support/alias_failure.rs in its tests.
    test_srcs = glob(["reverie-kvm-core/tests/**"]),
    deps = [
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:kvm-bindings",
        "fbsource//third-party/rust:kvm-ioctls",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:thiserror",
    ],
)

# The deprecated re-export of reverie::provider, kept for one release
# (reverie-linux-provider/src/lib.rs). Its Cargo manifest is the open-source
# one (oss_cargo), not autocargo's.
rust_library(
    name = "reverie-linux-provider",
    srcs = glob(["reverie-linux-provider/src/**/*.rs"]),
    autocargo = {"ignore_rule": True},
    named_deps = {"reverie": ":reverie"},
)

# Cargo's reverie-kvm-broker-test-launcher bin: the ordinary-main launcher the
# broker-routed tests re-run themselves under.
rust_binary(
    name = "reverie-kvm-broker-test-launcher",
    srcs = glob(["reverie-linuxemu/tests/support/**/*.rs"]),
    autocargo = {"ignore_rule": True},
    crate_root = "reverie-linuxemu/tests/support/broker_test_launcher.rs",
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    deps = [
        "fbsource//third-party/rust:libc",
        ":reverie-linuxemu",
    ],
)

# Native owner for the complete existing Cargo static_elf integration suite.
# Cargo already discovers this test; keep its generated package metadata intact.
rust_unittest(
    name = "reverie-kvm-static-elf-test",
    srcs = [
        "reverie-kvm/tests/static_elf.rs",
    ]
    + glob(["reverie-kvm-core/tests/**"])
    + glob([
        "reverie-kvm/tests/fixtures/**",
        "reverie-kvm/tests/support/**/*.rs",
        "reverie-linuxemu/tests/support/**/*.rs",
    ]),
    autocargo = {"ignore_rule": True},
    crate = "static_elf",
    crate_root = "reverie-kvm/tests/static_elf.rs",
    env = {
        "CARGO_BIN_EXE_reverie-kvm-broker-test-launcher": "$(location :reverie-kvm-broker-test-launcher)",
        "CARGO_MANIFEST_DIR": "$(location :kvm-signal-abi-fixtures)",
    },
    # Run by :reverie-kvm-static-elf-test-gated (fb-only/gated_tests).
    labels = run_gated_only(),
    named_deps = {"reverie": ":reverie"},
    resources = [
        ":kvm-signal-abi-fixtures",
        ":reverie-kvm-broker-test-launcher",
    ],
    run_env = {
        # fbcode's jemalloc starts background threads during a run, and the
        # dropped_public_run_* host-thread census would count them as leftovers.
        "MALLOC_CONF": "background_thread:false",
        "REVERIE_KVM_TEST_BROKER_LAUNCHER": "$(location :reverie-kvm-broker-test-launcher)",
        "REVERIE_REQUIRE_KVM": "1",
    },
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    deps = [
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:kvm-ioctls",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:serde",
        ":reverie-kvm",
        ":reverie-linuxemu",
    ],
)

gated_test(
    name = "reverie-kvm-static-elf-test-gated",
    env = {
        "CARGO_BIN_EXE_reverie-kvm-broker-test-launcher": "$(location :reverie-kvm-broker-test-launcher)",
        "CARGO_MANIFEST_DIR": "$(location :kvm-signal-abi-fixtures)",
        "MALLOC_CONF": "background_thread:false",
        "REVERIE_KVM_TEST_BROKER_LAUNCHER": "$(location :reverie-kvm-broker-test-launcher)",
        "REVERIE_REQUIRE_KVM": "1",
    },
    test = "//hermetic_infra/reverie:reverie-kvm-static-elf-test",
)

rust_library(
    name = "reverie-loader",
    srcs = glob(["reverie-loader/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": {
                "description": "Hermit's in-guest loader: validation of the fixed-address loader and runtime images, and the loader's initialization stages.",
                "publish": False,
            },
        },
        "cargo_toml_dir": "reverie-loader",
    },
)

rust_library(
    name = "reverie-inguest",
    srcs = glob(["reverie-inguest/src/**/*.rs"]) + ["reverie-inguest/src/guest/tool_region_keyed_oracle_probe.S"],
    autocargo = {
        "cargo_target_config": {
            "crate_type": [
                "cdylib",
                "rlib",
            ],
            # Cargo keeps running the lib tests; Buck runs them in
            # :reverie-inguest-unittest.
            "doctest": True,
            "test": True,
        },
        "cargo_toml_config": {
            "bin": [
                {
                    "name": "reverie-inguest-probe",
                    "path": "src/bin/preload_probe.rs",
                },
                {
                    "name": "reverie-inguest-pkey-buffers",
                    "path": "src/bin/pkey_buffers.rs",
                },
                {
                    "name": "reverie-inguest-native-syscall-result",
                    "path": "src/bin/native_syscall_result.rs",
                },
            ],
            "dependencies_override": {
                "dependencies": {
                    "bincode": {
                        "features": [
                            "serde",
                        ],
                        "optional": True,
                    },
                    "nix": {
                        "features": ["fs", "process", "signal"],
                        "optional": True,
                    },
                    "reverie": {
                        "optional": True,
                    },
                    "reverie-loader": {
                        "optional": True,
                    },
                    "reverie-memory": {
                        "optional": True,
                    },
                    "reverie-ptrace": {
                        "optional": True,
                    },
                    "reverie-rpc-transport": {
                        "optional": True,
                    },
                    "safeptrace": {
                        "features": ["memory", "notifier"],
                        "optional": True,
                    },
                    "serde": {
                        "features": [
                            "derive",
                        ],
                        "optional": True,
                    },
                    "tempfile": {
                        "optional": True,
                    },
                    "tokio": {
                        "features": ["macros", "net", "rt", "time"],
                        "optional": True,
                    },
                    "tracing": {
                        "optional": True,
                    },
                },
            },
            # Keep Cargo-only optional launcher dependencies out of the native
            # default-feature library's dependency graph.
            "extra_buck_dependencies": {
                "dependencies": [
                    ("nix", "fbsource//third-party/rust:nix"),
                    ("reverie-loader", ":reverie-loader"),
                    ("reverie-memory", ":reverie-memory"),
                    ("reverie-ptrace", ":reverie-ptrace"),
                    ("safeptrace", ":safeptrace"),
                    ("tempfile", "fbsource//third-party/rust:tempfile"),
                    ("tokio", "fbsource//third-party/rust:tokio"),
                    ("tracing", "fbsource//third-party/rust:tracing"),
                ],
                "dev-dependencies": [
                    "fbsource//third-party/rust:iced-x86",
                ],
            },
            "features": {
                "allocator-fixture": [],
                "coordinator-rpc": [
                    "dep:serde",
                    "dep:bincode",
                    "dep:reverie",
                    "dep:reverie-rpc-transport",
                ],
                "default": [
                    "preload-constructor",
                ],
                # Keep backend feature names declared; Cargo's exec-stop tests
                # require the upstream launcher dependency edges below.
                "exec-native-injection": [],
                "exec-private-init": [
                    "fixed-syscall-gates",
                ],
                "exec-private-successor": [],
                "exec-stop": [
                    "launcher",
                    "dep:reverie-loader",
                    "dep:safeptrace",
                    "dep:reverie-memory",
                    "dep:nix",
                ],
                "fixed-syscall-gates": [],
                "launcher": [
                    "coordinator-rpc",
                    "dep:tempfile",
                    "dep:tokio",
                    "dep:tracing",
                ],
                "loader-private-runtime": [
                    "exec-private-init",
                    "dep:reverie-loader",
                ],
                "native-exec-state": [],
                "native-exec-state-fixture": [],
                "preload-constructor": [],
                "rcb-clock": [
                    "dep:reverie",
                    "dep:reverie-ptrace",
                ],
                "rpc-io-fixture": [],
                "stage1a-probe": [],
            },
            "package": {
                "description": "Shared LD_PRELOAD + seccomp/SIGSYS instrumentation runtime for Reverie in-guest backends (e9patch, LiteInst, SaBRe)",
            },
            "test": [
                {
                    "name": "smoke",
                    "path": "tests/smoke.rs",
                },
                {
                    "name": "pkeys",
                    "path": "tests/pkeys.rs",
                },
            ],
        },
        "cargo_toml_dir": "reverie-inguest",
        "edge_features": [
            "coordinator-rpc",
            "rcb-clock",
        ],
    },
    features = [
        "coordinator-rpc",
        "rcb-clock",
    ],
    named_deps = {"reverie": ":reverie"},
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    # Built by :reverie-inguest-unittest below, with the system allocator.
    unittests = False,
    deps = [
        "fbsource//third-party/rust:bincode",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:syscalls",
        ":reverie-rpc-transport",
        ":reverie-syscalls",
    ],
)

# reverie-inguest as Cargo builds it for a downstream test build that unifies a
# dev-dependency on it (`exec-stop`, which implies `launcher` and
# `coordinator-rpc`) with reverie-liteinst's dependency (`coordinator-rpc`,
# `launcher`, `rcb-clock`) into one crate. Only that test build uses it
# (DOWNSTREAM_TEST_VISIBILITY), directly and through :reverie-liteinst-exec-stop
# below; the libraries above keep fbsource's feature sets. A binary must hold
# one reverie-inguest: two feature variants define its per-image entry symbols
# twice, which a static (opt) link refuses.
rust_library(
    name = "reverie-inguest-exec-stop",
    srcs = glob(["reverie-inguest/src/**/*.rs"]) + ["reverie-inguest/src/guest/tool_region_keyed_oracle_probe.S"],
    autocargo = {"ignore_rule": True},
    crate = "reverie_inguest",
    crate_root = "reverie-inguest/src/lib.rs",
    features = [
        "coordinator-rpc",
        "exec-stop",
        "launcher",
        "rcb-clock",
    ],
    named_deps = {"reverie": ":reverie"},
    # As :reverie-inguest-liteinst: its per-image symbols need a static link.
    preferred_linkage = "static",
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    unittests = False,
    visibility = DOWNSTREAM_TEST_VISIBILITY,
    deps = [
        "fbsource//third-party/rust:bincode",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:nix",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:syscalls",
        "fbsource//third-party/rust:tempfile",
        "fbsource//third-party/rust:tokio",
        "fbsource//third-party/rust:tracing",
        ":reverie-memory",
        ":reverie-rpc-transport",
        ":reverie-syscalls",
        ":safeptrace",
    ],
)

# reverie-inguest with the features reverie-liteinst's Cargo dependency
# declares: `launcher` (which implies `coordinator-rpc`) and `rcb-clock`.
rust_library(
    name = "reverie-inguest-liteinst",
    srcs = glob(["reverie-inguest/src/**/*.rs"]) + ["reverie-inguest/src/guest/tool_region_keyed_oracle_probe.S"],
    autocargo = {"ignore_rule": True},
    crate = "reverie_inguest",
    crate_root = "reverie-inguest/src/lib.rs",
    features = [
        "coordinator-rpc",
        "launcher",
        "rcb-clock",
    ],
    named_deps = {"reverie": ":reverie"},
    # The generic entry and installed-callback symbols are hidden per-image
    # contracts (guest/tool_region_constructor.rs), so a shared object of this
    # library cannot provide them; link it statically into each final image.
    preferred_linkage = "static",
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    unittests = False,
    deps = [
        "fbsource//third-party/rust:bincode",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:syscalls",
        "fbsource//third-party/rust:tempfile",
        "fbsource//third-party/rust:tokio",
        "fbsource//third-party/rust:tracing",
        ":reverie-rpc-transport",
        ":reverie-syscalls",
    ],
)

# The library's unit tests, with the system allocator as in the Cargo build.
# fbcode's default jemalloc starts a background thread that the SIGSYS filter
# under test kills (https://github.com/rrnewton/reverie/issues/867).
rust_unittest(
    name = "reverie-inguest-unittest",
    srcs = glob(["reverie-inguest/src/**/*.rs"]) + ["reverie-inguest/src/guest/tool_region_keyed_oracle_probe.S"],
    allocator = "malloc",
    autocargo = {"ignore_rule": True},
    crate = "reverie_inguest",
    crate_root = "reverie-inguest/src/lib.rs",
    features = [
        "coordinator-rpc",
        "rcb-clock",
    ],
    # A dev-mode shared link maps hundreds of libraries, more than the
    # tool-region tests' bounded /proc/self/maps buffer holds.
    link_style = "static",
    named_deps = {"reverie": ":reverie"},
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    deps = [
        "fbsource//third-party/rust:bincode",
        "fbsource//third-party/rust:iced-x86",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:syscalls",
        "fbsource//third-party/rust:tokio",
        ":reverie-loader",
        ":reverie-ptrace",
        ":reverie-rpc-transport",
        ":reverie-syscalls",
    ],
)

rpc_transport_library(
    name = "reverie-rpc-transport",
    srcs = glob(["reverie-rpc-transport/src/**/*.rs"]),
    autocargo = {
        "cargo_target_config": {"edition": "2021"},
        "cargo_toml_config": {
            "bin": [
                {
                    "name": "mapped_rpc_fork_fixture",
                    "path": "tests/fixtures/mapped_rpc_fork_fixture.rs",
                },
                {
                    "name": "guest_log_lifecycle_fixture",
                    "path": "tests/fixtures/guest_log_lifecycle_fixture.rs",
                },
            ],
            "dependencies_override": {
                "dependencies": {
                    "bincode": {
                        "features": [
                            "serde",
                        ],
                    },
                    "serde": {
                        "features": [
                            "derive",
                        ],
                    },
                    "tokio": {
                        "features": [
                            "io-util",
                            "net",
                            "rt",
                            "sync",
                            "macros",
                        ],
                    },
                },
                "dev-dependencies": {
                    "tokio": {
                        "features": [
                            "full",
                            "test-util",
                        ],
                    },
                },
            },
            "features": {
                "test-guest-log": [],
            },
            "package": {
                "description": "Cross-process transport for the Reverie GlobalTool RPC (Unix-domain sockets + bincode). Shared by non-ptrace backends (DBT, KVM, ...) that must run GlobalState in a separate coordinator process.",
                "edition": "2021",
            },
        },
        "cargo_toml_dir": "reverie-rpc-transport",
        "edge_features": [],
    },
    # Cargo sets this; the guest_log split tests read it with env!.
    env = {"CARGO_CRATE_NAME": "reverie_rpc_transport"},
    features = [],
    named_deps = {"reverie": ":reverie"},
    test_deps = [
        "fbsource//third-party/rust:tokio",
    ],
    deps = [
        "fbsource//third-party/rust:async-trait",
        "fbsource//third-party/rust:bincode",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:sha2-010",
        "fbsource//third-party/rust:thiserror",
        "fbsource//third-party/rust:tokio",
    ],
)

rust_library(
    name = "reverie-liteinst",
    srcs = glob(["reverie-liteinst/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            # The Buck dependency, :reverie-inguest-liteinst, is autocargo's
            # ignore_rule feature variant of reverie-inguest; the Cargo build
            # (fb-only/ci.sh) names the package with the same features.
            "dependencies_override": {
                "dependencies": {
                    "reverie-inguest": {
                        "default-features": False,
                        "features": [
                            "coordinator-rpc",
                            "launcher",
                            "rcb-clock",
                        ],
                    },
                },
            },
            "extra_buck_dependencies": {
                "dependencies": [
                    ("reverie-inguest", "//hermetic_infra/reverie:reverie-inguest"),
                ],
            },
            # Cargo's default `liteinst` feature adds the vendored liteinst
            # crate for site patching; this target builds the crate without it.
            "features": {
                "default": ["preload-constructor"],
                "liteinst": [],
                "preload-constructor": [],
            },
            "package": {
                "description": "Experimental in-process syscall instrumentation for Reverie",
                "documentation": "https://docs.rs/reverie-liteinst",
            },
        },
        "cargo_toml_dir": "reverie-liteinst",
    },
    # selected_backing() reads the hidden descriptor a final image defines
    # with a declare_* macro; a shared link of this library alone cannot
    # resolve that per-image symbol, so link it statically into consumers.
    preferred_linkage = "static",
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    test_deps = [
        "fbsource//third-party/rust:tracing-subscriber",
    ],
    deps = [
        "fbsource//third-party/rust:bincode",
        "fbsource//third-party/rust:iced-x86",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:tempfile",
        "fbsource//third-party/rust:tokio",
        "fbsource//third-party/rust:tracing",
        ":reverie",
        ":reverie-inguest-liteinst",  # @manual name:reverie_inguest
        ":reverie-rpc-transport",
    ],
)

# reverie-liteinst built against :reverie-inguest-exec-stop, for the same
# downstream test build only, so each of its test binaries holds the single
# reverie-inguest that its Cargo build holds.
rust_library(
    name = "reverie-liteinst-exec-stop",
    srcs = glob(["reverie-liteinst/src/**/*.rs"]),
    autocargo = {"ignore_rule": True},
    crate = "reverie_liteinst",
    crate_root = "reverie-liteinst/src/lib.rs",
    # As :reverie-liteinst: selected_backing() needs the final image's link.
    preferred_linkage = "static",
    target_compatible_with = [
        "ovr_config//cpu:x86_64",
        "ovr_config//os:linux",
    ],
    unittests = False,
    visibility = DOWNSTREAM_TEST_VISIBILITY,
    deps = [
        "fbsource//third-party/rust:bincode",
        "fbsource//third-party/rust:iced-x86",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:tempfile",
        "fbsource//third-party/rust:tokio",
        "fbsource//third-party/rust:tracing",
        ":reverie",
        ":reverie-inguest-exec-stop",  # @manual name:reverie_inguest
        ":reverie-rpc-transport",
    ],
)

# reverie-kvm/tests/fixtures laid out as under CARGO_MANIFEST_DIR.
buck_filegroup(
    name = "kvm-signal-abi-fixtures",
    srcs = {src.removeprefix("reverie-kvm/"): src for src in glob(["reverie-kvm/tests/fixtures/**"])},
)

# reverie-ptrace/tests/fixtures laid out as under CARGO_MANIFEST_DIR.
buck_filegroup(
    name = "ptrace-test-fixtures",
    srcs = {src.removeprefix("reverie-ptrace/"): src for src in glob(["reverie-ptrace/tests/fixtures/**"])},
)

# The native smoke workflow exercises the original ptrace process-tree contract.
# Keep the shared tool bytes; the OSS all-backend launcher has a wider graph.
# Its main source, fb-only/counter1_ptrace_smoke.rs, is the one Rust file under
# fb-only/, which the open-source tree does not carry: the glob finds it only
# in fbsource, and the target is fbsource-only.
rust_binary(
    name = "counter1-ptrace-smoke",
    srcs = glob(["fb-only/*.rs"])
    + [
        "reverie-examples/counter1_tool.rs",
    ],
    autocargo = {"ignore_rule": True},
    crate_root = "fb-only/counter1_ptrace_smoke.rs",
    named_deps = {"reverie": ":reverie"},
    target_compatible_with = ["fbcode//opensource/macros:broken-in-oss"],
    deps = [
        "fbsource//third-party/rust:clap",
        "fbsource//third-party/rust:serde",
        "fbsource//third-party/rust:tokio",
        "fbsource//third-party/rust:tracing",
        ":reverie-ptrace",
        ":reverie-util",
    ],
)
