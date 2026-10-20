load("@fbcode_macros//build_defs:sanitizers.bzl", "sanitizers")
load("@fbsource//tools/build_defs:fb_native_wrapper.bzl", "fb_native")
load("@fbsource//tools/build_defs:rust_library.bzl", "rust_library")
load("@fbsource//tools/build_defs:selects.bzl", "selects")

oncall("hermit")

# Keep registry metadata in the source of the autocargo manifests as well.
# Public package names differ from two internal target names. A BUCK file may
# not define functions (Buck2 rejects `def` outside .bzl files), so each target
# extends this shared table with its own documentation URL through dict().
_PUBLIC_CRATE_METADATA = {
    "version": "0.5.1",
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
        },
        "cargo_toml_dir": "reverie",
    },
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
                "dependencies": {
                    "safeptrace": {
                        "features": [
                            "notifier",
                            "memory",
                        ]
                    },
                },
            },
            "features": {"default": [], "nightly": []},
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
    name = "reverie-syscalls",
    srcs = glob(["reverie-syscalls/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-syscalls"),
            "dependencies_override": {
                "dependencies": {
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

# Hermit's SaBRe supervisor reads the statistics page through this crate.
rust_library(
    name = "reverie-sabre-stats",
    srcs = glob(["experimental/reverie-sabre-stats/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-sabre-stats"),
        },
        "cargo_toml_dir": "experimental/reverie-sabre-stats",
    },
    deps = [
        "fbsource//third-party/rust:libc",
        ":reverie",
    ],
)

rust_library(
    name = "reverie-loader",
    srcs = glob(["reverie-loader/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": {
                "version": "0.5.1",
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
                "launcher": ["coordinator-rpc", "dep:tempfile", "dep:tokio", "dep:tracing"],
                "preload-constructor": [],
                "rcb-clock": [
                    "reverie",
                    "reverie-ptrace",
                ],
            },
        },
        "cargo_toml_dir": "reverie-inguest",
    },
    features = [
        "coordinator-rpc",
        "exec-stop",
        "launcher",
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
        ":reverie-ptrace",
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
        "fbsource//third-party/rust:liteinst2",
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
        },
        "cargo_toml_dir": "reverie-kvm-core",
    },
    deps = [
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:kvm-ioctls",
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
    name = "reverie-kvm-terminal-read",
    srcs = ["reverie-kvm/src/terminal_read.c"],
    headers = {"terminal_read.h": "reverie-kvm/src/terminal_read.h"},
    compiler_flags = ["-std=c11", "-pthread", "-fexceptions"],
    exported_linker_flags = ["-pthread"],
)

rust_library(
    name = "reverie-kvm",
    srcs = glob(["reverie-kvm/src/**/*.rs"]),
    autocargo = {
        "cargo_toml_config": {
            "package": dict(_PUBLIC_CRATE_METADATA, documentation = "https://docs.rs/reverie-kvm", build = "build.rs"),
            "dependencies_override": {
                "build-dependencies": {"cc": {"version": "1.5.1"}},
            },
            "features": {
                "default": [],
                "native-test-support": [],
            },
        },
        "cargo_toml_dir": "reverie-kvm",
    },
    deps = [
        "fbsource//third-party/rust:futures",
        "fbsource//third-party/rust:goblin",
        "fbsource//third-party/rust:kvm-bindings",
        "fbsource//third-party/rust:kvm-ioctls",
        "fbsource//third-party/rust:libc",
        "fbsource//third-party/rust:perf-event-open-sys",
        "fbsource//third-party/rust:thiserror",
        ":reverie",
        ":reverie-kvm-core",
        ":reverie-kvm-terminal-read",
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
