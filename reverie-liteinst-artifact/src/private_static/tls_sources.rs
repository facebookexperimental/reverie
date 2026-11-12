//! Closed runtime TLS source declarations, never machine/entry authority.
//! Selection occurs only inside the existing authenticated Cargo source owner.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum Variant {
    LegacyInguest,
    SharedLoader,
}
impl Variant {
    pub(in super::super) fn geometry_source(self) -> &'static str {
        match self {
            Self::LegacyInguest => "reverie-inguest/src/private_runtime/tls/layout.rs",
            Self::SharedLoader => "reverie-loader/src/musl_tls.rs",
        }
    }
    pub(in super::super) fn geometry_symbol(self) -> &'static str {
        match self {
            Self::LegacyInguest => {
                "_RNvNtNtNtCs_15reverie_inguest15private_runtime3tls6layout4plan"
            }
            Self::SharedLoader => "_RNvNtCs_14reverie_loader8musl_tls4plan",
        }
    }
}

pub(in super::super) fn implementation_sha256() -> String {
    sha256(include_bytes!("tls_sources.rs"))
}

type SourceRow = (&'static str, u64, &'static str);
// Immutable reviewed git-object declarations. Runtime reads never manufacture
// expectations, and a hash from one row cannot satisfy a different tuple.
const LEGACY: &[SourceRow] = &[
    (
        "reverie-inguest/Cargo.toml",
        5569,
        "0c19352a33f158b91d1b37de71d5d8ef814a29be4599b95cee30ff0116e51176",
    ),
    (
        "reverie-inguest/src/lib.rs",
        11734,
        "0fbf94503eac27b65e52967c11c675e23e7a2f50338ca32150002ff4c64fabbf",
    ),
    (
        "reverie-inguest/src/private_runtime/mod.rs",
        2093,
        "f6764939d2016bd3c9414b17b35f21f8cf7217f128135b83cfb5459aa3ae5e1e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/mod.rs",
        4853,
        "369e35bcafda51a271720507dcf7a7c9072fb5db7486e110e14f15e4df91f0dd",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/abi.rs",
        12145,
        "5766f0c14cc1fdb586266b6644e80a0700a0f36e38d95f7da664ed37e161d948",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/layout.rs",
        5081,
        "c8510f4c9999bd88d06e5acbbbff9d0d26291cd860ff5762b02bed456b34c11b",
    ),
    (
        "reverie-loader/Cargo.toml",
        343,
        "f407fe1dcf3aa4829fe6b0257546cdf413e2917e5161281a14d4477f5f4c48d9",
    ),
    (
        "reverie-loader/src/lib.rs",
        1469,
        "62b857c9a7c1f03e5be131586864c3c11353dad4d65fac1ae7fa05612e2ccd51",
    ),
];
const SHARED: &[SourceRow] = &[
    (
        "reverie-inguest/Cargo.toml",
        5569,
        "0c19352a33f158b91d1b37de71d5d8ef814a29be4599b95cee30ff0116e51176",
    ),
    (
        "reverie-inguest/src/lib.rs",
        11734,
        "0fbf94503eac27b65e52967c11c675e23e7a2f50338ca32150002ff4c64fabbf",
    ),
    (
        "reverie-inguest/src/private_runtime/mod.rs",
        2093,
        "f6764939d2016bd3c9414b17b35f21f8cf7217f128135b83cfb5459aa3ae5e1e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/mod.rs",
        4853,
        "369e35bcafda51a271720507dcf7a7c9072fb5db7486e110e14f15e4df91f0dd",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/abi.rs",
        12171,
        "f7de3cd3a0653785f8aacc01e0fabdeb89172b2660f07ea0df9d393078299aab",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/layout.rs",
        499,
        "8fcceedb234c081b5125d95d73eaafa083fadc2d1be41698b724487ab7cfae36",
    ),
    (
        "reverie-loader/Cargo.toml",
        343,
        "f407fe1dcf3aa4829fe6b0257546cdf413e2917e5161281a14d4477f5f4c48d9",
    ),
    (
        "reverie-loader/src/lib.rs",
        1487,
        "493add9bd4bb95ca8778f52d14936e6cfc6f6e7866f249cb94870e1bb2c456b2",
    ),
    (
        "reverie-loader/src/musl_tls.rs",
        7478,
        "84011bb8505fa3357908e7445b1305f54303bae32ddb9d393546da8e309ee1ea",
    ),
];

// Complete shared-inputs source cohort. Geometry remains SHARED byte-for-byte.
const SHARED_INPUTS: &[SourceRow] = &[
    (
        "reverie-inguest/Cargo.toml",
        5569,
        "0c19352a33f158b91d1b37de71d5d8ef814a29be4599b95cee30ff0116e51176",
    ),
    (
        "reverie-inguest/src/lib.rs",
        11734,
        "0fbf94503eac27b65e52967c11c675e23e7a2f50338ca32150002ff4c64fabbf",
    ),
    (
        "reverie-inguest/src/private_runtime/mod.rs",
        2093,
        "f6764939d2016bd3c9414b17b35f21f8cf7217f128135b83cfb5459aa3ae5e1e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/mod.rs",
        4853,
        "369e35bcafda51a271720507dcf7a7c9072fb5db7486e110e14f15e4df91f0dd",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/abi.rs",
        12171,
        "f7de3cd3a0653785f8aacc01e0fabdeb89172b2660f07ea0df9d393078299aab",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/layout.rs",
        499,
        "8fcceedb234c081b5125d95d73eaafa083fadc2d1be41698b724487ab7cfae36",
    ),
    (
        "reverie-loader/Cargo.toml",
        343,
        "f407fe1dcf3aa4829fe6b0257546cdf413e2917e5161281a14d4477f5f4c48d9",
    ),
    (
        "reverie-loader/src/lib.rs",
        1510,
        "b3318334635e632a23283c1f51633b090eb809de9710ab0c98038b684abbb5b8",
    ),
    (
        "reverie-loader/src/musl_tls.rs",
        7478,
        "84011bb8505fa3357908e7445b1305f54303bae32ddb9d393546da8e309ee1ea",
    ),
    (
        "reverie-loader/src/mapped_inputs.rs",
        17803,
        "81cd7474215ff617fb1bc16b236461d4deb33697c7d559130f4bdb98b0f0e2c2",
    ),
];

// Complete 0.5.1 development cohort: only manifest version fields change.
// The eight Rust sources, geometry and existing machine checks are unchanged.
const SHARED_INPUTS_051: &[SourceRow] = &[
    (
        "reverie-inguest/Cargo.toml",
        5569,
        "71e2a295a5f59e3c129247c91b9beb84d19a07b0148153c884449af37d082aa7",
    ),
    (
        "reverie-inguest/src/lib.rs",
        11734,
        "0fbf94503eac27b65e52967c11c675e23e7a2f50338ca32150002ff4c64fabbf",
    ),
    (
        "reverie-inguest/src/private_runtime/mod.rs",
        2093,
        "f6764939d2016bd3c9414b17b35f21f8cf7217f128135b83cfb5459aa3ae5e1e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/mod.rs",
        4853,
        "369e35bcafda51a271720507dcf7a7c9072fb5db7486e110e14f15e4df91f0dd",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/abi.rs",
        12171,
        "f7de3cd3a0653785f8aacc01e0fabdeb89172b2660f07ea0df9d393078299aab",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/layout.rs",
        499,
        "8fcceedb234c081b5125d95d73eaafa083fadc2d1be41698b724487ab7cfae36",
    ),
    (
        "reverie-loader/Cargo.toml",
        343,
        "781863e2fb39d08ba64776020dc859abe6b68024f4c4219dc6fb96f4b814b203",
    ),
    (
        "reverie-loader/src/lib.rs",
        1510,
        "b3318334635e632a23283c1f51633b090eb809de9710ab0c98038b684abbb5b8",
    ),
    (
        "reverie-loader/src/musl_tls.rs",
        7478,
        "84011bb8505fa3357908e7445b1305f54303bae32ddb9d393546da8e309ee1ea",
    ),
    (
        "reverie-loader/src/mapped_inputs.rs",
        17803,
        "81cd7474215ff617fb1bc16b236461d4deb33697c7d559130f4bdb98b0f0e2c2",
    ),
];

// Complete 0.5.4 cohort: only the two manifests' version fields differ
// from SHARED_INPUTS_051. All eight Rust sources and geometry stay exact.
const SHARED_INPUTS_054: &[SourceRow] = &[
    (
        "reverie-inguest/Cargo.toml",
        5569,
        "0050a4e99fec9666cd297123bf298e19db712734e97cd97bd7b227114b826c50",
    ),
    (
        "reverie-inguest/src/lib.rs",
        11734,
        "0fbf94503eac27b65e52967c11c675e23e7a2f50338ca32150002ff4c64fabbf",
    ),
    (
        "reverie-inguest/src/private_runtime/mod.rs",
        2093,
        "f6764939d2016bd3c9414b17b35f21f8cf7217f128135b83cfb5459aa3ae5e1e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/mod.rs",
        4853,
        "369e35bcafda51a271720507dcf7a7c9072fb5db7486e110e14f15e4df91f0dd",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/abi.rs",
        12171,
        "f7de3cd3a0653785f8aacc01e0fabdeb89172b2660f07ea0df9d393078299aab",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/layout.rs",
        499,
        "8fcceedb234c081b5125d95d73eaafa083fadc2d1be41698b724487ab7cfae36",
    ),
    (
        "reverie-loader/Cargo.toml",
        343,
        "0ebb8a376d4c8b6637d5058d76ad7bf9b3fcecea3deb474065e41a1707f7cc23",
    ),
    (
        "reverie-loader/src/lib.rs",
        1510,
        "b3318334635e632a23283c1f51633b090eb809de9710ab0c98038b684abbb5b8",
    ),
    (
        "reverie-loader/src/musl_tls.rs",
        7478,
        "84011bb8505fa3357908e7445b1305f54303bae32ddb9d393546da8e309ee1ea",
    ),
    (
        "reverie-loader/src/mapped_inputs.rs",
        17803,
        "81cd7474215ff617fb1bc16b236461d4deb33697c7d559130f4bdb98b0f0e2c2",
    ),
];

// Reverie e39f78dd (0.5.5): manifests and crate roots only differ from
// SHARED_INPUTS_054. abi.rs differs by one comment word; geometry and every
// TLS export stay exact (TLS-ABI review, dh-9c8xwl).
const SHARED_INPUTS_055: &[SourceRow] = &[
    (
        "reverie-inguest/Cargo.toml",
        5690,
        "7b22069a7df3cbecaf93086ff01535b73edf2d5e2bc24ef4b0ac3155aec47dfe",
    ),
    (
        "reverie-inguest/src/lib.rs",
        11792,
        "2d3a8d6906a102cce3627d3b42ff87a334480807b44af14beaa4e60e7eeb78d4",
    ),
    (
        "reverie-inguest/src/private_runtime/mod.rs",
        2093,
        "f6764939d2016bd3c9414b17b35f21f8cf7217f128135b83cfb5459aa3ae5e1e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/mod.rs",
        4853,
        "369e35bcafda51a271720507dcf7a7c9072fb5db7486e110e14f15e4df91f0dd",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/abi.rs",
        12168,
        "b120c1f7bf2577e80264b0bab05a130d323248241ef62f101c917d4379e3e85a",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/layout.rs",
        499,
        "8fcceedb234c081b5125d95d73eaafa083fadc2d1be41698b724487ab7cfae36",
    ),
    (
        "reverie-loader/Cargo.toml",
        343,
        "1f0a18b134d7c34f0743899572b55a3e6ff20d9d5ae7ff4bf59b497fcd2dba7c",
    ),
    (
        "reverie-loader/src/lib.rs",
        2465,
        "a34726cf653275e7206fa7557881b530da4266994635273cfe769dbe30ae01d6",
    ),
    (
        "reverie-loader/src/musl_tls.rs",
        7478,
        "84011bb8505fa3357908e7445b1305f54303bae32ddb9d393546da8e309ee1ea",
    ),
    (
        "reverie-loader/src/mapped_inputs.rs",
        17803,
        "81cd7474215ff617fb1bc16b236461d4deb33697c7d559130f4bdb98b0f0e2c2",
    ),
];

// Reverie 1fc012a2: musl_tls.rs lines 1-223 and plan() are byte-unchanged from
// SHARED_INPUTS_055; the first-thread __init_tls path is byte-unchanged. The
// appended per-thread TCB ABI is admitted ONLY while uncalled; the final link
// enforces that through require_per_thread_abi_absent. Any caller needs a
// fresh TLS-ABI and scheduling review plus an extern link audit first.
const SHARED_INPUTS_055_THREADS: &[SourceRow] = &[
    (
        "reverie-inguest/Cargo.toml",
        5797,
        "b99c37792f39a34e45cb42ab531504ba09bd0175b6547d8fcc540308d704eb9a",
    ),
    (
        "reverie-inguest/src/lib.rs",
        13478,
        "9b619884552f14046a056f68693c49fc46d065b2a084ad49ca07819a10ec27b1",
    ),
    (
        "reverie-inguest/src/private_runtime/mod.rs",
        2093,
        "f6764939d2016bd3c9414b17b35f21f8cf7217f128135b83cfb5459aa3ae5e1e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/mod.rs",
        5001,
        "ba3a02d320c26c283acde7dfc0e0273ff7b04e68b4b5daa7a4f72619758f9f98",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/abi.rs",
        23446,
        "a7d7e8e10f4883b2802f8442666c07b95ee61edafca7528add65428d9971cf4e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/layout.rs",
        743,
        "8ee91d78869426196e2f4542dcffb2cf8be3b1372647bd407d9a28ca5b7d20c0",
    ),
    (
        "reverie-loader/Cargo.toml",
        343,
        "1f0a18b134d7c34f0743899572b55a3e6ff20d9d5ae7ff4bf59b497fcd2dba7c",
    ),
    (
        "reverie-loader/src/lib.rs",
        2486,
        "02aa2dae7b6eec327a0dcf68b92a66f512162d2fdd3a7f9ac89a3e8a51b1f5bf",
    ),
    (
        "reverie-loader/src/musl_tls.rs",
        17178,
        "18ca3aec385c4dd8ec79ee5f45e8a30863e28e8a49422cf6c1ae90eb2743696d",
    ),
    (
        "reverie-loader/src/mapped_inputs.rs",
        17803,
        "81cd7474215ff617fb1bc16b236461d4deb33697c7d559130f4bdb98b0f0e2c2",
    ),
];

// The reverie-inguest manifest gains the off-by-default `exec-stop-producer`
// feature and its optional sha2/iced-x86 dependencies, plus a serde_json
// dev-dependency. Every other row is exactly SHARED_INPUTS_055_THREADS; no TLS
// source, feature the runtime build selects, or crate root changes.
const SHARED_INPUTS_055_PRODUCER: &[SourceRow] = &[
    (
        "reverie-inguest/Cargo.toml",
        6166,
        "e30d39d15eb64c0ce1adb72fb92cd7a28268a4dc448d1c38690f868e979d63fb",
    ),
    (
        "reverie-inguest/src/lib.rs",
        13478,
        "9b619884552f14046a056f68693c49fc46d065b2a084ad49ca07819a10ec27b1",
    ),
    (
        "reverie-inguest/src/private_runtime/mod.rs",
        2093,
        "f6764939d2016bd3c9414b17b35f21f8cf7217f128135b83cfb5459aa3ae5e1e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/mod.rs",
        5001,
        "ba3a02d320c26c283acde7dfc0e0273ff7b04e68b4b5daa7a4f72619758f9f98",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/abi.rs",
        23446,
        "a7d7e8e10f4883b2802f8442666c07b95ee61edafca7528add65428d9971cf4e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/layout.rs",
        743,
        "8ee91d78869426196e2f4542dcffb2cf8be3b1372647bd407d9a28ca5b7d20c0",
    ),
    (
        "reverie-loader/Cargo.toml",
        343,
        "1f0a18b134d7c34f0743899572b55a3e6ff20d9d5ae7ff4bf59b497fcd2dba7c",
    ),
    (
        "reverie-loader/src/lib.rs",
        2486,
        "02aa2dae7b6eec327a0dcf68b92a66f512162d2fdd3a7f9ac89a3e8a51b1f5bf",
    ),
    (
        "reverie-loader/src/musl_tls.rs",
        17178,
        "18ca3aec385c4dd8ec79ee5f45e8a30863e28e8a49422cf6c1ae90eb2743696d",
    ),
    (
        "reverie-loader/src/mapped_inputs.rs",
        17803,
        "81cd7474215ff617fb1bc16b236461d4deb33697c7d559130f4bdb98b0f0e2c2",
    ),
];

// Reverie 0.5.6 release cut: only the package and internal dependency
// versions in reverie-inguest/Cargo.toml and reverie-loader/Cargo.toml
// change (rows 0, 6). Every other row is exactly SHARED_INPUTS_055_PRODUCER;
// no TLS source, feature the runtime build selects, or crate root changes.
const SHARED_INPUTS_056: &[SourceRow] = &[
    (
        "reverie-inguest/Cargo.toml",
        6166,
        "d95f244d25c20488c4def4d251c09f4433409a4ae7b6a6c19321f1491682adbc",
    ),
    (
        "reverie-inguest/src/lib.rs",
        13478,
        "9b619884552f14046a056f68693c49fc46d065b2a084ad49ca07819a10ec27b1",
    ),
    (
        "reverie-inguest/src/private_runtime/mod.rs",
        2093,
        "f6764939d2016bd3c9414b17b35f21f8cf7217f128135b83cfb5459aa3ae5e1e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/mod.rs",
        5001,
        "ba3a02d320c26c283acde7dfc0e0273ff7b04e68b4b5daa7a4f72619758f9f98",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/abi.rs",
        23446,
        "a7d7e8e10f4883b2802f8442666c07b95ee61edafca7528add65428d9971cf4e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/layout.rs",
        743,
        "8ee91d78869426196e2f4542dcffb2cf8be3b1372647bd407d9a28ca5b7d20c0",
    ),
    (
        "reverie-loader/Cargo.toml",
        343,
        "79063d5d763041a53c8d37e16093d49c7a8785d5903dbcd3df8ece208c2ca305",
    ),
    (
        "reverie-loader/src/lib.rs",
        2486,
        "02aa2dae7b6eec327a0dcf68b92a66f512162d2fdd3a7f9ac89a3e8a51b1f5bf",
    ),
    (
        "reverie-loader/src/musl_tls.rs",
        17178,
        "18ca3aec385c4dd8ec79ee5f45e8a30863e28e8a49422cf6c1ae90eb2743696d",
    ),
    (
        "reverie-loader/src/mapped_inputs.rs",
        17803,
        "81cd7474215ff617fb1bc16b236461d4deb33697c7d559130f4bdb98b0f0e2c2",
    ),
];

// Reverie 0.5.7 release cut: only the package and internal dependency
// versions in reverie-inguest/Cargo.toml and reverie-loader/Cargo.toml
// change (rows 0, 6). Every other row is exactly SHARED_INPUTS_056;
// no TLS source, feature the runtime build selects, or crate root changes.
const SHARED_INPUTS_057: &[SourceRow] = &[
    (
        "reverie-inguest/Cargo.toml",
        6166,
        "1cca57bb80f07e02e47977ea2f639475084a7e6838caa140b8445e6d358f0488",
    ),
    (
        "reverie-inguest/src/lib.rs",
        13478,
        "9b619884552f14046a056f68693c49fc46d065b2a084ad49ca07819a10ec27b1",
    ),
    (
        "reverie-inguest/src/private_runtime/mod.rs",
        2093,
        "f6764939d2016bd3c9414b17b35f21f8cf7217f128135b83cfb5459aa3ae5e1e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/mod.rs",
        5001,
        "ba3a02d320c26c283acde7dfc0e0273ff7b04e68b4b5daa7a4f72619758f9f98",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/abi.rs",
        23446,
        "a7d7e8e10f4883b2802f8442666c07b95ee61edafca7528add65428d9971cf4e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/layout.rs",
        743,
        "8ee91d78869426196e2f4542dcffb2cf8be3b1372647bd407d9a28ca5b7d20c0",
    ),
    (
        "reverie-loader/Cargo.toml",
        343,
        "7b659fdf29bcea1534e8b5239d3bd0beb5d49a9e0c66381a854129e148226e4f",
    ),
    (
        "reverie-loader/src/lib.rs",
        2486,
        "02aa2dae7b6eec327a0dcf68b92a66f512162d2fdd3a7f9ac89a3e8a51b1f5bf",
    ),
    (
        "reverie-loader/src/musl_tls.rs",
        17178,
        "18ca3aec385c4dd8ec79ee5f45e8a30863e28e8a49422cf6c1ae90eb2743696d",
    ),
    (
        "reverie-loader/src/mapped_inputs.rs",
        17803,
        "81cd7474215ff617fb1bc16b236461d4deb33697c7d559130f4bdb98b0f0e2c2",
    ),
];

// The private libc exports move behind the off-by-default
// `private-libc-exports` feature (rows 0, 4). The reverie-inguest manifest
// gains that feature. In abi.rs only `__init_tls`'s export attribute becomes
// conditional on it, and its doc comment grows; with the feature on, as every
// private image build has it, the compiled `__init_tls` and the TLS ABI are
// unchanged. Every other row is exactly SHARED_INPUTS_057.
const SHARED_INPUTS_057_EXPORTS: &[SourceRow] = &[
    (
        "reverie-inguest/Cargo.toml",
        6495,
        "2ee5115d633d33984ebfae0d5debd0278596536e8866587a25b68f26940b63e0",
    ),
    (
        "reverie-inguest/src/lib.rs",
        13478,
        "9b619884552f14046a056f68693c49fc46d065b2a084ad49ca07819a10ec27b1",
    ),
    (
        "reverie-inguest/src/private_runtime/mod.rs",
        2093,
        "f6764939d2016bd3c9414b17b35f21f8cf7217f128135b83cfb5459aa3ae5e1e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/mod.rs",
        5001,
        "ba3a02d320c26c283acde7dfc0e0273ff7b04e68b4b5daa7a4f72619758f9f98",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/abi.rs",
        23736,
        "f00da75509b08227ff7ed90e8f1969e63dfbeccab579bf4c8770a6fa163f1024",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/layout.rs",
        743,
        "8ee91d78869426196e2f4542dcffb2cf8be3b1372647bd407d9a28ca5b7d20c0",
    ),
    (
        "reverie-loader/Cargo.toml",
        343,
        "7b659fdf29bcea1534e8b5239d3bd0beb5d49a9e0c66381a854129e148226e4f",
    ),
    (
        "reverie-loader/src/lib.rs",
        2486,
        "02aa2dae7b6eec327a0dcf68b92a66f512162d2fdd3a7f9ac89a3e8a51b1f5bf",
    ),
    (
        "reverie-loader/src/musl_tls.rs",
        17178,
        "18ca3aec385c4dd8ec79ee5f45e8a30863e28e8a49422cf6c1ae90eb2743696d",
    ),
    (
        "reverie-loader/src/mapped_inputs.rs",
        17803,
        "81cd7474215ff617fb1bc16b236461d4deb33697c7d559130f4bdb98b0f0e2c2",
    ),
];

// abi.rs: in `__init_tls` an unnecessary `unsafe` block around `addr_of_mut!`
// and a null comparison become `&raw mut __libc` and `.is_null()` (row 4).
// Every other row is exactly SHARED_INPUTS_057_EXPORTS.
const SHARED_INPUTS_057_LINTS: &[SourceRow] = &[
    (
        "reverie-inguest/Cargo.toml",
        6495,
        "2ee5115d633d33984ebfae0d5debd0278596536e8866587a25b68f26940b63e0",
    ),
    (
        "reverie-inguest/src/lib.rs",
        13478,
        "9b619884552f14046a056f68693c49fc46d065b2a084ad49ca07819a10ec27b1",
    ),
    (
        "reverie-inguest/src/private_runtime/mod.rs",
        2093,
        "f6764939d2016bd3c9414b17b35f21f8cf7217f128135b83cfb5459aa3ae5e1e",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/mod.rs",
        5001,
        "ba3a02d320c26c283acde7dfc0e0273ff7b04e68b4b5daa7a4f72619758f9f98",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/abi.rs",
        23707,
        "216dd2050bec7f6611bfa51b9de9e308bf1e23d2831b46b2da9a8901a226dbaf",
    ),
    (
        "reverie-inguest/src/private_runtime/tls/layout.rs",
        743,
        "8ee91d78869426196e2f4542dcffb2cf8be3b1372647bd407d9a28ca5b7d20c0",
    ),
    (
        "reverie-loader/Cargo.toml",
        343,
        "7b659fdf29bcea1534e8b5239d3bd0beb5d49a9e0c66381a854129e148226e4f",
    ),
    (
        "reverie-loader/src/lib.rs",
        2486,
        "02aa2dae7b6eec327a0dcf68b92a66f512162d2fdd3a7f9ac89a3e8a51b1f5bf",
    ),
    (
        "reverie-loader/src/musl_tls.rs",
        17178,
        "18ca3aec385c4dd8ec79ee5f45e8a30863e28e8a49422cf6c1ae90eb2743696d",
    ),
    (
        "reverie-loader/src/mapped_inputs.rs",
        17803,
        "81cd7474215ff617fb1bc16b236461d4deb33697c7d559130f4bdb98b0f0e2c2",
    ),
];

fn classify(observed: &[(String, u64, String)]) -> Result<Variant> {
    let same = |expected: &[SourceRow]| {
        observed.len() == expected.len()
            && observed.iter().zip(expected).all(|(actual, expected)| {
                actual.0 == expected.0 && actual.1 == expected.1 && actual.2 == expected.2
            })
    };
    match (
        same(LEGACY),
        same(SHARED),
        same(SHARED_INPUTS),
        same(SHARED_INPUTS_051),
        same(SHARED_INPUTS_054),
        same(SHARED_INPUTS_055),
        same(SHARED_INPUTS_055_THREADS),
        same(SHARED_INPUTS_055_PRODUCER),
        same(SHARED_INPUTS_056),
        same(SHARED_INPUTS_057),
        same(SHARED_INPUTS_057_EXPORTS),
        same(SHARED_INPUTS_057_LINTS),
    ) {
        (true, false, false, false, false, false, false, false, false, false, false, false) => {
            Ok(Variant::LegacyInguest)
        }
        (false, true, false, false, false, false, false, false, false, false, false, false)
        | (false, false, true, false, false, false, false, false, false, false, false, false)
        | (false, false, false, true, false, false, false, false, false, false, false, false)
        | (false, false, false, false, true, false, false, false, false, false, false, false)
        | (false, false, false, false, false, true, false, false, false, false, false, false)
        | (false, false, false, false, false, false, true, false, false, false, false, false)
        | (false, false, false, false, false, false, false, true, false, false, false, false)
        | (false, false, false, false, false, false, false, false, true, false, false, false)
        | (false, false, false, false, false, false, false, false, false, true, false, false)
        | (false, false, false, false, false, false, false, false, false, false, true, false)
        | (false, false, false, false, false, false, false, false, false, false, false, true) => {
            Ok(Variant::SharedLoader)
        }
        _ => Err("runtime TLS sources are not one complete reviewed tuple".into()),
    }
}

// Per-thread TCB ABI (reverie-inguest private_runtime/tls/abi.rs) that
// SHARED_INPUTS_055_THREADS admits only while uncalled. A caller lands outside
// every tuple row, so the final image must not retain any of these. Admitting a
// caller needs a fresh TLS-ABI and scheduling review plus a final-link audit of
// the six externs they add: __ofl_lock, __ofl_unlock, __stdin_used,
// __stdout_used, __stderr_used and __pthread_tsd_main.
const PER_THREAD_ABI: [&str; 4] = [
    "build_thread_tcb",
    "first_thread_switch",
    "note_thread_added_locked",
    "note_thread_add_failed_locked",
];

fn require_per_thread_abi_names_absent(names: &[&str]) -> Result<()> {
    // Absence is meaningless without a symbol table: require the strong
    // source-bound __init_tls that every reviewed tuple links.
    require(
        names.contains(&"__init_tls"),
        "final image symbol table lacks __init_tls; per-thread TLS ABI absence is unobservable",
    )?;
    for function in PER_THREAD_ABI {
        // Same path segment in v0 and legacy Rust mangling.
        let path = format!("15private_runtime3tls3abi{}{function}", function.len());
        if let Some(name) = names.iter().find(|name| name.contains(&path)) {
            return Err(format!(
                "final image retains uncalled per-thread TLS ABI {name}; \
                 a caller needs a fresh TLS-ABI review and extern link audit"
            ));
        }
    }
    Ok(())
}

pub(super) fn require_per_thread_abi_absent(final_elf: &Elf) -> Result<()> {
    let names = final_elf
        .syms
        .iter()
        .filter_map(|symbol| final_elf.strtab.get_at(symbol.st_name))
        .collect::<Vec<_>>();
    require_per_thread_abi_names_absent(&names)
}

// The caller authenticates this sole Cargo root and closes its complete source
// guard on every Result path. All successfully opened files join that SAME
// caller's close list even when tuple classification fails.
pub(super) fn bind(root: &Path, files: &mut Vec<FileIdentity>) -> Result<Variant> {
    let mut observed = Vec::new();
    let optional_sources = [
        "reverie-loader/src/musl_tls.rs",
        "reverie-loader/src/mapped_inputs.rs",
    ];
    for relative in LEGACY.iter().map(|row| row.0).chain(optional_sources) {
        let path = root.join(relative);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error)
                if optional_sources.contains(&relative)
                    && error.kind() == std::io::ErrorKind::NotFound =>
            {
                continue;
            }
            Err(error) => {
                return Err(format!(
                    "runtime TLS source metadata {}: {error}",
                    path.display()
                ));
            }
        };
        require(
            metadata.file_type().is_file() && metadata.len() <= 64 * 1024,
            "runtime TLS source must be bounded ordinary file",
        )?;
        let file = FileIdentity::read(&path)?;
        observed.push((relative.to_owned(), metadata.len(), file.sha256.clone()));
        files.push(file);
    }
    classify(&observed)
}

// Self-check seam: the real bind() over one checkout's own runtime TLS
// sources. Reverie's integration test calls it on this workspace, so a source
// edit that outruns the closed list fails here instead of in a downstream
// private-static link. The error names every observed row.
pub(super) fn self_check(root: &Path) -> Result<()> {
    let mut files = Vec::new();
    let variant = bind(root, &mut files);
    variant.map(|_| ()).map_err(|error| {
        let observed = files
            .iter()
            .map(|file| {
                let relative = file.path.strip_prefix(root).unwrap_or(&file.path);
                format!("\n    {} {}", relative.display(), file.sha256)
            })
            .collect::<String>();
        format!("{error}; observed rows under {}:{observed}", root.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rows(expected: &[SourceRow]) -> Vec<(String, u64, String)> {
        expected
            .iter()
            .map(|row| (row.0.into(), row.1, row.2.into()))
            .collect()
    }
    // Release 34885654 changes only the two manifests' package/internal
    // dependency versions. These are declaration controls, not a runtime proof.
    fn development_051_rows() -> Vec<(String, u64, String)> {
        let mut observed = rows(SHARED_INPUTS);
        observed[0].2 = "71e2a295a5f59e3c129247c91b9beb84d19a07b0148153c884449af37d082aa7".into();
        observed[6].2 = "781863e2fb39d08ba64776020dc859abe6b68024f4c4219dc6fb96f4b814b203".into();
        observed
    }
    #[test]
    fn tls_source_declarations_select_complete_051_without_mixed_versions() {
        assert_eq!(
            classify(&development_051_rows()).unwrap(),
            Variant::SharedLoader
        );
        for index in [0, 6] {
            let mut partial = development_051_rows();
            partial[index] = rows(SHARED_INPUTS)[index].clone();
            assert!(classify(&partial).is_err(), "mixed manifest row {index}");
        }
    }
    #[test]
    fn tls_source_declarations_refuse_each_missing_changed_or_duplicate_051_row() {
        let expected = development_051_rows();
        for index in 0..expected.len() {
            let mut missing = expected.clone();
            missing.remove(index);
            assert!(classify(&missing).is_err(), "missing row {index}");
            let mut changed = expected.clone();
            changed[index].2.replace_range(..1, "x");
            assert!(classify(&changed).is_err(), "changed digest row {index}");
            let mut size = expected.clone();
            size[index].1 += 1;
            assert!(classify(&size).is_err(), "changed size row {index}");
            let mut path = expected.clone();
            path[index].0.push_str(".unreviewed");
            assert!(classify(&path).is_err(), "changed path row {index}");
        }
        let mut duplicate = expected;
        duplicate.push(duplicate[0].clone());
        assert!(classify(&duplicate).is_err());
    }
    // Fixed version-only declaration controls; no runtime filename authority.
    fn development_054_rows() -> Vec<(String, u64, String)> {
        let mut observed = rows(SHARED_INPUTS_051);
        observed[0].2 = "0050a4e99fec9666cd297123bf298e19db712734e97cd97bd7b227114b826c50".into();
        observed[6].2 = "0ebb8a376d4c8b6637d5058d76ad7bf9b3fcecea3deb474065e41a1707f7cc23".into();
        observed
    }
    #[test]
    fn tls_source_declarations_select_complete_054_without_mixed_versions() {
        assert_eq!(
            classify(&development_054_rows()).unwrap(),
            Variant::SharedLoader
        );
        for historical in [SHARED_INPUTS, SHARED_INPUTS_051] {
            for index in [0, 6] {
                let mut partial = development_054_rows();
                partial[index] = rows(historical)[index].clone();
                assert!(classify(&partial).is_err(), "mixed manifest row {index}");
            }
        }
        for index in [1, 2, 3, 4, 5, 7, 8, 9] {
            assert_eq!(SHARED_INPUTS_054[index], SHARED_INPUTS_051[index]);
        }
    }
    #[test]
    fn tls_source_declarations_refuse_each_missing_changed_or_duplicate_054_row() {
        let expected = development_054_rows();
        for index in 0..expected.len() {
            let mut missing = expected.clone();
            missing.remove(index);
            assert!(classify(&missing).is_err(), "missing row {index}");
            let mut changed = expected.clone();
            changed[index].2.replace_range(..1, "x");
            assert!(classify(&changed).is_err(), "changed digest row {index}");
            let mut size = expected.clone();
            size[index].1 += 1;
            assert!(classify(&size).is_err(), "changed size row {index}");
            let mut path = expected.clone();
            path[index].0.push_str(".unreviewed");
            assert!(classify(&path).is_err(), "changed path row {index}");
        }
        let mut duplicate = expected.clone();
        duplicate.push(duplicate[0].clone());
        assert!(classify(&duplicate).is_err());
        let mut extra = expected;
        extra.push(("unreviewed.rs".into(), 1, "0".repeat(64)));
        assert!(classify(&extra).is_err());
    }
    fn refuse_each_missing_changed_extra_or_duplicate_row(expected: &[SourceRow]) {
        let expected = rows(expected);
        assert_eq!(classify(&expected).unwrap(), Variant::SharedLoader);
        for index in 0..expected.len() {
            let mut missing = expected.clone();
            missing.remove(index);
            assert!(classify(&missing).is_err(), "missing row {index}");
            let mut changed = expected.clone();
            changed[index].2.replace_range(..1, "x");
            assert!(classify(&changed).is_err(), "changed digest row {index}");
            let mut size = expected.clone();
            size[index].1 += 1;
            assert!(classify(&size).is_err(), "changed size row {index}");
            let mut path = expected.clone();
            path[index].0.push_str(".unreviewed");
            assert!(classify(&path).is_err(), "changed path row {index}");
        }
        let mut duplicate = expected.clone();
        duplicate.push(duplicate[0].clone());
        assert!(classify(&duplicate).is_err());
        let mut extra = expected;
        extra.push(("unreviewed.rs".into(), 1, "0".repeat(64)));
        assert!(classify(&extra).is_err());
    }
    // Exactly `changed` rows differ from the predecessor, and swapping any one
    // of them in either direction mixes versions and refuses.
    fn refuse_mixed_versions(current: &[SourceRow], previous: &[SourceRow], changed: &[usize]) {
        assert_eq!(current.len(), previous.len());
        for index in 0..current.len() {
            assert_eq!(
                current[index] != previous[index],
                changed.contains(&index),
                "row {index} change set"
            );
            assert_eq!(current[index].0, previous[index].0, "row {index} path");
        }
        for &index in changed {
            let mut new_with_old = rows(current);
            new_with_old[index] = rows(previous)[index].clone();
            assert!(classify(&new_with_old).is_err(), "new with old row {index}");
            let mut old_with_new = rows(previous);
            old_with_new[index] = rows(current)[index].clone();
            assert!(classify(&old_with_new).is_err(), "old with new row {index}");
        }
    }
    // e39f78dd: manifests, crate roots and an abi.rs comment changed; rows
    // 2, 3, 5, 8 (geometry) and 9 are exactly SHARED_INPUTS_054.
    #[test]
    fn tls_source_declarations_select_complete_055_without_mixed_versions() {
        refuse_each_missing_changed_extra_or_duplicate_row(SHARED_INPUTS_055);
        refuse_mixed_versions(SHARED_INPUTS_055, SHARED_INPUTS_054, &[0, 1, 4, 6, 7]);
    }
    // 1fc012a2: geometry row 8 changes by appended code only; plan() and
    // musl_tls.rs lines 1-223 are byte-unchanged, which no row digest can show.
    // Rows 2, 6 and 9 are exactly SHARED_INPUTS_055.
    #[test]
    fn tls_source_declarations_select_complete_055_threads_without_mixed_versions() {
        refuse_each_missing_changed_extra_or_duplicate_row(SHARED_INPUTS_055_THREADS);
        refuse_mixed_versions(
            SHARED_INPUTS_055_THREADS,
            SHARED_INPUTS_055,
            &[0, 1, 3, 4, 5, 7, 8],
        );
    }
    // The producer manifest: only row 0 (reverie-inguest/Cargo.toml) differs
    // from SHARED_INPUTS_055_THREADS, so swapping that one row back yields the
    // threads tuple itself rather than a mixed one.
    #[test]
    fn tls_source_declarations_select_complete_055_producer() {
        refuse_each_missing_changed_extra_or_duplicate_row(SHARED_INPUTS_055_PRODUCER);
        assert_eq!(
            SHARED_INPUTS_055_PRODUCER.len(),
            SHARED_INPUTS_055_THREADS.len()
        );
        for (index, (producer, threads)) in SHARED_INPUTS_055_PRODUCER
            .iter()
            .zip(SHARED_INPUTS_055_THREADS)
            .enumerate()
        {
            assert_eq!(producer.0, threads.0, "row {index} path");
            assert_eq!(producer != threads, index == 0, "row {index} change set");
        }
    }
    // 0.5.6: only rows 0, 6 (the manifests) differ from SHARED_INPUTS_055_PRODUCER.
    #[test]
    fn tls_source_declarations_select_complete_056() {
        refuse_each_missing_changed_extra_or_duplicate_row(SHARED_INPUTS_056);
        refuse_mixed_versions(SHARED_INPUTS_056, SHARED_INPUTS_055_PRODUCER, &[0, 6]);
    }
    // 0.5.7: only rows 0, 6 (the manifests) differ from SHARED_INPUTS_056.
    #[test]
    fn tls_source_declarations_select_complete_057() {
        refuse_each_missing_changed_extra_or_duplicate_row(SHARED_INPUTS_057);
        refuse_mixed_versions(SHARED_INPUTS_057, SHARED_INPUTS_056, &[0, 6]);
    }
    // The private libc exports' feature: only rows 0 (the reverie-inguest
    // manifest) and 4 (abi.rs) differ from SHARED_INPUTS_057.
    #[test]
    fn tls_source_declarations_select_complete_057_exports() {
        refuse_each_missing_changed_extra_or_duplicate_row(SHARED_INPUTS_057_EXPORTS);
        refuse_mixed_versions(SHARED_INPUTS_057_EXPORTS, SHARED_INPUTS_057, &[0, 4]);
    }
    // The musl lint fixes: only row 4 (abi.rs) differs from
    // SHARED_INPUTS_057_EXPORTS, so swapping that one row back yields the
    // exports tuple itself rather than a mixed one. Against SHARED_INPUTS_057
    // rows 0 and 4 differ, and each swap mixes versions and refuses.
    #[test]
    fn tls_source_declarations_select_complete_057_lints() {
        refuse_each_missing_changed_extra_or_duplicate_row(SHARED_INPUTS_057_LINTS);
        assert_eq!(
            SHARED_INPUTS_057_LINTS.len(),
            SHARED_INPUTS_057_EXPORTS.len()
        );
        for (index, (lints, exports)) in SHARED_INPUTS_057_LINTS
            .iter()
            .zip(SHARED_INPUTS_057_EXPORTS)
            .enumerate()
        {
            assert_eq!(lints.0, exports.0, "row {index} path");
            assert_eq!(lints != exports, index == 4, "row {index} change set");
        }
        refuse_mixed_versions(SHARED_INPUTS_057_LINTS, SHARED_INPUTS_057, &[0, 4]);
    }
    #[test]
    fn tls_source_declarations_are_pairwise_distinct() {
        let lists = [
            LEGACY,
            SHARED,
            SHARED_INPUTS,
            SHARED_INPUTS_051,
            SHARED_INPUTS_054,
            SHARED_INPUTS_055,
            SHARED_INPUTS_055_THREADS,
            SHARED_INPUTS_055_PRODUCER,
            SHARED_INPUTS_056,
            SHARED_INPUTS_057,
            SHARED_INPUTS_057_EXPORTS,
            SHARED_INPUTS_057_LINTS,
        ];
        for (index, first) in lists.iter().enumerate() {
            for second in &lists[index + 1..] {
                assert_ne!(first, second);
            }
        }
    }
    #[test]
    fn final_image_refuses_retained_per_thread_tls_abi() {
        let present = [
            "__init_tls",
            "_RNvNtNtNtCs_15reverie_inguest15private_runtime3tls3abi10___init_tls",
        ];
        require_per_thread_abi_names_absent(&present).unwrap();
        assert!(require_per_thread_abi_names_absent(&["first_thread_switch"]).is_err());
        for function in PER_THREAD_ABI {
            let v0 = format!(
                "_RNvNtNtNtCs_15reverie_inguest15private_runtime3tls3abi{}{function}",
                function.len()
            );
            let legacy = format!(
                "_ZN15reverie_inguest15private_runtime3tls3abi{}{function}17h0123456789abcdefE",
                function.len()
            );
            for name in [v0, legacy] {
                let refusal =
                    require_per_thread_abi_names_absent(&["__init_tls", &name]).expect_err(&name);
                assert!(refusal.contains("uncalled per-thread TLS ABI"), "{refusal}");
            }
        }
    }
    // Numeric declaration controls only, not authenticated-source positives.
    #[test]
    fn tls_source_declarations_select_only_two_complete_tuples() {
        assert_eq!(classify(&rows(LEGACY)).unwrap(), Variant::LegacyInguest);
        assert_eq!(classify(&rows(SHARED)).unwrap(), Variant::SharedLoader);
        assert_eq!(Variant::LegacyInguest.geometry_source(), LEGACY[5].0);
        assert_eq!(Variant::SharedLoader.geometry_source(), SHARED[8].0);
        assert_ne!(
            Variant::LegacyInguest.geometry_symbol(),
            Variant::SharedLoader.geometry_symbol()
        );
    }
    #[test]
    fn tls_source_declarations_refuse_mixed_wrapper_definition_and_abi() {
        for index in [4, 5, 7] {
            let mut mixed = rows(SHARED);
            mixed[index] = rows(LEGACY)[index].clone();
            assert!(classify(&mixed).is_err(), "mixed source index {index}");
        }
        let mut legacy_with_new_definition = rows(LEGACY);
        legacy_with_new_definition.push(rows(SHARED)[8].clone());
        assert!(classify(&legacy_with_new_definition).is_err());
    }
    #[test]
    fn tls_source_declarations_refuse_missing_changed_extra_and_duplicate_rows() {
        for expected in [LEGACY, SHARED] {
            for index in 0..expected.len() {
                let mut missing = rows(expected);
                missing.remove(index);
                assert!(classify(&missing).is_err());
                let mut changed = rows(expected);
                changed[index].2.replace_range(..1, "x");
                assert!(classify(&changed).is_err());
                let mut size = rows(expected);
                size[index].1 += 1;
                assert!(classify(&size).is_err());
            }
            let mut duplicate = rows(expected);
            duplicate.push(duplicate[0].clone());
            assert!(classify(&duplicate).is_err());
            let mut wrong_path = rows(expected);
            wrong_path[0].0.push_str(".unreviewed");
            assert!(classify(&wrong_path).is_err());
        }
    }
    #[test]
    fn tls_source_declarations_select_complete_shared_inputs_without_geometry_change() {
        assert_eq!(
            classify(&rows(SHARED_INPUTS)).unwrap(),
            Variant::SharedLoader
        );
        assert_eq!(&SHARED_INPUTS[..7], &SHARED[..7]);
        assert_eq!(SHARED_INPUTS[8], SHARED[8]);
        assert_eq!(SHARED_INPUTS[9].0, "reverie-loader/src/mapped_inputs.rs");
        assert_eq!(SHARED_INPUTS.len(), SHARED.len() + 1);
    }
    #[test]
    fn tls_source_declarations_refuse_shared_inputs_mixed_exports_and_extra_module() {
        let mut old_with_module = rows(SHARED);
        old_with_module.push(rows(SHARED_INPUTS)[9].clone());
        assert!(classify(&old_with_module).is_err());
        let mut legacy_with_module = rows(LEGACY);
        legacy_with_module.push(rows(SHARED_INPUTS)[9].clone());
        assert!(classify(&legacy_with_module).is_err());
        for index in [4, 5, 7] {
            let mut mixed = rows(SHARED_INPUTS);
            mixed[index] = rows(LEGACY)[index].clone();
            assert!(
                classify(&mixed).is_err(),
                "legacy/shared inputs row {index}"
            );
        }
        let mut old_export = rows(SHARED_INPUTS);
        old_export[7] = rows(SHARED)[7].clone();
        assert!(classify(&old_export).is_err());
    }
    #[test]
    fn tls_source_declarations_refuse_each_missing_changed_or_duplicate_shared_inputs_row() {
        for index in 0..SHARED_INPUTS.len() {
            let mut missing = rows(SHARED_INPUTS);
            missing.remove(index);
            assert!(classify(&missing).is_err(), "missing row {index}");
            let mut changed = rows(SHARED_INPUTS);
            changed[index].2.replace_range(..1, "x");
            assert!(classify(&changed).is_err(), "changed digest row {index}");
            let mut size = rows(SHARED_INPUTS);
            size[index].1 += 1;
            assert!(classify(&size).is_err(), "changed size row {index}");
        }
        let mut duplicate = rows(SHARED_INPUTS);
        duplicate.push(duplicate[0].clone());
        assert!(classify(&duplicate).is_err());
        let mut wrong_path = rows(SHARED_INPUTS);
        wrong_path[9].0.push_str(".unreviewed");
        assert!(classify(&wrong_path).is_err());
    }
}
