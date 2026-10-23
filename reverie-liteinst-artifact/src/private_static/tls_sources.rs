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

// Complete 0.5.3 version-only cohort; all Rust source rows remain identical.
const SHARED_INPUTS_053: &[SourceRow] = &[
    (
        "reverie-inguest/Cargo.toml",
        5569,
        "d95d1413c8853732664d795dadfa65fa9c666d356585384c9d29eea5b351dfe8",
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
        "11ddee33344d8e2917248497d34e52c987eeca15d029cab1f87995dd5ad7b682",
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
        same(SHARED_INPUTS_053),
    ) {
        (true, false, false, false, false) => Ok(Variant::LegacyInguest),
        (false, true, false, false, false)
        | (false, false, true, false, false)
        | (false, false, false, true, false)
        | (false, false, false, false, true) => Ok(Variant::SharedLoader),
        _ => Err("runtime TLS sources are not one complete reviewed tuple".into()),
    }
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
    fn development_053_rows() -> Vec<(String, u64, String)> {
        let mut observed = development_051_rows();
        observed[0].2 = "d95d1413c8853732664d795dadfa65fa9c666d356585384c9d29eea5b351dfe8".into();
        observed[6].2 = "11ddee33344d8e2917248497d34e52c987eeca15d029cab1f87995dd5ad7b682".into();
        observed
    }
    #[test]
    fn tls_source_declarations_select_complete_051_without_mixed_versions() {
        for expected in [development_051_rows(), development_053_rows()] {
            assert_eq!(classify(&expected).unwrap(), Variant::SharedLoader);
            for other in [
                rows(SHARED_INPUTS),
                development_051_rows(),
                development_053_rows(),
            ] {
                if other == expected {
                    continue;
                }
                for index in [0, 6] {
                    let mut partial = expected.clone();
                    partial[index] = other[index].clone();
                    assert!(classify(&partial).is_err(), "mixed manifest row {index}");
                }
            }
        }
    }
    #[test]
    fn tls_source_declarations_refuse_each_missing_changed_or_duplicate_051_row() {
        for expected in [development_051_rows(), development_053_rows()] {
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
