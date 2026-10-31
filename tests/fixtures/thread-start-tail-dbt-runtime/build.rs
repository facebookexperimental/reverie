/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

use std::path::PathBuf;

fn identity(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("caller input identity must be exactly 64 lowercase hexadecimal characters");
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "malformed caller input identity")?;
    }
    Ok(bytes)
}

fn main() {
    println!("cargo:rerun-if-env-changed=REVERIE_DBT_CALLER_INPUT_IDENTITY");
    println!("cargo:rerun-if-changed=build.rs");
    let input = std::env::var("REVERIE_DBT_CALLER_INPUT_IDENTITY").expect(
        "caller identity is required; use reverie-dbt/scripts/build-client.sh --caller-manifest",
    );
    let identity = identity(&input).expect("invalid caller input identity");
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo did not supply OUT_DIR"));
    std::fs::write(
        output.join("caller_identity.rs"),
        format!("const CALLER_INPUT_IDENTITY: [u8; 32] = {identity:?};\n"),
    )
    .expect("write generated caller identity");
}

#[cfg(test)]
mod tests {
    use super::identity;

    #[test]
    fn identity_is_exact_and_has_no_default() {
        assert_eq!(identity(&"a5".repeat(32)).unwrap(), [0xa5; 32]);
        for invalid in [
            String::new(),
            "0".repeat(63),
            "0".repeat(65),
            "AA".repeat(32),
            "zz".repeat(32),
        ] {
            assert!(identity(&invalid).is_err());
        }
    }
}
