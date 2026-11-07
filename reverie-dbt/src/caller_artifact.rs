/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Verified pairing of a caller runtime and its native adapter.

use std::collections::BTreeSet;
use std::io::Read;
use std::io::{self};
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    path: PathBuf,
    sha256: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    abi: u32,
    capabilities: u64,
    runtime_input_identity: String,
    runtime: Input,
    client: Input,
    profile: String,
    target_triple: String,
    toolchain: String,
    inputs: Vec<Input>,
    sdk_recipe: String,
}

/// A source- and byte-bound external caller runtime/native-client pair.
///
/// A manifest is an explicit development artifact. Its declared source inputs
/// must remain present and unchanged. It grants no loader attestation; actual
/// native startup also checks the paired descriptor identity.
#[derive(Clone, Debug)]
pub struct CallerArtifact {
    runtime: PathBuf,
    native_client: PathBuf,
}

impl CallerArtifact {
    /// Verify the supported manifest and every declared input/image before use.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let manifest: Manifest =
            serde_json::from_slice(&std::fs::read(path)?).map_err(io::Error::other)?;
        if manifest.schema != 1
            || manifest.abi != crate::DBT_RUNTIME_ABI_VERSION
            || manifest.capabilities != crate::caller_abi::CALLER_CAPABILITIES
            || manifest.profile.is_empty()
            || manifest.target_triple != "x86_64-unknown-linux-gnu"
            || manifest.toolchain.is_empty()
            || manifest.sdk_recipe.is_empty()
            || manifest.inputs.is_empty()
        {
            return Err(invalid(
                "unsupported or incomplete caller artifact manifest",
            ));
        }
        require_digest(&manifest.runtime_input_identity)?;
        let mut paths = BTreeSet::new();
        let mut identity = Sha256::new();
        for input in &manifest.inputs {
            if !input.path.is_absolute() || !paths.insert(input.path.clone()) {
                return Err(invalid(
                    "caller artifact input paths must be absolute and unique",
                ));
            }
        }
        // The producer uses this same stable path/digest framing. JSON field
        // order and the runtime/client ELF hashes do not feed the input digest.
        let mut inputs = manifest.inputs.iter().collect::<Vec<_>>();
        use std::os::unix::ffi::OsStrExt;
        inputs.sort_by(|a, b| {
            a.path
                .as_os_str()
                .as_bytes()
                .cmp(b.path.as_os_str().as_bytes())
        });
        for input in inputs {
            verify_file(&input.path, &input.sha256)?;
            identity.update(input.path.as_os_str().as_bytes());
            identity.update([0]);
            identity.update(input.sha256.as_bytes());
            identity.update(b"\n");
        }
        if format!("{:x}", identity.finalize()) != manifest.runtime_input_identity {
            return Err(invalid("caller artifact input identity mismatch"));
        }
        verify_sdk_inputs(&manifest.inputs, &manifest.sdk_recipe)?;
        let parent = path
            .parent()
            .ok_or_else(|| invalid("caller manifest has no parent"))?;
        let runtime = resolve(parent, &manifest.runtime.path);
        let native_client = resolve(parent, &manifest.client.path);
        verify_file(&runtime, &manifest.runtime.sha256)?;
        verify_file(&native_client, &manifest.client.sha256)?;
        Ok(Self {
            runtime,
            native_client,
        })
    }

    /// Actual paired client whose linked runtime has been verified.
    pub fn native_client(&self) -> &Path {
        &self.native_client
    }

    /// Actual caller DSO, retained for provenance and loaded-image verification.
    pub fn runtime(&self) -> &Path {
        &self.runtime
    }
}

fn resolve(parent: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        parent.join(path)
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn require_digest(value: &str) -> io::Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        Ok(())
    } else {
        Err(invalid("caller artifact digest is not lowercase SHA256"))
    }
}

fn verify_file(path: &Path, expected: &str) -> io::Result<()> {
    require_digest(expected)?;
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(invalid(
            "caller artifact inputs must name regular files, not symlinks",
        ));
    }
    let mut input = std::fs::File::open(path)?;
    if !input.metadata()?.is_file() {
        return Err(invalid("caller artifact input is not a regular file"));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let size = input.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    if format!("{:x}", hash.finalize()) != expected {
        return Err(invalid(&format!(
            "caller artifact hash mismatch: {}",
            path.display()
        )));
    }
    Ok(())
}

// These are the existing build.rs install-manifest records. The marker bytes
// are already part of the caller input identity; verify their actual payload
// as well, so an unchanged marker cannot conceal a mutated SDK file or link.
fn verify_sdk_inputs(inputs: &[Input], recipe: &str) -> io::Result<()> {
    const INVENTORY: &str = ".reverie-dbt-install.sha256";
    const PROVENANCE: &str = ".reverie-dbt-install.provenance";
    let recipe = recipe
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid("caller SDK recipe is not SHA256"))?;
    require_digest(recipe)?;
    let markers = inputs
        .iter()
        .filter(|input| input.path.file_name().is_some_and(|name| name == INVENTORY))
        .collect::<Vec<_>>();
    if markers.len() != 1 {
        return Err(invalid(
            "caller artifact needs exactly one bound SDK inventory",
        ));
    }
    let root = markers[0]
        .path
        .parent()
        .ok_or_else(|| invalid("SDK inventory has no parent"))?;
    let provenance_path = root.join(PROVENANCE);
    if !inputs.iter().any(|input| input.path == provenance_path) {
        return Err(invalid("caller SDK provenance is not a bound input"));
    }
    let inventory = std::fs::read_to_string(&markers[0].path)?;
    let expected_provenance = format!(
        "schema=reverie-dbt-dynamorio-install-v1\nsource_recipe_sha256={recipe}\nmanifest_sha256={:x}\n",
        Sha256::digest(inventory.as_bytes()),
    );
    if std::fs::read_to_string(provenance_path)? != expected_provenance {
        return Err(invalid(
            "caller SDK provenance does not match its inventory/recipe",
        ));
    }
    let mut declared = BTreeSet::new();
    for line in inventory.lines() {
        let (kind, relative) = if let Some(row) = line.strip_prefix("sha256:") {
            row.split_once(' ')
                .ok_or_else(|| invalid("malformed SDK file record"))?
        } else if let Some(row) = line.strip_prefix("symlink ") {
            row.split_once(' ')
                .ok_or_else(|| invalid("malformed SDK link record"))?
        } else {
            return Err(invalid("unsupported SDK inventory record"));
        };
        let relative = Path::new(relative);
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || !declared.insert(relative.to_owned())
        {
            return Err(invalid("SDK inventory path is invalid or duplicated"));
        }
        let path = root.join(relative);
        if line.starts_with("symlink ") {
            if std::fs::read_link(path)? != Path::new(kind) {
                return Err(invalid("caller SDK symlink changed"));
            }
        } else {
            verify_file(&path, kind)?;
        }
    }
    fn paths(root: &Path, current: &Path, found: &mut BTreeSet<PathBuf>) -> io::Result<()> {
        for entry in std::fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root).map_err(io::Error::other)?;
            if relative == Path::new(INVENTORY) || relative == Path::new(PROVENANCE) {
                continue;
            }
            if entry.file_type()?.is_dir() {
                paths(root, &path, found)?;
            } else {
                found.insert(relative.to_owned());
            }
        }
        Ok(())
    }
    let mut actual = BTreeSet::new();
    paths(root, root, &mut actual)?;
    if declared != actual {
        return Err(invalid("caller SDK inventory no longer covers its files"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn caller_pair_refuses_stale_source_runtime_client_and_wrong_abi() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.rs");
        let runtime = directory.path().join("runtime.so");
        let client = directory.path().join("client.so");
        std::fs::write(&source, b"source").unwrap();
        std::fs::write(&runtime, b"runtime").unwrap();
        std::fs::write(&client, b"client").unwrap();
        let digest = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
        let source_hash = digest(b"source");
        let sdk = directory.path().join("sdk");
        std::fs::create_dir(&sdk).unwrap();
        let payload = sdk.join("payload");
        std::fs::write(&payload, b"sdk bytes").unwrap();
        std::os::unix::fs::symlink("payload", sdk.join("alias")).unwrap();
        let inventory = format!(
            "sha256:{} payload\nsymlink payload alias\n",
            digest(b"sdk bytes")
        );
        let recipe = digest(b"recipe");
        let provenance = format!(
            "schema=reverie-dbt-dynamorio-install-v1\nsource_recipe_sha256={recipe}\nmanifest_sha256={}\n",
            digest(inventory.as_bytes())
        );
        let inventory_path = sdk.join(".reverie-dbt-install.sha256");
        let provenance_path = sdk.join(".reverie-dbt-install.provenance");
        std::fs::write(&inventory_path, &inventory).unwrap();
        std::fs::write(&provenance_path, &provenance).unwrap();
        let mut inputs = vec![
            (source.clone(), source_hash),
            (inventory_path, digest(inventory.as_bytes())),
            (provenance_path, digest(provenance.as_bytes())),
        ];
        use std::os::unix::ffi::OsStrExt;
        inputs.sort_by(|a, b| a.0.as_os_str().as_bytes().cmp(b.0.as_os_str().as_bytes()));
        let mut identity = Sha256::new();
        for (path, hash) in &inputs {
            identity.update(path.as_os_str().as_bytes());
            identity.update([0]);
            identity.update(hash.as_bytes());
            identity.update(b"\n");
        }
        let original = json!({
            "schema":1,"abi":crate::DBT_RUNTIME_ABI_VERSION,
            "capabilities":crate::caller_abi::CALLER_CAPABILITIES,
            "runtime_input_identity":format!("{:x}",identity.finalize()),
            "runtime":{"path":"runtime.so","sha256":digest(b"runtime")},
            "client":{"path":"client.so","sha256":digest(b"client")},
            "profile":"validate","target_triple":"x86_64-unknown-linux-gnu",
            "toolchain":"fixture toolchain","sdk_recipe":format!("sha256:{recipe}"),
            "inputs":inputs.iter().map(|(path, hash)| json!({"path":path,"sha256":hash})).collect::<Vec<_>>()
        });
        let path = directory.path().join("manifest.json");
        std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
        let pair = CallerArtifact::load(&path).unwrap();
        assert_eq!(pair.native_client(), client);
        assert_eq!(pair.runtime(), runtime);
        for (file, bytes) in [
            (&source, b"source".as_slice()),
            (&runtime, b"runtime"),
            (&client, b"client"),
        ] {
            std::fs::write(file, b"changed").unwrap();
            assert!(CallerArtifact::load(&path).is_err());
            std::fs::write(file, bytes).unwrap();
        }
        // Unchanged marker bytes cannot conceal mutated SDK contents, links,
        // or additions outside the declared install inventory.
        std::fs::write(&payload, b"changed sdk").unwrap();
        assert!(CallerArtifact::load(&path).is_err());
        std::fs::write(&payload, b"sdk bytes").unwrap();
        std::fs::remove_file(sdk.join("alias")).unwrap();
        std::os::unix::fs::symlink("other", sdk.join("alias")).unwrap();
        assert!(CallerArtifact::load(&path).is_err());
        std::fs::remove_file(sdk.join("alias")).unwrap();
        std::os::unix::fs::symlink("payload", sdk.join("alias")).unwrap();
        std::fs::write(sdk.join("extra"), b"extra").unwrap();
        assert!(CallerArtifact::load(&path).is_err());
        std::fs::remove_file(sdk.join("extra")).unwrap();
        assert!(CallerArtifact::load(&path).is_ok());
        let mut bad = original.clone();
        bad["abi"] = json!(crate::DBT_RUNTIME_ABI_VERSION - 1);
        std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(CallerArtifact::load(&path).is_err());
        assert!(CallerArtifact::load(directory.path().join("absent.json")).is_err());
    }
}
