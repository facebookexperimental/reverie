//! Additive source-bound direct-public-call guest; never compiles a runtime.
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use crate::m1_artifact;
use crate::m1_artifact::FileIdentity;
use crate::m1_artifact::GuestReceipt;
use crate::m1_artifact::Result;
use crate::m1_artifact::Runner;

pub const SOURCE: &[u8] =
    include_bytes!("../reverie-liteinst/tests/fixtures/generic_bootstrap_guest.c");
pub const GUEST_ENV: &str = "REVERIE_LITEINST_GENERIC_GUEST";
pub const RECEIPT_ENV: &str = "REVERIE_LITEINST_GENERIC_GUEST_MANIFEST";

pub fn produce(root: &Path, bundle: &Path, runner: &mut Runner) -> Result<(PathBuf, PathBuf)> {
    let source = FileIdentity::read(
        &root.join("reverie-liteinst/tests/fixtures/generic_bootstrap_guest.c"),
    )?;
    if source.sha256 != m1_artifact::sha256(SOURCE) {
        return Err("generic guest compiled/current source differs".into());
    }
    let binary = bundle.join("generic_bootstrap_guest");
    let receipt_path = bundle.join("generic-bootstrap-guest.json");
    if binary.exists() || receipt_path.exists() {
        return Err("generic guest outputs must be fresh".into());
    }
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let compiler_version = runner.text(&compiler, &["--version"], root)?;
    runner.run(
        &compiler,
        &[
            "-std=c11".into(),
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            "-fsyntax-only".into(),
            source.path.to_string_lossy().into_owned(),
        ],
        root,
    )?;
    runner.run(
        &compiler,
        &[
            "-std=c11".into(),
            "-O0".into(),
            "-fno-builtin".into(),
            "-fno-lto".into(),
            "-Wl,--export-dynamic".into(),
            "-Wl,-z,now".into(),
            source.path.to_string_lossy().into_owned(),
            "-o".into(),
            binary.to_string_lossy().into_owned(),
            "-ldl".into(),
        ],
        root,
    )?;
    let receipt = GuestReceipt {
        schema_version: 1,
        source,
        binary: FileIdentity::read(&binary)?,
        compiler_version,
        command: runner
            .commands
            .last()
            .ok_or("generic compiler record missing")?
            .clone(),
        executed_tests: 0,
    };
    m1_artifact::write_new(
        &receipt_path,
        &serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?,
    )?;
    verify(&receipt_path, &binary, root)?;
    Ok((binary, receipt_path))
}

pub fn verify(receipt: &Path, guest: &Path, root: &Path) -> Result<GuestReceipt> {
    let accepted = m1_artifact::verify_guest_receipt(
        receipt,
        guest,
        &root.join("reverie-liteinst/tests/fixtures/generic_bootstrap_guest.c"),
        &m1_artifact::sha256(SOURCE),
    )?;
    let bytes = fs::read(guest).map_err(|e| e.to_string())?;
    let elf = goblin::elf::Elf::parse(&bytes).map_err(|e| e.to_string())?;
    for name in [
        "generic_fixture_call",
        "generic_bootstrap_call_site",
        "generic_bootstrap_return_site",
        "getenv",
    ] {
        if !elf
            .syms
            .iter()
            .any(|symbol| elf.strtab.get_at(symbol.st_name) == Some(name) && symbol.st_shndx != 0)
        {
            return Err(format!("generic guest lacks actual {name}"));
        }
    }
    Ok(accepted)
}
