//! Fixed receipt check for the root-only interposer. Ordinary executable guest
//! receipts continue to use m1_artifact's unchanged C recipe and verifier.

use std::fs;
use std::path::Path;

use crate::m1_artifact;
use crate::m1_artifact::GuestReceipt;
use crate::m1_artifact::Result;

pub const ROOT_SOURCE: &[u8] =
    include_bytes!("../reverie-liteinst/tests/fixtures/standalone_root_interposer.c");

pub fn root_arguments(source: &Path, output: &Path) -> Vec<String> {
    vec![
        "-std=c11".to_owned(),
        "-O0".to_owned(),
        "-fno-builtin".to_owned(),
        "-fno-lto".to_owned(),
        "-shared".to_owned(),
        "-fPIC".to_owned(),
        "-Wl,-z,now".to_owned(),
        source.to_string_lossy().into_owned(),
        "-o".to_owned(),
        output.to_string_lossy().into_owned(),
    ]
}

pub fn verify_root_receipt(
    receipt_path: &Path,
    selected: &Path,
    expected_source: &Path,
) -> Result<GuestReceipt> {
    let receipt: GuestReceipt =
        serde_json::from_slice(&fs::read(receipt_path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("root-only fixture receipt: {e}"))?;
    if receipt.schema_version != 1
        || receipt.executed_tests != 0
        || receipt.command.status != 0
        || receipt.compiler_version.trim().is_empty()
        || receipt.source.path != m1_artifact::real_file(expected_source)?
        || receipt.source.sha256 != m1_artifact::sha256(ROOT_SOURCE)
        || receipt.binary.path != m1_artifact::real_file(selected)?
        || receipt.command.arguments != root_arguments(&receipt.source.path, &receipt.binary.path)
    {
        return Err("root-only fixture source/identity/recipe differs".to_owned());
    }
    receipt.source.verify()?;
    receipt.binary.verify()?;
    receipt.command.stdout.verify()?;
    receipt.command.stderr.verify()?;
    // The interposer must define precisely the two intended functions and no
    // runtime/query/getter substitute. Its real leaf remains separately bound.
    let bytes = fs::read(selected).map_err(|e| e.to_string())?;
    let elf = goblin::elf::Elf::parse(&bytes).map_err(|e| e.to_string())?;
    let defined: std::collections::BTreeSet<_> = elf
        .dynsyms
        .iter()
        .filter(|symbol| symbol.is_function() && symbol.st_shndx != 0)
        .map(|symbol| elf.dynstrtab.get_at(symbol.st_name).unwrap_or(""))
        .collect();
    if elf.header.e_type != goblin::elf::header::ET_DYN
        || elf.header.e_machine != goblin::elf::header::EM_X86_64
        || defined
            != std::collections::BTreeSet::from([
                "reverie_liteinst_initialize",
                "standalone_root_interposer_calls",
            ])
    {
        return Err("root-only fixture has wrong ELF/export set".to_owned());
    }
    Ok(receipt)
}
