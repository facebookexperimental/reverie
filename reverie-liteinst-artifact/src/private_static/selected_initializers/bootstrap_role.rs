//! Conditional complete 73-byte Bootstrap::role leaf; not project validation.
//!
//! Actual ABI premises: enter the exact observed start; RDI denotes disjoint,
//! aligned live writable result storage >=24 bytes; RSI a valid immutable 24-byte
//! Bootstrap representation (backing pointer, length, represented address), RDX
//! the index. Its entire nonwrapping backing is live/readable, code is immutable,
//! stack/return address and callee-saved state valid. Output must not alias that
//! representation, backing, code or return slot. Signal/exception preservation,
//! host validation, role extent meanings and caller discriminator use remain
//! separate obligations. This factory proves none of these physical premises.
//!
//! Complete finite block argument, entry-relative half-open ranges:
//! 00..09 saves output pointer in RAX and refuses unsigned index>=5 at29.
//! 09..1d reads length and computes 16*i+0xe7; i<=4 makes arithmetic safe.
//! It branches29 unless the first word's last byte is strictly below length.
//! 1d..29 computes 16*i+0xef and reaches32 only if it is below length.
//! 29..32 writes Error::Bounds byte2 at output+1, tag1 at output+0, RET.
//! 32..49 loads backing pointer, adds 0xe0 to bounded 16*i, copies precisely16
//! bytes to output+8 via unaligned XMM loads/stores, writes tag0 and RET.
//! RAX returns the output pointer on both paths. Error padding/payload remains
//! unspecified; success copies the two words without validating their meanings.
//! The complete body has no call, loop, indirect branch, relocation, TLS/FS/GS,
//! allocator, panic, syscall or UD2. RET assumes the valid actual caller ABI.
//! This conditional normal-return fact does not establish source-qualified
//! role contents, descriptor/project/iterator closure, async safety or Ready.
use super::view_table::PlainLeafKind;
use super::view_table::ViewTableLeafObservation;
use super::*;

pub(super) const SIZE: usize = 73;
pub(super) const SYMBOL: &str = "_RNvMs1_NtCs_14reverie_loader7handoffNtB5_9Bootstrap4role";
const SOURCE_SHA: &str = "85abd905256f3bc5b526840cf3cd5e090238e4aa770f03d320c2ae907ee7ae75";
const INPUT: [u8; SIZE] = [
    0x48, 0x89, 0xf8, 0x48, 0x83, 0xfa, 0x05, 0x73, 0x20, 0x48, 0x8b, 0x4e, 0x08, 0x48, 0xc1, 0xe2,
    0x04, 0x48, 0x8d, 0xba, 0xe7, 0x00, 0x00, 0x00, 0x48, 0x39, 0xcf, 0x73, 0x0c, 0x48, 0x8d, 0xba,
    0xef, 0x00, 0x00, 0x00, 0x48, 0x39, 0xcf, 0x72, 0x09, 0xc6, 0x40, 0x01, 0x02, 0xb1, 0x01, 0x88,
    0x08, 0xc3, 0x48, 0x8b, 0x0e, 0x48, 0x81, 0xc2, 0xe0, 0x00, 0x00, 0x00, 0x0f, 0x10, 0x04, 0x11,
    0x0f, 0x11, 0x40, 0x08, 0x31, 0xc9, 0x88, 0x08, 0xc3,
];
pub(super) fn source_symbol(digest: &str) -> Result<&'static str> {
    require(
        digest == SOURCE_SHA,
        "Bootstrap::role complete runtime source differs",
    )?;
    Ok(SYMBOL)
}
pub(super) fn selected_name(name: &str, expected: &str) -> bool {
    !name.contains('.') && canonical_rust_symbol(name).as_deref() == Some(expected)
}
pub(super) fn code_form(bytes: &[u8]) -> Result<()> {
    require(
        bytes == INPUT.as_slice(),
        "Bootstrap::role complete finite form differs",
    )
}

/// Private-construction conditional normal-return fact, never entry permission.
/// The nested legacy provenance record carries no Records-result claim here;
/// its scope is explicitly ROLE, with no public conversion to a View observation.
#[derive(Debug, Serialize)]
pub struct BootstrapRoleLeafObservation {
    identity: ViewTableLeafObservation,
}
impl BootstrapRoleLeafObservation {
    /// Actual entry; this does not authorize calling it or validate its caller.
    pub fn entry(&self) -> u64 {
        self.identity.entry()
    }
    /// Under the documented premises, byte0 is Ok=0 or Err=1. Err has Bounds=2
    /// at byte1; only Ok initializes the copied two-word role at bytes8..24.
    pub fn conditional_result_tags(&self) -> [u8; 2] {
        [0, 1]
    }
}
/// Actual compiled checker identity for the closed source catalog.
pub fn bootstrap_role_implementation_sha256() -> String {
    sha256(include_bytes!("bootstrap_role.rs"))
}
impl VerifiedStaticSource {
    /// Observe this exact role leaf in the SAME live source/archive/definitions
    /// transaction. Existing full source/build-output/archive/ELF/map closures
    /// run on success and errors, including callback errors. No public supplied
    /// code, source name or policy can create this observation. Its caller and
    /// memory premises remain unproved, and it provides no entry or Ready API.
    pub fn with_bootstrap_role_leaf<T>(
        &self,
        archive: &StaticArchive,
        definitions: &SelectedInitializerDefinitions,
        artifact: &FileIdentity,
        link_map: &FileIdentity,
        runner: &mut Runner,
        body: impl FnOnce(&BootstrapRoleLeafObservation, &mut Runner) -> Result<T>,
    ) -> Result<T> {
        self.with_plain_leaf(
            PlainLeafKind::BootstrapRole,
            archive,
            definitions,
            (artifact, link_map),
            runner,
            |identity, runner| body(&BootstrapRoleLeafObservation { identity }, runner),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NAME: &str = "_RNvMs1_NtCsunit_14reverie_loader7handoffNtB5_9Bootstrap4role";
    #[test]
    fn bootstrap_role_complete_source_name_and_unknown_cohorts() {
        assert_eq!(source_symbol(SOURCE_SHA).unwrap(), SYMBOL);
        assert!(selected_name(NAME, SYMBOL));
        for digest in [
            "0".repeat(64),
            SOURCE_SHA[..63].to_owned(),
            format!("{SOURCE_SHA}0"),
            SOURCE_SHA.to_ascii_uppercase(),
        ] {
            assert!(source_symbol(&digest).is_err());
        }
        for name in [
            NAME.replace("Ms1_", "Ms2_"),
            NAME.replace("4role", "4site"),
            format!("{NAME}.llvm.0"),
        ] {
            assert!(!selected_name(&name, SYMBOL));
        }
    }
    #[test]
    fn bootstrap_role_every_byte_bound_and_return_store_is_exact() {
        code_form(&INPUT).unwrap();
        assert!(code_form(&INPUT[..72]).is_err());
        for i in 0..SIZE {
            let mut wrong = INPUT;
            wrong[i] ^= 1;
            assert!(code_form(&wrong).is_err(), "changed instruction byte {i}");
        }
        // These are actual bytes: index limit, both last-byte checks, tag/error,
        // copied 16-byte success payload and final success tag; no masks exist.
        assert_eq!(&INPUT[3..9], &[0x48, 0x83, 0xfa, 5, 0x73, 0x20]);
        assert_eq!(
            &INPUT[0x29..0x32],
            &[0xc6, 0x40, 1, 2, 0xb1, 1, 0x88, 8, 0xc3]
        );
    }
    #[test]
    fn bootstrap_role_zero_relocation_contract_includes_noop_and_crossing_writers() {
        use super::super::view_table::refuse_writer;
        use super::super::view_table::tests::plain_fixture;
        let bytes = plain_fixture(true, false, false, NAME, &INPUT);
        let elf = Elf::parse(&bytes).unwrap();
        let text = &elf.section_headers[1];
        let start = 0x100000;
        for (at, kind) in [
            (start, 0),
            (start, 2),
            (start - 1, 2),
            (start - 1, u32::MAX),
        ] {
            assert!(refuse_writer(text, at, kind, start, start + 73).is_err());
        }
        refuse_writer(text, start - 8, 1, start, start + 73).unwrap();
    }
    #[test]
    fn bootstrap_role_parsed_input_refuses_alias_relocation_and_geometry() {
        use super::super::view_table::check_plain_input_fixture;
        use super::super::view_table::tests::plain_fixture;
        let fixture = |writer, alias| plain_fixture(false, writer, alias, NAME, &INPUT);
        check_plain_input_fixture(&fixture(false, false), NAME).unwrap();
        assert!(check_plain_input_fixture(&fixture(false, true), NAME).is_err());
        assert!(check_plain_input_fixture(&fixture(true, false), NAME).is_err());
        let mut bad = fixture(false, false);
        bad[0x2800 + 64 + 32..0x2800 + 64 + 40].copy_from_slice(&74u64.to_le_bytes());
        assert!(check_plain_input_fixture(&bad, NAME).is_err());
        let mut bad = fixture(false, false);
        bad[0x100 + 7] ^= 1;
        assert!(check_plain_input_fixture(&bad, NAME).is_err());
    }
    #[test]
    fn bootstrap_role_parsed_final_refuses_writer_alias_rx_and_bytes() {
        use super::super::view_table::check_plain_final_fixture;
        use super::super::view_table::tests::plain_fixture;
        let fixture = |writer, alias| plain_fixture(true, writer, alias, NAME, &INPUT);
        check_plain_final_fixture(&fixture(false, false), NAME).unwrap();
        for bad in [fixture(true, false), fixture(false, true)] {
            assert!(check_plain_final_fixture(&bad, NAME).is_err());
        }
        let mut bad = fixture(false, false);
        bad[68..72].copy_from_slice(&7u32.to_le_bytes());
        assert!(check_plain_final_fixture(&bad, NAME).is_err());
        let mut bad = fixture(false, false);
        bad[0x1000 + 0x44] ^= 1;
        assert!(check_plain_final_fixture(&bad, NAME).is_err());
        let mut bad = fixture(false, false);
        bad[0x2238..0x2240].copy_from_slice(&0x100001u64.to_le_bytes());
        assert!(check_plain_final_fixture(&bad, NAME).is_err());
    }
}
