//! Shared, fixed M1 allocator oracle adapter for RV and H integration tests.
//!
//! One source is shared by RV and H consumers; no consumer builds live here.
//! Frozen RV fixture: 4f4315c39029a56927d910abc9d2a47a696b0a83.
//! C SHA256: e21fd8768d61edc7d14f51b98e2c5f9087fd4ddcfa08a19a2ca646b6df912b2e.
//! Rust export SHA256: d85c3094519855dde18571047b945aeca112b8e4df2138cff83fc33bfba0bce8.
//! M1 design SHA256: 2a1f1070176c04acfec13451ac067c3a46ef9cb2e866fe20e909d099264e84ee.
//!
//! The caller owns artifact/constructor/shim identity, real launcher selection,
//! fixed placement, resource boxing and guest-exit propagation. No Cargo/build
//! command, runtime discovery, address normalization or automatic retry lives here.
//! Hidden libc allocation, TLS/stacks/protection and the 96 MiB host control are
//! separate gates. Payload zero/prefix/content checks remain in the unchanged C:
//! they are accepted only with its actual successful exit, zero failures, complete
//! selected rows and the exact expected operation sequence.
//!
//! parse_trial preserves failing baseline observations. Only compare_pair plus
//! validate_matrix can certify this adapter's candidate matrix; Q is a control.

use std::ffi::OsString;
use std::fmt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::time::Duration;

pub const WALL_LIMIT: Duration = Duration::from_secs(120);
pub const OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
pub const PRIVATE_HEAP_BYTES: u64 = 32 * 1024 * 1024;
pub const EXHAUSTION_BYTES: u64 = 64 * 1024 * 1024 + 4096;
pub const ROUTES: [&str; 6] = [
    "malloc",
    "calloc",
    "realloc",
    "free",
    "aligned_alloc",
    "posix_memalign",
];
pub const CASE_NAMES: [&str; 6] = [
    "small",
    "zeroed",
    "grow_shrink",
    "overaligned",
    "retained",
    "exhaustion",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureCase {
    Small,
    Zeroed,
    GrowShrink,
    Overaligned,
    Retained,
    Exhaustion,
    Composition,
}

pub const FIXED_CASES: [FixtureCase; 7] = [
    FixtureCase::Small,
    FixtureCase::Zeroed,
    FixtureCase::GrowShrink,
    FixtureCase::Overaligned,
    FixtureCase::Retained,
    FixtureCase::Exhaustion,
    FixtureCase::Composition,
];

impl FixtureCase {
    pub const fn selector(self) -> u8 {
        match self {
            Self::Small => b'S',
            Self::Zeroed => b'Z',
            Self::GrowShrink => b'G',
            Self::Overaligned => b'O',
            Self::Retained => b'R',
            Self::Exhaustion => b'E',
            Self::Composition => b'A',
        }
    }

    pub const fn work_operations(self) -> usize {
        match self {
            Self::Small | Self::Zeroed | Self::Overaligned => 2,
            Self::GrowShrink => 4,
            Self::Retained => 32,
            Self::Exhaustion => 1,
            Self::Composition => 43,
        }
    }

    fn selected(self, index: usize) -> bool {
        self == Self::Composition || FIXED_CASES[index] == self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Quiet,
    Work,
}

impl Mode {
    pub const fn byte(self) -> u8 {
        match self {
            Self::Quiet => b'Q',
            Self::Work => b'W',
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrialKey {
    pub mode: Mode,
    pub case: FixtureCase,
}

impl TrialKey {
    pub const fn input(self) -> [u8; 2] {
        [self.mode.byte(), self.case.selector()]
    }
}

/// Hold this once for the complete matrix. The runner clears inheritance and
/// installs exactly this environment; it never varies argv/env to select Q/W.
/// policy records caller-held seed/personality/ASLR/epoch/artifact inputs that
/// are not expressible in Command getters. Their actual enforcement is the
/// launcher's responsibility.
#[derive(Clone, Eq, PartialEq)]
pub struct HeldInputs {
    pub environment: Vec<(OsString, OsString)>,
    pub policy: Vec<u8>,
}

impl fmt::Debug for HeldInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeldInputs")
            .field(
                "environment_names",
                &self.environment.iter().map(|p| &p.0).collect::<Vec<_>>(),
            )
            .field("policy_bytes", &self.policy.len())
            .finish()
    }
}

/// Raw Command program/argument/cwd values and the held launch inputs. No path,
/// argument, environment or byte normalization is performed by the comparator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchIdentity {
    pub program: OsString,
    pub arguments: Vec<OsString>,
    pub current_dir: PathBuf,
    pub held: HeldInputs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureEnd {
    Complete,
    Deadline,
    OutputLimit,
    IoFailure(String),
}

#[derive(Clone)]
pub struct CapturedRun {
    pub status: Option<ExitStatus>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Exact fixture input, or None for a command with closed stdin.
    pub input: Option<[u8; 2]>,
    pub launch: LaunchIdentity,
    pub elapsed: Duration,
    pub end: CaptureEnd,
    /// True means the output cap retained a raw prefix; it is always a failure.
    pub output_truncated: bool,
}

impl fmt::Debug for CapturedRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedRun")
            .field("status", &self.status)
            .field("input", &self.input)
            .field("launch", &self.launch)
            .field("elapsed", &self.elapsed)
            .field("end", &self.end)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("output_truncated", &self.output_truncated)
            .finish()
    }
}

pub struct ContractError {
    pub message: String,
    /// Preserve original stream bytes even when parsing or comparisons fail.
    pub captures: Vec<CapturedRun>,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl fmt::Debug for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContractError")
            .field("message", &self.message)
            .field("captures", &self.captures)
            .finish()
    }
}

impl std::error::Error for ContractError {}

fn error(message: impl Into<String>, captures: &[&CapturedRun]) -> ContractError {
    ContractError {
        message: message.into(),
        captures: captures.iter().map(|c| (**c).clone()).collect(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HexValue {
    pub value: u64,
    /// Kept as emitted; paired address checks compare this literal too.
    pub literal: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Region {
    pub start: u64,
    pub end: u64,
}

impl Region {
    fn contains(self, pointer: u64, size: u64) -> bool {
        pointer != 0
            && pointer >= self.start
            && pointer < self.end
            && pointer.checked_add(size).is_some_and(|end| end <= self.end)
    }

    fn overlaps(self, pointer: u64, size: u64) -> bool {
        pointer
            .checked_add(size)
            .is_some_and(|end| pointer < self.end && self.start < end)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatcherRow {
    pub positive_control: u64,
    pub export_entries: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaseRow {
    pub selected: bool,
    pub executed: bool,
    pub complete: bool,
}

#[derive(Clone, Debug)]
pub struct Operation {
    pub index: usize,
    pub name: String,
    pub return_status: u64,
    pub status: u64,
    pub pointer: u64,
    pub size: u64,
    pub align: u64,
    pub private_member: u64,
    pub depths: [u64; 4],
    pub breaks: [HexValue; 2],
    pub calls: [u64; 6],
}

#[derive(Clone, Debug)]
pub struct TrialReport {
    pub key: TrialKey,
    pub owner_base: HexValue,
    pub declared_operations: usize,
    pub c_failures: u64,
    pub regions: [Region; 2],
    pub watchers: [WatcherRow; 6],
    pub cases: [CaseRow; 6],
    pub operations: Vec<Operation>,
    pub guest: HexValue,
    pub next: HexValue,
    pub breaks: [HexValue; 2],
    pub payload_hashes: [HexValue; 2],
    pub guest_bytes: Vec<u8>,
    pub next_bytes: Vec<u8>,
    pub guest_bytes_literal: Vec<u8>,
    pub next_bytes_literal: Vec<u8>,
}

fn fields<'a>(line: &'a [u8], prefix: &[u8], keys: &[&str]) -> Result<Vec<&'a [u8]>, String> {
    let rest = line.strip_prefix(prefix).ok_or_else(|| {
        format!(
            "missing protocol prefix {:?}",
            String::from_utf8_lossy(prefix)
        )
    })?;
    let tokens: Vec<_> = rest.split(|b| *b == b' ').collect();
    if tokens.len() != keys.len() {
        return Err(format!(
            "protocol field count {} differs from {}",
            tokens.len(),
            keys.len()
        ));
    }
    tokens
        .iter()
        .zip(keys)
        .map(|(token, key)| {
            let equals = token
                .iter()
                .position(|b| *b == b'=')
                .ok_or("protocol field lacks equals sign")?;
            if &token[..equals] != key.as_bytes() || equals + 1 == token.len() {
                return Err(format!("expected nonempty field {key}"));
            }
            Ok(&token[equals + 1..])
        })
        .collect()
}

fn decimal(value: &[u8]) -> Result<u64, String> {
    if value.is_empty()
        || !value.iter().all(u8::is_ascii_digit)
        || (value.len() > 1 && value[0] == b'0')
    {
        return Err("noncanonical decimal field".into());
    }
    std::str::from_utf8(value)
        .map_err(|_| "non-ASCII decimal")?
        .parse()
        .map_err(|_| "decimal overflow".into())
}

fn hex(value: &[u8]) -> Result<HexValue, String> {
    let digits = value
        .strip_prefix(b"0x")
        .ok_or("hex field lacks literal 0x prefix")?;
    if digits.is_empty()
        || !digits
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        || (digits.len() > 1 && digits[0] == b'0')
    {
        return Err("noncanonical hexadecimal field".into());
    }
    let number = u64::from_str_radix(
        std::str::from_utf8(digits).map_err(|_| "non-ASCII hex")?,
        16,
    )
    .map_err(|_| "hexadecimal overflow")?;
    Ok(HexValue {
        value: number,
        literal: value.to_vec(),
    })
}

fn list<const N: usize>(value: &[u8]) -> Result<[&[u8]; N], String> {
    value
        .split(|b| *b == b',')
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| format!("expected exactly {N} comma-separated fields"))
}

fn decimal_list<const N: usize>(value: &[u8]) -> Result<[u64; N], String> {
    list::<N>(value)?
        .into_iter()
        .map(decimal)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "internal decimal-list length".into())
}

fn hex_pair(value: &[u8]) -> Result<[HexValue; 2], String> {
    list::<2>(value)?
        .into_iter()
        .map(hex)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "internal hex-pair length".into())
}

fn bit(value: &[u8]) -> Result<bool, String> {
    match value {
        b"0" => Ok(false),
        b"1" => Ok(true),
        _ => Err("case flag must be literal 0 or 1".into()),
    }
}

fn region(value: &[u8]) -> Result<Region, String> {
    let inside = value
        .strip_prefix(b"[")
        .and_then(|v| v.strip_suffix(b")"))
        .ok_or("region must retain half-open [start,end) syntax")?;
    let [start, end] = hex_pair(inside)?;
    Ok(Region {
        start: start.value,
        end: end.value,
    })
}

fn payload_hex(value: &[u8], size: usize) -> Result<Vec<u8>, String> {
    if value.len() != size * 2 {
        return Err(format!(
            "payload hex length {} differs from {}",
            value.len(),
            size * 2
        ));
    }
    value
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            if !pair
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            {
                return Err("payload must retain lowercase literal hex bytes".into());
            }
            u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| "non-ASCII payload")?,
                16,
            )
            .map_err(|_| "invalid payload byte".into())
        })
        .collect()
}

/// Parse raw C records, including genuine failing-baseline records. Parsing
/// alone never asserts success, private allocation or the Q/W address contract.
pub fn parse_trial(
    stdout: &[u8],
    key: TrialKey,
    expected_owner: &Path,
) -> Result<TrialReport, String> {
    #[cfg(not(unix))]
    let owner = expected_owner
        .to_str()
        .ok_or("non-UTF8 owner on non-Unix host")?
        .as_bytes();
    #[cfg(unix)]
    let owner = {
        use std::os::unix::ffi::OsStrExt;
        expected_owner.as_os_str().as_bytes()
    };
    if owner.is_empty() || owner.contains(&b'\n') || owner.contains(&b'\r') || owner.contains(&0) {
        return Err("expected owner must be an exact nonempty single-line path".into());
    }
    // The source has at most 64 operation observations. Bound parser metadata,
    // reject excess records, and preserve unrelated launcher diagnostics raw.
    const MAX_RECORDS: usize = 1 + 1 + 6 + 6 + 64 + 3;
    let records: Vec<_> = stdout
        .split(|b| *b == b'\n')
        .filter(|line| line.starts_with(b"m1 "))
        .take(MAX_RECORDS + 1)
        .collect();
    if records.len() > MAX_RECORDS {
        return Err("too many fixture records (duplicate/spurious output)".into());
    }
    let mut cursor = records.into_iter();
    let mut row = || {
        cursor
            .next()
            .ok_or_else(|| "missing required fixture record".to_owned())
    };
    let mut prefix = format!(
        "m1 fixture abi=1 mode={} case={} owner=",
        key.mode.byte() as char,
        key.case.selector() as char
    )
    .into_bytes();
    prefix.extend_from_slice(owner);
    prefix.push(b' ');
    let header = fields(row()?, &prefix, &["owner_base", "operations", "failures"])?;
    let owner_base = hex(header[0])?;
    let declared_operations =
        usize::try_from(decimal(header[1])?).map_err(|_| "operation count overflow")?;
    if declared_operations > 64 {
        return Err("operation count exceeds frozen C observation capacity".into());
    }
    let c_failures = decimal(header[2])?;
    let ranges = fields(row()?, b"m1 ranges ", &["tool", "patch"])?;
    let regions = [region(ranges[0])?, region(ranges[1])?];
    let mut watchers = [WatcherRow {
        positive_control: 0,
        export_entries: 0,
    }; 6];
    for (index, name) in ROUTES.iter().enumerate() {
        let values = fields(row()?, b"m1 watcher ", &["route", "self", "export"])?;
        if values[0] != name.as_bytes() {
            return Err(format!("watcher order/name differs at route {name}"));
        }
        watchers[index] = WatcherRow {
            positive_control: decimal(values[1])?,
            export_entries: decimal(values[2])?,
        };
    }
    let mut cases = [CaseRow {
        selected: false,
        executed: false,
        complete: false,
    }; 6];
    for (index, name) in CASE_NAMES.iter().enumerate() {
        let values = fields(
            row()?,
            b"m1 case ",
            &["name", "selected", "executed", "complete"],
        )?;
        if values[0] != name.as_bytes() {
            return Err(format!("case order/name differs at {name}"));
        }
        cases[index] = CaseRow {
            selected: bit(values[1])?,
            executed: bit(values[2])?,
            complete: bit(values[3])?,
        };
    }
    let mut operations = Vec::with_capacity(declared_operations);
    for index in 0..declared_operations {
        let values = fields(
            row()?,
            b"m1 op ",
            &[
                "index", "name", "rc", "status", "pointer", "size", "align", "private", "depths",
                "brk", "calls",
            ],
        )?;
        if decimal(values[0])? != index as u64 {
            return Err("operation indices are not contiguous from zero".into());
        }
        operations.push(Operation {
            index,
            name: std::str::from_utf8(values[1])
                .map_err(|_| "non-ASCII operation name")?
                .to_owned(),
            return_status: decimal(values[2])?,
            status: decimal(values[3])?,
            pointer: hex(values[4])?.value,
            size: decimal(values[5])?,
            align: decimal(values[6])?,
            private_member: decimal(values[7])?,
            depths: decimal_list(values[8])?,
            breaks: hex_pair(values[9])?,
            calls: decimal_list(values[10])?,
        });
    }
    let values = fields(
        row()?,
        b"m1 addresses ",
        &[
            "guest",
            "next",
            "brk",
            "payload_hash",
            "exact_address_comparison",
            "full_M1_pass",
        ],
    )?;
    if values[4] != b"pending_external" || values[5] != b"unclaimed" {
        return Err("frozen per-trial nonclaim markers changed".into());
    }
    let guest = hex(values[0])?;
    let next = hex(values[1])?;
    let breaks = hex_pair(values[2])?;
    let payload_hashes = hex_pair(values[3])?;
    let guest_bytes_literal = row()?
        .strip_prefix(b"m1 guest_bytes=")
        .ok_or("missing literal guest_bytes record")?
        .to_vec();
    let next_bytes_literal = row()?
        .strip_prefix(b"m1 next_bytes=")
        .ok_or("missing literal next_bytes record")?
        .to_vec();
    let guest_bytes = payload_hex(&guest_bytes_literal, 333)?;
    let next_bytes = payload_hex(&next_bytes_literal, 777)?;
    if row().is_ok() {
        return Err("duplicate or trailing fixture record".into());
    }
    Ok(TrialReport {
        key,
        owner_base,
        declared_operations,
        c_failures,
        regions,
        watchers,
        cases,
        operations,
        guest,
        next,
        breaks,
        payload_hashes,
        guest_bytes,
        next_bytes,
        guest_bytes_literal,
        next_bytes_literal,
    })
}

#[derive(Clone, Copy)]
enum Action {
    Allocate(usize),
    Reallocate(usize),
    Deallocate(usize),
    Exhaustion,
}

#[derive(Clone, Copy)]
struct ExpectedOperation {
    name: &'static str,
    size: u64,
    align: u64,
    action: Action,
}

fn expected_operations(case: FixtureCase) -> Vec<ExpectedOperation> {
    fn push(
        out: &mut Vec<ExpectedOperation>,
        name: &'static str,
        size: u64,
        align: u64,
        action: Action,
    ) {
        out.push(ExpectedOperation {
            name,
            size,
            align,
            action,
        });
    }
    fn one(case: FixtureCase, out: &mut Vec<ExpectedOperation>) {
        match case {
            FixtureCase::Small | FixtureCase::Zeroed | FixtureCase::Overaligned => {
                let (name, size, align) = match case {
                    FixtureCase::Small => ("alloc", 64, 16),
                    FixtureCase::Zeroed => ("alloc_zeroed", 257, 16),
                    _ => ("alloc", 4096, 4096),
                };
                push(out, name, size, align, Action::Allocate(0));
                push(out, "dealloc", size, align, Action::Deallocate(0));
            }
            FixtureCase::GrowShrink => {
                push(out, "alloc", 64, 16, Action::Allocate(0));
                push(out, "realloc", 4096, 16, Action::Reallocate(0));
                push(out, "realloc", 32, 16, Action::Reallocate(0));
                push(out, "dealloc", 32, 16, Action::Deallocate(0));
            }
            FixtureCase::Retained => {
                for _cycle in 0..2 {
                    for slot in 0..8 {
                        push(
                            out,
                            "alloc",
                            31 + slot as u64 * 37,
                            16,
                            Action::Allocate(slot),
                        );
                    }
                    for slot in [3, 0, 7, 2, 5, 1, 6, 4] {
                        push(
                            out,
                            "dealloc",
                            31 + slot as u64 * 37,
                            16,
                            Action::Deallocate(slot),
                        );
                    }
                }
            }
            FixtureCase::Exhaustion => {
                push(
                    out,
                    "exhaustion_alloc",
                    EXHAUSTION_BYTES,
                    16,
                    Action::Exhaustion,
                );
            }
            FixtureCase::Composition => {
                for individual in FIXED_CASES.into_iter().take(6) {
                    one(individual, out);
                }
            }
        }
    }
    let mut expected = Vec::with_capacity(case.work_operations());
    one(case, &mut expected);
    expected
}

#[derive(Clone, Copy)]
struct LiveAllocation {
    pointer: u64,
    size: u64,
    align: u64,
}

fn validate_report(report: &TrialReport) -> Result<(), String> {
    if report.owner_base.value == 0 || report.c_failures != 0 {
        return Err(format!(
            "owner base/unchanged C checks failed (C failures={})",
            report.c_failures
        ));
    }
    for pool in report.regions {
        if pool.start == 0 || pool.end.checked_sub(pool.start) != Some(PRIVATE_HEAP_BYTES) {
            return Err("actual backing pool differs from the frozen 32 MiB extent".into());
        }
    }
    if !(report.regions[0].end <= report.regions[1].start
        || report.regions[1].end <= report.regions[0].start)
    {
        return Err("Tool and patch backing pools overlap".into());
    }
    for (name, watcher) in ROUTES.iter().zip(report.watchers) {
        if watcher.positive_control == 0 || watcher.export_entries != 0 {
            return Err(format!(
                "watcher {name}: positive={} export={} (required positive and zero export)",
                watcher.positive_control, watcher.export_entries
            ));
        }
    }
    for (index, row) in report.cases.iter().enumerate() {
        let selected = report.key.case.selected(index);
        let executed = selected && report.key.mode == Mode::Work;
        if *row
            != (CaseRow {
                selected,
                executed,
                complete: executed,
            })
        {
            return Err(format!(
                "selected/executed/complete row differs for {}",
                CASE_NAMES[index]
            ));
        }
    }
    let expected = if report.key.mode == Mode::Work {
        expected_operations(report.key.case)
    } else {
        Vec::new()
    };
    let count = if report.key.mode == Mode::Work {
        report.key.case.work_operations()
    } else {
        0
    };
    if report.declared_operations != count
        || report.operations.len() != count
        || expected.len() != count
    {
        return Err(format!(
            "mode {:?} case {:?}: operations declared={} observed={} required={count}",
            report.key.mode,
            report.key.case,
            report.declared_operations,
            report.operations.len()
        ));
    }
    if report.breaks[0] != report.breaks[1] {
        return Err("literal guest break changed during the selected workload".into());
    }
    let mut live: [Option<LiveAllocation>; 8] = [None; 8];
    let mut totals = [0_u64; 6];
    for (actual, expected) in report.operations.iter().zip(expected) {
        if actual.name != expected.name
            || actual.size != expected.size
            || actual.align != expected.align
        {
            return Err(format!(
                "operation {} name/layout differs from frozen C workload",
                actual.index
            ));
        }
        if actual.depths != [0; 4] {
            return Err(format!(
                "operation {} observed nonzero actual scope depths {:?}",
                actual.index, actual.depths
            ));
        }
        if actual.return_status != actual.status || actual.calls != [0; 6] {
            return Err(format!(
                "operation {} return/status or zero-entry oracle failed",
                actual.index
            ));
        }
        if actual.breaks[0] != actual.breaks[1] || actual.breaks[0] != report.breaks[0] {
            return Err(format!(
                "operation {} literal brk observation changed",
                actual.index
            ));
        }
        for (total, calls) in totals.iter_mut().zip(actual.calls) {
            *total = total.checked_add(calls).ok_or("watcher sum overflow")?;
        }
        if matches!(expected.action, Action::Exhaustion) {
            if actual.return_status != 2
                || actual.status != 2
                || actual.pointer != 0
                || actual.private_member != 0
            {
                return Err("private exhaustion must be the real fallible status2/null result, never System success/cleanup".into());
            }
            continue;
        }
        if actual.status != 0
            || actual.pointer == 0
            || actual.private_member != 1
            || !actual.align.is_power_of_two()
            || actual.pointer % actual.align != 0
            || !report
                .regions
                .iter()
                .any(|pool| pool.contains(actual.pointer, actual.size))
        {
            return Err(format!(
                "operation {} lacks successful live private membership/alignment/extent",
                actual.index
            ));
        }
        let (slot, replaces) = match expected.action {
            Action::Allocate(slot) => {
                if live[slot].is_some() {
                    return Err("allocation overwrites a live workload slot".into());
                }
                (slot, false)
            }
            Action::Reallocate(slot) => {
                let prior = live[slot].ok_or("realloc source is not live")?;
                if prior.align != actual.align {
                    return Err("realloc changed the frozen source alignment".into());
                }
                (slot, true)
            }
            Action::Deallocate(slot) => {
                let prior = live[slot].ok_or("dealloc source is not live")?;
                if (prior.pointer, prior.size, prior.align)
                    != (actual.pointer, actual.size, actual.align)
                {
                    return Err(
                        "dealloc pointer/original layout differs from the live allocation".into(),
                    );
                }
                live[slot] = None;
                continue;
            }
            Action::Exhaustion => unreachable!(),
        };
        let end = actual
            .pointer
            .checked_add(actual.size)
            .ok_or("live allocation address overflow")?;
        for (other_slot, other) in live.iter().enumerate() {
            if other_slot == slot && replaces {
                continue;
            }
            if let Some(other) = other {
                let other_end = other
                    .pointer
                    .checked_add(other.size)
                    .ok_or("prior live extent overflow")?;
                if actual.pointer < other_end && other.pointer < end {
                    return Err("simultaneously live allocation extents overlap".into());
                }
            }
        }
        live[slot] = Some(LiveAllocation {
            pointer: actual.pointer,
            size: actual.size,
            align: actual.align,
        });
    }
    if live.iter().any(Option::is_some) {
        return Err("fixed workload left an allocation live".into());
    }
    for (total, watcher) in totals.into_iter().zip(report.watchers) {
        if total != watcher.export_entries {
            return Err("per-operation watcher totals differ from export counters".into());
        }
    }
    for (pointer, size) in [(report.guest.value, 333), (report.next.value, 777)] {
        if pointer == 0
            || pointer.checked_add(size).is_none()
            || report
                .regions
                .iter()
                .any(|pool| pool.overlaps(pointer, size))
        {
            return Err("ordinary guest allocation is null/overflowing/private".into());
        }
    }
    let guest_end = report
        .guest
        .value
        .checked_add(333)
        .ok_or("guest extent overflow")?;
    let next_end = report
        .next
        .value
        .checked_add(777)
        .ok_or("next extent overflow")?;
    if report.guest.value < next_end && report.next.value < guest_end {
        return Err("the two live guest payloads overlap".into());
    }
    for (bytes, seed, hash) in [
        (&report.guest_bytes, 77_u64, &report.payload_hashes[0]),
        (&report.next_bytes, 88_u64, &report.payload_hashes[1]),
    ] {
        if bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| *byte != ((index as u64 * 29 + seed * 17 + 3) & 255) as u8)
        {
            return Err("literal guest payload differs from unchanged C initialization".into());
        }
        let observed = bytes.iter().fold(14695981039346656037_u64, |value, byte| {
            (value ^ u64::from(*byte)).wrapping_mul(1099511628211)
        });
        if observed != hash.value {
            return Err("printed payload hash differs from the retained literal bytes".into());
        }
    }
    Ok(())
}

/// This requires the actual Command exit status and the unchanged C oracle.
/// Calling it for Q validates a quiet control, never a work execution.
pub fn validate_trial(
    run: &CapturedRun,
    key: TrialKey,
    expected_owner: &Path,
) -> Result<TrialReport, ContractError> {
    if run.input != Some(key.input())
        || run.end != CaptureEnd::Complete
        || run.output_truncated
        || run.elapsed > WALL_LIMIT
        || run
            .stdout
            .len()
            .checked_add(run.stderr.len())
            .is_none_or(|n| n > OUTPUT_LIMIT)
        || !run.status.is_some_and(|status| status.success())
    {
        return Err(error(
            format!(
                "actual {:?}/{:?} child did not complete successfully within the fixed bounds: {:?}",
                key.mode, key.case, run
            ),
            &[run],
        ));
    }
    let report = parse_trial(&run.stdout, key, expected_owner)
        .map_err(|message| error(format!("fixture protocol: {message}"), &[run]))?;
    validate_report(&report).map_err(|message| error(message, &[run]))?;
    Ok(report)
}

pub struct ValidatedPair {
    case: FixtureCase,
    quiet: CapturedRun,
    work: CapturedRun,
    quiet_report: TrialReport,
    work_report: TrialReport,
}

impl ValidatedPair {
    pub fn case(&self) -> FixtureCase {
        self.case
    }
    pub fn quiet(&self) -> &CapturedRun {
        &self.quiet
    }
    pub fn work(&self) -> &CapturedRun {
        &self.work
    }
    pub fn quiet_report(&self) -> &TrialReport {
        &self.quiet_report
    }
    pub fn work_report(&self) -> &TrialReport {
        &self.work_report
    }
}

/// Exact equality of actual held launch inputs, literal addresses/brk/bytes.
/// There is no numeric-relative, hash-only or masked comparator fallback.
pub fn compare_pair(
    quiet: &CapturedRun,
    work: &CapturedRun,
    case: FixtureCase,
    expected_owner: &Path,
) -> Result<ValidatedPair, ContractError> {
    if quiet.launch != work.launch {
        return Err(error(
            "Q/W program/argv/environment/cwd/held launch policy differs",
            &[quiet, work],
        ));
    }
    let quiet_report = validate_trial(
        quiet,
        TrialKey {
            mode: Mode::Quiet,
            case,
        },
        expected_owner,
    )
    .map_err(|failure| error(failure.message, &[quiet, work]))?;
    let work_report = validate_trial(
        work,
        TrialKey {
            mode: Mode::Work,
            case,
        },
        expected_owner,
    )
    .map_err(|failure| error(failure.message, &[quiet, work]))?;
    if quiet_report.owner_base != work_report.owner_base
        || quiet_report.regions != work_report.regions
    {
        return Err(error(
            "Q/W loaded owner base or actual private backing ranges differ",
            &[quiet, work],
        ));
    }
    if quiet_report.guest != work_report.guest
        || quiet_report.next != work_report.next
        || quiet_report.breaks != work_report.breaks
    {
        return Err(error(
            "Q/W literal guest pointer, next pointer or break differs",
            &[quiet, work],
        ));
    }
    if quiet_report.guest_bytes_literal != work_report.guest_bytes_literal
        || quiet_report.next_bytes_literal != work_report.next_bytes_literal
        || quiet_report.guest_bytes != work_report.guest_bytes
        || quiet_report.next_bytes != work_report.next_bytes
        || quiet_report.payload_hashes != work_report.payload_hashes
    {
        return Err(error(
            "Q/W literal initialized payload bytes or recorded hashes differ",
            &[quiet, work],
        ));
    }
    Ok(ValidatedPair {
        case,
        quiet: quiet.clone(),
        work: work.clone(),
        quiet_report,
        work_report,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatrixCounts {
    pub quiet_controls: usize,
    pub completed_work_runs: usize,
    pub completed_work_case_rows: usize,
    pub observed_work_operations: usize,
    pub literal_address_pairs: usize,
}

/// Require S/Z/G/O/R/E plus A in the frozen order, with all fourteen real
/// captures. Only validated W rows are counted as allocation work evidence.
pub fn validate_matrix(pairs: &[ValidatedPair]) -> Result<MatrixCounts, ContractError> {
    let captures: Vec<_> = pairs.iter().flat_map(|p| [&p.quiet, &p.work]).collect();
    if pairs.len() != FIXED_CASES.len() {
        return Err(error(
            "matrix requires exactly seven completed Q/W pairs",
            &captures,
        ));
    }
    let launch = &pairs[0].quiet.launch;
    let mut counts = MatrixCounts {
        quiet_controls: 0,
        completed_work_runs: 0,
        completed_work_case_rows: 0,
        observed_work_operations: 0,
        literal_address_pairs: 0,
    };
    for (pair, case) in pairs.iter().zip(FIXED_CASES) {
        if pair.case != case || &pair.quiet.launch != launch || &pair.work.launch != launch {
            return Err(error(
                "matrix order/selection or held launch inputs changed",
                &captures,
            ));
        }
        // These objects can only be constructed by compare_pair, and their raw
        // runs/reports cannot be mutated through this API.
        counts.quiet_controls += 1;
        counts.completed_work_runs += 1;
        counts.completed_work_case_rows += pair
            .work_report
            .cases
            .iter()
            .filter(|row| row.executed && row.complete)
            .count();
        counts.observed_work_operations += pair.work_report.operations.len();
        counts.literal_address_pairs += 1;
    }
    if counts
        != (MatrixCounts {
            quiet_controls: 7,
            completed_work_runs: 7,
            completed_work_case_rows: 12,
            observed_work_operations: 86,
            literal_address_pairs: 7,
        })
    {
        return Err(error(
            "matrix has missing actual work/complete/address observations",
            &captures,
        ));
    }
    Ok(counts)
}

/// Linux runner for one trusted fixture launch, with fixed two-byte stdin,
/// a new process group, 120-second deadline and combined 16 MiB pipe cap.
/// The outer official driver/dagrun still owns CPU/memory/PID/cgroup containment
/// and its wall backstop (including std::process::Command::spawn itself).
/// Descendants must remain in the assigned process group; stronger subtree
/// cleanup belongs to that outer driver. No unbounded reader/writer join occurs.
/// A timeout/cap/I/O failure is returned with retained raw output and cannot pass.
#[cfg(target_os = "linux")]
pub fn run_bounded(
    mut command: Command,
    input: [u8; 2],
    held: &HeldInputs,
) -> Result<CapturedRun, ContractError> {
    if !matches!(input[0], b'Q' | b'W')
        || !FIXED_CASES.iter().any(|case| case.selector() == input[1])
    {
        return Err(error(
            "runner requires one frozen Q/W plus case two-byte input",
            &[],
        ));
    }
    linux_runner::run(&mut command, Some(input), held)
}

/// Run a source-identity command or control that consumes no fixture input.
/// Stdin is /dev/null, so a fast child cannot race an unnecessary pipe write.
/// The deadline, output cap, environment and cleanup match [`run_bounded`].
/// Its capture has no fixture selector and cannot satisfy a matrix comparison.
#[cfg(target_os = "linux")]
pub fn run_without_input(
    mut command: Command,
    held: &HeldInputs,
) -> Result<CapturedRun, ContractError> {
    linux_runner::run(&mut command, None, held)
}

#[cfg(target_os = "linux")]
mod linux_runner {
    use std::collections::HashSet;
    use std::io::Read;
    use std::io::Write;
    use std::io::{self};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::process::Child;
    use std::process::Stdio;
    use std::time::Instant;

    use super::*;

    struct ProcessGroup {
        child: Option<Child>,
        pid: libc::pid_t,
        stopped: bool,
    }

    impl ProcessGroup {
        fn stop(&mut self) -> io::Result<()> {
            if self.stopped {
                return Ok(());
            }
            // SAFETY: process_group(0) created this owned group; until this
            // method stops it, waitid(WNOWAIT) has not reaped its leader. Thus
            // its PID cannot be reused for an unrelated group.
            if unsafe { libc::kill(-self.pid, libc::SIGKILL) } == -1 {
                let failure = io::Error::last_os_error();
                if failure.raw_os_error() != Some(libc::ESRCH) {
                    if let Some(child) = self.child.as_mut() {
                        let _ = child.kill();
                    }
                    return Err(failure);
                }
            }
            self.stopped = true;
            Ok(())
        }

        fn ready(&self) -> io::Result<bool> {
            // SAFETY: siginfo_t accepts an all-zero initial representation;
            // waitid writes it before the si_pid accessor reads the PID field.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // WNOWAIT preserves ownership of the leader PID while group
            // cleanup happens. Do not replace with reaping try_wait first.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == 0 {
                return Ok(unsafe { info.si_pid() } != 0);
            }
            let failure = io::Error::last_os_error();
            if failure.kind() == io::ErrorKind::Interrupted {
                // Recheck the deadline in the outer loop; continuous signals
                // must not turn a nonblocking readiness check into a wait.
                Ok(false)
            } else {
                Err(failure)
            }
        }

        fn reap_ready(&mut self) -> io::Result<ExitStatus> {
            let status = self
                .child
                .as_mut()
                .ok_or_else(|| io::Error::other("leader already reaped"))?
                .wait()?;
            self.child = None;
            Ok(status)
        }
    }

    impl Drop for ProcessGroup {
        fn drop(&mut self) {
            if self.child.is_none() {
                return;
            }
            let _ = self.stop();
            if self.ready().unwrap_or(false) {
                let _ = self.reap_ready();
            } else if let Some(mut child) = self.child.take() {
                // Killing a process does not guarantee immediate reapability
                // (for example kernel I/O). Do not hang this bounded caller on
                // an unbounded wait. The mandatory outer box owns subtree
                // cleanup; a detached host reaper retains this Child handle.
                let _ = std::thread::Builder::new()
                    .name("m1-fixture-reaper".into())
                    .spawn(move || {
                        let _ = child.wait();
                    });
            }
        }
    }

    fn nonblocking(fd: libc::c_int) -> io::Result<()> {
        // SAFETY: fd is an owned live stdout/stderr pipe descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    enum Drain {
        Open,
        Eof,
        Limit,
    }

    fn drain<R: Read>(
        pipe: &mut R,
        bytes: &mut Vec<u8>,
        total: &mut usize,
        deadline: Instant,
    ) -> io::Result<Drain> {
        let mut buffer = [0_u8; 8192];
        loop {
            if Instant::now() >= deadline {
                return Ok(Drain::Open);
            }
            match pipe.read(&mut buffer) {
                Ok(0) => return Ok(Drain::Eof),
                Ok(count) => {
                    let room = OUTPUT_LIMIT - *total;
                    let retain = count.min(room);
                    bytes.extend_from_slice(&buffer[..retain]);
                    *total += retain;
                    if retain != count {
                        return Ok(Drain::Limit);
                    }
                }
                Err(failure) if failure.kind() == io::ErrorKind::Interrupted => continue,
                Err(failure) if failure.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(Drain::Open);
                }
                Err(failure) => return Err(failure),
            }
        }
    }

    pub(super) fn run(
        command: &mut Command,
        input: Option<[u8; 2]>,
        held: &HeldInputs,
    ) -> Result<CapturedRun, ContractError> {
        let mut names = HashSet::new();
        for (name, value) in &held.environment {
            if name.is_empty()
                || name.as_bytes().contains(&b'=')
                || name.as_bytes().contains(&0)
                || value.as_bytes().contains(&0)
                || !names.insert(name)
            {
                return Err(error(
                    "held environment contains duplicate/invalid keys or NUL",
                    &[],
                ));
            }
        }
        let current_dir = match command.get_current_dir() {
            Some(path) => path.to_path_buf(),
            None => std::env::current_dir()
                .map_err(|failure| error(format!("launch cwd: {failure}"), &[]))?,
        };
        let launch = LaunchIdentity {
            program: command.get_program().to_os_string(),
            arguments: command
                .get_args()
                .map(|value| value.to_os_string())
                .collect(),
            current_dir: current_dir.clone(),
            held: held.clone(),
        };
        // Actual child environment is supplied by the caller's held snapshot,
        // rather than depending on mutable ambient inheritance. No Q/W selector
        // is placed in argv/environment. Fixture input is exactly two bytes;
        // source/control commands instead receive a closed stdin.
        command
            .env_clear()
            .envs(held.environment.iter().map(|(key, value)| (key, value)));
        command
            .current_dir(current_dir)
            .process_group(0)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: the child-side hook only invokes setrlimit and constructs an
        // OS error; it acquires no Rust locks and performs no allocation.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &limit) == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let start = Instant::now();
        let deadline = start + WALL_LIMIT;
        let child = command
            .spawn()
            .map_err(|failure| error(format!("fixture spawn: {failure}"), &[]))?;
        // Linux PIDs are represented by pid_t; Child::id is the same kernel PID.
        let pid = child.id() as libc::pid_t;
        let mut group = ProcessGroup {
            child: Some(child),
            pid,
            stopped: false,
        };
        let mut capture = CapturedRun {
            status: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            input,
            launch,
            elapsed: Duration::ZERO,
            end: CaptureEnd::Complete,
            output_truncated: false,
        };
        let child = group.child.as_mut().expect("newly spawned child is owned");
        let out = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing stdout pipe"))
            .and_then(|pipe| {
                nonblocking(pipe.as_raw_fd())?;
                Ok(pipe)
            });
        let err = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("missing stderr pipe"))
            .and_then(|pipe| {
                nonblocking(pipe.as_raw_fd())?;
                Ok(pipe)
            });
        let input_result = match input {
            Some(bytes) => child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("missing stdin pipe"))
                .and_then(|mut pipe| {
                    // Two bytes fit in the new empty pipe; dropping it closes
                    // stdin immediately. Failed fixture delivery stays a failure.
                    pipe.write_all(&bytes)
                }),
            None => Ok(()),
        };
        let mut preparation_errors = Vec::new();
        let mut stdout = match out {
            Ok(pipe) => Some(pipe),
            Err(failure) => {
                preparation_errors.push(format!("stdout setup: {failure}"));
                None
            }
        };
        let mut stderr = match err {
            Ok(pipe) => Some(pipe),
            Err(failure) => {
                preparation_errors.push(format!("stderr setup: {failure}"));
                None
            }
        };
        if let Err(failure) = input_result {
            preparation_errors.push(format!("fixed stdin: {failure}"));
        }
        if !preparation_errors.is_empty() {
            if let Err(failure) = group.stop() {
                preparation_errors.push(format!("setup cleanup: {failure}"));
            }
            capture.end = CaptureEnd::IoFailure(preparation_errors.join("; "));
            // Keep draining successfully configured pipes below: an early
            // BrokenPipe must not discard the child's raw diagnostics. A pipe
            // whose nonblocking setup failed is closed and this run cannot pass.
        }
        let mut total = 0;
        loop {
            if Instant::now() >= deadline {
                capture.end = CaptureEnd::Deadline;
                break;
            }
            if let Some(pipe) = stdout.as_mut() {
                match drain(pipe, &mut capture.stdout, &mut total, deadline) {
                    Ok(Drain::Eof) => stdout = None,
                    Ok(Drain::Limit) => {
                        capture.end = CaptureEnd::OutputLimit;
                        capture.output_truncated = true;
                        break;
                    }
                    Ok(Drain::Open) => {}
                    Err(failure) => {
                        capture.end = CaptureEnd::IoFailure(failure.to_string());
                        break;
                    }
                }
            }
            if let Some(pipe) = stderr.as_mut() {
                match drain(pipe, &mut capture.stderr, &mut total, deadline) {
                    Ok(Drain::Eof) => stderr = None,
                    Ok(Drain::Limit) => {
                        capture.end = CaptureEnd::OutputLimit;
                        capture.output_truncated = true;
                        break;
                    }
                    Ok(Drain::Open) => {}
                    Err(failure) => {
                        capture.end = CaptureEnd::IoFailure(failure.to_string());
                        break;
                    }
                }
            }
            if capture.status.is_none() {
                match group.ready() {
                    Ok(true) => {
                        if let Err(failure) = group.stop() {
                            capture.end = CaptureEnd::IoFailure(failure.to_string());
                            break;
                        }
                        match group.reap_ready() {
                            Ok(status) => capture.status = Some(status),
                            Err(failure) => {
                                capture.end = CaptureEnd::IoFailure(failure.to_string());
                                break;
                            }
                        }
                    }
                    Ok(false) => {}
                    Err(failure) => {
                        capture.end = CaptureEnd::IoFailure(failure.to_string());
                        break;
                    }
                }
            }
            if capture.status.is_some() && stdout.is_none() && stderr.is_none() {
                break;
            }
            let mut descriptors = [
                libc::pollfd {
                    fd: stdout.as_ref().map_or(-1, |pipe| pipe.as_raw_fd()),
                    events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stderr.as_ref().map_or(-1, |pipe| pipe.as_raw_fd()),
                    events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                    revents: 0,
                },
            ];
            let remaining = deadline.saturating_duration_since(Instant::now());
            let milliseconds = remaining.as_millis().clamp(1, 50) as libc::c_int;
            // SAFETY: descriptors are a writable two-element pollfd array.
            if unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as libc::nfds_t,
                    milliseconds,
                )
            } == -1
            {
                let failure = io::Error::last_os_error();
                if failure.kind() != io::ErrorKind::Interrupted {
                    capture.end = CaptureEnd::IoFailure(failure.to_string());
                    break;
                }
            }
        }
        if capture.end != CaptureEnd::Complete {
            if let Err(failure) = group.stop() {
                capture.end =
                    CaptureEnd::IoFailure(format!("cleanup after {:?}: {failure}", capture.end));
            }
            if capture.status.is_none() && group.ready().unwrap_or(false) {
                capture.status = group.reap_ready().ok();
            }
        }
        // Dropping pipes never waits for a descendant-held writer. Group cleanup
        // has already happened before reaping, or its guard owns failure cleanup.
        drop(stdout);
        drop(stderr);
        capture.elapsed = start.elapsed();
        if capture.end != CaptureEnd::Complete {
            return Err(error(
                format!("bounded fixture ended with {:?}", capture.end),
                &[&capture],
            ));
        }
        Ok(capture)
    }
}
