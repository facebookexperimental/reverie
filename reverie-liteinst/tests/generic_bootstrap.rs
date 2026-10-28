//! Actual public ABI calls in independent real-leaf processes. Provider RSP is
//! post-prologue; the external frozen observer owns any first-instruction or
//! literal69,632-byte window claim. Missing inputs/exports/entry are setup errors.
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

#[allow(dead_code)]
#[path = "support/liteinst_runtime.rs"]
mod liteinst_runtime;
use liteinst_runtime::artifact as m1_artifact;
use liteinst_runtime::contract;
#[allow(dead_code)]
#[path = "../../scripts/generic_bootstrap_fixture.rs"]
mod generic_bootstrap_fixture;

const BASE: u64 = 0x6000_0000_0000;
const END: u64 = 0x6001_0000_0000;
const BOTTOM: u64 = BASE + 0x101000;
const TOP: u64 = BASE + 0x901000;

fn need(value: bool, message: impl Into<String>) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.into()) }
}
fn selected(name: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(
        std::env::var_os(name).ok_or_else(|| format!("{name} is required, never skipped"))?,
    );
    need(
        path.is_absolute() && m1_artifact::real_file(&path)? == path,
        "canonical input required",
    )?;
    Ok(path)
}
fn words(bytes: &[u8]) -> Result<Vec<u64>, String> {
    need(
        bytes.len() == 8192,
        "setup: shared evidence must remain exactly8192 bytes",
    )?;
    Ok(bytes[..4096]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|x| u64::from_ne_bytes(*x))
        .collect())
}
fn record(w: &[u64]) -> [u64; 16] {
    w[..16].try_into().unwrap()
}
fn kernel(w: &[u64]) -> Result<(), String> {
    need(
        w.len() == 81 && w[0] == 1 && w[1] == 0 && w[2] > 0 && w[3] > 0 && w[4] == 0,
        "setup: real kernel query version/TID/PID/altstack status",
    )
}
fn local(elf: &goblin::elf::Elf<'_>, name: &str, base: u64) -> Result<u64, String> {
    let entries: Vec<_> = elf
        .syms
        .iter()
        .filter(|s| {
            elf.strtab.get_at(s.st_name) == Some(name)
                && s.is_function()
                && s.st_shndx != 0
                && s.st_size != 0
        })
        .collect();
    need(
        entries.len() == 1,
        format!("actual local {name} missing or ambiguous"),
    )?;
    let symbol = &entries[0];
    need(
        symbol.st_bind() == goblin::elf::sym::STB_LOCAL
            || symbol.st_visibility() == goblin::elf::sym::STV_HIDDEN,
        "generic internal function must be nonpreemptible",
    )?;
    Ok(base + symbol.st_value)
}
fn owned(s: &[u64], runtime: &Path) -> Result<(), String> {
    let r = record(&s[80..96]);
    need(
        s[24] == 0 && r[0] == 1 && r[1] == 4 && r[2] == s[179],
        "generic query must report genuinely RETURNED origin/current kernel TID",
    )?;
    need(
        r[3] == BASE + 0x100000
            && r[4] == BASE + 0x902000
            && r[5] == BOTTOM
            && r[6] == TOP
            && r[7] == s[7]
            && r[12] == BASE + 4096
            && r[13] == BASE + 0x210a0
            && r[14] == BASE
            && r[15] == END
            && (BOTTOM..TOP).contains(&r[10])
            && (BOTTOM..TOP).contains(&r[11]),
        "generic retained record must bind exact scalar caller/interior/control/distinct record",
    )?;
    let bytes = fs::read(runtime).map_err(|e| e.to_string())?;
    let elf = goblin::elf::Elf::parse(&bytes).map_err(|e| e.to_string())?;
    need(
        r[8] == local(&elf, "reverie_inguest_generic_adopt_entry", s[9])?
            && r[9] == local(&elf, "reverie_liteinst_generic_body", s[9])?,
        "generic record must bind actual same-owner adoption/body",
    )?;
    let q = &s[177..258];
    need(
        q[26] == 0 && record(&q[27..43]) == r && q[9] == u64::MAX && record(&q[10..26]) == [0; 16],
        "separate generic/constructor kernel record crosscheck",
    )?;
    need(
        q[43] == 15
            && q[44] == 1
            && q[45] as i64 == -i64::from(libc::EFAULT)
            && q[46] as i64 == -i64::from(libc::EFAULT)
            && q[47] == 264
            && q[48..80].iter().all(|x| *x == u64::MAX)
            && q[80] & 3 == 3,
        "actual guards and all2050 occupied extent pages",
    )
}
fn positive(s: &[u64], case: &str, runtime: &Path, stderr: &[u8]) -> Result<(), String> {
    need(
        s[4] > 0 && s[5] != 0,
        "setup: actual getter/body provider was never reached",
    )?;
    // Primary placement is the actual provider sample, independent of whether
    // the additive owner query exists. Baseline evidence retains its guest RSP.
    let placement = need(
        (BOTTOM..TOP).contains(&s[5]),
        format!(
            "actual reached getter/provider RSP {:#x} outside exact owned interior; caller RSP {:#x}; guest_window={}",
            s[5],
            s[7],
            s[7].saturating_sub(65536) <= s[5] && s[5] < s[7].saturating_add(4096)
        ),
    );
    let query = owned(s, runtime);
    match (placement, query) {
        (Err(a), Err(b)) => return Err(format!("placement: {a}; independent query: {b}")),
        (Err(a), Ok(())) => return Err(a),
        (Ok(()), Err(b)) => return Err(b),
        (Ok(()), Ok(())) => {}
    }
    need(
        s[3] == 1 && s[4] == 1 && s[6] == 63 && s[8] == s[7] + 8 && s[7] & 15 == 8,
        "one actual getter/body reach and scalar ABI/genuine return required",
    )?;
    let before = &s[96..177];
    let after = &s[177..258];
    need(
        before[2..4] == after[2..4]
            && after[9] == s[23]
            && after[26] == s[24]
            && record(&after[10..26]) == record(&s[64..80])
            && record(&after[27..43]) == record(&s[80..96]),
        "real before/after kernel PID/TID and direct origin queries differ",
    )?;
    need(
        before[8] as i64 == -i64::from(libc::ENOMEM) && after[8] == 0,
        "fresh reservation must follow initially absent fixed mapping",
    )?;
    if case == "strace" {
        need(
            (BASE..END).contains(&after[5])
                && after[5] >= BASE + 0x902000
                && after[6] == 65536
                && after[7] == 0
                && String::from_utf8_lossy(stderr).contains("[liteinst strace pid "),
            "actual getter-selected Strace/registered alternate stack not reached",
        )
    } else {
        need(
            after[5..8] == before[5..8]
                && !String::from_utf8_lossy(stderr).contains("[liteinst strace pid "),
            "None must retain kernel alternate state and install no Strace runtime",
        )
    }
}
fn trial(case: &str) -> Result<(), String> {
    let runtime = liteinst_runtime::required_runtime()?;
    let evidence = liteinst_runtime::evidence_directory(&format!("generic-bootstrap-{case}"))?;
    eprintln!(
        "generic bootstrap {case} raw evidence: {}",
        evidence.display()
    );
    let guest = selected(generic_bootstrap_fixture::GUEST_ENV)?;
    let receipt_path = selected(generic_bootstrap_fixture::RECEIPT_ENV)?;
    let receipt = generic_bootstrap_fixture::verify(&receipt_path, &guest, &runtime.source.root)?;
    let receipt_identity = m1_artifact::FileIdentity::read(&receipt_path)?;
    let state_path = evidence.join("actual-shared-state.bin");
    let mut initial = vec![0_u8; 8192];
    initial[4096..].fill(0xa5);
    m1_artifact::write_new(&state_path, &initial)?;
    let policy = serde_json::to_vec(&serde_json::json!({
        "case":case,"source_head":runtime.source.head,"source_tree":runtime.source.tree,
        "runtime":runtime.receipt.artifact,"guest":receipt.binary,"guest_source":receipt.source,
        "sample":"actual post-prologue getter provider RSP","first_instruction_credit":false,
        "whole_window_credit":false,"original_window_bytes":69632,"stdin":"closed"
    }))
    .map_err(|e| e.to_string())?;
    let mut held = liteinst_runtime::held_environment(policy);
    let mut env: BTreeMap<OsString, OsString> = held.environment.into_iter().collect();
    for key in [
        "LD_PRELOAD",
        "REVERIE_LITEINST_TOOL",
        "REVERIE_INGUEST_TOOL",
        reverie_liteinst::COMPAT_EVENT_FD_ENV,
        reverie_liteinst::COMPAT_EVENT_COOKIE_ENV,
        reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV,
    ] {
        env.remove(&OsString::from(key));
    }
    env.insert(reverie_liteinst::SITE_PATCHING_ENV.into(), "1".into());
    env.insert(reverie_liteinst::ALT_STACK_ENV.into(), "1".into());
    held.environment = env.into_iter().collect();
    let mut command = Command::new(&guest);
    command
        .arg("prepare")
        .arg(case)
        .arg(&runtime.path)
        .arg(&state_path)
        .current_dir(&runtime.source.root);
    let result = (|| -> Result<(), String> {
        let run = match contract::run_without_input(command, &held) {
            Ok(run) => {
                liteinst_runtime::retain_capture(&evidence, "actual-public-call", &run)?;
                run
            }
            Err(error) => {
                liteinst_runtime::retain_failure(&evidence, "actual-public-call", &error)?;
                return Err(error.to_string());
            }
        };
        need(
            run.input.is_none()
                && run.end == contract::CaptureEnd::Complete
                && !run.output_truncated,
            "setup: incomplete or truncated actual process capture",
        )?;
        need(
            !run.status.is_some_and(|x| x.code() == Some(2)),
            "setup: C probe exited2",
        )?;
        let bytes = fs::read(&state_path).map_err(|e| e.to_string())?;
        let s = words(&bytes)?;
        need(
            s[0] == 1 && s[1] == 1 && s[9] != 0 && s[10] != 0 && s[11] == 1 && s[2] >= 1,
            format!("setup: exact public call unreached; exit={:?}", run.status),
        )?;
        kernel(&s[96..177])?;
        let elf_bytes = fs::read(&runtime.path).map_err(|e| e.to_string())?;
        let elf = goblin::elf::Elf::parse(&elf_bytes).map_err(|e| e.to_string())?;
        let exports: Vec<_> = elf
            .dynsyms
            .iter()
            .filter(|x| {
                elf.dynstrtab.get_at(x.st_name) == Some("reverie_liteinst_initialize")
                    && x.st_shndx != 0
                    && x.is_function()
            })
            .collect();
        need(
            exports.len() == 1
                && exports[0].st_bind() == goblin::elf::sym::STB_GLOBAL
                && s[10] == s[9] + exports[0].st_value,
            "setup: called PC must be the actual strong public export in selected ELF",
        )?;
        need(
            s[21] == u64::MAX
                && s[22] == u64::MAX
                && record(&s[32..48]) == [0; 16]
                && record(&s[48..64]) == [0; 16]
                && s[105] == u64::MAX
                && s[122] == u64::MAX,
            "setup: constructor/generic origins must be absent before explicit call",
        )?;
        let raw = serde_json::json!({"case":case,"shared_words":s,"exit_code":run.status.and_then(|x|x.code()),
            "actual_provider_rsp":s[5],"actual_caller_rsp":s[7],"actual_getter_calls":s[4],
            "provider_in_guest_window":s[7].saturating_sub(65536)<=s[5] && s[5]<s[7].saturating_add(4096),
            "first_instruction_credit":false,"whole_window_credit":false});
        m1_artifact::write_new(
            &evidence.join("observation.json"),
            &serde_json::to_vec_pretty(&raw).map_err(|e| e.to_string())?,
        )?;
        match case {
            "strace" | "none" => {
                need(
                    run.status.is_some_and(|x| x.success()) && s[2] == 1 && s[17] == 1,
                    "genuine explicit generic call/return exit0 required",
                )?;
                kernel(&s[177..258])?;
                need(
                    s[23] == u64::MAX && record(&s[64..80]) == [0; 16],
                    "generic query must not hide a constructor owner",
                )?;
                positive(&s, case, &runtime.path, &run.stderr)
            }
            "repeat" => {
                kernel(&s[177..258])?;
                let placement = positive(&s, "none", &runtime.path, &[]);
                let refusal = need(
                    run.status.is_some_and(|x| x.code() == Some(127))
                        && s[2] == 2
                        && s[3] == 1
                        && s[4] == 1
                        && s[16] == 0
                        && run.stdout.is_empty()
                        && run.stderr.is_empty(),
                    "None→active second entry must exit127 before second getter/body; no runtime installation",
                );
                match (placement, refusal) {
                    (Ok(()), Ok(())) => Ok(()),
                    (Err(a), Err(b)) => Err(format!("{a}; {b}")),
                    (Err(a), _) | (_, Err(a)) => Err(a),
                }
            }
            "collision" | "ordinary" => {
                if case == "collision" {
                    need(
                        s[13] == BASE && s[14] == 1 && bytes[4096..].iter().all(|x| *x == 0xa5),
                        "actual collision mapping/sentinel changed",
                    )?;
                } else {
                    need(
                        s[18] == 1 && s[104] == 0,
                        "actual ordinary owner reserve not reached",
                    )?;
                }
                need(
                    run.status.is_some_and(|x| x.code() == Some(127))
                        && s[2] == 1
                        && s[3] == 0
                        && s[4] == 0
                        && run.stdout.is_empty()
                        && run.stderr.is_empty(),
                    "existing mapping/ordinary owner must refuse before getter/body, never adopt",
                )
            }
            _ => Err("case outside fixed table".into()),
        }
    })();
    let recorded = m1_artifact::write_new(&evidence.join("predicate-result.json"),
        &serde_json::to_vec_pretty(&serde_json::json!({"case":case,"predicate_passed":result.is_ok(),
            "error":result.as_ref().err(),"first_instruction_credit":false,"whole_window_credit":false})).map_err(|e|e.to_string())?);
    let after = (|| -> Result<(), String> {
        runtime.receipt.artifact.verify()?;
        receipt.source.verify()?;
        receipt.binary.verify()?;
        receipt_identity.verify()?;
        liteinst_runtime::verify_unchanged(&evidence)
    })();
    let errors: Vec<_> = [result, recorded, after]
        .into_iter()
        .filter_map(Result::err)
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{}; raw evidence {}",
            errors.join("; "),
            evidence.display()
        ))
    }
}

#[test]
fn explicit_getter_strace_uses_owned_generic_stack() {
    trial("strace").unwrap();
}
#[test]
fn explicit_none_reserves_owned_stack_without_runtime() {
    trial("none").unwrap();
}
#[test]
fn repeated_none_then_active_refuses_before_second_getter() {
    trial("repeat").unwrap();
}
#[test]
fn fixed_collision_refuses_without_changing_sentinel() {
    trial("collision").unwrap();
}
#[test]
fn ordinary_region_is_not_adopted_by_generic_entry() {
    trial("ordinary").unwrap();
}

#[test]
fn actual_scoped_compat_public_caller_remains_supported() -> Result<(), String> {
    let evidence = liteinst_runtime::evidence_directory("generic-scoped-compat")?;
    let before = liteinst_runtime::current_source(&evidence, "before")?;
    let binary = m1_artifact::FileIdentity::read(Path::new(env!(
        "CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest"
    )))?;
    let mut held = liteinst_runtime::held_environment(
        b"actual existing ScopedToolAllocator public Compat caller".to_vec(),
    );
    held.environment.retain(|(key, _)| {
        ![
            "LD_PRELOAD",
            "REVERIE_LITEINST_TOOL",
            "REVERIE_INGUEST_TOOL",
        ]
        .iter()
        .any(|x| key == &OsString::from(*x))
    });
    let mut command = Command::new(&binary.path);
    command.arg("syscall-fallback-refusal").arg("unused");
    let result = (|| -> Result<(), String> {
        let run = match contract::run_without_input(command, &held) {
            Ok(run) => {
                liteinst_runtime::retain_capture(&evidence, "actual-scoped-compat", &run)?;
                run
            }
            Err(error) => {
                liteinst_runtime::retain_failure(&evidence, "actual-scoped-compat", &error)?;
                return Err(error.to_string());
            }
        };
        need(
            run.end == contract::CaptureEnd::Complete
                && !run.output_truncated
                && run.status.is_some_and(|x| x.success()),
            "actual Scoped Compat process/return failed",
        )?;
        need(run.stdout == b"fallback refusal: result=-95 attempts=1 refused=1 syscall=1 hooks=0 bytes=unchanged\n",
            "existing Scoped Compat fallback predicate changed")?;
        let stderr = String::from_utf8(run.stderr).map_err(|e| e.to_string())?;
        need(!stderr.is_empty(), "actual Compat log missing")?;
        for line in stderr.lines() {
            line.strip_prefix("reverie-liteinst: tool=compat syscall=")
                .ok_or("actual Compat diagnostic differs")?
                .parse::<i64>()
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    })();
    let after = (|| -> Result<(), String> {
        binary.verify()?;
        need(
            liteinst_runtime::current_source(&evidence, "after")? == before,
            "Scoped Compat source changed",
        )
    })();
    let written = m1_artifact::write_new(&evidence.join("predicate-result.json"),
        &serde_json::to_vec_pretty(&serde_json::json!({"actual_binary":binary,"source":before,
            "predicate_passed":result.is_ok(),"source_guard_passed":after.is_ok(),
            "error":result.as_ref().err(),"first_instruction_credit":false,"whole_window_credit":false})).map_err(|e|e.to_string())?);
    let errors: Vec<_> = [result, after, written]
        .into_iter()
        .filter_map(Result::err)
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{}; raw evidence {}",
            errors.join("; "),
            evidence.display()
        ))
    }
}
