/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

//! Exact two-image original-instruction facts, not continuous virtual time.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::time::Instant;

fn run(command: &mut Command, out: &Path, name: &str) -> Output {
    eprintln!("{name}: {command:?}");
    let started = Instant::now();
    let result = Command::new("timeout")
        .args(["--signal=TERM", "--kill-after=2s", "20s"])
        .arg(command.get_program())
        .args(command.get_args())
        .output()
        .unwrap();
    fs::write(out.join(format!("{name}.stdout")), &result.stdout).unwrap();
    fs::write(out.join(format!("{name}.stderr")), &result.stderr).unwrap();
    fs::write(
        out.join(format!("{name}.status")),
        format!(
            "{:?} elapsed_seconds={}\n",
            result.status,
            started.elapsed().as_secs_f64()
        ),
    )
    .unwrap();
    result
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{:?}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn fixture_dir(name: &str) -> PathBuf {
    let root = std::env::var_os("REVERIE_DBT_TEST_ARTIFACT_DIR")
        .map(PathBuf::from)
        .expect("explicit retained artifact directory");
    let out = root.join(name);
    fs::create_dir_all(out.parent().unwrap()).unwrap();
    fs::create_dir(&out).expect("fresh receipt directory");
    out
}

fn symbol(text: &str, name: &str) -> u64 {
    let matches: Vec<_> = text
        .lines()
        .filter_map(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            (parts.len() == 3 && parts[2] == name)
                .then(|| u64::from_str_radix(parts[0], 16).unwrap())
        })
        .collect();
    assert_eq!(matches.len(), 1, "symbol {name}");
    matches[0]
}

fn elf_evidence(elf: &Path, out: &Path, name: &str, conditionals: usize) -> (String, Vec<u64>) {
    let headers = run(
        Command::new("readelf")
            .args(["-W", "-h", "-l", "-d", "-r", "-s"])
            .arg(elf),
        out,
        &format!("{name}-elf"),
    );
    success(&headers);
    let headers = String::from_utf8(headers.stdout).unwrap();
    assert!(headers.contains("ELF64") && headers.contains("Advanced Micro Devices X86-64"));
    for forbidden in [
        "(NEEDED)",
        "(INIT)",
        "(FINI)",
        "(INIT_ARRAY)",
        "(FINI_ARRAY)",
        " IFUNC ",
        " TLS ",
        " RWE ",
    ] {
        assert!(!headers.contains(forbidden), "unexpected {forbidden}");
    }
    assert!(headers.contains("There are no relocations in this file."));
    assert!(
        headers.contains("GNU_STACK")
            && !headers
                .lines()
                .any(|l| l.contains("GNU_STACK") && l.contains("RWE"))
    );
    let disassembly = run(
        Command::new("objdump").args(["-d", "-w"]).arg(elf),
        out,
        &format!("{name}-disassembly"),
    );
    success(&disassembly);
    let disassembly = String::from_utf8(disassembly.stdout).unwrap();
    let branches: Vec<_> = disassembly
        .lines()
        .filter_map(|line| {
            let mnemonic = line
                .split('\t')
                .nth(2)
                .unwrap_or("")
                .split_whitespace()
                .next()
                .unwrap_or("");
            if mnemonic.starts_with("loop")
                || (mnemonic.starts_with('j') && mnemonic != "jmp" && mnemonic != "jmpq")
            {
                assert_eq!(mnemonic, "jne", "exact original opcode");
                Some(u64::from_str_radix(line.split(':').next().unwrap().trim(), 16).unwrap())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(branches.len(), conditionals, "original conditional sites");
    let symbols = run(
        Command::new("nm").arg("-n").arg(elf),
        out,
        &format!("{name}-symbols"),
    );
    success(&symbols);
    (String::from_utf8(symbols.stdout).unwrap(), branches)
}

fn client() -> PathBuf {
    let path = PathBuf::from(std::env::var_os("REVERIE_DBT_CLIENT").expect("built native client"));
    assert!(path.is_file());
    path
}

fn observations(path: &Path) -> Vec<serde_json::Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter_map(|s| s.strip_prefix("BRANCH_FACT_OBSERVATION "))
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}

fn image_identity(app: &Path, interpreter: &Path) -> serde_json::Value {
    serde_json::Value::Array(
        [app, interpreter]
            .into_iter()
            .map(|path| {
                let metadata = fs::metadata(path).unwrap();
                serde_json::json!({"path":path,"device":metadata.dev(),
            "inode":metadata.ino(),"bytes":metadata.len()})
            })
            .collect(),
    )
}

fn fact_oracle(
    rows: &[serde_json::Value],
    enabled: bool,
    app_symbols: &str,
    interp_symbols: &str,
) -> Result<(), String> {
    let calls: Vec<_> = rows
        .iter()
        .filter(|r| r["event"] == "tool-syscall")
        .collect();
    if calls.len() != 5 {
        return Err(format!("syscall observation count {}", calls.len()));
    }
    let expected = [3u64, 5, 10, 10, 10];
    let counts: Vec<_> = calls.iter().map(|r| r["count"].as_u64()).collect();
    if enabled && counts != expected.map(Some) {
        return Err(format!("absolute counts {counts:?}, expected {expected:?}"));
    }
    let mut owner = None;
    let mut rsp = None;
    let mut interp_bias = None;
    for (index, row) in calls.iter().enumerate() {
        if row["repeated_equal"] != true || row["register_status"] != 1 {
            return Err(format!("query/register status {row}"));
        }
        if row["sysnum"] != if index == 4 { 60 } else { 1 } {
            return Err(format!("syscall number {row}"));
        }
        if enabled {
            if row["status"] != "Ready" {
                return Err(format!("unavailable {row}"));
            }
            if let Some(previous) = owner
                && previous != &row["owner"]
            {
                return Err("scope changed within image/task".into());
            }
            owner = Some(&row["owner"]);
        } else if row["status"] != "Disabled" || !row["count"].is_null() || !row["owner"].is_null()
        {
            return Err(format!("disabled fact {row}"));
        }
        let r: Vec<u64> = row["registers"]
            .as_array()
            .ok_or("register array")?
            .iter()
            .map(|x| x.as_u64().unwrap())
            .collect();
        if r.len() != 27 {
            return Err("complete integer register record".into());
        }
        let original_rsp = *rsp.get_or_insert(r[19]);
        let bias = *interp_bias.get_or_insert(
            r[16]
                .checked_sub(symbol(interp_symbols, "sample_prefix_after"))
                .ok_or("interpreter PC underflow")?,
        );
        let pc = if index == 0 {
            bias + symbol(interp_symbols, "sample_prefix_after")
        } else if index == 4 {
            symbol(app_symbols, "terminal_exit") + 2
        } else {
            symbol(
                app_symbols,
                [
                    "sample_main_after",
                    "sample_helper_after",
                    "sample_zero_after",
                ][index - 1],
            )
        };
        if r[16] != pc
            || r[18] != 0x247
            || r[19] != original_rsp
            || r[0] != original_rsp
            || r[5] != 0x1122334455667701
            || r[4] != 0x1122334455667705
            || r[3] != 0x112233445566770a
            || r[1] != 0x112233445566770c
            || r[2]
                != if index == 0 {
                    0x112233445566770b
                } else {
                    bias + symbol(interp_symbols, "interp_helper")
                }
            || r[9] != [3, 2, 5, 0, 0][index]
            || r[8] != [0x11, 0x22, 0x35, 0x40, 0x40][index]
            || r[7]
                != if index == 4 {
                    0x434252ff
                } else {
                    0x43425201 + index as u64
                }
            || r[10] != if index == 4 { 60 } else { 1 }
            || r[14] != if index == 4 { 0 } else { 1 }
            || r[12] != 0
        {
            return Err(format!("non-clobbered guest context at {index}: {r:?}"));
        }
        // Native ptrace enters after SYSCALL's RCX/R11 clobbers. These concrete
        // DBT hooks retain the input registers but dr_get_mcontext.xip is the
        // syscall continuation. No raw cross-boundary GPR equality is asserted.
    }
    let starts: Vec<_> = rows
        .iter()
        .filter(|r| r["event"] == "tool-thread-start")
        .collect();
    if starts.len() > 1 {
        return Err("more than one actual thread-start".into());
    }
    for row in starts {
        let position = rows.iter().position(|r| std::ptr::eq(r, row)).unwrap();
        if position != 0 || row["repeated_equal"] != true {
            return Err("thread-start ordering/query".into());
        }
        if enabled && (row["status"] != "Ready" || row["count"] != 0) {
            return Err(format!("actual pre-entry sample {row}"));
        }
        if !enabled && row["status"] != "Disabled" {
            return Err(format!("disabled startup {row}"));
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires built native client and admitted AMD PMU; run explicitly"]
fn all_original_images_keep_prefix_and_helper_work() {
    let out = fixture_dir("all-original-app");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/branch_counter/all_original_app");
    // The pinned root's existing executable tmpfs avoids btrfs's distinct
    // stat/subvolume versus maps/filesystem device identities. No identity
    // assertion is weakened; both ELFs stay here for all four executions.
    let guest_root = PathBuf::from(
        std::env::var_os("REVERIE_DBT_TEST_GUEST_ROOT").expect("fresh executable guest directory"),
    );
    fs::create_dir(&guest_root).unwrap();
    let interp = guest_root.join("app-interpreter");
    let app = guest_root.join("app");
    assert!(!interp.to_str().unwrap().contains(['"', '\\', '\n']));
    success(&run(
        Command::new("cc")
            .args([
                "-fPIC",
                "-shared",
                "-nostdlib",
                "-nostartfiles",
                "-nodefaultlibs",
                "-fno-stack-protector",
                "-Wl,-e,interp_start",
                "-Wl,-Bsymbolic",
                "-Wl,--build-id=none",
                "-Wl,-z,noexecstack",
            ])
            .arg(source.join("interpreter.S"))
            .arg("-o")
            .arg(&interp),
        &out,
        "compile-interpreter",
    ));
    success(&run(
        Command::new("cc")
            .args([
                "-static",
                "-no-pie",
                "-fno-pie",
                "-nostdlib",
                "-nostartfiles",
                "-nodefaultlibs",
                "-fno-stack-protector",
                "-Wl,--build-id=none",
                "-Wl,-z,noexecstack",
            ])
            .arg(format!("-Wl,-T,{}", source.join("executable.ld").display()))
            .arg(format!("-DAPP_INTERPRETER_PATH=\"{}\"", interp.display()))
            .arg(source.join("executable.S"))
            .arg("-o")
            .arg(&app),
        &out,
        "compile-app",
    ));
    let observer = out.join("native-observer");
    success(&run(
        Command::new("cc")
            .args(["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(source.join("native_observer.c"))
            .arg("-o")
            .arg(&observer),
        &out,
        "compile-observer",
    ));
    let (app_symbols, _) = elf_evidence(&app, &out, "app", 1);
    let (interp_symbols, branches) = elf_evidence(&interp, &out, "interpreter", 2);
    assert_eq!(symbol(&app_symbols, "app_entry"), 0x401000);
    let helper = symbol(&interp_symbols, "interp_helper");
    let omitted: Vec<_> = branches.into_iter().filter(|pc| *pc >= helper).collect();
    assert_eq!(omitted.len(), 1, "one helper conditional mutation");
    let app_bytes = fs::read(&app).unwrap();
    let interp_bytes = fs::read(&interp).unwrap();
    fs::write(out.join("app.frozen.elf"), &app_bytes).unwrap();
    fs::write(out.join("interpreter.frozen.elf"), &interp_bytes).unwrap();
    let cwd = std::env::current_dir().unwrap();
    fs::write(
        out.join("inputs.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
        "argv":[app],"application_environment_settings":["LC_ALL=C","TZ=UTC"],"cwd":cwd,
        "expected_absolute":[3,5,10,10],"helper_omitted_offset":omitted[0],
        "native_observer":"real exec-stop/TID-scoped raw0x5100d1",
        "dbt_tool":"existing uncoordinated Counter1 Tool via generic DbtGuest bridge"}))
        .unwrap(),
    )
    .unwrap();
    let identity = image_identity(&app, &interp);
    fs::write(
        out.join("native.identity-before.json"),
        serde_json::to_vec_pretty(&identity).unwrap(),
    )
    .unwrap();
    let native = run(
        Command::new(&observer)
            .arg(&app)
            .arg(&interp)
            .arg(out.join("native-guest.stdout"))
            .arg(out.join("native-guest.stderr")),
        &out,
        "native",
    );
    success(&native);
    assert!(String::from_utf8_lossy(&native.stdout).contains("\"native_reference\":true"));
    assert!(native.stderr.is_empty());
    let after = image_identity(&app, &interp);
    fs::write(
        out.join("native.identity-after.json"),
        serde_json::to_vec_pretty(&after).unwrap(),
    )
    .unwrap();
    assert_eq!(after, identity);

    let native_client = client();
    for (name, enabled) in [
        ("disabled", false),
        ("enabled", true),
        ("missing-helper", true),
    ] {
        let selected_client = if name == "missing-helper" {
            let mutant = out.join("mutant-source");
            fs::create_dir(&mutant).unwrap();
            let native_source = Path::new(env!("CARGO_MANIFEST_DIR")).join("native");
            for file in fs::read_dir(&native_source).unwrap() {
                let file = file.unwrap();
                if file.file_type().unwrap().is_file() {
                    fs::copy(file.path(), mutant.join(file.file_name())).unwrap();
                }
            }
            let header_path = mutant.join("branch_counter.h");
            let header = fs::read_to_string(&header_path).unwrap();
            let anchor = "  instr_set_note(instruction, (void*)branch_counter_original_note);";
            assert_eq!(header.matches(anchor).count(), 1);
            let injected = format!(
                "  module_data_t* test_module = dr_lookup_module(instr_get_app_pc(original));\n  bool test_omit = test_module != NULL && test_module->full_path != NULL && strcmp(test_module->full_path, \"{}\") == 0 && (uintptr_t)(instr_get_app_pc(original) - test_module->start) == {};\n  if (test_module != NULL) dr_free_module_data(test_module);\n  if (test_omit) {{ dr_fprintf(diagnostic_file, \"BRANCH_MUTANT omitted_helper offset={}\\n\"); return DR_EMIT_DEFAULT; }}\n{}",
                interp.display(),
                omitted[0],
                omitted[0],
                anchor
            );
            fs::write(&header_path, header.replace(anchor, &injected)).unwrap();
            let build = out.join("mutant-build");
            let runtime = std::env::var_os("REVERIE_DBT_RUNTIME").expect("exact built runtime DSO");
            success(&run(
                Command::new("cmake")
                    .arg("-S")
                    .arg(&mutant)
                    .arg("-B")
                    .arg(&build)
                    .arg("-DCMAKE_BUILD_TYPE=Release")
                    .arg(format!(
                        "-DDynamoRIO_DIR={}",
                        reverie_dbt::bundled_dynamorio_cmake_dir().display()
                    ))
                    .arg(format!(
                        "-DREVERIE_DBT_RUNTIME={}",
                        Path::new(&runtime).display()
                    )),
                &out,
                "mutant-configure",
            ));
            success(&run(
                Command::new("cmake")
                    .arg("--build")
                    .arg(&build)
                    .args(["--parallel", "2"]),
                &out,
                "mutant-build",
            ));
            build.join("libreverie_dbt_client.so")
        } else {
            native_client.clone()
        };
        let diagnostic_path = out.join(format!("{name}.diagnostics"));
        let diagnostics = fs::File::create(&diagnostic_path).unwrap();
        let mut runner =
            reverie_dbt::DbtRunner::new(reverie_dbt::bundled_drrun_path(), selected_client)
                .unwrap()
                .diagnostic_file(&diagnostics)
                .unwrap();
        if enabled {
            runner = runner.client_argument("-branch-facts");
        }
        let config = out.join(format!("{name}-config"));
        fs::create_dir(&config).unwrap();
        let environment: BTreeMap<OsString, OsString> = [
            ("LC_ALL", "C"),
            ("TZ", "UTC"),
            ("HERMIT_DBT_TEST_BRANCH_FACTS", "1"),
            ("HERMIT_DBT_COUNTER1_EXACT", "1"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .chain([(
            OsString::from("DYNAMORIO_CONFIGDIR"),
            config.into_os_string(),
        )])
        .collect();
        let started = Instant::now();
        let before = image_identity(&app, &interp);
        fs::write(
            out.join(format!("{name}.identity-before.json")),
            serde_json::to_vec_pretty(&before).unwrap(),
        )
        .unwrap();
        assert_eq!(before, identity);
        let output = runner
            .output_with_environment(&Command::new(&app), &environment)
            .unwrap();
        fs::write(out.join(format!("{name}.stdout")), &output.stdout).unwrap();
        fs::write(out.join(format!("{name}.stderr")), &output.stderr).unwrap();
        fs::write(
            out.join(format!("{name}.status")),
            format!(
                "{:?} elapsed_seconds={}\n",
                output.status,
                started.elapsed().as_secs_f64()
            ),
        )
        .unwrap();
        success(&output);
        assert!(
            output.stdout.is_empty() && output.stderr.is_empty(),
            "guest output: {output:?}"
        );
        let rows = observations(&diagnostic_path);
        fs::write(
            out.join(format!("{name}.observations.json")),
            serde_json::to_vec_pretty(&rows).unwrap(),
        )
        .unwrap();
        let verdict = fact_oracle(&rows, enabled, &app_symbols, &interp_symbols);
        fs::write(out.join(format!("{name}.oracle")), format!("{verdict:?}\n")).unwrap();
        if name == "missing-helper" {
            assert!(
                verdict
                    .as_ref()
                    .is_err_and(|s| s.contains("absolute counts")),
                "unchanged positive oracle: {verdict:?}"
            );
            let calls: Vec<_> = rows
                .iter()
                .filter(|r| r["event"] == "tool-syscall")
                .collect();
            assert_eq!(
                calls
                    .iter()
                    .map(|r| r["count"].as_u64().unwrap())
                    .collect::<Vec<_>>(),
                [3, 5, 5, 5, 5]
            );
            assert!(
                fs::read_to_string(&diagnostic_path)
                    .unwrap()
                    .contains("BRANCH_MUTANT omitted_helper")
            );
        } else {
            verdict.unwrap();
        }
        assert_eq!(fs::read(&app).unwrap(), app_bytes);
        assert_eq!(fs::read(&interp).unwrap(), interp_bytes);
        let after = image_identity(&app, &interp);
        fs::write(
            out.join(format!("{name}.identity-after.json")),
            serde_json::to_vec_pretty(&after).unwrap(),
        )
        .unwrap();
        assert_eq!(after, identity);
    }
}
