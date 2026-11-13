//! Real source/archive/link qualification of both mapped generations.
//! The required fixture file names an owned source copy, canonical tools,
//! native inputs, one target and evidence directory. It grants no authority.
//! The source copy and produced files are modified by the refusal controls.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use goblin::elf::Elf;
use goblin::elf::sym;
use reverie_liteinst_artifact::FileIdentity;
use reverie_liteinst_artifact::Runner;
use reverie_liteinst_artifact::private_static::SourceExpectation;
use reverie_liteinst_artifact::private_static::VerifiedStaticSource;
use reverie_liteinst_artifact::private_static::selected_initializers::GenerationKind;
use reverie_liteinst_artifact::private_static::selected_initializers::InitializerLinkInputs;
use reverie_liteinst_artifact::private_static::selected_initializers::MappedConsumer;
use serde::Deserialize;
use serde_json::Value;

const FIRST_SOURCE: &str = "preload/src/mapped_initial_entry.rs";
const FIRST_SHA256: &str = "96cbfe6ae8cac1f5410486c0ccbbebc08191712326fc2dd63ef03381c64a7e25";
const SUCCESSOR_SHA256: &str = "13c86e80c0ab927508422539f4d81c93b9af24d45e545464d7d2c9210177a9d0";
const FEATURES: [&str; 6] = [
    "default",
    "exec-stage",
    "liteinst",
    "mapped-successor",
    "mapped-successor-image",
    "successor",
];

type Result<T> = std::result::Result<T, String>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    workspace: PathBuf,
    workspace_head: String,
    reverie_pin: String,
    cargo: PathBuf,
    rustc: PathBuf,
    target_dir: PathBuf,
    evidence: PathBuf,
    qualifier_head: String,
    qualifier_tree: String,
    lld: PathBuf,
    objdump: PathBuf,
    libc: PathBuf,
    libunwind: PathBuf,
    musl_source_authority: PathBuf,
    memcpy_source: PathBuf,
    stack_chk_source: PathBuf,
    // Executable fixture preparation takes the actual selected archive and
    // the output script path as its two arguments. It classifies that archive
    // with the native inputs; the factory independently checks the result.
    script_preparer: PathBuf,
    script_preparer_sha256: String,
}

fn require(value: bool, message: &str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn symbol(elf: &Elf<'_>, name: &str) -> Result<sym::Sym> {
    let rows = elf
        .syms
        .iter()
        .filter(|s| s.st_shndx != 0 && elf.strtab.get_at(s.st_name) == Some(name))
        .collect::<Vec<_>>();
    require(
        rows.len() == 1,
        &format!("mapped fixture symbol absent/duplicate: {name}"),
    )?;
    Ok(rows[0])
}

fn body_symbol(elf: &Elf<'_>, module: &str, leaf: &str) -> Result<sym::Sym> {
    let suffix = format!("_16literoot_preload{module}{leaf}");
    let rows = elf
        .syms
        .iter()
        .filter(|s| {
            s.st_shndx != 0
                && elf.strtab.get_at(s.st_name).is_some_and(|name| {
                    name.strip_prefix("_RNvNtCs")
                        .and_then(|rest| rest.strip_suffix(&suffix))
                        .is_some_and(|disambiguator| {
                            !disambiguator.is_empty()
                                && disambiguator.bytes().all(|b| b.is_ascii_alphanumeric())
                        })
                })
        })
        .collect::<Vec<_>>();
    require(
        rows.len() == 1,
        &format!("mapped fixture exact body absent/duplicate: {module}{leaf}"),
    )?;
    Ok(rows[0])
}

fn byte_at(elf: &Elf<'_>, bytes: &[u8], address: u64) -> Result<u8> {
    let rows = elf
        .program_headers
        .iter()
        .filter(|p| {
            p.p_type == goblin::elf::program_header::PT_LOAD
                && p.p_vaddr <= address
                && address < p.p_vaddr + p.p_filesz
        })
        .collect::<Vec<_>>();
    require(
        rows.len() == 1 && rows[0].p_flags == 5,
        "mapped fixture trap is not uniquely file-backed RX",
    )?;
    let offset = rows[0].p_offset + address - rows[0].p_vaddr;
    bytes
        .get(usize::try_from(offset).map_err(|e| e.to_string())?)
        .copied()
        .ok_or_else(|| "mapped fixture trap outside file".into())
}

fn produced_row(
    runner: &Runner,
    archive: &reverie_liteinst_artifact::private_static::StaticArchive,
) -> Result<Value> {
    let builds = runner
        .commands
        .iter()
        .filter(|command| command.arguments.iter().any(|arg| arg == "rustc"))
        .collect::<Vec<_>>();
    require(
        builds.len() == 1,
        "mapped fixture requires one actual Cargo archive build",
    )?;
    requested_seed(&builds[0].arguments)?;
    let bytes = fs::read(&builds[0].stdout.path).map_err(|e| e.to_string())?;
    require(
        FileIdentity::read(&builds[0].stdout.path)?.sha256 == archive.cargo_messages_sha256(),
        "mapped fixture Cargo stream does not match selected archive",
    )?;
    let rows = bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>>>()?;
    let artifacts = rows
        .iter()
        .filter(|row| {
            row["reason"] == "compiler-artifact" && row["target"]["name"] == "literoot_preload"
        })
        .collect::<Vec<_>>();
    require(
        artifacts.len() == 1,
        "mapped fixture compiler artifact absent/duplicate",
    )?;
    require(
        artifacts[0]["features"] == serde_json::json!(FEATURES),
        "mapped fixture actual activated features differ",
    )?;
    require(
        artifacts[0]["profile"]
            == serde_json::json!({"debug_assertions": true, "debuginfo": 0, "opt_level": "3", "overflow_checks": true, "test": false}),
        "mapped fixture actual profile differs",
    )?;
    require(
        artifacts[0]["executable"].is_null(),
        "mapped fixture archive has an executable",
    )?;
    let finished = rows
        .iter()
        .filter(|row| row["reason"] == "build-finished")
        .collect::<Vec<_>>();
    require(
        finished.len() == 1 && finished[0]["success"] == true,
        "mapped fixture current build did not finish exactly once",
    )?;
    Ok(artifacts[0].clone())
}

fn requested_seed(arguments: &[String]) -> Result<()> {
    let seeds = arguments
        .windows(2)
        .filter(|pair| pair[0] == "--features")
        .map(|pair| pair[1].as_str())
        .collect::<Vec<_>>();
    require(
        seeds == ["mapped-successor-image"]
            && !arguments
                .iter()
                .any(|arg| arg == "--all-features" || arg == "--no-default-features"),
        "mapped fixture Cargo request differs from the image feature seed",
    )
}

/// Required-fixture qualification. It needs private native inputs that
/// ordinary test runs do not have, so it is ignored by default; being
/// ignored is not a pass, and the qualification stays owed until a real
/// run. A producer runs it with `--ignored --exact` and
/// `LITEROOT_REQUIRE_FIXTURES=1`, the Literoot required-fixture switch.
/// Every execution without that switch, or without
/// `REVERIE_MAPPED_LITEROOT_FIXTURE`, fails by name: there is no skip.
#[test]
#[ignore = "required-fixture qualification with private native inputs: run with LITEROOT_REQUIRE_FIXTURES=1 and REVERIE_MAPPED_LITEROOT_FIXTURE, using --ignored --exact"]
fn literoot_image_qualifies_first_and_successor_with_nearby_refusals() -> Result<()> {
    require(
        env::var("LITEROOT_REQUIRE_FIXTURES").as_deref() == Ok("1"),
        "required-fixture run: set LITEROOT_REQUIRE_FIXTURES=1",
    )?;
    let fixture_path = env::var_os("REVERIE_MAPPED_LITEROOT_FIXTURE")
        .ok_or("mapped fixture required: set REVERIE_MAPPED_LITEROOT_FIXTURE")?;
    let fixture: Fixture = serde_json::from_slice(
        &fs::read(&fixture_path).map_err(|e| format!("mapped fixture unreadable: {e}"))?,
    )
    .map_err(|e| format!("mapped fixture invalid: {e}"))?;
    require(
        env::var_os("CARGO_TARGET_DIR").as_deref() == Some(fixture.target_dir.as_os_str()),
        "mapped fixture target differs from the sole explicit target",
    )?;
    require(
        env::var_os("RUSTC").as_deref() == Some(fixture.rustc.as_os_str()),
        "mapped fixture rustc differs from explicit compiler",
    )?;
    require(
        fixture.workspace_head == "03a958b0ee621a536caf0790f77803726d7785a1",
        "mapped fixture accepted source head differs",
    )?;
    require(
        fixture.reverie_pin == "52fcfde386bdec275bd3d23a2ceaa1b1e7c59977",
        "mapped fixture actual dependency pin differs",
    )?;
    require(
        FileIdentity::read(&fixture.workspace.join(FIRST_SOURCE))?.sha256 == FIRST_SHA256,
        "mapped fixture first source input differs",
    )?;
    require(
        FileIdentity::read(&fixture.workspace.join("preload/src/mapped_entry.rs"))?.sha256
            == SUCCESSOR_SHA256,
        "mapped fixture successor source input differs",
    )?;
    fs::create_dir_all(&fixture.evidence).map_err(|e| e.to_string())?;
    let stamp = serde_json::json!({"expected_qualifier_head": fixture.qualifier_head, "expected_qualifier_tree": fixture.qualifier_tree,
        "workspace_head": fixture.workspace_head, "reverie_pin": fixture.reverie_pin,
        "scope": "FINITE_TERMINAL_OBSERVER_STATIC_OBSERVATIONS_ONLY"});
    fs::write(
        fixture.evidence.join("source-identities.json"),
        serde_json::to_vec_pretty(&stamp).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let expected = SourceExpectation {
        workspace: &fixture.workspace,
        workspace_head: &fixture.workspace_head,
        reverie_pin: &fixture.reverie_pin,
        cargo: &fixture.cargo,
        rustc: &fixture.rustc,
        target_dir: &fixture.target_dir,
    };
    let mut runner = Runner::new(
        fixture.evidence.join("commands"),
        Duration::from_secs(3600),
        64 * 1024 * 1024,
    )?;
    let result = VerifiedStaticSource::with_resolved_for(
        MappedConsumer::Literoot,
        &expected,
        &mut runner,
        |source, runner| {
            let metadata = runner
                .commands
                .iter()
                .filter(|command| {
                    command
                        .arguments
                        .first()
                        .is_some_and(|arg| arg == "metadata")
                })
                .collect::<Vec<_>>();
            require(
                metadata.len() == 1,
                "mapped fixture metadata command absent/duplicate",
            )?;
            requested_seed(&metadata[0].arguments)?;
            require(
                metadata[0].stdout.sha256 == source.metadata_sha256(),
                "mapped fixture metadata stream differs from source binding",
            )?;
            let archive = source.build_archive(runner)?;
            let compiler_row = produced_row(runner, &archive)?;
            let script_preparer = FileIdentity::read(&fixture.script_preparer)?;
            require(
                script_preparer.sha256 == fixture.script_preparer_sha256,
                "mapped fixture script preparer differs",
            )?;
            let script = fixture.target_dir.join("mapped-generations.ld");
            runner.run(
                script_preparer
                    .path
                    .to_str()
                    .ok_or("mapped fixture preparer UTF8")?,
                &[
                    archive
                        .file()
                        .path
                        .to_str()
                        .ok_or("mapped fixture archive UTF8")?
                        .to_owned(),
                    script
                        .to_str()
                        .ok_or("mapped fixture script UTF8")?
                        .to_owned(),
                ],
                &fixture.workspace,
            )?;
            script_preparer.verify()?;
            let output = fixture.target_dir.join("mapped-generations-link");
            let supporting = [fixture.libunwind.as_path()];
            let definitions = source.link_and_join_initializer_definitions(
                &archive,
                &InitializerLinkInputs {
                    lld: &fixture.lld,
                    script: &script,
                    libc: &fixture.libc,
                    supporting_archives: &supporting,
                    memcpy_source: &fixture.memcpy_source,
                    musl_source_authority: &fixture.musl_source_authority,
                    stack_chk_source: &fixture.stack_chk_source,
                    output_directory: &output,
                },
                runner,
            )?;
            let artifact =
                FileIdentity::read(&output.join("initializer-definitions.not-qualified.elf"))?;
            let map = FileIdentity::read(&output.join("initializer-definitions.map"))?;
            let objdump = FileIdentity::read(&fixture.objdump)?;
            let bytes = fs::read(&artifact.path).map_err(|e| e.to_string())?;
            let elf = Elf::parse(&bytes).map_err(|e| e.to_string())?;
            let first = symbol(&elf, "literoot_mapped_initial_entry")?;
            let successor = symbol(&elf, "literoot_mapped_successor_entry")?;
            require(
                first.st_value == elf.entry && successor.st_value != elf.entry,
                "mapped fixture ELF entry is not First only",
            )?;
            for root in [first, successor] {
                require(
                    root.st_type() == sym::STT_FUNC
                        && root.st_bind() == sym::STB_GLOBAL
                        && root.st_visibility() == sym::STV_PROTECTED,
                    "mapped fixture root binding differs",
                )?;
            }
            let layout = symbol(&elf, "literoot_mapped_layout")?;
            let loads = elf
                .program_headers
                .iter()
                .filter(|p| {
                    p.p_type == goblin::elf::program_header::PT_LOAD
                        && p.p_vaddr <= layout.st_value
                        && layout.st_value + layout.st_size <= p.p_vaddr + p.p_filesz
                })
                .collect::<Vec<_>>();
            require(
                loads.len() == 1 && loads[0].p_flags == 4,
                "mapped fixture layout is not unique RO data",
            )?;
            for name in [
                "malloc",
                "__libc_malloc",
                "__libc_malloc_impl",
                "calloc",
                "__libc_calloc",
                "free",
                "__libc_free",
                "realloc",
                "__libc_realloc",
                "reallocarray",
                "aligned_alloc",
                "memalign",
                "valloc",
                "posix_memalign",
                "malloc_usable_size",
                "__malloc_allzerop",
                "__init_tls",
            ] {
                let exported = symbol(&elf, name)?;
                require(
                    exported.st_type() == sym::STT_FUNC && exported.st_bind() != sym::STB_WEAK,
                    "mapped fixture private allocator/TLS export differs",
                )?;
            }
            require(
                !elf.syms.iter().any(|s| {
                    elf.strtab
                        .get_at(s.st_name)
                        .is_some_and(|name| name.contains("LITEROOT_INIT"))
                }),
                "mapped fixture preload constructor is retained",
            )?;
            let mut bodies = BTreeSet::new();
            for module in ["20mapped_initial_entry", "12mapped_entry"] {
                for leaf in ["8terminal", "26observe_initializer_return"] {
                    require(
                        bodies.insert(body_symbol(&elf, module, leaf)?.st_value),
                        "mapped fixture terminal/observer bodies alias",
                    )?;
                }
            }
            let mut observations = Vec::new();
            for (generation, root, label, module) in [
                (
                    GenerationKind::First,
                    first,
                    "literoot_mapped_initial_entry_observed_int3",
                    "20mapped_initial_entry",
                ),
                (
                    GenerationKind::Successor,
                    successor,
                    "literoot_mapped_successor_entry_observed_int3",
                    "12mapped_entry",
                ),
            ] {
                source.with_mapped_terminal_observation_for(
                    generation,
                    &archive,
                    &definitions,
                    &objdump,
                    runner,
                    |observation, _| {
                        require(
                            observation.generation() == generation,
                            "mapped fixture observation generation differs",
                        )?;
                        let coordinates = observation.entry_coordinates();
                        require(
                            coordinates == (root.st_value, symbol(&elf, label)?.st_value),
                            "mapped fixture coordinates differ from actual ELF",
                        )?;
                        require(
                            byte_at(&elf, &bytes, coordinates.1)? == 0xcc,
                            "mapped fixture observed coordinate is not INT3",
                        )?;
                        require(
                            coordinates.1
                                == body_symbol(&elf, module, "26observe_initializer_return")?
                                    .st_value
                                    + 4,
                            "mapped fixture trap is not observer start plus four",
                        )?;
                        let mut data =
                            serde_json::to_value(observation).map_err(|e| e.to_string())?;
                        require(
                            data["observer_int3"] == coordinates.1
                                && data["expected_post_rip"] == coordinates.1 + 1,
                            "mapped fixture post-trap RIP differs from INT3 plus one",
                        )?;
                        require(
                            data["scope"] == "FINITE_TERMINAL_OBSERVER_STATIC_OBSERVATIONS_ONLY"
                                && data["remaining"]
                                    .as_array()
                                    .is_some_and(|remaining| remaining.len() == 6),
                            "mapped fixture finite scope or open obligations differ",
                        )?;
                        data["generation"] = serde_json::json!(format!("{generation:?}"));
                        data["entry"] = serde_json::json!(coordinates.0);
                        data["observed_int3"] = serde_json::json!(coordinates.1);
                        observations.push(data);
                        Ok(())
                    },
                )?;
            }
            require(
                observations.len() == 2
                    && observations[0]["entry"] != observations[1]["entry"]
                    && observations[0]["observed_int3"] != observations[1]["observed_int3"],
                "mapped fixture generation observations are not distinct",
            )?;
            let census = source
                .inspect_private_startup_census(&archive, &artifact, &map, &objdump, runner)?;
            let census: Value =
                serde_json::from_slice(&census.to_json_pretty()?).map_err(|e| e.to_string())?;
            require(
                census["sources"]["entry"]["path"].as_str()
                    == fixture.workspace.join(FIRST_SOURCE).to_str()
                    && census["sources"]["entry"]["sha256"] == FIRST_SHA256,
                "mapped fixture census entry source is not First",
            )?;
            require(
                census["bodies"].as_array().is_some_and(|bodies| {
                    bodies.iter().any(|body| {
                        body["role"] == "entry"
                            && body["symbols"].as_array().is_some_and(|symbols| {
                                symbols
                                    .iter()
                                    .any(|s| s["name"] == "literoot_mapped_initial_entry")
                            })
                    })
                }),
                "mapped fixture census does not select First",
            )?;
            // A genuine second source owner cannot use the first owner's archive,
            // even with the same metadata; no second archive build is needed.
            let mut entered = false;
            let foreign = VerifiedStaticSource::with_resolved_for(
                MappedConsumer::Literoot,
                &expected,
                runner,
                |other, runner| {
                    other.with_mapped_terminal_observation_for(
                        GenerationKind::First,
                        &archive,
                        &definitions,
                        &objdump,
                        runner,
                        |_, _| {
                            entered = true;
                            Ok(())
                        },
                    )
                },
            );
            require(
                !entered
                    && foreign.err().is_some_and(|e| {
                        e.contains("static archive belongs to another source transaction")
                    }),
                "mapped fixture foreign owner did not refuse before callback",
            )?;
            for file in [&artifact, &map] {
                let original = fs::read(&file.path).map_err(|e| e.to_string())?;
                let mut changed = original.clone();
                *changed
                    .first_mut()
                    .ok_or("mapped fixture empty produced file")? ^= 1;
                fs::write(&file.path, changed).map_err(|e| e.to_string())?;
                let mut entered = false;
                let refused = source.with_mapped_terminal_observation_for(
                    GenerationKind::First,
                    &archive,
                    &definitions,
                    &objdump,
                    runner,
                    |_, _| {
                        entered = true;
                        Ok(())
                    },
                );
                fs::write(&file.path, original).map_err(|e| e.to_string())?;
                require(
                    refused.is_err() && !entered,
                    "mapped fixture changed ELF/map admitted an observation",
                )?;
            }
            // A late source mutation enters the callback, then must fail the close.
            // No successful observation result may escape that enclosing method.
            let entry_path = fixture.workspace.join(FIRST_SOURCE);
            let original = fs::read(&entry_path).map_err(|e| e.to_string())?;
            let mut entered = false;
            let refused = source.with_mapped_terminal_observation_for(
                GenerationKind::Successor,
                &archive,
                &definitions,
                &objdump,
                runner,
                |_, _| {
                    entered = true;
                    let mut changed = original.clone();
                    changed.extend_from_slice(b"\n// source custody control\n");
                    fs::write(&entry_path, changed).map_err(|e| e.to_string())
                },
            );
            fs::write(&entry_path, &original).map_err(|e| e.to_string())?;
            let refusal = refused
                .err()
                .ok_or("mapped fixture late First-source mutation escaped the close")?;
            let canonical_first = entry_path.canonicalize().map_err(|e| e.to_string())?;
            require(
                entered
                    && refusal.contains(&format!(
                        "file identity changed: {}",
                        canonical_first.display()
                    )),
                "mapped fixture late First-source close lacks its named file identity refusal",
            )?;
            archive.verify()?;
            definitions.verify()?;
            artifact.verify()?;
            map.verify()?;
            Ok(
                serde_json::json!({"identities": stamp, "archive": archive.file(), "compiler_artifact": compiler_row,
            "artifact": artifact, "map": map, "observations": observations, "census": census,
            "refusals": ["foreign_archive_owner", "changed_elf", "changed_map", "late_first_source_close"]}),
            )
        },
    );
    fs::write(
        fixture.evidence.join("commands.json"),
        serde_json::to_vec_pretty(&runner.commands).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let data = result.map_err(|e| format!("mapped fixture factory transaction refused: {e}"))?;
    fs::write(
        fixture.evidence.join("finite-observations.json"),
        serde_json::to_vec_pretty(&data).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
