//! Additive installed FullTool route rows, one disposable actual child per row.
use std::collections::BTreeMap;

use super::*;

fn fields<'a>(stdout: &'a str, prefix: &str) -> BTreeMap<&'a str, &'a str> {
    let rows: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "one complete {prefix} row required: {stdout}"
    );
    let mut fields = BTreeMap::new();
    for field in rows[0].split_whitespace() {
        let (key, value) = field.split_once('=').expect("typed field");
        assert!(fields.insert(key, value).is_none(), "duplicate {key}");
    }
    fields
}

fn number(fields: &BTreeMap<&str, &str>, key: &str) -> i64 {
    fields[key].parse().unwrap()
}

fn address(fields: &BTreeMap<&str, &str>, key: &str) -> u64 {
    u64::from_str_radix(fields[key].strip_prefix("0x").expect("hex address"), 16).unwrap()
}

fn map_block<'a>(stdout: &'a str, begin: &str, end: &str) -> &'a str {
    assert_eq!(stdout.matches(begin).count(), 1);
    assert_eq!(stdout.matches(end).count(), 1);
    let (_, rest) = stdout.split_once(begin).unwrap();
    let (maps, _) = rest.split_once(end).unwrap();
    assert!(!maps.is_empty() && maps.ends_with('\n'));
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (start, end) = fields.next().unwrap().split_once('-').unwrap();
        assert!(u64::from_str_radix(start, 16).unwrap() < u64::from_str_radix(end, 16).unwrap());
        assert_eq!(fields.next().unwrap().len(), 4);
    }
    maps
}

async fn row(route: &str, operation: &str) {
    let (_preload_directory, preload) = compile_noop_preload();
    let mut command = guest_command("mapping-routes");
    command.arg(route).arg(operation);
    command.env(
        SITE_PATCHING_ENV,
        if route == "nested-trap" { "0" } else { "1" },
    );
    command.env(reverie_liteinst::SIGALRM_HANDLERS_ENV, "0");
    let (output, global, stats) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload_and_stats::<CoordinatorOnlyTool>(
            command,
            (),
            preload,
        ),
    )
    .await
    .expect("mapping route child hung")
    .unwrap();
    let stdout = std::str::from_utf8(&output.stdout).expect("complete UTF8 fixture output");
    println!(
        "mapping route={route} operation={operation} status={}\n{stdout}\nstderr={}\n{stats}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "{output:?}");
    let literal = fields(stdout, "MAPPING_ROUTE_LITERAL ");
    let owner = fields(stdout, "MAPPING_OWNER_FACTS ");
    // Read all retained observation fields before checking the child's verdict.
    let before = map_block(
        stdout,
        "MAPPING_MAPS_BEFORE_BEGIN\n",
        "MAPPING_MAPS_BEFORE_END\n",
    );
    let after = map_block(
        stdout,
        "MAPPING_MAPS_AFTER_BEGIN\n",
        "MAPPING_MAPS_AFTER_END\n",
    );
    assert_eq!(literal["route"], route);
    assert_eq!(literal["op"], operation);
    assert_eq!(number(&owner, "version"), 1);
    for key in ["owner", "control", "state", "live", "free"] {
        assert_ne!(address(&owner, key), 0);
    }
    assert!(number(&owner, "pid") > 0 && owner["pid"] == owner["tid"]);
    assert!(address(&owner, "alt_bottom") < address(&owner, "alt_top"));
    for key in ["live_bytes", "free_bytes"] {
        assert_eq!(number(&owner, key), 4096);
    }
    for key in ["live_owned", "free_unowned"] {
        assert_eq!(number(&owner, key), 1);
    }
    let target = address(&literal, "target");
    assert_eq!(target, address(&owner, "free"));
    assert!((0x6000_0000_0000..0x6001_0000_0000).contains(&target));
    let outside = address(&literal, "outside_address");
    assert!(outside + 4096 <= 0x6000_0000_0000 || outside >= 0x6001_0000_0000);
    let owner_lines = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|line| {
                let (start, end) = line
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .split_once('-')
                    .unwrap();
                let start = u64::from_str_radix(start, 16).unwrap();
                let end = u64::from_str_radix(end, 16).unwrap();
                start < 0x6001_0000_0000 && end > 0x6000_0000_0000
            })
            .map(str::to_owned)
            .collect()
    };
    let before_owner = owner_lines(before);
    assert!(!before_owner.is_empty());
    assert_eq!(
        before_owner,
        owner_lines(after),
        "complete owner VMA changes"
    );
    let expected = if route == "rewrite-outside" {
        0
    } else {
        -i64::from(libc::EPERM)
    };
    assert_eq!(number(&literal, "expected"), expected);
    assert_eq!(
        number(&literal, "raw"),
        expected,
        "actual protected/final syscall scalar"
    );
    assert_eq!(number(&literal, "sentinel"), 0x6d);
    for key in [
        "maps_equal",
        "identity",
        "lease_same",
        "outside_positive",
        "original_intact",
        "outside_effect",
        "route_seen",
        "physical",
    ] {
        assert_eq!(number(&literal, key), 1, "{key}: {stdout}");
    }
    for key in ["reuse", "second_reuse"] {
        assert_eq!(number(&literal, key), 0);
    }
    assert_eq!(fields(stdout, "MAPPING_FINISH ")["raw"], "0");
    if operation == "mseal" {
        let support = fields(stdout, "MAPPING_MSEAL_HOST ");
        assert_eq!(support["mapped"], "1");
        let support_result = number(&support, "raw");
        assert!(support_result == 0 || support_result == -i64::from(libc::ENOSYS));
        if support_result == -i64::from(libc::ENOSYS) {
            let facility = fields(stdout, "MAPPING_MSEAL_UNMEASURED ");
            assert_eq!(facility["host"], "ENOSYS");
            assert_eq!(facility["kernel_mutation"], "unmeasured");
            assert_eq!(facility["guard_route"], "required");
        } else {
            assert!(!stdout.contains("MAPPING_MSEAL_UNMEASURED"));
        }
        assert_eq!(
            number(&literal, "outside"),
            -i64::from(libc::ENOSYS),
            "typed FullTool remains ENOSYS"
        );
    } else {
        assert_eq!(number(&literal, "outside"), 0);
    }
    match route {
        "unsubscribed" => {
            assert_eq!(number(&literal, "entered"), 0);
            assert_eq!(address(&literal, "original"), target);
            assert_eq!(address(&literal, "recorded_original"), 0);
            assert_eq!(address(&literal, "final"), 0);
        }
        "nested-hook" | "nested-trap" => {
            assert_eq!(number(&literal, "entered"), 1);
            assert_eq!(address(&literal, "original"), 0);
            assert_eq!(address(&literal, "recorded_original"), 0);
            assert_eq!(address(&literal, "final"), target);
            let expected_outside = if operation == "mseal" {
                number(&fields(stdout, "MAPPING_MSEAL_HOST "), "raw")
            } else {
                0
            };
            assert_eq!(number(&literal, "nested_outside"), expected_outside);
            let path = if route == "nested-hook" {
                LiteinstDispatchPath::InGuestNestedHook
            } else {
                LiteinstDispatchPath::InGuestNestedSigsys
            };
            assert!(
                stats.dispatch_path_counts().count(&path) >= 2,
                "two actual nested mutations required: {stats}"
            );
        }
        _ => {
            assert_eq!(number(&literal, "entered"), 1);
            assert_eq!(
                address(&literal, "original"),
                address(&literal, "recorded_original")
            );
            if route == "rewrite-protected" {
                let original = address(&literal, "original");
                assert!(original + 4096 <= 0x6000_0000_0000 || original >= 0x6001_0000_0000);
                assert_eq!(address(&literal, "final"), target);
            } else if route == "rewrite-outside" {
                assert_eq!(address(&literal, "original"), target);
                assert_eq!(address(&literal, "final"), outside);
            } else {
                assert_eq!(address(&literal, "original"), target);
                assert_eq!(address(&literal, "final"), target);
            }
        }
    }
    assert_eq!(
        output.status.code(),
        Some(0),
        "literal child verdict: {output:?}"
    );
    let record = stats
        .snapshot()
        .dispatch_stats()
        .expect("actual dispatch record");
    assert_eq!(record.inconsistencies(), Vec::<String>::new(), "{record}");
    assert_physical_signals_agree(&stats, &record);
    assert_tool_callbacks_were_delivered(&global, &stats);
    if route == "nested-trap" {
        assert_eq!(
            stats
                .dispatch_path_counts()
                .count(&LiteinstDispatchPath::DirectHook),
            0
        );
        assert!(
            stats
                .dispatch_path_counts()
                .count(&LiteinstDispatchPath::PatchingDisabledFallback)
                > 0
        );
        assert_eq!(number(&literal, "traps"), 0);
        assert_eq!(number(&literal, "hooks"), 0);
    } else {
        assert!(number(&literal, "hooks") > 1);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn published_owner_survives_unsubscribed_fulltool_mapping_changes() {
    for operation in ["mprotect", "munmap"] {
        row("unsubscribed", operation).await;
    }
}
#[tokio::test(flavor = "current_thread")]
async fn published_owner_survives_injected_fulltool_mapping_changes() {
    for operation in ["mprotect", "munmap"] {
        row("inject", operation).await;
    }
}
#[tokio::test(flavor = "current_thread")]
async fn published_owner_survives_tail_injected_fulltool_mapping_changes() {
    for operation in ["mprotect", "munmap"] {
        row("tail", operation).await;
    }
}
#[tokio::test(flavor = "current_thread")]
async fn published_owner_survives_nested_hook_mapping_changes() {
    for operation in ["mprotect", "munmap"] {
        row("nested-hook", operation).await;
    }
}
#[tokio::test(flavor = "current_thread")]
async fn published_owner_survives_nested_sigsys_mapping_changes() {
    for operation in ["mprotect", "munmap"] {
        row("nested-trap", operation).await;
    }
}
#[tokio::test(flavor = "current_thread")]
async fn published_owner_mapping_guard_uses_rewritten_final_arguments() {
    for route in ["rewrite-protected", "rewrite-outside"] {
        for operation in ["mprotect", "munmap"] {
            row(route, operation).await;
        }
    }
}
#[tokio::test(flavor = "current_thread")]
async fn published_owner_guards_nested_raw_mseal_and_reports_kernel_support() {
    for route in ["nested-hook", "nested-trap"] {
        row(route, "mseal").await;
    }
}
