//! Compatibility controls for the shared counter/configuration extraction.
#![cfg(target_arch = "x86_64")]
use reverie_ptrace::InGuestRcbCounter;
use reverie_ptrace::PmuConfig;

#[test]
fn public_counter_and_config_types_are_identical() {
    fn to_core(counter: InGuestRcbCounter) -> reverie::InGuestRcbCounter {
        counter
    }
    fn to_ptrace(counter: reverie::InGuestRcbCounter) -> InGuestRcbCounter {
        counter
    }
    fn config(config: PmuConfig) -> reverie::pmu_config::PmuConfig {
        config
    }
    let _ = (to_core, to_ptrace, config);
}

#[test]
fn shared_configuration_child() {
    let Ok(mode) = std::env::var("REVERIE_SHARED_PMU_TEST_CHILD") else {
        return;
    };
    if mode == "singleton" {
        assert_eq!(reverie_ptrace::set_skid_margin_override(4321), Ok(()));
        assert_eq!(
            reverie::pmu_config::set_skid_margin_override(1234),
            Err(1234)
        );
        let config = PmuConfig::for_family_model(0x06, 0x3c).unwrap();
        assert_eq!(reverie_ptrace::set_pmu_config(config.clone()), Ok(()));
        assert_eq!(reverie::pmu_config::try_get_pmu_config(), Some(&config));
        assert_eq!(
            reverie::pmu_config::set_pmu_config(config.clone()),
            Err(config)
        );
        assert_eq!(reverie_ptrace::set_skid_margin_override(1), Err(1));
    } else {
        if mode == "recorded" {
            assert_eq!(reverie_ptrace::set_skid_margin_override(29), Ok(()));
        }
        let core = reverie::pmu_config::PmuConfig::new();
        let ptrace = PmuConfig::new();
        assert_eq!(format!("{core:?}"), format!("{ptrace:?}"));
        match core {
            Ok(config) => {
                if mode == "recorded" {
                    assert_eq!(config.skid_margin(), 29);
                }
                println!("KNOWN_CONFIG_MATCH");
            }
            Err(
                reverie::pmu_config::PmuValidationError::UnsupportedCpu { .. }
                | reverie::pmu_config::PmuValidationError::CouldNotReadCpuInfo,
            ) => println!("UNAVAILABLE_CONFIG_MATCH"),
            Err(error) => panic!("unexpected constructor refusal {error:?}"),
        }
    }
}

#[test]
fn configuration_storage_and_environment_diagnostics_are_shared() {
    for (mode, margin, latency) in [
        ("singleton", "0", "0"),
        ("valid", "17", "23"),
        ("invalid", "bad-margin", "bad-latency"),
        ("recorded", "17", "23"),
    ] {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "shared_configuration_child", "--nocapture"])
            .env("REVERIE_SHARED_PMU_TEST_CHILD", mode)
            .env("REVERIE_SKID_MARGIN_OVERRIDE", margin)
            .env("REVERIE_SKID_LATENCY_BUDGET_NS", latency)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        if mode != "singleton" {
            let stdout = String::from_utf8(out.stdout).unwrap();
            let stderr = String::from_utf8(out.stderr).unwrap();
            if stdout.contains("UNAVAILABLE_CONFIG_MATCH") {
                assert!(stderr.is_empty());
            } else {
                assert!(stdout.contains("KNOWN_CONFIG_MATCH"), "{stdout}");
                assert_eq!(stderr.matches("[reverie-ptrace]").count(), 4, "{stderr}");
                assert_eq!(
                    stderr.matches("REVERIE_SKID_MARGIN_OVERRIDE").count(),
                    2,
                    "{stderr}"
                );
                assert_eq!(
                    stderr.matches("REVERIE_SKID_LATENCY_BUDGET_NS").count(),
                    2,
                    "{stderr}"
                );
                if mode == "valid" || mode == "recorded" {
                    assert!(stderr.contains("forced to 17 RCBs"));
                    assert!(stderr.contains("room for 23 ns"));
                } else {
                    assert!(stderr.contains("bad-margin"));
                    assert!(stderr.contains("bad-latency"));
                    assert_eq!(stderr.matches("not a u64").count(), 4);
                }
            }
        }
    }
}
