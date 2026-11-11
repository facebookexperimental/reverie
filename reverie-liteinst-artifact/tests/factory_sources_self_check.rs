//! The reviewed Reverie source identities the private-static producer's
//! providers enforce must accept this checkout. view_site/caller.rs's
//! installer identity, which no producer calls, is not covered (dh-rtkedo).
//!
//! The factory refuses a source it has not reviewed: trap.rs by its gate
//! shape, fixed_gates.rs, exec_private.rs and handoff.rs by complete digest.
//! Nothing else tests those declarations against Reverie's own tree, so an
//! edit to one of the sources silently disabled the owned link until a
//! pipeline run reached the refusal. This runs each consumer's real
//! predicate over this workspace and names every one that refuses.
//!
//! An integration test, not a unit test: Hermit compiles src/lib.rs into a
//! script package whose CARGO_MANIFEST_DIR is not this crate, and that harness
//! never builds tests/.

use std::path::Path;

use reverie_liteinst_artifact::private_static::factory_source_self_check;

const ARMS: [&str; 9] = [
    "ordinary_gate trap.rs gate shape",
    "ordinary_gate fixed_gates.rs",
    "terminal_observation exec_private.rs",
    "bootstrap_descriptor handoff.rs",
    "bootstrap_env_aux handoff.rs",
    "bootstrap_role handoff.rs",
    "bootstrap_site handoff.rs",
    "view_site handoff.rs",
    "view_table handoff.rs",
];

#[test]
fn factory_source_identities_accept_this_checkout() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("artifact crate sits inside the Reverie workspace");
    let results = factory_source_self_check(root);
    let names = results.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    assert_eq!(names, ARMS, "the factory source self-check arms changed");
    let refusals = results
        .into_iter()
        .filter_map(|(name, result)| result.err().map(|error| format!("\n  {name}: {error}")))
        .collect::<String>();
    assert!(
        refusals.is_empty(),
        "reviewed source identities refuse this checkout ({}):{refusals}",
        root.display()
    );
}
