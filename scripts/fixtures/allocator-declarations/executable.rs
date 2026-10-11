#[cfg(feature = "legacy")]
reverie_liteinst::declare_legacy_tool_backing!();

mod anchor;

fn main() {
    anchor::fixture_retains_real_initializer();
}
