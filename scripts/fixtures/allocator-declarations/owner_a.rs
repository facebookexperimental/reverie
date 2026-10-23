reverie_liteinst::declare_legacy_tool_backing!();

#[unsafe(no_mangle)]
pub extern "C" fn fixture_descriptor_owner_a() {
    std::hint::black_box(
        reverie_liteinst::reverie_liteinst_initialize as unsafe extern "C" fn(),
    );
}
