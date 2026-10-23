// Retain the genuine native initializer and its real preflight reader.
// This link-only anchor never invokes initialization.
#[unsafe(no_mangle)]
pub extern "C" fn fixture_retains_real_initializer() {
    std::hint::black_box(
        reverie_liteinst::reverie_liteinst_initialize as unsafe extern "C" fn(),
    );
}
