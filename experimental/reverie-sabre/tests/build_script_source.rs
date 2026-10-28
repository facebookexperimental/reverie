#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

#[test]
fn relocated_cache_reset_precedes_cmake_configuration() {
    let build_script = include_str!("../build.rs");
    let reset = build_script
        .find("reset_relocated_cmake_build(source, build);")
        .expect("build script does not reset relocated CMake state");
    let configure = build_script
        .find("let mut configure = Command::new(&cmake);")
        .expect("build script does not configure CMake");
    assert!(
        reset < configure,
        "relocated state must be reset before CMake runs"
    );
}
