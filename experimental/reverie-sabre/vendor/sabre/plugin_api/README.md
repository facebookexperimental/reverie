# Using `recursion_protector.c` as part of your source files in your plugin and licensing considerations

All plugins that run under SaBRe 2.0 are required to export the `from_plugin` and `vdso_ready` variables. Some languages, including Rust, currently cannot create such variables under the TLS model `initial-exec` which is a mandatory technical requirement. Thus, we provide the `recursion_protector.c` file so plugin authors can include it as part of their source code. The file is under the MIT license in order to avoid forcing plugin authors to opensource their plugins.
