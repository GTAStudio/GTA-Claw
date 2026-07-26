//! Compiles the external Slint component tree for Android targets.

use std::collections::HashMap;
use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-changed=ui");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS")
        .expect("Cargo must provide the target operating system");
    if target_os != "android" {
        // Every Slint runtime dependency is gated on `cfg(target_os = "android")`,
        // so a host `cargo check`/`cargo test` compiles the portable core alone
        // and must not emit generated UI that nothing includes.
        return;
    }

    let module_root = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR")
            .expect("Cargo must provide the package manifest directory"),
    )
    .join("ui")
    .join("modules");
    let configuration = slint_build::CompilerConfiguration::new()
        .with_style("material".into())
        .with_library_paths(HashMap::from([("gta-ui".into(), module_root)]));

    slint_build::compile_with_config("ui/app-window.slint", configuration)
        .expect("Slint UI compilation must succeed");
}
