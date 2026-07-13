//! Compiles the external Slint component tree.

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn main() {
    use std::collections::HashMap;
    use std::path::PathBuf;

    let target_os = std::env::var("CARGO_CFG_TARGET_OS")
        .expect("Cargo must provide the target operating system");
    let style = match target_os.as_str() {
        "windows" => "fluent",
        "macos" => "cupertino",
        unsupported => panic!("gta-claw-desktop does not support {unsupported}"),
    };
    let module_root = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR")
            .expect("Cargo must provide the package manifest directory"),
    )
    .join("ui")
    .join("modules");
    let configuration = slint_build::CompilerConfiguration::new()
        .with_style(style.into())
        .with_library_paths(HashMap::from([("gta-ui".into(), module_root)]));

    slint_build::compile_with_config("ui/app-window.slint", configuration)
        .expect("Slint UI compilation must succeed");
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn main() {
    panic!("gta-claw-desktop supports only Windows and macOS");
}
