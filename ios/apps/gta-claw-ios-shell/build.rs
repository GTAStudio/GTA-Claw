//! Compiles the iOS Slint component tree.

fn main() {
    let configuration = slint_build::CompilerConfiguration::new().with_style("cupertino".into());
    slint_build::compile_with_config("ui/app-window.slint", configuration)
        .expect("iOS Slint UI compilation must succeed");
}
