//! Compiles the Slint component tree for the iOS shell.

fn main() {
    let configuration = slint_build::CompilerConfiguration::new().with_style("cupertino".into());
    slint_build::compile_with_config("ui/app-window.slint", configuration)
        .expect("Slint UI compilation must succeed");
}
