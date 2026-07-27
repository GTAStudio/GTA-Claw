//! Compiles the Android Slint component tree.

fn main() {
    let configuration = slint_build::CompilerConfiguration::new().with_style("material".into());
    slint_build::compile_with_config("ui/app-window.slint", configuration)
        .expect("Android Slint UI compilation must succeed");
}
