//! Compiles the external Slint component tree.

fn main() {
    slint_build::compile("ui/app-window.slint").expect("Slint UI compilation must succeed");
}
