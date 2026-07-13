//! Compiles the external Slint component tree.

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn main() {
    slint_build::compile("ui/app-window.slint").expect("Slint UI compilation must succeed");
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn main() {
    panic!("gta-claw-desktop supports only Windows and macOS");
}
