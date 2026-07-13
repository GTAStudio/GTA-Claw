//! Main-thread smoke test for the native macOS Slint winit backend.

#[cfg(target_os = "macos")]
slint::slint! {
    export component BackendSmokeWindow inherits Window {
        title: "GTA Claw backend smoke";
        width: 64px;
        height: 64px;
    }
}

#[cfg(target_os = "macos")]
fn main() {
    use std::time::Duration;

    use slint::ComponentHandle as _;

    let _watchdog = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(30));
        eprintln!("macOS winit smoke exceeded its hard timeout");
        std::process::abort();
    });

    let window = BackendSmokeWindow::new().expect("initialize the Slint winit backend");
    window.show().expect("show the native smoke-test window");

    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::SingleShot,
        Duration::from_millis(250),
        || slint::quit_event_loop().expect("quit the Slint event loop"),
    );
    slint::run_event_loop().expect("run the native Slint event loop");
    window.hide().expect("hide the native smoke-test window");
}

#[cfg(not(target_os = "macos"))]
fn main() {}
