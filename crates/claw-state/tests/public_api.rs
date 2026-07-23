//! Public API compatibility checks for state profiles and protected receipts.

use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::{
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use claw_state::{
    LinuxProtectedInitialization, ProtectedSnapshotReceipt, StateError, StateErrorKind,
    StateProfile, StateStore, StoreConfig, SynchronousPolicy, initialize_linux_protected_offline,
};

fn existing_store_config_surface_still_compiles(path: &Path) -> StoreConfig {
    StoreConfig::new(path)
        .with_max_connections(2)
        .with_busy_timeout(std::time::Duration::from_secs(1))
        .with_acquire_timeout(std::time::Duration::from_secs(1))
        .with_open_timeout(std::time::Duration::from_secs(1))
        .with_operation_timeout(std::time::Duration::from_secs(1))
        .with_close_timeout(std::time::Duration::from_secs(1))
        .with_synchronous(SynchronousPolicy::Normal)
}

fn protected_receipt_surface_still_compiles(receipt: &ProtectedSnapshotReceipt) {
    let _: u64 = receipt.generation();
    let _: u8 = receipt.slot();
    let _: u64 = receipt.byte_length();
    let _: &[u8; 32] = receipt.digest();
    let _: u64 = receipt.database_device();
    let _: u64 = receipt.database_inode();
    let _: u64 = receipt.writer_device();
    let _: u64 = receipt.writer_inode();
    let _: u64 = receipt.writer_generation();
}

fn protected_store_methods_still_compile(store: &StateStore) {
    let _publication = store.publish_protected_snapshot();
    let _latest = store.latest_protected_snapshot_receipt();
}

fn protected_initializer_surface_still_compiles(namespace: &Path) {
    let _: Result<LinuxProtectedInitialization, StateError> =
        initialize_linux_protected_offline(namespace, 65_534, 65_534);
}

#[cfg(target_os = "linux")]
fn bounded_output(command: &mut Command, timeout: Duration) -> Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn bounded public API child");
    let deadline = Instant::now() + timeout;
    loop {
        if child
            .try_wait()
            .expect("read bounded public API child status")
            .is_some()
        {
            return child
                .wait_with_output()
                .expect("collect bounded public API child output");
        }
        if Instant::now() >= deadline {
            child.kill().expect("terminate unbounded public API child");
            let _ = child.wait();
            panic!("public API child exceeded its deadline");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn profile_configuration_is_additive_and_derives_the_fixed_database_name() {
    let portable_path = PathBuf::from(if cfg!(windows) {
        r"C:\state\portable.sqlite"
    } else {
        "/state/portable.sqlite"
    });
    let portable = existing_store_config_surface_still_compiles(&portable_path);
    assert_eq!(portable.path(), portable_path);
    assert_eq!(portable.profile(), StateProfile::PortablePrivate);

    let namespace = PathBuf::from(if cfg!(windows) {
        r"C:\state\protected"
    } else {
        "/state/protected"
    });
    let protected = StoreConfig::linux_protected(&namespace);
    assert_eq!(protected.path(), namespace.join("state.sqlite"));
    assert_eq!(protected.profile(), StateProfile::LinuxProtected);

    let _receipt_api = protected_receipt_surface_still_compiles;
    let _store_api = protected_store_methods_still_compile;
    let _initializer_api = protected_initializer_surface_still_compiles;
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn linux_protected_open_is_explicitly_unsupported_off_linux() {
    let namespace = std::env::temp_dir().join("gta-claw-linux-protected-unsupported");
    let error = match StateStore::open(StoreConfig::linux_protected(namespace)).await {
        Ok(store) => {
            drop(store);
            panic!("LinuxProtected open must fail off Linux");
        }
        Err(error) => error,
    };
    assert!(matches!(
        &error,
        StateError::InvalidValue {
            field: "state platform",
            reason: "opening LinuxProtected state requires Linux",
        }
    ));
    assert_eq!(error.kind(), StateErrorKind::UnsupportedPlatform);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn linux_protected_initializer_is_explicitly_unsupported_off_linux() {
    let namespace = std::env::temp_dir().join("gta-claw-linux-protected-init-unsupported");
    let error = initialize_linux_protected_offline(namespace, 65_534, 65_534)
        .expect_err("LinuxProtected initialization must fail off Linux");
    assert!(matches!(
        &error,
        StateError::InvalidValue {
            field: "state platform",
            reason: "offline LinuxProtected initialization requires Linux",
        }
    ));
    assert_eq!(error.kind(), StateErrorKind::UnsupportedPlatform);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_protected_initializer_requires_real_and_effective_root() {
    const CHILD_ENV: &str = "GTA_CLAW_LP3_NONROOT_INITIALIZER_CHILD";
    let mut identity = Command::new("/usr/bin/id");
    identity.arg("-u");
    let uid = bounded_output(&mut identity, Duration::from_secs(5));
    if uid.stdout == b"0\n" && std::env::var_os(CHILD_ENV).is_none() {
        let mut child = Command::new("/usr/bin/setpriv");
        child
            .args(["--reuid=65534", "--regid=65534", "--clear-groups", "--"])
            .arg(std::env::current_exe().expect("resolve public API test executable"))
            .args([
                "--exact",
                "linux_protected_initializer_requires_real_and_effective_root",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "1");
        let output = bounded_output(&mut child, Duration::from_secs(10));
        assert!(
            output.status.success(),
            "nonroot initializer child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let error = initialize_linux_protected_offline(
        Path::new("/root/not-inspected-before-credential-check"),
        65_534,
        65_534,
    )
    .expect_err("nonroot initializer must fail");
    assert!(matches!(
        &error,
        StateError::InvalidValue {
            field: "state privilege",
            reason: "offline LinuxProtected initialization requires real and effective UID 0",
        }
    ));
    assert_eq!(error.kind(), StateErrorKind::PrivilegeRequired);
}
