//! Explicitly selected Gateway identity profiles in platform credential storage.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use claw_provider_sdk::secret::{CredentialKey, SecretStore, SecretString};
use claw_security::identity::DeviceIdentity;
use ring::rand::{SecureRandom as _, SystemRandom};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const SERVICE: &str = "gta-claw.gateway-device.v1";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// A stable, redaction-safe persistent-identity failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// Profile or canonical endpoint exceeds its allowed grammar or size.
    InvalidProfile,
    /// Credential storage is unavailable; there is no plaintext fallback.
    StoreUnavailable,
    /// Another process owns the profile initialization lock, or the lock path is unsafe.
    ProfileBusy,
    /// Stored private material is malformed and must not be replaced automatically.
    Corrupt,
    /// The operating system refused fresh entropy.
    EntropyUnavailable,
    /// A credential write or its readback could not be confirmed.
    CommitUnknown,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProfile => "invalid Gateway device profile",
            Self::StoreUnavailable => "native credential storage is unavailable; no plaintext fallback is permitted",
            Self::ProfileBusy => "device profile is busy or its coordination directory is unsafe",
            Self::Corrupt => "device profile is corrupt; preserve it and do not create a replacement identity",
            Self::EntropyUnavailable => "system entropy is unavailable",
            Self::CommitUnknown => "device profile publication could not be confirmed; retry the same profile without replacing it",
        })
    }
}

impl std::error::Error for IdentityError {}

/// Holds no private seed; it only identifies one endpoint-bound native credential and lock root.
pub struct DeviceProfile {
    key: CredentialKey,
    lock_root: PathBuf,
}

impl DeviceProfile {
    /// Selects a profile by canonical endpoint, local alias and an existing private lock directory.
    ///
    /// # Errors
    /// Rejects invalid aliases, endpoints or an unsafe coordination directory.
    pub fn new(endpoint: &str, alias: &str, lock_root: impl AsRef<Path>) -> Result<Self, IdentityError> {
        if alias.is_empty() || alias.len() > 64
            || !alias.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || endpoint.is_empty() || endpoint.len() > 2048 || endpoint.chars().any(char::is_control)
        {
            return Err(IdentityError::InvalidProfile);
        }
        let mut digest = Sha256::new();
        digest.update(u64::try_from(endpoint.len()).map_err(|_| IdentityError::InvalidProfile)?.to_le_bytes());
        digest.update(endpoint.as_bytes());
        digest.update(alias.as_bytes());
        let account = hex(&digest.finalize());
        let key = CredentialKey::new(SERVICE, account).map_err(|_| IdentityError::InvalidProfile)?;
        let lock_root = lock_root.as_ref().to_owned();
        check_directory(&lock_root)?;
        Ok(Self { key, lock_root })
    }

    fn lock(&self) -> Result<File, IdentityError> {
        check_directory(&self.lock_root)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x0020_0000).share_mode(3);
        }
        let file = options.open(self.lock_root.join(format!("{}.lock", self.key.account()))).map_err(|_| IdentityError::ProfileBusy)?;
        let metadata = file.metadata().map_err(|_| IdentityError::ProfileBusy)?;
        if !metadata.is_file() { return Err(IdentityError::ProfileBusy); }
        check_metadata(&metadata)?;
        file.try_lock().map_err(|_| IdentityError::ProfileBusy)?;
        Ok(file)
    }

    /// Loads or explicitly initializes the profile using one process-exclusive critical section.
    ///
    /// The store must be a protected backend; errors never fall back to transient or plaintext state.
    ///
    /// # Errors
    /// Refuses unavailable stores, corrupt entries, concurrent initialization and uncertain publication.
    pub fn load_or_create(&self, store: &dyn SecretStore) -> Result<DeviceIdentity, IdentityError> {
        let _lock = self.lock()?;
        if let Some(secret) = store.get(&self.key).map_err(|_| IdentityError::StoreUnavailable)? {
            return identity_from_secret(&secret);
        }
        let mut seed = Zeroizing::new([0_u8; 32]);
        SystemRandom::new().fill(seed.as_mut()).map_err(|_| IdentityError::EntropyUnavailable)?;
        let secret = SecretString::new(hex(seed.as_slice()));
        store.set(&self.key, &secret).map_err(|_| IdentityError::CommitUnknown)?;
        let stored = store.get(&self.key).map_err(|_| IdentityError::CommitUnknown)?.ok_or(IdentityError::CommitUnknown)?;
        if stored != secret { return Err(IdentityError::CommitUnknown); }
        identity_from_secret(&stored)
    }

    /// Deletes only this explicitly selected local identity; it does not revoke remote grants.
    ///
    /// # Errors
    /// Refuses an unavailable backend, unsafe path or concurrent profile operation.
    pub fn forget(&self, store: &dyn SecretStore) -> Result<bool, IdentityError> {
        let _lock = self.lock()?;
        store.delete(&self.key).map_err(|_| IdentityError::StoreUnavailable)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]]).map(char::from).collect()
}

fn identity_from_secret(secret: &SecretString) -> Result<DeviceIdentity, IdentityError> {
    let bytes = secret.expose().as_bytes();
    if bytes.len() != 64 { return Err(IdentityError::Corrupt); }
    let mut seed = Zeroizing::new([0_u8; 32]);
    for (slot, pair) in seed.iter_mut().zip(bytes.as_chunks::<2>().0) {
        let nibble = |byte| match byte { b'0'..=b'9' => Ok(byte - b'0'), b'a'..=b'f' => Ok(byte - b'a' + 10), _ => Err(IdentityError::Corrupt) };
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(DeviceIdentity::from_protected_seed(&seed))
}

fn check_metadata(metadata: &fs::Metadata) -> Result<(), IdentityError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(IdentityError::ProfileBusy);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 { return Err(IdentityError::ProfileBusy); }
    }
    Ok(())
}

fn check_directory(path: &Path) -> Result<(), IdentityError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| IdentityError::ProfileBusy)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() { return Err(IdentityError::ProfileBusy); }
    check_metadata(&metadata)
}

/// Opens the supported operating-system credential backend without installing a global default.
///
/// # Errors
/// Refuses platforms without an implemented native backend; never creates a plaintext file store.
pub fn native_store() -> Result<Box<dyn SecretStore>, IdentityError> {
    #[cfg(windows)]
    { claw_provider_sdk::secret::WindowsCredentialManagerStore::new().map(|store| Box::new(store) as Box<dyn SecretStore>).map_err(|_| IdentityError::StoreUnavailable) }
    #[cfg(target_os = "macos")]
    { claw_provider_sdk::secret::AppleKeychainStore::new().map(|store| Box::new(store) as Box<dyn SecretStore>).map_err(|_| IdentityError::StoreUnavailable) }
    #[cfg(not(any(windows, target_os = "macos")))]
    { Err(IdentityError::StoreUnavailable) }
}

/// Creates a coordination-only per-user directory; no secret bytes are written there.
///
/// # Errors
/// Refuses absent user-directory configuration, unsafe existing paths and directory creation failure.
pub fn native_lock_directory() -> Result<PathBuf, IdentityError> {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).ok_or(IdentityError::ProfileBusy)?;
    #[cfg(not(windows))]
    let base = std::env::var_os("HOME").map(PathBuf::from).ok_or(IdentityError::ProfileBusy)?;
    let path = base.join("gta-claw-device-locks-v1");
    if !path.exists() {
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        match builder.create(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(IdentityError::ProfileBusy),
        }
    }
    check_directory(&path)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use claw_provider_sdk::secret::MemorySecretStore;
    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("claw-profile-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            let builder = { use std::os::unix::fs::DirBuilderExt; let mut builder = builder; builder.mode(0o700); builder };
            builder.create(&path).expect("private fixture directory");
            Self(path)
        }
    }
    impl Drop for Root { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

    #[test]
    fn persistent_identity_reopens_and_is_partitioned_by_endpoint_and_alias() {
        let root = Root::new();
        let store = MemorySecretStore::new();
        let profile = DeviceProfile::new("wss://one.test", "main", &root.0).expect("profile");
        let identity = profile.load_or_create(&store).expect("new identity");
        let restored = DeviceProfile::new("wss://one.test", "main", &root.0).expect("same profile").load_or_create(&store).expect("restore");
        assert_eq!(identity.device_id(), restored.device_id());
        for (endpoint, alias) in [("wss://two.test", "main"), ("wss://one.test", "other")] {
            let other = DeviceProfile::new(endpoint, alias, &root.0).expect("other profile").load_or_create(&store).expect("other identity");
            assert_ne!(identity.device_id(), other.device_id());
        }
        assert!(profile.forget(&store).expect("explicit forget"));
        assert!(!profile.forget(&store).expect("idempotent forget"));
    }

    #[test]
    fn corrupt_or_busy_identity_never_rotates_silently() {
        let root = Root::new();
        let store = MemorySecretStore::new();
        let profile = DeviceProfile::new("wss://one.test", "main", &root.0).expect("profile");
        store.set(&profile.key, &SecretString::new("invalid-seed" )).expect("corruption fixture");
        assert_eq!(profile.load_or_create(&store).err(), Some(IdentityError::Corrupt));
        assert_eq!(store.get(&profile.key).expect("retained").expect("entry").expose(), "invalid-seed");
        let lock = profile.lock().expect("exclusive profile lock");
        assert_eq!(profile.load_or_create(&store).err(), Some(IdentityError::ProfileBusy));
        drop(lock);
        assert_eq!(profile.load_or_create(&store).err(), Some(IdentityError::Corrupt));
    }
}