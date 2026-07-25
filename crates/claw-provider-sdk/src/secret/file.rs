//! Permission-strict file credential backend.
//!
//! This is the default backend on Linux and other targets without a native
//! keystore. Credentials live one-per-file under a directory that must be
//! private to the current user. On Unix the directory is created with mode
//! `0700` and files with mode `0600`; a file whose mode grants any group or
//! other bit is refused rather than read.
//!
//! Reads additionally consult the systemd credentials directory named by
//! `$CREDENTIALS_DIRECTORY`, which lets a service receive credentials without
//! ever writing them to persistent storage.

use std::fmt::{self, Debug, Formatter};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::{CredentialKey, SecretStore, SecretStoreError, SecretString};

const BACKEND: &str = "file";

/// Credential store backed by per-credential files with strict permissions.
pub struct FileSecretStore {
    root: PathBuf,
    systemd_root: Option<PathBuf>,
}

impl Debug for FileSecretStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileSecretStore")
            .field("root", &self.root)
            .field("systemd_root", &self.systemd_root)
            .finish()
    }
}

impl FileSecretStore {
    /// Opens (and creates, if needed) a store rooted at `root`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError`] when the directory cannot be created with
    /// owner-only permissions.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, SecretStoreError> {
        let root = root.into();
        create_private_dir(&root)?;
        Ok(Self {
            root,
            systemd_root: systemd_credentials_dir(),
        })
    }

    /// Opens the store at the conventional per-user location.
    ///
    /// The location is `$GTA_CLAW_CREDENTIALS_DIR` when set, otherwise
    /// `$XDG_DATA_HOME/gta-claw/credentials`, otherwise
    /// `$HOME/.local/share/gta-claw/credentials`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError::Unavailable`] when no home directory is
    /// known, or a filesystem error from [`FileSecretStore::new`].
    pub fn default_location() -> Result<Self, SecretStoreError> {
        Self::new(default_root()?)
    }

    /// Returns the directory holding the credential files.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Overrides the systemd credentials directory consulted on reads.
    #[must_use]
    pub fn with_systemd_root(mut self, root: Option<PathBuf>) -> Self {
        self.systemd_root = root;
        self
    }

    fn path_for(&self, key: &CredentialKey) -> PathBuf {
        self.root.join(encode_key(key))
    }

    fn read_file(path: &Path) -> Result<Option<SecretString>, SecretStoreError> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Err(SecretStoreError::AccessDenied { backend: BACKEND });
            }
            Err(_) => {
                return Err(SecretStoreError::Backend {
                    backend: BACKEND,
                    detail: "credential file could not be read",
                });
            }
        };
        let text =
            String::from_utf8(bytes).map_err(|_| SecretStoreError::Corrupt { backend: BACKEND })?;
        Ok(Some(SecretString::new(text)))
    }
}

impl SecretStore for FileSecretStore {
    fn backend(&self) -> &'static str {
        BACKEND
    }

    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, SecretStoreError> {
        let path = self.path_for(key);
        if path.exists() {
            check_private_file(&path)?;
            return Self::read_file(&path);
        }
        if let Some(systemd_root) = &self.systemd_root {
            let systemd_path = systemd_root.join(encode_key(key));
            if systemd_path.exists() {
                check_private_file(&systemd_path)?;
                return Self::read_file(&systemd_path);
            }
        }
        Ok(None)
    }

    fn set(&self, key: &CredentialKey, secret: &SecretString) -> Result<(), SecretStoreError> {
        create_private_dir(&self.root)?;
        let path = self.path_for(key);
        let temporary = path.with_extension("tmp");
        write_private_file(&temporary, secret.expose().as_bytes())?;
        fs::rename(&temporary, &path).map_err(|_| SecretStoreError::Backend {
            backend: BACKEND,
            detail: "credential file could not be replaced",
        })?;
        check_private_file(&path)
    }

    fn delete(&self, key: &CredentialKey) -> Result<bool, SecretStoreError> {
        match fs::remove_file(self.path_for(key)) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                Err(SecretStoreError::AccessDenied { backend: BACKEND })
            }
            Err(_) => Err(SecretStoreError::Backend {
                backend: BACKEND,
                detail: "credential file could not be removed",
            }),
        }
    }

    fn insert_if_absent(
        &self,
        key: &CredentialKey,
        secret: &SecretString,
    ) -> Result<bool, SecretStoreError> {
        create_private_dir(&self.root)?;
        let path = self.path_for(key);
        if create_new_private_file(&path, secret.expose().as_bytes())? {
            check_private_file(&path)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn accounts(&self, service: &str) -> Result<Vec<String>, SecretStoreError> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Err(SecretStoreError::AccessDenied { backend: BACKEND });
            }
            Err(_) => {
                return Err(SecretStoreError::Backend {
                    backend: BACKEND,
                    detail: "the credential directory could not be listed",
                });
            }
        };

        let mut accounts = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| SecretStoreError::Backend {
                backend: BACKEND,
                detail: "the credential directory could not be listed",
            })?;
            // A crashed `set` can leave a `.tmp` file behind; it is not a
            // credential and must never be reported as one.
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if let Some((found, account)) = decode_key(&name)
                && found == service
            {
                accounts.push(account);
            }
        }
        Ok(accounts)
    }
}

/// Encodes a credential key into a single filesystem-safe file name.
///
/// Every byte outside `A-Za-z0-9._-` is percent-encoded and the two components
/// are joined with `~`, which the encoding can never produce. Distinct keys
/// therefore always yield distinct names, and no component can escape the
/// credential directory.
#[must_use]
pub fn encode_key(key: &CredentialKey) -> String {
    let mut encoded = String::new();
    for (index, part) in [key.service(), key.account()].into_iter().enumerate() {
        if index > 0 {
            encoded.push('~');
        }
        for byte in part.as_bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
                encoded.push(char::from(*byte));
            } else {
                encoded.push('%');
                encoded.push(char::from(hex_digit(byte >> 4)));
                encoded.push(char::from(hex_digit(byte & 0x0F)));
            }
        }
    }
    encoded.push_str(".cred");
    encoded
}

const fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'A' + (value - 10),
    }
}

/// Reverses [`encode_key`], returning the service and account it encoded.
///
/// Returns `None` for any name [`encode_key`] could not have produced, which is
/// how stray files such as the `.tmp` written during a replace are ignored.
#[must_use]
pub fn decode_key(name: &str) -> Option<(String, String)> {
    let body = name.strip_suffix(".cred")?;
    let (service, account) = body.split_once('~')?;
    // `~` is percent-encoded, so exactly one separator can ever appear.
    if account.contains('~') {
        return None;
    }
    Some((decode_component(service)?, decode_component(account)?))
}

fn decode_component(part: &str) -> Option<String> {
    let bytes = part.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            decoded.push(byte);
            index += 1;
        } else {
            return None;
        }
    }
    String::from_utf8(decoded).ok()
}

const fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

fn default_root() -> Result<PathBuf, SecretStoreError> {
    if let Some(explicit) = std::env::var_os("GTA_CLAW_CREDENTIALS_DIR") {
        return Ok(PathBuf::from(explicit));
    }
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME") {
        let data_home = PathBuf::from(data_home);
        if data_home.is_absolute() {
            return Ok(data_home.join("gta-claw").join("credentials"));
        }
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or(SecretStoreError::Unavailable { backend: BACKEND })?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("gta-claw")
        .join("credentials"))
}

fn systemd_credentials_dir() -> Option<PathBuf> {
    std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from)
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<(), SecretStoreError> {
    use std::os::unix::fs::DirBuilderExt;

    if path.is_dir() {
        return check_private_dir(path);
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.is_dir()
    {
        fs::create_dir_all(parent).map_err(|_| SecretStoreError::Backend {
            backend: BACKEND,
            detail: "credential directory could not be created",
        })?;
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| SecretStoreError::Backend {
            backend: BACKEND,
            detail: "credential directory could not be created",
        })?;
    check_private_dir(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> Result<(), SecretStoreError> {
    if path.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(path).map_err(|_| SecretStoreError::Backend {
        backend: BACKEND,
        detail: "credential directory could not be created",
    })
}

#[cfg(unix)]
fn check_private_dir(path: &Path) -> Result<(), SecretStoreError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|_| SecretStoreError::Backend {
        backend: BACKEND,
        detail: "credential directory could not be inspected",
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SecretStoreError::InsecurePermissions { mode });
    }
    Ok(())
}

#[cfg(unix)]
fn check_private_file(path: &Path) -> Result<(), SecretStoreError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|_| SecretStoreError::Backend {
        backend: BACKEND,
        detail: "credential file could not be inspected",
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SecretStoreError::InsecurePermissions { mode });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_file(_path: &Path) -> Result<(), SecretStoreError> {
    // Windows relies on the per-user profile ACL rather than POSIX mode bits.
    Ok(())
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), SecretStoreError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| map_write_error(&error))?;
    file.write_all(bytes)
        .map_err(|error| map_write_error(&error))?;
    file.sync_all().map_err(|error| map_write_error(&error))
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), SecretStoreError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|error| map_write_error(&error))?;
    file.write_all(bytes)
        .map_err(|error| map_write_error(&error))?;
    file.sync_all().map_err(|error| map_write_error(&error))
}

fn map_write_error(error: &io::Error) -> SecretStoreError {
    if error.kind() == io::ErrorKind::PermissionDenied {
        SecretStoreError::AccessDenied { backend: BACKEND }
    } else {
        SecretStoreError::Backend {
            backend: BACKEND,
            detail: "credential file could not be written",
        }
    }
}

/// Creates a credential file, failing instead of overwriting when it already exists.
///
/// `create_new` maps to `O_EXCL` on Unix and `CREATE_NEW` on Windows, so exactly one
/// caller wins even when the racing callers are separate processes. That is what makes
/// [`FileSecretStore::insert_if_absent`] a usable mutual-exclusion primitive.
#[cfg(unix)]
fn create_new_private_file(path: &Path, bytes: &[u8]) -> Result<bool, SecretStoreError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(map_write_error(&error)),
    };
    file.write_all(bytes)
        .map_err(|error| map_write_error(&error))?;
    file.sync_all().map_err(|error| map_write_error(&error))?;
    Ok(true)
}

/// Creates a credential file, failing instead of overwriting when it already exists.
#[cfg(not(unix))]
fn create_new_private_file(path: &Path, bytes: &[u8]) -> Result<bool, SecretStoreError> {
    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(map_write_error(&error)),
    };
    file.write_all(bytes)
        .map_err(|error| map_write_error(&error))?;
    file.sync_all().map_err(|error| map_write_error(&error))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    /// Creates a directory holding credential material.
    ///
    /// On Unix this must be `0o700`: `FileSecretStore` refuses a credential root that
    /// any other user can read, so a directory left at the umask default of `0o755`
    /// makes the store fail to open. `mkdir(2)` masks the requested mode with the
    /// process umask, which can only clear bits, so the result is never wider than
    /// `0o700` whatever the ambient umask is.
    #[cfg(unix)]
    fn create_temp_dir(path: &Path) {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(path)
            .expect("temporary directory");
        let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o700,
            "temporary credential directory {} was created as {mode:o}, not 0o700",
            path.display()
        );
    }

    #[cfg(not(unix))]
    fn create_temp_dir(path: &Path) {
        fs::create_dir_all(path).expect("temporary directory");
    }

    /// Plants a credential file the way a real one exists on disk.
    ///
    /// Plain [`fs::write`] creates `0o666 & !umask`, i.e. `0o644` under the usual
    /// `0o022`. The store refuses to read any credential with group or other bits
    /// set, so a file planted with [`fs::write`] is rejected on permissions before
    /// its contents are ever examined.
    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
        }
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock is after the epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("claw-cred-{label}-{nanos}"));
            create_temp_dir(&path);
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn keys_encode_to_unambiguous_file_names() {
        let plain = CredentialKey::new("gta-claw", "default").expect("valid");
        assert_eq!(encode_key(&plain), "gta-claw~default.cred");

        let punctuated = CredentialKey::new("gta-claw:openai", "team default").expect("valid");
        assert_eq!(
            encode_key(&punctuated),
            "gta-claw%3Aopenai~team%20default.cred"
        );

        let traversal = CredentialKey::new("../../etc", "passwd").expect("valid");
        assert_eq!(encode_key(&traversal), "..%2F..%2Fetc~passwd.cred");
        assert!(!encode_key(&traversal).contains('/'));
        assert!(!encode_key(&traversal).contains('\\'));

        let non_ascii = CredentialKey::new("qwen", "登录").expect("valid");
        assert_eq!(encode_key(&non_ascii), "qwen~%E7%99%BB%E5%BD%95.cred");
    }

    #[test]
    fn encoded_names_never_collide_across_different_keys() {
        let left = CredentialKey::new("a/b", "c").expect("valid");
        let right = CredentialKey::new("a", "b/c").expect("valid");
        assert_eq!(encode_key(&left), "a%2Fb~c.cred");
        assert_eq!(encode_key(&right), "a~b%2Fc.cred");
        assert_ne!(encode_key(&left), encode_key(&right));

        let tilde_left = CredentialKey::new("a~b", "c").expect("valid");
        let tilde_right = CredentialKey::new("a", "b~c").expect("valid");
        assert_eq!(encode_key(&tilde_left), "a%7Eb~c.cred");
        assert_eq!(encode_key(&tilde_right), "a~b%7Ec.cred");
        assert_ne!(encode_key(&tilde_left), encode_key(&tilde_right));
    }

    #[test]
    fn file_store_round_trips_a_credential() {
        let temporary = TempDir::new("roundtrip");
        let store = FileSecretStore::new(temporary.path().join("credentials")).expect("store");
        let key = CredentialKey::new("gta-claw:openai", "default").expect("valid");

        assert_eq!(store.get(&key).expect("get"), None);
        store
            .set(&key, &SecretString::new("sk-live-4f9a2c7e0b1d"))
            .expect("set");
        assert_eq!(
            store.get(&key).expect("get").expect("present").expose(),
            "sk-live-4f9a2c7e0b1d"
        );

        store.set(&key, &SecretString::new("rotated")).expect("set");
        assert_eq!(
            store.get(&key).expect("get").expect("present").expose(),
            "rotated"
        );

        assert!(store.delete(&key).expect("delete"));
        assert!(!store.delete(&key).expect("second delete"));
        assert_eq!(store.get(&key).expect("get"), None);
        assert_eq!(store.backend(), "file");
        assert_eq!(store.root(), temporary.path().join("credentials"));
    }

    #[test]
    fn stored_bytes_are_exactly_the_secret_with_no_envelope() {
        let temporary = TempDir::new("bytes");
        let store = FileSecretStore::new(temporary.path()).expect("store");
        let key = CredentialKey::new("gta-claw:anthropic", "default").expect("valid");
        store
            .set(&key, &SecretString::new("abc\ndef"))
            .expect("set");

        let path = temporary.path().join(encode_key(&key));
        assert_eq!(fs::read(&path).expect("read"), b"abc\ndef");
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn a_non_utf8_credential_file_is_reported_as_corrupt() {
        let temporary = TempDir::new("corrupt");
        let store = FileSecretStore::new(temporary.path()).expect("store");
        let key = CredentialKey::new("gta-claw:openai", "default").expect("valid");
        write_private(&temporary.path().join(encode_key(&key)), &[0xFF, 0xFE]);
        assert_eq!(
            store.get(&key),
            Err(SecretStoreError::Corrupt { backend: "file" })
        );
    }

    #[test]
    fn reads_fall_back_to_the_systemd_credentials_directory() {
        let temporary = TempDir::new("systemd");
        let systemd = temporary.path().join("systemd");
        fs::create_dir_all(&systemd).expect("systemd directory");
        let key = CredentialKey::new("gta-claw:openai", "default").expect("valid");
        write_private(&systemd.join(encode_key(&key)), b"from-systemd");

        let store = FileSecretStore::new(temporary.path().join("credentials"))
            .expect("store")
            .with_systemd_root(Some(systemd));
        assert_eq!(
            store.get(&key).expect("get").expect("present").expose(),
            "from-systemd"
        );

        store.set(&key, &SecretString::new("local")).expect("set");
        assert_eq!(
            store.get(&key).expect("get").expect("present").expose(),
            "local",
            "a local credential takes precedence over the systemd one"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_files_are_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = TempDir::new("mode");
        let root = temporary.path().join("credentials");
        let store = FileSecretStore::new(&root).expect("store");
        let key = CredentialKey::new("gta-claw:openai", "default").expect("valid");
        store.set(&key, &SecretString::new("secret")).expect("set");

        let directory_mode = fs::metadata(&root).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(directory_mode, 0o700);
        let file_mode = fs::metadata(root.join(encode_key(&key)))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn unix_refuses_to_read_a_world_readable_credential() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = TempDir::new("insecure");
        let root = temporary.path().join("credentials");
        let store = FileSecretStore::new(&root).expect("store");
        let key = CredentialKey::new("gta-claw:openai", "default").expect("valid");
        store.set(&key, &SecretString::new("secret")).expect("set");

        let path = root.join(encode_key(&key));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_eq!(
            store.get(&key),
            Err(SecretStoreError::InsecurePermissions { mode: 0o644 })
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(
            store.get(&key).expect("get").expect("present").expose(),
            "secret"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_refuses_a_group_readable_credential_directory() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = TempDir::new("insecure-dir");
        let root = temporary.path().join("credentials");
        fs::create_dir_all(&root).expect("create");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).expect("chmod");
        assert_eq!(
            FileSecretStore::new(&root).map(|_| ()),
            Err(SecretStoreError::InsecurePermissions { mode: 0o750 })
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_refuses_a_world_readable_systemd_credential() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = TempDir::new("systemd-insecure");
        let systemd = temporary.path().join("systemd");
        fs::create_dir_all(&systemd).expect("systemd directory");
        let key = CredentialKey::new("gta-claw:openai", "default").expect("valid");
        let planted = systemd.join(encode_key(&key));
        fs::write(&planted, b"from-systemd").expect("write");
        fs::set_permissions(&planted, fs::Permissions::from_mode(0o644)).expect("chmod");

        let store = FileSecretStore::new(temporary.path().join("credentials"))
            .expect("store")
            .with_systemd_root(Some(systemd));
        assert_eq!(
            store.get(&key),
            Err(SecretStoreError::InsecurePermissions { mode: 0o644 }),
            "a systemd credential any other user can read must be refused, \
             exactly as a local one is"
        );

        // systemd itself installs credentials as 0o400, which must still be readable.
        fs::set_permissions(&planted, fs::Permissions::from_mode(0o400)).expect("chmod");
        assert_eq!(
            store.get(&key).expect("get").expect("present").expose(),
            "from-systemd"
        );
    }

    #[test]
    fn debug_output_contains_no_secret_material() {
        let temporary = TempDir::new("debug");
        let store = FileSecretStore::new(temporary.path()).expect("store");
        let key = CredentialKey::new("gta-claw:openai", "default").expect("valid");
        store
            .set(&key, &SecretString::new("sk-live-4f9a2c7e0b1d"))
            .expect("set");
        let rendered = format!("{store:?}");
        assert!(!rendered.contains("sk-live-4f9a2c7e0b1d"), "{rendered}");
        assert!(rendered.contains("FileSecretStore"));
    }
}
