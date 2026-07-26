//! Fail-closed access to candidate data.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::{PolicyError, PolicyResult, error};

/// Default maximum size for one policy text file.
pub const DEFAULT_FILE_LIMIT: u64 = 4 * 1024 * 1024;
/// Default maximum number of files in one protected tree.
pub const DEFAULT_TREE_ENTRIES: usize = 4096;
/// Default maximum aggregate bytes in one protected tree.
pub const DEFAULT_TREE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_TREE_DEPTH: usize = 64;

/// A canonical root used for bounded non-following reads.
#[derive(Debug, Clone)]
pub struct SafeRoot {
    canonical: PathBuf,
}

/// One regular file discovered beneath a safe root.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TreeFile {
    /// Slash-separated relative path.
    pub relative: String,
    /// File size in bytes.
    pub size: u64,
}

#[cfg(windows)]
fn has_reparse_attribute(attributes: u32) -> bool {
    attributes & 0x400 != 0
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        has_reparse_attribute(metadata.file_attributes())
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

pub(crate) fn require_plain(metadata: &fs::Metadata, path: &Path) -> PolicyResult<()> {
    if metadata.file_type().is_symlink() || is_reparse(metadata) {
        return Err(PolicyError::new(format!(
            "candidate path is a symlink or reparse point: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::has_reparse_attribute;

    #[test]
    fn windows_reparse_attribute_is_rejected_even_for_regular_files() {
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

        assert!(!has_reparse_attribute(FILE_ATTRIBUTE_NORMAL));
        assert!(has_reparse_attribute(
            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_REPARSE_POINT
        ));
    }
}

fn validate_relative(relative: &Path) -> PolicyResult<()> {
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(PolicyError::new(format!(
            "policy path must be a non-empty relative path: {}",
            relative.display()
        )));
    }
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(PolicyError::new(format!(
                "policy path contains a non-normal component: {}",
                relative.display()
            )));
        }
    }
    Ok(())
}

fn slash_path(path: &Path) -> PolicyResult<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return Err(PolicyError::new(format!(
                "inventory path contains a non-normal component: {}",
                path.display()
            )));
        };
        let value = part.to_str().ok_or_else(|| {
            PolicyError::new(format!(
                "inventory path is not valid UTF-8: {}",
                path.display()
            ))
        })?;
        parts.push(value);
    }
    Ok(parts.join("/"))
}

impl SafeRoot {
    /// Creates a safe canonical directory root.
    pub fn new(root: impl AsRef<Path>) -> PolicyResult<Self> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(PolicyError::new(format!(
                "candidate root must be absolute: {}",
                root.display()
            )));
        }
        let metadata =
            fs::symlink_metadata(root).map_err(|cause| error("inspect candidate root", cause))?;
        require_plain(&metadata, root)?;
        if !metadata.is_dir() {
            return Err(PolicyError::new(format!(
                "candidate root is not a directory: {}",
                root.display()
            )));
        }
        let canonical =
            fs::canonicalize(root).map_err(|cause| error("canonicalize candidate root", cause))?;
        Ok(Self { canonical })
    }

    /// Returns the canonical root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.canonical
    }

    fn inspect_components(&self, relative: &Path) -> PolicyResult<PathBuf> {
        validate_relative(relative)?;
        let mut current = self.canonical.clone();
        for component in relative.components() {
            let Component::Normal(part) = component else {
                return Err(PolicyError::new("policy path component changed"));
            };
            current.push(part);
            let metadata = fs::symlink_metadata(&current)
                .map_err(|cause| error("inspect candidate path component", cause))?;
            require_plain(&metadata, &current)?;
        }
        let canonical = fs::canonicalize(&current)
            .map_err(|cause| error("canonicalize candidate policy path", cause))?;
        if !canonical.starts_with(&self.canonical) {
            return Err(PolicyError::new(format!(
                "candidate policy path escapes root: {}",
                relative.display()
            )));
        }
        Ok(canonical)
    }

    /// Resolves one required regular file beneath the root.
    pub fn regular_file(&self, relative: impl AsRef<Path>, limit: u64) -> PolicyResult<PathBuf> {
        let relative = relative.as_ref();
        let canonical = self.inspect_components(relative)?;
        let metadata = fs::symlink_metadata(&canonical)
            .map_err(|cause| error("inspect candidate policy file", cause))?;
        require_plain(&metadata, &canonical)?;
        if !metadata.is_file() {
            return Err(PolicyError::new(format!(
                "candidate policy input is not a regular file: {}",
                relative.display()
            )));
        }
        if metadata.len() > limit {
            return Err(PolicyError::new(format!(
                "candidate policy input exceeds {limit} bytes: {}",
                relative.display()
            )));
        }
        Ok(canonical)
    }

    /// Reads one bounded required file.
    pub fn read_bytes(&self, relative: impl AsRef<Path>, limit: u64) -> PolicyResult<Vec<u8>> {
        let relative = relative.as_ref();
        let path = self.regular_file(relative, limit)?;
        let before = fs::metadata(&path)
            .map_err(|cause| error("inspect candidate file before read", cause))?;
        let mut file =
            File::open(&path).map_err(|cause| error("open candidate policy file", cause))?;
        let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
        file.by_ref()
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|cause| error("read candidate policy file", cause))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
            return Err(PolicyError::new(format!(
                "candidate policy input exceeded {limit} bytes while reading: {}",
                relative.display()
            )));
        }
        let after = file
            .metadata()
            .map_err(|cause| error("inspect candidate file after read", cause))?;
        require_plain(&after, &path)?;
        if before.len() != after.len() || after.len() != bytes.len() as u64 {
            return Err(PolicyError::new(format!(
                "candidate policy input changed during read: {}",
                relative.display()
            )));
        }
        Ok(bytes)
    }

    /// Reads one bounded UTF-8 policy file.
    pub fn read_text(&self, relative: impl AsRef<Path>, limit: u64) -> PolicyResult<String> {
        let relative = relative.as_ref();
        let bytes = self.read_bytes(relative, limit)?;
        String::from_utf8(bytes).map_err(|cause| {
            PolicyError::new(format!(
                "candidate policy input is not UTF-8 ({}): {cause}",
                relative.display()
            ))
        })
    }

    /// Returns whether a path exists without following links.
    pub fn exists(&self, relative: impl AsRef<Path>) -> PolicyResult<bool> {
        let relative = relative.as_ref();
        validate_relative(relative)?;
        let path = self.canonical.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                require_plain(&metadata, &path)?;
                Ok(true)
            }
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(cause) => Err(error("inspect optional candidate path", cause)),
        }
    }

    /// Inventories a directory without following links or reparse points.
    pub fn list_tree(
        &self,
        relative: impl AsRef<Path>,
        max_entries: usize,
        max_bytes: u64,
    ) -> PolicyResult<Vec<TreeFile>> {
        let relative = relative.as_ref();
        let start = self.inspect_components(relative)?;
        let metadata =
            fs::symlink_metadata(&start).map_err(|cause| error("inspect inventory root", cause))?;
        require_plain(&metadata, &start)?;
        if !metadata.is_dir() {
            return Err(PolicyError::new(format!(
                "inventory root is not a directory: {}",
                relative.display()
            )));
        }
        let mut files = Vec::new();
        let mut aggregate = 0_u64;
        self.walk_tree(
            &start,
            relative,
            0,
            max_entries,
            max_bytes,
            &mut aggregate,
            &mut files,
        )?;
        files.sort_by(|left, right| left.relative.cmp(&right.relative));
        Ok(files)
    }

    /// Inventories the complete root without following links or reparse points.
    pub fn list_all(&self, max_entries: usize, max_bytes: u64) -> PolicyResult<Vec<TreeFile>> {
        let mut files = Vec::new();
        let mut aggregate = 0_u64;
        self.walk_tree(
            &self.canonical,
            Path::new(""),
            0,
            max_entries,
            max_bytes,
            &mut aggregate,
            &mut files,
        )?;
        files.sort_by(|left, right| left.relative.cmp(&right.relative));
        Ok(files)
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_tree(
        &self,
        directory: &Path,
        relative: &Path,
        depth: usize,
        max_entries: usize,
        max_bytes: u64,
        aggregate: &mut u64,
        files: &mut Vec<TreeFile>,
    ) -> PolicyResult<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(PolicyError::new(format!(
                "candidate tree exceeds depth {MAX_TREE_DEPTH}: {}",
                relative.display()
            )));
        }
        let mut entries = fs::read_dir(directory)
            .map_err(|cause| error("read candidate inventory directory", cause))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|cause| error("enumerate candidate inventory directory", cause))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            if files.len() >= max_entries {
                return Err(PolicyError::new(format!(
                    "candidate tree exceeds {max_entries} files: {}",
                    relative.display()
                )));
            }
            let name = entry.file_name();
            if name == OsStr::new(".") || name == OsStr::new("..") {
                return Err(PolicyError::new("candidate tree contains dot entry"));
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|cause| error("inspect candidate inventory entry", cause))?;
            require_plain(&metadata, &path)?;
            let child_relative = relative.join(&name);
            if metadata.is_dir() {
                self.walk_tree(
                    &path,
                    &child_relative,
                    depth + 1,
                    max_entries,
                    max_bytes,
                    aggregate,
                    files,
                )?;
            } else if metadata.is_file() {
                *aggregate = aggregate
                    .checked_add(metadata.len())
                    .ok_or_else(|| PolicyError::new("candidate tree aggregate size overflowed"))?;
                if *aggregate > max_bytes {
                    return Err(PolicyError::new(format!(
                        "candidate tree exceeds {max_bytes} aggregate bytes: {}",
                        relative.display()
                    )));
                }
                files.push(TreeFile {
                    relative: slash_path(&child_relative)?,
                    size: metadata.len(),
                });
            } else {
                return Err(PolicyError::new(format!(
                    "candidate inventory entry is not regular: {}",
                    child_relative.display()
                )));
            }
        }
        Ok(())
    }
}

/// Computes a lowercase SHA-256 digest.
#[must_use]
pub fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Computes a SHA-256 digest for one bounded safe-root file.
pub fn file_sha256(root: &SafeRoot, relative: impl AsRef<Path>) -> PolicyResult<String> {
    Ok(sha256(&root.read_bytes(relative, DEFAULT_FILE_LIMIT)?))
}

/// Requires two complete trees to contain identical paths and bytes.
pub fn compare_trees(
    trusted: &SafeRoot,
    candidate: &SafeRoot,
    relative: impl AsRef<Path>,
) -> PolicyResult<()> {
    let relative = relative.as_ref();
    let trusted_files = trusted.list_tree(relative, DEFAULT_TREE_ENTRIES, DEFAULT_TREE_BYTES)?;
    let candidate_files =
        candidate.list_tree(relative, DEFAULT_TREE_ENTRIES, DEFAULT_TREE_BYTES)?;
    if trusted_files != candidate_files {
        return Err(PolicyError::new(format!(
            "protected tree inventory changed: {}",
            relative.display()
        )));
    }
    let candidate_sizes = candidate_files
        .iter()
        .map(|file| (file.relative.as_str(), file.size))
        .collect::<BTreeMap<_, _>>();
    for file in trusted_files {
        let path = Path::new(&file.relative);
        let trusted_bytes = trusted.read_bytes(path, file.size)?;
        let candidate_limit = *candidate_sizes
            .get(file.relative.as_str())
            .ok_or_else(|| PolicyError::new("protected tree inventory changed"))?;
        let candidate_bytes = candidate.read_bytes(path, candidate_limit)?;
        if trusted_bytes != candidate_bytes {
            return Err(PolicyError::new(format!(
                "protected trust-root file changed: {}",
                file.relative
            )));
        }
    }
    Ok(())
}
