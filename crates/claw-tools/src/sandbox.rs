//! Workspace sandbox: every filesystem path a tool touches is resolved here.
//!
//! The resolver is closed rather than filtering: a path is rejected unless it
//! is a relative, component-normalized name whose every component exists inside
//! the canonical workspace root and is not a symbolic link, junction, or other
//! reparse point. Windows naming semantics are enforced on every platform so a
//! payload cannot be accepted on Linux and later escape on Windows.
//!
//! Layers, in order:
//! 1. Lexical rejection of absolute, UNC, drive-relative, traversal, alternate
//!    data stream, reserved device, trailing dot/space and wildcard forms.
//! 2. Component-by-component `symlink_metadata` walk that refuses links and
//!    reparse points at every level, including the final component.
//! 3. A no-follow open (`O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`) so the
//!    final component cannot be swapped for a link between check and use.
//! 4. Canonical re-verification against the exact expected path, which also
//!    enforces byte-exact component casing on case-insensitive filesystems.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// `FILE_ATTRIBUTE_REPARSE_POINT`.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
/// `FILE_FLAG_OPEN_REPARSE_POINT`.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Reserved Windows device names, compared case-insensitively against the
/// portion of a component before its first dot.
const RESERVED_DEVICE_NAMES: [&str; 26] = [
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM0", "COM1", "COM2", "COM3", "COM4",
    "COM5", "COM6", "COM7", "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6",
    "LPT7", "LPT8", "LPT9",
];

/// Superscript digits Windows also maps onto `COM`/`LPT` devices.
const SUPERSCRIPT_DEVICE_DIGITS: [char; 3] = ['\u{b9}', '\u{b2}', '\u{b3}'];

/// Characters that are invalid in a Windows file name or enable globbing.
const FORBIDDEN_COMPONENT_CHARACTERS: [char; 7] = ['<', '>', '"', '|', '?', '*', '\0'];

/// Declared resource bounds enforced by the sandbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxLimits {
    /// Inclusive maximum number of path components below the root.
    pub max_path_components: usize,
    /// Inclusive maximum UTF-8 byte length of a single component.
    pub max_component_bytes: usize,
    /// Inclusive maximum UTF-8 byte length of the whole relative path.
    pub max_relative_bytes: usize,
    /// Inclusive maximum size of any file read or written.
    pub max_file_bytes: u64,
    /// Inclusive maximum number of entries enumerated in one directory.
    pub max_directory_entries: usize,
    /// Inclusive maximum number of files visited by a recursive walk.
    pub max_walked_files: usize,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            max_path_components: 32,
            max_component_bytes: 255,
            max_relative_bytes: 1024,
            max_file_bytes: 8 * 1024 * 1024,
            max_directory_entries: 4096,
            max_walked_files: 20_000,
        }
    }
}

/// A validated, normalized workspace-relative path.
///
/// Components are guaranteed to be non-empty, free of traversal, separators,
/// reserved device names, alternate data stream markers, and trailing dots or
/// spaces. The normalized form always uses `/` separators.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RelativePath {
    components: Vec<String>,
    normalized: String,
}

impl RelativePath {
    /// Returns the normalized `/`-separated form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    /// Returns the validated components.
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// Returns the final component.
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.components
            .last()
            .map_or("", |component| component.as_str())
    }

    /// Returns the parent path, or `None` when this path is a root child.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.components.len() <= 1 {
            return None;
        }
        let components = self.components[..self.components.len() - 1].to_vec();
        Some(Self {
            normalized: components.join("/"),
            components,
        })
    }
}

impl Display for RelativePath {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.normalized)
    }
}

/// A path proven to live inside the sandbox root at resolution time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedPath {
    relative: RelativePath,
    absolute: PathBuf,
}

impl ResolvedPath {
    /// Returns the validated workspace-relative path.
    #[must_use]
    pub const fn relative(&self) -> &RelativePath {
        &self.relative
    }

    /// Returns the canonical absolute path.
    #[must_use]
    pub fn absolute(&self) -> &Path {
        &self.absolute
    }

    /// Returns the absolute path in a form accepted by process APIs.
    ///
    /// Windows canonical paths carry the `\\?\` verbatim prefix, which several
    /// process and console APIs reject; this strips it for drive paths only.
    #[must_use]
    pub fn native(&self) -> PathBuf {
        strip_verbatim_prefix(&self.absolute)
    }
}

/// Kind of a directory entry reported by a listing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link, junction, or other reparse point, never followed.
    Link,
    /// Anything else, such as a device or socket.
    Other,
}

impl EntryKind {
    /// Returns the stable entry-kind identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Link => "link",
            Self::Other => "other",
        }
    }
}

/// One enumerated directory entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    /// Workspace-relative path of the entry.
    pub path: RelativePath,
    /// Entry kind, with links reported rather than followed.
    pub kind: EntryKind,
    /// Size in bytes for regular files.
    pub size_bytes: Option<u64>,
}

/// How an existing file is treated by a write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteMode {
    /// Fail if the path already exists.
    CreateNew,
    /// Replace the whole content of an existing file, or create it.
    Overwrite,
}

/// Confinement root for every filesystem tool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sandbox {
    root: PathBuf,
    limits: SandboxLimits,
}

impl Sandbox {
    /// Canonicalizes and adopts an existing directory as the workspace root.
    pub fn new(root: &Path, limits: SandboxLimits) -> Result<Self, SandboxError> {
        let canonical = std::fs::canonicalize(root).map_err(map_io)?;
        let metadata = std::fs::symlink_metadata(&canonical).map_err(map_io)?;
        if !metadata.is_dir() {
            return Err(SandboxError::RootNotADirectory);
        }
        Ok(Self {
            root: canonical,
            limits,
        })
    }

    /// Returns the canonical workspace root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the enforced limits.
    #[must_use]
    pub const fn limits(&self) -> SandboxLimits {
        self.limits
    }

    /// Validates caller-supplied text into a normalized relative path.
    pub fn relative(&self, input: &str) -> Result<RelativePath, SandboxError> {
        parse_relative(input, self.limits)
    }

    /// Resolves an existing directory inside the root.
    pub fn resolve_directory(&self, path: &RelativePath) -> Result<ResolvedPath, SandboxError> {
        let resolved = self.resolve_existing(path)?;
        let metadata = std::fs::symlink_metadata(&resolved.absolute).map_err(map_io)?;
        if !metadata.is_dir() {
            return Err(SandboxError::NotADirectory);
        }
        Ok(resolved)
    }

    /// Resolves an existing regular file inside the root.
    pub fn resolve_file(&self, path: &RelativePath) -> Result<ResolvedPath, SandboxError> {
        let resolved = self.resolve_existing(path)?;
        let metadata = std::fs::symlink_metadata(&resolved.absolute).map_err(map_io)?;
        if !metadata.is_file() {
            return Err(SandboxError::NotAFile);
        }
        Ok(resolved)
    }

    /// Resolves the workspace root itself.
    #[must_use]
    pub fn resolve_root(&self) -> ResolvedPath {
        ResolvedPath {
            relative: RelativePath {
                components: Vec::new(),
                normalized: String::new(),
            },
            absolute: self.root.clone(),
        }
    }

    /// Resolves a path that a write is allowed to create.
    ///
    /// The parent must already exist inside the root, and the leaf must not
    /// collide case-insensitively with a different existing name.
    pub fn resolve_for_write(
        &self,
        path: &RelativePath,
        mode: WriteMode,
    ) -> Result<ResolvedPath, SandboxError> {
        let Some(leaf) = path.components.last() else {
            return Err(SandboxError::EmptyPath);
        };
        let parent = match path.parent() {
            Some(parent) => self.resolve_directory(&parent)?,
            None => self.resolve_root(),
        };
        let absolute = parent.absolute.join(leaf);
        // Scanned before the existence check so that a case-insensitive
        // filesystem cannot silently redirect the write onto a differently
        // cased file, and so the refusal is identical on every platform.
        self.reject_case_collision(&parent.absolute, leaf)?;
        match std::fs::symlink_metadata(&absolute) {
            Ok(metadata) => {
                if is_link_like(&metadata) {
                    return Err(SandboxError::SymlinkForbidden);
                }
                if metadata.is_dir() {
                    return Err(SandboxError::NotAFile);
                }
                if mode == WriteMode::CreateNew {
                    return Err(SandboxError::AlreadyExists);
                }
                self.verify_canonical(&absolute, &path.components)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_io(error)),
        }
        Ok(ResolvedPath {
            relative: path.clone(),
            absolute,
        })
    }

    /// Reads an existing file, refusing links and oversized content.
    pub fn read_file(&self, path: &RelativePath) -> Result<Vec<u8>, SandboxError> {
        let resolved = self.resolve_file(path)?;
        let mut file = self.open_no_follow(&resolved)?;
        let length = file.metadata().map_err(map_io)?.len();
        if length > self.limits.max_file_bytes {
            return Err(SandboxError::FileTooLarge);
        }
        let capacity = usize::try_from(length).unwrap_or(0);
        let mut buffer = Vec::with_capacity(capacity);
        let limit = self.limits.max_file_bytes.saturating_add(1);
        let read = Read::by_ref(&mut file)
            .take(limit)
            .read_to_end(&mut buffer)
            .map_err(map_io)?;
        if u64::try_from(read).unwrap_or(u64::MAX) > self.limits.max_file_bytes {
            return Err(SandboxError::FileTooLarge);
        }
        Ok(buffer)
    }

    /// Writes a whole file, refusing links, escapes, and oversized content.
    pub fn write_file(
        &self,
        path: &RelativePath,
        content: &[u8],
        mode: WriteMode,
    ) -> Result<ResolvedPath, SandboxError> {
        if u64::try_from(content.len()).unwrap_or(u64::MAX) > self.limits.max_file_bytes {
            return Err(SandboxError::FileTooLarge);
        }
        let resolved = self.resolve_for_write(path, mode)?;
        let mut options = OpenOptions::new();
        options.write(true).truncate(true);
        match mode {
            WriteMode::CreateNew => {
                options.create_new(true);
            }
            WriteMode::Overwrite => {
                options.create(true);
            }
        }
        apply_no_follow(&mut options);
        let mut file = options.open(&resolved.absolute).map_err(map_io)?;
        verify_handle_is_not_reparse_point(&file)?;
        self.verify_canonical(&resolved.absolute, &resolved.relative.components)?;
        file.write_all(content).map_err(map_io)?;
        file.flush().map_err(map_io)?;
        Ok(resolved)
    }

    /// Enumerates one directory without following links.
    pub fn read_directory(&self, path: &RelativePath) -> Result<Vec<DirectoryEntry>, SandboxError> {
        let resolved = if path.components.is_empty() {
            self.resolve_root()
        } else {
            self.resolve_directory(path)?
        };
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&resolved.absolute).map_err(map_io)? {
            let entry = entry.map_err(map_io)?;
            if entries.len() >= self.limits.max_directory_entries {
                return Err(SandboxError::DirectoryTooLarge);
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(child) = self.child_of(path, &name) else {
                continue;
            };
            let metadata = entry.metadata().map_err(map_io)?;
            let kind = classify(&metadata);
            entries.push(DirectoryEntry {
                path: child,
                kind,
                size_bytes: (kind == EntryKind::File).then_some(metadata.len()),
            });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(entries)
    }

    /// Walks the tree below `path`, returning files only and never crossing a
    /// link, junction, or other reparse point.
    pub fn walk_files(&self, path: &RelativePath) -> Result<Vec<RelativePath>, SandboxError> {
        let mut queue = vec![path.clone()];
        let mut files = Vec::new();
        let mut visited = 0_usize;
        while let Some(current) = queue.pop() {
            for entry in self.read_directory(&current)? {
                visited += 1;
                if visited > self.limits.max_walked_files {
                    return Err(SandboxError::DirectoryTooLarge);
                }
                match entry.kind {
                    EntryKind::File => files.push(entry.path),
                    EntryKind::Directory => queue.push(entry.path),
                    EntryKind::Link | EntryKind::Other => {}
                }
            }
        }
        files.sort();
        Ok(files)
    }

    /// Opens an already-resolved file without following a final-component link.
    pub fn open_no_follow(&self, resolved: &ResolvedPath) -> Result<File, SandboxError> {
        let mut options = OpenOptions::new();
        options.read(true);
        apply_no_follow(&mut options);
        let file = options.open(&resolved.absolute).map_err(map_io)?;
        verify_handle_is_not_reparse_point(&file)?;
        self.verify_canonical(&resolved.absolute, &resolved.relative.components)?;
        Ok(file)
    }

    fn child_of(&self, parent: &RelativePath, name: &str) -> Result<RelativePath, SandboxError> {
        let component = validate_component(name, 0, self.limits)?;
        let mut components = parent.components.clone();
        components.push(component);
        if components.len() > self.limits.max_path_components {
            return Err(SandboxError::TooManyComponents);
        }
        let normalized = components.join("/");
        if normalized.len() > self.limits.max_relative_bytes {
            return Err(SandboxError::PathTooLong);
        }
        Ok(RelativePath {
            components,
            normalized,
        })
    }

    fn resolve_existing(&self, path: &RelativePath) -> Result<ResolvedPath, SandboxError> {
        if path.components.is_empty() {
            return Ok(self.resolve_root());
        }
        let mut absolute = self.root.clone();
        let last = path.components.len() - 1;
        for (index, component) in path.components.iter().enumerate() {
            absolute.push(component);
            let metadata = std::fs::symlink_metadata(&absolute).map_err(map_io)?;
            if is_link_like(&metadata) {
                return Err(SandboxError::SymlinkForbidden);
            }
            if index < last && !metadata.is_dir() {
                return Err(SandboxError::NotADirectory);
            }
        }
        self.verify_canonical(&absolute, &path.components)?;
        Ok(ResolvedPath {
            relative: path.clone(),
            absolute,
        })
    }

    fn verify_canonical(&self, absolute: &Path, components: &[String]) -> Result<(), SandboxError> {
        let canonical = std::fs::canonicalize(absolute).map_err(map_io)?;
        let mut expected = self.root.clone();
        for component in components {
            expected.push(component);
        }
        if canonical == expected {
            return Ok(());
        }
        if canonical.starts_with(&self.root) {
            Err(SandboxError::CaseMismatch)
        } else {
            Err(SandboxError::EscapesRoot)
        }
    }

    fn reject_case_collision(&self, parent: &Path, leaf: &str) -> Result<(), SandboxError> {
        let mut scanned = 0_usize;
        for entry in std::fs::read_dir(parent).map_err(map_io)? {
            let entry = entry.map_err(map_io)?;
            scanned += 1;
            if scanned > self.limits.max_directory_entries {
                return Err(SandboxError::DirectoryTooLarge);
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name != leaf && name.eq_ignore_ascii_case(leaf) {
                return Err(SandboxError::CaseCollision);
            }
        }
        Ok(())
    }
}

fn classify(metadata: &std::fs::Metadata) -> EntryKind {
    if is_link_like(metadata) {
        EntryKind::Link
    } else if metadata.is_dir() {
        EntryKind::Directory
    } else if metadata.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    }
}

/// Returns whether metadata describes a symbolic link, junction, or any other
/// reparse point that can redirect the namespace.
#[cfg(windows)]
fn is_link_like(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Returns whether metadata describes a symbolic link.
#[cfg(not(windows))]
fn is_link_like(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn apply_no_follow(options: &mut OpenOptions) {
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(unix)]
fn apply_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(any(windows, unix)))]
fn apply_no_follow(_options: &mut OpenOptions) {}

#[cfg(windows)]
fn verify_handle_is_not_reparse_point(file: &File) -> Result<(), SandboxError> {
    let metadata = file.metadata().map_err(map_io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        Ok(())
    } else {
        Err(SandboxError::SymlinkForbidden)
    }
}

#[cfg(not(windows))]
fn verify_handle_is_not_reparse_point(file: &File) -> Result<(), SandboxError> {
    let metadata = file.metadata().map_err(map_io)?;
    if metadata.file_type().is_symlink() {
        Err(SandboxError::SymlinkForbidden)
    } else {
        Ok(())
    }
}

/// Strips the Windows `\\?\` verbatim prefix from a drive path.
fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let mut components = path.components();
    match components.next() {
        Some(Component::Prefix(prefix)) => {
            let text = prefix.as_os_str().to_string_lossy();
            match text.strip_prefix(r"\\?\") {
                Some(drive) if drive.len() == 2 && drive.ends_with(':') => {
                    let mut rebuilt = PathBuf::from(format!("{drive}\\"));
                    for component in components {
                        if !matches!(component, Component::RootDir) {
                            rebuilt.push(component);
                        }
                    }
                    rebuilt
                }
                _ => path.to_path_buf(),
            }
        }
        _ => path.to_path_buf(),
    }
}

fn parse_relative(input: &str, limits: SandboxLimits) -> Result<RelativePath, SandboxError> {
    if input.is_empty() {
        return Err(SandboxError::EmptyPath);
    }
    if input.len() > limits.max_relative_bytes {
        return Err(SandboxError::PathTooLong);
    }
    if input.chars().any(char::is_control) {
        return Err(SandboxError::ControlCharacter);
    }
    if input.starts_with('/') || input.starts_with('\\') {
        return Err(SandboxError::AbsolutePathForbidden);
    }
    if input.starts_with('~') {
        return Err(SandboxError::AbsolutePathForbidden);
    }
    let raw: Vec<&str> = input.split(['/', '\\']).collect();
    if raw.len() > limits.max_path_components {
        return Err(SandboxError::TooManyComponents);
    }
    let mut components = Vec::with_capacity(raw.len());
    for (index, component) in raw.iter().enumerate() {
        components.push(validate_component(component, index, limits)?);
    }
    let normalized = components.join("/");
    if normalized.len() > limits.max_relative_bytes {
        return Err(SandboxError::PathTooLong);
    }
    Ok(RelativePath {
        components,
        normalized,
    })
}

fn validate_component(
    component: &str,
    index: usize,
    limits: SandboxLimits,
) -> Result<String, SandboxError> {
    if component.is_empty() {
        return Err(SandboxError::EmptyComponent);
    }
    if component.len() > limits.max_component_bytes {
        return Err(SandboxError::ComponentTooLong);
    }
    if component.chars().any(char::is_control) {
        return Err(SandboxError::ControlCharacter);
    }
    if component.chars().all(|character| character == '.') {
        return Err(if component == "." {
            SandboxError::CurrentDirectoryComponentForbidden
        } else {
            SandboxError::ParentTraversalForbidden
        });
    }
    if index == 0 && is_drive_designator(component) {
        return Err(SandboxError::AbsolutePathForbidden);
    }
    if component.contains(':') {
        return Err(SandboxError::AlternateDataStreamForbidden);
    }
    if component
        .chars()
        .any(|character| FORBIDDEN_COMPONENT_CHARACTERS.contains(&character))
    {
        return Err(SandboxError::InvalidCharacter);
    }
    if component.starts_with(' ')
        || component.ends_with(' ')
        || component.ends_with('.')
        || component.starts_with('\u{feff}')
    {
        return Err(SandboxError::TrailingDotOrSpace);
    }
    if is_reserved_device_name(component) {
        return Err(SandboxError::ReservedDeviceName);
    }
    Ok(component.to_owned())
}

fn is_drive_designator(component: &str) -> bool {
    let mut characters = component.chars();
    matches!(
        (characters.next(), characters.next()),
        (Some(letter), Some(':')) if letter.is_ascii_alphabetic()
    )
}

fn is_reserved_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    let upper = stem.to_ascii_uppercase();
    if RESERVED_DEVICE_NAMES.contains(&upper.as_str()) {
        return true;
    }
    let mut characters = upper.chars();
    let head: String = characters.by_ref().take(3).collect();
    matches!(head.as_str(), "COM" | "LPT")
        && matches!(
            (characters.next(), characters.next()),
            (Some(digit), None) if SUPERSCRIPT_DEVICE_DIGITS.contains(&digit)
        )
}

fn map_io(error: io::Error) -> SandboxError {
    // `O_NOFOLLOW` reports a final-component symlink as `ELOOP`, which has no
    // stable `ErrorKind` yet, so the raw code is matched directly.
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ELOOP) {
        return SandboxError::SymlinkForbidden;
    }
    match error.kind() {
        io::ErrorKind::NotFound => SandboxError::NotFound,
        io::ErrorKind::AlreadyExists => SandboxError::AlreadyExists,
        io::ErrorKind::PermissionDenied => SandboxError::PermissionDenied,
        kind => SandboxError::Io(kind),
    }
}

/// A path the sandbox refused to resolve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxError {
    /// The path was empty.
    EmptyPath,
    /// The relative path exceeded its byte bound.
    PathTooLong,
    /// A component exceeded its byte bound.
    ComponentTooLong,
    /// The path had more components than the bound allows.
    TooManyComponents,
    /// Absolute, UNC, drive-relative, and home-relative paths are forbidden.
    AbsolutePathForbidden,
    /// A `..` component was supplied.
    ParentTraversalForbidden,
    /// A `.` component was supplied.
    CurrentDirectoryComponentForbidden,
    /// A repeated separator produced an empty component.
    EmptyComponent,
    /// A control character was present.
    ControlCharacter,
    /// A character that is invalid or enables globbing was present.
    InvalidCharacter,
    /// A `:` marked a drive or NTFS alternate data stream.
    AlternateDataStreamForbidden,
    /// A reserved Windows device name was used.
    ReservedDeviceName,
    /// A component started or ended with a space, or ended with a dot.
    TrailingDotOrSpace,
    /// A symbolic link, junction, or reparse point was on the path.
    SymlinkForbidden,
    /// The resolved path left the workspace root.
    EscapesRoot,
    /// The requested casing does not match the on-disk casing.
    CaseMismatch,
    /// A different name already exists that differs only by case.
    CaseCollision,
    /// The path does not exist.
    NotFound,
    /// A component that had to be a directory was not one.
    NotADirectory,
    /// A path that had to be a regular file was not one.
    NotAFile,
    /// The path already exists and the mode forbids replacing it.
    AlreadyExists,
    /// The file exceeded the declared size bound.
    FileTooLarge,
    /// The file is not valid UTF-8 text.
    BinaryContent,
    /// The directory or walk exceeded the declared entry bound.
    DirectoryTooLarge,
    /// The operating system refused access.
    PermissionDenied,
    /// The configured root is not a directory.
    RootNotADirectory,
    /// Any other operating-system failure.
    Io(io::ErrorKind),
}

impl Display for SandboxError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyPath => "path is empty",
            Self::PathTooLong => "path is too long",
            Self::ComponentTooLong => "path component is too long",
            Self::TooManyComponents => "path has too many components",
            Self::AbsolutePathForbidden => "absolute and drive-relative paths are forbidden",
            Self::ParentTraversalForbidden => "parent traversal is forbidden",
            Self::CurrentDirectoryComponentForbidden => {
                "current-directory components are forbidden"
            }
            Self::EmptyComponent => "empty path component",
            Self::ControlCharacter => "path contains a control character",
            Self::InvalidCharacter => "path contains a forbidden character",
            Self::AlternateDataStreamForbidden => "alternate data streams are forbidden",
            Self::ReservedDeviceName => "reserved device names are forbidden",
            Self::TrailingDotOrSpace => {
                "leading or trailing spaces and trailing dots are forbidden"
            }
            Self::SymlinkForbidden => "links, junctions, and reparse points are forbidden",
            Self::EscapesRoot => "path escapes the workspace root",
            Self::CaseMismatch => "path casing does not match the on-disk name",
            Self::CaseCollision => "a name differing only by case already exists",
            Self::NotFound => "path does not exist",
            Self::NotADirectory => "path component is not a directory",
            Self::NotAFile => "path is not a regular file",
            Self::AlreadyExists => "path already exists",
            Self::FileTooLarge => "file exceeds the configured size limit",
            Self::BinaryContent => "file is not valid UTF-8 text",
            Self::DirectoryTooLarge => "directory exceeds the configured entry limit",
            Self::PermissionDenied => "the operating system denied access",
            Self::RootNotADirectory => "the workspace root is not a directory",
            Self::Io(_) => "filesystem operation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for SandboxError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> SandboxLimits {
        SandboxLimits::default()
    }

    fn parse(input: &str) -> Result<RelativePath, SandboxError> {
        parse_relative(input, limits())
    }

    #[test]
    fn accepts_plain_relative_paths_and_normalizes_separators() {
        let path = parse("src/tools/mod.rs").expect("plain relative path");
        assert_eq!(path.as_str(), "src/tools/mod.rs");
        assert_eq!(path.components(), ["src", "tools", "mod.rs"]);
        assert_eq!(path.file_name(), "mod.rs");
        assert_eq!(
            path.parent().expect("parent").as_str(),
            "src/tools",
            "parents are derived from validated components"
        );

        let windows = parse(r"src\tools\mod.rs").expect("backslash separators");
        assert_eq!(windows.as_str(), "src/tools/mod.rs");
        assert_eq!(windows, path);
    }

    #[test]
    fn rejects_every_traversal_and_absolute_form() {
        let cases: [(&str, SandboxError); 16] = [
            ("", SandboxError::EmptyPath),
            ("..", SandboxError::ParentTraversalForbidden),
            ("../etc/passwd", SandboxError::ParentTraversalForbidden),
            ("src/../../etc", SandboxError::ParentTraversalForbidden),
            (r"src\..\..\etc", SandboxError::ParentTraversalForbidden),
            ("...", SandboxError::ParentTraversalForbidden),
            (".", SandboxError::CurrentDirectoryComponentForbidden),
            ("./src", SandboxError::CurrentDirectoryComponentForbidden),
            ("/etc/passwd", SandboxError::AbsolutePathForbidden),
            (r"\Windows\System32", SandboxError::AbsolutePathForbidden),
            (r"\\server\share\file", SandboxError::AbsolutePathForbidden),
            (r"\\?\C:\Windows", SandboxError::AbsolutePathForbidden),
            (r"\\.\PhysicalDrive0", SandboxError::AbsolutePathForbidden),
            ("~/.ssh/id_ed25519", SandboxError::AbsolutePathForbidden),
            (r"C:\Windows\System32", SandboxError::AbsolutePathForbidden),
            ("C:relative", SandboxError::AbsolutePathForbidden),
        ];
        for (input, expected) in cases {
            assert_eq!(parse(input), Err(expected), "input {input:?}");
        }
    }

    #[test]
    fn rejects_alternate_data_streams_and_device_names() {
        let cases: [(&str, SandboxError); 13] = [
            (
                "notes.txt:hidden",
                SandboxError::AlternateDataStreamForbidden,
            ),
            (
                "notes.txt:$DATA",
                SandboxError::AlternateDataStreamForbidden,
            ),
            (
                "dir/file:stream:$DATA",
                SandboxError::AlternateDataStreamForbidden,
            ),
            ("CON", SandboxError::ReservedDeviceName),
            ("con", SandboxError::ReservedDeviceName),
            ("CoN.txt", SandboxError::ReservedDeviceName),
            ("NUL", SandboxError::ReservedDeviceName),
            ("aux.log", SandboxError::ReservedDeviceName),
            ("COM1", SandboxError::ReservedDeviceName),
            ("lpt9.txt", SandboxError::ReservedDeviceName),
            ("CONIN$", SandboxError::ReservedDeviceName),
            ("com\u{b9}", SandboxError::ReservedDeviceName),
            ("logs/PRN.txt", SandboxError::ReservedDeviceName),
        ];
        for (input, expected) in cases {
            assert_eq!(parse(input), Err(expected), "input {input:?}");
        }
        assert!(parse("console.txt").is_ok());
        assert!(parse("com10.txt").is_ok());
        assert!(parse("nulls.json").is_ok());
    }

    #[test]
    fn rejects_windows_name_mangling_and_glob_characters() {
        let cases: [(&str, SandboxError); 10] = [
            ("notes.txt.", SandboxError::TrailingDotOrSpace),
            ("notes.txt ", SandboxError::TrailingDotOrSpace),
            (" notes.txt", SandboxError::TrailingDotOrSpace),
            ("dir /file.txt", SandboxError::TrailingDotOrSpace),
            ("a//b", SandboxError::EmptyComponent),
            (r"a\\b", SandboxError::EmptyComponent),
            ("a\u{0}b", SandboxError::ControlCharacter),
            ("a\nb", SandboxError::ControlCharacter),
            ("*.rs", SandboxError::InvalidCharacter),
            ("file?.txt", SandboxError::InvalidCharacter),
        ];
        for (input, expected) in cases {
            assert_eq!(parse(input), Err(expected), "input {input:?}");
        }
    }

    #[test]
    fn enforces_length_and_component_bounds() {
        let bounds = SandboxLimits {
            max_path_components: 3,
            max_component_bytes: 8,
            max_relative_bytes: 20,
            ..limits()
        };
        assert_eq!(
            parse_relative("a/b/c/d", bounds),
            Err(SandboxError::TooManyComponents)
        );
        assert_eq!(
            parse_relative("aaaaaaaaa", bounds),
            Err(SandboxError::ComponentTooLong)
        );
        assert_eq!(
            parse_relative("aaaaaaaa/bbbbbbbb/cccc", bounds),
            Err(SandboxError::PathTooLong)
        );
        assert!(parse_relative("aaaaaaaa/bbbbbbbb", bounds).is_ok());
    }

    #[test]
    fn strips_only_windows_drive_verbatim_prefixes() {
        #[cfg(windows)]
        {
            assert_eq!(
                strip_verbatim_prefix(Path::new(r"\\?\C:\work\a.txt")),
                PathBuf::from(r"C:\work\a.txt")
            );
            assert_eq!(
                strip_verbatim_prefix(Path::new(r"\\?\UNC\server\share\a.txt")),
                PathBuf::from(r"\\?\UNC\server\share\a.txt"),
                "UNC verbatim paths keep their prefix"
            );
        }
        assert_eq!(
            strip_verbatim_prefix(Path::new("relative/a.txt")),
            PathBuf::from("relative/a.txt")
        );
    }
}
