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
/// `FILE_FLAG_BACKUP_SEMANTICS`, required to open a directory handle.
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// `FILE_SHARE_READ`.
#[cfg(windows)]
const FILE_SHARE_READ: u32 = 0x0000_0001;
/// `FILE_SHARE_WRITE`.
#[cfg(windows)]
const FILE_SHARE_WRITE: u32 = 0x0000_0002;

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
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::NotFound`] when `root` does not exist,
    /// [`SandboxError::PermissionDenied`] when the operating system refuses to
    /// canonicalize it, and [`SandboxError::RootNotADirectory`] when the
    /// canonical root is a file or any other non-directory object.
    pub fn new(root: &Path, limits: SandboxLimits) -> Result<Self, SandboxError> {
        let canonical = std::fs::canonicalize(root).map_err(|error| map_io(&error))?;
        let metadata = std::fs::symlink_metadata(&canonical).map_err(|error| map_io(&error))?;
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
    ///
    /// This is lexical validation only; nothing is touched on disk.
    ///
    /// # Errors
    ///
    /// Names the first rule the input breaks:
    /// [`SandboxError::EmptyPath`] for an empty string,
    /// [`SandboxError::PathTooLong`] or [`SandboxError::ComponentTooLong`] past
    /// the declared byte bounds, [`SandboxError::TooManyComponents`] past
    /// [`SandboxLimits::max_path_components`],
    /// [`SandboxError::AbsolutePathForbidden`] for absolute, UNC,
    /// drive-qualified and `~`-relative forms,
    /// [`SandboxError::ParentTraversalForbidden`] for a `..` component,
    /// [`SandboxError::CurrentDirectoryComponentForbidden`] for a `.`
    /// component, [`SandboxError::EmptyComponent`] for a repeated separator,
    /// [`SandboxError::ControlCharacter`] or [`SandboxError::InvalidCharacter`]
    /// for control and wildcard characters,
    /// [`SandboxError::AlternateDataStreamForbidden`] for a `:`,
    /// [`SandboxError::ReservedDeviceName`] for a Windows device name, and
    /// [`SandboxError::TrailingDotOrSpace`] for a component that starts or ends
    /// with a space or ends with a dot.
    pub fn relative(&self, input: &str) -> Result<RelativePath, SandboxError> {
        parse_relative(input, self.limits)
    }

    /// Resolves an existing directory inside the root.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::NotFound`] when a component does not exist,
    /// [`SandboxError::SymlinkForbidden`] when any component including the
    /// final one is a link, junction or other reparse point,
    /// [`SandboxError::EscapesRoot`] when the canonical path leaves the
    /// workspace root, [`SandboxError::CaseMismatch`] when it stays inside the
    /// root but under different casing, and [`SandboxError::NotADirectory`]
    /// when the path exists but is not a directory.
    pub fn resolve_directory(&self, path: &RelativePath) -> Result<ResolvedPath, SandboxError> {
        let resolved = self.resolve_existing(path)?;
        let metadata =
            std::fs::symlink_metadata(&resolved.absolute).map_err(|error| map_io(&error))?;
        if !metadata.is_dir() {
            return Err(SandboxError::NotADirectory);
        }
        Ok(resolved)
    }

    /// Resolves an existing regular file inside the root.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::NotFound`] when a component does not exist,
    /// [`SandboxError::SymlinkForbidden`] when any component is a link,
    /// junction or other reparse point, [`SandboxError::NotADirectory`] when an
    /// intermediate component is not a directory, [`SandboxError::EscapesRoot`]
    /// or [`SandboxError::CaseMismatch`] when the canonical path is not exactly
    /// the requested path below the root, and [`SandboxError::NotAFile`] when
    /// the path exists but is not a regular file.
    pub fn resolve_file(&self, path: &RelativePath) -> Result<ResolvedPath, SandboxError> {
        let resolved = self.resolve_existing(path)?;
        let metadata =
            std::fs::symlink_metadata(&resolved.absolute).map_err(|error| map_io(&error))?;
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
    ///
    /// This is validation only. The result is a *name*, and a name can be
    /// invalidated the instant this returns, so nothing may act on it without
    /// going back through [`Sandbox::write_file`], which re-establishes the
    /// pinned ancestor chain before it opens anything.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::EmptyPath`] when `path` names the root itself,
    /// [`SandboxError::NotFound`] when the parent directory does not exist,
    /// [`SandboxError::SymlinkForbidden`] when the parent chain or an existing
    /// leaf is a link, junction or other reparse point,
    /// [`SandboxError::CaseCollision`] when a differently-cased name already
    /// exists in the parent, [`SandboxError::AlreadyExists`] when the leaf
    /// exists and `mode` is [`WriteMode::CreateNew`],
    /// [`SandboxError::NotAFile`] when the leaf exists but is not a regular
    /// file, and
    /// [`SandboxError::EscapesRoot`] or [`SandboxError::CaseMismatch`] when an
    /// existing leaf does not canonicalize back onto the requested path.
    pub fn resolve_for_write(
        &self,
        path: &RelativePath,
        mode: WriteMode,
    ) -> Result<ResolvedPath, SandboxError> {
        let prepared = self.prepare_write(path, mode)?;
        Ok(ResolvedPath {
            relative: path.clone(),
            absolute: prepared.absolute,
        })
    }

    /// Validates a write target while holding every ancestor directory open.
    ///
    /// The returned pin must stay alive until the target file has been opened
    /// and re-verified: it is what stops an ancestor being swapped for a link
    /// after the checks below have passed.
    fn prepare_write(
        &self,
        path: &RelativePath,
        mode: WriteMode,
    ) -> Result<PreparedWrite, SandboxError> {
        let Some(leaf) = path.components.last() else {
            return Err(SandboxError::EmptyPath);
        };
        let parent_components = &path.components[..path.components.len() - 1];
        let pin = self.pin_ancestors(parent_components)?;
        let absolute = pin.path().join(leaf);
        // Scanned before the existence check so that a case-insensitive
        // filesystem cannot silently redirect the write onto a differently
        // cased file, and so the refusal is identical on every platform.
        self.reject_case_collision(&pin, leaf)?;
        match std::fs::symlink_metadata(&absolute) {
            Ok(metadata) => {
                if is_link_like(&metadata) {
                    return Err(SandboxError::SymlinkForbidden);
                }
                if !metadata.is_file() {
                    return Err(SandboxError::NotAFile);
                }
                if mode == WriteMode::CreateNew {
                    return Err(SandboxError::AlreadyExists);
                }
                self.verify_canonical(&absolute, &path.components)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_io(&error)),
        }
        Ok(PreparedWrite { pin, absolute })
    }

    /// Reads an existing file, refusing links and oversized content.
    ///
    /// This is the hottest path in the crate and it is syscall-bound, not
    /// allocation-bound. One small-file read costs 72–78 µs, of which roughly
    /// 87% is spent in the kernel: about three `canonicalize` calls at
    /// 9–10 µs each, four opens, six `fstat` and ten `lstat`. Every one of
    /// them is a check this design mandates, and two tempting removals were
    /// measured and rejected rather than taken:
    ///
    /// * Dropping the [`Sandbox::resolve_file`] pre-check below would save
    ///   14.0 µs, about 19% of every read, because
    ///   [`Sandbox::open_no_follow`] re-derives every layer of it anyway. It
    ///   stays: it is a re-verification, and it is also the only place the
    ///   leaf is confirmed to be a regular file *before* `open`, without
    ///   which a FIFO left in the workspace would block the open forever.
    /// * Collapsing the two `canonicalize` calls on the open path — one in
    ///   `Sandbox::pin_ancestors` before the open, one on the leaf after —
    ///   would save about 10 µs. They stay: they answer the same question at
    ///   two different moments, which is the entire point of checking after
    ///   the handle exists.
    ///
    /// Caching a resolution, a pin, or the root handle across calls would beat
    /// all of this by a wide margin and is rejected outright: a cache is a
    /// check that is not performed, and the check-then-use window this type
    /// closes would reopen exactly as wide as the cache is long-lived.
    ///
    /// # Errors
    ///
    /// Returns everything [`Sandbox::resolve_file`] and
    /// [`Sandbox::open_no_follow`] can return, plus
    /// [`SandboxError::FileTooLarge`] when the file holds more than
    /// [`SandboxLimits::max_file_bytes`] bytes, either at the time it was
    /// measured or while it was being read.
    pub fn read_file(&self, path: &RelativePath) -> Result<Vec<u8>, SandboxError> {
        let resolved = self.resolve_file(path)?;
        let mut file = self.open_no_follow(&resolved)?;
        let length = file.metadata().map_err(|error| map_io(&error))?.len();
        if length > self.limits.max_file_bytes {
            return Err(SandboxError::FileTooLarge);
        }
        let capacity = usize::try_from(length).unwrap_or(0);
        let mut buffer = Vec::with_capacity(capacity);
        let limit = self.limits.max_file_bytes.saturating_add(1);
        let read = Read::by_ref(&mut file)
            .take(limit)
            .read_to_end(&mut buffer)
            .map_err(|error| map_io(&error))?;
        if u64::try_from(read).unwrap_or(u64::MAX) > self.limits.max_file_bytes {
            return Err(SandboxError::FileTooLarge);
        }
        Ok(buffer)
    }

    /// Writes a whole file, refusing links, escapes, and oversized content.
    ///
    /// Ordering is the security property. The target is opened with no
    /// destructive flag, then the opened handle itself is re-verified against
    /// the validated path and the pinned ancestor chain, and only then is the
    /// file truncated. A process that wins a race to swap a directory therefore
    /// never gets a file truncated or written.
    ///
    /// Unix opens the leaf relative to the pinned parent handle, so renaming an
    /// ancestor cannot redirect creation. If later verification fails after a
    /// create, the empty file is retained: attempting pathname cleanup in a
    /// mutable directory could delete a replacement planted after verification.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::FileTooLarge`] when `content` is longer than
    /// [`SandboxLimits::max_file_bytes`], everything
    /// [`Sandbox::resolve_for_write`] can return, and
    /// [`SandboxError::RaceDetected`] when the opened handle turns out not to
    /// be the file the validated path names. On every one of these paths the
    /// target is left untruncated and unwritten.
    pub fn write_file(
        &self,
        path: &RelativePath,
        content: &[u8],
        mode: WriteMode,
    ) -> Result<ResolvedPath, SandboxError> {
        if u64::try_from(content.len()).unwrap_or(u64::MAX) > self.limits.max_file_bytes {
            return Err(SandboxError::FileTooLarge);
        }
        let prepared = self.prepare_write(path, mode)?;
        let mut file = open_write_no_follow(
            prepared.pin.handle()?,
            &prepared.absolute,
            path.file_name(),
            mode,
        )?;
        let verified = verify_handle_is_not_reparse_point(&file)
            .and_then(|()| verify_handle_is_regular(&file))
            .and_then(|()| self.verify_canonical(&prepared.absolute, &path.components))
            .and_then(|()| prepared.pin.verify())
            .and_then(|()| verify_handle_matches_path(&file, &prepared.absolute));
        verified?;
        // The first mutation of the target happens here, after every check.
        file.set_len(0).map_err(|error| map_io(&error))?;
        file.write_all(content).map_err(|error| map_io(&error))?;
        file.flush().map_err(|error| map_io(&error))?;
        Ok(ResolvedPath {
            relative: path.clone(),
            absolute: prepared.absolute,
        })
    }

    /// Enumerates one directory without following links.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::NotFound`] when the directory does not exist,
    /// [`SandboxError::NotADirectory`] when a component on the path is not a
    /// directory, [`SandboxError::SymlinkForbidden`] when one is a link,
    /// junction or other reparse point, [`SandboxError::DirectoryTooLarge`]
    /// when the directory holds more than
    /// [`SandboxLimits::max_directory_entries`] entries, and
    /// [`SandboxError::RaceDetected`] when a pinned directory changed identity
    /// while it was being enumerated.
    pub fn read_directory(&self, path: &RelativePath) -> Result<Vec<DirectoryEntry>, SandboxError> {
        let mut entries = self.enumerate_directory(path)?;
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(entries)
    }

    /// Enumerates one directory in the order the operating system reports it.
    ///
    /// Every check [`Sandbox::read_directory`] performs happens here; the only
    /// difference is the ordering of the returned vector, which a recursive
    /// walk sorts once at the end instead of once per directory.
    fn enumerate_directory(
        &self,
        path: &RelativePath,
    ) -> Result<Vec<DirectoryEntry>, SandboxError> {
        // The directory is enumerated through its own pinned handle, so the
        // listing cannot be redirected to another directory after the
        // components were validated.
        let pin = self.pin_ancestors(&path.components)?;
        let handle = pin.handle()?;
        let names = list_pinned_names(handle, pin.path(), self.limits.max_directory_entries)?;
        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            let Ok(child) = self.child_of(path, &name) else {
                continue;
            };
            let (kind, size) = stat_pinned_child(handle, pin.path(), &name)?;
            entries.push(DirectoryEntry {
                path: child,
                kind,
                size_bytes: (kind == EntryKind::File).then_some(size),
            });
        }
        pin.verify()?;
        Ok(entries)
    }

    /// Walks the tree below `path`, returning files only and never crossing a
    /// link, junction, or other reparse point.
    ///
    /// # Errors
    ///
    /// Returns everything [`Sandbox::read_directory`] can return for the
    /// starting directory or for any directory below it, plus
    /// [`SandboxError::DirectoryTooLarge`] when the walk visits more than
    /// [`SandboxLimits::max_walked_files`] entries. A subtree deeper than
    /// [`SandboxLimits::max_path_components`] is skipped rather than refused.
    pub fn walk_files(&self, path: &RelativePath) -> Result<Vec<RelativePath>, SandboxError> {
        let mut queue = vec![path.clone()];
        let mut files = Vec::new();
        let mut visited = 0_usize;
        while let Some(current) = queue.pop() {
            // Unsorted: the walk sorts the whole result once, so ordering each
            // directory on the way down is work the final sort discards.
            for entry in self.enumerate_directory(&current)? {
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
    ///
    /// The ancestor chain is pinned again here rather than trusted from the
    /// earlier resolution, and re-verified after the handle exists, so the file
    /// behind the handle is provably the file that was validated.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::NotAFile`] when `resolved` names the workspace
    /// root itself, [`SandboxError::NotFound`] or
    /// [`SandboxError::PermissionDenied`] when the open fails,
    /// [`SandboxError::SymlinkForbidden`] when an ancestor or the final
    /// component is a link, junction or other reparse point,
    /// [`SandboxError::EscapesRoot`] or [`SandboxError::CaseMismatch`] when the
    /// path no longer canonicalizes onto itself, and
    /// [`SandboxError::RaceDetected`] when an ancestor or the opened handle
    /// stopped matching the validated path between check and use.
    pub fn open_no_follow(&self, resolved: &ResolvedPath) -> Result<File, SandboxError> {
        let components = &resolved.relative.components;
        let Some(leaf) = components.last() else {
            return Err(SandboxError::NotAFile);
        };
        let pin = self.pin_ancestors(&components[..components.len() - 1])?;
        let absolute = pin.path().join(leaf);
        let mut options = OpenOptions::new();
        options.read(true);
        apply_no_follow(&mut options);
        let file = options.open(&absolute).map_err(|error| map_io(&error))?;
        verify_handle_is_not_reparse_point(&file)?;
        self.verify_canonical(&absolute, components)?;
        pin.verify()?;
        // Last, because it is the only check that can see an ancestor swap
        // which was reverted before the checks above ran.
        verify_handle_matches_path(&file, &absolute)?;
        Ok(file)
    }

    /// Opens and holds a handle to the root and to every named directory below
    /// it, refusing links at every level.
    ///
    /// On Windows the handles are opened without `FILE_SHARE_DELETE`, so the
    /// operating system itself refuses to rename or delete any pinned
    /// directory while the pin lives. On Unix, where no such lock exists, each
    /// directory's device and inode are captured from its own handle and
    /// re-compared in [`DirectoryPin::verify`].
    ///
    /// This runs once per directory visited, and measurement puts nearly all
    /// of a recursive walk here: enumerating one 20-entry directory two levels
    /// down costs 73–80 µs, of which the 20 `statat` calls are 14 µs and the
    /// rest is this function — three `open`+`fstat` pairs, two `lstat`, one
    /// `canonicalize` at 9–10 µs — plus the pin re-verification afterwards.
    /// Walking 4 200 files across 421 directories costs 20.6 ms, and 421
    /// pins at that price account for essentially all of it.
    ///
    /// Three ways to make that cheaper were considered and all three are
    /// rejected, because each one is a check not performed:
    ///
    /// * Holding the root handle for the lifetime of the sandbox instead of
    ///   re-opening it per call (about 8 µs × once per directory, ~16% of a
    ///   walk).
    /// * Keeping the pin alive across a walk and descending from it.
    /// * Dropping the `symlink_metadata` below on the grounds that the
    ///   `O_DIRECTORY | O_NOFOLLOW` open in [`pin_directory`] already refuses
    ///   a link and a non-directory.
    ///
    /// The cost of this function is the price of the guarantee, and the
    /// guarantee is the reason the type exists.
    fn pin_ancestors(&self, components: &[String]) -> Result<DirectoryPin, SandboxError> {
        if components.len() > self.limits.max_path_components {
            return Err(SandboxError::TooManyComponents);
        }
        let mut levels = Vec::with_capacity(components.len() + 1);
        levels.push(pin_directory(&self.root)?);
        let mut absolute = self.root.clone();
        for component in components {
            absolute.push(component);
            let metadata = std::fs::symlink_metadata(&absolute).map_err(|error| map_io(&error))?;
            if is_link_like(&metadata) {
                return Err(SandboxError::SymlinkForbidden);
            }
            if !metadata.is_dir() {
                return Err(SandboxError::NotADirectory);
            }
            levels.push(pin_directory(&absolute)?);
        }
        self.verify_canonical(&absolute, components)?;
        Ok(DirectoryPin { levels })
    }

    fn child_of(&self, parent: &RelativePath, name: &str) -> Result<RelativePath, SandboxError> {
        let component = validate_component(name, 0, self.limits)?;
        if parent.components.len() >= self.limits.max_path_components {
            return Err(SandboxError::TooManyComponents);
        }
        // Extended from the parent's normalized form rather than re-joining
        // every component: this runs once per entry of every directory listing
        // and once per entry of every level of a recursive walk.
        let mut normalized = String::with_capacity(parent.normalized.len() + 1 + component.len());
        normalized.push_str(&parent.normalized);
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(&component);
        if normalized.len() > self.limits.max_relative_bytes {
            return Err(SandboxError::PathTooLong);
        }
        let mut components = Vec::with_capacity(parent.components.len() + 1);
        components.extend_from_slice(&parent.components);
        components.push(component);
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
            let metadata = std::fs::symlink_metadata(&absolute).map_err(|error| map_io(&error))?;
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
        let canonical = std::fs::canonicalize(absolute).map_err(|error| map_io(&error))?;
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

    fn reject_case_collision(&self, pin: &DirectoryPin, leaf: &str) -> Result<(), SandboxError> {
        // Enumerated through the pinned handle for the same reason as
        // `read_directory`: a scan redirected to another directory would miss a
        // real collision, or invent one.
        let names =
            list_pinned_names(pin.handle()?, pin.path(), self.limits.max_directory_entries)?;
        for name in names {
            if name != leaf && name.eq_ignore_ascii_case(leaf) {
                return Err(SandboxError::CaseCollision);
            }
        }
        Ok(())
    }
}

/// Classifies an entry from its metadata.
///
/// Only the path-based enumeration needs this; on Unix entries are classified
/// from a `statat` taken relative to the pinned descriptor instead.
#[cfg(not(unix))]
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

/// Validated write target together with the ancestor pin that guards it.
struct PreparedWrite {
    pin: DirectoryPin,
    absolute: PathBuf,
}

/// Identity of a directory as reported by its own open handle.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn identity_of(metadata: &std::fs::Metadata) -> DirectoryIdentity {
    use std::os::unix::fs::MetadataExt;

    DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

/// One pinned ancestor directory.
#[derive(Debug)]
struct PinnedDirectory {
    path: PathBuf,
    /// Held open for the whole check-and-use window, and enumerated through
    /// directly by [`list_pinned_names`] on Unix. Even where nothing reads it,
    /// its value is that the operating system knows it exists.
    handle: File,
    #[cfg(unix)]
    identity: DirectoryIdentity,
}

/// Open handles to the workspace root and to every named directory below it.
///
/// A pin is the object the sandbox acts on. Nothing between validation and use
/// re-derives a directory from its name, which is what makes the check-then-use
/// window closed rather than merely narrow.
#[derive(Debug)]
struct DirectoryPin {
    levels: Vec<PinnedDirectory>,
}

impl DirectoryPin {
    /// Returns the deepest pinned directory.
    fn path(&self) -> &Path {
        self.levels
            .last()
            .map_or_else(|| Path::new(""), |level| level.path.as_path())
    }

    /// Borrows the open handle of the deepest pinned directory.
    ///
    /// Enumeration acts on this handle rather than on [`Self::path`], so a
    /// listing cannot be redirected by an ancestor swapped after validation.
    fn handle(&self) -> Result<&File, SandboxError> {
        self.levels
            .last()
            .map(|level| &level.handle)
            .ok_or(SandboxError::NotADirectory)
    }

    /// Re-checks that every pinned directory is still the same directory.
    fn verify(&self) -> Result<(), SandboxError> {
        for level in &self.levels {
            let metadata =
                std::fs::symlink_metadata(&level.path).map_err(|error| map_io(&error))?;
            if is_link_like(&metadata) || !metadata.is_dir() {
                return Err(SandboxError::RaceDetected);
            }
            #[cfg(unix)]
            if identity_of(&metadata) != level.identity {
                return Err(SandboxError::RaceDetected);
            }
        }
        Ok(())
    }
}

/// Opens one directory handle without following a link at its final component.
fn pin_directory(path: &Path) -> Result<PinnedDirectory, SandboxError> {
    let handle = open_directory_no_follow(path)?;
    let metadata = handle.metadata().map_err(|error| map_io(&error))?;
    if is_link_like(&metadata) {
        return Err(SandboxError::SymlinkForbidden);
    }
    if !metadata.is_dir() {
        return Err(SandboxError::NotADirectory);
    }
    Ok(PinnedDirectory {
        path: path.to_path_buf(),
        #[cfg(unix)]
        identity: identity_of(&metadata),
        handle,
    })
}

#[cfg(windows)]
fn open_directory_no_follow(path: &Path) -> Result<File, SandboxError> {
    OpenOptions::new()
        .read(true)
        // Withholding FILE_SHARE_DELETE makes Windows refuse to rename or
        // delete this directory for as long as the handle lives, which is what
        // stops a validated ancestor being swapped for a junction.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| map_io(&error))
}

#[cfg(unix)]
fn open_directory_no_follow(path: &Path) -> Result<File, SandboxError> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| map_io(&error))
}

#[cfg(not(any(windows, unix)))]
fn open_directory_no_follow(path: &Path) -> Result<File, SandboxError> {
    File::open(path).map_err(|error| map_io(&error))
}

/// Opens a write target relative to its pinned parent without following links.
///
/// Unix uses `openat`, so a renamed ancestor cannot redirect creation or
/// overwrite through a different pathname. `NONBLOCK` makes a special file
/// planted after the metadata check fail promptly instead of hanging on open.
#[cfg(unix)]
fn open_write_no_follow(
    parent: &File,
    _absolute: &Path,
    leaf: &str,
    mode: WriteMode,
) -> Result<File, SandboxError> {
    use rustix::fs::{Mode, OFlags, openat};

    let existing_flags = OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let create_flags = existing_flags | OFlags::CREATE | OFlags::EXCL;
    let permissions = Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH;
    if mode == WriteMode::CreateNew {
        return openat(parent, leaf, create_flags, permissions)
            .map(File::from)
            .map_err(map_errno);
    }
    match openat(parent, leaf, existing_flags, Mode::empty()) {
        Ok(handle) => Ok(File::from(handle)),
        Err(rustix::io::Errno::NOENT) => match openat(parent, leaf, create_flags, permissions) {
            Ok(handle) => Ok(File::from(handle)),
            Err(rustix::io::Errno::EXIST) => openat(parent, leaf, existing_flags, Mode::empty())
                .map(File::from)
                .map_err(map_errno),
            Err(error) => Err(map_errno(error)),
        },
        Err(error) => Err(map_errno(error)),
    }
}

/// Windows pins every ancestor without delete sharing before opening the full
/// path, so the namespace cannot be redirected while this operation runs.
#[cfg(not(unix))]
fn open_write_no_follow(
    _parent: &File,
    absolute: &Path,
    _leaf: &str,
    mode: WriteMode,
) -> Result<File, SandboxError> {
    fn open_existing(absolute: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.write(true);
        apply_no_follow(&mut options);
        options.open(absolute)
    }

    fn create_new(absolute: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        apply_no_follow(&mut options);
        options.open(absolute)
    }

    if mode == WriteMode::CreateNew {
        return create_new(absolute).map_err(|error| map_io(&error));
    }
    match open_existing(absolute) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => match create_new(absolute) {
            Ok(file) => Ok(file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                open_existing(absolute).map_err(|error| map_io(&error))
            }
            Err(error) => Err(map_io(&error)),
        },
        Err(error) => Err(map_io(&error)),
    }
}

/// Returns whether metadata describes a symbolic link.
#[cfg(not(windows))]
fn is_link_like(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn apply_no_follow(options: &mut OpenOptions) {
    options
        // Keep the opened leaf from being renamed outside the pinned tree
        // between verification and the final read/write.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
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
    let metadata = file.metadata().map_err(|error| map_io(&error))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        Ok(())
    } else {
        Err(SandboxError::SymlinkForbidden)
    }
}

fn verify_handle_is_regular(file: &File) -> Result<(), SandboxError> {
    if file.metadata().map_err(|error| map_io(&error))?.is_file() {
        Ok(())
    } else {
        Err(SandboxError::NotAFile)
    }
}

#[cfg(not(windows))]
fn verify_handle_is_not_reparse_point(file: &File) -> Result<(), SandboxError> {
    let metadata = file.metadata().map_err(|error| map_io(&error))?;
    if metadata.file_type().is_symlink() {
        Err(SandboxError::SymlinkForbidden)
    } else {
        Ok(())
    }
}

/// Confirms the opened handle really is the file the validated path names.
///
/// This closes the last "validate a name, then act on the name" gap in the
/// write and read paths. `O_NOFOLLOW` protects only the final component, so an
/// ancestor directory swapped for a link between validation and open redirects
/// the open to a file outside the root. Re-canonicalising the path cannot see
/// that, because an attacker who restores the honest directory before the check
/// leaves the name resolving exactly where it should, and the ancestor identity
/// comparison cannot see it either because the restored directory is the same
/// object it always was.
///
/// The handle is the only witness of what was actually opened, so it is what is
/// compared: if the validated path now names a different object from the one
/// held open, the open went somewhere else and the operation is refused before
/// anything is truncated or read.
#[cfg(unix)]
fn verify_handle_matches_path(file: &File, absolute: &Path) -> Result<(), SandboxError> {
    let opened = identity_of(&file.metadata().map_err(|error| map_io(&error))?);
    let named = identity_of(&std::fs::symlink_metadata(absolute).map_err(|error| map_io(&error))?);
    if opened == named {
        Ok(())
    } else {
        Err(SandboxError::RaceDetected)
    }
}

/// Windows counterpart, where the swap this guards against cannot happen.
///
/// Pinned ancestors and the opened leaf are held without `FILE_SHARE_DELETE`,
/// so the kernel refuses to rename or delete them while the operation lives.
/// That is prevention rather than detection, and it is why no identity
/// comparison is needed here; Windows also exposes no stable file identity on
/// stable Rust.
#[cfg(not(unix))]
fn verify_handle_matches_path(_file: &File, _absolute: &Path) -> Result<(), SandboxError> {
    Ok(())
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

/// Returns whether a component names a reserved Windows device.
///
/// Compared with `eq_ignore_ascii_case` rather than by uppercasing into a
/// `String`: this runs for every component of every path and for every entry of
/// every directory listing, where the two allocations the uppercase form needed
/// were the largest single cost of lexical validation.
fn is_reserved_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    if RESERVED_DEVICE_NAMES
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return true;
    }
    // `COM`/`LPT` followed by a superscript digit and nothing else. The head is
    // three ASCII characters, so a byte comparison is a character comparison.
    let bytes = stem.as_bytes();
    if bytes.len() < 3
        || !(bytes[..3].eq_ignore_ascii_case(b"COM") || bytes[..3].eq_ignore_ascii_case(b"LPT"))
    {
        return false;
    }
    let mut rest = stem[3..].chars();
    matches!(
        (rest.next(), rest.next()),
        (Some(digit), None) if SUPERSCRIPT_DEVICE_DIGITS.contains(&digit)
    )
}

/// Lists the child names of a pinned directory.
///
/// On Unix this reads through the pinned descriptor with `rustix::fs::Dir`,
/// which wraps `fdopendir`. The enumeration is therefore bound to the open
/// description that was validated, not to a pathname that can be re-resolved,
/// which closes the same check-then-use gap that `verify_handle_matches_path`
/// closes for files. Reopening the directory through its path — or through
/// `/dev/fd/N` — would re-enter the path namespace and discard exactly the
/// protection the descriptor provides.
#[cfg(unix)]
fn list_pinned_names(
    handle: &File,
    _path: &Path,
    limit: usize,
) -> Result<Vec<String>, SandboxError> {
    let mut dir = rustix::fs::Dir::read_from(handle).map_err(map_errno)?;
    // The descriptor is freshly opened, but rewinding removes any dependence on
    // its current offset.
    dir.rewind();
    let mut names = Vec::new();
    for entry in dir {
        let entry = entry.map_err(map_errno)?;
        let raw = entry.file_name();
        if raw == c"." || raw == c".." {
            continue;
        }
        if names.len() >= limit {
            return Err(SandboxError::DirectoryTooLarge);
        }
        // A non-UTF-8 name cannot be a legal sandbox component, so it is
        // skipped rather than treated as an error.
        let Ok(name) = std::str::from_utf8(raw.to_bytes()) else {
            continue;
        };
        names.push(name.to_owned());
    }
    Ok(names)
}

/// Windows and other platforms enumerate by path.
///
/// This is safe here for the reason the identity comparison is unnecessary
/// there: pinned ancestors are held without `FILE_SHARE_DELETE`, so the kernel
/// refuses to rename or delete them while the pin lives.
#[cfg(not(unix))]
fn list_pinned_names(
    _handle: &File,
    path: &Path,
    limit: usize,
) -> Result<Vec<String>, SandboxError> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(path).map_err(|error| map_io(&error))? {
        let entry = entry.map_err(|error| map_io(&error))?;
        if names.len() >= limit {
            return Err(SandboxError::DirectoryTooLarge);
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        names.push(name);
    }
    Ok(names)
}

/// Classifies one child of a pinned directory without following a link.
#[cfg(unix)]
fn stat_pinned_child(
    handle: &File,
    _path: &Path,
    name: &str,
) -> Result<(EntryKind, u64), SandboxError> {
    use rustix::fs::{AtFlags, FileType};

    // Relative to the pinned descriptor, so the child is resolved from the
    // directory that was validated rather than from a name walked again.
    let stat = rustix::fs::statat(handle, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)?;
    let kind = match FileType::from_raw_mode(stat.st_mode) {
        FileType::Directory => EntryKind::Directory,
        FileType::RegularFile => EntryKind::File,
        FileType::Symlink => EntryKind::Link,
        _ => EntryKind::Other,
    };
    Ok((kind, u64::try_from(stat.st_size).unwrap_or(0)))
}

#[cfg(not(unix))]
fn stat_pinned_child(
    _handle: &File,
    path: &Path,
    name: &str,
) -> Result<(EntryKind, u64), SandboxError> {
    let metadata = std::fs::symlink_metadata(path.join(name)).map_err(|error| map_io(&error))?;
    Ok((classify(&metadata), metadata.len()))
}

/// Maps a `rustix` error onto the sandbox error type through `std::io`.
#[cfg(unix)]
fn map_errno(error: rustix::io::Errno) -> SandboxError {
    map_io(&io::Error::from_raw_os_error(error.raw_os_error()))
}

fn map_io(error: &io::Error) -> SandboxError {
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
    /// An ancestor directory changed identity between validation and use.
    RaceDetected,
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
            Self::RaceDetected => "a directory on the path changed between validation and use",
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

    /// The race test that found this hole is timing dependent, so the primitive
    /// closing it is also proved deterministically.
    #[cfg(unix)]
    #[test]
    fn a_handle_is_refused_when_the_validated_name_resolves_elsewhere() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("claw-handle-identity-{nanos}"));
        std::fs::create_dir_all(&root).expect("create the scratch directory");
        let held = root.join("held.txt");
        let other = root.join("other.txt");
        std::fs::write(&held, b"held").expect("write the held file");
        std::fs::write(&other, b"other").expect("write the other file");

        let file = File::open(&held).expect("open the held file");
        assert_eq!(verify_handle_matches_path(&file, &held), Ok(()));
        assert_eq!(
            verify_handle_matches_path(&file, &other),
            Err(SandboxError::RaceDetected),
            "a handle on one file passed validation against a different file"
        );

        // A name that no longer resolves at all is equally not the open handle.
        std::fs::remove_file(&other).expect("remove the other file");
        assert!(verify_handle_matches_path(&file, &other).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn write_leaf_handle_blocks_concurrent_rename_outside_the_root() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("claw-write-leaf-share-{nanos}"));
        let workspace = root.join("workspace");
        let outside = root.join("outside");
        std::fs::create_dir_all(&workspace).expect("create the workspace");
        std::fs::create_dir_all(&outside).expect("create the outside directory");
        let parent = open_directory_no_follow(&workspace).expect("pin the workspace");

        for (leaf, mode) in [
            ("existing.txt", WriteMode::Overwrite),
            ("created.txt", WriteMode::CreateNew),
        ] {
            let inside = workspace.join(leaf);
            let escaped = outside.join(leaf);
            if mode == WriteMode::Overwrite {
                std::fs::write(&inside, b"original").expect("create the existing leaf");
            }
            let file = open_write_no_follow(&parent, &inside, leaf, mode)
                .expect("open the leaf without delete sharing");

            let rename_inside = inside.clone();
            let rename_escaped = escaped.clone();
            let rename = std::thread::spawn(move || std::fs::rename(rename_inside, rename_escaped))
                .join()
                .expect("rename thread finishes");
            assert!(
                rename.is_err(),
                "{mode:?} leaf was renamed outside while its writable handle remained open"
            );
            assert!(
                inside.is_file(),
                "the opened leaf must stay in the workspace"
            );
            assert!(
                !escaped.exists(),
                "the opened leaf must never appear outside the workspace"
            );

            drop(file);
            std::fs::rename(&inside, &escaped)
                .expect("the same rename succeeds once the leaf handle is closed");
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn overwrite_opens_the_preexisting_file_from_the_pinned_parent() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("claw-write-provenance-{nanos}"));
        let honest = root.join("honest");
        let moved = root.join("moved-aside");
        std::fs::create_dir_all(&honest).expect("create the honest directory");
        std::fs::write(honest.join("existing.txt"), []).expect("create an empty existing file");
        let parent = open_directory_no_follow(&honest).expect("pin the honest directory");

        std::fs::rename(&honest, &moved).expect("move the pinned directory aside");
        std::fs::create_dir(&honest).expect("replace the validated pathname");
        let file = open_write_no_follow(
            &parent,
            &honest.join("existing.txt"),
            "existing.txt",
            WriteMode::Overwrite,
        )
        .expect("open through the pinned parent");

        drop(file);
        assert!(
            moved.join("existing.txt").is_file(),
            "failed-write cleanup must never delete the pre-existing pinned file"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Proves the listing is bound to the open descriptor rather than the name.
    ///
    /// The directory is swapped for a different one *after* the handle is open,
    /// which is the swap-and-restore shape that device/inode comparison cannot
    /// see. Path-based enumeration returns the impostor's contents here; a
    /// descriptor-based one cannot, because the descriptor still refers to the
    /// inode that was validated.
    #[cfg(unix)]
    #[test]
    fn a_pinned_listing_follows_the_descriptor_not_the_path() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!("claw-pinned-listing-{nanos}"));
        let honest = root.join("honest");
        let impostor = root.join("impostor");
        let moved = root.join("moved-aside");
        std::fs::create_dir_all(&honest).expect("create the honest directory");
        std::fs::create_dir_all(&impostor).expect("create the impostor directory");
        std::fs::write(honest.join("inside.txt"), b"inside").expect("write the honest entry");
        std::fs::write(impostor.join("secret.txt"), b"secret").expect("write the impostor entry");

        let handle = open_directory_no_follow(&honest).expect("pin the honest directory");
        // The swap a validated-name check cannot detect.
        std::fs::rename(&honest, &moved).expect("move the honest directory aside");
        std::fs::rename(&impostor, &honest).expect("put the impostor in its place");

        let names = list_pinned_names(&handle, &honest, 64).expect("the pinned listing succeeds");
        assert_eq!(
            names,
            vec!["inside.txt".to_owned()],
            "the listing followed the path to the impostor instead of the pinned descriptor"
        );

        // The same descriptor must also classify children relative to itself.
        let (kind, size) =
            stat_pinned_child(&handle, &honest, "inside.txt").expect("stat through the descriptor");
        assert_eq!(kind, EntryKind::File);
        assert_eq!(size, 6);
        assert_eq!(
            stat_pinned_child(&handle, &honest, "secret.txt")
                .expect_err("the impostor's entry is not reachable through the pinned descriptor"),
            SandboxError::NotFound
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
