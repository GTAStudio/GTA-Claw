//! Handle-relative Windows filesystem operations.

#![cfg(windows)]

use std::ffi::OsString;
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path};
use std::ptr::{null, null_mut};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, FileNamesInformation, NtCreateFile, NtQueryDirectoryFile,
};
use windows_sys::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, HANDLE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError,
    STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, STATUS_SUCCESS, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const BUFFER_BYTES: usize = 64 * 1024;
const BUFFER_BYTES_U32: u32 = 64 * 1024;
const FILE_NAMES_HEADER_BYTES: usize = 12;

/// A synchronous directory handle created and owned by this helper.
///
/// The type deliberately has no conversion from [`File`], so a caller cannot
/// pass a handle opened with `FILE_FLAG_OVERLAPPED` to handle-relative
/// enumeration:
///
/// ```compile_fail
/// use std::fs::OpenOptions;
/// use std::os::windows::fs::OpenOptionsExt;
///
/// use claw_windows_handle_dir::DirectoryHandle;
///
/// const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
/// const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
///
/// let file = OpenOptions::new()
///     .read(true)
///     .custom_flags(FILE_FLAG_OVERLAPPED | FILE_FLAG_BACKUP_SEMANTICS)
///     .open(".")
///     .unwrap();
/// let directory = DirectoryHandle::from(file);
/// ```
#[derive(Debug)]
pub struct DirectoryHandle {
    file: File,
}

/// Access requested for a handle-relative file open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenMode {
    Directory,
    Read,
    Write,
    CreateNew,
    Metadata,
}

impl DirectoryHandle {
    /// Opens an existing directory without following its final reparse point.
    ///
    /// The helper omits `FILE_FLAG_OVERLAPPED`, so all operations on the owned
    /// handle have synchronous completion semantics.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the path cannot be opened or does
    /// not name a directory.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        if !file.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "path does not name a directory",
            ));
        }
        Ok(Self { file })
    }

    /// Returns metadata for the pinned directory.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when metadata cannot be queried.
    pub fn metadata(&self) -> io::Result<Metadata> {
        self.file.metadata()
    }

    /// Opens one child directory relative to this pinned directory.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the child cannot be opened.
    pub fn open_directory(&self, name: &Path) -> io::Result<Self> {
        self.open_relative(name, OpenMode::Directory)
            .map(|file| Self { file })
    }

    /// Opens one existing regular file for reading.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the child cannot be opened.
    pub fn open_read(&self, name: &Path) -> io::Result<File> {
        self.open_relative(name, OpenMode::Read)
    }

    /// Opens one existing regular file for writing.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the child cannot be opened.
    pub fn open_write(&self, name: &Path) -> io::Result<File> {
        self.open_relative(name, OpenMode::Write)
    }

    /// Creates one new regular file for writing.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the child cannot be created.
    pub fn create_new(&self, name: &Path) -> io::Result<File> {
        self.open_relative(name, OpenMode::CreateNew)
    }

    /// Opens one existing child without following its final reparse point.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the child cannot be opened.
    pub fn open_metadata(&self, name: &Path) -> io::Result<File> {
        self.open_relative(name, OpenMode::Metadata)
    }

    /// Enumerates at most `max_names` children directly from this directory.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error from `NtQueryDirectoryFile`, or
    /// [`io::ErrorKind::InvalidData`] when Windows returns malformed entry data.
    pub fn read_names(&self, max_names: usize) -> io::Result<Vec<OsString>> {
        read_names(self, max_names)
    }

    /// Opens `name` relative to this directory without following its final
    /// reparse point.
    ///
    /// Returned handles never permit delete sharing, so a writable leaf cannot
    /// be renamed outside the pinned tree while it remains open.
    #[expect(
        unsafe_code,
        reason = "rooted NtCreateFile and ownership transfer from its returned HANDLE have no safe std equivalent"
    )]
    fn open_relative(&self, name: &Path, mode: OpenMode) -> io::Result<File> {
        let mut components = name.components();
        let Some(Component::Normal(name)) = components.next() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relative name must contain one normal component",
            ));
        };
        if components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relative name must contain one normal component",
            ));
        }
        let wide = name.encode_wide().collect::<Vec<_>>();
        let length_bytes = wide
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|length| u16::try_from(length).ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "relative name is too long")
            })?;
        let name = UNICODE_STRING {
            Length: length_bytes,
            MaximumLength: length_bytes,
            Buffer: wide.as_ptr().cast_mut(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "OBJECT_ATTRIBUTES size exceeds the Windows ABI field",
                )
            })?,
            RootDirectory: self.file.as_raw_handle() as HANDLE,
            ObjectName: &raw const name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: null(),
            SecurityQualityOfService: null(),
        };
        let (access, disposition, options) = match mode {
            OpenMode::Directory => (
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ),
            OpenMode::Read => (
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ),
            OpenMode::Write => (
                GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ),
            OpenMode::CreateNew => (
                GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_CREATE,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ),
            OpenMode::Metadata => (
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_OPEN,
                FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ),
        };
        let mut handle = null_mut();
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: the parent handle and all pointed-to stack values remain alive
        // for the synchronous call. `name` points into `wide`, and optional buffers
        // are null. A successful returned handle is transferred exactly once into
        // `File`.
        let status = unsafe {
            NtCreateFile(
                &raw mut handle,
                access,
                &raw const attributes,
                &raw mut status_block,
                null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                disposition,
                options,
                null(),
                0,
            )
        };
        if status != STATUS_SUCCESS {
            return Err(status_error(status));
        }
        // SAFETY: `NtCreateFile` returned success and ownership of this non-null
        // handle; `File` becomes its sole owner.
        Ok(unsafe { File::from_raw_handle(handle) })
    }
}

#[expect(
    unsafe_code,
    reason = "NtQueryDirectoryFile is safe here because DirectoryHandle owns a synchronous, non-overlapped handle"
)]
fn read_names(directory: &DirectoryHandle, max_names: usize) -> io::Result<Vec<OsString>> {
    let mut names = Vec::with_capacity(max_names.min(256));
    let mut buffer = vec![0_u64; BUFFER_BYTES / size_of::<u64>()];
    let mut restart_scan = true;
    while names.len() < max_names {
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: `directory` remains open for the call; the aligned buffer is
        // writable for its declared byte length; all optional pointers are
        // null; and `status_block` lives until the synchronous call returns.
        let status = unsafe {
            NtQueryDirectoryFile(
                directory.file.as_raw_handle() as HANDLE,
                null_mut(),
                None,
                null(),
                &raw mut status_block,
                buffer.as_mut_ptr().cast(),
                BUFFER_BYTES_U32,
                FileNamesInformation,
                true,
                null(),
                restart_scan,
            )
        };
        restart_scan = false;
        if enumeration_exhausted(status, status_block.Information) {
            break;
        }
        if status != STATUS_SUCCESS {
            return Err(status_error(status));
        }

        let returned = status_block.Information;
        if !(FILE_NAMES_HEADER_BYTES..=BUFFER_BYTES).contains(&returned) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NtQueryDirectoryFile returned an invalid byte count",
            ));
        }
        let bytes = as_bytes(&buffer)[..returned].as_ref();
        let name_bytes = usize::try_from(u32::from_ne_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11],
        ]))
        .unwrap_or(usize::MAX);
        let name_end = FILE_NAMES_HEADER_BYTES.saturating_add(name_bytes);
        if name_bytes % size_of::<u16>() != 0 || name_end > returned {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NtQueryDirectoryFile returned an invalid name length",
            ));
        }
        let wide = bytes[FILE_NAMES_HEADER_BYTES..name_end]
            .chunks_exact(size_of::<u16>())
            .map(|unit| u16::from_ne_bytes([unit[0], unit[1]]))
            .collect::<Vec<_>>();
        let name = OsString::from_wide(&wide);
        if name != "." && name != ".." {
            names.push(name);
        }
    }
    Ok(names)
}

const fn enumeration_exhausted(status: i32, information: usize) -> bool {
    status == STATUS_NO_MORE_FILES
        || status == STATUS_NO_SUCH_FILE
        || (status == STATUS_SUCCESS && information == 0)
}

#[expect(
    unsafe_code,
    reason = "the aligned NtQueryDirectoryFile output buffer must be viewed as its initialized byte representation"
)]
const fn as_bytes(words: &[u64]) -> &[u8] {
    // SAFETY: `u8` has alignment one, and the byte slice covers exactly the
    // initialized storage of `words` for the duration of the shared borrow.
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), size_of_val(words)) }
}

#[expect(
    unsafe_code,
    reason = "RtlNtStatusToDosError is the Windows conversion for NTSTATUS values returned by the audited NT calls"
)]
fn status_error(status: i32) -> io::Error {
    // SAFETY: converting an NTSTATUS to its Win32 error code has no
    // memory-safety preconditions.
    let code = unsafe { RtlNtStatusToDosError(status) };
    io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_directory_statuses_are_exhaustion() {
        assert!(enumeration_exhausted(STATUS_NO_MORE_FILES, 0));
        assert!(enumeration_exhausted(STATUS_NO_SUCH_FILE, 1));
        assert!(enumeration_exhausted(STATUS_SUCCESS, 0));
        assert!(!enumeration_exhausted(STATUS_SUCCESS, 1));
    }

    #[test]
    fn helper_owned_directory_handle_enumerates_synchronously() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let directory = std::env::temp_dir().join(format!("claw-sync-directory-{unique}"));
        std::fs::create_dir(&directory).expect("create test directory");
        std::fs::write(directory.join("child.txt"), b"child").expect("create child");

        let handle = DirectoryHandle::open(&directory).expect("open synchronous directory handle");
        let names = handle.read_names(8).expect("enumerate synchronously");
        assert!(names.iter().any(|name| name == "child.txt"));

        drop(handle);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }
}
