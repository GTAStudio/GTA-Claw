//! Handle-relative Windows filesystem operations.

#![cfg(windows)]
#![allow(
    unsafe_code,
    reason = "NtCreateFile and NtQueryDirectoryFile bind operations to an open directory handle"
)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
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
    FILE_ATTRIBUTE_NORMAL, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const BUFFER_BYTES: usize = 64 * 1024;
const BUFFER_BYTES_U32: u32 = 64 * 1024;
const FILE_NAMES_HEADER_BYTES: usize = 12;

/// Access requested for a handle-relative open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenMode {
    /// Open an existing directory for enumeration and metadata.
    Directory,
    /// Open an existing regular file for reading.
    Read,
    /// Open an existing regular file for writing.
    Write,
    /// Create a new regular file for writing.
    CreateNew,
    /// Open an existing child without following its final reparse point.
    Metadata,
}

/// Opens `name` relative to `directory` without following its final reparse point.
///
/// The returned handle never permits delete sharing, so a writable leaf cannot
/// be renamed outside the pinned tree while it remains open.
///
/// # Errors
///
/// Returns an operating-system error when the relative open is rejected.
pub fn open_relative(directory: &File, name: &Path, mode: OpenMode) -> io::Result<File> {
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
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "relative name is too long"))?;
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
        RootDirectory: directory.as_raw_handle() as HANDLE,
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

/// Enumerates at most `max_names` children directly from `directory`.
///
/// # Errors
///
/// Returns the operating-system error from `NtQueryDirectoryFile`, or
/// [`io::ErrorKind::InvalidData`] when Windows returns malformed entry data.
pub fn read_names(directory: &File, max_names: usize) -> io::Result<Vec<OsString>> {
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
                directory.as_raw_handle() as HANDLE,
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

const fn as_bytes(words: &[u64]) -> &[u8] {
    // SAFETY: `u8` has alignment one, and the byte slice covers exactly the
    // initialized storage of `words` for the duration of the shared borrow.
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), size_of_val(words)) }
}

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
}
