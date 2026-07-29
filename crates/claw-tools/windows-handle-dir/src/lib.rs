//! Handle-relative Windows directory enumeration.

#![cfg(windows)]
#![allow(
    unsafe_code,
    reason = "NtQueryDirectoryFile is the Windows primitive that binds enumeration to an open directory handle"
)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use std::ptr::{null, null_mut};

use windows_sys::Wdk::Storage::FileSystem::{FileNamesInformation, NtQueryDirectoryFile};
use windows_sys::Win32::Foundation::{
    HANDLE, RtlNtStatusToDosError, STATUS_NO_MORE_FILES, STATUS_SUCCESS,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const BUFFER_BYTES: usize = 64 * 1024;
const BUFFER_BYTES_U32: u32 = 64 * 1024;
const FILE_NAMES_HEADER_BYTES: usize = 12;

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
        if status == STATUS_NO_MORE_FILES
            || (status == STATUS_SUCCESS && status_block.Information == 0)
        {
            break;
        }
        if status != STATUS_SUCCESS {
            // SAFETY: converting an NTSTATUS to its Win32 error code has no
            // memory-safety preconditions.
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(io::Error::from_raw_os_error(
                i32::try_from(code).unwrap_or(i32::MAX),
            ));
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

const fn as_bytes(words: &[u64]) -> &[u8] {
    // SAFETY: `u8` has alignment one, and the byte slice covers exactly the
    // initialized storage of `words` for the duration of the shared borrow.
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), size_of_val(words)) }
}
