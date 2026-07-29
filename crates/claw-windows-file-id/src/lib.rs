//! Audited Windows retained-handle file identity.

/// Full Windows file identity returned by `FILE_ID_INFO`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileId {
    volume_serial_number: u64,
    identifier: [u8; 16],
}

impl FileId {
    /// Creates an identity from its complete Windows fields.
    #[must_use]
    pub const fn new(volume_serial_number: u64, identifier: [u8; 16]) -> Self {
        Self {
            volume_serial_number,
            identifier,
        }
    }

    /// Returns the volume serial number.
    #[must_use]
    pub const fn volume_serial_number(self) -> u64 {
        self.volume_serial_number
    }

    /// Returns all 128 file-ID bits in Windows byte order.
    #[must_use]
    pub const fn identifier(self) -> [u8; 16] {
        self.identifier
    }
}

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Windows exposes full 128-bit file identity only through FILE_ID_INFO; this module \
              accepts only already-open handles and is the crate's sole audited FFI boundary"
)]
mod windows {
    use std::io;
    use std::mem;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    use super::FileId;

    pub(super) fn from_handle(handle: &(impl AsRawHandle + ?Sized)) -> io::Result<FileId> {
        let mut info = FILE_ID_INFO::default();
        let buffer_size =
            u32::try_from(mem::size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO size fits in u32");
        let raw_handle: HANDLE = handle.as_raw_handle();
        // SAFETY: `handle` remains borrowed for the call and `info` points to
        // writable storage of exactly FILE_ID_INFO size.
        let succeeded = unsafe {
            GetFileInformationByHandleEx(
                raw_handle,
                FileIdInfo,
                (&raw mut info).cast(),
                buffer_size,
            )
        };
        if succeeded == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(FileId::new(info.VolumeSerialNumber, info.FileId.Identifier))
    }
}

/// Returns the complete Windows identity of an already-open handle.
///
/// # Errors
///
/// Returns the operating-system error from `GetFileInformationByHandleEx`.
#[cfg(windows)]
pub fn from_handle(
    handle: &(impl std::os::windows::io::AsRawHandle + ?Sized),
) -> std::io::Result<FileId> {
    windows::from_handle(handle)
}

#[cfg(test)]
mod tests {
    use super::FileId;

    #[test]
    fn compares_all_identifier_bits() {
        let mut first = [0_u8; 16];
        first[..8].copy_from_slice(&0x0123_4567_89ab_cdef_u64.to_le_bytes());
        let mut second = first;
        second[15] = 1;

        assert_eq!(&first[..8], &second[..8]);
        assert_ne!(FileId::new(7, first), FileId::new(7, second));
    }
}
