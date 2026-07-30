//! Platform filesystem primitives used by guarded configuration publication.
//!
//! Guarded publication displaces the destination instead of renaming blindly
//! over it. The displaced object remains reachable so callers can validate the
//! exact bytes that occupied the destination at the linearization point.

use std::fs::File;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Volume-unique identity of one filesystem object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ObjectIdentity {
    volume: u64,
    object: [u8; 16],
}

#[cfg(unix)]
mod platform {
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use super::ObjectIdentity;

    pub(super) fn open_lock_no_follow(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    pub(super) fn create_new_no_follow(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    pub(super) fn open_no_follow(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    pub(super) fn identity_of_handle(file: &File) -> io::Result<ObjectIdentity> {
        let metadata = file.metadata()?;
        Ok(ObjectIdentity {
            volume: metadata.dev(),
            object: u128::from(metadata.ino()).to_le_bytes(),
        })
    }

    pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
        open_no_follow(path)?.sync_all()
    }

    pub(super) fn c_path(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains an interior NUL byte",
            )
        })
    }
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
#[expect(
    unsafe_code,
    reason = "renameat2 is the only atomic exchange/no-replace primitive on Linux and Android"
)]
mod rename {
    use std::io;
    use std::path::Path;

    use super::platform::c_path;

    fn rename_with_flags(first: &Path, second: &Path, flags: u32) -> io::Result<()> {
        let first = c_path(first)?;
        let second = c_path(second)?;
        // SAFETY: Both pointers reference live NUL-terminated path buffers and
        // the flags are documented `renameat2` constants.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                first.as_ptr(),
                libc::AT_FDCWD,
                second.as_ptr(),
                flags,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn exchange(first: &Path, second: &Path) -> io::Result<()> {
        rename_with_flags(first, second, libc::RENAME_EXCHANGE)
    }

    pub(super) fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
        rename_with_flags(from, to, libc::RENAME_NOREPLACE)
    }
}

#[cfg(all(unix, target_vendor = "apple"))]
#[expect(
    unsafe_code,
    reason = "renamex_np is the only atomic exchange/no-replace primitive on Apple targets"
)]
mod rename {
    use std::io;
    use std::path::Path;

    use super::platform::c_path;

    fn rename_with_flags(first: &Path, second: &Path, flags: libc::c_uint) -> io::Result<()> {
        let first = c_path(first)?;
        let second = c_path(second)?;
        // SAFETY: Both pointers reference live NUL-terminated path buffers and
        // the flags are documented `renamex_np` constants.
        let result = unsafe { libc::renamex_np(first.as_ptr(), second.as_ptr(), flags) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn exchange(first: &Path, second: &Path) -> io::Result<()> {
        rename_with_flags(first, second, libc::RENAME_SWAP)
    }

    pub(super) fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
        rename_with_flags(from, to, libc::RENAME_EXCL)
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
mod rename {
    use std::io;
    use std::path::Path;

    pub(super) fn exchange(_first: &Path, _second: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic path exchange is not available on this Unix target",
        ))
    }

    pub(super) fn rename_no_replace(_from: &Path, _to: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic no-replace rename is not available on this Unix target",
        ))
    }
}

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Windows no-follow identity and replacement operations have no safe standard API"
)]
mod platform {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    #[cfg(test)]
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorControl, SE_DACL_PROTECTED, UNPROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_INFO,
        FILE_NAME_NORMALIZED, FILE_STANDARD_INFO, FileIdInfo, FileStandardInfo,
        GetFileInformationByHandleEx, GetFinalPathNameByHandleW, WRITE_DAC,
    };

    use super::ObjectIdentity;

    fn reject_reparse(file: File) -> io::Result<File> {
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to open a Windows reparse point",
            ));
        }
        Ok(file)
    }

    pub(super) fn open_lock_no_follow(path: &Path) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        reject_reparse(file)
    }

    fn open_dacl_no_follow(path: &Path) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | WRITE_DAC)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        reject_reparse(file)
    }

    pub(super) fn create_new_no_follow(path: &Path) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH)
            .open(path)?;
        reject_reparse(file)
    }

    pub(super) fn open_no_follow(path: &Path) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        reject_reparse(file)
    }

    pub(super) fn identity_of_handle(file: &File) -> io::Result<ObjectIdentity> {
        if file.metadata()?.is_file() {
            let mut standard = MaybeUninit::<FILE_STANDARD_INFO>::uninit();
            // SAFETY: The handle remains live and the output buffer has the
            // exact size required for `FileStandardInfo`.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    file.as_raw_handle() as HANDLE,
                    FileStandardInfo,
                    standard.as_mut_ptr().cast(),
                    u32::try_from(std::mem::size_of::<FILE_STANDARD_INFO>())
                        .expect("FILE_STANDARD_INFO size fits u32"),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: The successful call initialized the complete structure.
            let standard = unsafe { standard.assume_init() };
            if standard.NumberOfLinks != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "guarded publication refuses multiply linked Windows files",
                ));
            }
        }

        let mut information = MaybeUninit::<FILE_ID_INFO>::uninit();
        // SAFETY: `file` owns a valid handle for the duration of the call and the
        // output pointer references a correctly sized writable structure.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                FileIdInfo,
                information.as_mut_ptr().cast(),
                u32::try_from(std::mem::size_of::<FILE_ID_INFO>())
                    .expect("FILE_ID_INFO size fits u32"),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: A successful call initialized the complete structure.
        let information = unsafe { information.assume_init() };
        Ok(ObjectIdentity {
            volume: information.VolumeSerialNumber,
            object: information.FileId.Identifier,
        })
    }

    pub(super) fn final_path_of_handle(file: &File) -> io::Result<std::path::PathBuf> {
        let handle = file.as_raw_handle() as HANDLE;
        // Zero selects a normalized file name and the default DOS-volume form.
        let flags = FILE_NAME_NORMALIZED;
        let mut capacity = 256_usize;
        loop {
            let mut buffer = vec![0_u16; capacity];
            // SAFETY: The handle stays live and the buffer is writable for its
            // advertised length.
            let written = unsafe {
                GetFinalPathNameByHandleW(
                    handle,
                    buffer.as_mut_ptr(),
                    u32::try_from(buffer.len()).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "resolved path is too long")
                    })?,
                    flags,
                )
            };
            if written == 0 {
                return Err(io::Error::last_os_error());
            }
            let written = usize::try_from(written).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "resolved path length overflow")
            })?;
            if written < buffer.len() {
                buffer.truncate(written);
                return Ok(std::path::PathBuf::from(std::ffi::OsString::from_wide(
                    &buffer,
                )));
            }
            capacity = written.saturating_add(1);
        }
    }

    #[cfg(test)]
    pub(super) fn short_path(path: &Path) -> io::Result<std::path::PathBuf> {
        let wide = wide(path);
        // SAFETY: The source is a live NUL-terminated UTF-16 buffer; a null
        // output buffer requests the required length.
        let needed = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetShortPathNameW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0_u16; usize::try_from(needed).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "short path length overflow")
        })?];
        // SAFETY: Both UTF-16 buffers remain live and the output length matches
        // the allocated buffer.
        let written = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetShortPathNameW(
                wide.as_ptr(),
                buffer.as_mut_ptr(),
                needed,
            )
        };
        if written == 0 {
            return Err(io::Error::last_os_error());
        }
        buffer.truncate(usize::try_from(written).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "short path length overflow")
        })?);
        Ok(std::path::PathBuf::from(std::ffi::OsString::from_wide(
            &buffer,
        )))
    }

    pub(super) fn copy_restrictive_dacl(source: &File, target: &File) -> io::Result<()> {
        let source_dacl = SecurityDacl::read(source)?;
        let dacl = source_dacl.dacl;
        // Copy the source's effective DACL and protect the copy from gaining
        // broader inherited ACEs after it becomes a sibling recovery artifact.
        // SAFETY: `dacl` remains valid while `source_dacl` is alive and `target`
        // owns a handle opened with `WRITE_DAC`.
        let status = unsafe {
            SetSecurityInfo(
                target.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null(),
            )
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(
                i32::try_from(status).unwrap_or(i32::MAX),
            ))
        }
    }

    pub(super) fn protect_restrictive_dacl(path: &Path) -> io::Result<()> {
        let file = open_dacl_no_follow(path)?;
        copy_restrictive_dacl(&file, &file)
    }

    #[cfg(test)]
    pub(super) fn dacl_bytes(file: &File) -> io::Result<Vec<u8>> {
        let dacl = SecurityDacl::read(file)?;
        // SAFETY: The ACL header belongs to the live descriptor and `AclSize`
        // is the complete validated allocation length returned by Windows.
        let bytes = unsafe {
            std::slice::from_raw_parts(dacl.dacl.cast::<u8>(), usize::from((*dacl.dacl).AclSize))
        };
        Ok(bytes.to_vec())
    }

    #[cfg(test)]
    pub(super) fn dacl_is_protected(file: &File) -> io::Result<bool> {
        let dacl = SecurityDacl::read(file)?;
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: The descriptor remains live and both output pointers are valid.
        let ok = unsafe {
            GetSecurityDescriptorControl(dacl.descriptor.0, &mut control, &mut revision)
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(control & SE_DACL_PROTECTED != 0)
        }
    }

    #[cfg(test)]
    pub(super) fn set_dacl_protection(path: &Path, protected: bool) -> io::Result<()> {
        let file = open_dacl_no_follow(path)?;
        let dacl = SecurityDacl::read(&file)?;
        let protection = if protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        // SAFETY: The DACL remains live through the call and the file handle was
        // opened with `WRITE_DAC`.
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | protection,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl.dacl,
                ptr::null(),
            )
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(
                i32::try_from(status).unwrap_or(i32::MAX),
            ))
        }
    }

    struct SecurityDacl {
        #[allow(
            dead_code,
            reason = "owns the allocation that keeps the borrowed DACL pointer valid"
        )]
        descriptor: LocalSecurityDescriptor,
        dacl: *mut ACL,
    }

    impl SecurityDacl {
        fn read(file: &File) -> io::Result<Self> {
            let mut dacl: *mut ACL = ptr::null_mut();
            let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
            // SAFETY: The handle remains live for the call. The returned
            // descriptor is owned by `LocalFree`, and `dacl` points into it.
            let status = unsafe {
                GetSecurityInfo(
                    file.as_raw_handle() as HANDLE,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut dacl,
                    ptr::null_mut(),
                    &mut descriptor,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(
                    i32::try_from(status).unwrap_or(i32::MAX),
                ));
            }
            let descriptor = LocalSecurityDescriptor(descriptor);
            if dacl.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "source configuration has a null DACL",
                ));
            }
            Ok(Self {
                descriptor,
                dacl,
            })
        }
    }

    pub(super) fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `GetSecurityInfo` allocated this descriptor and this
                // guard owns the only obligation to release it.
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }
}

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "ReplaceFileW and MoveFileExW have no safe standard equivalents"
)]
mod rename {
    use std::io;
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, ReplaceFileW};

    use super::platform::wide;

    pub(super) fn displace(
        replacement: &Path,
        destination: &Path,
        displaced: &Path,
    ) -> io::Result<()> {
        let destination = wide(destination);
        let replacement = wide(replacement);
        let displaced = wide(displaced);
        // SAFETY: All buffers are live NUL-terminated UTF-16 paths and the
        // reserved pointers are null as required by `ReplaceFileW`.
        let replaced = unsafe {
            ReplaceFileW(
                destination.as_ptr(),
                replacement.as_ptr(),
                displaced.as_ptr(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if replaced == 0 {
            // `ReplaceFileW` documents partial failure modes. The caller's
            // synchronized journal names every path, so nothing is removed here.
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
        let from = wide(from);
        let to = wide(to);
        // SAFETY: Both buffers are live NUL-terminated UTF-16 paths. Omitting
        // `MOVEFILE_REPLACE_EXISTING` makes an occupied destination fail.
        let moved = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) };
        if moved == 0 {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(80 | 183)) {
                Err(io::Error::new(io::ErrorKind::AlreadyExists, error))
            } else {
                Err(error)
            }
        } else {
            Ok(())
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::fs::File;
    use std::io;
    use std::path::Path;

    use super::ObjectIdentity;

    fn unsupported(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, message)
    }

    pub(super) fn open_lock_no_follow(_path: &Path) -> io::Result<File> {
        Err(unsupported(
            "no-follow lock opening is not available on this platform",
        ))
    }

    pub(super) fn create_new_no_follow(_path: &Path) -> io::Result<File> {
        Err(unsupported(
            "no-follow file creation is not available on this platform",
        ))
    }

    pub(super) fn open_no_follow(_path: &Path) -> io::Result<File> {
        Err(unsupported(
            "no-follow file opening is not available on this platform",
        ))
    }

    pub(super) fn identity_of_handle(_file: &File) -> io::Result<ObjectIdentity> {
        Err(unsupported(
            "filesystem object identity is not available on this platform",
        ))
    }

}

#[cfg(not(any(unix, windows)))]
mod rename {
    use std::io;
    use std::path::Path;

    pub(super) fn rename_no_replace(_from: &Path, _to: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic no-replace rename is not available on this platform",
        ))
    }
}

/// Opens or creates the advisory lock sentinel without following a final link.
pub(crate) fn open_lock_no_follow(path: &Path) -> io::Result<File> {
    platform::open_lock_no_follow(path)
}

/// Creates a new file without following a final link.
pub(crate) fn create_new_no_follow(path: &Path) -> io::Result<File> {
    platform::create_new_no_follow(path)
}

/// Opens a file or directory without following a final link.
pub(crate) fn open_no_follow(path: &Path) -> io::Result<File> {
    platform::open_no_follow(path)
}

/// Reads the volume-unique identity behind an open handle.
pub(crate) fn identity_of_handle(file: &File) -> io::Result<ObjectIdentity> {
    platform::identity_of_handle(file)
}

/// Reads the identity of the object currently named by `path`.
pub(crate) fn identity_of_path(path: &Path) -> io::Result<ObjectIdentity> {
    identity_of_handle(&open_no_follow(path)?)
}

/// Returns the normalized final Windows path behind an existing no-follow handle.
#[cfg(windows)]
pub(crate) fn final_path_of_handle(file: &File) -> io::Result<std::path::PathBuf> {
    platform::final_path_of_handle(file)
}

/// Flushes a Unix directory entry set to stable storage.
#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    platform::sync_directory(path)
}

/// Copies the source file's effective DACL to a Windows recovery artifact and
/// protects the copy from gaining inherited access.
#[cfg(windows)]
pub(crate) fn copy_restrictive_dacl(source: &File, target: &File) -> io::Result<()> {
    platform::copy_restrictive_dacl(source, target)
}

#[cfg(windows)]
pub(crate) fn protect_restrictive_dacl(path: &Path) -> io::Result<()> {
    platform::protect_restrictive_dacl(path)
}

#[cfg(all(windows, test))]
pub(crate) fn dacl_bytes(file: &File) -> io::Result<Vec<u8>> {
    platform::dacl_bytes(file)
}

#[cfg(all(windows, test))]
pub(crate) fn dacl_is_protected(file: &File) -> io::Result<bool> {
    platform::dacl_is_protected(file)
}

#[cfg(all(windows, test))]
pub(crate) fn short_path(path: &Path) -> io::Result<std::path::PathBuf> {
    platform::short_path(path)
}

#[cfg(all(windows, test))]
pub(crate) fn set_dacl_protection(path: &Path, protected: bool) -> io::Result<()> {
    platform::set_dacl_protection(path, protected)
}

/// Atomically displaces `destination` while publishing `replacement`.
///
/// Unix uses one exchange path, so `displaced` must equal `replacement`.
/// Windows uses `ReplaceFileW` and requires a distinct absent displacement path.
pub(crate) fn displace_file(
    replacement: &Path,
    destination: &Path,
    displaced: &Path,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        if replacement != displaced {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unix displacement must reuse the replacement path",
            ));
        }
        return rename::exchange(replacement, destination);
    }
    #[cfg(windows)]
    {
        return rename::displace(replacement, destination, displaced);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (replacement, destination, displaced);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic file displacement is not available on this platform",
        ))
    }
}

/// Atomically renames `from` to absent `to`.
pub(crate) fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    rename::rename_no_replace(from, to)
}

#[cfg(test)]
mod tests {
    use super::ObjectIdentity;

    #[test]
    fn full_width_object_identity_round_trips_through_the_recovery_format() {
        let identity = ObjectIdentity {
            volume: u64::MAX,
            object: [u8::MAX; 16],
        };

        let encoded = serde_json::to_vec(&identity).expect("encode full-width identity");
        let decoded: ObjectIdentity =
            serde_json::from_slice(&encoded).expect("decode full-width identity");

        assert_eq!(decoded, identity);
    }
}
