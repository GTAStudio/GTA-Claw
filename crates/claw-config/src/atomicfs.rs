//! Platform primitives for compare-and-swap publication.
//!
//! Configuration is published by *displacing* the object that currently occupies
//! the destination, not by renaming over it. The shared advisory lock only
//! orders writers that agreed to take it; a text editor, an installer, or any
//! other process that simply writes the file does not, and a digest read a
//! moment before an unconditional rename cannot see that write at all.
//!
//! [`exchange_paths`] closes that window: it swaps the temporary file with the
//! destination in one atomic step, so the object that was replaced is reachable
//! at the temporary path and can be compared against what the caller expected.
//! The destination holds either the old object or the new one at every instant.
//! [`rename_no_replace`] is the same guarantee for a destination that must not
//! exist yet.
//!
//! Where a platform cannot provide these operations the functions return
//! [`io::ErrorKind::Unsupported`] rather than degrading to a blind rename,
//! because a caller that believed it had performed a compare-and-swap would
//! report a guarantee it never had. [`sync_directory`] follows the same rule and
//! reports the operating-system failure instead of returning success from a
//! no-op.

use std::fs::File;
use std::io;
use std::path::Path;

/// Volume-unique identity of one filesystem object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObjectIdentity {
    volume: u64,
    object: u128,
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
            object: u128::from(metadata.ino()),
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
    reason = "atomic exchange and no-replace rename are only reachable through the renameat2 \
              system call, which has no safe std equivalent; the crate denies unsafe everywhere \
              else so these call sites stay an audited FFI surface"
)]
mod rename {
    use std::io;
    use std::path::Path;

    use super::platform::c_path;

    fn rename_with_flags(first: &Path, second: &Path, flags: u32) -> io::Result<()> {
        let first = c_path(first)?;
        let second = c_path(second)?;
        // SAFETY: both arguments are NUL-terminated C strings that outlive the
        // call, and `AT_FDCWD` resolves the relative paths exactly as the safe
        // `std::fs::rename` would.
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

    pub(super) fn exchange_paths(first: &Path, second: &Path) -> io::Result<()> {
        rename_with_flags(first, second, libc::RENAME_EXCHANGE)
    }

    pub(super) fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
        rename_with_flags(from, to, libc::RENAME_NOREPLACE)
    }
}

#[cfg(all(unix, target_vendor = "apple"))]
#[expect(
    unsafe_code,
    reason = "atomic exchange and no-replace rename are only reachable through renamex_np, which \
              has no safe std equivalent; the crate denies unsafe everywhere else so these call \
              sites stay an audited FFI surface"
)]
mod rename {
    use std::io;
    use std::path::Path;

    use super::platform::c_path;

    fn rename_with_flags(first: &Path, second: &Path, flags: libc::c_uint) -> io::Result<()> {
        let first = c_path(first)?;
        let second = c_path(second)?;
        // SAFETY: both arguments are NUL-terminated C strings that outlive the
        // call, and the flags are the documented `renamex_np` constants.
        let result = unsafe { libc::renamex_np(first.as_ptr(), second.as_ptr(), flags) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn exchange_paths(first: &Path, second: &Path) -> io::Result<()> {
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

    pub(super) fn exchange_paths(_first: &Path, _second: &Path) -> io::Result<()> {
        Err(super::unsupported(
            "atomic path exchange is not available on this platform",
        ))
    }

    pub(super) fn rename_no_replace(_from: &Path, _to: &Path) -> io::Result<()> {
        Err(super::unsupported(
            "atomic no-replace rename is not available on this platform",
        ))
    }
}

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "reparse-safe identity and no-replace rename are only reachable through \
              GetFileInformationByHandle and MoveFileExW, neither of which has a safe std \
              equivalent; the crate denies unsafe everywhere else so this module stays an \
              audited FFI surface"
)]
mod platform {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_WRITE_THROUGH, GetFileInformationByHandle,
    };

    use super::ObjectIdentity;

    /// Opens the advisory lock sentinel without ever traversing a reparse point.
    ///
    /// `FILE_FLAG_OPEN_REPARSE_POINT` makes the open fail on a symbolic link or
    /// junction planted at the final component instead of silently following it
    /// somewhere else, which is the Windows counterpart of `O_NOFOLLOW`.
    pub(super) fn open_lock_no_follow(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    pub(super) fn create_new_no_follow(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH)
            .open(path)
    }

    pub(super) fn open_no_follow(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    pub(super) fn identity_of_handle(file: &File) -> io::Result<ObjectIdentity> {
        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: the handle is owned by `file` and stays open for the call, and
        // the output buffer is a correctly sized, writable structure.
        let ok = unsafe {
            GetFileInformationByHandle(file.as_raw_handle() as HANDLE, information.as_mut_ptr())
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call reported success, so the structure is initialized.
        let information = unsafe { information.assume_init() };
        Ok(ObjectIdentity {
            volume: u64::from(information.dwVolumeSerialNumber),
            object: (u128::from(information.nFileIndexHigh) << 32)
                | u128::from(information.nFileIndexLow),
        })
    }

    /// Attempts to flush a directory's metadata.
    ///
    /// Windows exposes no documented way to force a directory entry to stable
    /// storage: `FlushFileBuffers` needs write access that `CreateFileW` refuses
    /// for directories on NTFS. The attempt is made through a backup-semantics
    /// handle and whatever the operating system reports is returned unchanged,
    /// so a refusal is surfaced as a durability warning rather than mistaken for
    /// a durable flush. File data itself is covered separately, because every
    /// temporary file is opened `FILE_FLAG_WRITE_THROUGH`.
    pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?
            .sync_all()
    }

    pub(super) fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
}

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "see the audited FFI note on the Windows platform module"
)]
mod rename {
    use std::io;
    use std::path::Path;

    use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

    use std::fs;
    use std::ptr;
    use std::sync::atomic::{AtomicU64, Ordering};

    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    use super::platform::wide;

    static DISPLACEMENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    /// Emulates an atomic exchange through `ReplaceFileW`.
    ///
    /// `ReplaceFileW` publishes `first` over `second` and writes `second`'s
    /// previous object to a reserved third path in one operation, preserving the
    /// destination's ACLs, attributes, creation time, named streams, encryption
    /// and compression. The displaced object is then moved back onto `first` so
    /// callers see the same post-conditions as the Unix exchange. `second` names
    /// either the old object or the new one at every instant.
    pub(super) fn exchange_paths(first: &Path, second: &Path) -> io::Result<()> {
        let displaced = reserve_displacement(second)?;
        let second_wide = wide(second);
        let first_wide = wide(first);
        let displaced_wide = wide(&displaced);
        // SAFETY: all three buffers are valid, NUL-terminated UTF-16 paths that
        // outlive the call, and the reserved pointers are null as documented.
        let replaced = unsafe {
            ReplaceFileW(
                second_wide.as_ptr(),
                first_wide.as_ptr(),
                displaced_wide.as_ptr(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if replaced == 0 {
            let error = io::Error::last_os_error();
            let _ = fs::remove_file(&displaced);
            return Err(error);
        }
        fs::rename(&displaced, first).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "published the replacement but could not return the displaced object to {}: \
                     {error}; the displaced object remains at {}",
                    first.display(),
                    displaced.display()
                ),
            )
        })
    }

    fn reserve_displacement(destination: &Path) -> io::Result<std::path::PathBuf> {
        for _ in 0..128 {
            let sequence = DISPLACEMENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = format!(
                ".{}.gta-claw.displaced.{}.{sequence}",
                destination
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("config"),
                std::process::id()
            );
            let path = destination.with_file_name(name);
            if !path.try_exists()? {
                return Ok(path);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique displacement path",
        ))
    }

    pub(super) fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
        let from_wide = wide(from);
        let to_wide = wide(to);
        // SAFETY: both buffers are valid, NUL-terminated UTF-16 paths that
        // outlive the call. Omitting `MOVEFILE_REPLACE_EXISTING` makes the move
        // fail rather than clobber an existing destination.
        let moved = unsafe { MoveFileExW(from_wide.as_ptr(), to_wide.as_ptr(), 0) };
        if moved == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::fs::File;
    use std::io;
    use std::path::Path;

    use super::{ObjectIdentity, unsupported};

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
            "no-follow opening is not available on this platform",
        ))
    }

    pub(super) fn identity_of_handle(_file: &File) -> io::Result<ObjectIdentity> {
        Err(unsupported(
            "filesystem object identity is not available on this platform",
        ))
    }

    pub(super) fn sync_directory(_path: &Path) -> io::Result<()> {
        Err(unsupported(
            "durable directory synchronization is not available on this platform",
        ))
    }
}

#[cfg(not(any(unix, windows)))]
mod rename {
    use std::io;
    use std::path::Path;

    pub(super) fn exchange_paths(_first: &Path, _second: &Path) -> io::Result<()> {
        Err(super::unsupported(
            "atomic path exchange is not available on this platform",
        ))
    }

    pub(super) fn rename_no_replace(_from: &Path, _to: &Path) -> io::Result<()> {
        Err(super::unsupported(
            "atomic no-replace rename is not available on this platform",
        ))
    }
}

/// Refuses an operation the platform cannot perform, instead of approximating it.
#[cfg(not(any(
    windows,
    all(
        unix,
        any(target_os = "linux", target_os = "android", target_vendor = "apple")
    )
)))]
fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

/// Opens or creates the advisory lock sentinel without following a link.
pub(crate) fn open_lock_no_follow(path: &Path) -> io::Result<File> {
    platform::open_lock_no_follow(path)
}

/// Creates and opens `path`, refusing to traverse a link at the final component.
pub(crate) fn create_new_no_follow(path: &Path) -> io::Result<File> {
    platform::create_new_no_follow(path)
}

/// Reads the volume-unique identity behind an open handle.
pub(crate) fn identity_of_handle(file: &File) -> io::Result<ObjectIdentity> {
    platform::identity_of_handle(file)
}

/// Reads the volume-unique identity of whatever `path` names right now, without
/// following a link at the final component.
pub(crate) fn identity_of_path(path: &Path) -> io::Result<ObjectIdentity> {
    identity_of_handle(&platform::open_no_follow(path)?)
}

/// Flushes a directory's entries to stable storage.
pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    platform::sync_directory(path)
}

/// Atomically exchanges the objects at `first` and `second`.
///
/// Both paths must exist. After a successful call each path names the object the
/// other one named before, so a caller that staged new bytes at `first` can
/// inspect the exact object it displaced from `second`.
pub(crate) fn exchange_paths(first: &Path, second: &Path) -> io::Result<()> {
    rename::exchange_paths(first, second)
}

/// Atomically renames `from` onto `to`, refusing to replace an existing object.
pub(crate) fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    rename::rename_no_replace(from, to)
}
