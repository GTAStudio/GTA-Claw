//! Platform primitives for compare-and-swap publication.
//!
//! Migration publishes by *displacing* the object that currently occupies a
//! target rather than by renaming over it blindly. A blind `rename` is atomic
//! but unconditional: two applies that both verified the same prior bytes would
//! each overwrite the other, and the second one would silently destroy the
//! first one's published bytes. The primitives here bind the comparison to the
//! displacement itself, so the object that was replaced is the object that gets
//! inspected.
//!
//! [`exchange_paths`] is the compare half: it swaps two existing paths in one
//! atomic step, which leaves the previous occupant of the target reachable at
//! the staging path where its digest can be compared against the value the
//! caller expected. Both halves of the swap are always occupied, so a crash at
//! any instant leaves the target holding either the old object or the new one.
//! [`rename_no_replace`] is the same idea for a target that must not exist yet.
//!
//! Neither operation has a portable implementation. Where the platform cannot
//! provide it the functions return [`io::ErrorKind::Unsupported`] instead of
//! degrading to a blind rename, because a caller that believed it had performed
//! a compare-and-swap would report a durability guarantee it never had.
//!
//! Directory synchronization follows the same rule: [`sync_directory`] reports
//! the operating-system failure rather than returning success from a no-op.

use std::fs::File;
use std::io;
use std::path::Path;

/// Volume-unique identity of one filesystem object.
///
/// Used to prove that a handle opened earlier still refers to the object a path
/// currently names, so a staging file cannot be swapped for another object
/// between reservation and publication.
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
              else so these two call sites are the whole audited FFI surface"
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
              has no safe std equivalent; the crate denies unsafe everywhere else so these two \
              call sites are the whole audited FFI surface"
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
    reason = "reparse-safe identity, no-replace rename and replace-with-backup publication are \
              only reachable through GetFileInformationByHandle, MoveFileExW and ReplaceFileW, \
              none of which has a safe std equivalent; the crate denies unsafe everywhere else \
              so this module is the whole audited FFI surface"
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
        // the output buffer is a correctly sized, writable `BY_HANDLE_FILE_INFORMATION`.
        let ok = unsafe {
            GetFileInformationByHandle(file.as_raw_handle() as HANDLE, information.as_mut_ptr())
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `GetFileInformationByHandle` reported success, so it fully
        // initialized the structure.
        let information = unsafe { information.assume_init() };
        Ok(ObjectIdentity {
            volume: u64::from(information.dwVolumeSerialNumber),
            object: (u128::from(information.nFileIndexHigh) << 32)
                | u128::from(information.nFileIndexLow),
        })
    }

    /// Flushes a directory's metadata.
    ///
    /// Windows exposes no documented way to force a directory entry to stable
    /// storage; `FlushFileBuffers` needs write access that `CreateFileW` refuses
    /// for directories on NTFS. The attempt is made through a backup-semantics
    /// handle, and whatever the operating system reports is returned unchanged
    /// so that a caller never mistakes a refusal for a durable flush. Data
    /// blocks themselves are covered separately, because every staged file is
    /// opened `FILE_FLAG_WRITE_THROUGH`.
    pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
        let handle = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        handle.sync_all()
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
    use std::fs;
    use std::io;
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, ReplaceFileW};

    use std::sync::atomic::{AtomicU64, Ordering};

    use super::platform::wide;
    use super::unsupported;

    static DISPLACEMENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    /// Emulates an atomic exchange for regular files.
    ///
    /// `ReplaceFileW` publishes `first` over `second` and writes `second`'s
    /// previous contents to a reserved third path in one operation, preserving
    /// the destination's ACLs, attributes, creation time, named streams,
    /// encryption and compression. The displaced object is then moved back onto
    /// `first` so callers observe the same post-conditions as the Unix
    /// exchange. `second` is occupied by either the old object or the new one at
    /// every instant, which is the property publication depends on.
    ///
    /// Windows has no equivalent for directories, so a directory exchange is
    /// refused rather than approximated.
    pub(super) fn exchange_paths(first: &Path, second: &Path) -> io::Result<()> {
        if fs::symlink_metadata(second)?.is_dir() || fs::symlink_metadata(first)?.is_dir() {
            return Err(unsupported(
                "atomic directory exchange is not available on Windows",
            ));
        }
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
            // `ReplaceFileW` failed, so nothing was published and the reservation
            // holds nothing worth keeping.
            let _ = fs::remove_file(&displaced);
            return Err(error);
        }
        // The displaced object is now the only copy of what `second` held. It is
        // never deleted on failure: the error names where it is so the caller can
        // recover it, because deleting it would turn a failed exchange into data
        // loss.
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
                ".{}.migration-displaced.{}.{sequence}",
                destination
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("target"),
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
#[cfg(not(all(
    unix,
    any(target_os = "linux", target_os = "android", target_vendor = "apple")
)))]
fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

/// Creates and opens `path`, refusing to traverse a link at the final component.
pub(crate) fn create_new_no_follow(path: &Path) -> io::Result<File> {
    platform::create_new_no_follow(path)
}

/// Opens an existing file or directory, refusing to traverse a link at the
/// final component.
pub(crate) fn open_no_follow(path: &Path) -> io::Result<File> {
    platform::open_no_follow(path)
}

/// Reads the volume-unique identity behind an open handle.
pub(crate) fn identity_of_handle(file: &File) -> io::Result<ObjectIdentity> {
    platform::identity_of_handle(file)
}

/// Reads the volume-unique identity of whatever `path` names right now, without
/// following a link at the final component.
pub(crate) fn identity_of_path(path: &Path) -> io::Result<ObjectIdentity> {
    identity_of_handle(&open_no_follow(path)?)
}

/// Flushes a directory's entries to stable storage.
///
/// Returns the operating-system failure when the platform cannot honour the
/// request; the caller must not treat that as a durable write.
pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    platform::sync_directory(path)
}

/// Atomically exchanges the objects at `first` and `second`.
///
/// Both paths must exist. After a successful call each path names the object the
/// other one named before, so a caller that staged new bytes at `first` can
/// inspect the exact object it displaced from `second`.
///
/// Returns [`io::ErrorKind::Unsupported`] when the platform or filesystem cannot
/// perform the exchange, rather than falling back to an unconditional rename.
pub(crate) fn exchange_paths(first: &Path, second: &Path) -> io::Result<()> {
    rename::exchange_paths(first, second)
}

/// Atomically renames `from` onto `to`, refusing to replace an existing object.
///
/// Returns [`io::ErrorKind::AlreadyExists`] when `to` is occupied, and
/// [`io::ErrorKind::Unsupported`] when the platform cannot perform the check
/// atomically.
pub(crate) fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    rename::rename_no_replace(from, to)
}
