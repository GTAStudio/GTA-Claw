//! Genuine sandbox-escape attempts against a real temporary directory tree.
//!
//! Every case here builds the escape on disk — a real file outside the root, a
//! real symbolic link, a real Windows junction — and then asks the sandbox to
//! resolve it. Nothing is mocked, and every assertion names the exact refusal.

mod common;

use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use claw_tools::sandbox::{Sandbox, SandboxError, SandboxLimits, WriteMode};

use common::{TempTree, remove_dir_link, try_junction, try_symlink_dir, try_symlink_file};

/// Builds a workspace root with a sibling directory holding a secret file.
///
/// The secret is real: any escape that resolves reads attacker-visible data
/// that lives outside the workspace.
fn workspace() -> (TempTree, Sandbox) {
    let tree = TempTree::new("escape");
    tree.dir("workspace");
    tree.dir("outside");
    tree.write("outside/secret.txt", "TOP-SECRET-OUTSIDE-THE-ROOT");
    tree.write("workspace/notes.txt", "inside the workspace");
    tree.dir("workspace/src");
    let sandbox = Sandbox::new(&tree.join("workspace"), SandboxLimits::default())
        .expect("workspace root is adoptable");
    (tree, sandbox)
}

#[test]
fn the_sibling_secret_really_exists_outside_the_root() {
    let (tree, sandbox) = workspace();
    assert!(
        tree.exists("outside/secret.txt"),
        "the escape target must exist or these tests prove nothing"
    );
    let secret = fs::canonicalize(tree.join("outside/secret.txt")).expect("canonicalizable");
    let root = fs::canonicalize(sandbox.root()).expect("canonicalizable");
    assert!(
        !secret.starts_with(&root),
        "the secret at {secret:?} must live outside {root:?}"
    );
    assert_eq!(
        tree.read("outside/secret.txt"),
        "TOP-SECRET-OUTSIDE-THE-ROOT"
    );
}

#[test]
fn parent_traversal_is_refused_in_every_position() {
    let (_tree, sandbox) = workspace();
    for candidate in [
        "../outside/secret.txt",
        "..\\outside\\secret.txt",
        "src/../../outside/secret.txt",
        "src/..",
        "..",
        "...",
        "src/.../../outside/secret.txt",
    ] {
        assert_eq!(
            sandbox.relative(candidate),
            Err(SandboxError::ParentTraversalForbidden),
            "traversal accepted for {candidate:?}"
        );
    }
}

#[test]
fn current_directory_components_are_refused() {
    let (_tree, sandbox) = workspace();
    for candidate in ["./notes.txt", "src/./notes.txt", "."] {
        assert_eq!(
            sandbox.relative(candidate),
            Err(SandboxError::CurrentDirectoryComponentForbidden),
            "dot component accepted for {candidate:?}"
        );
    }
}

#[test]
fn absolute_drive_unc_and_home_paths_are_refused() {
    let (_tree, sandbox) = workspace();
    for candidate in [
        "/etc/passwd",
        "\\Windows\\win.ini",
        "C:\\Windows\\win.ini",
        "c:/Windows/win.ini",
        "\\\\server\\share\\payload.txt",
        "//server/share/payload.txt",
        "~/.ssh/id_rsa",
    ] {
        assert_eq!(
            sandbox.relative(candidate),
            Err(SandboxError::AbsolutePathForbidden),
            "absolute form accepted for {candidate:?}"
        );
    }
}

#[test]
fn the_real_absolute_path_of_the_secret_is_refused() {
    let (tree, sandbox) = workspace();
    let absolute = tree
        .join("outside/secret.txt")
        .to_str()
        .expect("temporary paths are UTF-8")
        .to_owned();
    let error = sandbox
        .relative(&absolute)
        .expect_err("an absolute path must never resolve");
    assert!(
        matches!(
            error,
            SandboxError::AbsolutePathForbidden | SandboxError::AlternateDataStreamForbidden
        ),
        "unexpected refusal {error:?} for {absolute:?}"
    );
}

#[test]
fn alternate_data_stream_syntax_is_refused() {
    let (_tree, sandbox) = workspace();
    for candidate in [
        "notes.txt:hidden",
        "notes.txt:$DATA",
        "notes.txt::$INDEX_ALLOCATION",
        "src/file:stream:$DATA",
    ] {
        assert_eq!(
            sandbox.relative(candidate),
            Err(SandboxError::AlternateDataStreamForbidden),
            "stream syntax accepted for {candidate:?}"
        );
    }
}

#[test]
fn reserved_device_names_are_refused_on_every_platform() {
    let (_tree, sandbox) = workspace();
    for candidate in [
        "CON",
        "con",
        "NUL",
        "nul.txt",
        "COM1",
        "com9.log",
        "LPT1",
        "lpt3.dat",
        "AUX",
        "PRN",
        "CONIN$",
        "CONOUT$",
        "src/NUL",
        "src/com1.txt",
    ] {
        assert_eq!(
            sandbox.relative(candidate),
            Err(SandboxError::ReservedDeviceName),
            "device name accepted for {candidate:?}"
        );
    }
}

#[test]
fn trailing_dots_and_spaces_are_refused() {
    let (_tree, sandbox) = workspace();
    for candidate in ["notes.txt.", "notes.txt ", " notes.txt", "src /notes.txt"] {
        assert_eq!(
            sandbox.relative(candidate),
            Err(SandboxError::TrailingDotOrSpace),
            "trailing dot or space accepted for {candidate:?}"
        );
    }
}

#[test]
fn control_characters_and_wildcards_are_refused() {
    let (_tree, sandbox) = workspace();
    assert_eq!(
        sandbox.relative("notes\u{0}.txt"),
        Err(SandboxError::ControlCharacter)
    );
    assert_eq!(
        sandbox.relative("notes\n.txt"),
        Err(SandboxError::ControlCharacter)
    );
    for candidate in ["*.txt", "src/?.txt", "a<b", "a>b", "a|b", "a\"b"] {
        assert_eq!(
            sandbox.relative(candidate),
            Err(SandboxError::InvalidCharacter),
            "invalid character accepted for {candidate:?}"
        );
    }
}

#[test]
fn empty_components_and_oversized_paths_are_refused() {
    let (_tree, sandbox) = workspace();
    assert_eq!(sandbox.relative(""), Err(SandboxError::EmptyPath));
    assert_eq!(
        sandbox.relative("src//notes.txt"),
        Err(SandboxError::EmptyComponent)
    );
    assert_eq!(
        sandbox.relative(&"a".repeat(300)),
        Err(SandboxError::ComponentTooLong)
    );
    let deep: String = (0..64).map(|_| "d/").collect::<String>() + "file.txt";
    assert_eq!(
        sandbox.relative(&deep),
        Err(SandboxError::TooManyComponents)
    );
}

#[test]
fn a_symlinked_file_pointing_outside_the_root_is_refused() {
    let (tree, sandbox) = workspace();
    let created = try_symlink_file(
        &tree.join("outside/secret.txt"),
        &tree.join("workspace/leak.txt"),
    );
    if !created {
        // Unprivileged Windows hosts cannot create symbolic links. The
        // junction test below covers the escape that is actually buildable
        // there.
        return;
    }
    assert!(
        tree.exists("workspace/leak.txt"),
        "the link must really exist for this to be a real escape"
    );
    let path = sandbox
        .relative("leak.txt")
        .expect("the name itself is legal");
    assert_eq!(
        sandbox.resolve_file(&path),
        Err(SandboxError::SymlinkForbidden)
    );
    assert_eq!(
        sandbox.read_file(&path),
        Err(SandboxError::SymlinkForbidden)
    );
    assert_eq!(
        sandbox.write_file(&path, b"overwritten", WriteMode::Overwrite),
        Err(SandboxError::SymlinkForbidden)
    );
    assert_eq!(
        tree.read("outside/secret.txt"),
        "TOP-SECRET-OUTSIDE-THE-ROOT",
        "the refused write must not have reached the link target"
    );
}

#[test]
fn a_symlinked_directory_in_the_middle_of_a_path_is_refused() {
    let (tree, sandbox) = workspace();
    let created = try_symlink_dir(&tree.join("outside"), &tree.join("workspace/bridge"));
    if !created {
        return;
    }
    let path = sandbox
        .relative("bridge/secret.txt")
        .expect("the name itself is legal");
    assert_eq!(
        sandbox.read_file(&path),
        Err(SandboxError::SymlinkForbidden)
    );
    assert_eq!(
        sandbox.resolve_directory(
            &sandbox
                .relative("bridge")
                .expect("the name itself is legal")
        ),
        Err(SandboxError::SymlinkForbidden)
    );
    assert_eq!(
        sandbox.write_file(
            &sandbox
                .relative("bridge/planted.txt")
                .expect("the name itself is legal"),
            b"planted",
            WriteMode::Overwrite
        ),
        Err(SandboxError::SymlinkForbidden)
    );
    assert!(
        !tree.exists("outside/planted.txt"),
        "the refused write must not have crossed the link"
    );
}

#[test]
fn a_windows_junction_pointing_outside_the_root_is_refused() {
    let (tree, sandbox) = workspace();
    let created = try_junction(&tree.join("outside"), &tree.join("workspace/junction"));
    if !created {
        // Junctions only exist on Windows.
        return;
    }
    let path = sandbox
        .relative("junction/secret.txt")
        .expect("the name itself is legal");
    assert_eq!(
        sandbox.read_file(&path),
        Err(SandboxError::SymlinkForbidden)
    );
    assert_eq!(
        sandbox.write_file(&path, b"clobbered", WriteMode::Overwrite),
        Err(SandboxError::SymlinkForbidden)
    );
    assert_eq!(
        tree.read("outside/secret.txt"),
        "TOP-SECRET-OUTSIDE-THE-ROOT",
        "the refused write must not have reached the junction target"
    );
    // The junction is visible to a listing but reported as a link, never
    // walked into.
    let notes = sandbox.relative("notes.txt").expect("legal name");
    assert_eq!(
        String::from_utf8(sandbox.read_file(&notes).expect("readable")).expect("utf-8"),
        "inside the workspace"
    );
    let root = sandbox.resolve_root();
    let walked = sandbox
        .walk_files(root.relative())
        .expect("a walk of the root succeeds");
    assert!(
        walked
            .iter()
            .all(|found| !found.as_str().contains("junction")),
        "the walk crossed a junction: {walked:?}"
    );
}

#[test]
fn a_link_planted_after_validation_still_cannot_be_read() {
    // The final-component no-follow open is what closes the window between
    // the metadata check and the read.
    let (tree, sandbox) = workspace();
    let created = try_symlink_file(
        &tree.join("outside/secret.txt"),
        &tree.join("workspace/late.txt"),
    );
    if !created {
        return;
    }
    let path = sandbox.relative("late.txt").expect("legal name");
    let error = sandbox
        .read_file(&path)
        .expect_err("a link must not be read");
    assert_eq!(error, SandboxError::SymlinkForbidden);
}

#[test]
fn case_insensitive_collisions_are_refused_on_write() {
    let (tree, sandbox) = workspace();
    tree.write("workspace/Report.md", "original");
    let shadow = sandbox.relative("report.md").expect("legal name");
    assert_eq!(
        sandbox.write_file(&shadow, b"shadow", WriteMode::CreateNew),
        Err(SandboxError::CaseCollision)
    );
    // An overwrite must not be a way around the same check.
    assert_eq!(
        sandbox.write_file(&shadow, b"shadow", WriteMode::Overwrite),
        Err(SandboxError::CaseCollision)
    );
    assert_eq!(
        tree.read("workspace/Report.md"),
        "original",
        "the original file must be untouched"
    );
    // The exactly cased name still works, so the check is not a blanket ban.
    let exact = sandbox.relative("Report.md").expect("legal name");
    sandbox
        .write_file(&exact, b"revised", WriteMode::Overwrite)
        .expect("an exactly cased overwrite is legitimate");
    assert_eq!(tree.read("workspace/Report.md"), "revised");
}

#[test]
fn reading_through_the_wrong_case_never_silently_succeeds() {
    let (tree, sandbox) = workspace();
    tree.write("workspace/Report.md", "original");
    let path = sandbox.relative("REPORT.MD").expect("legal name");
    let error = sandbox
        .read_file(&path)
        .expect_err("a mis-cased name must never resolve to the real file");
    // Case-insensitive filesystems resolve the name and are caught by the
    // canonical re-verification; case-sensitive ones simply have no such file.
    assert!(
        matches!(error, SandboxError::CaseMismatch | SandboxError::NotFound),
        "unexpected refusal {error:?}"
    );
}

#[test]
fn a_file_above_the_size_limit_is_refused_in_both_directions() {
    let tree = TempTree::new("limits");
    tree.dir("workspace");
    let limits = SandboxLimits {
        max_file_bytes: 64,
        ..SandboxLimits::default()
    };
    let sandbox =
        Sandbox::new(&tree.join("workspace"), limits).expect("workspace root is adoptable");

    tree.write("workspace/big.txt", &"x".repeat(65));
    let big = sandbox.relative("big.txt").expect("legal name");
    assert_eq!(sandbox.read_file(&big), Err(SandboxError::FileTooLarge));

    let target = sandbox.relative("written.txt").expect("legal name");
    assert_eq!(
        sandbox.write_file(&target, &[b'y'; 65], WriteMode::CreateNew),
        Err(SandboxError::FileTooLarge)
    );
    assert!(
        !tree.exists("workspace/written.txt"),
        "an oversized write must not create the file"
    );

    let small = sandbox.relative("small.txt").expect("legal name");
    sandbox
        .write_file(&small, &[b'z'; 64], WriteMode::CreateNew)
        .expect("a file at the limit is accepted");
    assert_eq!(sandbox.read_file(&small).expect("readable").len(), 64);
}

#[test]
fn directory_and_walk_counts_are_bounded() {
    let tree = TempTree::new("counts");
    tree.dir("workspace/many");
    for index in 0..12 {
        tree.write(&format!("workspace/many/file{index}.txt"), "x");
    }
    let limits = SandboxLimits {
        max_directory_entries: 5,
        max_walked_files: 4,
        ..SandboxLimits::default()
    };
    let sandbox =
        Sandbox::new(&tree.join("workspace"), limits).expect("workspace root is adoptable");
    let many = sandbox.relative("many").expect("legal name");
    assert_eq!(
        sandbox.read_directory(&many),
        Err(SandboxError::DirectoryTooLarge)
    );
    assert_eq!(
        sandbox.walk_files(&many),
        Err(SandboxError::DirectoryTooLarge)
    );
}

#[test]
fn legitimate_paths_still_resolve_to_the_expected_file() {
    // A confinement layer that refuses everything is useless; this proves the
    // ordinary path still works and lands exactly where it should.
    let (tree, sandbox) = workspace();
    tree.write("workspace/src/main.rs", "fn main() {}\n");
    let path = sandbox.relative("src/main.rs").expect("legal name");
    assert_eq!(path.as_str(), "src/main.rs");
    let resolved = sandbox.resolve_file(&path).expect("resolvable");
    assert_eq!(
        fs::canonicalize(resolved.absolute()).expect("canonicalizable"),
        fs::canonicalize(tree.join("workspace/src/main.rs")).expect("canonicalizable")
    );
    assert_eq!(
        String::from_utf8(sandbox.read_file(&path).expect("readable")).expect("utf-8"),
        "fn main() {}\n"
    );
    let written = sandbox
        .write_file(
            &sandbox.relative("src/new.rs").expect("legal name"),
            b"pub fn added() {}\n",
            WriteMode::CreateNew,
        )
        .expect("writable");
    assert_eq!(written.relative().as_str(), "src/new.rs");
    assert_eq!(tree.read("workspace/src/new.rs"), "pub fn added() {}\n");
}

#[test]
fn backslash_separated_paths_normalize_to_forward_slashes() {
    let (tree, sandbox) = workspace();
    tree.write("workspace/src/lib.rs", "content");
    let path = sandbox.relative("src\\lib.rs").expect("legal name");
    assert_eq!(path.as_str(), "src/lib.rs");
    assert_eq!(path.components(), ["src".to_owned(), "lib.rs".to_owned()]);
    assert_eq!(
        String::from_utf8(sandbox.read_file(&path).expect("readable")).expect("utf-8"),
        "content"
    );
}

#[test]
fn a_root_that_is_a_file_is_refused() {
    let tree = TempTree::new("rootfile");
    tree.write("not-a-directory", "content");
    assert_eq!(
        Sandbox::new(&tree.join("not-a-directory"), SandboxLimits::default()),
        Err(SandboxError::RootNotADirectory)
    );
}

#[test]
fn a_parent_swapped_after_validation_never_gets_the_write() {
    // The audited failure: validation approved a parent directory, and the
    // write then reopened the ORIGINAL pathname, so a parent swapped in
    // between decided where the bytes landed. Here the swap happens after a
    // successful validation and before the write, which is exactly that
    // window, and the file outside the root must be untouched.
    let (tree, sandbox) = workspace();
    let real_parent = tree.dir("workspace/sub");
    fs::write(tree.join("outside/target.txt"), "ORIGINAL-OUTSIDE-CONTENT")
        .expect("outside file is writable");
    let path = sandbox.relative("sub/target.txt").expect("legal name");

    // Validation succeeds against the honest directory.
    sandbox
        .resolve_for_write(&path, WriteMode::Overwrite)
        .expect("an honest parent validates");

    // The attacker now replaces the approved parent with a link out of the
    // root. Nothing about the pathname changed.
    fs::remove_dir_all(&real_parent).expect("the real parent is removable");
    let swapped = try_symlink_dir(&tree.join("outside"), &real_parent)
        || try_junction(&tree.join("outside"), &real_parent);
    if !swapped {
        return;
    }

    let error = sandbox
        .write_file(&path, b"ATTACKER-CONTROLLED", WriteMode::Overwrite)
        .expect_err("a swapped parent must not be written through");
    assert!(
        matches!(
            error,
            SandboxError::SymlinkForbidden | SandboxError::EscapesRoot | SandboxError::NotFound
        ),
        "unexpected error {error:?}"
    );
    assert_eq!(
        fs::read_to_string(tree.join("outside/target.txt")).expect("outside file survives"),
        "ORIGINAL-OUTSIDE-CONTENT",
        "the write escaped the sandbox through a swapped parent"
    );
}

#[test]
fn a_parent_swapped_concurrently_never_truncates_a_file_outside_the_root() {
    // A pre-planted link is not a race. This test flips the parent directory
    // between an honest directory and a link out of the root while writes are
    // in flight, so the swap really can land between validation and open. The
    // invariant is not "the write fails" (it may legitimately succeed against
    // the honest directory) but "nothing outside the root is ever modified".
    let (tree, sandbox) = workspace();
    let outside = tree.dir("outside/victimdir");
    let victim = outside.join("target.txt");
    fs::write(&victim, "ORIGINAL-OUTSIDE-CONTENT").expect("outside file is writable");
    let parent = tree.join("workspace/flip");
    fs::create_dir(&parent).expect("honest parent is creatable");

    // Confirm the platform can actually build the escape before racing it.
    fs::remove_dir(&parent).expect("honest parent is removable");
    let linkable = try_symlink_dir(&outside, &parent) || try_junction(&outside, &parent);
    if !linkable {
        return;
    }
    remove_dir_link(&parent).expect("link is removable");
    fs::create_dir(&parent).expect("honest parent is recreatable");

    let stop = Arc::new(AtomicBool::new(false));
    let flips = Arc::new(AtomicUsize::new(0));
    let flipper_stop = Arc::clone(&stop);
    let flipper_count = Arc::clone(&flips);
    let flip_target = parent.clone();
    let flip_stash = tree.join("workspace/flipstash");
    let flip_source = outside.clone();
    let flipper = thread::spawn(move || {
        while !flipper_stop.load(Ordering::Relaxed) {
            // The honest directory is moved aside rather than deleted, so the
            // flipper never has to reach inside a directory that might already
            // be the link. A rename that fails means the sandbox is holding the
            // directory open, which is itself the defence under test.
            if fs::rename(&flip_target, &flip_stash).is_err() {
                continue;
            }
            if try_symlink_dir(&flip_source, &flip_target)
                || try_junction(&flip_source, &flip_target)
            {
                flipper_count.fetch_add(1, Ordering::Relaxed);
            }
            // Removing a directory link removes the link, never its target.
            let _ = remove_dir_link(&flip_target);
            let _ = fs::rename(&flip_stash, &flip_target);
        }
        let _ = remove_dir_link(&flip_target);
        let _ = fs::rename(&flip_stash, &flip_target);
    });

    let path = sandbox.relative("flip/target.txt").expect("legal name");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut attempts = 0_u32;
    while Instant::now() < deadline && (attempts < 400 || flips.load(Ordering::Relaxed) < 20) {
        attempts += 1;
        let _ = sandbox.write_file(&path, b"ATTACKER-CONTROLLED", WriteMode::Overwrite);
        // Read back through a path the sandbox never validated, so the check
        // is on the real file rather than on the sandbox's own view.
        let survived = fs::read_to_string(&victim).unwrap_or_default();
        assert_eq!(
            survived, "ORIGINAL-OUTSIDE-CONTENT",
            "a racing parent swap let a write reach outside the root"
        );
    }
    stop.store(true, Ordering::Relaxed);
    flipper.join().expect("flipper thread finishes");
    // Without this the test could silently degrade into a no-op on a host
    // where neither link type can be created.
    assert!(
        flips.load(Ordering::Relaxed) > 0,
        "the swap never happened, so no race was exercised"
    );
    assert_eq!(
        fs::read_to_string(&victim).expect("outside file survives"),
        "ORIGINAL-OUTSIDE-CONTENT"
    );
    assert!(
        fs::symlink_metadata(outside.join("target.txt"))
            .map(|metadata| metadata.len())
            .unwrap_or(0)
            == u64::try_from("ORIGINAL-OUTSIDE-CONTENT".len()).expect("small"),
        "the outside file was truncated"
    );
}

#[test]
fn a_create_new_write_through_a_swapped_parent_creates_nothing_outside() {
    // Creation is the other destructive primitive: a swapped parent must not
    // let the sandbox author a brand new file in someone else's directory.
    let (tree, sandbox) = workspace();
    let real_parent = tree.dir("workspace/fresh");
    let path = sandbox.relative("fresh/planted.txt").expect("legal name");
    sandbox
        .resolve_for_write(&path, WriteMode::CreateNew)
        .expect("an honest parent validates");

    fs::remove_dir_all(&real_parent).expect("the real parent is removable");
    let swapped = try_symlink_dir(&tree.join("outside"), &real_parent)
        || try_junction(&tree.join("outside"), &real_parent);
    if !swapped {
        return;
    }

    let error = sandbox
        .write_file(&path, b"planted", WriteMode::CreateNew)
        .expect_err("a swapped parent must not be created through");
    assert!(
        matches!(
            error,
            SandboxError::SymlinkForbidden | SandboxError::EscapesRoot | SandboxError::NotFound
        ),
        "unexpected error {error:?}"
    );
    assert!(
        fs::symlink_metadata(tree.join("outside/planted.txt")).is_err(),
        "a file was created outside the root"
    );
}
