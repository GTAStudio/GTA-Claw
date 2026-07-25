//! Process execution: explicit argv only, never a shell string.
//!
//! The model never supplies a program path, an environment variable, or a
//! command line. It selects a name from an operator-configured allowlist and
//! supplies argv entries. The child runs with a cleared environment, a
//! sandbox-confined working directory, a deadline, output caps, and whole-tree
//! termination on cancel or timeout.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::error::ToolError;
use crate::fs::PATH_MAX_BYTES;
use crate::permission::{Authorization, Capability, PermissionDescriptor, Resource, RiskLevel};
use crate::sandbox::ResolvedPath;
use crate::schema::{Arguments, Field, FieldType, ParameterSchema};
use crate::tool::{Tool, ToolContext, ToolDescriptor, ToolOutput};

/// Inclusive maximum byte length of one argv entry.
const MAX_ARGUMENT_BYTES: usize = 4096;
/// Inclusive maximum number of argv entries after the program name.
const MAX_ARGUMENTS: usize = 64;
/// Inclusive maximum byte length of a program name.
const MAX_PROGRAM_BYTES: usize = 128;
/// Inclusive maximum request timeout in milliseconds.
const MAX_TIMEOUT_MILLIS: u64 = 600_000;
/// Interval between child liveness polls.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// File extensions that Windows executes through a command interpreter.
///
/// Spawning these hands the argument vector to a parser with its own quoting
/// rules, which reintroduces command injection. They are refused outright.
const INTERPRETED_EXTENSIONS: [&str; 9] =
    ["bat", "cmd", "com", "js", "jse", "msc", "ps1", "vbs", "wsf"];

/// Program names that turn an allowlist entry into arbitrary execution.
///
/// Every one of these selects the real program from its argument vector, so
/// allowlisting it grants everything the host can run.
const INTERPRETER_NAMES: &[&str] = &[
    "ash",
    "awk",
    "bash",
    "busybox",
    "cmd",
    "csh",
    "dash",
    "doas",
    "env",
    "fish",
    "gawk",
    "ksh",
    "mawk",
    "nu",
    "osascript",
    "rbash",
    "runas",
    "sh",
    "ssh",
    "start",
    "sudo",
    "tclsh",
    "wine",
    "wsl",
    "xargs",
    "zsh",
];

/// Program-name prefixes covering versioned interpreters such as `python3.12`.
const INTERPRETER_PREFIXES: &[&str] = &[
    "bun",
    "deno",
    "lua",
    "node",
    "perl",
    "php",
    "powershell",
    "pwsh",
    "python",
    "ruby",
];

/// `FILE_FLAG_OPEN_REPARSE_POINT`.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `FILE_SHARE_READ`.
#[cfg(windows)]
const FILE_SHARE_READ: u32 = 0x0000_0001;
/// `FILE_SHARE_DELETE`.
#[cfg(windows)]
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
/// Longest wait for a pipe reader to finish after the tree was terminated.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

const EXEC_SCHEMA: ParameterSchema = ParameterSchema::new(&[
    Field {
        name: "program",
        description: "Allowlisted program name; never a path and never a shell command line",
        required: true,
        ty: FieldType::Text {
            max_bytes: MAX_PROGRAM_BYTES,
        },
    },
    Field {
        name: "args",
        description: "Argument vector passed verbatim to the program, without shell parsing",
        required: false,
        ty: FieldType::TextList {
            max_items: MAX_ARGUMENTS,
            max_item_bytes: MAX_ARGUMENT_BYTES,
        },
    },
    Field {
        name: "cwd",
        description: "Workspace-relative working directory; defaults to the workspace root",
        required: false,
        ty: FieldType::Text {
            max_bytes: PATH_MAX_BYTES,
        },
    },
    Field {
        name: "timeout_ms",
        description: "Deadline in milliseconds, clamped to the policy maximum",
        required: false,
        ty: FieldType::Count {
            max: MAX_TIMEOUT_MILLIS,
        },
    },
])
.recording(&["program", "cwd", "timeout_ms"]);

/// Environment exposed to a child process.
///
/// The default is empty: a child inherits nothing unless an operator names a
/// variable. Values are never taken from tool arguments.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnvPolicy {
    inherited: BTreeSet<String>,
    explicit: BTreeMap<String, String>,
}

impl EnvPolicy {
    /// Creates a policy that passes no environment at all.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Inherits one named variable from this process, when it is set.
    pub fn inherit(&mut self, name: &str) -> Result<(), ExecutionError> {
        validate_env_name(name)?;
        self.inherited.insert(name.to_owned());
        Ok(())
    }

    /// Sets one variable to a fixed value.
    pub fn set(&mut self, name: &str, value: &str) -> Result<(), ExecutionError> {
        validate_env_name(name)?;
        if value.contains('\0') {
            return Err(ExecutionError::EnvironmentRejected);
        }
        self.explicit.insert(name.to_owned(), value.to_owned());
        Ok(())
    }

    /// Inherits the minimum set a child needs to load on the host platform.
    ///
    /// On Windows this is `SystemRoot`, without which most executables fail to
    /// initialize. On other platforms it is empty.
    pub fn with_platform_minimum(mut self) -> Result<Self, ExecutionError> {
        if cfg!(windows) {
            self.inherit("SystemRoot")?;
            self.inherit("windir")?;
        }
        Ok(self)
    }

    /// Resolves the policy into the concrete variables for one child.
    #[must_use]
    pub fn resolve(&self) -> BTreeMap<String, String> {
        let mut resolved = BTreeMap::new();
        for name in &self.inherited {
            if let Ok(value) = std::env::var(name)
                && !value.contains('\0')
            {
                resolved.insert(name.clone(), value);
            }
        }
        for (name, value) in &self.explicit {
            resolved.insert(name.clone(), value.clone());
        }
        resolved
    }

    /// Returns the variable names this policy may expose.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut names: BTreeSet<String> = self.inherited.clone();
        names.extend(self.explicit.keys().cloned());
        names.into_iter().collect()
    }
}

fn validate_env_name(name: &str) -> Result<(), ExecutionError> {
    if name.is_empty() || name.len() > 256 {
        return Err(ExecutionError::EnvironmentRejected);
    }
    let valid = name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_');
    if valid {
        Ok(())
    } else {
        Err(ExecutionError::EnvironmentRejected)
    }
}

/// Per-program restriction on the argument vector a model may supply.
///
/// Argument meaning is program-specific, so the operator decides. The bounded
/// default only caps size and count; [`ArgvPolicy::exactly`] narrows a program
/// to a fixed vocabulary, which is the only way to make an allowlisted program
/// that can also read files, such as a version control client, safe to expose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgvPolicy {
    max_arguments: usize,
    max_argument_bytes: usize,
    allowed: Option<BTreeSet<String>>,
}

impl Default for ArgvPolicy {
    fn default() -> Self {
        Self::bounded()
    }
}

impl ArgvPolicy {
    /// Accepts any argument within the global count and size bounds.
    #[must_use]
    pub const fn bounded() -> Self {
        Self {
            max_arguments: MAX_ARGUMENTS,
            max_argument_bytes: MAX_ARGUMENT_BYTES,
            allowed: None,
        }
    }

    /// Accepts only arguments drawn from a fixed set.
    #[must_use]
    pub fn exactly<I, S>(allowed: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            allowed: Some(
                allowed
                    .into_iter()
                    .map(|value| value.as_ref().to_owned())
                    .collect(),
            ),
            ..Self::bounded()
        }
    }

    /// Accepts no argument at all.
    #[must_use]
    pub fn none() -> Self {
        Self {
            max_arguments: 0,
            allowed: Some(BTreeSet::new()),
            ..Self::bounded()
        }
    }

    /// Lowers the argument count bound.
    #[must_use]
    pub fn with_max_arguments(mut self, max_arguments: usize) -> Self {
        self.max_arguments = max_arguments.min(MAX_ARGUMENTS);
        self
    }

    /// Lowers the per-argument size bound.
    #[must_use]
    pub fn with_max_argument_bytes(mut self, max_argument_bytes: usize) -> Self {
        self.max_argument_bytes = max_argument_bytes.min(MAX_ARGUMENT_BYTES);
        self
    }

    /// Checks one argument vector against this policy.
    pub fn check(&self, argv: &[String]) -> Result<(), ExecutionError> {
        if argv.len() > self.max_arguments {
            return Err(ExecutionError::TooManyArguments);
        }
        for argument in argv {
            if argument.contains('\0') || argument.len() > self.max_argument_bytes {
                return Err(ExecutionError::ArgumentRejected);
            }
            if let Some(allowed) = &self.allowed
                && !allowed.contains(argument.as_str())
            {
                return Err(ExecutionError::ArgumentNotAllowed);
            }
        }
        Ok(())
    }
}

/// Identity of an allowlisted executable, captured when it was allowlisted.
///
/// It is compared again immediately before every spawn, so replacing the file
/// behind an allowlisted name is detected instead of executed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableIdentity {
    length: u64,
    modified_millis: u128,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
}

impl ExecutableIdentity {
    fn of(metadata: &std::fs::Metadata) -> Result<Self, ExecutionError> {
        let modified_millis = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |elapsed| elapsed.as_millis());
        Ok(Self {
            length: metadata.len(),
            modified_millis,
            #[cfg(unix)]
            device: std::os::unix::fs::MetadataExt::dev(metadata),
            #[cfg(unix)]
            inode: std::os::unix::fs::MetadataExt::ino(metadata),
            #[cfg(unix)]
            mode: std::os::unix::fs::MetadataExt::mode(metadata),
        })
    }
}

/// One allowlisted program: a pinned executable and its argument policy.
#[derive(Clone, Debug, Eq, PartialEq)]
struct AllowedProgram {
    executable: PathBuf,
    identity: ExecutableIdentity,
    argv: ArgvPolicy,
}

/// Operator-configured execution policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecPolicy {
    programs: BTreeMap<String, AllowedProgram>,
    env: EnvPolicy,
    timeout: Duration,
    max_output_bytes: usize,
    writable_root: Option<PathBuf>,
}

impl Default for ExecPolicy {
    fn default() -> Self {
        Self {
            programs: BTreeMap::new(),
            env: EnvPolicy::empty(),
            timeout: Duration::from_secs(30),
            max_output_bytes: 256 * 1024,
            writable_root: None,
        }
    }
}

impl ExecPolicy {
    /// Creates a policy that allows no program at all.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Declares a directory whose contents may never be executed.
    ///
    /// Set it to the workspace root. An agent that can write a file and then
    /// run it has no allowlist at all, so an executable located under this
    /// directory is refused at configuration time rather than at spawn time.
    #[must_use]
    pub fn with_writable_root(mut self, root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        self.writable_root = Some(std::fs::canonicalize(&root).map_or(root, strip_verbatim));
        self
    }

    /// Allows one program name, bound to an absolute executable path.
    ///
    /// The binding is what removes `PATH` from the trust base: the child is
    /// always the exact file the operator named. The file must additionally be
    /// a real, canonical, non-link regular file that is neither an interpreter
    /// nor a script, and it must not live anywhere the agent can write.
    pub fn allow_program(
        &mut self,
        name: &str,
        executable: impl Into<PathBuf>,
    ) -> Result<(), ExecutionError> {
        self.allow_program_with_argv(name, executable, ArgvPolicy::bounded())
    }

    /// Allows one program name with a narrowed argument policy.
    pub fn allow_program_with_argv(
        &mut self,
        name: &str,
        executable: impl Into<PathBuf>,
        argv: ArgvPolicy,
    ) -> Result<(), ExecutionError> {
        validate_program_name(name)?;
        let executable = executable.into();
        if !executable.is_absolute() {
            return Err(ExecutionError::ProgramPathNotAbsolute);
        }
        reject_interpreted_extension(&executable)?;
        reject_interpreter_name(&executable)?;

        let metadata = std::fs::symlink_metadata(&executable)
            .map_err(|_| ExecutionError::ExecutableNotFound)?;
        if metadata.file_type().is_symlink() {
            return Err(ExecutionError::ExecutableIsALink);
        }
        if !metadata.is_file() {
            return Err(ExecutionError::ExecutableNotAFile);
        }
        // Canonicalization resolves every ancestor. Requiring the result to be
        // the path the operator supplied refuses an executable reached through
        // a linked or junctioned directory, where the real target can change
        // without the configured path changing.
        let canonical = std::fs::canonicalize(&executable)
            .map(strip_verbatim)
            .map_err(|_| ExecutionError::ExecutableNotFound)?;
        if canonical != executable {
            return Err(ExecutionError::ExecutablePathNotCanonical);
        }
        if let Some(root) = &self.writable_root
            && canonical.starts_with(root)
        {
            return Err(ExecutionError::ExecutableInsideWritableRoot);
        }
        reject_shebang(&canonical)?;

        self.programs.insert(
            name.to_owned(),
            AllowedProgram {
                identity: ExecutableIdentity::of(&metadata)?,
                executable: canonical,
                argv,
            },
        );
        Ok(())
    }

    /// Replaces the environment policy.
    #[must_use]
    pub fn with_env(mut self, env: EnvPolicy) -> Self {
        self.env = env;
        self
    }

    /// Replaces the default deadline.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replaces the combined stdout and stderr cap.
    #[must_use]
    pub const fn with_max_output_bytes(mut self, max_output_bytes: usize) -> Self {
        self.max_output_bytes = max_output_bytes;
        self
    }

    /// Returns the allowlisted program names in stable order.
    #[must_use]
    pub fn program_names(&self) -> Vec<String> {
        self.programs.keys().cloned().collect()
    }

    /// Resolves an allowlisted name to its bound executable.
    pub fn resolve_program(&self, name: &str) -> Result<&Path, ExecutionError> {
        validate_program_name(name)?;
        self.program(name)
            .map(|program| program.executable.as_path())
    }

    fn program(&self, name: &str) -> Result<&AllowedProgram, ExecutionError> {
        validate_program_name(name)?;
        self.programs
            .get(name)
            .ok_or(ExecutionError::ProgramNotAllowed)
    }
}

/// Opens the allowlisted executable and proves it is still the same file.
///
/// The returned handle is held across the spawn. On Windows it is opened
/// without `FILE_SHARE_WRITE`, so the file cannot be overwritten in place
/// between this check and the spawn that follows it.
fn open_verified_executable(program: &AllowedProgram) -> Result<File, ExecutionError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        options.share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE);
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NOFOLLOW);
    }
    let handle = options
        .open(&program.executable)
        .map_err(|_| ExecutionError::ExecutableNotFound)?;
    let metadata = handle
        .metadata()
        .map_err(|_| ExecutionError::ExecutableNotFound)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(ExecutionError::ExecutableChanged);
    }
    if ExecutableIdentity::of(&metadata)? != program.identity {
        return Err(ExecutionError::ExecutableChanged);
    }
    // Re-read the first bytes through the same handle: a file that became a
    // script since it was allowlisted must not be handed to an interpreter.
    let mut prefix = [0_u8; 2];
    let mut source = &handle;
    let read = source
        .read(&mut prefix)
        .map_err(|_| ExecutionError::ExecutableChanged)?;
    if read == 2 && prefix == *b"#!" {
        return Err(ExecutionError::InterpretedProgramForbidden);
    }
    Ok(handle)
}

/// Rejects an executable whose name is a shell, an interpreter, or a launcher.
///
/// Allowlisting one of these is equivalent to allowlisting every program on the
/// host, because the argument vector alone selects what actually runs.
fn reject_interpreter_name(executable: &Path) -> Result<(), ExecutionError> {
    let Some(stem) = executable.file_stem().and_then(OsStr::to_str) else {
        return Ok(());
    };
    let stem = stem.to_ascii_lowercase();
    if INTERPRETER_NAMES.contains(&stem.as_str())
        || INTERPRETER_PREFIXES
            .iter()
            .any(|prefix| stem.starts_with(prefix))
    {
        return Err(ExecutionError::ExecutableIsAnInterpreter);
    }
    Ok(())
}

/// Rejects a file that the operating system would hand to an interpreter.
fn reject_shebang(executable: &Path) -> Result<(), ExecutionError> {
    let Ok(mut file) = File::open(executable) else {
        return Err(ExecutionError::ExecutableNotFound);
    };
    let mut prefix = [0_u8; 2];
    let read = file
        .read(&mut prefix)
        .map_err(|_| ExecutionError::ExecutableNotFound)?;
    if read == 2 && prefix == *b"#!" {
        return Err(ExecutionError::InterpretedProgramForbidden);
    }
    Ok(())
}

/// Strips the Windows verbatim prefix so a canonical path compares equal to the
/// path an operator would write.
fn strip_verbatim(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy().into_owned();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.len() >= 2 && rest.as_bytes()[1] == b':' => PathBuf::from(rest),
        _ => path,
    }
}

/// Rejects anything that is not a bare, safe program name.
fn validate_program_name(name: &str) -> Result<(), ExecutionError> {
    if name.is_empty() || name.len() > MAX_PROGRAM_BYTES {
        return Err(ExecutionError::ProgramNameRejected);
    }
    let acceptable = name.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '+')
    });
    if !acceptable || name.starts_with('-') || name.contains("..") {
        return Err(ExecutionError::ProgramNameRejected);
    }
    Ok(())
}

fn reject_interpreted_extension(executable: &Path) -> Result<(), ExecutionError> {
    let extension = executable
        .extension()
        .and_then(OsStr::to_str)
        .map(str::to_ascii_lowercase);
    match extension {
        Some(extension) if INTERPRETED_EXTENSIONS.contains(&extension.as_str()) => {
            Err(ExecutionError::InterpretedProgramForbidden)
        }
        _ => Ok(()),
    }
}

/// Cooperative cancellation shared with a caller outside the tool.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates an uncancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation of every process observing this token.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Reports whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Outcome of one completed child process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOutcome {
    /// Exit status code, absent when the process was signalled or killed.
    pub exit_code: Option<i32>,
    /// Captured standard output, lossily decoded and capped.
    pub stdout: String,
    /// Captured standard error, lossily decoded and capped.
    pub stderr: String,
    /// Whether a stream hit the output cap.
    pub truncated: bool,
}

/// Runs allowlisted programs with an explicit argument vector.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProcessExecTool {
    policy: ExecPolicy,
    cancellation: Option<CancellationTokenHandle>,
}

/// Comparable wrapper so the tool can derive equality for tests.
#[derive(Clone, Debug)]
struct CancellationTokenHandle(CancellationToken);

impl PartialEq for CancellationTokenHandle {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0.cancelled, &other.0.cancelled)
    }
}

impl Eq for CancellationTokenHandle {}

impl ProcessExecTool {
    /// Creates the tool from an operator policy.
    #[must_use]
    pub fn new(policy: ExecPolicy) -> Self {
        Self {
            policy,
            cancellation: None,
        }
    }

    /// Attaches a cancellation token observed while a child runs.
    #[must_use]
    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.cancellation = Some(CancellationTokenHandle(token));
        self
    }

    /// Returns the policy in force.
    #[must_use]
    pub const fn policy(&self) -> &ExecPolicy {
        &self.policy
    }

    fn working_directory(
        &self,
        arguments: &Arguments,
        context: &ToolContext<'_>,
    ) -> Result<ResolvedPath, ToolError> {
        match arguments.text("cwd") {
            Some(raw) => {
                let relative = context.sandbox.relative(raw)?;
                Ok(context.sandbox.resolve_directory(&relative)?)
            }
            None => Ok(context.sandbox.resolve_root()),
        }
    }
}

impl Tool for ProcessExecTool {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "process_exec",
            title: "Run a program",
            description: "Runs an allowlisted program with an explicit argument vector. There is \
                          no shell: arguments are passed verbatim, so shell metacharacters have \
                          no meaning. The child inherits no environment beyond the operator \
                          allowlist and cannot leave the workspace.",
            schema: EXEC_SCHEMA,
            permission: PermissionDescriptor {
                capability: Capability::ProcessExecute,
                risk: RiskLevel::High,
                requires_approval: true,
                gateway_scope: "operator.approvals",
            },
        }
    }

    fn resource(
        &self,
        arguments: &Arguments,
        _context: &ToolContext<'_>,
    ) -> Result<Resource, ToolError> {
        let program = arguments.required_text("program")?;
        // Resolution happens here so an unknown program is refused before a
        // permission broker is ever consulted.
        self.policy.resolve_program(program)?;
        Ok(Resource::Program(program.to_owned()))
    }

    fn invoke(
        &self,
        arguments: &Arguments,
        context: &ToolContext<'_>,
        _authorization: &Authorization<'_>,
    ) -> Result<ToolOutput, ToolError> {
        let name = arguments.required_text("program")?;
        let program = self.policy.program(name)?;
        let argv = arguments.text_list("args").unwrap_or_default();
        program.argv.check(argv)?;
        let cwd = self.working_directory(arguments, context)?;
        let timeout = match arguments.count("timeout_ms") {
            Some(requested) => Duration::from_millis(requested).min(self.policy.timeout),
            None => self.policy.timeout,
        };

        // Identity is proven here, immediately before the spawn, and the handle
        // is held until the child exists so the file cannot be replaced inside
        // the window.
        let pinned = open_verified_executable(program)?;
        let mut command = Command::new(&program.executable);
        command
            .args(argv)
            .current_dir(cwd.native())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();
        for (name, value) in self.policy.env.resolve() {
            command.env(name, value);
        }
        place_in_own_process_group(&mut command);

        let child = command
            .spawn()
            .map_err(|_| ToolError::Execution(ExecutionError::SpawnFailed))?;
        drop(pinned);
        let cancellation = self.cancellation.as_ref().map(|handle| handle.0.clone());
        let outcome = supervise(child, timeout, self.policy.max_output_bytes, cancellation)?;

        let rendered = if outcome.stderr.is_empty() {
            outcome.stdout.clone()
        } else {
            format!("{}\n{}", outcome.stdout, outcome.stderr)
        };
        Ok(ToolOutput::new(
            rendered,
            json!({
                "program": name,
                "argument_count": argv.len(),
                "cwd": cwd.relative().as_str(),
                "exit_code": outcome.exit_code,
                "stdout": outcome.stdout,
                "stderr": outcome.stderr,
                "environment": self.policy.env.names(),
            }),
        )
        .truncated(outcome.truncated))
    }
}

/// Puts the child at the head of its own process group where the platform has
/// one, so descendants can be signalled together even after the child exits.
#[cfg(unix)]
fn place_in_own_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
}

#[cfg(not(unix))]
fn place_in_own_process_group(_command: &mut Command) {}

/// Drives one child to completion, enforcing the deadline and the output cap.
///
/// The process tree is terminated on every exit path, including a clean one. A
/// child that spawns a detached payload, closes its pipes and exits
/// immediately would otherwise leave that payload running past the deadline
/// and past any revocation of the grant that started it.
fn supervise(
    mut child: Child,
    timeout: Duration,
    max_output_bytes: usize,
    cancellation: Option<CancellationToken>,
) -> Result<ProcessOutcome, ToolError> {
    let pid = child.id();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_reader = spawn_reader(stdout, max_output_bytes);
    let stderr_reader = spawn_reader(stderr, max_output_bytes);

    let deadline = Instant::now() + timeout;
    let mut expiry: Option<ExecutionError> = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => {
                expiry = Some(ExecutionError::WaitFailed);
                break None;
            }
        }
        if cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            expiry = Some(ExecutionError::Cancelled);
            break None;
        }
        if Instant::now() >= deadline {
            expiry = Some(ExecutionError::TimedOut);
            break None;
        }
        std::thread::sleep(POLL_INTERVAL);
    };

    // Terminate before the child handle is dropped: while it is held the
    // operating system cannot reuse the identifier, so the sweep still finds
    // descendants of an already-exited child.
    terminate_tree(pid);
    if expiry.is_some() {
        let _ = child.kill();
        let _ = child.wait();
    }
    // Bounded: a descendant that inherited the pipes and never closes them must
    // not stall the supervisor forever.
    let (stdout, stdout_truncated) = drain(stdout_reader);
    let (stderr, stderr_truncated) = drain(stderr_reader);
    drop(child);

    if let Some(reason) = expiry {
        return Err(ToolError::Execution(reason));
    }
    Ok(ProcessOutcome {
        exit_code: status.and_then(|status| status.code()),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        truncated: stdout_truncated || stderr_truncated,
    })
}

/// Buffer shared between a pipe reader thread and the supervisor.
#[derive(Debug, Default)]
struct ReaderBuffer {
    collected: std::sync::Mutex<Vec<u8>>,
    truncated: AtomicBool,
}

type ReaderHandle = Option<(std::thread::JoinHandle<()>, Arc<ReaderBuffer>)>;

/// Reads a pipe on its own thread so a chatty child cannot deadlock the caller.
fn spawn_reader<R: Read + Send + 'static>(stream: Option<R>, cap: usize) -> ReaderHandle {
    let mut stream = stream?;
    let buffer = Arc::new(ReaderBuffer::default());
    let sink = Arc::clone(&buffer);
    let handle = std::thread::spawn(move || {
        let mut chunk = [0_u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let Ok(mut collected) = sink.collected.lock() else {
                        break;
                    };
                    if collected.len() < cap {
                        let remaining = cap - collected.len();
                        let take = remaining.min(read);
                        collected.extend_from_slice(&chunk[..take]);
                        if take < read {
                            sink.truncated.store(true, Ordering::SeqCst);
                        }
                    } else {
                        // Keep draining so the child is never blocked on a
                        // full pipe, but discard everything past the cap.
                        sink.truncated.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
    });
    Some((handle, buffer))
}

/// Collects what a reader captured, waiting only a bounded time for it to end.
fn drain(handle: ReaderHandle) -> (Vec<u8>, bool) {
    let Some((thread, buffer)) = handle else {
        return (Vec::new(), false);
    };
    let deadline = Instant::now() + DRAIN_GRACE;
    while !thread.is_finished() && Instant::now() < deadline {
        std::thread::sleep(POLL_INTERVAL);
    }
    let collected = buffer
        .collected
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let truncated = buffer.truncated.load(Ordering::SeqCst);
    if thread.is_finished() {
        let _ = thread.join();
    }
    (collected, truncated)
}

/// Kills a process and every descendant it spawned.
///
/// A child that forks before the deadline must not outlive the tool, so the
/// whole tree is terminated rather than just the direct child.
fn terminate_tree(pid: u32) {
    #[cfg(windows)]
    {
        let mut command = Command::new("taskkill");
        command
            .args(["/F", "/T", "/PID", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Ok(mut killer) = command.spawn() {
            let _ = killer.wait();
        }
    }
    #[cfg(not(windows))]
    {
        // The child leads its own process group, so signalling the group
        // reaches descendants that were reparented when it exited.
        for group in [format!("-{pid}")] {
            let mut command = Command::new("kill");
            command
                .args(["-KILL", "--", &group])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if let Ok(mut killer) = command.spawn() {
                let _ = killer.wait();
            }
        }
        let table = process_table();
        let mut targets = descendants(&table, pid);
        // Deepest first, so a parent cannot reparent a survivor mid-sweep.
        targets.reverse();
        targets.push(pid);
        for target in targets {
            let mut command = Command::new("kill");
            command
                .args(["-KILL", &target.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if let Ok(mut killer) = command.spawn() {
                let _ = killer.wait();
            }
        }
    }
}

#[cfg(not(windows))]
fn process_table() -> Vec<(u32, u32)> {
    let output = Command::new("ps").args(["-A", "-o", "pid=,ppid="]).output();
    match output {
        Ok(output) => parse_process_table(&String::from_utf8_lossy(&output.stdout)),
        Err(_) => Vec::new(),
    }
}

/// Parses `pid ppid` pairs, ignoring anything that is not a pair of integers.
#[cfg_attr(windows, allow(dead_code))]
fn parse_process_table(listing: &str) -> Vec<(u32, u32)> {
    listing
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse::<u32>().ok()?;
            let ppid = fields.next()?.parse::<u32>().ok()?;
            Some((pid, ppid))
        })
        .collect()
}

/// Returns every transitive descendant of `root`, in breadth-first order.
#[cfg_attr(windows, allow(dead_code))]
fn descendants(table: &[(u32, u32)], root: u32) -> Vec<u32> {
    let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (pid, ppid) in table {
        if *pid != *ppid {
            children.entry(*ppid).or_default().push(*pid);
        }
    }
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    seen.insert(root);
    let mut queue: VecDeque<u32> = VecDeque::new();
    queue.push_back(root);
    let mut found = Vec::new();
    while let Some(current) = queue.pop_front() {
        let Some(kids) = children.get(&current) else {
            continue;
        };
        for kid in kids {
            if seen.insert(*kid) {
                found.push(*kid);
                queue.push_back(*kid);
            }
        }
    }
    found
}

/// A refused or failed process execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    /// The program name is not on the operator allowlist.
    ProgramNotAllowed,
    /// The program name is not a bare, acceptable identifier.
    ProgramNameRejected,
    /// The configured executable path was not absolute.
    ProgramPathNotAbsolute,
    /// The executable would run through a command interpreter.
    InterpretedProgramForbidden,
    /// The configured executable does not exist or cannot be opened.
    ExecutableNotFound,
    /// The configured executable is a symbolic link or reparse point.
    ExecutableIsALink,
    /// The configured executable is not a regular file.
    ExecutableNotAFile,
    /// The configured path differs from its canonical form.
    ExecutablePathNotCanonical,
    /// The configured executable is a shell, interpreter, or launcher.
    ExecutableIsAnInterpreter,
    /// The configured executable lives where the agent can write.
    ExecutableInsideWritableRoot,
    /// The executable changed between being allowlisted and being run.
    ExecutableChanged,
    /// An argv entry was rejected by a bound or contained a NUL byte.
    ArgumentRejected,
    /// An argv entry is not in the program's allowed argument set.
    ArgumentNotAllowed,
    /// More argv entries were supplied than the bound allows.
    TooManyArguments,
    /// An environment variable name or value was rejected.
    EnvironmentRejected,
    /// The child process could not be spawned.
    SpawnFailed,
    /// Waiting on the child failed.
    WaitFailed,
    /// The deadline expired and the process tree was terminated.
    TimedOut,
    /// Cancellation was requested and the process tree was terminated.
    Cancelled,
}

impl Display for ExecutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ProgramNotAllowed => "program is not allowlisted",
            Self::ProgramNameRejected => "program name is not an acceptable identifier",
            Self::ProgramPathNotAbsolute => "allowlisted executable path must be absolute",
            Self::InterpretedProgramForbidden => {
                "executables interpreted by a command shell are forbidden"
            }
            Self::ExecutableNotFound => "allowlisted executable does not exist",
            Self::ExecutableIsALink => "allowlisted executable is a link or reparse point",
            Self::ExecutableNotAFile => "allowlisted executable is not a regular file",
            Self::ExecutablePathNotCanonical => {
                "allowlisted executable path is not its own canonical path"
            }
            Self::ExecutableIsAnInterpreter => {
                "shells, interpreters, and launchers cannot be allowlisted"
            }
            Self::ExecutableInsideWritableRoot => {
                "an executable the agent can overwrite cannot be allowlisted"
            }
            Self::ExecutableChanged => "allowlisted executable changed since it was allowlisted",
            Self::ArgumentRejected => "argument was rejected",
            Self::ArgumentNotAllowed => "argument is not in the allowed set for this program",
            Self::TooManyArguments => "too many arguments",
            Self::EnvironmentRejected => "environment variable was rejected",
            Self::SpawnFailed => "process could not be spawned",
            Self::WaitFailed => "waiting on the process failed",
            Self::TimedOut => "process exceeded its deadline and was terminated",
            Self::Cancelled => "process was cancelled and terminated",
        };
        formatter.write_str(message)
    }
}

impl Error for ExecutionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn absolute(name: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("C:\\tools\\{name}"))
        } else {
            PathBuf::from(format!("/usr/bin/{name}"))
        }
    }

    #[test]
    fn program_names_that_are_paths_or_flags_are_refused() {
        let cases = [
            "",
            "../evil",
            "bin/tool",
            "bin\\tool",
            "C:tool",
            "-rf",
            "tool;rm",
            "tool rm",
            "tool|rm",
            "tool&rm",
            "tool$(rm)",
            "tool`rm`",
            "tool\nrm",
            "tool\0",
        ];
        for case in cases {
            assert!(
                validate_program_name(case).is_err(),
                "accepted program name {case:?}"
            );
        }
        for case in ["cargo", "git", "python3.12", "clang++", "my-tool_1"] {
            assert_eq!(validate_program_name(case), Ok(()), "refused {case:?}");
        }
    }

    #[test]
    fn interpreted_extensions_are_refused_at_configuration_time() {
        let mut policy = ExecPolicy::deny_all();
        for extension in INTERPRETED_EXTENSIONS {
            let path = absolute(&format!("runner.{extension}"));
            assert_eq!(
                policy.allow_program("runner", &path),
                Err(ExecutionError::InterpretedProgramForbidden),
                "accepted .{extension}"
            );
            let upper = absolute(&format!("runner.{}", extension.to_uppercase()));
            assert_eq!(
                policy.allow_program("runner", &upper),
                Err(ExecutionError::InterpretedProgramForbidden),
                "accepted uppercase .{extension}"
            );
        }
        assert!(policy.program_names().is_empty());
    }

    #[test]
    fn relative_executable_paths_are_refused() {
        let mut policy = ExecPolicy::deny_all();
        assert_eq!(
            policy.allow_program("tool", PathBuf::from("tool")),
            Err(ExecutionError::ProgramPathNotAbsolute)
        );
        assert_eq!(
            policy.allow_program("tool", PathBuf::from("./tool")),
            Err(ExecutionError::ProgramPathNotAbsolute)
        );
    }

    #[test]
    fn an_unlisted_program_never_resolves() {
        // A real file is required now, so the test binary stands in for an
        // operator-supplied executable.
        let real = std::fs::canonicalize(std::env::current_exe().expect("test binary path"))
            .map(strip_verbatim)
            .expect("test binary canonicalizes");
        let mut policy = ExecPolicy::deny_all();
        policy
            .allow_program("runner", real.clone())
            .expect("valid program");
        assert_eq!(policy.resolve_program("runner"), Ok(real.as_path()));
        assert_eq!(
            policy.resolve_program("curl"),
            Err(ExecutionError::ProgramNotAllowed)
        );
        assert_eq!(policy.program_names(), vec!["runner".to_owned()]);
    }

    #[test]
    fn an_executable_that_does_not_exist_is_refused() {
        let mut policy = ExecPolicy::deny_all();
        assert_eq!(
            policy.allow_program("ghost", absolute("definitely-not-installed-xyz")),
            Err(ExecutionError::ExecutableNotFound)
        );
        assert!(policy.program_names().is_empty());
    }

    #[test]
    fn shells_and_interpreters_are_refused_by_name() {
        let mut policy = ExecPolicy::deny_all();
        for name in ["sh", "bash", "cmd", "powershell", "python3", "node", "env"] {
            assert_eq!(
                policy.allow_program("runner", absolute(name)),
                Err(ExecutionError::ExecutableIsAnInterpreter),
                "accepted interpreter {name}"
            );
        }
        assert!(policy.program_names().is_empty());
    }

    #[test]
    fn environment_names_are_validated_and_values_are_explicit() {
        let mut env = EnvPolicy::empty();
        for bad in ["", "A=B", "A B", "PATH;", "ä", "A\0"] {
            assert_eq!(env.inherit(bad), Err(ExecutionError::EnvironmentRejected));
        }
        env.set("CLAW_MODE", "test").expect("valid variable");
        assert_eq!(
            env.set("CLAW_MODE", "bad\0value"),
            Err(ExecutionError::EnvironmentRejected)
        );
        let resolved = env.resolve();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.get("CLAW_MODE"), Some(&"test".to_owned()));
        assert_eq!(env.names(), vec!["CLAW_MODE".to_owned()]);
    }

    #[test]
    fn an_inherited_variable_that_is_unset_is_simply_absent() {
        let mut env = EnvPolicy::empty();
        env.inherit("CLAW_TOOLS_DEFINITELY_UNSET_VARIABLE")
            .expect("valid name");
        assert_eq!(env.resolve(), BTreeMap::new());
    }

    #[test]
    fn process_table_parsing_ignores_headers_and_garbage() {
        let listing = "  PID  PPID\n 100 1\n101   100\nnot a row\n102 101\n 103\n";
        assert_eq!(
            parse_process_table(listing),
            vec![(100, 1), (101, 100), (102, 101)]
        );
    }

    #[test]
    fn descendants_are_transitive_and_cycle_safe() {
        let table = vec![
            (1, 0),
            (10, 1),
            (11, 10),
            (12, 11),
            (13, 10),
            (20, 1),
            (21, 20),
            (30, 31),
            (31, 30),
        ];
        assert_eq!(descendants(&table, 10), vec![11, 13, 12]);
        assert_eq!(descendants(&table, 12), Vec::<u32>::new());
        assert_eq!(descendants(&table, 20), vec![21]);
        assert_eq!(descendants(&table, 30), vec![31]);
    }

    #[test]
    fn cancellation_tokens_share_state() {
        let token = CancellationToken::new();
        let clone = token.clone();
        assert!(!clone.is_cancelled());
        token.cancel();
        assert!(clone.is_cancelled());
    }
}
