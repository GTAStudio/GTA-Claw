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
]);

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

/// Operator-configured execution policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecPolicy {
    programs: BTreeMap<String, PathBuf>,
    env: EnvPolicy,
    timeout: Duration,
    max_output_bytes: usize,
}

impl Default for ExecPolicy {
    fn default() -> Self {
        Self {
            programs: BTreeMap::new(),
            env: EnvPolicy::empty(),
            timeout: Duration::from_secs(30),
            max_output_bytes: 256 * 1024,
        }
    }
}

impl ExecPolicy {
    /// Creates a policy that allows no program at all.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Allows one program name, bound to an absolute executable path.
    ///
    /// The binding is what removes `PATH` from the trust base: the child is
    /// always the exact file the operator named.
    pub fn allow_program(
        &mut self,
        name: &str,
        executable: impl Into<PathBuf>,
    ) -> Result<(), ExecutionError> {
        validate_program_name(name)?;
        let executable = executable.into();
        if !executable.is_absolute() {
            return Err(ExecutionError::ProgramPathNotAbsolute);
        }
        reject_interpreted_extension(&executable)?;
        self.programs.insert(name.to_owned(), executable);
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
        self.programs
            .get(name)
            .map(PathBuf::as_path)
            .ok_or(ExecutionError::ProgramNotAllowed)
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
        let program = arguments.required_text("program")?;
        let executable = self.policy.resolve_program(program)?.to_path_buf();
        let argv = arguments.text_list("args").unwrap_or_default();
        if argv.len() > MAX_ARGUMENTS {
            return Err(ToolError::Execution(ExecutionError::TooManyArguments));
        }
        for argument in argv {
            if argument.contains('\0') {
                return Err(ToolError::Execution(ExecutionError::ArgumentRejected));
            }
            if argument.len() > MAX_ARGUMENT_BYTES {
                return Err(ToolError::Execution(ExecutionError::ArgumentRejected));
            }
        }
        let cwd = self.working_directory(arguments, context)?;
        let timeout = match arguments.count("timeout_ms") {
            Some(requested) => Duration::from_millis(requested).min(self.policy.timeout),
            None => self.policy.timeout,
        };

        let mut command = Command::new(&executable);
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

        let child = command
            .spawn()
            .map_err(|_| ToolError::Execution(ExecutionError::SpawnFailed))?;
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
                "program": program,
                "args": argv,
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

/// Drives one child to completion, enforcing the deadline and the output cap.
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

    if let Some(reason) = expiry {
        terminate_tree(pid);
        let _ = child.kill();
        let _ = child.wait();
        drain(stdout_reader);
        drain(stderr_reader);
        return Err(ToolError::Execution(reason));
    }

    let (stdout, stdout_truncated) = drain(stdout_reader);
    let (stderr, stderr_truncated) = drain(stderr_reader);
    Ok(ProcessOutcome {
        exit_code: status.and_then(|status| status.code()),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        truncated: stdout_truncated || stderr_truncated,
    })
}

type ReaderHandle = Option<std::thread::JoinHandle<(Vec<u8>, bool)>>;

/// Reads a pipe on its own thread so a chatty child cannot deadlock the caller.
fn spawn_reader<R: Read + Send + 'static>(stream: Option<R>, cap: usize) -> ReaderHandle {
    let mut stream = stream?;
    Some(std::thread::spawn(move || {
        let mut collected: Vec<u8> = Vec::new();
        let mut truncated = false;
        let mut buffer = [0_u8; 8192];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if collected.len() < cap {
                        let remaining = cap - collected.len();
                        let take = remaining.min(read);
                        collected.extend_from_slice(&buffer[..take]);
                        if take < read {
                            truncated = true;
                        }
                    } else {
                        // Keep draining so the child is never blocked on a
                        // full pipe, but discard everything past the cap.
                        truncated = true;
                    }
                }
            }
        }
        (collected, truncated)
    }))
}

fn drain(handle: ReaderHandle) -> (Vec<u8>, bool) {
    handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_else(|| (Vec::new(), false))
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
    /// An argv entry was rejected by a bound or contained a NUL byte.
    ArgumentRejected,
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
            Self::ArgumentRejected => "argument was rejected",
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
        let mut policy = ExecPolicy::deny_all();
        policy
            .allow_program("git", absolute("git"))
            .expect("valid program");
        assert_eq!(policy.resolve_program("git"), Ok(absolute("git").as_path()));
        assert_eq!(
            policy.resolve_program("curl"),
            Err(ExecutionError::ProgramNotAllowed)
        );
        assert_eq!(policy.program_names(), vec!["git".to_owned()]);
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
