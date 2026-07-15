//! Bounded subprocess execution for trusted tools.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::{PolicyError, PolicyResult, error};

const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// A subprocess specification with explicit limits and an empty inherited environment.
#[derive(Debug, Clone)]
pub struct CommandSpec {
    program: PathBuf,
    args: Vec<OsString>,
    cwd: PathBuf,
    env: Vec<(OsString, OsString)>,
    timeout: Duration,
    max_stdout: usize,
    max_stderr: usize,
}

impl CommandSpec {
    /// Creates a specification for an absolute trusted executable.
    pub fn new(program: impl Into<PathBuf>, cwd: impl Into<PathBuf>) -> PolicyResult<Self> {
        let program = program.into();
        if !program.is_absolute() {
            return Err(PolicyError::new(format!(
                "trusted executable must be absolute: {}",
                program.display()
            )));
        }
        let cwd = cwd.into();
        if !cwd.is_absolute() {
            return Err(PolicyError::new(format!(
                "trusted working directory must be absolute: {}",
                cwd.display()
            )));
        }
        Ok(Self {
            program,
            args: Vec::new(),
            cwd,
            env: Vec::new(),
            timeout: Duration::from_secs(30),
            max_stdout: 4 * 1024 * 1024,
            max_stderr: 512 * 1024,
        })
    }

    /// Appends one argv value without shell interpretation.
    #[must_use]
    pub fn arg(mut self, value: impl AsRef<OsStr>) -> Self {
        self.args.push(value.as_ref().to_owned());
        self
    }

    /// Appends argv values without shell interpretation.
    #[must_use]
    pub fn args<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(values.into_iter().map(|value| value.as_ref().to_owned()));
        self
    }

    /// Adds one explicit environment variable.
    #[must_use]
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.env
            .push((key.as_ref().to_owned(), value.as_ref().to_owned()));
        self
    }

    /// Sets the wall-clock timeout.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets independent stdout and stderr byte limits.
    #[must_use]
    pub const fn output_limits(mut self, stdout: usize, stderr: usize) -> Self {
        self.max_stdout = stdout;
        self.max_stderr = stderr;
        self
    }
}

/// Captured bounded subprocess output.
#[derive(Debug)]
pub struct BoundedOutput {
    /// Process exit status.
    pub status: ExitStatus,
    /// Captured stdout.
    pub stdout: Vec<u8>,
    /// Captured stderr.
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
struct StreamOutput {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn read_bounded(mut reader: impl Read, limit: usize) -> io::Result<StreamOutput> {
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    let mut exceeded = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let available = limit.saturating_sub(bytes.len());
        let retained = available.min(count);
        bytes.extend_from_slice(&buffer[..retained]);
        if retained != count {
            exceeded = true;
        }
    }
    Ok(StreamOutput { bytes, exceeded })
}

/// Runs a trusted executable with no inherited environment and bounded resources.
pub fn run(spec: &CommandSpec) -> PolicyResult<BoundedOutput> {
    let metadata = std::fs::symlink_metadata(&spec.program)
        .map_err(|cause| error("inspect trusted executable", cause))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PolicyError::new(format!(
            "trusted executable is not a regular file: {}",
            spec.program.display()
        )));
    }
    let cwd = std::fs::canonicalize(&spec.cwd)
        .map_err(|cause| error("canonicalize trusted working directory", cause))?;
    if !cwd.is_dir() {
        return Err(PolicyError::new(format!(
            "trusted working directory is not a directory: {}",
            cwd.display()
        )));
    }

    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .current_dir(&cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }

    let mut child = command
        .spawn()
        .map_err(|cause| error("spawn trusted subprocess", cause))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| PolicyError::new("trusted subprocess stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| PolicyError::new("trusted subprocess stderr was not piped"))?;
    let stdout_limit = spec.max_stdout;
    let stderr_limit = spec.max_stderr;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, stdout_limit));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, stderr_limit));

    let started = Instant::now();
    let (status, timed_out) = loop {
        match child
            .try_wait()
            .map_err(|cause| error("poll trusted subprocess", cause))?
        {
            Some(status) => break (status, false),
            None if started.elapsed() >= spec.timeout => {
                child
                    .kill()
                    .map_err(|cause| error("terminate timed-out trusted subprocess", cause))?;
                let status = child
                    .wait()
                    .map_err(|cause| error("reap timed-out trusted subprocess", cause))?;
                break (status, true);
            }
            None => thread::sleep(POLL_INTERVAL),
        }
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| PolicyError::new("trusted subprocess stdout reader panicked"))?
        .map_err(|cause| error("read trusted subprocess stdout", cause))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| PolicyError::new("trusted subprocess stderr reader panicked"))?
        .map_err(|cause| error("read trusted subprocess stderr", cause))?;

    if timed_out {
        return Err(PolicyError::new(format!(
            "trusted subprocess timed out after {} ms: {}",
            spec.timeout.as_millis(),
            spec.program.display()
        )));
    }
    if stdout.exceeded {
        return Err(PolicyError::new(format!(
            "trusted subprocess stdout exceeded {} bytes: {}",
            spec.max_stdout,
            spec.program.display()
        )));
    }
    if stderr.exceeded {
        return Err(PolicyError::new(format!(
            "trusted subprocess stderr exceeded {} bytes: {}",
            spec.max_stderr,
            spec.program.display()
        )));
    }

    Ok(BoundedOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

/// Runs a trusted executable and requires a successful status.
pub fn run_checked(spec: &CommandSpec, label: &str) -> PolicyResult<BoundedOutput> {
    let output = run(spec)?;
    if output.status.success() {
        return Ok(output);
    }
    Err(PolicyError::new(format!(
        "{label} failed with status {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    )))
}

/// Requires a regular absolute trusted tool and returns its canonical path.
pub fn canonical_tool(path: &Path) -> PolicyResult<PathBuf> {
    if !path.is_absolute() {
        return Err(PolicyError::new(format!(
            "trusted tool path must be absolute: {}",
            path.display()
        )));
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|cause| error("inspect trusted tool", cause))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PolicyError::new(format!(
            "trusted tool is not a regular file: {}",
            path.display()
        )));
    }
    std::fs::canonicalize(path).map_err(|cause| error("canonicalize trusted tool", cause))
}
