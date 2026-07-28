//! The argument vector planner for local container cells.
//!
//! Every fleet operation eventually becomes an `execve` of a container CLI with
//! a list of arguments assembled from operator-supplied names, images, mounts,
//! environment and labels. That assembly is the whole attack surface: there is
//! no shell here to quote, so a value that starts with `-` becomes a flag, a
//! value containing `,` splits a `--mount` specification into extra options, and
//! a value containing a newline or a NUL corrupts whatever reads the log.
//!
//! This module builds those vectors and nothing else. It never spawns a process
//! and never contacts a container daemon, so the exact argv for create, status,
//! logs, backup, doctor and remove is assertable on a runner with no container
//! runtime installed at all.

use core::fmt;
use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};

/// Label key carrying the cell identifier.
pub const LABEL_CELL: &str = "claw.cell";
/// Label key carrying the member name.
pub const LABEL_MEMBER: &str = "claw.member";
/// Label key carrying the member role.
pub const LABEL_ROLE: &str = "claw.role";
/// Mount point the cell data volume is exposed at inside a member.
pub const DATA_MOUNT_TARGET: &str = "/var/lib/claw";
/// Mount point a backup writes into.
pub const BACKUP_MOUNT_TARGET: &str = "/backup";

/// The role a member plays inside its cell.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MemberRole {
    /// Holds the write lease.
    Leader,
    /// Follows the leader.
    Follower,
}

impl MemberRole {
    /// Returns the label value for this role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Leader => "leader",
            Self::Follower => "follower",
        }
    }
}

impl fmt::Display for MemberRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A validated container image reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageRef {
    reference: String,
    digest_pinned: bool,
}

impl ImageRef {
    /// Parses an image reference.
    ///
    /// Only two forms are accepted: `repository@sha256:<64 hex>` and
    /// `repository:<tag>`. A bare repository is refused because it silently
    /// resolves to `:latest`, which makes a cell unreproducible.
    ///
    /// # Errors
    ///
    /// Returns [`FleetPlanError::InvalidImage`] for any other shape, for a
    /// reference that would be read as a flag, and for a reference carrying a
    /// character that is not valid in a repository, tag or digest.
    pub fn parse(reference: &str) -> Result<Self, FleetPlanError> {
        let invalid = |detail: &str| FleetPlanError::InvalidImage {
            image: reference.to_owned(),
            detail: detail.to_owned(),
        };
        if reference.is_empty() {
            return Err(invalid("empty image reference"));
        }
        if reference.starts_with('-') {
            return Err(invalid("image reference would be parsed as a flag"));
        }
        if let Some((repository, digest)) = reference.split_once('@') {
            validate_repository(repository).map_err(|detail| invalid(&detail))?;
            let hex = digest
                .strip_prefix("sha256:")
                .ok_or_else(|| invalid("digest must use the sha256 algorithm"))?;
            if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(invalid("sha256 digest must be 64 hex characters"));
            }
            return Ok(Self {
                reference: reference.to_owned(),
                digest_pinned: true,
            });
        }
        let (repository, tag) = reference
            .rsplit_once(':')
            .ok_or_else(|| invalid("image reference must carry a tag or a digest"))?;
        if repository.contains('/') && tag.contains('/') {
            return Err(invalid("tag must not contain a path separator"));
        }
        validate_repository(repository).map_err(|detail| invalid(&detail))?;
        if tag.is_empty() || tag.len() > 128 {
            return Err(invalid("tag must be 1 to 128 characters"));
        }
        let tag_byte_ok =
            |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.' || byte == b'-';
        if !tag.bytes().all(tag_byte_ok) || tag.starts_with(['.', '-']) {
            return Err(invalid("tag carries a character outside [A-Za-z0-9_.-]"));
        }
        Ok(Self {
            reference: reference.to_owned(),
            digest_pinned: false,
        })
    }

    /// Returns the reference exactly as it will appear in argv.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.reference
    }

    /// Returns `true` when the reference is pinned to a digest.
    #[must_use]
    pub const fn is_digest_pinned(&self) -> bool {
        self.digest_pinned
    }
}

fn validate_repository(repository: &str) -> Result<(), String> {
    if repository.is_empty() {
        return Err("empty repository".to_owned());
    }
    let byte_ok = |byte: u8| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'-' | b'_' | b'/')
    };
    if !repository.bytes().all(byte_ok) {
        return Err("repository carries a character outside [a-z0-9._/-]".to_owned());
    }
    if repository.starts_with('/') || repository.ends_with('/') || repository.contains("//") {
        return Err("repository has an empty path element".to_owned());
    }
    Ok(())
}

/// One member of a cell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberSpec {
    /// Member name, unique within the cell.
    pub name: String,
    /// Member role.
    pub role: MemberRole,
    /// Command appended after the image, positionally.
    pub command: Vec<String>,
}

/// A local container cell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellSpec {
    /// Cell identifier, unique on the host.
    pub cell_id: String,
    /// Image every member runs.
    pub image: ImageRef,
    /// Members, in the order they are created.
    pub members: Vec<MemberSpec>,
    /// Named volume holding the cell's durable state.
    pub data_volume: String,
    /// Extra labels applied to every member.
    pub labels: BTreeMap<String, String>,
    /// Environment applied to every member.
    pub environment: BTreeMap<String, String>,
}

impl CellSpec {
    /// Validates every operator-supplied field.
    ///
    /// # Errors
    ///
    /// Returns the first [`FleetPlanError`] the specification violates.
    pub fn validate(&self, policy: &PlanPolicy) -> Result<(), FleetPlanError> {
        validate_identifier("cell id", &self.cell_id)?;
        validate_identifier("data volume", &self.data_volume)?;
        if policy.require_digest_pinned_images && !self.image.is_digest_pinned() {
            return Err(FleetPlanError::InvalidImage {
                image: self.image.as_str().to_owned(),
                detail: "policy requires a digest-pinned image".to_owned(),
            });
        }
        if self.members.is_empty() {
            return Err(FleetPlanError::EmptyCell(self.cell_id.clone()));
        }
        let leaders = self
            .members
            .iter()
            .filter(|member| member.role == MemberRole::Leader)
            .count();
        if leaders != 1 {
            return Err(FleetPlanError::LeaderCount(self.cell_id.clone(), leaders));
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.members.len());
        for member in &self.members {
            validate_identifier("member name", &member.name)?;
            if seen.contains(&member.name.as_str()) {
                return Err(FleetPlanError::DuplicateMember(member.name.clone()));
            }
            seen.push(&member.name);
            for argument in &member.command {
                validate_argument("command argument", argument)?;
            }
        }
        for (key, value) in &self.environment {
            validate_environment_key(key)?;
            validate_argument("environment value", value)?;
        }
        for (key, value) in &self.labels {
            validate_label_key(key)?;
            validate_argument("label value", value)?;
            if key.starts_with("claw.") {
                return Err(FleetPlanError::ReservedLabel(key.clone()));
            }
        }
        Ok(())
    }

    /// Returns the container name for `member`.
    #[must_use]
    pub fn container_name(&self, member: &str) -> String {
        format!("claw-{}-{member}", self.cell_id)
    }

    /// Returns the private network name for this cell.
    #[must_use]
    pub fn network_name(&self) -> String {
        format!("claw-{}", self.cell_id)
    }
}

/// Knobs that harden or relax planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanPolicy {
    /// Whether an image must be pinned to a digest.
    pub require_digest_pinned_images: bool,
    /// Restart policy applied to every member.
    pub restart_policy: String,
}

impl Default for PlanPolicy {
    /// The default policy is the strict one: images must be digest pinned.
    fn default() -> Self {
        Self {
            require_digest_pinned_images: true,
            restart_policy: "unless-stopped".to_owned(),
        }
    }
}

/// The fleet operations that reach the container CLI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CellOperation {
    /// Create the network, the volume and every member.
    Create,
    /// Report the state of every member.
    Status,
    /// Read one member's logs.
    Logs {
        /// Member to read.
        member: String,
        /// Number of trailing lines.
        tail: u32,
    },
    /// Snapshot the data volume into a host directory.
    Backup {
        /// Host directory receiving the archive.
        destination: PathBuf,
        /// Caller-supplied identifier naming the archive.
        snapshot_id: String,
    },
    /// Collect the diagnostics a cell health report is built from.
    Doctor,
    /// Delete every member, then the network, then optionally the volume.
    Remove {
        /// Whether the data volume is deleted too.
        purge_volume: bool,
    },
}

/// One planned invocation of the container CLI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPlan {
    /// Executable to run.
    pub program: PathBuf,
    /// Arguments, excluding `argv[0]`.
    pub argv: Vec<String>,
}

impl CommandPlan {
    /// Renders the plan as a single space-joined line, for assertions.
    #[must_use]
    pub fn to_line(&self) -> String {
        let mut line = self.program.display().to_string();
        for argument in &self.argv {
            line.push(' ');
            line.push_str(argument);
        }
        line
    }
}

/// A validated container CLI executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerCli {
    program: PathBuf,
}

impl ContainerCli {
    /// Validates a container CLI path.
    ///
    /// # Errors
    ///
    /// Returns [`FleetPlanError::InvalidProgram`] for an empty path, a path that
    /// would be parsed as a flag, and a path carrying a NUL or a newline.
    pub fn new(program: impl Into<PathBuf>) -> Result<Self, FleetPlanError> {
        let program = program.into();
        let text = program.to_string_lossy().into_owned();
        let invalid = |detail: &str| FleetPlanError::InvalidProgram {
            program: text.clone(),
            detail: detail.to_owned(),
        };
        if text.is_empty() {
            return Err(invalid("empty program path"));
        }
        if text.starts_with('-') {
            return Err(invalid("program path would be parsed as a flag"));
        }
        if text
            .bytes()
            .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
        {
            return Err(invalid("program path carries a control character"));
        }
        Ok(Self { program })
    }

    /// Returns the executable path.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Plans one operation against one cell.
    ///
    /// The returned plans are executed in order; an empty list is never
    /// returned.
    ///
    /// # Errors
    ///
    /// Returns the first [`FleetPlanError`] the specification or the operation
    /// violates.
    pub fn plan(
        &self,
        spec: &CellSpec,
        policy: &PlanPolicy,
        operation: &CellOperation,
    ) -> Result<Vec<CommandPlan>, FleetPlanError> {
        spec.validate(policy)?;
        let plans = match operation {
            CellOperation::Create => self.plan_create(spec, policy),
            CellOperation::Status => vec![self.command(vec![
                "ps".to_owned(),
                "--all".to_owned(),
                "--no-trunc".to_owned(),
                "--filter".to_owned(),
                format!("label={LABEL_CELL}={}", spec.cell_id),
                "--format".to_owned(),
                "{{.Names}}\t{{.State}}\t{{.Status}}".to_owned(),
            ])],
            CellOperation::Logs { member, tail } => {
                if !spec.members.iter().any(|entry| entry.name == *member) {
                    return Err(FleetPlanError::UnknownMember(member.clone()));
                }
                vec![self.command(vec![
                    "logs".to_owned(),
                    "--timestamps".to_owned(),
                    "--tail".to_owned(),
                    tail.to_string(),
                    spec.container_name(member),
                ])]
            }
            CellOperation::Backup {
                destination,
                snapshot_id,
            } => self.plan_backup(spec, destination, snapshot_id)?,
            CellOperation::Doctor => self.plan_doctor(spec),
            CellOperation::Remove { purge_volume } => self.plan_remove(spec, *purge_volume),
        };
        Ok(plans)
    }

    fn command(&self, argv: Vec<String>) -> CommandPlan {
        CommandPlan {
            program: self.program.clone(),
            argv,
        }
    }

    fn plan_create(&self, spec: &CellSpec, policy: &PlanPolicy) -> Vec<CommandPlan> {
        let network = spec.network_name();
        let mut plans = vec![
            self.command(vec![
                "network".to_owned(),
                "create".to_owned(),
                "--internal".to_owned(),
                "--label".to_owned(),
                format!("{LABEL_CELL}={}", spec.cell_id),
                network.clone(),
            ]),
            self.command(vec![
                "volume".to_owned(),
                "create".to_owned(),
                "--label".to_owned(),
                format!("{LABEL_CELL}={}", spec.cell_id),
                spec.data_volume.clone(),
            ]),
        ];
        for member in &spec.members {
            let mut argv = vec![
                "run".to_owned(),
                "--detach".to_owned(),
                "--name".to_owned(),
                spec.container_name(&member.name),
                "--network".to_owned(),
                network.clone(),
                "--restart".to_owned(),
                policy.restart_policy.clone(),
                "--label".to_owned(),
                format!("{LABEL_CELL}={}", spec.cell_id),
                "--label".to_owned(),
                format!("{LABEL_MEMBER}={}", member.name),
                "--label".to_owned(),
                format!("{LABEL_ROLE}={}", member.role),
            ];
            for (key, value) in &spec.labels {
                argv.push("--label".to_owned());
                argv.push(format!("{key}={value}"));
            }
            for (key, value) in &spec.environment {
                argv.push("--env".to_owned());
                argv.push(format!("{key}={value}"));
            }
            argv.push("--mount".to_owned());
            argv.push(format!(
                "type=volume,source={},target={DATA_MOUNT_TARGET}",
                spec.data_volume
            ));
            argv.push(spec.image.as_str().to_owned());
            argv.extend(member.command.iter().cloned());
            plans.push(self.command(argv));
        }
        plans
    }

    fn plan_backup(
        &self,
        spec: &CellSpec,
        destination: &Path,
        snapshot_id: &str,
    ) -> Result<Vec<CommandPlan>, FleetPlanError> {
        validate_identifier("snapshot id", snapshot_id)?;
        let destination_text = destination.to_string_lossy().into_owned();
        // A container bind source is a POSIX path inside the runtime's view of
        // the world, so it is validated as one. Using the host's notion of an
        // absolute path would make a plan that is valid on Linux and refused on
        // Windows, or the reverse.
        validate_posix_directory(&destination_text)?;
        validate_mount_field("backup destination", &destination_text)?;
        Ok(vec![self.command(vec![
            "run".to_owned(),
            "--rm".to_owned(),
            "--network".to_owned(),
            "none".to_owned(),
            "--label".to_owned(),
            format!("{LABEL_CELL}={}", spec.cell_id),
            "--mount".to_owned(),
            format!(
                "type=volume,source={},target={DATA_MOUNT_TARGET},readonly",
                spec.data_volume
            ),
            "--mount".to_owned(),
            format!("type=bind,source={destination_text},target={BACKUP_MOUNT_TARGET}"),
            spec.image.as_str().to_owned(),
            "tar".to_owned(),
            "--create".to_owned(),
            "--file".to_owned(),
            format!("{BACKUP_MOUNT_TARGET}/{}-{snapshot_id}.tar", spec.cell_id),
            "--directory".to_owned(),
            DATA_MOUNT_TARGET.to_owned(),
            ".".to_owned(),
        ])])
    }

    fn plan_doctor(&self, spec: &CellSpec) -> Vec<CommandPlan> {
        let mut plans = vec![
            self.command(vec![
                "version".to_owned(),
                "--format".to_owned(),
                "{{json .}}".to_owned(),
            ]),
            self.command(vec![
                "network".to_owned(),
                "inspect".to_owned(),
                spec.network_name(),
            ]),
            self.command(vec![
                "volume".to_owned(),
                "inspect".to_owned(),
                spec.data_volume.clone(),
            ]),
        ];
        let mut inspect = vec![
            "inspect".to_owned(),
            "--format".to_owned(),
            "{{.Name}}\t{{.State.Status}}\t{{.State.Health.Status}}\t{{.RestartCount}}".to_owned(),
        ];
        inspect.extend(
            spec.members
                .iter()
                .map(|member| spec.container_name(&member.name)),
        );
        plans.push(self.command(inspect));
        plans
    }

    fn plan_remove(&self, spec: &CellSpec, purge_volume: bool) -> Vec<CommandPlan> {
        let mut remove = vec![
            "rm".to_owned(),
            "--force".to_owned(),
            "--volumes".to_owned(),
        ];
        remove.extend(
            spec.members
                .iter()
                .map(|member| spec.container_name(&member.name)),
        );
        let mut plans = vec![
            self.command(remove),
            self.command(vec![
                "network".to_owned(),
                "rm".to_owned(),
                spec.network_name(),
            ]),
        ];
        if purge_volume {
            plans.push(self.command(vec![
                "volume".to_owned(),
                "rm".to_owned(),
                spec.data_volume.clone(),
            ]));
        }
        plans
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), FleetPlanError> {
    let reject = |detail: &str| FleetPlanError::InvalidIdentifier {
        field,
        value: value.to_owned(),
        detail: detail.to_owned(),
    };
    if value.is_empty() || value.len() > 63 {
        return Err(reject("identifier must be 1 to 63 characters"));
    }
    let byte_ok = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-';
    if !value.bytes().all(byte_ok) {
        return Err(reject("identifier carries a character outside [a-z0-9-]"));
    }
    if value.starts_with('-') || value.ends_with('-') {
        return Err(reject("identifier must not start or end with a hyphen"));
    }
    Ok(())
}

fn validate_argument(field: &'static str, value: &str) -> Result<(), FleetPlanError> {
    if value
        .bytes()
        .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
    {
        return Err(FleetPlanError::InvalidValue {
            field,
            value: value.to_owned(),
            detail: "value carries a NUL or a line break".to_owned(),
        });
    }
    Ok(())
}

fn validate_environment_key(key: &str) -> Result<(), FleetPlanError> {
    let reject = |detail: &str| FleetPlanError::InvalidValue {
        field: "environment key",
        value: key.to_owned(),
        detail: detail.to_owned(),
    };
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return Err(reject("empty environment key"));
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Err(reject(
            "environment key must start with a letter or underscore",
        ));
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
        return Err(reject(
            "environment key carries a character outside [A-Za-z0-9_]",
        ));
    }
    Ok(())
}

fn validate_label_key(key: &str) -> Result<(), FleetPlanError> {
    let reject = |detail: &str| FleetPlanError::InvalidValue {
        field: "label key",
        value: key.to_owned(),
        detail: detail.to_owned(),
    };
    if key.is_empty() {
        return Err(reject("empty label key"));
    }
    let byte_ok =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/');
    if !key.bytes().all(byte_ok) {
        return Err(reject(
            "label key carries a character outside [A-Za-z0-9._/-]",
        ));
    }
    if key.contains('=') {
        return Err(reject("label key must not contain an equals sign"));
    }
    Ok(())
}

fn validate_posix_directory(path: &str) -> Result<(), FleetPlanError> {
    let reject = |detail: &str| FleetPlanError::InvalidPath {
        path: path.to_owned(),
        detail: detail.to_owned(),
    };
    if !path.starts_with('/') {
        return Err(reject("path must be POSIX absolute"));
    }
    if path.contains('\\') {
        return Err(reject("path must not carry a backslash"));
    }
    if path
        .bytes()
        .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
    {
        return Err(reject("path carries a control character"));
    }
    for segment in path.trim_end_matches('/').split('/').skip(1) {
        if segment.is_empty() {
            return Err(reject("path has an empty segment"));
        }
        if segment == "." || segment == ".." {
            return Err(reject("path traverses relative to itself"));
        }
    }
    Ok(())
}

fn validate_mount_field(field: &'static str, value: &str) -> Result<(), FleetPlanError> {
    if value.bytes().any(|byte| matches!(byte, b',' | b'=' | 0)) {
        return Err(FleetPlanError::InvalidValue {
            field,
            value: value.to_owned(),
            detail: "value would split the --mount specification into extra options".to_owned(),
        });
    }
    Ok(())
}

/// Every way a fleet plan can be refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FleetPlanError {
    /// The container CLI path was unusable.
    InvalidProgram {
        /// The offending path.
        program: String,
        /// Why it was refused.
        detail: String,
    },
    /// An image reference was unusable.
    InvalidImage {
        /// The offending reference.
        image: String,
        /// Why it was refused.
        detail: String,
    },
    /// A cell, volume, member or snapshot identifier was unusable.
    InvalidIdentifier {
        /// Which field held it.
        field: &'static str,
        /// The offending value.
        value: String,
        /// Why it was refused.
        detail: String,
    },
    /// An environment, label or command value was unusable.
    InvalidValue {
        /// Which field held it.
        field: &'static str,
        /// The offending value.
        value: String,
        /// Why it was refused.
        detail: String,
    },
    /// A filesystem path was unusable.
    InvalidPath {
        /// The offending path.
        path: String,
        /// Why it was refused.
        detail: String,
    },
    /// A label collided with the reserved `claw.` namespace.
    ReservedLabel(String),
    /// The cell declared no members.
    EmptyCell(String),
    /// The cell declared a number of leaders other than one.
    LeaderCount(String, usize),
    /// Two members shared a name.
    DuplicateMember(String),
    /// An operation named a member the cell does not have.
    UnknownMember(String),
}

impl fmt::Display for FleetPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProgram { program, detail } => {
                write!(formatter, "container CLI {program:?} rejected: {detail}")
            }
            Self::InvalidImage { image, detail } => {
                write!(formatter, "image {image:?} rejected: {detail}")
            }
            Self::InvalidIdentifier {
                field,
                value,
                detail,
            }
            | Self::InvalidValue {
                field,
                value,
                detail,
            } => write!(formatter, "{field} {value:?} rejected: {detail}"),
            Self::InvalidPath { path, detail } => {
                write!(formatter, "path {path:?} rejected: {detail}")
            }
            Self::ReservedLabel(key) => write!(
                formatter,
                "label {key:?} collides with the reserved claw. namespace"
            ),
            Self::EmptyCell(cell) => write!(formatter, "cell {cell:?} declares no members"),
            Self::LeaderCount(cell, count) => {
                write!(
                    formatter,
                    "cell {cell:?} declares {count} leaders, expected 1"
                )
            }
            Self::DuplicateMember(name) => write!(formatter, "duplicate member {name:?}"),
            Self::UnknownMember(name) => write!(formatter, "cell has no member {name:?}"),
        }
    }
}

impl Error for FleetPlanError {}
