//! Local container fleet cells, coordination leases, health, and rolling updates.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::io::AsyncReadExt as _;
use tokio::process::Command;

const MAX_LEASE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_LOG_BYTES: usize = 1024 * 1024;
const MAX_LOG_LINES: u16 = 1000;

/// Fleet member's coordination role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberRole {
    /// Eligible to coordinate the cell.
    Coordinator,
    /// Workload-only member.
    Worker,
}

impl MemberRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::Worker => "worker",
        }
    }
}

/// One desired cell member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberSpec {
    /// Stable identifier unique within the cell.
    pub id: String,
    /// Coordination role.
    pub role: MemberRole,
}

/// Desired local container cell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellSpec {
    /// Stable cell identifier.
    pub id: String,
    /// OCI image reference.
    pub image: String,
    /// Ordered desired membership.
    pub members: Vec<MemberSpec>,
    /// Per-cell persistent-data root.
    pub data_root: PathBuf,
    /// Maximum time for a replacement to become healthy.
    pub health_timeout: Duration,
}

impl CellSpec {
    /// Validates identifiers, membership, image, and time bounds.
    pub fn validate(&self) -> Result<(), FleetError> {
        if !valid_identifier(&self.id)
            || !valid_image(&self.image)
            || self.members.is_empty()
            || self.members.len() > 128
            || self.data_root.as_os_str().is_empty()
            || self.health_timeout.is_zero()
            || self.health_timeout > Duration::from_secs(10 * 60)
        {
            return Err(FleetError::InvalidCell);
        }
        let mut ids = BTreeSet::new();
        let mut coordinators = 0_usize;
        for member in &self.members {
            if !valid_identifier(&member.id) || !ids.insert(member.id.as_str()) {
                return Err(FleetError::InvalidMember);
            }
            if member.role == MemberRole::Coordinator {
                coordinators += 1;
            }
        }
        if coordinators == 0 {
            return Err(FleetError::NoCoordinator);
        }
        Ok(())
    }
}

/// Observed container lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberState {
    /// Container is running and its health check, when present, passes.
    Healthy,
    /// Container is still starting.
    Starting,
    /// Container exists but is not healthy.
    Unhealthy,
    /// Container does not exist.
    Missing,
}

/// Observed member health.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberHealth {
    /// Member identifier.
    pub member_id: String,
    /// Container state.
    pub state: MemberState,
    /// Exit code when stopped.
    pub exit_code: Option<i64>,
    /// Unix timestamp supplied by the controller.
    pub checked_at: i64,
}

/// Member status including deployed image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberStatus {
    /// Desired member specification.
    pub member: MemberSpec,
    /// Currently deployed image.
    pub image: String,
    /// Latest observed health.
    pub health: MemberHealth,
}

/// Full cell status and coordination state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellStatus {
    /// Cell identifier.
    pub cell_id: String,
    /// Current desired image.
    pub desired_image: String,
    /// Current elected leader, when any coordinator is healthy.
    pub leader_id: Option<String>,
    /// Monotonic leader-election term.
    pub coordination_term: u64,
    /// Desired and observed membership in configured order.
    pub members: Vec<MemberStatus>,
}

/// Bounded logs for one member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberLogs {
    /// Member identifier.
    pub member_id: String,
    /// UTF-8 lossy log text.
    pub text: String,
}

/// Completed cell backup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupManifest {
    /// Cell identifier.
    pub cell_id: String,
    /// Destination root.
    pub destination: PathBuf,
    /// Backed-up member identifiers.
    pub members: Vec<String>,
    /// Unix completion timestamp.
    pub created_at: i64,
}

/// Cell diagnostic report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorReport {
    /// Cell identifier.
    pub cell_id: String,
    /// Whether runtime and all desired members are healthy.
    pub healthy: bool,
    /// Exact diagnostic issue list.
    pub issues: Vec<String>,
}

/// Successful rolling-update result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollingUpdateReport {
    /// Cell identifier.
    pub cell_id: String,
    /// New desired image.
    pub image: String,
    /// Members replaced in this invocation.
    pub updated_members: Vec<String>,
    /// Members already running the requested image.
    pub unchanged_members: Vec<String>,
}

/// Lease proving exclusive authority for one cell mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationLease {
    cell_id: String,
    holder: String,
    generation: u64,
    expires_at: i64,
}

impl OperationLease {
    /// Cell protected by this lease.
    #[must_use]
    pub fn cell_id(&self) -> &str {
        &self.cell_id
    }

    /// Lease holder identifier.
    #[must_use]
    pub fn holder(&self) -> &str {
        &self.holder
    }

    /// Unix lease expiry.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// Local container runtime boundary used by the fleet controller.
#[async_trait]
pub trait ContainerRuntime: Send + Sync {
    /// Creates the cell network and persistent roots.
    async fn prepare_cell(&self, cell: &CellSpec) -> Result<(), FleetError>;
    /// Starts one desired member.
    async fn start_member(
        &self,
        cell: &CellSpec,
        member: &MemberSpec,
        image: &str,
    ) -> Result<(), FleetError>;
    /// Removes one member.
    async fn remove_member(&self, cell_id: &str, member_id: &str) -> Result<(), FleetError>;
    /// Removes cell-wide runtime resources.
    async fn remove_cell(&self, cell_id: &str) -> Result<(), FleetError>;
    /// Reads member health.
    async fn member_health(
        &self,
        cell_id: &str,
        member_id: &str,
        checked_at: i64,
    ) -> Result<MemberHealth, FleetError>;
    /// Reads bounded member logs.
    async fn member_logs(
        &self,
        cell_id: &str,
        member_id: &str,
        tail_lines: u16,
    ) -> Result<String, FleetError>;
    /// Copies persistent member state to the backup root.
    async fn backup_member(
        &self,
        cell_id: &str,
        member_id: &str,
        destination: &Path,
    ) -> Result<(), FleetError>;
    /// Verifies the local container engine.
    async fn doctor(&self) -> Result<(), FleetError>;
    /// Pulls an image before replacement starts.
    async fn pull_image(&self, image: &str) -> Result<(), FleetError>;
    /// Replaces one member and rolls it back unless it becomes healthy.
    async fn update_member(
        &self,
        cell: &CellSpec,
        member: &MemberSpec,
        image: &str,
        checked_at: i64,
    ) -> Result<MemberHealth, FleetError>;
}

/// Docker/Podman-compatible command adapter that never invokes a shell.
pub struct CliContainerRuntime {
    executable: PathBuf,
}

impl CliContainerRuntime {
    /// Selects an explicit container CLI executable.
    pub fn new(executable: PathBuf) -> Result<Self, FleetError> {
        if executable.as_os_str().is_empty() {
            return Err(FleetError::InvalidRuntime);
        }
        Ok(Self { executable })
    }

    async fn command<I, S>(&self, arguments: I) -> Result<Vec<u8>, FleetError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut child = Command::new(&self.executable)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(FleetError::Io)?;
        let mut stdout = child.stdout.take().ok_or(FleetError::InvalidRuntime)?;
        let mut output = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let read = stdout.read(&mut buffer).await.map_err(FleetError::Io)?;
            if read == 0 {
                break;
            }
            if output.len().saturating_add(read) > MAX_LOG_BYTES {
                child.kill().await.map_err(FleetError::Io)?;
                return Err(FleetError::RuntimeOutputTooLarge);
            }
            output.extend_from_slice(&buffer[..read]);
        }
        let status = child.wait().await.map_err(FleetError::Io)?;
        if !status.success() {
            return Err(FleetError::RuntimeCommand(status.code().unwrap_or(-1)));
        }
        Ok(output)
    }

    async fn start_named_member(
        &self,
        cell: &CellSpec,
        member: &MemberSpec,
        image: &str,
        container_name: &str,
    ) -> Result<(), FleetError> {
        let member_root = cell.data_root.join(&member.id);
        tokio::fs::create_dir_all(&member_root)
            .await
            .map_err(FleetError::Io)?;
        let volume = format!("{}:/var/lib/gta-claw", member_root.display());
        self.command([
            "run",
            "-d",
            "--name",
            container_name,
            "--network",
            &network_name(&cell.id),
            "--restart",
            "unless-stopped",
            "--label",
            &format!("gta-claw.cell={}", cell.id),
            "--label",
            &format!("gta-claw.member={}", member.id),
            "--env",
            &format!("GTA_CLAW_CELL_ID={}", cell.id),
            "--env",
            &format!("GTA_CLAW_MEMBER_ID={}", member.id),
            "--env",
            &format!("GTA_CLAW_MEMBER_ROLE={}", member.role.as_str()),
            "--volume",
            &volume,
            image,
        ])
        .await
        .map(|_| ())
    }

    async fn member_exists(&self, cell_id: &str, member_id: &str) -> Result<bool, FleetError> {
        let output = self.command(["ps", "-a", "--format", "{{.Names}}"]).await?;
        listed_resource_exists(&output, &container_name(cell_id, member_id))
    }

    async fn network_exists(&self, cell_id: &str) -> Result<bool, FleetError> {
        let output = self
            .command(["network", "ls", "--format", "{{.Name}}"])
            .await?;
        listed_resource_exists(&output, &network_name(cell_id))
    }

    async fn inspect_health(
        &self,
        name: &str,
        member_id: &str,
        checked_at: i64,
    ) -> Result<MemberHealth, FleetError> {
        if !self.member_exists_by_name(name).await? {
            return Ok(MemberHealth {
                member_id: member_id.to_owned(),
                state: MemberState::Missing,
                exit_code: None,
                checked_at,
            });
        }
        let output = self
            .command(["inspect", "--format", "{{json .State}}", name])
            .await?;
        let state = serde_json::from_slice::<ContainerState>(&output)
            .map_err(FleetError::InvalidRuntimeResponse)?;
        let observed = if !state.running {
            MemberState::Unhealthy
        } else {
            match state.health.as_ref().map(|health| health.status.as_str()) {
                None | Some("healthy") => MemberState::Healthy,
                Some("starting") => MemberState::Starting,
                Some(_) => MemberState::Unhealthy,
            }
        };
        Ok(MemberHealth {
            member_id: member_id.to_owned(),
            state: observed,
            exit_code: (!state.running).then_some(state.exit_code),
            checked_at,
        })
    }

    async fn member_exists_by_name(&self, name: &str) -> Result<bool, FleetError> {
        let output = self.command(["ps", "-a", "--format", "{{.Names}}"]).await?;
        listed_resource_exists(&output, name)
    }

    async fn rollback_update(&self, cell_id: &str, member_id: &str) -> Result<(), FleetError> {
        let name = container_name(cell_id, member_id);
        let rollback = rollback_name(cell_id, member_id);
        let removal = self.command(["rm", "-f", &name]).await;
        let rename = self.command(["rename", &rollback, &name]).await;
        match (removal, rename) {
            (_, Ok(_)) => {}
            (Ok(_), Err(error)) => return Err(error),
            (Err(removal), Err(rename)) => {
                return Err(FleetError::RollbackFailed {
                    operation: removal.to_string(),
                    rollback: rename.to_string(),
                });
            }
        }
        self.command(["start", &name]).await.map(|_| ())
    }

    async fn rollback_failure(
        &self,
        cell_id: &str,
        member_id: &str,
        operation: FleetError,
    ) -> FleetError {
        match self.rollback_update(cell_id, member_id).await {
            Ok(()) => operation,
            Err(rollback) => FleetError::RollbackFailed {
                operation: operation.to_string(),
                rollback: rollback.to_string(),
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerState {
    running: bool,
    exit_code: i64,
    health: Option<ContainerHealth>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerHealth {
    status: String,
}

#[async_trait]
impl ContainerRuntime for CliContainerRuntime {
    async fn prepare_cell(&self, cell: &CellSpec) -> Result<(), FleetError> {
        tokio::fs::create_dir_all(&cell.data_root)
            .await
            .map_err(FleetError::Io)?;
        self.command(["network", "create", &network_name(&cell.id)])
            .await
            .map(|_| ())
    }

    async fn start_member(
        &self,
        cell: &CellSpec,
        member: &MemberSpec,
        image: &str,
    ) -> Result<(), FleetError> {
        self.start_named_member(cell, member, image, &container_name(&cell.id, &member.id))
            .await
    }

    async fn remove_member(&self, cell_id: &str, member_id: &str) -> Result<(), FleetError> {
        if !self.member_exists(cell_id, member_id).await? {
            return Ok(());
        }
        let name = container_name(cell_id, member_id);
        match self.command(["rm", "-f", &name]).await {
            Ok(_) => Ok(()),
            Err(error) => {
                if self.member_exists_by_name(&name).await? {
                    Err(error)
                } else {
                    Ok(())
                }
            }
        }
    }

    async fn remove_cell(&self, cell_id: &str) -> Result<(), FleetError> {
        if !self.network_exists(cell_id).await? {
            return Ok(());
        }
        let name = network_name(cell_id);
        match self.command(["network", "rm", &name]).await {
            Ok(_) => Ok(()),
            Err(error) => {
                if self.network_exists(cell_id).await? {
                    Err(error)
                } else {
                    Ok(())
                }
            }
        }
    }

    async fn member_health(
        &self,
        cell_id: &str,
        member_id: &str,
        checked_at: i64,
    ) -> Result<MemberHealth, FleetError> {
        self.inspect_health(&container_name(cell_id, member_id), member_id, checked_at)
            .await
    }

    async fn member_logs(
        &self,
        cell_id: &str,
        member_id: &str,
        tail_lines: u16,
    ) -> Result<String, FleetError> {
        if tail_lines == 0 || tail_lines > MAX_LOG_LINES {
            return Err(FleetError::InvalidLogLimit);
        }
        let output = self
            .command([
                "logs",
                "--tail",
                &tail_lines.to_string(),
                &container_name(cell_id, member_id),
            ])
            .await?;
        Ok(String::from_utf8_lossy(&output).into_owned())
    }

    async fn backup_member(
        &self,
        cell_id: &str,
        member_id: &str,
        destination: &Path,
    ) -> Result<(), FleetError> {
        tokio::fs::create_dir_all(destination)
            .await
            .map_err(FleetError::Io)?;
        let source = format!("{}:/var/lib/gta-claw/.", container_name(cell_id, member_id));
        self.command(["cp", &source, &destination.display().to_string()])
            .await
            .map(|_| ())
    }

    async fn doctor(&self) -> Result<(), FleetError> {
        self.command(["version", "--format", "{{.Server.Version}}"])
            .await
            .map(|_| ())
    }

    async fn pull_image(&self, image: &str) -> Result<(), FleetError> {
        if !valid_image(image) {
            return Err(FleetError::InvalidImage);
        }
        self.command(["pull", image]).await.map(|_| ())
    }

    async fn update_member(
        &self,
        cell: &CellSpec,
        member: &MemberSpec,
        image: &str,
        checked_at: i64,
    ) -> Result<MemberHealth, FleetError> {
        let name = container_name(&cell.id, &member.id);
        let rollback = rollback_name(&cell.id, &member.id);
        self.command(["rename", &name, &rollback]).await?;
        if let Err(error) = self.command(["stop", &rollback]).await {
            return match self.command(["rename", &rollback, &name]).await {
                Ok(_) => Err(error),
                Err(rollback) => Err(FleetError::RollbackFailed {
                    operation: error.to_string(),
                    rollback: rollback.to_string(),
                }),
            };
        }
        if let Err(error) = self.start_named_member(cell, member, image, &name).await {
            return Err(self.rollback_failure(&cell.id, &member.id, error).await);
        }

        let deadline = tokio::time::Instant::now() + cell.health_timeout;
        loop {
            let health = match self.inspect_health(&name, &member.id, checked_at).await {
                Ok(health) => health,
                Err(error) => {
                    return Err(self.rollback_failure(&cell.id, &member.id, error).await);
                }
            };
            match health.state {
                MemberState::Healthy => {
                    if let Err(error) = self.command(["rm", "-f", &rollback]).await {
                        return Err(self.rollback_failure(&cell.id, &member.id, error).await);
                    }
                    return Ok(health);
                }
                MemberState::Starting if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                MemberState::Starting | MemberState::Unhealthy | MemberState::Missing => {
                    let error = FleetError::ReplacementUnhealthy(member.id.clone());
                    return Err(self.rollback_failure(&cell.id, &member.id, error).await);
                }
            }
        }
    }
}

#[derive(Clone)]
struct CellRecord {
    spec: CellSpec,
    deployed_images: BTreeMap<String, String>,
    removed_members: BTreeSet<String>,
    leader_id: Option<String>,
    coordination_term: u64,
}

/// Fleet lifecycle and coordination controller.
pub struct FleetController<R> {
    runtime: R,
    cells: BTreeMap<String, CellRecord>,
    leases: BTreeMap<String, OperationLease>,
    next_lease_generation: u64,
}

impl<R: ContainerRuntime> FleetController<R> {
    /// Creates an empty fleet around a local runtime adapter.
    #[must_use]
    pub fn new(runtime: R) -> Self {
        Self {
            runtime,
            cells: BTreeMap::new(),
            leases: BTreeMap::new(),
            next_lease_generation: 1,
        }
    }

    /// Acquires an exclusive, maximum-five-minute operation lease.
    pub fn acquire_lease(
        &mut self,
        cell_id: &str,
        holder: &str,
        now: i64,
        ttl: Duration,
    ) -> Result<OperationLease, FleetError> {
        if !valid_identifier(cell_id)
            || !valid_identifier(holder)
            || ttl.is_zero()
            || ttl > MAX_LEASE_TTL
        {
            return Err(FleetError::InvalidLease);
        }
        if self
            .leases
            .get(cell_id)
            .is_some_and(|lease| lease.expires_at > now)
        {
            return Err(FleetError::LeaseConflict);
        }
        let ttl = i64::try_from(ttl.as_secs()).map_err(|_| FleetError::InvalidLease)?;
        let lease = OperationLease {
            cell_id: cell_id.to_owned(),
            holder: holder.to_owned(),
            generation: self.next_lease_generation,
            expires_at: now.saturating_add(ttl),
        };
        self.next_lease_generation = self.next_lease_generation.saturating_add(1);
        self.leases.insert(cell_id.to_owned(), lease.clone());
        Ok(lease)
    }

    /// Renews an exact live lease.
    pub fn renew_lease(
        &mut self,
        lease: &OperationLease,
        now: i64,
        ttl: Duration,
    ) -> Result<OperationLease, FleetError> {
        self.validate_lease(lease, now)?;
        if ttl.is_zero() || ttl > MAX_LEASE_TTL {
            return Err(FleetError::InvalidLease);
        }
        let ttl = i64::try_from(ttl.as_secs()).map_err(|_| FleetError::InvalidLease)?;
        let mut renewed = lease.clone();
        renewed.expires_at = now.saturating_add(ttl);
        self.leases.insert(renewed.cell_id.clone(), renewed.clone());
        Ok(renewed)
    }

    /// Releases an exact lease.
    pub fn release_lease(&mut self, lease: &OperationLease) -> Result<(), FleetError> {
        if self.leases.get(&lease.cell_id) != Some(lease) {
            return Err(FleetError::LeaseMismatch);
        }
        self.leases.remove(&lease.cell_id);
        Ok(())
    }

    /// Creates all local runtime resources and members transactionally.
    pub async fn create(
        &mut self,
        spec: CellSpec,
        lease: &OperationLease,
        now: i64,
    ) -> Result<CellStatus, FleetError> {
        spec.validate()?;
        self.validate_lease_for(&spec.id, lease, now)?;
        if self.cells.contains_key(&spec.id) {
            return Err(FleetError::CellExists);
        }
        self.runtime.prepare_cell(&spec).await?;
        let mut started = Vec::<String>::new();
        for member in &spec.members {
            if let Err(error) = self.runtime.start_member(&spec, member, &spec.image).await {
                let mut cleanup_failures = Vec::new();
                for member_id in started.iter().rev() {
                    if let Err(cleanup) = self.runtime.remove_member(&spec.id, member_id).await {
                        cleanup_failures.push(format!("{member_id}: {cleanup}"));
                    }
                }
                if let Err(cleanup) = self.runtime.remove_cell(&spec.id).await {
                    cleanup_failures.push(format!("cell: {cleanup}"));
                }
                return if cleanup_failures.is_empty() {
                    Err(error)
                } else {
                    Err(FleetError::RollbackFailed {
                        operation: error.to_string(),
                        rollback: cleanup_failures.join("; "),
                    })
                };
            }
            started.push(member.id.clone());
        }
        let deployed_images = spec
            .members
            .iter()
            .map(|member| (member.id.clone(), spec.image.clone()))
            .collect();
        self.cells.insert(
            spec.id.clone(),
            CellRecord {
                spec,
                deployed_images,
                removed_members: BTreeSet::new(),
                leader_id: None,
                coordination_term: 0,
            },
        );
        match self.status(lease.cell_id(), now).await {
            Ok(status) => Ok(status),
            Err(error) => {
                let mut cleanup_failures = Vec::new();
                for member_id in started.iter().rev() {
                    match self.runtime.remove_member(lease.cell_id(), member_id).await {
                        Ok(()) => {
                            self.cells
                                .get_mut(lease.cell_id())
                                .ok_or(FleetError::RegistryCorrupt)?
                                .removed_members
                                .insert(member_id.clone());
                        }
                        Err(cleanup) => {
                            cleanup_failures.push(format!("{member_id}: {cleanup}"));
                        }
                    }
                }
                if let Err(cleanup) = self.runtime.remove_cell(lease.cell_id()).await {
                    cleanup_failures.push(format!("cell: {cleanup}"));
                }
                if cleanup_failures.is_empty() {
                    self.cells.remove(lease.cell_id());
                    Err(error)
                } else {
                    Err(FleetError::RollbackFailed {
                        operation: error.to_string(),
                        rollback: cleanup_failures.join("; "),
                    })
                }
            }
        }
    }

    /// Reads health and performs deterministic healthy-coordinator failover.
    pub async fn status(&mut self, cell_id: &str, now: i64) -> Result<CellStatus, FleetError> {
        let record = self
            .cells
            .get_mut(cell_id)
            .ok_or(FleetError::CellNotFound)?;
        let mut members = Vec::with_capacity(record.spec.members.len());
        for member in &record.spec.members {
            let health = self.runtime.member_health(cell_id, &member.id, now).await?;
            members.push(MemberStatus {
                member: member.clone(),
                image: record
                    .deployed_images
                    .get(&member.id)
                    .cloned()
                    .ok_or(FleetError::RegistryCorrupt)?,
                health,
            });
        }
        let eligible = members
            .iter()
            .filter(|status| {
                status.member.role == MemberRole::Coordinator
                    && status.health.state == MemberState::Healthy
            })
            .map(|status| status.member.id.as_str())
            .collect::<BTreeSet<_>>();
        let next_leader = record
            .leader_id
            .as_ref()
            .filter(|leader| eligible.contains(leader.as_str()))
            .cloned()
            .or_else(|| eligible.first().map(|leader| (*leader).to_owned()));
        if next_leader != record.leader_id {
            record.coordination_term = record.coordination_term.saturating_add(1);
            record.leader_id.clone_from(&next_leader);
        }
        Ok(CellStatus {
            cell_id: cell_id.to_owned(),
            desired_image: record.spec.image.clone(),
            leader_id: next_leader,
            coordination_term: record.coordination_term,
            members,
        })
    }

    /// Returns bounded logs for every desired member.
    pub async fn logs(
        &self,
        cell_id: &str,
        tail_lines: u16,
    ) -> Result<Vec<MemberLogs>, FleetError> {
        if tail_lines == 0 || tail_lines > MAX_LOG_LINES {
            return Err(FleetError::InvalidLogLimit);
        }
        let record = self.cells.get(cell_id).ok_or(FleetError::CellNotFound)?;
        let mut logs = Vec::with_capacity(record.spec.members.len());
        for member in &record.spec.members {
            let text = self
                .runtime
                .member_logs(cell_id, &member.id, tail_lines)
                .await?;
            if text.len() > MAX_LOG_BYTES {
                return Err(FleetError::RuntimeOutputTooLarge);
            }
            logs.push(MemberLogs {
                member_id: member.id.clone(),
                text,
            });
        }
        Ok(logs)
    }

    /// Backs up all desired members while holding an operation lease.
    pub async fn backup(
        &self,
        cell_id: &str,
        destination: PathBuf,
        lease: &OperationLease,
        now: i64,
    ) -> Result<BackupManifest, FleetError> {
        self.validate_lease_for(cell_id, lease, now)?;
        if destination.as_os_str().is_empty() {
            return Err(FleetError::InvalidBackupPath);
        }
        let record = self.cells.get(cell_id).ok_or(FleetError::CellNotFound)?;
        let mut backed_up = Vec::with_capacity(record.spec.members.len());
        for member in &record.spec.members {
            self.runtime
                .backup_member(cell_id, &member.id, &destination.join(&member.id))
                .await?;
            backed_up.push(member.id.clone());
        }
        Ok(BackupManifest {
            cell_id: cell_id.to_owned(),
            destination,
            members: backed_up,
            created_at: now,
        })
    }

    /// Checks runtime availability, membership, health, and leadership.
    pub async fn doctor(&mut self, cell_id: &str, now: i64) -> Result<DoctorReport, FleetError> {
        let mut issues = Vec::new();
        if let Err(error) = self.runtime.doctor().await {
            issues.push(error.to_string());
        }
        let status = self.status(cell_id, now).await?;
        for member in &status.members {
            if member.health.state != MemberState::Healthy {
                issues.push(format!(
                    "member {} is {:?}",
                    member.member.id, member.health.state
                ));
            }
        }
        if status.leader_id.is_none() {
            issues.push("cell has no healthy coordinator".to_owned());
        }
        Ok(DoctorReport {
            cell_id: cell_id.to_owned(),
            healthy: issues.is_empty(),
            issues,
        })
    }

    /// Replaces members one at a time, preserving a resumable partial state.
    pub async fn rolling_update(
        &mut self,
        cell_id: &str,
        image: &str,
        lease: &OperationLease,
        now: i64,
    ) -> Result<RollingUpdateReport, FleetError> {
        self.validate_lease_for(cell_id, lease, now)?;
        if !valid_image(image) {
            return Err(FleetError::InvalidImage);
        }
        self.runtime.pull_image(image).await?;
        let record = self
            .cells
            .get_mut(cell_id)
            .ok_or(FleetError::CellNotFound)?;
        record.spec.image = image.to_owned();
        let mut updated = Vec::new();
        let mut unchanged = Vec::new();
        for member in &record.spec.members {
            if record
                .deployed_images
                .get(&member.id)
                .is_some_and(|deployed| deployed == image)
            {
                unchanged.push(member.id.clone());
                continue;
            }
            match self
                .runtime
                .update_member(&record.spec, member, image, now)
                .await
            {
                Ok(health) if health.state == MemberState::Healthy => {
                    record
                        .deployed_images
                        .insert(member.id.clone(), image.to_owned());
                    updated.push(member.id.clone());
                }
                Ok(_) => {
                    return Err(FleetError::RollingUpdateFailed {
                        member_id: member.id.clone(),
                        updated_members: updated,
                        cause: "replacement did not become healthy".to_owned(),
                    });
                }
                Err(error) => {
                    return Err(FleetError::RollingUpdateFailed {
                        member_id: member.id.clone(),
                        updated_members: updated,
                        cause: error.to_string(),
                    });
                }
            }
        }
        Ok(RollingUpdateReport {
            cell_id: cell_id.to_owned(),
            image: image.to_owned(),
            updated_members: updated,
            unchanged_members: unchanged,
        })
    }

    /// Tears down every member and cell-wide runtime resource.
    pub async fn remove(
        &mut self,
        cell_id: &str,
        lease: &OperationLease,
        now: i64,
    ) -> Result<(), FleetError> {
        self.validate_lease_for(cell_id, lease, now)?;
        let record = self.cells.get(cell_id).ok_or(FleetError::CellNotFound)?;
        let pending_members = record
            .spec
            .members
            .iter()
            .rev()
            .filter(|member| !record.removed_members.contains(&member.id))
            .map(|member| member.id.clone())
            .collect::<Vec<_>>();
        let mut failures = Vec::new();
        for member_id in pending_members {
            match self.runtime.remove_member(cell_id, &member_id).await {
                Ok(()) => {
                    self.cells
                        .get_mut(cell_id)
                        .ok_or(FleetError::RegistryCorrupt)?
                        .removed_members
                        .insert(member_id);
                }
                Err(error) => failures.push(format!("member {member_id}: {error}")),
            }
        }
        if !failures.is_empty() {
            return Err(FleetError::TeardownFailed(failures));
        }
        if let Err(error) = self.runtime.remove_cell(cell_id).await {
            return Err(FleetError::TeardownFailed(vec![format!(
                "cell resources: {error}"
            )]));
        }
        self.cells.remove(cell_id);
        Ok(())
    }

    fn validate_lease(&self, lease: &OperationLease, now: i64) -> Result<(), FleetError> {
        self.validate_lease_for(&lease.cell_id, lease, now)
    }

    fn validate_lease_for(
        &self,
        cell_id: &str,
        lease: &OperationLease,
        now: i64,
    ) -> Result<(), FleetError> {
        if lease.cell_id != cell_id || self.leases.get(cell_id) != Some(lease) {
            return Err(FleetError::LeaseMismatch);
        }
        if lease.expires_at <= now {
            return Err(FleetError::LeaseExpired);
        }
        Ok(())
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && !value.starts_with('-')
}

fn listed_resource_exists(output: &[u8], expected: &str) -> Result<bool, FleetError> {
    let output = std::str::from_utf8(output).map_err(|_| FleetError::InvalidRuntimeOutput)?;
    Ok(output
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .any(|line| line == expected))
}

fn valid_image(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with('-')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'.' | b'-' | b'_' | b'@')
        })
}

fn network_name(cell_id: &str) -> String {
    format!("gta-claw-{cell_id}")
}

fn container_name(cell_id: &str, member_id: &str) -> String {
    format!("gta-claw.{cell_id}.{member_id}")
}

fn rollback_name(cell_id: &str, member_id: &str) -> String {
    format!("gta-claw.{cell_id}.{member_id}.rollback")
}

/// Fleet configuration, lease, runtime, or lifecycle failure.
#[derive(Debug)]
pub enum FleetError {
    /// Cell specification is malformed.
    InvalidCell,
    /// Member specification is malformed.
    InvalidMember,
    /// Cell has no coordination candidate.
    NoCoordinator,
    /// Image reference is malformed.
    InvalidImage,
    /// Runtime executable is malformed.
    InvalidRuntime,
    /// Lease request is malformed.
    InvalidLease,
    /// Another live lease owns the cell.
    LeaseConflict,
    /// Supplied lease does not match the registry.
    LeaseMismatch,
    /// Supplied lease has expired.
    LeaseExpired,
    /// Cell already exists.
    CellExists,
    /// Cell does not exist.
    CellNotFound,
    /// In-memory deployed membership is inconsistent.
    RegistryCorrupt,
    /// Requested log limit is invalid.
    InvalidLogLimit,
    /// Backup destination is invalid.
    InvalidBackupPath,
    /// Runtime output exceeded its fixed bound.
    RuntimeOutputTooLarge,
    /// Container CLI returned a non-zero status.
    RuntimeCommand(i32),
    /// Runtime JSON was malformed.
    InvalidRuntimeResponse(serde_json::Error),
    /// Runtime name-list output was not UTF-8.
    InvalidRuntimeOutput,
    /// Runtime filesystem or process I/O failed.
    Io(std::io::Error),
    /// Replacement did not become healthy and was rolled back.
    ReplacementUnhealthy(String),
    /// Creation cleanup failed after an operation error.
    RollbackFailed {
        /// Initial operation failure.
        operation: String,
        /// Cleanup failure.
        rollback: String,
    },
    /// Rolling update stopped after preserving prior healthy members.
    RollingUpdateFailed {
        /// Member whose replacement failed.
        member_id: String,
        /// Members successfully replaced before failure.
        updated_members: Vec<String>,
        /// Sanitized failure category.
        cause: String,
    },
    /// Teardown attempted every pending resource but one or more failed.
    TeardownFailed(Vec<String>),
}

impl Display for FleetError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCell => formatter.write_str("invalid fleet cell"),
            Self::InvalidMember => formatter.write_str("invalid fleet member"),
            Self::NoCoordinator => formatter.write_str("fleet cell has no coordinator"),
            Self::InvalidImage => formatter.write_str("invalid container image"),
            Self::InvalidRuntime => formatter.write_str("invalid container runtime"),
            Self::InvalidLease => formatter.write_str("invalid fleet operation lease"),
            Self::LeaseConflict => formatter.write_str("fleet operation lease conflict"),
            Self::LeaseMismatch => formatter.write_str("fleet operation lease mismatch"),
            Self::LeaseExpired => formatter.write_str("fleet operation lease expired"),
            Self::CellExists => formatter.write_str("fleet cell already exists"),
            Self::CellNotFound => formatter.write_str("fleet cell not found"),
            Self::RegistryCorrupt => formatter.write_str("fleet registry is inconsistent"),
            Self::InvalidLogLimit => formatter.write_str("invalid fleet log limit"),
            Self::InvalidBackupPath => formatter.write_str("invalid fleet backup path"),
            Self::RuntimeOutputTooLarge => {
                formatter.write_str("container runtime output is too large")
            }
            Self::RuntimeCommand(code) => {
                write!(
                    formatter,
                    "container runtime command failed with status {code}"
                )
            }
            Self::InvalidRuntimeResponse(error) => {
                write!(formatter, "invalid container runtime response: {error}")
            }
            Self::InvalidRuntimeOutput => {
                formatter.write_str("invalid container runtime name-list output")
            }
            Self::Io(error) => write!(formatter, "fleet runtime I/O failed: {error}"),
            Self::ReplacementUnhealthy(member) => {
                write!(formatter, "replacement for member {member} is unhealthy")
            }
            Self::RollbackFailed {
                operation,
                rollback,
            } => write!(
                formatter,
                "fleet operation failed ({operation}) and cleanup failed ({rollback})"
            ),
            Self::RollingUpdateFailed {
                member_id,
                updated_members,
                cause,
            } => write!(
                formatter,
                "rolling update failed at {member_id} after {} members: {cause}",
                updated_members.len()
            ),
            Self::TeardownFailed(failures) => {
                write!(
                    formatter,
                    "fleet teardown failed for {} resources",
                    failures.len()
                )
            }
        }
    }
}

impl Error for FleetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRuntimeResponse(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct FakeRuntime {
        calls: Mutex<Vec<String>>,
        health: Mutex<BTreeMap<String, MemberState>>,
        fail_update: Mutex<Option<String>>,
        fail_removal: Mutex<BTreeSet<String>>,
        fail_health: Mutex<Option<String>>,
    }

    impl FakeRuntime {
        fn call(&self, value: String) {
            self.calls.lock().expect("calls").push(value);
        }
    }

    #[async_trait]
    impl ContainerRuntime for FakeRuntime {
        async fn prepare_cell(&self, cell: &CellSpec) -> Result<(), FleetError> {
            self.call(format!("prepare:{}", cell.id));
            Ok(())
        }

        async fn start_member(
            &self,
            cell: &CellSpec,
            member: &MemberSpec,
            image: &str,
        ) -> Result<(), FleetError> {
            self.call(format!("start:{}:{}:{image}", cell.id, member.id));
            self.health
                .lock()
                .expect("health")
                .insert(member.id.clone(), MemberState::Healthy);
            Ok(())
        }

        async fn remove_member(&self, cell_id: &str, member_id: &str) -> Result<(), FleetError> {
            self.call(format!("remove-member:{cell_id}:{member_id}"));
            if self
                .fail_removal
                .lock()
                .expect("removal failures")
                .contains(member_id)
            {
                return Err(FleetError::RuntimeCommand(1));
            }
            Ok(())
        }

        async fn remove_cell(&self, cell_id: &str) -> Result<(), FleetError> {
            self.call(format!("remove-cell:{cell_id}"));
            Ok(())
        }

        async fn member_health(
            &self,
            _cell_id: &str,
            member_id: &str,
            checked_at: i64,
        ) -> Result<MemberHealth, FleetError> {
            if self.fail_health.lock().expect("health failure").as_deref() == Some(member_id) {
                return Err(FleetError::RuntimeCommand(2));
            }
            let state = self
                .health
                .lock()
                .expect("health")
                .get(member_id)
                .copied()
                .unwrap_or(MemberState::Missing);
            Ok(MemberHealth {
                member_id: member_id.to_owned(),
                state,
                exit_code: None,
                checked_at,
            })
        }

        async fn member_logs(
            &self,
            cell_id: &str,
            member_id: &str,
            tail_lines: u16,
        ) -> Result<String, FleetError> {
            self.call(format!("logs:{cell_id}:{member_id}:{tail_lines}"));
            Ok(format!("{member_id}-log"))
        }

        async fn backup_member(
            &self,
            cell_id: &str,
            member_id: &str,
            destination: &Path,
        ) -> Result<(), FleetError> {
            self.call(format!(
                "backup:{cell_id}:{member_id}:{}",
                destination.display()
            ));
            Ok(())
        }

        async fn doctor(&self) -> Result<(), FleetError> {
            self.call("doctor".to_owned());
            Ok(())
        }

        async fn pull_image(&self, image: &str) -> Result<(), FleetError> {
            self.call(format!("pull:{image}"));
            Ok(())
        }

        async fn update_member(
            &self,
            _cell: &CellSpec,
            member: &MemberSpec,
            image: &str,
            checked_at: i64,
        ) -> Result<MemberHealth, FleetError> {
            self.call(format!("update:{}:{image}", member.id));
            if self.fail_update.lock().expect("fail").as_deref() == Some(&member.id) {
                return Err(FleetError::ReplacementUnhealthy(member.id.clone()));
            }
            Ok(MemberHealth {
                member_id: member.id.clone(),
                state: MemberState::Healthy,
                exit_code: None,
                checked_at,
            })
        }
    }

    fn spec() -> CellSpec {
        CellSpec {
            id: "studio".to_owned(),
            image: "ghcr.io/gtastudio/gta-claw:1.0.0".to_owned(),
            members: vec![
                MemberSpec {
                    id: "alpha".to_owned(),
                    role: MemberRole::Coordinator,
                },
                MemberSpec {
                    id: "beta".to_owned(),
                    role: MemberRole::Coordinator,
                },
                MemberSpec {
                    id: "worker".to_owned(),
                    role: MemberRole::Worker,
                },
            ],
            data_root: PathBuf::from("fleet-data"),
            health_timeout: Duration::from_secs(30),
        }
    }

    #[tokio::test]
    async fn full_create_status_logs_backup_doctor_remove_lifecycle() {
        let mut controller = FleetController::new(FakeRuntime::default());
        let lease = controller
            .acquire_lease("studio", "operator", 100, Duration::from_secs(300))
            .expect("lease");

        let created = controller
            .create(spec(), &lease, 101)
            .await
            .expect("create");
        assert_eq!(created.leader_id, Some("alpha".to_owned()));
        assert_eq!(created.coordination_term, 1);
        assert_eq!(created.members.len(), 3);

        let logs = controller.logs("studio", 50).await.expect("logs");
        assert_eq!(
            logs,
            vec![
                MemberLogs {
                    member_id: "alpha".to_owned(),
                    text: "alpha-log".to_owned(),
                },
                MemberLogs {
                    member_id: "beta".to_owned(),
                    text: "beta-log".to_owned(),
                },
                MemberLogs {
                    member_id: "worker".to_owned(),
                    text: "worker-log".to_owned(),
                },
            ]
        );
        let backup = controller
            .backup("studio", PathBuf::from("backup"), &lease, 102)
            .await
            .expect("backup");
        assert_eq!(
            backup,
            BackupManifest {
                cell_id: "studio".to_owned(),
                destination: PathBuf::from("backup"),
                members: vec!["alpha".to_owned(), "beta".to_owned(), "worker".to_owned()],
                created_at: 102,
            }
        );
        assert_eq!(
            controller.doctor("studio", 103).await.expect("doctor"),
            DoctorReport {
                cell_id: "studio".to_owned(),
                healthy: true,
                issues: Vec::new(),
            }
        );
        controller
            .remove("studio", &lease, 104)
            .await
            .expect("remove");
        assert!(matches!(
            controller.status("studio", 105).await,
            Err(FleetError::CellNotFound)
        ));
    }

    #[tokio::test]
    async fn leadership_fails_over_and_term_advances() {
        let runtime = FakeRuntime::default();
        let mut controller = FleetController::new(runtime);
        let lease = controller
            .acquire_lease("studio", "operator", 100, Duration::from_secs(300))
            .expect("lease");
        controller
            .create(spec(), &lease, 101)
            .await
            .expect("create");
        controller
            .runtime
            .health
            .lock()
            .expect("health")
            .insert("alpha".to_owned(), MemberState::Unhealthy);

        let status = controller.status("studio", 102).await.expect("status");

        assert_eq!(status.leader_id, Some("beta".to_owned()));
        assert_eq!(status.coordination_term, 2);
    }

    #[test]
    fn operation_leases_conflict_expire_and_require_exact_tokens() {
        let mut controller = FleetController::new(FakeRuntime::default());
        let first = controller
            .acquire_lease("studio", "operator", 100, Duration::from_secs(300))
            .expect("first");
        assert!(matches!(
            controller.acquire_lease("studio", "other", 101, Duration::from_secs(300)),
            Err(FleetError::LeaseConflict)
        ));
        let second = controller
            .acquire_lease("studio", "other", 401, Duration::from_secs(300))
            .expect("expired lease can be replaced");
        assert_ne!(first, second);
        assert!(matches!(
            controller.release_lease(&first),
            Err(FleetError::LeaseMismatch)
        ));
        controller.release_lease(&second).expect("release");
    }

    #[tokio::test]
    async fn rolling_update_stops_on_failure_and_preserves_resume_state() {
        let runtime = FakeRuntime::default();
        *runtime.fail_update.lock().expect("fail") = Some("beta".to_owned());
        let mut controller = FleetController::new(runtime);
        let lease = controller
            .acquire_lease("studio", "operator", 100, Duration::from_secs(300))
            .expect("lease");
        controller
            .create(spec(), &lease, 101)
            .await
            .expect("create");

        let error = controller
            .rolling_update("studio", "ghcr.io/gtastudio/gta-claw:2.0.0", &lease, 102)
            .await
            .expect_err("beta update fails");
        match error {
            FleetError::RollingUpdateFailed {
                member_id,
                updated_members,
                cause,
            } => {
                assert_eq!(member_id, "beta");
                assert_eq!(updated_members, vec!["alpha"]);
                assert_eq!(cause, "replacement for member beta is unhealthy");
            }
            other => panic!("unexpected error: {other}"),
        }
        let status = controller.status("studio", 103).await.expect("status");
        assert_eq!(
            status
                .members
                .iter()
                .map(|member| member.image.as_str())
                .collect::<Vec<_>>(),
            vec![
                "ghcr.io/gtastudio/gta-claw:2.0.0",
                "ghcr.io/gtastudio/gta-claw:1.0.0",
                "ghcr.io/gtastudio/gta-claw:1.0.0",
            ]
        );
    }

    #[tokio::test]
    async fn creation_health_failure_rolls_back_registry_and_runtime() {
        let runtime = FakeRuntime::default();
        *runtime.fail_health.lock().expect("health failure") = Some("alpha".to_owned());
        let mut controller = FleetController::new(runtime);
        let lease = controller
            .acquire_lease("studio", "operator", 100, Duration::from_secs(300))
            .expect("lease");

        let error = controller
            .create(spec(), &lease, 101)
            .await
            .expect_err("health inspection fails");
        assert!(matches!(error, FleetError::RuntimeCommand(2)));
        assert!(matches!(
            controller.status("studio", 102).await,
            Err(FleetError::CellNotFound)
        ));
        assert_eq!(
            *controller.runtime.calls.lock().expect("calls"),
            vec![
                "prepare:studio",
                "start:studio:alpha:ghcr.io/gtastudio/gta-claw:1.0.0",
                "start:studio:beta:ghcr.io/gtastudio/gta-claw:1.0.0",
                "start:studio:worker:ghcr.io/gtastudio/gta-claw:1.0.0",
                "remove-member:studio:worker",
                "remove-member:studio:beta",
                "remove-member:studio:alpha",
                "remove-cell:studio",
            ]
        );
        *controller
            .runtime
            .fail_health
            .lock()
            .expect("health failure") = None;
        controller
            .create(spec(), &lease, 103)
            .await
            .expect("retry creation");
    }

    #[tokio::test]
    async fn teardown_aggregates_failures_and_retries_only_pending_resources() {
        let runtime = FakeRuntime::default();
        runtime
            .fail_removal
            .lock()
            .expect("removal failures")
            .extend(["alpha".to_owned(), "worker".to_owned()]);
        let mut controller = FleetController::new(runtime);
        let lease = controller
            .acquire_lease("studio", "operator", 100, Duration::from_secs(300))
            .expect("lease");
        controller
            .create(spec(), &lease, 101)
            .await
            .expect("create");

        let error = controller
            .remove("studio", &lease, 102)
            .await
            .expect_err("two removals fail");
        match error {
            FleetError::TeardownFailed(failures) => assert_eq!(
                failures,
                vec![
                    "member worker: container runtime command failed with status 1",
                    "member alpha: container runtime command failed with status 1",
                ]
            ),
            other => panic!("unexpected error: {other}"),
        }
        controller
            .runtime
            .fail_removal
            .lock()
            .expect("removal failures")
            .clear();
        controller
            .remove("studio", &lease, 103)
            .await
            .expect("resume teardown");

        assert_eq!(
            *controller.runtime.calls.lock().expect("calls"),
            vec![
                "prepare:studio",
                "start:studio:alpha:ghcr.io/gtastudio/gta-claw:1.0.0",
                "start:studio:beta:ghcr.io/gtastudio/gta-claw:1.0.0",
                "start:studio:worker:ghcr.io/gtastudio/gta-claw:1.0.0",
                "remove-member:studio:worker",
                "remove-member:studio:beta",
                "remove-member:studio:alpha",
                "remove-member:studio:worker",
                "remove-member:studio:alpha",
                "remove-cell:studio",
            ]
        );
    }

    #[test]
    fn runtime_names_have_collision_free_member_and_rollback_namespaces() {
        assert_eq!(
            container_name("studio-alpha", "worker-rollback"),
            "gta-claw.studio-alpha.worker-rollback"
        );
        assert_eq!(
            rollback_name("studio-alpha", "worker"),
            "gta-claw.studio-alpha.worker.rollback"
        );
        assert_ne!(
            container_name("studio-alpha", "worker-rollback"),
            rollback_name("studio-alpha", "worker")
        );
        assert_ne!(
            container_name("studio-alpha", "worker"),
            container_name("studio", "alpha-worker")
        );
    }

    #[test]
    fn runtime_name_listing_confirms_exact_presence_and_absence() {
        assert!(
            listed_resource_exists(
                b"unrelated\r\ngta-claw.studio.worker\r\n",
                "gta-claw.studio.worker"
            )
            .expect("valid listing")
        );
        assert!(
            !listed_resource_exists(b"gta-claw.studio.worker-old\n", "gta-claw.studio.worker")
                .expect("valid listing")
        );
        assert!(matches!(
            listed_resource_exists(&[0xff], "gta-claw.studio.worker"),
            Err(FleetError::InvalidRuntimeOutput)
        ));
    }
}
