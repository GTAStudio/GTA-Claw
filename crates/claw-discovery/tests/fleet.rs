//! Local container cell argv oracles for create, status, logs, backup, doctor
//! and remove.
//!
//! No process is spawned and no container daemon is contacted anywhere in this
//! file, so the exact argument vector each fleet operation would execute is
//! assertable on a runner with no container runtime installed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use claw_discovery::fleet_cli::{
    BACKUP_MOUNT_TARGET, CellOperation, CellSpec, CommandPlan, ContainerCli, DATA_MOUNT_TARGET,
    FleetPlanError, ImageRef, LABEL_CELL, MemberRole, MemberSpec, PlanPolicy,
};

const IMAGE: &str = "ghcr.io/gtastudio/claw-cell@sha256:\
                     3b1f2a4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708";

fn cli() -> ContainerCli {
    ContainerCli::new("podman").expect("container cli")
}

fn spec() -> CellSpec {
    let mut labels = BTreeMap::new();
    labels.insert("io.example.tier".to_owned(), "gold".to_owned());
    let mut environment = BTreeMap::new();
    environment.insert("CLAW_CELL".to_owned(), "alpha".to_owned());
    environment.insert("CLAW_LOG".to_owned(), "info".to_owned());
    CellSpec {
        cell_id: "alpha".to_owned(),
        image: ImageRef::parse(IMAGE).expect("image"),
        members: vec![
            MemberSpec {
                name: "lead".to_owned(),
                role: MemberRole::Leader,
                command: vec![
                    "claw-cell".to_owned(),
                    "--role".to_owned(),
                    "leader".to_owned(),
                ],
            },
            MemberSpec {
                name: "replica".to_owned(),
                role: MemberRole::Follower,
                command: vec![
                    "claw-cell".to_owned(),
                    "--role".to_owned(),
                    "follower".to_owned(),
                ],
            },
        ],
        data_volume: "claw-alpha-data".to_owned(),
        labels,
        environment,
    }
}

fn lines(plans: &[CommandPlan]) -> Vec<String> {
    plans.iter().map(CommandPlan::to_line).collect()
}

#[test]
fn create_plan_matches_the_pinned_argv() {
    let plans = cli()
        .plan(&spec(), &PlanPolicy::default(), &CellOperation::Create)
        .expect("create plan");

    assert_eq!(
        lines(&plans),
        vec![
            format!("podman network create --internal --label {LABEL_CELL}=alpha claw-alpha"),
            format!("podman volume create --label {LABEL_CELL}=alpha claw-alpha-data"),
            format!(
                "podman run --detach --name claw-alpha-lead --network claw-alpha \
                 --restart unless-stopped --label {LABEL_CELL}=alpha --label claw.member=lead \
                 --label claw.role=leader --label io.example.tier=gold \
                 --env CLAW_CELL=alpha --env CLAW_LOG=info \
                 --mount type=volume,source=claw-alpha-data,target={DATA_MOUNT_TARGET} \
                 {IMAGE} claw-cell --role leader"
            ),
            format!(
                "podman run --detach --name claw-alpha-replica --network claw-alpha \
                 --restart unless-stopped --label {LABEL_CELL}=alpha --label claw.member=replica \
                 --label claw.role=follower --label io.example.tier=gold \
                 --env CLAW_CELL=alpha --env CLAW_LOG=info \
                 --mount type=volume,source=claw-alpha-data,target={DATA_MOUNT_TARGET} \
                 {IMAGE} claw-cell --role follower"
            ),
        ]
    );

    // Ordering is deterministic: the network and volume exist before any member
    // references them, and labels and environment are emitted in sorted order
    // rather than in hash order.
    assert_eq!(
        plans[0].argv[0..2],
        ["network".to_owned(), "create".to_owned()]
    );
    assert_eq!(plans[0].program, Path::new("podman"));
    let repeated = cli()
        .plan(&spec(), &PlanPolicy::default(), &CellOperation::Create)
        .expect("second plan");
    assert_eq!(lines(&plans), lines(&repeated));
}

#[test]
fn status_logs_doctor_and_remove_plans_match_the_pinned_argv() {
    let cli = cli();
    let spec = spec();
    let policy = PlanPolicy::default();

    let status = cli
        .plan(&spec, &policy, &CellOperation::Status)
        .expect("status");
    assert_eq!(
        lines(&status),
        vec![format!(
            "podman ps --all --no-trunc --filter label={LABEL_CELL}=alpha \
             --format {{{{.Names}}}}\t{{{{.State}}}}\t{{{{.Status}}}}"
        )]
    );

    let logs = cli
        .plan(
            &spec,
            &policy,
            &CellOperation::Logs {
                member: "replica".to_owned(),
                tail: 200,
            },
        )
        .expect("logs");
    assert_eq!(
        lines(&logs),
        vec!["podman logs --timestamps --tail 200 claw-alpha-replica".to_owned()]
    );

    let doctor = cli
        .plan(&spec, &policy, &CellOperation::Doctor)
        .expect("doctor");
    assert_eq!(
        lines(&doctor),
        vec![
            "podman version --format {{json .}}".to_owned(),
            "podman network inspect claw-alpha".to_owned(),
            "podman volume inspect claw-alpha-data".to_owned(),
            "podman inspect --format \
             {{.Name}}\t{{.State.Status}}\t{{.State.Health.Status}}\t{{.RestartCount}} \
             claw-alpha-lead claw-alpha-replica"
                .to_owned(),
        ]
    );

    let remove = cli
        .plan(
            &spec,
            &policy,
            &CellOperation::Remove {
                purge_volume: false,
            },
        )
        .expect("remove");
    assert_eq!(
        lines(&remove),
        vec![
            "podman rm --force --volumes claw-alpha-lead claw-alpha-replica".to_owned(),
            "podman network rm claw-alpha".to_owned(),
        ],
        "the data volume must survive a remove that did not ask to purge it"
    );

    let purge = cli
        .plan(
            &spec,
            &policy,
            &CellOperation::Remove { purge_volume: true },
        )
        .expect("purge");
    assert_eq!(
        lines(&purge).last().map(String::as_str),
        Some("podman volume rm claw-alpha-data"),
        "purging must delete the volume last, after every reference is gone"
    );
}

#[test]
fn backup_plan_matches_the_pinned_argv_and_mounts_the_data_read_only() {
    let plans = cli()
        .plan(
            &spec(),
            &PlanPolicy::default(),
            &CellOperation::Backup {
                destination: PathBuf::from("/srv/claw/backups"),
                snapshot_id: "2026-07-27t0100".to_owned(),
            },
        )
        .expect("backup");

    assert_eq!(
        lines(&plans),
        vec![format!(
            "podman run --rm --network none --label {LABEL_CELL}=alpha \
             --mount type=volume,source=claw-alpha-data,target={DATA_MOUNT_TARGET},readonly \
             --mount type=bind,source=/srv/claw/backups,target={BACKUP_MOUNT_TARGET} \
             {IMAGE} tar --create --file {BACKUP_MOUNT_TARGET}/alpha-2026-07-27t0100.tar \
             --directory {DATA_MOUNT_TARGET} ."
        )]
    );
    assert!(
        plans[0]
            .argv
            .iter()
            .any(|argument| argument.ends_with(",readonly")),
        "a backup must never be able to write to the volume it is reading"
    );
    assert!(
        plans[0]
            .argv
            .windows(2)
            .any(|window| window == ["--network".to_owned(), "none".to_owned()]),
        "a backup container needs no network at all"
    );

    // A relative, traversing or Windows-shaped destination is refused rather
    // than resolved against whatever the process happens to have as its working
    // directory.
    for destination in [
        "relative/path",
        "/srv/../etc",
        "/srv/./etc",
        "/srv//etc",
        "C:\\srv\\backups",
    ] {
        let error = cli()
            .plan(
                &spec(),
                &PlanPolicy::default(),
                &CellOperation::Backup {
                    destination: PathBuf::from(destination),
                    snapshot_id: "snap".to_owned(),
                },
            )
            .expect_err("unsafe destination");
        assert!(
            matches!(error, FleetPlanError::InvalidPath { .. }),
            "destination {destination:?} must be refused, got {error}"
        );
    }
}

#[test]
fn values_that_would_inject_a_flag_or_a_mount_option_are_refused() {
    let policy = PlanPolicy::default();

    // A cell id that would be read as a flag never reaches argv.
    let mut flag_cell = spec();
    flag_cell.cell_id = "-rf".to_owned();
    let error = cli()
        .plan(&flag_cell, &policy, &CellOperation::Create)
        .expect_err("flag-shaped cell id");
    assert!(
        matches!(
            error,
            FleetPlanError::InvalidIdentifier {
                field: "cell id",
                ..
            }
        ),
        "got {error}"
    );

    // A volume name carrying a comma would append options to the --mount
    // specification, which is how a read-only mount becomes writable.
    let mut comma_volume = spec();
    comma_volume.data_volume = "claw-alpha-data,readonly=false".to_owned();
    assert!(
        matches!(
            cli()
                .plan(&comma_volume, &policy, &CellOperation::Create)
                .expect_err("comma in volume"),
            FleetPlanError::InvalidIdentifier {
                field: "data volume",
                ..
            }
        ),
        "a volume name must not be able to split the mount specification"
    );

    // The same applies to a backup destination, which is operator supplied.
    assert!(matches!(
        cli()
            .plan(
                &spec(),
                &policy,
                &CellOperation::Backup {
                    destination: PathBuf::from("/srv/backups,type=bind,source=/"),
                    snapshot_id: "snap".to_owned(),
                },
            )
            .expect_err("comma in destination"),
        FleetPlanError::InvalidValue { .. }
    ));

    // Line breaks and NULs corrupt whatever reads the resulting logs.
    let mut broken_env = spec();
    broken_env
        .environment
        .insert("CLAW_NOTE".to_owned(), "one\ntwo".to_owned());
    assert!(matches!(
        cli()
            .plan(&broken_env, &policy, &CellOperation::Create)
            .expect_err("newline in env value"),
        FleetPlanError::InvalidValue {
            field: "environment value",
            ..
        }
    ));

    let mut bad_env_key = spec();
    bad_env_key
        .environment
        .insert("2BAD".to_owned(), "x".to_owned());
    assert!(matches!(
        cli()
            .plan(&bad_env_key, &policy, &CellOperation::Create)
            .expect_err("bad env key"),
        FleetPlanError::InvalidValue {
            field: "environment key",
            ..
        }
    ));

    // The reserved label namespace cannot be overwritten, or a cell could
    // impersonate another cell's membership.
    let mut reserved = spec();
    reserved
        .labels
        .insert(LABEL_CELL.to_owned(), "beta".to_owned());
    assert_eq!(
        cli()
            .plan(&reserved, &policy, &CellOperation::Create)
            .expect_err("reserved label"),
        FleetPlanError::ReservedLabel(LABEL_CELL.to_owned())
    );

    // A container CLI path that would be read as a flag is refused up front.
    assert!(matches!(
        ContainerCli::new("--rm").expect_err("flag-shaped program"),
        FleetPlanError::InvalidProgram { .. }
    ));
    assert!(ContainerCli::new("").is_err());
}

#[test]
fn image_references_must_be_tagged_or_digest_pinned() {
    assert!(ImageRef::parse(IMAGE).expect("digest").is_digest_pinned());
    assert!(
        !ImageRef::parse("ghcr.io/gtastudio/claw-cell:2026.7.2")
            .expect("tag")
            .is_digest_pinned()
    );

    for bad in [
        "",
        "-flag:latest",
        "ghcr.io/gtastudio/claw-cell",
        "ghcr.io/gtastudio/claw-cell@sha512:abc",
        "ghcr.io/gtastudio/claw-cell@sha256:short",
        "ghcr.io/gtastudio/claw-cell:",
        "ghcr.io/gtastudio/claw-cell:-leading",
        "ghcr.io/gtastudio/claw-cell:tag with space",
        "ghcr.io//claw-cell:1",
        "GHCR.io/claw-cell:1",
    ] {
        assert!(
            ImageRef::parse(bad).is_err(),
            "image reference {bad:?} must be refused"
        );
    }

    // The strict default policy requires a digest; relaxing it is an explicit,
    // visible choice rather than the default.
    let mut tagged = spec();
    tagged.image = ImageRef::parse("ghcr.io/gtastudio/claw-cell:2026.7.2").expect("tag");
    assert!(matches!(
        cli()
            .plan(&tagged, &PlanPolicy::default(), &CellOperation::Create)
            .expect_err("unpinned image under the strict default"),
        FleetPlanError::InvalidImage { .. }
    ));
    let relaxed = PlanPolicy {
        require_digest_pinned_images: false,
        ..PlanPolicy::default()
    };
    assert!(
        cli()
            .plan(&tagged, &relaxed, &CellOperation::Create)
            .is_ok()
    );
}

#[test]
fn cell_membership_invariants_are_enforced_for_every_operation() {
    let policy = PlanPolicy::default();

    let mut empty = spec();
    empty.members.clear();
    assert_eq!(
        cli()
            .plan(&empty, &policy, &CellOperation::Status)
            .expect_err("empty cell"),
        FleetPlanError::EmptyCell("alpha".to_owned())
    );

    let mut two_leaders = spec();
    two_leaders.members[1].role = MemberRole::Leader;
    assert_eq!(
        cli()
            .plan(&two_leaders, &policy, &CellOperation::Create)
            .expect_err("split brain"),
        FleetPlanError::LeaderCount("alpha".to_owned(), 2)
    );

    let mut no_leader = spec();
    no_leader.members[0].role = MemberRole::Follower;
    assert_eq!(
        cli()
            .plan(&no_leader, &policy, &CellOperation::Create)
            .expect_err("leaderless"),
        FleetPlanError::LeaderCount("alpha".to_owned(), 0)
    );

    let mut duplicate = spec();
    duplicate.members[1].name = "lead".to_owned();
    assert_eq!(
        cli()
            .plan(&duplicate, &policy, &CellOperation::Create)
            .expect_err("duplicate member"),
        FleetPlanError::DuplicateMember("lead".to_owned())
    );

    // Reading logs for a member the cell does not have must not silently
    // succeed against a container name that belongs to someone else.
    assert_eq!(
        cli()
            .plan(
                &spec(),
                &policy,
                &CellOperation::Logs {
                    member: "ghost".to_owned(),
                    tail: 10,
                },
            )
            .expect_err("unknown member"),
        FleetPlanError::UnknownMember("ghost".to_owned())
    );
}

#[test]
fn full_create_status_logs_backup_doctor_remove_lifecycle_plans_cleanly() {
    let cli = cli();
    let spec = spec();
    let policy = PlanPolicy::default();
    let operations = [
        CellOperation::Create,
        CellOperation::Status,
        CellOperation::Logs {
            member: "lead".to_owned(),
            tail: 50,
        },
        CellOperation::Backup {
            destination: PathBuf::from("/srv/claw/backups"),
            snapshot_id: "nightly".to_owned(),
        },
        CellOperation::Doctor,
        CellOperation::Remove { purge_volume: true },
    ];

    let mut names = Vec::new();
    for operation in &operations {
        let plans = cli
            .plan(&spec, &policy, operation)
            .unwrap_or_else(|error| panic!("{operation:?} must plan: {error}"));
        assert!(!plans.is_empty(), "{operation:?} produced no command");
        for plan in &plans {
            assert_eq!(plan.program, Path::new("podman"));
            assert!(
                !plan.argv.is_empty() && !plan.argv[0].starts_with('-'),
                "{operation:?} must start with a subcommand, got {:?}",
                plan.argv
            );
            for argument in &plan.argv {
                assert!(
                    !argument.contains('\0') && !argument.contains('\n'),
                    "{operation:?} emitted an argument with a control character: {argument:?}"
                );
            }
            names.push(plan.argv[0].clone());
        }
    }

    // Every operation reached the container CLI through a distinct subcommand,
    // so no operation is quietly aliased to another.
    assert!(names.contains(&"run".to_owned()));
    assert!(names.contains(&"ps".to_owned()));
    assert!(names.contains(&"logs".to_owned()));
    assert!(names.contains(&"version".to_owned()));
    assert!(names.contains(&"rm".to_owned()));
    assert!(names.contains(&"network".to_owned()));
    assert!(names.contains(&"volume".to_owned()));

    // Container and network naming is namespaced per cell, so two cells on one
    // host can never collide.
    assert_eq!(spec.container_name("lead"), "claw-alpha-lead");
    assert_eq!(spec.network_name(), "claw-alpha");
    let mut other = spec.clone();
    other.cell_id = "beta".to_owned();
    assert_ne!(spec.container_name("lead"), other.container_name("lead"));
    assert_ne!(spec.network_name(), other.network_name());
}
