use serde_yaml_ng::{Mapping as YamlMapping, Value as YamlValue};
use toml::Value as TomlValue;

fn yaml_key(key: &str) -> YamlValue {
    YamlValue::String(key.to_owned())
}

fn yaml_mapping(value: &YamlValue) -> Option<&YamlMapping> {
    if let YamlValue::Mapping(mapping) = value {
        Some(mapping)
    } else {
        None
    }
}

fn yaml_mapping_mut(value: &mut YamlValue) -> Option<&mut YamlMapping> {
    if let YamlValue::Mapping(mapping) = value {
        Some(mapping)
    } else {
        None
    }
}

fn yaml_get<'a>(value: &'a YamlValue, key: &str) -> Option<&'a YamlValue> {
    yaml_mapping(value)?.get(yaml_key(key))
}

fn yaml_get_mut<'a>(value: &'a mut YamlValue, key: &str) -> Option<&'a mut YamlValue> {
    yaml_mapping_mut(value)?.get_mut(yaml_key(key))
}

fn yaml_string(value: Option<&YamlValue>) -> Option<&str> {
    if let Some(YamlValue::String(value)) = value {
        Some(value)
    } else {
        None
    }
}

fn yaml_sequence_mut(value: Option<&mut YamlValue>) -> Option<&mut Vec<YamlValue>> {
    if let Some(YamlValue::Sequence(sequence)) = value {
        Some(sequence)
    } else {
        None
    }
}

fn job_steps_mut<'a>(workflow: &'a mut YamlValue, job: &str) -> Option<&'a mut Vec<YamlValue>> {
    yaml_sequence_mut(yaml_get_mut(
        yaml_get_mut(yaml_get_mut(workflow, "jobs")?, job)?,
        "steps",
    ))
}

fn step_by_name_mut<'a>(
    workflow: &'a mut YamlValue,
    job: &str,
    name: &str,
) -> Option<&'a mut YamlValue> {
    let steps = job_steps_mut(workflow, job)?;
    if steps
        .iter()
        .filter(|step| yaml_string(yaml_get(step, "name")) == Some(name))
        .count()
        != 1
    {
        return None;
    }
    steps
        .iter_mut()
        .find(|step| yaml_string(yaml_get(step, "name")) == Some(name))
}

fn toml_table_mut<'a>(
    value: &'a mut TomlValue,
    key: &str,
) -> Option<&'a mut toml::map::Map<String, TomlValue>> {
    value.get_mut(key)?.as_table_mut()
}
pub fn mutate_negative_case(
    mutation: &str,
    workflow: &mut YamlValue,
    macos_workflow: &mut YamlValue,
    root_deny: &mut TomlValue,
    deny: &mut TomlValue,
    audit: &mut TomlValue,
    manifests: (&mut TomlValue, &mut TomlValue),
) {
    let (desktop_manifest, app_manifest) = manifests;
    match mutation {
        "root-audit-continue-on-error" => {
            yaml_mapping_mut(
                step_by_name_mut(workflow, "supply-chain", "Audit root lockfile")
                    .expect("root audit step"),
            )
            .expect("root audit mapping")
            .insert(yaml_key("continue-on-error"), YamlValue::Bool(true));
        }
        "desktop-audit-disabled" => {
            yaml_mapping_mut(
                step_by_name_mut(workflow, "supply-chain", "Audit desktop lockfile")
                    .expect("desktop audit step"),
            )
            .expect("desktop audit mapping")
            .insert(
                yaml_key("if"),
                YamlValue::String("github.event_name == 'schedule'".to_owned()),
            );
        }
        "desktop-audit-redirected" => {
            yaml_mapping_mut(
                step_by_name_mut(workflow, "supply-chain", "Audit desktop lockfile")
                    .expect("desktop audit step"),
            )
            .expect("desktop audit mapping")
            .insert(
                yaml_key("working-directory"),
                YamlValue::String(".".to_owned()),
            );
            let mut unrelated = YamlMapping::new();
            unrelated.insert(
                yaml_key("name"),
                YamlValue::String("Unrelated desktop step".to_owned()),
            );
            unrelated.insert(
                yaml_key("working-directory"),
                YamlValue::String("desktop".to_owned()),
            );
            unrelated.insert(yaml_key("run"), YamlValue::String("true".to_owned()));
            job_steps_mut(workflow, "supply-chain")
                .expect("supply-chain steps")
                .push(YamlValue::Mapping(unrelated));
        }
        "cargo-audit-install-latest" => {
            yaml_mapping_mut(
                step_by_name_mut(
                    workflow,
                    "supply-chain",
                    "Bootstrap verified Rust security tools",
                )
                .expect("bootstrap tools step"),
            )
            .expect("bootstrap tools mapping")
            .insert(
                yaml_key("run"),
                YamlValue::String("cargo install cargo-audit".to_owned()),
            );
        }
        "windows-arm64-deny-missing" => {
            let steps = job_steps_mut(workflow, "supply-chain").expect("supply-chain steps");
            let before = steps.len();
            steps.retain(|step| {
                yaml_string(yaml_get(step, "name"))
                    != Some("Check Windows ARM64 desktop dependency policy")
            });
            assert_eq!(
                before - steps.len(),
                1,
                "remove exactly one ARM64 deny step"
            );
        }
        "supply-checkout-action-substitution" => {
            yaml_mapping_mut(
                step_by_name_mut(workflow, "supply-chain", "Checkout")
                    .expect("supply-chain checkout"),
            )
            .expect("supply-chain checkout mapping")
            .insert(
                yaml_key("uses"),
                YamlValue::String(
                    "example/checkout@0000000000000000000000000000000000000000".to_owned(),
                ),
            );
        }
        "job-checks-write" => {
            let mut permissions = YamlMapping::new();
            permissions.insert(yaml_key("checks"), YamlValue::String("write".to_owned()));
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "jobs").expect("workflow jobs"),
                    "supply-chain",
                )
                .expect("supply-chain job"),
            )
            .expect("supply-chain mapping")
            .insert(yaml_key("permissions"), YamlValue::Mapping(permissions));
        }
        "job-write-all" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "jobs").expect("workflow jobs"),
                    "supply-chain",
                )
                .expect("supply-chain job"),
            )
            .expect("supply-chain mapping")
            .insert(
                yaml_key("permissions"),
                YamlValue::String("write-all".to_owned()),
            );
        }
        "supply-job-disabled" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "jobs").expect("workflow jobs"),
                    "supply-chain",
                )
                .expect("supply-chain job"),
            )
            .expect("supply-chain mapping")
            .insert(
                yaml_key("if"),
                YamlValue::String("github.event_name == 'schedule'".to_owned()),
            );
        }
        "supply-job-env-shadow" => {
            let mut env = YamlMapping::new();
            env.insert(
                yaml_key("CARGO_AUDIT_BIN"),
                YamlValue::String("/tmp/fake-audit".to_owned()),
            );
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "jobs").expect("workflow jobs"),
                    "supply-chain",
                )
                .expect("supply-chain job"),
            )
            .expect("supply-chain mapping")
            .insert(yaml_key("env"), YamlValue::Mapping(env));
        }
        "supply-unknown-shadow-step" => {
            let mut shadow = YamlMapping::new();
            shadow.insert(
                yaml_key("name"),
                YamlValue::String("Shadow verified audit binary".to_owned()),
            );
            shadow.insert(
                yaml_key("run"),
                YamlValue::String(
                    "echo 'CARGO_AUDIT_BIN=/tmp/fake-audit' >> \"$GITHUB_ENV\"".to_owned(),
                ),
            );
            job_steps_mut(workflow, "supply-chain")
                .expect("supply-chain steps")
                .insert(2, YamlValue::Mapping(shadow));
        }
        "bootstrap-wrapper-env" => {
            let bootstrap = step_by_name_mut(
                workflow,
                "supply-chain",
                "Bootstrap verified Rust security tools",
            )
            .expect("bootstrap tools step");
            yaml_mapping_mut(yaml_get_mut(bootstrap, "env").expect("bootstrap environment"))
                .expect("bootstrap environment mapping")
                .insert(
                    yaml_key("RUSTC_WRAPPER"),
                    YamlValue::String("/tmp/fake-wrapper".to_owned()),
                );
        }
        "bootstrap-inherited-shell" => {
            yaml_mapping_mut(
                step_by_name_mut(
                    workflow,
                    "supply-chain",
                    "Bootstrap verified Rust security tools",
                )
                .expect("bootstrap tools step"),
            )
            .expect("bootstrap tools mapping")
            .insert(yaml_key("shell"), YamlValue::String("bash".to_owned()));
        }
        "bootstrap-shadow-path-change" => {
            let bootstrap = step_by_name_mut(
                workflow,
                "supply-chain",
                "Bootstrap verified Rust security tools",
            )
            .expect("bootstrap tools step");
            yaml_mapping_mut(yaml_get_mut(bootstrap, "env").expect("bootstrap environment"))
                .expect("bootstrap environment mapping")
                .insert(
                    yaml_key("PATH"),
                    YamlValue::String("/tmp/shadow".to_owned()),
                );
        }
        "policy-step-runner-env" => {
            let mut env = YamlMapping::new();
            for key in [
                "CARGO",
                "PATH",
                "RUSTC_WRAPPER",
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
                "Cargo_Target_X86_64_Pc_Windows_Msvc_Runner",
            ] {
                env.insert(yaml_key(key), YamlValue::String("/tmp/poison".to_owned()));
            }
            yaml_mapping_mut(
                step_by_name_mut(workflow, "supply-chain", "Check root dependency policy")
                    .expect("root dependency policy step"),
            )
            .expect("root dependency policy mapping")
            .insert(yaml_key("env"), YamlValue::Mapping(env));
        }
        "negative-desktop-path" => {
            yaml_sequence_mut(yaml_get_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "on").expect("workflow triggers"),
                    "pull_request",
                )
                .expect("pull request trigger"),
                "paths",
            ))
            .expect("pull request paths")
            .push(YamlValue::String("!desktop/**".to_owned()));
        }
        "rust-branches-ignore" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "on").expect("Rust workflow triggers"),
                    "pull_request",
                )
                .expect("Rust pull_request trigger"),
            )
            .expect("Rust pull_request mapping")
            .insert(
                yaml_key("branches-ignore"),
                YamlValue::Sequence(vec![YamlValue::String("main".to_owned())]),
            );
        }
        "rust-types-filter" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "on").expect("Rust workflow triggers"),
                    "pull_request",
                )
                .expect("Rust pull_request trigger"),
            )
            .expect("Rust pull_request mapping")
            .insert(
                yaml_key("types"),
                YamlValue::Sequence(vec![YamlValue::String("opened".to_owned())]),
            );
        }
        "macos-branches-ignore" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(macos_workflow, "on").expect("macOS workflow triggers"),
                    "pull_request",
                )
                .expect("macOS pull_request trigger"),
            )
            .expect("macOS pull_request mapping")
            .insert(
                yaml_key("branches-ignore"),
                YamlValue::Sequence(vec![YamlValue::String("main".to_owned())]),
            );
        }
        "macos-types-filter" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(macos_workflow, "on").expect("macOS workflow triggers"),
                    "pull_request",
                )
                .expect("macOS pull_request trigger"),
            )
            .expect("macOS pull_request mapping")
            .insert(
                yaml_key("types"),
                YamlValue::Sequence(vec![YamlValue::String("opened".to_owned())]),
            );
        }
        "native-matrix-runner-collapse" => {
            let jobs = yaml_get_mut(macos_workflow, "jobs").expect("macOS jobs");
            let native = yaml_get_mut(jobs, "native").expect("native macOS job");
            let strategy = yaml_get_mut(native, "strategy").expect("native strategy");
            let matrix = yaml_get_mut(strategy, "matrix").expect("native matrix");
            let include = yaml_sequence_mut(yaml_get_mut(matrix, "include"))
                .expect("native include sequence");
            yaml_mapping_mut(
                include
                    .get_mut(0)
                    .expect("native matrix must declare an arm64 row at index 0"),
            )
            .expect("arm64 matrix row")
            .insert(
                yaml_key("runner"),
                YamlValue::String("macos-15-intel".to_owned()),
            );
        }
        "native-arch-assertion-removed" => {
            yaml_mapping_mut(
                step_by_name_mut(
                    macos_workflow,
                    "native",
                    "Test both Cargo workspaces natively",
                )
                .expect("native workspace test"),
            )
            .expect("native workspace test mapping")
            .insert(
                yaml_key("run"),
                YamlValue::String("cargo test --workspace --all-targets --locked\n".to_owned()),
            );
        }
        "source-policy-disabled" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(macos_workflow, "jobs").expect("macOS jobs"),
                    "source-policy",
                )
                .expect("source-policy job"),
            )
            .expect("source-policy mapping")
            .insert(
                yaml_key("if"),
                YamlValue::String("github.event_name == 'schedule'".to_owned()),
            );
        }
        "native-format-replaced" => {
            yaml_mapping_mut(
                step_by_name_mut(macos_workflow, "native", "Format both Cargo workspaces")
                    .expect("native format step"),
            )
            .expect("native format mapping")
            .insert(yaml_key("run"), YamlValue::String("true".to_owned()));
        }
        "native-arch-shell-added" => {
            yaml_mapping_mut(
                step_by_name_mut(
                    macos_workflow,
                    "native",
                    "Test both Cargo workspaces natively",
                )
                .expect("native workspace test"),
            )
            .expect("native workspace test mapping")
            .insert(yaml_key("shell"), YamlValue::String("sh".to_owned()));
        }
        "native-workflow-env-shadow" => {
            yaml_mapping_mut(yaml_get_mut(macos_workflow, "env").expect("macOS workflow env"))
                .expect("macOS workflow env mapping")
                .insert(
                    yaml_key("PATH"),
                    YamlValue::String("/tmp/shadow".to_owned()),
                );
        }
        "native-matrix-extra-key" => {
            let jobs = yaml_get_mut(macos_workflow, "jobs").expect("macOS jobs");
            let native = yaml_get_mut(jobs, "native").expect("native macOS job");
            let strategy = yaml_get_mut(native, "strategy").expect("native strategy");
            let matrix = yaml_get_mut(strategy, "matrix").expect("native matrix");
            let include = yaml_sequence_mut(yaml_get_mut(matrix, "include"))
                .expect("native include sequence");
            yaml_mapping_mut(
                include
                    .get_mut(0)
                    .expect("native matrix must declare an arm64 row at index 0"),
            )
            .expect("ARM matrix row")
            .insert(yaml_key("image"), YamlValue::String("shadow".to_owned()));
        }
        "deny-no-locked" => {
            let step = step_by_name_mut(
                workflow,
                "supply-chain",
                "Check Windows x64 desktop dependency policy",
            )
            .expect("Windows x64 deny step");
            let run = yaml_string(yaml_get(step, "run"))
                .expect("Windows x64 deny command")
                .replace(" --locked", "");
            yaml_mapping_mut(step)
                .expect("Windows x64 deny mapping")
                .insert(yaml_key("run"), YamlValue::String(run));
        }
        "deny-advisory-ignore" => {
            toml_table_mut(deny, "advisories")
                .expect("deny advisories")
                .insert(
                    "ignore".to_owned(),
                    TomlValue::Array(vec![TomlValue::String("RUSTSEC-2026-0194".to_owned())]),
                );
        }
        "audit-config-ignore" => {
            toml_table_mut(audit, "advisories")
                .expect("audit advisories")
                .insert(
                    "ignore".to_owned(),
                    TomlValue::Array(vec![TomlValue::String("RUSTSEC-2026-0194".to_owned())]),
                );
        }
        "deny-git-source" => {
            toml_table_mut(deny, "sources")
                .expect("deny sources")
                .insert(
                    "allow-git".to_owned(),
                    TomlValue::Array(vec![TomlValue::String(
                        "https://github.com/example/unpinned".to_owned(),
                    )]),
                );
        }
        "deny-license-widening" => {
            deny.get_mut("licenses")
                .and_then(|licenses| licenses.get_mut("allow"))
                .and_then(TomlValue::as_array_mut)
                .expect("deny license allow-list")
                .push(TomlValue::String("GPL-3.0-only".to_owned()));
        }
        "deny-graph-exclude" => {
            toml_table_mut(deny, "graph").expect("deny graph").insert(
                "exclude".to_owned(),
                TomlValue::Array(vec![TomlValue::String("quick-xml".to_owned())]),
            );
        }
        "root-deny-license-widening" => {
            root_deny
                .get_mut("licenses")
                .and_then(|licenses| licenses.get_mut("allow"))
                .and_then(TomlValue::as_array_mut)
                .expect("root deny license allow-list")
                .push(TomlValue::String("GPL-3.0-only".to_owned()));
        }
        "root-deny-inline-exception" => {
            let mut exception = toml::map::Map::new();
            exception.insert(
                "name".to_owned(),
                TomlValue::String("prohibited".to_owned()),
            );
            exception.insert(
                "allow".to_owned(),
                TomlValue::Array(vec![TomlValue::String("GPL-3.0-only".to_owned())]),
            );
            toml_table_mut(root_deny, "licenses")
                .expect("root deny licenses")
                .insert(
                    "exceptions".to_owned(),
                    TomlValue::Array(vec![TomlValue::Table(exception)]),
                );
        }
        "root-deny-source-widening" => {
            toml_table_mut(root_deny, "sources")
                .expect("root deny sources")
                .insert(
                    "allow-git".to_owned(),
                    TomlValue::Array(vec![TomlValue::String(
                        "https://github.com/example/unpinned".to_owned(),
                    )]),
                );
        }
        "root-deny-ban-skip" => {
            let mut skipped = toml::map::Map::new();
            skipped.insert(
                "name".to_owned(),
                TomlValue::String("prohibited".to_owned()),
            );
            skipped.insert("version".to_owned(), TomlValue::String("1.0.0".to_owned()));
            root_deny
                .get_mut("bans")
                .and_then(|bans| bans.get_mut("skip"))
                .and_then(TomlValue::as_array_mut)
                .expect("root deny ban skips")
                .push(TomlValue::Table(skipped));
        }
        "root-deny-string-skip" => {
            root_deny
                .get_mut("bans")
                .and_then(|bans| bans.get_mut("skip"))
                .and_then(TomlValue::as_array_mut)
                .expect("root deny ban skips")
                .push(TomlValue::String("prohibited".to_owned()));
        }
        "root-deny-crate-skip" => {
            root_deny
                .get_mut("bans")
                .and_then(|bans| bans.get_mut("skip"))
                .and_then(TomlValue::as_array_mut)
                .expect("root deny ban skips")
                .push(TomlValue::Table(toml::map::Map::from_iter([(
                    "crate".to_owned(),
                    TomlValue::String("prohibited".to_owned()),
                )])));
        }
        "root-deny-versionless-name-skip" => {
            root_deny
                .get_mut("bans")
                .and_then(|bans| bans.get_mut("skip"))
                .and_then(TomlValue::as_array_mut)
                .expect("root deny ban skips")
                .push(TomlValue::Table(toml::map::Map::from_iter([(
                    "name".to_owned(),
                    TomlValue::String("prohibited".to_owned()),
                )])));
        }
        "slint-wildcard-version" => {
            app_manifest
                .get_mut("target")
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| {
                    target.get_mut(r#"cfg(any(target_os = "windows", target_os = "macos"))"#)
                })
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| target.get_mut("dependencies"))
                .and_then(TomlValue::as_table_mut)
                .and_then(|dependencies| dependencies.get_mut("slint"))
                .and_then(TomlValue::as_table_mut)
                .expect("desktop Slint dependency")
                .insert("version".to_owned(), TomlValue::String("*".to_owned()));
        }
        "slint-build-caret-version" => {
            app_manifest
                .get_mut("target")
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| {
                    target.get_mut(r#"cfg(any(target_os = "windows", target_os = "macos"))"#)
                })
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| target.get_mut("build-dependencies"))
                .and_then(TomlValue::as_table_mut)
                .and_then(|dependencies| dependencies.get_mut("slint-build"))
                .and_then(TomlValue::as_table_mut)
                .expect("desktop slint-build dependency")
                .insert("version".to_owned(), TomlValue::String("1.17.1".to_owned()));
        }
        "duplicate-target-slint-widening" => {
            let mut slint = toml::map::Map::new();
            slint.insert(
                "version".to_owned(),
                TomlValue::String("=1.17.1".to_owned()),
            );
            slint.insert("default-features".to_owned(), TomlValue::Boolean(true));
            slint.insert(
                "features".to_owned(),
                TomlValue::Array(vec![TomlValue::String("backend-winit".to_owned())]),
            );
            slint.insert(
                "registry".to_owned(),
                TomlValue::String("alternate".to_owned()),
            );
            let dependencies =
                toml::map::Map::from_iter([("slint".to_owned(), TomlValue::Table(slint))]);
            let duplicate_target = toml::map::Map::from_iter([(
                "dependencies".to_owned(),
                TomlValue::Table(dependencies),
            )]);
            app_manifest
                .get_mut("target")
                .and_then(TomlValue::as_table_mut)
                .expect("desktop target tables")
                .insert(
                    r#"cfg(target_os = "windows")"#.to_owned(),
                    TomlValue::Table(duplicate_target),
                );
        }
        "renamed-slint-package" => {
            app_manifest
                .get_mut("target")
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| {
                    target.get_mut(r#"cfg(any(target_os = "windows", target_os = "macos"))"#)
                })
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| target.get_mut("dependencies"))
                .and_then(TomlValue::as_table_mut)
                .expect("desktop target dependencies")
                .insert(
                    "claw-application".to_owned(),
                    TomlValue::Table(toml::map::Map::from_iter([
                        ("package".to_owned(), TomlValue::String("slint".to_owned())),
                        (
                            "version".to_owned(),
                            TomlValue::String("=1.17.1".to_owned()),
                        ),
                        ("default-features".to_owned(), TomlValue::Boolean(true)),
                    ])),
                );
        }
        "workspace-renamed-slint-package" => {
            desktop_manifest
                .get_mut("workspace")
                .and_then(TomlValue::as_table_mut)
                .and_then(|workspace| workspace.get_mut("dependencies"))
                .and_then(TomlValue::as_table_mut)
                .expect("desktop workspace dependencies")
                .insert(
                    "claw-application".to_owned(),
                    TomlValue::Table(toml::map::Map::from_iter([
                        ("package".to_owned(), TomlValue::String("slint".to_owned())),
                        (
                            "version".to_owned(),
                            TomlValue::String("=1.17.1".to_owned()),
                        ),
                        ("default-features".to_owned(), TomlValue::Boolean(true)),
                    ])),
                );
        }
        "app-claw-application-registry" => {
            app_manifest
                .get_mut("target")
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| {
                    target.get_mut(r#"cfg(any(target_os = "windows", target_os = "macos"))"#)
                })
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| target.get_mut("dependencies"))
                .and_then(TomlValue::as_table_mut)
                .expect("desktop app dependencies")
                .insert(
                    "claw-application".to_owned(),
                    TomlValue::Table(toml::map::Map::from_iter([(
                        "version".to_owned(),
                        TomlValue::String("0.1.0".to_owned()),
                    )])),
                );
        }
        "app-claw-platform-path" => {
            app_manifest
                .get_mut("target")
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| {
                    target.get_mut(r#"cfg(any(target_os = "windows", target_os = "macos"))"#)
                })
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| target.get_mut("dependencies"))
                .and_then(TomlValue::as_table_mut)
                .expect("desktop app dependencies")
                .insert(
                    "claw-platform".to_owned(),
                    TomlValue::Table(toml::map::Map::from_iter([(
                        "path".to_owned(),
                        TomlValue::String("../../../../untrusted".to_owned()),
                    )])),
                );
        }
        "desktop-replace-slint-build" => {
            desktop_manifest
                .as_table_mut()
                .expect("desktop manifest table")
                .insert(
                    "replace".to_owned(),
                    TomlValue::Table(toml::map::Map::from_iter([(
                        "slint-build:1.17.1".to_owned(),
                        TomlValue::Table(toml::map::Map::from_iter([(
                            "path".to_owned(),
                            TomlValue::String("vendor/slint-build".to_owned()),
                        )])),
                    )])),
                );
        }
        other => panic!("unknown policy mutation: {other}"),
    }
}
