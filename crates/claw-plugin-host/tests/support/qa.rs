//! Test tooling for the three source-only QA plugin contracts.
//!
//! Upstream keeps `qa-channel`, `qa-lab` and `qa-matrix` in its source tree for
//! QA and never publishes them, so there is nothing to install and nothing to
//! port. The only honest place they can be represented is here: this module
//! turns each of those contracts into a fixture the plugin host really
//! processes, so the frozen rows are exercised rather than merely listed.
//!
//! Nothing below names a QA plugin. [`qa_fixtures`] enumerates
//! [`DeliveryClass::SourceOnlyQa`] in the frozen registry, so a QA row added,
//! removed or reclassified upstream changes what this tooling produces.

use std::path::{Path, PathBuf};

use claw_plugin_api::compat::{self, CompatibilityDecision, InstallDecision, PluginCompatibility};
use claw_plugin_api::limits::ResourceLimits;
use claw_plugin_api::manifest::{ComponentRef, MANIFEST_VERSION, PluginManifest};
use claw_plugin_api::registry::DeliveryClass;
use claw_plugin_api::trust::{IdentityBinding, TrustPolicy, component_sha256};

use super::{PROBE_VERSION, install, probe_component};

/// One source-only QA contract, materialised as an installable fixture.
///
/// The manifest carries the contract's real id and delivery class, so the
/// host's trust policy and its registry cross-check both see the genuine
/// plugin identity. The component bytes are the shared probe fixture: this
/// repository has no QA plugin component and this tooling does not pretend
/// otherwise.
pub struct QaFixture {
    id: &'static str,
    package_name: &'static str,
    source_path: &'static str,
    decision: PluginCompatibility,
    component: Vec<u8>,
    manifest: PluginManifest,
}

impl QaFixture {
    /// The upstream plugin id.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    /// The upstream npm package name, recorded as provenance only.
    #[must_use]
    pub const fn package_name(&self) -> &'static str {
        self.package_name
    }

    /// The path of the plugin inside the upstream source tree.
    #[must_use]
    pub const fn source_path(&self) -> &'static str {
        self.source_path
    }

    /// The install and compatibility decisions this contract carries.
    #[must_use]
    pub const fn decision(&self) -> PluginCompatibility {
        self.decision
    }

    /// The manifest this fixture installs.
    #[must_use]
    pub const fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    /// The component bytes this fixture installs.
    #[must_use]
    pub fn component(&self) -> &[u8] {
        &self.component
    }

    /// The directory name this fixture installs into, below a trust root.
    #[must_use]
    pub fn directory_name(&self) -> String {
        format!("qa-{}", self.id)
    }

    /// Writes the manifest and the component into a fresh directory below
    /// `root` and returns it.
    pub fn install(&self, root: &Path) -> PathBuf {
        install(
            root,
            &self.directory_name(),
            &self.component,
            &self.manifest,
        )
    }
}

/// Every source-only QA contract in the frozen registry, as a fixture.
///
/// Ordered by plugin id, because the registry is.
#[must_use]
pub fn qa_fixtures() -> Vec<QaFixture> {
    compat::by_delivery_class(DeliveryClass::SourceOnlyQa)
        .map(fixture_for)
        .collect()
}

/// The ids this tooling represents, sorted.
#[must_use]
pub fn represented_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = qa_fixtures().iter().map(QaFixture::id).collect();
    ids.sort_unstable();
    ids
}

/// A trust policy that accepts unsigned source-only QA plugins below `root`.
///
/// Every QA contract is bound to the directory [`QaFixture::install`] would
/// place it in, because a reserved inventory id always requires an identity
/// binding — the frozen registry is what makes the id reserved.
///
/// This exists only so a test can prove that a refusal was caused by the
/// delivery class and not by something incidental. No production policy should
/// ever enable a class upstream never publishes.
#[must_use]
pub fn unsigned_qa_policy(root: &Path) -> TrustPolicy {
    let mut policy = TrustPolicy::deny_all()
        .with_root(root.to_path_buf())
        .require_signature(false)
        .require_identity_binding(false)
        .allow_delivery_class(DeliveryClass::SourceOnlyQa);
    for fixture in qa_fixtures() {
        policy = policy.with_identity_binding(IdentityBinding::new(
            fixture.id(),
            DeliveryClass::SourceOnlyQa,
            root.join(fixture.directory_name()),
        ));
    }
    policy
}

fn fixture_for(decision: PluginCompatibility) -> QaFixture {
    let record = decision.descriptor().record();
    assert_eq!(
        decision.delivery_class(),
        DeliveryClass::SourceOnlyQa,
        "`{}` is not a source-only QA contract",
        record.id()
    );
    assert_eq!(
        decision.install(),
        InstallDecision::NeverPublishedSourceOnly,
        "`{}` would be installed from somewhere",
        record.id()
    );
    assert!(
        matches!(decision.compatibility(), CompatibilityDecision::Stub(_)),
        "`{}` claims a component this repository does not ship",
        record.id()
    );

    let component = probe_component();
    let manifest = PluginManifest {
        manifest_version: MANIFEST_VERSION,
        id: record.id().to_owned(),
        display_name: format!("Upstream QA plugin {}", record.id()),
        description: format!(
            "Source-only QA contract `{}` from `{}`, represented by GTA-Claw test tooling only.",
            record.package_name(),
            record.source_path()
        ),
        version: PROBE_VERSION.to_owned(),
        abi_version: "1.0.0".to_owned(),
        delivery_class: DeliveryClass::SourceOnlyQa,
        component: ComponentRef {
            path: "component.wasm".to_owned(),
            sha256: component_sha256(&component),
            size_bytes: component.len() as u64,
        },
        capabilities: Vec::new(),
        limits: ResourceLimits::default(),
        signature: None,
    };
    manifest
        .validate()
        .expect("a QA fixture manifest must be valid");

    QaFixture {
        id: record.id(),
        package_name: record.package_name(),
        source_path: record.source_path(),
        decision,
        component,
        manifest,
    }
}
