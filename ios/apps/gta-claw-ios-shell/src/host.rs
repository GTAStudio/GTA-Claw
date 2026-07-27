//! Honest host-facility boundaries for the current Slint iOS shell.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex, PoisonError};

use gta_claw_ios::{
    CredentialKey, DeclarationStatus, DiscoveryDiagnostic, DiscoveryEventSink, DiscoveryRequest,
    GatewayMdnsBackend, HostAppDeclarations, HostCredentialStore, HostDiscoveryProvider,
    HostDiscoverySession, PersistedCredentialKind,
};
use secrecy::SecretString;

/// Process-local credential storage behind the same port a Keychain adapter uses.
#[derive(Debug, Default)]
pub(crate) struct SessionCredentialStore {
    secrets: Mutex<BTreeMap<(String, PersistedCredentialKind), SecretString>>,
}

impl HostCredentialStore for SessionCredentialStore {
    type Error = Infallible;

    fn load_secret(
        &self,
        key: &CredentialKey,
        kind: PersistedCredentialKind,
    ) -> Result<Option<SecretString>, Self::Error> {
        let secrets = self.secrets.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(secrets
            .get(&(key.expose_to_host().to_owned(), kind))
            .cloned())
    }

    fn save_secret(
        &self,
        key: &CredentialKey,
        kind: PersistedCredentialKind,
        secret: &SecretString,
    ) -> Result<(), Self::Error> {
        self.secrets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((key.expose_to_host().to_owned(), kind), secret.clone());
        Ok(())
    }

    fn delete_secret(
        &self,
        key: &CredentialKey,
        kind: PersistedCredentialKind,
    ) -> Result<(), Self::Error> {
        self.secrets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(key.expose_to_host().to_owned(), kind));
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DiscoveryAdapterUnavailable;

impl Display for DiscoveryAdapterUnavailable {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("the Slint shell has no Apple DNS-SD adapter")
    }
}

impl Error for DiscoveryAdapterUnavailable {}

#[derive(Debug)]
struct InactiveDiscoverySession;

impl HostDiscoverySession for InactiveDiscoverySession {
    fn cancel(&self) {}
}

#[derive(Debug, Default)]
struct UnavailableDiscoveryProvider;

impl HostDiscoveryProvider<GatewayMdnsBackend> for UnavailableDiscoveryProvider {
    type Error = DiscoveryAdapterUnavailable;
    type Session = InactiveDiscoverySession;

    fn start(
        &self,
        _request: DiscoveryRequest<GatewayMdnsBackend>,
        _sink: Arc<dyn DiscoveryEventSink>,
    ) -> Result<Self::Session, Self::Error> {
        Err(DiscoveryAdapterUnavailable)
    }
}

/// Host ports and their redaction-safe presentation.
#[derive(Debug)]
pub(crate) struct HostBoundaries {
    credentials: SessionCredentialStore,
    _discovery: UnavailableDiscoveryProvider,
    discovery_diagnostic: DiscoveryDiagnostic,
}

impl HostBoundaries {
    pub(crate) fn new() -> Self {
        let declarations = HostAppDeclarations::new()
            .with_local_network_usage(DeclarationStatus::Declared)
            .with_bonjour_services(DeclarationStatus::Absent, []);
        let discovery_diagnostic = match declarations.discovery_precondition::<GatewayMdnsBackend>()
        {
            Ok(_) => unreachable!("the committed Info.plist declares no Bonjour services"),
            Err(unavailable) => unavailable.diagnostic(),
        };
        let discovery = UnavailableDiscoveryProvider;
        assert_discovery_boundary(&discovery);
        Self {
            credentials: SessionCredentialStore::default(),
            _discovery: discovery,
            discovery_diagnostic,
        }
    }

    pub(crate) const fn credentials(&self) -> &SessionCredentialStore {
        &self.credentials
    }

    pub(crate) const fn discovery_diagnostic(&self) -> &DiscoveryDiagnostic {
        &self.discovery_diagnostic
    }

    pub(crate) const fn credential_notice() -> &'static str {
        "Credential host port: process memory only; no Keychain adapter is attached."
    }
}

const fn assert_discovery_boundary<P: HostDiscoveryProvider<GatewayMdnsBackend>>(_provider: &P) {}

#[cfg(test)]
mod tests {
    use gta_claw_ios::{
        CredentialKey, DiscoveryRemediation, HostAppDeclaration, IosCredential,
        PersistedCredentialKind, delete_host_credential, load_host_credential,
        save_host_credential,
    };

    use super::HostBoundaries;

    #[test]
    fn session_credentials_cross_the_validated_host_port() {
        let host = HostBoundaries::new();
        let key = CredentialKey::parse("manual-gateway").expect("bounded account key");
        let credential = IosCredential::token("session-token").expect("valid token");

        save_host_credential(host.credentials(), &key, &credential)
            .expect("in-memory host save succeeds");
        let loaded = load_host_credential(host.credentials(), &key, PersistedCredentialKind::Token)
            .expect("in-memory host load succeeds")
            .expect("saved token exists");
        assert_eq!(loaded.kind(), credential.kind());
        delete_host_credential(host.credentials(), &key, PersistedCredentialKind::Token)
            .expect("in-memory host delete succeeds");
        assert!(
            load_host_credential(host.credentials(), &key, PersistedCredentialKind::Token)
                .expect("in-memory host load succeeds")
                .is_none()
        );
    }

    #[test]
    fn absent_bonjour_declaration_produces_typed_remediation() {
        let host = HostBoundaries::new();
        let diagnostic = host.discovery_diagnostic();

        assert_eq!(
            diagnostic.title(),
            "Required Info.plist declaration is missing"
        );
        assert!(matches!(
            diagnostic.remediation(),
            DiscoveryRemediation::AddInfoPlistDeclaration(HostAppDeclaration::BonjourServices)
        ));
        assert_eq!(
            diagnostic.remediation().action_label(),
            "Add NSBonjourServices to Info.plist"
        );
    }
}
