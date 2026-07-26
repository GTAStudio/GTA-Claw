//! Endpoint intake, Gateway connection lifecycle, and action gating.
//!
//! # Every control here is gated on what the server actually confirmed
//!
//! [`IosSessionModel::authorize`] consults exactly the record
//! [`IosViewSnapshot::permits`] renders, so a control this shell enables is one
//! the acting code will also accept, and a control it disables is one the
//! acting code would refuse. No permission displayed here is inferred from what
//! the client *requested*: a requested scope is not a held scope.
//!
//! # What this shell does not do
//!
//! It sends no Gateway requests once authenticated. Pressing an enabled action
//! reports the authorization decision and nothing else, because the command
//! surface those actions would drive is not part of this package.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use claw_gateway_client::{ConnectionState, GatewayClient};
use claw_security::authorization::Scope;
use claw_security::identity::DeviceIdentity;
use gta_claw_ios::{
    GatewayEndpoint, GatewayMdnsBackend, HostAppDeclarations, IosAction, IosClientIdentity,
    IosCredential, IosGatewayProfile, IosSessionModel, IosViewSnapshot, UnobservedDeviceProbe,
};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::generated_ui::{ActionRow, AppWindow};

/// Scopes this client asks for. The server decides what it actually grants.
const REQUESTED_SCOPES: [Scope; 3] = [
    Scope::OperatorRead,
    Scope::OperatorWrite,
    Scope::OperatorApprovals,
];

/// Builds the action rows from a snapshot, or the empty state when there is none.
fn action_model(snapshot: Option<&IosViewSnapshot>) -> ModelRc<ActionRow> {
    let rows = IosAction::ALL
        .iter()
        .map(|action| {
            let permitted = snapshot.is_some_and(|snapshot| snapshot.permits(*action));
            ActionRow {
                label: SharedString::from(action.label()),
                permitted,
                detail: SharedString::from(if permitted {
                    "confirmed by the server"
                } else {
                    "not confirmed by the server"
                }),
            }
        })
        .collect::<Vec<_>>();
    ModelRc::new(VecModel::from(rows))
}

/// Reports the real local-discovery precondition rather than an empty result.
fn describe_discovery() -> String {
    // Nothing here reads `Info.plist`; an unconfirmed declaration is treated
    // exactly as strictly as a missing one, so this reports the honest default.
    match HostAppDeclarations::new().discovery_precondition::<GatewayMdnsBackend>() {
        Ok(_) => "Local network discovery is permitted by the declared bundle.".to_owned(),
        Err(unavailable) => unavailable.to_string(),
    }
}

/// Generates a device identity from operating-system entropy.
fn device_identity() -> Arc<DeviceIdentity> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).expect("the operating system must provide entropy");
    let mut rng = ChaCha20Rng::from_seed(seed);
    Arc::new(DeviceIdentity::generate(&mut rng))
}

/// Pushes a snapshot into the window.
fn apply(window: &AppWindow, snapshot: &IosViewSnapshot) {
    window.set_status_title(SharedString::from(snapshot.title()));
    window.set_status_detail(SharedString::from(snapshot.detail()));
    window.set_busy(snapshot.busy());
    window.set_actions(action_model(Some(snapshot)));
    let authorization = snapshot.authorization().map_or_else(
        || "No connection has been authenticated, so nothing is authorized.".to_owned(),
        gta_claw_ios::ObservedAuthorization::summary,
    );
    window.set_authorization_text(SharedString::from(authorization));
}

/// Runs the shell, returning only when the window closes.
///
/// # Errors
///
/// Returns a [`slint::PlatformError`] when the platform cannot create or run a
/// window, which on iOS includes the case where no UIKit scene is available.
pub(crate) fn run() -> Result<(), slint::PlatformError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a Tokio runtime must start");
    let window = AppWindow::new()?;

    window.set_status_title(SharedString::from("Not connected"));
    window.set_status_detail(SharedString::from("Enter a Gateway endpoint to begin."));
    window.set_authorization_text(SharedString::from(
        "No connection has been authenticated, so nothing is authorized.",
    ));
    window.set_discovery_text(SharedString::from(describe_discovery()));
    window.set_actions(action_model(None));

    let session_slot: Rc<RefCell<Option<IosSessionModel>>> = Rc::new(RefCell::new(None));

    let handle = runtime.handle().clone();
    let connect_slot = Rc::clone(&session_slot);
    let connect_weak = window.as_weak();
    window.on_connect_pressed(move || {
        let Some(window) = connect_weak.upgrade() else {
            return;
        };
        let endpoint = match GatewayEndpoint::parse(window.get_endpoint_text().as_str()) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                window.set_status_title(SharedString::from("Endpoint rejected"));
                window.set_status_detail(SharedString::from(error.to_string()));
                return;
            }
        };
        let credential = match IosCredential::token(window.get_token_text().as_str()) {
            Ok(credential) => credential,
            Err(error) => {
                window.set_status_title(SharedString::from("Credential rejected"));
                window.set_status_detail(SharedString::from(error.to_string()));
                return;
            }
        };
        let identity = match IosClientIdentity::observe(&UnobservedDeviceProbe) {
            Ok(identity) => identity,
            Err(error) => {
                window.set_status_title(SharedString::from("Identity unavailable"));
                window.set_status_detail(SharedString::from(error.to_string()));
                return;
            }
        };

        let profile = IosGatewayProfile::new(endpoint, credential, identity, device_identity())
            .requesting(REQUESTED_SCOPES);
        let session = profile.session_model();
        let attempt = match session.begin_attempt() {
            Ok(attempt) => attempt,
            Err(rejected) => {
                window.set_status_detail(SharedString::from(rejected.to_string()));
                return;
            }
        };
        *connect_slot.borrow_mut() = Some(session.clone());
        apply(&window, &session.snapshot());

        let config = profile.into_client_config();
        let task_weak = window.as_weak();
        handle.spawn(async move {
            // The guard moves into the future, so abandoning this task — which
            // is the ordinary case on iOS, where the system suspends the app on
            // backgrounding — releases the in-flight marker by dropping rather
            // than by reaching a completion path.
            let _attempt = attempt;
            let (client, _events) = match GatewayClient::start(config) {
                Ok(started) => started,
                Err(error) => {
                    let text = error.to_string();
                    let _ = task_weak.upgrade_in_event_loop(move |window| {
                        window.set_status_title(SharedString::from("Connection failed"));
                        window.set_status_detail(SharedString::from(text));
                        window.set_busy(false);
                    });
                    return;
                }
            };
            let mut states = client.subscribe_state();
            loop {
                let state: ConnectionState = states.borrow_and_update().clone();
                session.observe(state);
                let snapshot = session.snapshot();
                let _ = task_weak.upgrade_in_event_loop(move |window| {
                    apply(&window, &snapshot);
                });
                if states.changed().await.is_err() {
                    break;
                }
            }
        });
    });

    let action_slot = Rc::clone(&session_slot);
    let action_weak = window.as_weak();
    window.on_action_pressed(move |index| {
        let Some(window) = action_weak.upgrade() else {
            return;
        };
        let Ok(index) = usize::try_from(index) else {
            return;
        };
        let Some(action) = IosAction::ALL.get(index).copied() else {
            return;
        };
        let borrowed = action_slot.borrow();
        let Some(session) = borrowed.as_ref() else {
            window.set_action_result(SharedString::from(
                "No session exists, so no action is authorized.",
            ));
            return;
        };
        // The same record the row was rendered from, consulted again at the
        // moment of acting rather than trusted from the render.
        let text = match session.authorize(action) {
            Ok(authorized) => format!("Authorized: {}", authorized.action().label()),
            Err(denied) => denied.to_string(),
        };
        window.set_action_result(SharedString::from(text));
    });

    window.run()
}
