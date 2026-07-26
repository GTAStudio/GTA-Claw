//! Headless GTA Claw use cases and the ports required to execute them.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_protocol::{ClientCommand, PROTOCOL_VERSION, RuntimeDescriptor, ServerEvent};

/// Domain model shared by the agent runtime's ports.
///
/// Gated behind the `runtime-ports` feature so that front-ends linking this
/// crate only for [`Application`] and [`SystemProbe`] do not inherit
/// `claw-domain`. `test` is in the gate as well so `cargo test -p
/// claw-application` still compiles and runs the suite rather than reporting
/// success over skipped tests.
#[cfg(any(feature = "runtime-ports", test))]
pub mod model;
/// Port traits the agent runtime requires of its adapters.
///
/// Gated behind the `runtime-ports` feature; see [`model`].
#[cfg(any(feature = "runtime-ports", test))]
pub mod ports;

#[cfg(any(feature = "runtime-ports", test))]
pub use ports::approval::ApprovalPort;
#[cfg(any(feature = "runtime-ports", test))]
pub use ports::clock::ClockPort;
#[cfg(any(feature = "runtime-ports", test))]
pub use ports::context::ContextEnginePort;
#[cfg(any(feature = "runtime-ports", test))]
pub use ports::goal::GoalStorePort;
#[cfg(any(feature = "runtime-ports", test))]
pub use ports::provider::{ProviderPort, ProviderStream};
#[cfg(any(feature = "runtime-ports", test))]
pub use ports::state::StatePort;
#[cfg(any(feature = "runtime-ports", test))]
pub use ports::tool::ToolPort;
#[cfg(any(feature = "runtime-ports", test))]
pub use ports::{PortError, PortFuture};

/// Supplies native runtime identity without coupling the application to an OS.
pub trait SystemProbe {
    /// Returns the native runtime identity.
    fn runtime(&self) -> RuntimeDescriptor;
}

/// The entry point for headless GTA Claw use cases.
#[derive(Debug)]
pub struct Application<P> {
    system_probe: P,
}

impl<P> Application<P>
where
    P: SystemProbe,
{
    /// Creates an application using the supplied platform port.
    #[must_use]
    pub const fn new(system_probe: P) -> Self {
        Self { system_probe }
    }

    /// Returns the startup event for process adapters.
    #[must_use]
    pub const fn ready(&self) -> ServerEvent {
        ServerEvent::Ready {
            protocol_version: PROTOCOL_VERSION,
        }
    }

    /// Returns current runtime health without a fallible domain transition.
    #[must_use]
    pub fn health(&self) -> ServerEvent {
        ServerEvent::Healthy {
            runtime: self.system_probe.runtime(),
        }
    }

    /// Executes one typed command.
    pub fn handle(&self, command: ClientCommand) -> Result<ServerEvent, ApplicationError> {
        match command {
            ClientCommand::Health => Ok(self.health()),
            ClientCommand::Submit { .. } => Err(ApplicationError::Unsupported(
                "message transport is not configured",
            )),
        }
    }
}

/// A use case that cannot be completed by the configured application ports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationError {
    /// The required adapter has not been implemented or configured.
    Unsupported(&'static str),
}

impl Display for ApplicationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(reason) => write!(formatter, "unsupported operation: {reason}"),
        }
    }
}

impl Error for ApplicationError {}

#[cfg(test)]
mod tests {
    use claw_domain::SessionId;
    use claw_protocol::{ClientCommand, RuntimeDescriptor, ServerEvent};

    use super::{Application, ApplicationError, SystemProbe};

    #[derive(Debug)]
    struct TestSystemProbe;

    impl SystemProbe for TestSystemProbe {
        fn runtime(&self) -> RuntimeDescriptor {
            RuntimeDescriptor::new("test-os", "test-arch")
        }
    }

    #[test]
    fn health_command_crosses_the_platform_port() {
        let application = Application::new(TestSystemProbe);
        let event = application
            .handle(ClientCommand::Health)
            .expect("health command succeeds");

        assert_eq!(
            event,
            ServerEvent::Healthy {
                runtime: RuntimeDescriptor::new("test-os", "test-arch")
            }
        );
    }

    #[test]
    fn startup_announces_the_protocol_version() {
        let application = Application::new(TestSystemProbe);

        assert_eq!(
            application.ready(),
            ServerEvent::Ready {
                protocol_version: 1
            }
        );
    }

    #[test]
    fn submit_is_rejected_without_a_message_transport() {
        let application = Application::new(TestSystemProbe);
        let command = ClientCommand::Submit {
            session_id: SessionId::new("session-7").expect("valid session id"),
            content: "hello".to_owned(),
        };

        let error = application
            .handle(command)
            .expect_err("submit must fail without a transport");

        assert_eq!(
            error,
            ApplicationError::Unsupported("message transport is not configured")
        );
    }
}
