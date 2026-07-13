//! Headless GTA Claw use cases and the ports required to execute them.

use claw_domain::{DomainError, Message, MessageRole};
use claw_protocol::{ClientCommand, PROTOCOL_VERSION, RuntimeDescriptor, ServerEvent};

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
    pub fn handle(&self, command: ClientCommand) -> Result<ServerEvent, DomainError> {
        match command {
            ClientCommand::Health => Ok(self.health()),
            ClientCommand::Submit {
                session_id,
                content,
            } => {
                let message = Message::new(session_id, MessageRole::User, content)?;
                Ok(ServerEvent::MessageAccepted { message })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use claw_protocol::{ClientCommand, RuntimeDescriptor, ServerEvent};

    use super::{Application, SystemProbe};

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
}
