//! Native implementations of ports defined by the GTA Claw application core.

use claw_application::SystemProbe;
use claw_protocol::RuntimeDescriptor;

/// Reads platform identity from the Rust target.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeSystemProbe;

impl SystemProbe for NativeSystemProbe {
    fn runtime(&self) -> RuntimeDescriptor {
        RuntimeDescriptor::new(std::env::consts::OS, std::env::consts::ARCH)
    }
}

#[cfg(test)]
mod tests {
    use claw_application::SystemProbe;

    use super::NativeSystemProbe;

    #[test]
    fn native_probe_reports_the_compilation_target() {
        let runtime = NativeSystemProbe.runtime();

        assert_eq!(runtime.os(), std::env::consts::OS);
        assert_eq!(runtime.architecture(), std::env::consts::ARCH);
    }
}
