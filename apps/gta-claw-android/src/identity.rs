//! Session device identity, sourced from the platform CSPRNG.
//!
//! The Android client mirrors the headless CLI here rather than reaching for a
//! second randomness crate: `ring`'s `SystemRandom` is already linked for the
//! Gateway's TLS, so this adds nothing to the dependency graph. On Android it
//! reads `/dev/urandom` (via `getrandom(2)` where the kernel provides it), which
//! is what the platform documents as the correct source for key material.
//!
//! # No persistence
//!
//! The identity produced here lives only as long as the process. Nothing writes
//! it to storage and nothing reloads it, so **every launch is a new device from
//! the Gateway's point of view**. Persisting it properly would mean the Android
//! Keystore, which is reachable only through JNI, which needs `unsafe` — and
//! this workspace forbids `unsafe`. See the crate documentation.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_security::identity::DeviceIdentity;
use rand_core::{TryCryptoRng, TryRng};
use ring::rand::{SecureRandom, SystemRandom};

/// The platform could not supply cryptographic randomness.
///
/// Callers must surface this rather than substituting a weaker source: an
/// identity built from predictable bytes would authenticate successfully and be
/// forgeable, which is worse than failing to connect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RandomnessUnavailable;

impl Display for RandomnessUnavailable {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("the platform random number generator refused to produce bytes")
    }
}

impl Error for RandomnessUnavailable {}

/// Generates a device identity that lives only for this process.
///
/// # Errors
///
/// Returns [`RandomnessUnavailable`] if the platform CSPRNG fails.
pub fn generate_session_identity() -> Result<DeviceIdentity, RandomnessUnavailable> {
    generate_session_identity_from(&SystemRandom::new())
}

/// Generates a device identity from a caller-supplied byte source.
///
/// Split out from [`generate_session_identity`] so tests can drive a source that
/// fails, which the platform CSPRNG will not do on demand.
///
/// # Errors
///
/// Returns [`RandomnessUnavailable`] if `source` fails to fill a buffer.
pub fn generate_session_identity_from<R>(
    source: &R,
) -> Result<DeviceIdentity, RandomnessUnavailable>
where
    R: RandomFill,
{
    let mut rng = IdentityRng(source);
    DeviceIdentity::try_generate(&mut rng)
}

/// A source of cryptographically secure bytes.
pub trait RandomFill {
    /// Fills `destination` completely, or fails without partially trusting it.
    ///
    /// # Errors
    ///
    /// Returns [`RandomnessUnavailable`] if the source cannot fill the buffer.
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomnessUnavailable>;
}

impl RandomFill for SystemRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomnessUnavailable> {
        SecureRandom::fill(self, destination).map_err(|_| RandomnessUnavailable)
    }
}

struct IdentityRng<'a, R>(&'a R);

impl<R> TryRng for IdentityRng<'_, R>
where
    R: RandomFill,
{
    type Error = RandomnessUnavailable;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.0.fill(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.0.fill(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill(destination)
    }
}

impl<R> TryCryptoRng for IdentityRng<'_, R> where R: RandomFill {}

#[cfg(test)]
mod tests {
    use super::{
        RandomFill, RandomnessUnavailable, generate_session_identity,
        generate_session_identity_from,
    };

    /// Refuses to produce anything, standing in for a platform CSPRNG failure.
    struct BrokenSource;

    impl RandomFill for BrokenSource {
        fn fill(&self, _destination: &mut [u8]) -> Result<(), RandomnessUnavailable> {
            Err(RandomnessUnavailable)
        }
    }

    #[test]
    fn the_platform_source_produces_an_identity() {
        let identity = generate_session_identity()
            .expect("the host platform must be able to supply cryptographic randomness");

        let device_id = identity.device_id().to_string();
        assert!(
            !device_id.is_empty(),
            "a generated identity must have a device id, got {device_id:?}"
        );
    }

    #[test]
    fn two_generations_do_not_collide() {
        let first = generate_session_identity().expect("randomness available");
        let second = generate_session_identity().expect("randomness available");

        assert_ne!(
            first.device_id().to_string(),
            second.device_id().to_string(),
            "independent generations must differ; identical ids mean the source is not random"
        );
    }

    #[test]
    fn a_failing_source_produces_an_error_rather_than_a_weak_identity() {
        let error = generate_session_identity_from(&BrokenSource)
            .expect_err("a source that never yields bytes must not yield an identity");

        assert_eq!(
            error, RandomnessUnavailable,
            "the failure must be reported as such, got {error:?}"
        );
    }
}
