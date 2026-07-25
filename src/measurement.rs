//! Measured-admission primitives used before Granite commits to firmware exit.

use blacklab::oureboros::sha256;

pub const SHA256_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MeasurementError {
    ManifestMissing,
    DigestMismatch,
}

/// Computes an artifact digest and requires it to match the build-bound
/// manifest in constant time. An all-zero manifest is never a fallback: it is
/// an explicit failure state for incomplete builds.
pub fn verify(
    bytes: &[u8],
    expected: [u8; SHA256_BYTES],
) -> Result<[u8; SHA256_BYTES], MeasurementError> {
    if expected == [0; SHA256_BYTES] {
        return Err(MeasurementError::ManifestMissing);
    }
    let actual = sha256(bytes);
    if !constant_time_equal(actual, expected) {
        return Err(MeasurementError::DigestMismatch);
    }
    Ok(actual)
}

/// Binds the ordered Boulder, Push, and Crest measurements into one root for
/// the native handoff record. Order is part of the evidence.
pub fn boot_root(
    boulder: [u8; SHA256_BYTES],
    push: [u8; SHA256_BYTES],
    crest: [u8; SHA256_BYTES],
) -> [u8; SHA256_BYTES] {
    let mut material = [0_u8; SHA256_BYTES * 3];
    material[..SHA256_BYTES].copy_from_slice(&boulder);
    material[SHA256_BYTES..SHA256_BYTES * 2].copy_from_slice(&push);
    material[SHA256_BYTES * 2..].copy_from_slice(&crest);
    sha256(&material)
}

/// Performs the complete comparison independently of the first differing
/// byte, so the firmware-side reject path does not expose a prefix oracle.
pub fn constant_time_equal(left: [u8; SHA256_BYTES], right: [u8; SHA256_BYTES]) -> bool {
    let mut difference = 0_u8;
    let mut index = 0;
    while index < left.len() {
        difference |= left[index] ^ right[index];
        index += 1;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_the_exact_artifact_only() {
        let artifact = b"Granite measured artifact";
        let expected = sha256(artifact);
        assert_eq!(verify(artifact, expected), Ok(expected));
        assert_eq!(
            verify(b"Granite altered artifact", expected),
            Err(MeasurementError::DigestMismatch)
        );
    }

    #[test]
    fn refuses_an_unbound_manifest() {
        assert_eq!(
            verify(b"artifact", [0; SHA256_BYTES]),
            Err(MeasurementError::ManifestMissing)
        );
    }

    #[test]
    fn ordered_boot_root_cannot_alias_a_permuted_bundle() {
        let boulder = sha256(b"boulder");
        let push = sha256(b"push");
        let crest = sha256(b"crest");
        assert_ne!(
            boot_root(boulder, push, crest),
            boot_root(push, boulder, crest)
        );
    }
}
