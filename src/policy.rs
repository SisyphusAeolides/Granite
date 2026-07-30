//! Boot-readiness telemetry. This score can never override digest admission.

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReadinessEvidence {
    pub manifest_bound: f64,
    pub artifacts_verified: f64,
    pub firmware_ready: f64,
    pub handoff_bounded: f64,
}

impl ReadinessEvidence {
    const fn as_array(self) -> [f64; 4] {
        [
            self.manifest_bound,
            self.artifacts_verified,
            self.firmware_ready,
            self.handoff_bounded,
        ]
    }
}

pub fn readiness_score(evidence: ReadinessEvidence) -> f64 {
    let values = evidence.as_array();
    score_impl(&values)
}

#[cfg(feature = "fortran-policy")]
fn score_impl(values: &[f64; 4]) -> f64 {
    unsafe extern "C" {
        fn arach_granite_readiness_score(features: *const f64, count: i32) -> f64;
    }
    // SAFETY: the Fortran boundary reads exactly four contiguous f64 values.
    unsafe { arach_granite_readiness_score(values.as_ptr(), values.len() as i32) }
}

#[cfg(not(feature = "fortran-policy"))]
fn score_impl(values: &[f64; 4]) -> f64 {
    let mut product = 1.0;
    for value in values {
        product *= value.clamp(0.0, 1.0);
    }
    product
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_missing_gate_collapses_readiness() {
        let ready = readiness_score(ReadinessEvidence {
            manifest_bound: 1.0,
            artifacts_verified: 1.0,
            firmware_ready: 1.0,
            handoff_bounded: 1.0,
        });
        let missing = readiness_score(ReadinessEvidence {
            artifacts_verified: 0.0,
            ..ReadinessEvidence {
                manifest_bound: 1.0,
                artifacts_verified: 1.0,
                firmware_ready: 1.0,
                handoff_bounded: 1.0,
            }
        });
        assert_eq!(ready, 1.0);
        assert_eq!(missing, 0.0);
    }
}
