//! TEMPORARY CI CONTROL -- MUST NOT BE MERGED.
//!
//! This file exists to execute acceptance control 3 for the workflow patch in
//! PR #167: with a root-workspace test failing, prove that
//!
//!   * the doctest step still executes (it carries `if: ${{ !cancelled() }}`),
//!   * the desktop-workspace step still executes on macOS native, and
//!   * the job is nevertheless still red.
//!
//! Without this control, a green run only proves the patch was applied, not
//! that the fail-fast vacuum it targets is actually closed. The branch
//! carrying this file is deleted once the evidence is captured.

use std::hint::black_box;

/// Fails on purpose. See the module comment.
#[test]
fn deliberate_failure_for_ci_acceptance_control_three() {
    panic!("deliberate CI control failure: proving later steps still execute");
}

/// Passes, so the run also demonstrates that `--no-fail-fast` keeps going past
/// the failure above instead of abandoning the remaining test binaries.
#[test]
fn control_companion_that_must_still_report_a_result() {
    let left = black_box(2_u32) + black_box(2_u32);
    assert_eq!(left, black_box(4_u32));
}
