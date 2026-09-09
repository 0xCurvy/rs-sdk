//! Acceptance flow against a live Curvy-enabled Blokli stack.
//!
//! `CURVY_E2E_SHIELD` selects which deposit path the run exercises: `portal` (the default) funds
//! and deploys an entry portal, `direct` pays the aggregator itself. The latter needs a
//! deployment with `directShieldEnabled` set, and is the topology a HOPR node runs against.
//!
//! ```text
//! CURVY_E2E_SHIELD=direct cargo test -p curvy-e2e --test e2e -- --ignored
//! ```

#[tokio::test]
#[ignore = "requires a live Curvy-enabled Blokli stack and evaluation zkeys"]
async fn deposit_aggregate_and_withdraw_through_blokli() {
    let report = curvy_e2e::run()
        .await
        .expect("strict Curvy E2E flow failed");
    print!("{}", report.summary());

    assert_eq!(
        report.phases.len(),
        curvy_e2e::E2E_PHASE_COUNT,
        "every phase must be recorded"
    );
    assert!(report.delivered_wei > 0, "withdrawal delivered nothing");

    // Every transaction must use Blokli.
    let bypassed = report
        .transactions()
        .filter(|tx| tx.backend != "blokli")
        .collect::<Vec<_>>();
    assert!(
        bypassed.is_empty(),
        "every tx must go through Blokli, these did not: {bypassed:?}"
    );
}
