//! Acceptance flow against a live Curvy-enabled Blokli stack.

#[tokio::test]
#[ignore = "requires a live Curvy-enabled Blokli stack and evaluation zkeys"]
async fn deposit_aggregate_and_withdraw_through_blokli() {
    let report = curvy_e2e::run()
        .await
        .expect("strict Curvy E2E flow failed");
    print!("{}", report.summary());

    assert_eq!(report.phases.len(), 13, "every phase must be recorded");
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
