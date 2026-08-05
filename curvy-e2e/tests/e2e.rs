//! Full PIX flow against the live Curvy-enabled Blokli image.

#[tokio::test]
#[ignore = "requires a live Curvy-enabled Blokli stack and evaluation zkeys"]
async fn deposit_aggregate_and_withdraw_pix_through_blokli() {
    let report = curvy_e2e::run()
        .await
        .expect("strict Curvy E2E flow failed");
    print!("{}", report.summary());

    assert_eq!(report.phases.len(), 13, "every phase must be recorded");
    assert!(report.delivered_wei > 0, "withdrawal delivered nothing");

    // Blokli is the only backend: every seam — submission, the event index, the trust
    // anchor, fees, balances, portal derivation — goes through it, so no transaction
    // may report any other backend.
    let bypassed = report
        .transactions()
        .filter(|tx| tx.backend != "blokli")
        .collect::<Vec<_>>();
    assert!(
        bypassed.is_empty(),
        "every tx must go through Blokli, these did not: {bypassed:?}"
    );
}
