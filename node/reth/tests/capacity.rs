//! Startup refuses an identity capacity too small for the configured load.

#[test]
fn capacity_validation_refuses_insufficient_slots() {
    use ops_reth_policy::identity::validate_capacity;
    // capacity ≥ 1.25 × (tps × (2 s inclusion + finality bound) + pending limit)
    assert!(validate_capacity(262_144, 2_000, 64, 37_500).is_ok());
    assert!(validate_capacity(211_875, 2_000, 64, 37_500).is_ok());
    assert!(validate_capacity(211_874, 2_000, 64, 37_500).is_err());
    assert!(
        validate_capacity(100_000, 2_000, 64, 37_500).is_err(),
        "the old default is too small"
    );
    assert!(
        validate_capacity(262_144, 5_250, 64, 37_500).is_err(),
        "5k tx/s needs ≈ 480k slots"
    );
    assert!(validate_capacity(480_000, 5_250, 64, 37_500).is_ok());
    assert!(validate_capacity(262_144, 0, 64, 37_500).is_err());
    assert!(validate_capacity(usize::MAX, u64::MAX, u64::MAX, u64::MAX).is_err());
    assert!(
        validate_capacity(262_144, 2_000, 0, 37_500).is_err(),
        "zero finality bound"
    );
    assert!(
        validate_capacity(usize::MAX, u64::MAX / 66, 64, 0).is_err(),
        "overflow in the headroom step"
    );
    let error = validate_capacity(100_000, 2_000, 64, 37_500).unwrap_err();
    assert!(
        error.contains("OPS_NODE_POLICY_CAPACITY") && error.contains("211875"),
        "{error}"
    );
}
