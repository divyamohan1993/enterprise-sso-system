use dudect_harness::*;

#[test]
fn welch_zero_for_identical_streams() {
    let mut w = WelchT::new();
    for _ in 0..100 {
        w.push(0, 1.0);
        w.push(1, 1.0);
    }
    assert!(w.t().abs() < 1e-9);
}

#[test]
fn detects_obvious_leak() {
    // Positive control: a data-dependent loop whose iteration count is driven
    // by the first input byte. class-1 (0xFF) runs 255 extra iterations per
    // call versus class-0 (0x00), an unmissable timing difference. If the
    // harness ever regresses to an always-zero t-statistic this test fails.
    let class0 = [0u8; 16];
    let class1 = [0xFFu8; 16];
    let report = measure(&class0, &class1, 20_000, |input| {
        let mut acc = 0u64;
        for _ in 0..input[0] {
            acc = std::hint::black_box(acc).wrapping_add(1);
        }
        let _ = std::hint::black_box(acc);
    });
    assert_eq!(
        report.verdict,
        Verdict::LeakDetected,
        "harness failed to flag a blatant input-dependent loop: |t|={:.3}",
        report.t
    );
}

#[test]
fn constant_op_passes() {
    let report = measure(&[0u8; 32], &[0xFFu8; 32], 1000, |input| {
        let _ = std::hint::black_box(input[0]);
    });
    assert_eq!(report.verdict, Verdict::ConstantTime);
}
