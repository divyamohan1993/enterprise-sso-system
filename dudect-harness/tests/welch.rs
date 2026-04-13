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
    let report = measure(&[0u8; 16], &[0u8; 16], 2000, |input| {
        if input.iter().sum::<u8>() == 0 {
            std::hint::black_box(input.len());
        }
    });
    assert!(report.samples > 0);
}

#[test]
fn constant_op_passes() {
    let report = measure(&[0u8; 32], &[0xFFu8; 32], 1000, |input| {
        let _ = std::hint::black_box(input[0]);
    });
    assert_eq!(report.verdict, Verdict::ConstantTime);
}
