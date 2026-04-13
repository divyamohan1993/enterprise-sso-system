//! `stig-checks` binary — runs the V5R3 APP-* checks against the running
//! configuration and emits a JSON score-card on stdout plus an XCCDF report
//! on stderr. Exit code is non-zero if any CatI control fails.

use stig_checks::{render_xccdf, score, Outcome, Severity, StigEvaluator};

fn main() {
    let evaluator = StigEvaluator::default();
    let checks = evaluator.run();
    let card = score(&checks);

    let card_json = serde_json::to_string_pretty(&card).unwrap_or_else(|_| "{}".into());
    println!("{}", card_json);

    let xccdf = render_xccdf(&checks);
    eprintln!("{}", xccdf);

    let cat1_fail = checks
        .iter()
        .any(|c| c.severity == Severity::CatI && c.outcome == Outcome::Fail);
    if cat1_fail {
        std::process::exit(2);
    }
}
