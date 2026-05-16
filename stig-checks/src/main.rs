//! `stig-checks` binary — inspects the real posture of the running `authsrv`
//! deployment against the V5R3 APP-* controls and emits a JSON score-card on
//! stdout plus an XCCDF report on stderr.
//!
//! Exit codes:
//!   0  all evaluated CatI controls pass
//!   2  at least one CatI control failed
//!   3  no controls could be evaluated (host posture undeterminable) —
//!      a STIG run with zero coverage is a failure, not a clean pass.

use stig_checks::{render_xccdf, score, Outcome, Severity, StigEvaluator};

fn main() {
    // Inspect the real system. Values that cannot be observed stay `None` and
    // their controls report `NotChecked` — never a fabricated `Pass`.
    let evaluator = StigEvaluator::from_system();
    let checks = evaluator.run();
    let card = score(&checks);

    let card_json = serde_json::to_string_pretty(&card).unwrap_or_else(|_| "{}".into());
    println!("{card_json}");

    let xccdf = render_xccdf(&checks);
    eprintln!("{xccdf}");

    let cat1_fail = checks
        .iter()
        .any(|c| c.severity == Severity::CatI && c.outcome == Outcome::Fail);
    if cat1_fail {
        std::process::exit(2);
    }

    // Fail loud if nothing was actually inspected: a 0%-coverage run must not
    // be mistaken for a compliant system.
    let evaluated = card.passed + card.failed;
    if evaluated == 0 {
        eprintln!(
            "stig-checks: no controls could be evaluated on this host \
             (set STIG_* environment variables from the authsrv configuration)"
        );
        std::process::exit(3);
    }
}
