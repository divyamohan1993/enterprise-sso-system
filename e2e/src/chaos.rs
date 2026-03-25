//! Chaos test engine for MILNET SSO.
//!
//! Provides the `ChaosResult` type and `ChaosScenario` trait used by all
//! chaos/failure-injection test files.

/// The result of running a single chaos scenario.
pub struct ChaosResult {
    /// Human-readable name of the scenario.
    pub scenario: String,
    /// Whether the system behaved correctly under the chaos condition.
    pub passed: bool,
    /// What the system was expected to do.
    pub expected_behavior: String,
    /// What the system actually did.
    pub actual_behavior: String,
    /// Wall-clock duration of the scenario in milliseconds.
    pub duration_ms: u64,
}

/// A named, self-contained chaos scenario.
pub trait ChaosScenario: Send + Sync {
    /// Short identifier for this scenario (used in reports).
    fn name(&self) -> &str;
    /// Human-readable description of what failure mode is being injected.
    fn description(&self) -> &str;
    /// Execute the scenario and return a result.
    fn run(&self) -> ChaosResult;
}
