//! Automated key rotation scheduler.
//!
//! Provides a background task that triggers key rotation at configurable intervals.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Configuration for the key rotation scheduler.
pub struct RotationSchedule {
    /// Interval between rotation checks.
    pub interval: Duration,
    /// Whether to actually rotate (vs. just log that rotation is due).
    pub auto_rotate: bool,
}

impl Default for RotationSchedule {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(3600), // Check every hour
            auto_rotate: true, // Always auto-rotate — single production mode
        }
    }
}

/// Start a background key rotation monitor.
///
/// Returns a shutdown handle that can be used to stop the scheduler.
pub fn start_rotation_monitor(
    schedule: RotationSchedule,
    rotation_callback: impl Fn() -> Result<(), String> + Send + 'static,
) -> Arc<AtomicBool> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    std::thread::Builder::new()
        .name("key-rotation-monitor".into())
        .spawn(move || {
            tracing::info!(
                "Key rotation monitor started (interval: {:?}, auto: {})",
                schedule.interval,
                schedule.auto_rotate
            );
            while !shutdown_clone.load(Ordering::Relaxed) {
                std::thread::sleep(schedule.interval);
                if shutdown_clone.load(Ordering::Relaxed) {
                    break;
                }

                tracing::info!("Key rotation check: rotation interval reached");

                if schedule.auto_rotate {
                    match rotation_callback() {
                        Ok(()) => {
                            tracing::info!("Key rotation completed successfully");
                            crate::siem::SecurityEvent::key_rotation("scheduled rotation completed");
                        }
                        Err(e) => {
                            tracing::error!("Key rotation failed: {}", e);
                            crate::siem::SecurityEvent::tamper_detected(
                                &format!("key rotation failure: {}", e),
                            );
                        }
                    }
                } else {
                    tracing::warn!("Key rotation is DUE — manual rotation required (auto_rotate=false)");
                }
            }
            tracing::info!("Key rotation monitor stopped");
        })
        .expect("failed to spawn key rotation monitor thread");

    shutdown
}
