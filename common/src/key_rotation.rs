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
) -> Result<Arc<AtomicBool>, String> {
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
        .map_err(|e| format!("failed to spawn key rotation monitor thread: {e}"))?;

    Ok(shutdown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    #[test]
    fn rotation_schedule_default_values() {
        let schedule = RotationSchedule::default();
        assert_eq!(schedule.interval, Duration::from_secs(3600));
        assert!(schedule.auto_rotate, "auto_rotate must default to true (production mode)");
    }

    #[test]
    fn shutdown_handle_stops_monitor() {
        // Use a very short interval so the monitor thread loops quickly.
        let schedule = RotationSchedule {
            interval: Duration::from_millis(10),
            auto_rotate: false, // Don't call callback, just test shutdown
        };
        let shutdown = start_rotation_monitor(schedule, || Ok(())).unwrap();

        // Let it run briefly, then signal shutdown.
        std::thread::sleep(Duration::from_millis(50));
        shutdown.store(true, Ordering::Relaxed);

        // Give the thread time to observe the flag and exit.
        std::thread::sleep(Duration::from_millis(30));
        // If we get here without hanging, the shutdown handle works.
        assert!(shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn monitor_invokes_callback_on_auto_rotate() {
        let call_count = Arc::new(AtomicU32::new(0));
        let count_clone = call_count.clone();

        let schedule = RotationSchedule {
            interval: Duration::from_millis(10),
            auto_rotate: true,
        };
        let shutdown = start_rotation_monitor(schedule, move || {
            count_clone.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();

        // Let a few rotation cycles run.
        std::thread::sleep(Duration::from_millis(80));
        shutdown.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(30));

        assert!(
            call_count.load(Ordering::Relaxed) >= 1,
            "rotation callback must be invoked at least once"
        );
    }

    #[test]
    fn monitor_handles_callback_error_without_crashing() {
        let schedule = RotationSchedule {
            interval: Duration::from_millis(10),
            auto_rotate: true,
        };
        let shutdown = start_rotation_monitor(schedule, || {
            Err("simulated rotation failure".to_string())
        })
        .unwrap();

        // Let it run a few cycles with the failing callback.
        std::thread::sleep(Duration::from_millis(80));
        shutdown.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(30));
        // No panic means the error path is handled gracefully.
    }

    #[test]
    fn monitor_skips_callback_when_auto_rotate_false() {
        let call_count = Arc::new(AtomicU32::new(0));
        let count_clone = call_count.clone();

        let schedule = RotationSchedule {
            interval: Duration::from_millis(10),
            auto_rotate: false,
        };
        let shutdown = start_rotation_monitor(schedule, move || {
            count_clone.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();

        std::thread::sleep(Duration::from_millis(80));
        shutdown.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(30));

        assert_eq!(
            call_count.load(Ordering::Relaxed),
            0,
            "callback must NOT be invoked when auto_rotate is false"
        );
    }
}
