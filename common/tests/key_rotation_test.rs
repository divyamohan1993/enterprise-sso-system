use common::key_rotation::{start_rotation_monitor, RotationSchedule};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ── 1. Rotation monitor creation with interval ─────────────────────────

#[test]
fn rotation_monitor_creates_with_custom_interval() {
    let schedule = RotationSchedule {
        interval: Duration::from_millis(50),
        auto_rotate: false,
    };
    let shutdown = start_rotation_monitor(schedule, || Ok(())).unwrap();
    // Monitor started successfully.
    assert!(!shutdown.load(Ordering::Relaxed), "shutdown flag must start false");
    shutdown.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(100));
}

#[test]
fn rotation_schedule_default_values() {
    let schedule = RotationSchedule::default();
    assert_eq!(schedule.interval, Duration::from_secs(3600));
    assert!(schedule.auto_rotate);
}

// ── 2. Callback invoked on rotation trigger ────────────────────────────

#[test]
fn callback_invoked_on_rotation() {
    let count = Arc::new(AtomicU32::new(0));
    let c = count.clone();

    let schedule = RotationSchedule {
        interval: Duration::from_millis(10),
        auto_rotate: true,
    };
    let shutdown = start_rotation_monitor(schedule, move || {
        c.fetch_add(1, Ordering::Relaxed);
        Ok(())
    })
    .unwrap();

    std::thread::sleep(Duration::from_millis(100));
    shutdown.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(30));

    assert!(
        count.load(Ordering::Relaxed) >= 1,
        "callback must be invoked at least once"
    );
}

// ── 3. Multiple rotations execute correctly ────────────────────────────

#[test]
fn multiple_rotations_execute() {
    let count = Arc::new(AtomicU32::new(0));
    let c = count.clone();

    let schedule = RotationSchedule {
        interval: Duration::from_millis(10),
        auto_rotate: true,
    };
    let shutdown = start_rotation_monitor(schedule, move || {
        c.fetch_add(1, Ordering::Relaxed);
        Ok(())
    })
    .unwrap();

    // Let several rotation cycles run.
    std::thread::sleep(Duration::from_millis(150));
    shutdown.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(30));

    let total = count.load(Ordering::Relaxed);
    assert!(
        total >= 3,
        "multiple rotations must execute, got {total}"
    );
}

#[test]
fn callback_error_does_not_crash_monitor() {
    let error_count = Arc::new(AtomicU32::new(0));
    let c = error_count.clone();

    let schedule = RotationSchedule {
        interval: Duration::from_millis(10),
        auto_rotate: true,
    };
    let shutdown = start_rotation_monitor(schedule, move || {
        c.fetch_add(1, Ordering::Relaxed);
        Err("simulated rotation failure".to_string())
    })
    .unwrap();

    std::thread::sleep(Duration::from_millis(100));
    shutdown.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(30));

    assert!(
        error_count.load(Ordering::Relaxed) >= 2,
        "monitor must continue invoking callback even after errors"
    );
}

// ── 4. Shutdown stops the monitor cleanly ──────────────────────────────

#[test]
fn shutdown_stops_monitor_cleanly() {
    let count = Arc::new(AtomicU32::new(0));
    let c = count.clone();

    let schedule = RotationSchedule {
        interval: Duration::from_millis(10),
        auto_rotate: true,
    };
    let shutdown = start_rotation_monitor(schedule, move || {
        c.fetch_add(1, Ordering::Relaxed);
        Ok(())
    })
    .unwrap();

    std::thread::sleep(Duration::from_millis(80));
    shutdown.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(30));

    let count_at_shutdown = count.load(Ordering::Relaxed);

    // Wait more and verify no additional callbacks fire.
    std::thread::sleep(Duration::from_millis(100));
    let count_after = count.load(Ordering::Relaxed);

    // Allow at most 1 extra callback (the one in-flight when shutdown was set).
    assert!(
        count_after <= count_at_shutdown + 1,
        "monitor must stop after shutdown: at_shutdown={count_at_shutdown}, after={count_after}"
    );
}

#[test]
fn auto_rotate_false_skips_callback() {
    let count = Arc::new(AtomicU32::new(0));
    let c = count.clone();

    let schedule = RotationSchedule {
        interval: Duration::from_millis(10),
        auto_rotate: false,
    };
    let shutdown = start_rotation_monitor(schedule, move || {
        c.fetch_add(1, Ordering::Relaxed);
        Ok(())
    })
    .unwrap();

    std::thread::sleep(Duration::from_millis(80));
    shutdown.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(30));

    assert_eq!(
        count.load(Ordering::Relaxed),
        0,
        "callback must NOT fire when auto_rotate is false"
    );
}
