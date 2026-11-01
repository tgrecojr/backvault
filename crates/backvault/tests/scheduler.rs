//! scheduler-retention: interval loop, failure tolerance, shutdown, retention cleanup (SCHED-*).

mod common;

use std::cell::Cell;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use common::*;
use time::macros::datetime;

use backvault::cycle::CycleError;
use backvault::env::MapEnv;
use backvault::scheduler::{
    Clock, CycleRunner, Sleeper, Supervisor, interval_hours, retain_days, run_cleanup,
    sleep_interruptible, version_line,
};

struct FakeClock(Cell<time::OffsetDateTime>);
impl FakeClock {
    fn at(t: time::OffsetDateTime) -> Self {
        Self(Cell::new(t))
    }
}
impl Clock for FakeClock {
    fn now_utc(&self) -> time::OffsetDateTime {
        self.0.get()
    }
}

/// Counts sleeps; trips the shutdown flag after `trip_after` calls; advances a clock per sleep.
struct FakeSleeper<'a> {
    calls: Vec<Duration>,
    shutdown: Arc<AtomicBool>,
    trip_after: Option<usize>,
    clock: Option<&'a FakeClock>,
}
impl Sleeper for FakeSleeper<'_> {
    fn sleep(&mut self, d: Duration) {
        self.calls.push(d);
        if let Some(c) = self.clock {
            c.0.set(c.0.get() + d);
        }
        if Some(self.calls.len()) == self.trip_after {
            self.shutdown.store(true, Ordering::SeqCst);
        }
    }
}

enum Step {
    Ok(PathBuf),
    Err(String),
    Panic(String),
    OkThenShutdown(PathBuf),
    ErrThenShutdown(String),
}

struct FakeRunner {
    steps: VecDeque<Step>,
    calls: usize,
    shutdown: Arc<AtomicBool>,
    on_call: Option<Box<dyn FnMut(usize)>>,
}
impl CycleRunner for FakeRunner {
    fn run_cycle(&mut self) -> Result<PathBuf, CycleError> {
        self.calls += 1;
        if let Some(f) = self.on_call.as_mut() {
            f(self.calls);
        }
        match self
            .steps
            .pop_front()
            .expect("runner called more times than scripted")
        {
            Step::Ok(p) => Ok(p),
            Step::Err(m) => Err(CycleError::InvalidPath(m)),
            Step::Panic(m) => panic!("{m}"),
            Step::OkThenShutdown(p) => {
                self.shutdown.store(true, Ordering::SeqCst);
                Ok(p)
            }
            Step::ErrThenShutdown(m) => {
                self.shutdown.store(true, Ordering::SeqCst);
                Err(CycleError::InvalidPath(m))
            }
        }
    }
}

struct Harness {
    env: MapEnv,
    base: PathBuf,
    _dir: tempfile::TempDir,
    shutdown: Arc<AtomicBool>,
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("app").canonicalize().unwrap_or_else(|_| {
        std::fs::create_dir(dir.path().join("app")).unwrap();
        dir.path().join("app").canonicalize().unwrap()
    });
    let env = MapEnv::default().set(
        "BACKUP_DIR",
        base.join("backups").as_os_str().to_os_string(),
    );
    Harness {
        env,
        base,
        _dir: dir,
        shutdown: Arc::new(AtomicBool::new(false)),
    }
}

fn runner(h: &Harness, steps: Vec<Step>) -> FakeRunner {
    FakeRunner {
        steps: steps.into(),
        calls: 0,
        shutdown: h.shutdown.clone(),
        on_call: None,
    }
}

fn sleeper<'a>(
    h: &Harness,
    trip_after: Option<usize>,
    clock: Option<&'a FakeClock>,
) -> FakeSleeper<'a> {
    FakeSleeper {
        calls: Vec::new(),
        shutdown: h.shutdown.clone(),
        trip_after,
        clock,
    }
}

fn supervise(h: &Harness, r: &mut FakeRunner, c: &FakeClock, s: &mut FakeSleeper<'_>) -> i32 {
    Supervisor {
        env: &h.env,
        allowed_base: h.base.clone(),
        runner: r,
        clock: c,
        sleeper: s,
        shutdown: h.shutdown.clone(),
    }
    .run()
}

fn p(name: &str) -> PathBuf {
    PathBuf::from(format!("/app/backups/{name}"))
}

const DAY1: time::OffsetDateTime = datetime!(2024-01-01 10:00:00 UTC);

// ---------------------------------------------------------------------------
// Interval loop
// ---------------------------------------------------------------------------

// @spec SCHED-LOOP-001
#[test]
fn one_backup_runs_immediately_on_start() {
    capture_logs();
    let h = harness();
    let clock = FakeClock::at(DAY1);
    let mut r = runner(&h, vec![Step::OkThenShutdown(p("a.enc"))]);
    let mut s = sleeper(&h, None, None);
    assert_eq!(supervise(&h, &mut r, &clock, &mut s), 0);
    assert_eq!(r.calls, 1);
    assert!(s.calls.is_empty(), "no wait before the first backup");
}

// @spec SCHED-LOOP-002
#[test]
fn interval_defaults_to_12_hours() {
    assert_eq!(interval_hours(&MapEnv::default()).unwrap(), 12);
    assert_eq!(
        interval_hours(&MapEnv::default().set("BACKUP_INTERVAL_HOURS", "24")).unwrap(),
        24
    );
    assert_eq!(
        interval_hours(&MapEnv::default().set("BACKUP_INTERVAL_HOURS", "8760")).unwrap(),
        8760
    );
}

// @spec SCHED-LOOP-003
#[test]
fn invalid_interval_is_fatal_before_any_cycle() {
    for bad in ["abc", "0", "8761", "1.5", "-1", ""] {
        assert!(
            interval_hours(&MapEnv::default().set("BACKUP_INTERVAL_HOURS", bad)).is_err(),
            "{bad:?}"
        );
        capture_logs();
        let mut h = harness();
        h.env = h.env.set("BACKUP_INTERVAL_HOURS", bad);
        let clock = FakeClock::at(DAY1);
        let mut r = runner(&h, vec![]);
        let mut s = sleeper(&h, None, None);
        assert_eq!(supervise(&h, &mut r, &clock, &mut s), 1, "{bad:?}");
        assert_eq!(r.calls, 0);
        assert!(
            records()
                .iter()
                .any(|(l, m)| *l == log::Level::Error && m.contains("BACKUP_INTERVAL_HOURS"))
        );
    }
}

// @spec SCHED-LOOP-004
#[test]
fn waits_the_full_interval_between_cycles() {
    capture_logs();
    let mut h = harness();
    h.env = h.env.set("BACKUP_INTERVAL_HOURS", "1");
    let clock = FakeClock::at(DAY1);
    let mut r = runner(
        &h,
        vec![Step::Ok(p("a.enc")), Step::OkThenShutdown(p("b.enc"))],
    );
    let mut s = sleeper(&h, None, Some(&clock));
    assert_eq!(supervise(&h, &mut r, &clock, &mut s), 0);
    assert_eq!(r.calls, 2);
    let total: Duration = s.calls.iter().sum();
    assert_eq!(total, Duration::from_secs(3600));
    assert!(s.calls.iter().all(|d| *d <= Duration::from_secs(1)));
}

// @spec SCHED-LOOP-005
#[test]
fn failed_cycle_is_logged_and_schedule_continues() {
    capture_logs();
    let mut h = harness();
    h.env = h.env.set("BACKUP_INTERVAL_HOURS", "1");
    let clock = FakeClock::at(DAY1);
    let mut r = runner(
        &h,
        vec![
            Step::Err("token rejected".into()),
            Step::OkThenShutdown(p("b.enc")),
        ],
    );
    let mut s = sleeper(&h, None, Some(&clock));
    assert_eq!(supervise(&h, &mut r, &clock, &mut s), 0);
    assert_eq!(r.calls, 2);
    assert!(
        records()
            .iter()
            .any(|(l, m)| *l == log::Level::Error && m.contains("token rejected"))
    );
}

// @spec SCHED-LOOP-005
#[test]
fn panicking_cycle_is_logged_and_schedule_continues() {
    capture_logs();
    let mut h = harness();
    h.env = h.env.set("BACKUP_INTERVAL_HOURS", "1");
    let clock = FakeClock::at(DAY1);
    let mut r = runner(
        &h,
        vec![
            Step::Panic("boom inside cycle".into()),
            Step::OkThenShutdown(p("b.enc")),
        ],
    );
    let mut s = sleeper(&h, None, Some(&clock));
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let code = supervise(&h, &mut r, &clock, &mut s);
    std::panic::set_hook(prev);
    assert_eq!(code, 0);
    assert_eq!(r.calls, 2);
    assert!(
        records()
            .iter()
            .any(|(l, m)| *l == log::Level::Error && m.contains("boom inside cycle"))
    );
}

// @spec SCHED-LOOP-006
#[test]
fn successful_cycle_logs_the_path() {
    capture_logs();
    let h = harness();
    let clock = FakeClock::at(DAY1);
    let mut r = runner(
        &h,
        vec![Step::OkThenShutdown(p("backup_20240101_100000.enc"))],
    );
    let mut s = sleeper(&h, None, None);
    supervise(&h, &mut r, &clock, &mut s);
    assert!(records().iter().any(|(l, m)| *l == log::Level::Info
        && m.contains("backup_20240101_100000.enc")
        && m.to_lowercase().contains("success")));
}

// @spec SCHED-LOOP-007
#[test]
fn loop_is_driven_entirely_through_injected_traits() {
    // Every test in this file runs the real supervisor in milliseconds with no real time:
    // a full year of 1-hour intervals is just sleeper calls.
    capture_logs();
    let mut h = harness();
    h.env = h.env.set("BACKUP_INTERVAL_HOURS", "1");
    let clock = FakeClock::at(DAY1);
    let steps: Vec<Step> = (0..23)
        .map(|i| Step::Ok(p(&format!("{i}.enc"))))
        .chain([Step::OkThenShutdown(p("last.enc"))])
        .collect();
    let mut r = runner(&h, steps);
    let mut s = sleeper(&h, None, Some(&clock));
    assert_eq!(supervise(&h, &mut r, &clock, &mut s), 0);
    assert_eq!(r.calls, 24);
}

// @spec SCHED-LOOP-008
#[test]
fn version_line_names_the_binary_and_version() {
    assert_eq!(
        version_line(),
        format!("backvault {}", env!("CARGO_PKG_VERSION"))
    );
}

// ---------------------------------------------------------------------------
// Signals and shutdown
// ---------------------------------------------------------------------------

// @spec SCHED-SIGNAL-001
#[test]
fn shutdown_during_wait_stops_within_one_second_and_runs_no_more_cycles() {
    let flag = AtomicBool::new(false);
    let h = harness();
    let mut s = sleeper(&h, Some(5), None);
    s.shutdown = Arc::new(AtomicBool::new(false));
    let shared = s.shutdown.clone();
    sleep_interruptible(3600, &shared, &mut s);
    assert_eq!(
        s.calls.len(),
        5,
        "returned right after the slice in which the flag was raised"
    );
    assert!(s.calls.iter().all(|d| *d <= Duration::from_secs(1)));

    flag.store(true, Ordering::SeqCst);
    let mut s2 = sleeper(&h, None, None);
    sleep_interruptible(3600, &flag, &mut s2);
    assert!(
        s2.calls.is_empty(),
        "an already-raised flag means no sleep at all"
    );

    capture_logs();
    let mut h = harness();
    h.env = h.env.set("BACKUP_INTERVAL_HOURS", "1");
    let clock = FakeClock::at(DAY1);
    let mut r = runner(&h, vec![Step::Ok(p("a.enc"))]);
    let mut s = sleeper(&h, Some(3), Some(&clock));
    assert_eq!(supervise(&h, &mut r, &clock, &mut s), 0);
    assert_eq!(r.calls, 1);
    assert_eq!(s.calls.len(), 3);
}

// @spec SCHED-SIGNAL-002
#[test]
fn shutdown_during_cycle_lets_cycle_and_due_cleanup_finish() {
    capture_logs();
    let mut h = harness();
    h.env = h
        .env
        .set("BACKUP_INTERVAL_HOURS", "1")
        .set("RETAIN_DAYS", "1");
    let backups = h.base.join("backups");
    std::fs::create_dir_all(&backups).unwrap();
    let old = backups.join("old.enc");
    std::fs::write(&old, b"x").unwrap();
    std::fs::File::open(&old)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .unwrap();
    let clock = FakeClock::at(datetime!(2024-01-01 23:30:00 UTC));
    // Second cycle starts on 2024-01-02 (the sleeper advances the clock), and the flag is raised during it.
    let mut r = runner(
        &h,
        vec![Step::Ok(p("a.enc")), Step::OkThenShutdown(p("b.enc"))],
    );
    let mut s = sleeper(&h, None, Some(&clock));
    assert_eq!(supervise(&h, &mut r, &clock, &mut s), 0);
    assert_eq!(r.calls, 2);
    assert!(
        !old.exists(),
        "cleanup due on the new UTC day still ran before exit"
    );
}

// @spec SCHED-SIGNAL-003
#[test]
fn shutdown_logs_complete_and_exits_0() {
    capture_logs();
    let h = harness();
    let clock = FakeClock::at(DAY1);
    let mut r = runner(&h, vec![Step::ErrThenShutdown("whatever".into())]);
    let mut s = sleeper(&h, None, None);
    assert_eq!(supervise(&h, &mut r, &clock, &mut s), 0);
    assert!(
        records()
            .iter()
            .any(|(l, m)| *l == log::Level::Info && m == "Shutdown complete")
    );
}

// ---------------------------------------------------------------------------
// Retention cleanup
// ---------------------------------------------------------------------------

fn populated(h: &Harness) -> (PathBuf, Vec<(PathBuf, bool)>) {
    let dir = h.base.join("backups");
    std::fs::create_dir_all(&dir).unwrap();
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let mut files = Vec::new();
    let mut make = |name: &str, aged: bool, expect_deleted: bool| {
        let path = dir.join(name);
        std::fs::write(&path, b"x").unwrap();
        if aged {
            std::fs::File::open(&path)
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        files.push((path, expect_deleted));
    };
    make("old.enc", true, true);
    make("old.enc.part", true, true);
    make("fresh.enc", false, false);
    make("old.txt", true, false);
    make("old-target.bak", true, false);
    std::os::unix::fs::symlink(dir.join("old-target.bak"), dir.join("link.enc")).unwrap();
    files.push((dir.join("link.enc"), false));
    std::fs::create_dir(dir.join("subdir.enc")).unwrap();
    files.push((dir.join("subdir.enc"), false));
    (dir, files)
}

// @spec SCHED-RETAIN-001
#[test]
fn retain_days_defaults_to_7() {
    assert_eq!(retain_days(&MapEnv::default()), Some(7));
    assert_eq!(
        retain_days(&MapEnv::default().set("RETAIN_DAYS", "30")),
        Some(30)
    );
}

// @spec SCHED-RETAIN-002
#[test]
fn zero_or_non_integer_retain_days_skips_cleanup_with_info() {
    for bad in ["0", "-1", "abc", "1.5", ""] {
        capture_logs();
        assert_eq!(
            retain_days(&MapEnv::default().set("RETAIN_DAYS", bad)),
            None,
            "{bad:?}"
        );
        assert!(
            records()
                .iter()
                .any(|(l, m)| *l == log::Level::Info && m.to_lowercase().contains("skipping")),
            "{bad:?}"
        );
    }
}

// @spec SCHED-RETAIN-003
#[test]
fn retain_days_above_3650_skips_cleanup_with_error() {
    capture_logs();
    assert_eq!(
        retain_days(&MapEnv::default().set("RETAIN_DAYS", "3651")),
        None
    );
    assert!(
        records()
            .iter()
            .any(|(l, m)| *l == log::Level::Error && m.contains("3650"))
    );
    assert_eq!(
        retain_days(&MapEnv::default().set("RETAIN_DAYS", "3650")),
        Some(3650)
    );
}

// @spec SCHED-RETAIN-004
#[test]
fn cleanup_runs_once_per_new_utc_date_after_a_cycle() {
    capture_logs();
    let mut h = harness();
    h.env = h.env.set("BACKUP_INTERVAL_HOURS", "6");
    let (_, files) = populated(&h);
    let old = files[0].0.clone();
    // Day 1 at 10:00: startup cycle, no cleanup (same date as startup). 16:00 and 22:00: same date.
    // 04:00 next day: cleanup runs once. 10:00 next day: not again.
    let clock = FakeClock::at(DAY1);
    let mut r = runner(
        &h,
        vec![
            Step::Ok(p("1.enc")),
            Step::Ok(p("2.enc")),
            Step::Ok(p("3.enc")),
            Step::Ok(p("4.enc")),
            Step::OkThenShutdown(p("5.enc")),
        ],
    );
    let flag = h.shutdown.clone();
    let old_probe = old.clone();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    r.on_call = Some(Box::new(move |n| {
        seen2.lock().unwrap().push((n, old_probe.exists()));
        let _ = &flag;
    }));
    let mut s = sleeper(&h, None, Some(&clock));
    assert_eq!(supervise(&h, &mut r, &clock, &mut s), 0);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        [(1, true), (2, true), (3, true), (4, true), (5, false)],
        "old file survives until the first cycle of day 2 completes"
    );
    let cleanups = records()
        .iter()
        .filter(|(_, m)| m.contains("Cleanup finished"))
        .count();
    assert_eq!(cleanups, 1);
}

// @spec SCHED-RETAIN-005, SCHED-RETAIN-007
#[test]
fn cleanup_deletes_only_expired_regular_enc_and_part_files() {
    capture_logs();
    let h = harness();
    let (_, files) = populated(&h);
    let removed = run_cleanup(&h.env, &h.base, &FakeClock::at(DAY1));
    assert_eq!(removed, 2);
    for (path, expect_deleted) in files {
        assert_eq!(
            !path.exists() && path.symlink_metadata().is_err(),
            expect_deleted,
            "{path:?}"
        );
    }
    assert!(
        h.base.join("backups/old-target.bak").exists(),
        "symlink target untouched"
    );
    assert!(
        records()
            .iter()
            .any(|(l, m)| *l == log::Level::Info && m.contains("removed 2"))
    );
}

// @spec SCHED-RETAIN-005
#[test]
fn cleanup_uses_retain_days_times_24_hours_by_mtime() {
    let mut h = harness();
    h.env = h.env.set("RETAIN_DAYS", "2");
    let dir = h.base.join("backups");
    std::fs::create_dir_all(&dir).unwrap();
    let now = DAY1;
    let unix = |t: time::OffsetDateTime| {
        SystemTime::UNIX_EPOCH + Duration::from_secs(t.unix_timestamp() as u64)
    };
    let keep = dir.join("keep.enc");
    let drop = dir.join("drop.enc");
    std::fs::write(&keep, b"x").unwrap();
    std::fs::write(&drop, b"x").unwrap();
    std::fs::File::open(&keep)
        .unwrap()
        .set_modified(unix(now - Duration::from_secs(2 * 86400 - 60)))
        .unwrap();
    std::fs::File::open(&drop)
        .unwrap()
        .set_modified(unix(now - Duration::from_secs(2 * 86400 + 60)))
        .unwrap();
    assert_eq!(run_cleanup(&h.env, &h.base, &FakeClock::at(now)), 1);
    assert!(keep.exists());
    assert!(!drop.exists());
}

// @spec SCHED-RETAIN-006
#[test]
fn missing_backup_dir_warns_and_skips() {
    capture_logs();
    let h = harness();
    assert_eq!(run_cleanup(&h.env, &h.base, &FakeClock::at(DAY1)), 0);
    assert!(
        records()
            .iter()
            .any(|(l, m)| *l == log::Level::Warn && m.to_lowercase().contains("does not exist"))
    );
}

// @spec SCHED-RETAIN-008
#[test]
fn cleanup_refuses_a_directory_outside_app() {
    capture_logs();
    let mut h = harness();
    let outside = h._dir.path().join("elsewhere");
    std::fs::create_dir(&outside).unwrap();
    let victim = outside.join("old.enc");
    std::fs::write(&victim, b"x").unwrap();
    std::fs::File::open(&victim)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .unwrap();
    h.env = h.env.set("BACKUP_DIR", outside.as_os_str().to_os_string());
    assert_eq!(run_cleanup(&h.env, &h.base, &FakeClock::at(DAY1)), 0);
    assert!(victim.exists());
    assert!(
        records()
            .iter()
            .any(|(l, m)| *l == log::Level::Error && m.contains("elsewhere"))
    );
}

#[test]
fn every_spec_cited_here_exists() {
    assert_cited_specs_exist(
        "crates/backvault/tests/scheduler.rs",
        "docs/intent/scheduler-retention/scheduler-retention-specs.md",
        "SCHED",
    );
    let _ = Path::new("");
}
