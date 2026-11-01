//! scheduler-retention: the supervisor loop, retention cleanup, and the time abstractions.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use time::OffsetDateTime;

use crate::cycle::{CycleError, DEFAULT_BACKUP_DIR, confine_to_app};
use crate::env::Env;

pub const DEFAULT_INTERVAL_HOURS: u64 = 12;
pub const MAX_INTERVAL_HOURS: u64 = 8760;
pub const DEFAULT_RETAIN_DAYS: u64 = 7;
pub const MAX_RETAIN_DAYS: u64 = 3650;

/// Source of the current time (UTC). One definition, consumed by backup-cycle too.
pub trait Clock {
    fn now_utc(&self) -> OffsetDateTime;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Waits; production sleeps the thread, tests count calls and may raise the shutdown flag.
pub trait Sleeper {
    fn sleep(&mut self, duration: Duration);
}

pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// One backup attempt as the supervisor sees it.
pub trait CycleRunner {
    fn run_cycle(&mut self) -> Result<PathBuf, CycleError>;
}

/// `backvault --version` output.
// @spec SCHED-LOOP-008
pub fn version_line() -> String {
    format!("backvault {}", env!("CARGO_PKG_VERSION"))
}

fn env_text(env: &dyn Env, name: &str, default: &str) -> String {
    env.get(name)
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_else(|| default.to_string())
}

/// Parse `BACKUP_INTERVAL_HOURS` (default 12, 1..=8760). `Err` carries the message to log before exit 1.
// @spec SCHED-LOOP-002, SCHED-LOOP-003
pub fn interval_hours(env: &dyn Env) -> Result<u64, String> {
    let raw = env_text(
        env,
        "BACKUP_INTERVAL_HOURS",
        &DEFAULT_INTERVAL_HOURS.to_string(),
    );
    let value: u64 = raw
        .trim()
        .parse()
        .map_err(|_| format!("BACKUP_INTERVAL_HOURS must be a positive integer (got {raw:?})"))?;
    if !(1..=MAX_INTERVAL_HOURS).contains(&value) {
        return Err(format!(
            "BACKUP_INTERVAL_HOURS must be between 1 and {MAX_INTERVAL_HOURS} (1 year)"
        ));
    }
    Ok(value)
}

/// Parse `RETAIN_DAYS` (default 7). `None` disables cleanup (already logged).
// @spec SCHED-RETAIN-001, SCHED-RETAIN-002, SCHED-RETAIN-003
pub fn retain_days(env: &dyn Env) -> Option<u64> {
    let raw = env_text(env, "RETAIN_DAYS", &DEFAULT_RETAIN_DAYS.to_string());
    let value = match raw.trim().parse::<u64>() {
        Ok(v) if v > 0 && raw.trim().bytes().all(|b| b.is_ascii_digit()) => v,
        _ => {
            log::info!("RETAIN_DAYS={raw:?}, skipping cleanup");
            return None;
        }
    };
    if value > MAX_RETAIN_DAYS {
        log::error!(
            "RETAIN_DAYS must be between 1 and {MAX_RETAIN_DAYS} (10 years), skipping cleanup"
        );
        return None;
    }
    Some(value)
}

/// Delete expired `.enc` and `.enc.part` regular files from the confined backup directory. Returns the count removed.
// @spec SCHED-RETAIN-005, SCHED-RETAIN-006, SCHED-RETAIN-007, SCHED-RETAIN-008
pub fn run_cleanup(env: &dyn Env, allowed_base: &Path, clock: &dyn Clock) -> usize {
    let Some(retain) = retain_days(env) else {
        return 0;
    };
    let requested = PathBuf::from(env_text(env, "BACKUP_DIR", DEFAULT_BACKUP_DIR));
    let dir = match confine_to_app(&requested, allowed_base) {
        Ok(d) => d,
        Err(e) => {
            log::error!("{e}; skipping cleanup");
            return 0;
        }
    };
    if !dir.is_dir() {
        log::warn!(
            "Backup dir {} does not exist, skipping cleanup",
            dir.display()
        );
        return 0;
    }
    log::info!(
        "Cleaning *.enc backups older than {retain} days in {}",
        dir.display()
    );
    let now = clock.now_utc();
    let cutoff = SystemTime::UNIX_EPOCH + Duration::from_secs(now.unix_timestamp().max(0) as u64)
        - Duration::from_secs(retain * 86_400);
    let mut removed = 0;
    let Ok(entries) = std::fs::read_dir(&dir) else {
        log::warn!(
            "Backup dir {} could not be read, skipping cleanup",
            dir.display()
        );
        return 0;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.ends_with(".enc") || name.ends_with(".enc.part")) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let Ok(modified) = meta.modified() else {
            continue;
        };
        if modified < cutoff {
            log::info!("Removing {name}");
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(e) => log::error!("could not remove {name}: {e}"),
            }
        }
    }
    log::info!("Cleanup finished, removed {removed} file(s)");
    removed
}

/// Sleep `seconds` in slices of at most one second, returning early when `shutdown` is set.
// @spec SCHED-SIGNAL-001
pub fn sleep_interruptible(seconds: u64, shutdown: &AtomicBool, sleeper: &mut dyn Sleeper) {
    let mut remaining = seconds;
    while remaining > 0 && !shutdown.load(Ordering::SeqCst) {
        let slice = remaining.min(1);
        sleeper.sleep(Duration::from_secs(slice));
        remaining -= slice;
    }
}

/// The main loop. `run` returns the process exit status.
pub struct Supervisor<'a> {
    pub env: &'a dyn Env,
    pub allowed_base: PathBuf,
    pub runner: &'a mut dyn CycleRunner,
    pub clock: &'a dyn Clock,
    pub sleeper: &'a mut dyn Sleeper,
    pub shutdown: Arc<AtomicBool>,
}

impl Supervisor<'_> {
    // @spec SCHED-LOOP-005, SCHED-LOOP-006
    fn run_backup(&mut self) {
        log::info!("Starting backup...");
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.runner.run_cycle()));
        match outcome {
            Ok(Ok(path)) => log::info!("Backup completed successfully: {}", path.display()),
            Ok(Err(e)) => log::error!("Backup failed: {e}"),
            Err(payload) => {
                let message = payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".to_string());
                log::error!("Backup panicked: {message}");
            }
        }
    }

    /// Validate the interval, run one cycle, then loop: sleep → cycle → cleanup on a new UTC date.
    // @spec SCHED-LOOP-001, SCHED-LOOP-004, SCHED-LOOP-007, SCHED-SIGNAL-002, SCHED-SIGNAL-003, SCHED-RETAIN-004
    pub fn run(&mut self) -> i32 {
        log::info!("Initializing BackVault backup service");
        let interval_seconds = match interval_hours(self.env) {
            Ok(hours) => hours * 3600,
            Err(message) => {
                log::error!("{message}");
                return 1;
            }
        };
        log::info!("Running initial backup on startup...");
        self.run_backup();
        let mut last_cleanup_date = self.clock.now_utc().date();
        log::info!("Starting backup loop, interval = {interval_seconds}s");
        while !self.shutdown.load(Ordering::SeqCst) {
            sleep_interruptible(interval_seconds, &self.shutdown, self.sleeper);
            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }
            self.run_backup();
            let today = self.clock.now_utc().date();
            if today != last_cleanup_date {
                run_cleanup(self.env, &self.allowed_base, self.clock);
                last_cleanup_date = today;
            }
        }
        log::info!("Shutdown complete");
        0
    }
}
