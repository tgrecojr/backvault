//! Process-wide log backend: one line per record on stdout, optionally appended to `LOG_FILE`.

use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use time::OffsetDateTime;
use time::macros::format_description;

/// `YYYY-MM-DDTHH:MM:SSZ LEVEL message`.
// @spec SCHED-LOG-001
pub fn format_line(now: OffsetDateTime, level: log::Level, message: &str) -> String {
    let stamp = now
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
        ))
        .expect("fixed format");
    format!("{stamp} {level} {message}")
}

/// The backend. `file` is `None` when `LOG_FILE` is unset or could not be opened.
pub struct Backend {
    stdout: Mutex<Box<dyn Write + Send>>,
    file: Option<Mutex<Box<dyn Write + Send>>>,
}

impl Backend {
    pub fn new(stdout: Box<dyn Write + Send>, file: Option<Box<dyn Write + Send>>) -> Self {
        Self {
            stdout: Mutex::new(stdout),
            file: file.map(Mutex::new),
        }
    }

    /// Open `log_file` for append (creating it). On failure returns the warning line to emit on stdout.
    // @spec SCHED-LOG-002
    pub fn with_log_file(
        stdout: Box<dyn Write + Send>,
        log_file: Option<&Path>,
    ) -> (Self, Option<String>) {
        let Some(path) = log_file else {
            return (Self::new(stdout, None), None);
        };
        match std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
        {
            Ok(file) => (Self::new(stdout, Some(Box::new(file))), None),
            Err(e) => (
                Self::new(stdout, None),
                Some(format!(
                    "could not open LOG_FILE '{}': {e}; logging to stdout only",
                    path.display()
                )),
            ),
        }
    }

    /// Write one already-formatted line to every sink.
    // @spec SCHED-LOG-001, SCHED-LOG-002
    pub fn write_line(&self, line: &str) {
        if let Ok(mut out) = self.stdout.lock() {
            let _ = writeln!(out, "{line}");
            let _ = out.flush();
        }
        if let Some(file) = &self.file
            && let Ok(mut f) = file.lock()
        {
            let _ = writeln!(f, "{line}");
            let _ = f.flush();
        }
    }
}

impl log::Log for Backend {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }
    // @spec SCHED-LOG-001
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            self.write_line(&format_line(
                OffsetDateTime::now_utc(),
                record.level(),
                &record.args().to_string(),
            ));
        }
    }
    fn flush(&self) {}
}

/// Install the global backend (stdout plus optional `LOG_FILE`). Never fails; a bad file is reported on stdout.
// @spec SCHED-LOG-001, SCHED-LOG-002
pub fn install(log_file: Option<&Path>) {
    let (backend, warning) = Backend::with_log_file(Box::new(std::io::stdout()), log_file);
    if let Some(warning) = warning {
        backend.write_line(&format_line(
            OffsetDateTime::now_utc(),
            log::Level::Warn,
            &warning,
        ));
    }
    if log::set_boxed_logger(Box::new(backend)).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
}
