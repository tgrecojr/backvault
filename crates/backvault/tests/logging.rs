//! scheduler-retention: the log backend (SCHED-LOG). Tested directly; the global logger is
//! installed only by the binary.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use time::macros::datetime;

use backvault::logging::{Backend, format_line};

#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);
impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Shared {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

// @spec SCHED-LOG-001
#[test]
fn line_format_is_timestamp_level_message() {
    let now = datetime!(2026-01-02 03:04:05 UTC);
    assert_eq!(
        format_line(now, log::Level::Info, "hello"),
        "2026-01-02T03:04:05Z INFO hello"
    );
    assert_eq!(
        format_line(now, log::Level::Error, "x y"),
        "2026-01-02T03:04:05Z ERROR x y"
    );
    assert_eq!(
        format_line(now, log::Level::Warn, ""),
        "2026-01-02T03:04:05Z WARN "
    );
}

// @spec SCHED-LOG-001
#[test]
fn backend_writes_each_line_to_stdout() {
    let out = Shared::default();
    let backend = Backend::new(Box::new(out.clone()), None);
    backend.write_line("2026-01-02T03:04:05Z INFO one");
    backend.write_line("2026-01-02T03:04:06Z ERROR two");
    assert_eq!(
        out.text(),
        "2026-01-02T03:04:05Z INFO one\n2026-01-02T03:04:06Z ERROR two\n"
    );
}

// @spec SCHED-LOG-001
#[test]
fn log_records_are_formatted_and_info_and_above_are_enabled() {
    use log::Log;
    let out = Shared::default();
    let backend = Backend::new(Box::new(out.clone()), None);
    let record = log::Record::builder()
        .level(log::Level::Warn)
        .args(format_args!("careful"))
        .build();
    backend.log(&record);
    let text = out.text();
    assert!(text.ends_with("Z WARN careful\n"), "{text}");
    assert_eq!(
        text.len(),
        "2026-01-02T03:04:05".len() + "Z WARN careful\n".len()
    );
    assert!(backend.enabled(&log::Metadata::builder().level(log::Level::Info).build()));
    assert!(backend.enabled(&log::Metadata::builder().level(log::Level::Error).build()));
    assert!(!backend.enabled(&log::Metadata::builder().level(log::Level::Debug).build()));
}

// @spec SCHED-LOG-002
#[test]
fn log_file_receives_every_line_and_is_created() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub").join("backvault.log");
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let out = Shared::default();
    let (backend, warning) = Backend::with_log_file(Box::new(out.clone()), Some(&path));
    assert!(warning.is_none());
    backend.write_line("2026-01-02T03:04:05Z INFO one");
    drop(backend);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "2026-01-02T03:04:05Z INFO one\n"
    );
    assert_eq!(out.text(), "2026-01-02T03:04:05Z INFO one\n");
    // Append, never truncate.
    let (backend, _) = Backend::with_log_file(Box::new(out.clone()), Some(&path));
    backend.write_line("2026-01-02T03:04:06Z INFO two");
    drop(backend);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "2026-01-02T03:04:05Z INFO one\n2026-01-02T03:04:06Z INFO two\n"
    );
}

// @spec SCHED-LOG-002
#[test]
fn unopenable_log_file_is_reported_on_stdout_and_logging_continues() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing-dir").join("backvault.log");
    let out = Shared::default();
    let (backend, warning) = Backend::with_log_file(Box::new(out.clone()), Some(&path));
    let warning = warning.expect("a warning line");
    assert!(warning.contains("backvault.log"), "{warning}");
    backend.write_line("2026-01-02T03:04:05Z INFO still here");
    assert!(out.text().contains("still here"));
    assert!(!path.exists());
}

#[test]
fn every_spec_cited_here_exists() {
    common::assert_cited_specs_exist(
        "crates/backvault/tests/logging.rs",
        "docs/intent/scheduler-retention/scheduler-retention-specs.md",
        "SCHED",
    );
}
