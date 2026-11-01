//! scheduler-retention: the service binary's `--version` path (SCHED-LOOP-008).

use std::process::Command;

// @spec SCHED-LOOP-008
#[test]
fn version_flag_prints_and_exits_0_without_running_anything() {
    let out = Command::new(env!("CARGO_BIN_EXE_backvault"))
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("backvault {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(
        out.stderr.is_empty(),
        "no log lines, no configuration errors"
    );
}
