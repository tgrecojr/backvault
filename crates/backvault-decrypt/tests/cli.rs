//! backup-encryption: the restore tool as a subprocess (ENC-TOOL).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_backvault-decrypt");
const PASSWORD: &[u8] = b"fixture-password-2026";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../backvault-format/tests/fixtures")
}

struct Outcome {
    status: i32,
    stdout: Vec<u8>,
    stderr: String,
}

fn run(args: &[&str], stdin: Option<&[u8]>) -> Outcome {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn backvault-decrypt");
    if let Some(bytes) = stdin {
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    Outcome {
        status: out.status.code().unwrap_or(-1),
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn arg(p: PathBuf) -> String {
    p.to_string_lossy().into_owned()
}

// @spec ENC-TOOL-001, ENC-TOOL-004
#[test]
fn piped_password_yields_exact_plaintext_on_stdout() {
    let expected = std::fs::read(fixtures().join("plaintext.json")).unwrap();
    let out = run(
        &[&arg(fixtures().join("v2.enc"))],
        Some(b"fixture-password-2026\n"),
    );
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(
        out.stdout, expected,
        "stdout is exactly the plaintext, nothing added"
    );
    assert!(
        out.stderr.contains("Decryption successful"),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("version 2"), "{}", out.stderr);
    assert!(
        !out.stderr.contains("Enter backup password"),
        "no prompt when stdin is not a terminal"
    );
    assert!(!out.stderr.contains(std::str::from_utf8(PASSWORD).unwrap()));
}

// @spec ENC-TOOL-004
#[test]
fn piped_password_tolerates_crlf_and_no_newline() {
    let expected = std::fs::read(fixtures().join("plaintext.json")).unwrap();
    for stdin in [&b"fixture-password-2026\r\n"[..], b"fixture-password-2026"] {
        let out = run(&[&arg(fixtures().join("v2.enc"))], Some(stdin));
        assert_eq!(out.status, 0, "{}", out.stderr);
        assert_eq!(out.stdout, expected);
    }
}

// @spec ENC-TOOL-001
#[test]
fn version_1_fixture_opens_too() {
    let expected = std::fs::read(fixtures().join("plaintext.json")).unwrap();
    let out = run(
        &[&arg(fixtures().join("v1.enc"))],
        Some(b"fixture-password-2026\n"),
    );
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(out.stdout, expected);
    assert!(out.stderr.contains("version 1"), "{}", out.stderr);
}

// @spec ENC-TOOL-002
#[test]
fn wrong_password_exits_1_with_nothing_on_stdout() {
    let out = run(&[&arg(fixtures().join("v2.enc"))], Some(b"wrong\n"));
    assert_eq!(out.status, 1);
    assert!(out.stdout.is_empty());
    assert!(
        out.stderr.to_lowercase().contains("password")
            || out.stderr.to_lowercase().contains("corrupt"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("Decryption successful"));
}

// @spec ENC-TOOL-002
#[test]
fn missing_file_exits_1_naming_path() {
    let missing = arg(fixtures().join("does-not-exist.enc"));
    let out = run(&[&missing], Some(b"x\n"));
    assert_eq!(out.status, 1);
    assert!(out.stdout.is_empty());
    assert!(out.stderr.contains("does-not-exist.enc"), "{}", out.stderr);
}

// @spec ENC-TOOL-002
#[test]
fn truncated_and_unsupported_version_files_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let truncated = dir.path().join("short.enc");
    std::fs::write(&truncated, b"abc").unwrap();
    let out = run(&[&arg(truncated)], Some(b"x\n"));
    assert_eq!(out.status, 1);
    assert!(
        out.stderr.to_lowercase().contains("truncated"),
        "{}",
        out.stderr
    );

    let mut bad = std::fs::read(fixtures().join("v2.enc")).unwrap();
    bad[..4].copy_from_slice(&999u32.to_be_bytes());
    let unsupported = dir.path().join("v999.enc");
    std::fs::write(&unsupported, bad).unwrap();
    let out = run(&[&arg(unsupported)], Some(b"x\n"));
    assert_eq!(out.status, 1);
    assert!(out.stderr.contains("999"), "{}", out.stderr);
    assert!(out.stdout.is_empty());
}

// @spec ENC-TOOL-005
#[test]
fn version_and_help_flags() {
    let out = run(&["--version"], None);
    assert_eq!(out.status, 0);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("backvault-decrypt {}\n", env!("CARGO_PKG_VERSION"))
    );
    let out = run(&["--help"], None);
    assert_eq!(out.status, 0);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("backvault-decrypt <file.enc>"), "{text}");
    assert!(text.contains("--version"));
}

// @spec ENC-TOOL-006
#[test]
fn usage_errors_exit_2_with_usage_on_stderr() {
    for args in [
        vec![],
        vec!["a.enc", "b.enc"],
        vec!["--bogus"],
        vec!["--bogus", "a.enc"],
    ] {
        let out = run(&args, None);
        assert_eq!(out.status, 2, "args {args:?}: {}", out.stderr);
        assert!(out.stdout.is_empty());
        assert!(
            out.stderr.contains("backvault-decrypt <file.enc>"),
            "{}",
            out.stderr
        );
    }
}

// @spec ENC-TOOL-003
#[cfg(target_os = "macos")]
#[test]
fn binary_links_only_system_libraries() {
    let out = Command::new("otool")
        .args(["-L", BIN])
        .output()
        .expect("otool");
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        assert!(
            line.starts_with("/usr/lib/") || line.starts_with("/System/"),
            "non-system dependency: {line}"
        );
    }
}

// @spec ENC-TOOL-003
#[cfg(all(target_os = "linux", target_env = "musl"))]
#[test]
fn binary_is_statically_linked() {
    let out = Command::new("ldd").arg(BIN).output().expect("ldd");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .to_lowercase();
    assert!(
        text.contains("not a dynamic executable") || text.contains("statically linked"),
        "{text}"
    );
}

#[test]
fn every_spec_cited_here_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let specs = std::fs::read_to_string(
        root.join("docs/intent/backup-encryption/backup-encryption-specs.md"),
    )
    .unwrap();
    for file in [
        "crates/backvault-decrypt/tests/cli.rs",
        "crates/backvault-decrypt/src/main.rs",
    ] {
        let text = std::fs::read_to_string(root.join(file)).unwrap();
        for line in text
            .lines()
            .filter(|l| l.trim_start().starts_with("// @spec "))
        {
            for id in line
                .split("@spec ")
                .nth(1)
                .unwrap()
                .split(',')
                .map(str::trim)
            {
                assert!(
                    specs.contains(&format!("**{id}**")),
                    "{file}: undefined spec {id}"
                );
            }
        }
    }
}
