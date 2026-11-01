//! `backvault-decrypt <file.enc>`: the standalone restore tool (backup-encryption segment).
//!
//! Password from the terminal (no echo) or, when stdin is not a terminal, the first line of
//! stdin. Exact plaintext bytes to stdout; everything else to stderr. Exit 0 success, 1 failure,
//! 2 usage.

use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::process::ExitCode;

use zeroize::Zeroizing;

const USAGE: &str = "usage: backvault-decrypt <file.enc>\n       backvault-decrypt --version | --help\n\n\
Decrypts a BackVault backup. The password is read from the terminal, or from the first line of\n\
stdin when stdin is not a terminal. The plaintext is written to stdout.";

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Decrypt(String),
    Version,
    Help,
    Usage,
}

/// Parse `args` (without the program name).
// @spec ENC-TOOL-005, ENC-TOOL-006
fn parse_args(args: &[String]) -> Invocation {
    match args {
        [one] if one == "--version" => Invocation::Version,
        [one] if one == "--help" => Invocation::Help,
        [one] if !one.starts_with('-') => Invocation::Decrypt(one.clone()),
        _ => Invocation::Usage,
    }
}

/// Read the first line of a non-terminal stdin as raw password bytes, without `\n` or `\r\n`.
// @spec ENC-TOOL-004, ENC-TOOL-007
fn read_piped_password(reader: &mut dyn Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(Vec::new());
    io::BufReader::new(reader).read_until(b'\n', &mut line)?;
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    }
    Ok(line)
}

/// Write the plaintext in full; any failure is reported, never swallowed.
// @spec ENC-TOOL-001, ENC-TOOL-002
fn write_plaintext(out: &mut dyn Write, plaintext: &[u8]) -> io::Result<()> {
    out.write_all(plaintext)?;
    out.flush()
}

// @spec ENC-TOOL-001, ENC-TOOL-004, ENC-TOOL-007
fn read_password() -> io::Result<Zeroizing<Vec<u8>>> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Enter backup password: ");
        io::stderr().flush()?;
        let typed = Zeroizing::new(rpassword::read_password()?);
        Ok(Zeroizing::new(typed.as_bytes().to_vec()))
    } else {
        read_piped_password(&mut stdin.lock())
    }
}

fn describe_version(file: &[u8]) {
    if file.len() < 4 {
        return;
    }
    match u32::from_be_bytes([file[0], file[1], file[2], file[3]]) {
        1 => eprintln!(
            "Decrypting version 1 file (PBKDF2-HMAC-SHA256, {} iterations)",
            backvault_format::PBKDF2_ITERATIONS
        ),
        2 => eprintln!(
            "Decrypting version 2 file (Argon2id, {} MiB)",
            backvault_format::ARGON2_MEMORY_KIB / 1024
        ),
        _ => {}
    }
}

// @spec ENC-TOOL-002
fn run(path: &str) -> Result<(), String> {
    let file = std::fs::read(path).map_err(|e| format!("cannot read '{path}': {e}"))?;
    let password = read_password().map_err(|e| format!("cannot read the password: {e}"))?;
    describe_version(&file);
    let plaintext = backvault_format::decrypt(&file, &password)
        .map_err(|e| format!("Decryption failed: {e}"))?;
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    write_plaintext(&mut lock, &plaintext)
        .map_err(|e| format!("could not write the plaintext to stdout: {e}"))?;
    eprintln!("Decryption successful.");
    Ok(())
}

// @spec ENC-TOOL-003
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Invocation::Version => {
            println!("backvault-decrypt {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Invocation::Help => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Invocation::Usage => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        Invocation::Decrypt(path) => match run(&path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("{message}");
                ExitCode::from(1)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // @spec ENC-TOOL-004, ENC-TOOL-007
    #[test]
    fn piped_password_strips_line_ending_and_is_zeroizing() {
        fn assert_wiped_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        for (input, expected) in [
            (&b"secret\n"[..], &b"secret"[..]),
            (b"secret\r\n", b"secret"),
            (b"secret", b"secret"),
            (b"\xff\xfe pw\n", b"\xff\xfe pw"),
            (b"two\nlines\n", b"two"),
            (b"\n", b""),
        ] {
            let got = read_piped_password(&mut &input[..]).unwrap();
            assert_wiped_on_drop(&got);
            assert_eq!(got.as_slice(), expected, "{input:?}");
        }
    }

    // @spec ENC-TOOL-002
    #[test]
    fn write_failure_is_reported() {
        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("disk full"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert!(write_plaintext(&mut Full, b"data").is_err());
        let mut sink = Vec::new();
        write_plaintext(&mut sink, b"data").unwrap();
        assert_eq!(sink, b"data");
    }

    // @spec ENC-TOOL-005, ENC-TOOL-006
    #[test]
    fn argument_parsing() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse_args(&a(&["x.enc"])),
            Invocation::Decrypt("x.enc".into())
        );
        assert_eq!(parse_args(&a(&["--version"])), Invocation::Version);
        assert_eq!(parse_args(&a(&["--help"])), Invocation::Help);
        assert_eq!(parse_args(&a(&[])), Invocation::Usage);
        assert_eq!(parse_args(&a(&["a.enc", "b.enc"])), Invocation::Usage);
        assert_eq!(parse_args(&a(&["--bogus"])), Invocation::Usage);
        assert_eq!(parse_args(&a(&["--version", "x.enc"])), Invocation::Usage);
        assert!(USAGE.contains("backvault-decrypt <file.enc>"));
    }
}
