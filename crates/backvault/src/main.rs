//! BackVault service entry point (scheduler-retention segment): PID 1 of the container.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use backvault::cycle::{self, DEFAULT_ALLOWED_BASE, VaultExporter};
use backvault::env::{Env, SystemEnv};
use backvault::logging;
use backvault::scheduler::{CycleRunner, Supervisor, SystemClock, ThreadSleeper, version_line};
use backvault::vault::{Credentials, VaultError, export_vault_json_default};

struct RealVault;

impl VaultExporter for RealVault {
    fn export(
        &mut self,
        creds: &Credentials<'_>,
    ) -> Result<zeroize::Zeroizing<String>, VaultError> {
        export_vault_json_default(creds)
    }
}

struct RealRunner<'a> {
    env: &'a dyn Env,
    allowed_base: &'a Path,
}

impl CycleRunner for RealRunner<'_> {
    fn run_cycle(&mut self) -> Result<PathBuf, cycle::CycleError> {
        cycle::run_from_env(self.env, self.allowed_base, &mut RealVault, &SystemClock)
    }
}

// @spec SCHED-LOG-001, SCHED-LOOP-008, SCHED-SIGNAL-001, SCHED-SIGNAL-002, SCHED-SIGNAL-003
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 1 && args[0] == "--version" {
        println!("{}", version_line());
        return ExitCode::SUCCESS;
    }

    let env = SystemEnv;
    let log_file = env
        .get("LOG_FILE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    logging::install(log_file.as_deref());

    let shutdown = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        if let Err(e) = signal_hook::flag::register(signal, Arc::clone(&shutdown)) {
            log::error!("could not register signal handler for {signal}: {e}");
            return ExitCode::from(1);
        }
    }

    let allowed_base = Path::new(DEFAULT_ALLOWED_BASE);
    let mut runner = RealRunner {
        env: &env,
        allowed_base,
    };
    let mut sleeper = ThreadSleeper;
    let code = Supervisor {
        env: &env,
        allowed_base: allowed_base.to_path_buf(),
        runner: &mut runner,
        clock: &SystemClock,
        sleeper: &mut sleeper,
        shutdown,
    }
    .run();
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
