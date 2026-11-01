//! Environment access as a trait so configuration is testable without mutating the process environment.

use std::collections::HashMap;
use std::ffi::OsString;

/// Read-only view of environment variables, as raw OS strings (never UTF-8 validated).
pub trait Env {
    fn get(&self, name: &str) -> Option<OsString>;
}

/// The process environment.
pub struct SystemEnv;

impl Env for SystemEnv {
    fn get(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

/// An in-memory environment for tests.
#[derive(Default, Clone)]
pub struct MapEnv(pub HashMap<String, OsString>);

impl MapEnv {
    pub fn set(mut self, name: &str, value: impl Into<OsString>) -> Self {
        self.0.insert(name.to_string(), value.into());
        self
    }
    pub fn unset(mut self, name: &str) -> Self {
        self.0.remove(name);
        self
    }
}

impl Env for MapEnv {
    fn get(&self, name: &str) -> Option<OsString> {
        self.0.get(name).cloned()
    }
}
