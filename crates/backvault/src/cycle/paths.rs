//! Filesystem containment: the `/app` check shared with scheduler-retention, and per-file rules.

use std::path::{Component, Path, PathBuf};

use super::CycleError;

/// Canonicalise the longest existing prefix of `path`, then append the remainder lexically normalised.
fn resolve_lenient(path: &Path) -> PathBuf {
    let components: Vec<Component<'_>> = path.components().collect();
    for n in (1..=components.len()).rev() {
        let prefix: PathBuf = components[..n].iter().collect();
        let Ok(mut out) = prefix.canonicalize() else {
            continue;
        };
        for component in &components[n..] {
            match component {
                Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(name) => out.push(name),
            }
        }
        return out;
    }
    path.to_path_buf()
}

/// Canonicalise `dir` and require it to sit under `allowed_base`. Shared with scheduler-retention.
// @spec CYCLE-CONFIG-003
pub fn confine_to_app(dir: &Path, allowed_base: &Path) -> Result<PathBuf, CycleError> {
    let resolved = resolve_lenient(dir);
    let base = resolve_lenient(allowed_base);
    if resolved.starts_with(&base) {
        Ok(resolved)
    } else {
        Err(CycleError::DirectoryOutsideBase {
            dir: dir.display().to_string(),
            base: allowed_base.display().to_string(),
        })
    }
}

/// Require the final file to sit inside `allowed_dir` with a safe name ending in `.enc`.
// @spec CYCLE-FILE-002
pub fn validate_backup_path(file: &Path, allowed_dir: &Path) -> Result<PathBuf, CycleError> {
    let resolved = resolve_lenient(file);
    let allowed = resolve_lenient(allowed_dir);
    if !resolved.starts_with(&allowed) || resolved == allowed {
        return Err(CycleError::InvalidPath(format!(
            "must be within {}",
            allowed_dir.display()
        )));
    }
    let name = resolved
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| CycleError::InvalidPath("filename is not valid UTF-8".to_string()))?;
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(CycleError::InvalidPath(
            "filename may contain only alphanumeric characters, dots, dashes, and underscores"
                .to_string(),
        ));
    }
    if !name.ends_with(".enc") {
        return Err(CycleError::InvalidPath(
            "filename must end with .enc".to_string(),
        ));
    }
    if resolved
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(CycleError::InvalidPath(
            "path must not contain '..'".to_string(),
        ));
    }
    Ok(resolved)
}
