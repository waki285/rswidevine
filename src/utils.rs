//! Miscellaneous helper utilities.
use std::env;
use std::path::{Path, PathBuf};

/// Search PATH for the first matching binary name.
#[must_use]
pub fn get_binary_path(names: &[&str]) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    let paths = env::split_paths(&path_var);

    for dir in paths {
        for name in names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }

            if cfg!(windows) {
                for ext in ["exe", "cmd", "bat"] {
                    let candidate = dir.join(format!("{}.{}", name, ext));
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
            }
        }
    }

    None
}

/// Ensure a file path's parent directory exists.
pub fn ensure_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}
