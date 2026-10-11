//! File permission checks for administrator-controlled and secret files.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Current effective uid.
pub fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn owner_ok(uid: u32) -> bool {
    uid == current_uid() || uid == 0
}

/// Administrator-managed file (authorized_keys, known_hosts, config): must exist, be a regular
/// file owned by the service user or root, and not be writable by group or others.
pub fn check_admin_file(path: &Path) -> Result<(), String> {
    let md = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !md.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if !owner_ok(md.uid()) {
        return Err(format!(
            "{} must be owned by the service user or root",
            path.display()
        ));
    }
    if md.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is writable by group/others (mode {:o}); run: chmod go-w {}",
            path.display(),
            md.mode() & 0o777,
            path.display()
        ));
    }
    Ok(())
}

/// Secret file (TLS key, SSH identity): must not be readable or writable by group or others.
pub fn check_private_file(path: &Path) -> Result<(), String> {
    let md = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !md.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if !owner_ok(md.uid()) {
        return Err(format!(
            "{} must be owned by the service user or root",
            path.display()
        ));
    }
    if md.mode() & 0o077 != 0 {
        return Err(format!(
            "{} is accessible by group/others (mode {:o}); run: chmod 600 {}",
            path.display(),
            md.mode() & 0o777,
            path.display()
        ));
    }
    Ok(())
}

/// Create a directory (and parents) and restrict it to the owner.
pub fn ensure_private_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

/// Write a new file with the given mode, failing if it exists unless `overwrite`.
pub fn write_new_file(
    path: &Path,
    contents: &[u8],
    mode: u32,
    overwrite: bool,
) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).mode(mode);
    if overwrite {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut f = opts.open(path)?;
    f.write_all(contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_file_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        write_new_file(&p, b"x", 0o644, false).unwrap();
        assert!(check_admin_file(&p).is_ok());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(check_admin_file(&p).unwrap_err().contains("writable"));
        assert!(check_admin_file(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn private_file_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        write_new_file(&p, b"x", 0o600, false).unwrap();
        assert!(check_private_file(&p).is_ok());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(check_private_file(&p).is_err());
        assert!(write_new_file(&p, b"y", 0o600, false).is_err());
    }
}
