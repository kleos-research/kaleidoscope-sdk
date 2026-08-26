use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest as _, Sha256};

use crate::error::{ManagerError, Result};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub bytes: Option<Vec<u8>>,
    pub sha256: String,
    pub unix_mode: Option<u32>,
}

impl Snapshot {
    #[must_use]
    pub fn absent() -> Self {
        Self {
            bytes: None,
            sha256: digest_bytes(b"<absent>"),
            unix_mode: None,
        }
    }
}

pub fn validate_absolute_path(path: &Path, target: &'static str) -> Result<()> {
    if !path.is_absolute() {
        return Err(ManagerError::UnsafePath {
            target,
            reason: "path is not absolute",
        });
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ManagerError::UnsafePath {
            target,
            reason: "path contains traversal",
        });
    }
    if path.to_str().is_none() {
        return Err(ManagerError::UnsafePath {
            target,
            reason: "path is not UTF-8",
        });
    }
    Ok(())
}

pub fn read_snapshot(path: &Path, maximum: u64, target: &'static str) -> Result<Snapshot> {
    validate_absolute_path(path, target)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Snapshot::absent());
        }
        Err(error) => return Err(ManagerError::io("inspect file", error)),
    };
    if metadata.file_type().is_symlink() {
        return Err(ManagerError::UnsafePath {
            target,
            reason: "selected file is a symlink",
        });
    }
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(ManagerError::UnsafePath {
            target,
            reason: "not a bounded regular file",
        });
    }
    let bytes = fs::read(path).map_err(|error| ManagerError::io("read file", error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(ManagerError::UnsafePath {
            target,
            reason: "file grew beyond its size limit",
        });
    }
    Ok(Snapshot {
        sha256: digest_bytes(&bytes),
        bytes: Some(bytes),
        unix_mode: snapshot_mode(&metadata),
    })
}

pub fn assert_unchanged(
    path: &Path,
    expected: &Snapshot,
    maximum: u64,
    target: &'static str,
) -> Result<()> {
    if read_snapshot(path, maximum, target)? == *expected {
        Ok(())
    } else {
        Err(ManagerError::ConcurrentEdit)
    }
}

#[must_use]
pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn sibling_path(path: &Path, suffix: &str) -> Result<PathBuf> {
    let name = path.file_name().ok_or(ManagerError::UnsafePath {
        target: "configuration file",
        reason: "path has no file name",
    })?;
    let mut owned = OsString::from(name);
    owned.push(suffix);
    Ok(path.with_file_name(owned))
}

pub fn ensure_parent_directory(path: &Path) -> Result<()> {
    ensure_parent_directory_for(path, "configuration file", "configuration directory")
}

pub fn ensure_vault_parent_directory(path: &Path) -> Result<()> {
    ensure_parent_directory_for(path, "vault root", "vault root parent")
}

fn ensure_parent_directory_for(
    path: &Path,
    path_target: &'static str,
    ancestor_target: &'static str,
) -> Result<()> {
    validate_absolute_path(path, path_target)?;
    let parent = path.parent().ok_or(ManagerError::UnsafePath {
        target: path_target,
        reason: "path has no parent",
    })?;
    let mut cursor = PathBuf::new();
    for component in parent.components() {
        cursor.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ManagerError::UnsafePath {
                    target: ancestor_target,
                    reason: "an ancestor is a symlink",
                });
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(ManagerError::UnsafePath {
                    target: ancestor_target,
                    reason: "an ancestor is not a directory",
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::create_dir(&cursor) {
                    Ok(()) => set_directory_mode(&cursor)?,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let metadata = fs::symlink_metadata(&cursor)
                            .map_err(|error| ManagerError::io("inspect directory", error))?;
                        if metadata.file_type().is_symlink() || !metadata.is_dir() {
                            return Err(ManagerError::UnsafePath {
                                target: ancestor_target,
                                reason: "raced with an unsafe entry",
                            });
                        }
                    }
                    Err(error) => return Err(ManagerError::io("create directory", error)),
                }
            }
            Err(error) => return Err(ManagerError::io("inspect directory", error)),
        }
    }
    Ok(())
}

pub struct FileLock {
    path: PathBuf,
}

impl FileLock {
    pub fn acquire(target: &Path) -> Result<Self> {
        ensure_parent_directory(target)?;
        let path = sibling_path(target, ".kaleidoscope-lock")?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(ManagerError::HostConflict(
                    "another manager operation owns the target lock".to_owned(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ManagerError::io("inspect lock", error)),
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|error| ManagerError::io("create lock", error))?;
        file.write_all(format!("{}\n", std::process::id()).as_bytes())
            .map_err(|error| ManagerError::io("write lock", error))?;
        file.sync_all()
            .map_err(|error| ManagerError::io("sync lock", error))?;
        Ok(Self { path })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Remove a directory the manager created and has just emptied.
///
/// Called ONLY on the branch that deletes a file the manager itself created
/// (`updated.is_none()`), so a directory that held anything of the user's is
/// never a candidate -- and `read_dir` is checked anyway, so a directory that
/// still holds anything at all is left alone.
///
/// The list carries every directory any planner can create. It used to live in
/// `instructions.rs` and name five; `host.rs` had no equivalent at all, so a
/// teardown that removed `.codex/config.toml` left an empty `.codex/` behind in
/// the user's project. Widening it here rather than copying it there is what
/// keeps the three planners from drifting apart again.
///
/// CALLERS MUST DROP THEIR `FileLock` FIRST. The lock lives beside the target
/// as `<file>.kaleidoscope-lock` and is only unlinked on drop, so pruning while
/// it is held finds a directory that is never empty.
pub fn prune_empty_managed_directories(target: &Path) {
    const MANAGED_DIRECTORY_NAMES: [&str; 7] = [
        "use-kaleidoscope",
        "skills",
        ".agents",
        ".claude",
        "rules",
        ".codex",
        ".cursor",
    ];
    let mut cursor = target.parent().map(Path::to_path_buf);
    while let Some(directory) = cursor {
        let name = directory
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !MANAGED_DIRECTORY_NAMES.contains(&name.as_str()) {
            return;
        }
        if fs::read_dir(&directory).is_ok_and(|mut entries| entries.next().is_some()) {
            return;
        }
        if fs::remove_dir(&directory).is_err() {
            return;
        }
        cursor = directory.parent().map(Path::to_path_buf);
    }
}

pub fn write_bounded_backup(target: &Path, original: &Snapshot) -> Result<Option<PathBuf>> {
    let Some(bytes) = original.bytes.as_deref() else {
        return Ok(None);
    };
    let backup = sibling_path(target, ".kaleidoscope-backup")?;
    atomic_write(&backup, bytes, Some(0o600))?;
    Ok(Some(backup))
}

pub fn atomic_write(path: &Path, bytes: &[u8], unix_mode: Option<u32>) -> Result<()> {
    ensure_parent_directory(path)?;
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(ManagerError::UnsafePath {
            target: "configuration file",
            reason: "selected file is a symlink",
        });
    }
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = sibling_path(path, &format!(".tmp-{}-{sequence}", std::process::id()))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(unix_mode.unwrap_or(0o600));
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| ManagerError::io("create temporary file", error))?;
    let result = (|| {
        #[cfg(unix)]
        if let Some(mode) = unix_mode {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(fs::Permissions::from_mode(mode))
                .map_err(|error| ManagerError::io("set file permissions", error))?;
        }
        file.write_all(bytes)
            .map_err(|error| ManagerError::io("write temporary file", error))?;
        file.sync_all()
            .map_err(|error| ManagerError::io("sync temporary file", error))?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| ManagerError::io("publish file", error))?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn atomic_remove(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(ManagerError::UnsafePath {
                target: "configuration file",
                reason: "removal target is not a regular file",
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(ManagerError::io("inspect removal target", error)),
    }
    fs::remove_file(path).map_err(|error| ManagerError::io("remove file", error))?;
    sync_parent(path)
}

pub fn restore_snapshot(path: &Path, snapshot: &Snapshot) -> Result<()> {
    match snapshot.bytes.as_deref() {
        Some(bytes) => atomic_write(path, bytes, snapshot.unix_mode),
        None => atomic_remove(path),
    }
}

#[allow(clippy::unnecessary_wraps)]
fn snapshot_mode(metadata: &fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        Some(metadata.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

fn set_directory_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| ManagerError::io("set directory permissions", error))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let parent = path.parent().ok_or(ManagerError::UnsafePath {
            target: "configuration file",
            reason: "path has no parent",
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| ManagerError::io("sync directory", error))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
