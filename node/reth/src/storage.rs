//! The filesystem operations the policy archive uses, behind one seam. Durability
//! has exactly two sources: `write_synced` (file data) and `sync_dir` (directory
//! entries). Tests substitute a model that counts both and simulates a crash.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub trait Storage: Send + Sync + fmt::Debug {
    /// Create a 0700 directory if missing (and make its entry durable), then
    /// require that it is a directory nobody else can read.
    fn ensure_private_dir(&self, path: &Path) -> io::Result<()>;
    fn list(&self, dir: &Path) -> io::Result<Vec<String>>;
    /// `None` when absent. A non-regular, empty or larger-than-`limit` file is an error.
    fn read(&self, path: &Path, limit: usize) -> io::Result<Option<Vec<u8>>>;
    /// Create a new 0600 file with these bytes and `sync_all` it.
    fn write_synced(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;
    /// Hard-link `from` to `to`; `false` when `to` already exists.
    fn link(&self, from: &Path, to: &Path) -> io::Result<bool>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    /// `false` when absent.
    fn remove(&self, path: &Path) -> io::Result<bool>;
    /// `sync_all` on the directory, making its entries durable.
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;
}

/// The real filesystem. On macOS `sync_all` is `F_FULLFSYNC`.
#[derive(Debug, Default)]
pub struct DiskStorage;

impl Storage for DiskStorage {
    fn ensure_private_dir(&self, path: &Path) -> io::Result<()> {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "not a private directory",
            ));
        }
        // Always, not only on creation: an earlier start may have crashed
        // between mkdir and this sync, leaving the entry not yet durable.
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        File::open(parent)?.sync_all()
    }

    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(dir)? {
            let name = entry?.file_name();
            names.push(
                name.into_string()
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
            );
        }
        Ok(names)
    }

    fn read(&self, path: &Path, limit: usize) -> io::Result<Option<Vec<u8>>> {
        let meta = match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            other => other?,
        };
        if !meta.is_file() || meta.len() == 0 || meta.len() > limit as u64 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bytes = Vec::new();
        File::open(path)?
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > limit {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Some(bytes))
    }

    fn write_synced(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn link(&self, from: &Path, to: &Path) -> io::Result<bool> {
        match fs::hard_link(from, to) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn remove(&self, path: &Path) -> io::Result<bool> {
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        File::open(dir)?.sync_all()
    }
}
