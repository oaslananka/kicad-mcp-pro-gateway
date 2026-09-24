//! Filesystem primitives for checkpoint snapshots. `exclude` is always the
//! checkpoints storage root itself, so a checkpoint operation never walks
//! into (and thus never recursively snapshots) previously created
//! checkpoints, even when the checkpoints directory happens to live inside
//! the workspace it is snapshotting.

use std::path::{Path, PathBuf};

pub fn copy_dir_recursive(src: &Path, dest: &Path, exclude: &Path) -> std::io::Result<()> {
    let canonical_exclude = canonical_or_original(exclude);
    copy_dir_recursive_inner(src, dest, &canonical_exclude)
}

fn copy_dir_recursive_inner(src: &Path, dest: &Path, exclude: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        if is_excluded(&path, exclude) {
            continue;
        }
        let dest_path = dest.join(entry.file_name());
        if path.is_dir() {
            copy_dir_recursive_inner(&path, &dest_path, exclude)?;
        } else {
            std::fs::copy(&path, &dest_path)?;
        }
    }
    Ok(())
}

pub fn clear_dir_excluding(dir: &Path, exclude: &Path) -> std::io::Result<()> {
    let canonical_exclude = canonical_or_original(exclude);
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if is_excluded(&path, &canonical_exclude) {
            continue;
        }
        if path.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

fn canonical_or_original(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn is_excluded(candidate: &Path, canonical_exclude: &Path) -> bool {
    let canonical_candidate = canonical_or_original(candidate);
    canonical_candidate == canonical_exclude
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn exclusion_matches_a_symlink_alias_of_the_same_directory() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real-checkpoints");
        std::fs::create_dir_all(real.join("nested")).unwrap();
        let alias = temp.path().join("checkpoint-alias");
        symlink(&real, &alias).unwrap();

        let canonical_exclude = canonical_or_original(&alias);
        assert!(is_excluded(&real, &canonical_exclude));
    }
}
