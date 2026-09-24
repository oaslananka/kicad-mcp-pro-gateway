use std::path::Path;

use companion_workspace::{WorkspaceAuthorization, WorkspaceBoundary, WorkspaceError};

#[test]
fn path_inside_root_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("sub")).unwrap();
    let ws = WorkspaceAuthorization::new("proj".into(), dir.path()).unwrap();
    let resolved = ws.resolve_within(&dir.path().join("sub/file.kicad_pro"));
    assert!(resolved.is_ok(), "{resolved:?}");
}

#[test]
fn sibling_directory_with_prefix_collision_is_rejected() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("project");
    let evil = parent.path().join("project-evil");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&evil).unwrap();
    let ws = WorkspaceAuthorization::new("proj".into(), &root).unwrap();
    let resolved = ws.resolve_within(&evil.join("file"));
    assert!(
        matches!(resolved, Err(WorkspaceError::PathEscapesRoot)),
        "{resolved:?}"
    );
}

#[cfg(unix)]
#[test]
fn symlink_ancestor_outside_workspace_does_not_change_escape_classification() {
    let parent = tempfile::tempdir().unwrap();
    let real_parent = parent.path().join("real-parent");
    std::fs::create_dir_all(&real_parent).unwrap();
    let alias_parent = parent.path().join("alias-parent");
    std::os::unix::fs::symlink(&real_parent, &alias_parent).unwrap();

    let root = alias_parent.join("project");
    let evil = alias_parent.join("project-evil");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&evil).unwrap();

    let ws = WorkspaceAuthorization::new("proj".into(), &root).unwrap();
    let resolved = ws.resolve_within(&evil.join("file"));
    assert!(
        matches!(resolved, Err(WorkspaceError::PathEscapesRoot)),
        "{resolved:?}"
    );
}

#[test]
fn traversal_sequence_is_rejected() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("project");
    std::fs::create_dir_all(&root).unwrap();
    let ws = WorkspaceAuthorization::new("proj".into(), &root).unwrap();
    let escape = root.join("..").join("project-evil").join("file");
    let resolved = ws.resolve_within(&escape);
    assert!(
        matches!(resolved, Err(WorkspaceError::PathEscapesRoot)),
        "{resolved:?}"
    );
}

#[test]
fn deep_traversal_toward_system_root_is_rejected() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("project");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    let ws = WorkspaceAuthorization::new("proj".into(), &root).unwrap();
    let escape = root
        .join("sub")
        .join("..")
        .join("..")
        .join("..")
        .join("evil");
    let resolved = ws.resolve_within(&escape);
    assert!(
        matches!(resolved, Err(WorkspaceError::PathEscapesRoot)),
        "{resolved:?}"
    );
}

#[cfg(unix)]
#[test]
fn symlink_escaping_root_is_rejected() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("project");
    let outside = parent.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
    let ws = WorkspaceAuthorization::new("proj".into(), &root).unwrap();
    let resolved = ws.resolve_within(&root.join("link").join("file"));
    assert!(
        matches!(resolved, Err(WorkspaceError::SymlinkEscapesRoot)),
        "{resolved:?}"
    );
}

#[cfg(windows)]
#[test]
fn symlink_escaping_root_is_rejected() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("project");
    let outside = parent.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();

    // Creating a Windows symlink requires SeCreateSymbolicLinkPrivilege,
    // which is not always available (e.g. some CI runners without Developer
    // Mode). Skip gracefully if we cannot create one, rather than failing
    // the whole suite over an environment limitation unrelated to the
    // boundary logic itself.
    if std::os::windows::fs::symlink_dir(&outside, root.join("link")).is_err() {
        eprintln!("skipping symlink_escaping_root_is_rejected: cannot create symlinks in this environment");
        return;
    }

    let ws = WorkspaceAuthorization::new("proj".into(), &root).unwrap();
    let resolved = ws.resolve_within(&root.join("link").join("file"));
    assert!(
        matches!(resolved, Err(WorkspaceError::SymlinkEscapesRoot)),
        "{resolved:?}"
    );
}

#[test]
fn mixed_separators_still_resolve_within_root() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("sub")).unwrap();
    let ws = WorkspaceAuthorization::new("proj".into(), dir.path()).unwrap();
    let mixed = format!("{}/sub\\file.kicad_pro", dir.path().display());
    let resolved = ws.resolve_within(Path::new(&mixed));
    assert!(resolved.is_ok(), "{resolved:?}");
}

#[test]
fn relative_root_is_rejected_at_construction() {
    let result = WorkspaceAuthorization::new("proj".into(), Path::new("relative/dir"));
    assert!(matches!(result, Err(WorkspaceError::RelativeRoot)));
}

#[test]
fn nonexistent_root_is_rejected_at_construction() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("does-not-exist");
    let result = WorkspaceAuthorization::new("proj".into(), &missing);
    assert!(matches!(result, Err(WorkspaceError::RootNotFound(_))));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn unicode_segments_are_compared_byte_exact_not_fuzzy_matched() {
    let dir = tempfile::tempdir().unwrap();
    // "cafe" with a combining acute accent (NFD) vs precomposed "café" (NFC)
    // are visually identical but byte-different. We create only the NFC
    // directory and confirm the NFD-styled request does NOT get silently
    // matched to it, and does NOT escape the root either (since it simply
    // doesn't exist, it is treated as a to-be-created path under root).
    let nfc_dir = dir.path().join("caf\u{00e9}");
    std::fs::create_dir_all(&nfc_dir).unwrap();
    let nfd_request = dir.path().join("cafe\u{0301}").join("file.kicad_pro");

    let ws = WorkspaceAuthorization::new("proj".into(), dir.path()).unwrap();
    let resolved = ws.resolve_within(&nfd_request);

    // It resolves (it's still under the authorized root as a not-yet-existing
    // path), but it must NOT resolve to a path underneath the NFC directory.
    let resolved = resolved.expect("distinct unicode segment under root still resolves");
    assert!(!resolved.starts_with(dunce::canonicalize(&nfc_dir).unwrap()));
}
