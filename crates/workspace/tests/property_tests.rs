//! Property/fuzz coverage for the workspace path boundary (T3 in the threat
//! model).
//!
//! Two invariants carry the whole boundary: a resolved path is always inside
//! the authorized root, and a path is only ever rejected — never partially
//! applied — when it escapes. Both are checked here against arbitrary path
//! text, against the historical escape attempts, and against lexical
//! normalization.
//!
//! See `docs/development/testing.md` for the bounded CI lane and the longer
//! local fuzz lane.

use std::path::{Component, Path, PathBuf};

use companion_workspace::{WorkspaceAuthorization, WorkspaceBoundary};
use proptest::prelude::*;

/// Path text that has actually been tried against this boundary: traversal,
/// sibling-directory collisions, foreign absolute syntax, mixed separators,
/// alternate data and home expansion, and Unicode look-alikes.
fn historical_path_attempts() -> Vec<String> {
    [
        "",
        ".",
        "..",
        "../",
        "../../../../../../etc/passwd",
        "a/../../b",
        "./a/./b/../c",
        "a//b",
        "a/",
        "/",
        "//",
        "///etc/passwd",
        "file.kicad_pro",
        "sub/dir/file.kicad_sch",
        // Sibling-directory collision with the root name.
        "../project-evil",
        "../project-evil/secret",
        "../project",
        "../project-evilish",
        // Foreign absolute syntax.
        "C:\\Windows\\System32",
        "C:/Windows/System32",
        "c:\\project-evil",
        "\\\\?\\C:\\Windows",
        "\\\\server\\share\\secret",
        // Mixed and doubled separators.
        "sub\\dir/file.kicad_sch",
        "sub/dir\\file.kicad_sch",
        "sub\\\\dir",
        // Home and variable expansion, which must never be expanded here.
        "~/secrets",
        "~root/secrets",
        "$HOME/secrets",
        "${HOME}/secrets",
        "%USERPROFILE%/secrets",
        // NUL and other control characters.
        "a\0b",
        "\0",
        "a\nb",
        // Unicode, including an NFC/NFD look-alike pair.
        "caf\u{e9}",
        "cafe\u{301}",
        "项目/secret",
        "\u{202e}gpj.exe",
    ]
    .iter()
    .map(|attempt| (*attempt).to_string())
    .collect()
}

/// Segments a relative request is built from, including the ones that make
/// lexical normalization do real work.
fn relative_segments() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(
        prop_oneof![
            prop::sample::select(vec!["a", "b", "sub", "café", "a b", "-"])
                .prop_map(str::to_string),
            prop::sample::select(vec!["", ".", ".."]).prop_map(str::to_string),
        ],
        0..8,
    )
}

/// The same purely lexical `.`/`..` collapse the boundary performs, so a
/// normalized request can be compared against what it resolved to.
fn lexically_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn authorized_root() -> (tempfile::TempDir, WorkspaceAuthorization) {
    let parent = tempfile::tempdir().expect("temp dir");
    let root = parent.path().join("project");
    std::fs::create_dir_all(&root).expect("workspace root");
    let authorization = WorkspaceAuthorization::new("Test Workspace".into(), &root)
        .expect("existing absolute root is authorized");
    (parent, authorization)
}

proptest! {
    #[test]
    fn arbitrary_path_strings_never_panic_or_escape(
        random_path in prop_oneof![
            prop::sample::select(historical_path_attempts()),
            ".*",
        ],
    ) {
        let (_parent, workspace) = authorized_root();

        if let Ok(resolved) = workspace.resolve_within(Path::new(&random_path)) {
            // INVARIANT: any successful resolution is contained within the
            // canonical root, compared component-wise and never by string
            // prefix.
            assert!(
                resolved.starts_with(&workspace.canonical_root),
                "Resolved path {resolved:?} must start with workspace root {:?}",
                workspace.canonical_root
            );
        }
    }

    #[test]
    fn a_request_resolves_to_its_lexically_normalized_form_or_is_refused(
        segments in relative_segments(),
    ) {
        let (_parent, workspace) = authorized_root();
        // Built component by component: an empty leading segment joined with
        // "/" would silently turn a relative request into an absolute one.
        let requested = segments.iter().fold(PathBuf::new(), |mut path, segment| {
            path.push(segment);
            path
        });
        let full = workspace.canonical_root.join(&requested);
        let normalized = lexically_normalize(&full);
        let contained = normalized.starts_with(&workspace.canonical_root);

        match workspace.resolve_within(&full) {
            // A request is accepted exactly when its normalized form is inside
            // the root, and it resolves to that form and nothing else.
            Ok(resolved) => {
                assert!(
                    contained,
                    "{full:?} resolved to {resolved:?} but normalizes to {normalized:?}, outside the workspace"
                );
                assert_eq!(
                    resolved, normalized,
                    "{full:?} did not normalize the way the boundary documents"
                );
            }
            Err(_) => assert!(
                !contained,
                "{full:?} was refused but normalizes to {normalized:?}, inside the workspace"
            ),
        }
    }

    #[test]
    fn a_sibling_directory_whose_name_shares_the_root_prefix_is_never_inside(
        suffix in "[a-z0-9_-]{1,8}",
    ) {
        let (parent, workspace) = authorized_root();
        let sibling = parent.path().join(format!("project-{suffix}"));
        std::fs::create_dir_all(&sibling).expect("sibling directory");
        std::fs::write(sibling.join("secret"), b"secret").expect("sibling file");

        // `C:\project` vs `C:\project-evil`: a string-prefix containment check
        // would accept this.
        let requested = workspace
            .canonical_root
            .join("..")
            .join(format!("project-{suffix}"))
            .join("secret");

        assert!(
            workspace.resolve_within(&requested).is_err(),
            "{requested:?} is outside the workspace but resolved"
        );
    }
}

// A symlink inside the workspace is a legitimate alias, so it has to resolve;
// one that points outside is an escape, so it has to be refused. The
// deterministic cases live in `tests/boundary.rs`; this exercises arbitrary
// link names and nesting. Symlink creation needs privileges on Windows, so the
// property is Unix-only.
#[cfg(unix)]
proptest! {
    #[test]
    fn a_symlink_inside_the_workspace_never_resolves_outside_it(
        name in "[a-z0-9_]{1,12}",
        depth in 1usize..4,
        escapes in any::<bool>(),
    ) {
        use std::os::unix::fs::symlink;

        let (parent, workspace) = authorized_root();
        let outside = parent.path().join("outside");
        std::fs::create_dir_all(&outside).expect("outside directory");

        let mut link_parent = workspace.canonical_root.clone();
        for level in 0..depth {
            link_parent = link_parent.join(format!("{name}{level}"));
        }
        std::fs::create_dir_all(&link_parent).expect("link parent");

        let link = link_parent.join(format!("{name}-link"));
        let target = if escapes { &outside } else { &link_parent };
        symlink(target, &link).expect("symlink");

        let requested = link.join("secret");
        match workspace.resolve_within(&requested) {
            Ok(resolved) => {
                prop_assert!(
                    !escapes,
                    "{requested:?} resolved to {resolved:?} through a symlink that leaves the workspace"
                );
                prop_assert!(resolved.starts_with(&workspace.canonical_root));
            }
            Err(_) => prop_assert!(escapes, "{requested:?} was refused but links inside the workspace"),
        }
    }
}
