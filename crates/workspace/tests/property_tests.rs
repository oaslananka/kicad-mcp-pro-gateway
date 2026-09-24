use companion_workspace::{WorkspaceAuthorization, WorkspaceBoundary};
use proptest::prelude::*;
use std::path::Path;

proptest! {
    #[test]
    fn arbitrary_path_strings_never_panic_or_escape(random_path in ".*") {
        let temp_dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp_dir.path()).unwrap();
        let simplified_root = dunce::simplified(&root).to_path_buf();

        let ws = WorkspaceAuthorization::new("Test Workspace".into(), &simplified_root).unwrap();

        // Must evaluate safely without panicking
        if let Ok(resolved) = ws.resolve_within(Path::new(&random_path)) {
            let simplified_resolved = dunce::simplified(&resolved).to_path_buf();
            // INVARIANT: Any successful resolution MUST be contained within the canonical root
            assert!(
                simplified_resolved.starts_with(&simplified_root),
                "Resolved path {:?} must start with workspace root {:?}",
                simplified_resolved,
                simplified_root
            );
        }
    }
}
