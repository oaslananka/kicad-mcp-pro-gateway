use std::path::{Path, PathBuf};

use companion_policy::{
    NormalizedOperationEffects, OperationEffect, PathArgumentContract, ToolEffectContract,
};
use companion_workspace::{WorkspaceAuthorization, WorkspaceBoundary};
use proptest::prelude::*;
use serde_json::Value;

fn contract() -> ToolEffectContract {
    ToolEffectContract::new(
        ["paths".to_string(), "default_path".to_string()],
        [
            OperationEffect::Read,
            OperationEffect::Write,
            OperationEffect::Create,
            OperationEffect::Delete,
        ],
        [
            PathArgumentContract::new(
                "paths",
                [OperationEffect::Read, OperationEffect::Write],
                false,
                None,
                None,
            )
            .unwrap(),
            PathArgumentContract::new(
                "default_path",
                [OperationEffect::Create],
                false,
                Some("generated/output".to_string()),
                None,
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn paths(effects: &NormalizedOperationEffects, effect: OperationEffect) -> Vec<PathBuf> {
    effects.paths_for(effect).map(Path::to_path_buf).collect()
}

#[test]
fn models_read_write_create_delete_and_default_paths() {
    let root = Path::new("/workspace/project");
    let effects = contract().normalize(&serde_json::Map::new(), root).unwrap();

    for effect in [
        OperationEffect::Read,
        OperationEffect::Write,
        OperationEffect::Create,
        OperationEffect::Delete,
    ] {
        assert!(paths(&effects, effect).contains(&root.to_path_buf()));
    }
    assert!(paths(&effects, OperationEffect::Create).contains(&root.join("generated/output")));
}

#[test]
fn every_mixed_separator_segment_is_normalized() {
    let root = Path::new("/workspace/project");
    let arguments = serde_json::json!({
        "paths": ["child\\one.kicad_sch", "child/two.kicad_sch"]
    });
    let effects = contract()
        .normalize(arguments.as_object().unwrap(), root)
        .unwrap();

    assert!(paths(&effects, OperationEffect::Read).contains(&root.join("child/one.kicad_sch")));
    assert!(paths(&effects, OperationEffect::Read).contains(&root.join("child/two.kicad_sch")));
}

proptest! {
    #[test]
    fn every_value_in_a_multi_path_argument_is_normalized(
        segments in prop::collection::vec("[a-z][a-z0-9_]{0,15}", 1..24),
    ) {
        let root = Path::new("/workspace/project");
        let relative = segments.join("/");
        let arguments = serde_json::json!({ "paths": [relative.clone()] });
        let effects = contract()
            .normalize(arguments.as_object().unwrap(), root)
            .unwrap();

        prop_assert!(paths(&effects, OperationEffect::Read)
            .contains(&root.join(&relative)));
        prop_assert!(paths(&effects, OperationEffect::Write)
            .contains(&root.join(&relative)));
    }

    #[test]
    fn generated_workspace_relative_paths_satisfy_containment(
        segments in prop::collection::vec("[a-z][a-z0-9_]{0,15}", 1..12),
    ) {
        let parent = tempfile::tempdir().unwrap();
        let workspace = WorkspaceAuthorization::new("prop".into(), parent.path()).unwrap();
        let relative = segments.join("/file.kicad_sch");
        let arguments = serde_json::json!({ "paths": [relative] });
        let effects = contract()
            .normalize(arguments.as_object().unwrap(), &workspace.canonical_root)
            .unwrap();

        for path in effects.paths_for(OperationEffect::Read) {
            prop_assert!(workspace.resolve_within(path).is_ok());
        }
    }

    #[test]
    fn any_non_string_member_denies_normalization(
        value in prop::sample::select(vec![
            Value::Bool(true),
            Value::Number(42.into()),
            Value::Null,
            serde_json::json!({ "path": "inside" }),
        ]),
    ) {
        let arguments = serde_json::json!({ "paths": [value] });
        prop_assert!(contract()
            .normalize(arguments.as_object().unwrap(), Path::new("/workspace/project"))
            .is_err());
    }
}
