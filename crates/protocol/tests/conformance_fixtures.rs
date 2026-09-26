use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use companion_protocol::{Envelope, MAX_MESSAGE_BYTES};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct FixtureIndexEntry {
    file: String,
    abuse_case: String,
    description: String,
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/protocol-abuse")
}

fn read_fixture(name: &str) -> String {
    fs::read_to_string(fixture_root().join(name))
        .unwrap_or_else(|error| panic!("failed to read fixture {name}: {error}"))
}

fn index_entries() -> Vec<FixtureIndexEntry> {
    serde_json::from_str(&read_fixture("index.json")).expect("index.json must be valid JSON")
}

#[test]
fn conformance_fixture_index_matches_committed_fixture_set_exactly_once() {
    let entries = index_entries();
    let listed: BTreeSet<_> = entries.iter().map(|entry| entry.file.clone()).collect();

    assert_eq!(
        entries.len(),
        listed.len(),
        "index.json must reference every fixture exactly once"
    );

    let actual: BTreeSet<_> = fs::read_dir(fixture_root())
        .expect("fixture directory must exist")
        .map(|entry| entry.expect("fixture directory entry"))
        .filter_map(|entry| {
            let path = entry.path();
            let is_json = path.extension().and_then(|ext| ext.to_str()) == Some("json");
            let name = path.file_name()?.to_str()?.to_owned();
            (is_json && name != "index.json").then_some(name)
        })
        .collect();

    assert_eq!(
        listed, actual,
        "index.json and the committed fixture set must stay in lockstep"
    );

    for entry in entries {
        assert!(!entry.abuse_case.trim().is_empty());
        assert!(!entry.description.trim().is_empty());
    }
}

#[test]
fn conformance_fixture_wire_shapes_are_stable() {
    let jsonl = BTreeSet::from(["out_of_order.json", "flood.json"]);

    for entry in index_entries() {
        let raw = read_fixture(&entry.file);

        if entry.file == "invalid_envelope.json" {
            assert!(
                serde_json::from_str::<Value>(&raw).is_err(),
                "invalid_envelope.json is intentionally malformed"
            );
            continue;
        }

        if jsonl.contains(entry.file.as_str()) {
            assert!(
                serde_json::from_str::<Value>(&raw).is_err(),
                "{} must remain JSONL rather than a single JSON value",
                entry.file
            );

            let mut count = 0usize;
            for (line_no, line) in raw
                .lines()
                .filter(|line| !line.trim().is_empty())
                .enumerate()
            {
                serde_json::from_str::<Envelope>(line).unwrap_or_else(|error| {
                    panic!(
                        "{} line {} must deserialize as Envelope: {error}",
                        entry.file,
                        line_no + 1
                    )
                });
                count += 1;
            }
            assert!(
                count > 0,
                "{} must contain at least one envelope",
                entry.file
            );
            continue;
        }

        let value: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("{} must be valid JSON: {error}", entry.file));

        if entry.file == "unknown_message_type.json" {
            assert!(
                serde_json::from_value::<Envelope>(value).is_err(),
                "unknown message types must fail Envelope deserialization"
            );
        } else {
            serde_json::from_value::<Envelope>(value).unwrap_or_else(|error| {
                panic!("{} must deserialize as Envelope: {error}", entry.file)
            });
        }
    }
}

#[test]
fn oversized_fixture_exceeds_protocol_codec_limit() {
    let bytes =
        fs::read(fixture_root().join("oversized.json")).expect("oversized.json must be readable");
    assert!(
        bytes.len() > MAX_MESSAGE_BYTES,
        "oversized.json must exceed MAX_MESSAGE_BYTES ({MAX_MESSAGE_BYTES}), got {} bytes",
        bytes.len()
    );
}

// These fixtures are conformance inputs for production-only behavior such as
// replay persistence, rate limiting, principal verification, and reconnect
// authorization semantics. This test file deliberately validates their wire
// shape only; it does not claim those future controls are implemented today.
