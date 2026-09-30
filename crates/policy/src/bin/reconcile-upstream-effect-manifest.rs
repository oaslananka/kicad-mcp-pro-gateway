use std::error::Error;
use std::io::Read;

use companion_policy::{TomlToolRegistry, ToolCatalogSnapshot, UpstreamEffectManifest};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

fn read_manifest<R: Read>(reader: R) -> Result<String, Box<dyn Error>> {
    let mut input = String::new();
    let mut limited = reader.take(MAX_MANIFEST_BYTES + 1);
    limited.read_to_string(&mut input)?;
    if input.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("tool-effect manifest exceeds the 1 MiB reconciliation limit".into());
    }
    if input.trim().is_empty() {
        return Err("tool-effect manifest input is empty".into());
    }
    Ok(input)
}

fn main() -> Result<(), Box<dyn Error>> {
    let json = read_manifest(std::io::stdin().lock())?;
    let manifest = UpstreamEffectManifest::from_json_str(&json)?;
    let registry = TomlToolRegistry::try_embedded()?;
    let snapshot = ToolCatalogSnapshot::embedded();

    let report = manifest.reconcile_with_fallback(&registry)?;
    println!(
        "schema={} upstream_version={} reviewed_source_sha={}",
        manifest.schema_version(),
        manifest.source().version,
        manifest.source().reviewed_source_sha
    );
    println!(
        "fallback_only={} upstream_only={} mismatches={}",
        report.fallback_only_reviewed.len(),
        report.upstream_only_reviewed.len(),
        report.contract_mismatches.len()
    );
    if !report.fallback_only_reviewed.is_empty() {
        eprintln!(
            "fallback-only reviewed tools: {}",
            report.fallback_only_reviewed.join(", ")
        );
    }
    if !report.upstream_only_reviewed.is_empty() {
        eprintln!(
            "upstream-only reviewed tools: {}",
            report.upstream_only_reviewed.join(", ")
        );
    }
    if !report.contract_mismatches.is_empty() {
        eprintln!(
            "reviewed contract mismatches: {}",
            report.contract_mismatches.join(", ")
        );
    }

    let source_result = manifest.validate_source(&snapshot);
    if let Err(error) = &source_result {
        eprintln!("source pin mismatch: {error}");
    }

    if source_result.is_err() || !report.is_exact_match() {
        return Err(
            "upstream effect manifest is not an exact production fallback/source-pin match".into(),
        );
    }

    println!("upstream effect manifest exactly matches the pinned production fallback");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn rejects_empty_input() {
        assert!(read_manifest(Cursor::new(Vec::<u8>::new())).is_err());
    }

    #[test]
    fn rejects_oversized_input() {
        let payload = vec![b'x'; MAX_MANIFEST_BYTES as usize + 1];
        assert!(read_manifest(Cursor::new(payload)).is_err());
    }

    #[test]
    fn accepts_bounded_utf8_json_input() {
        let payload = br#"{"schemaVersion":"1.0.0"}"#.to_vec();
        assert_eq!(
            read_manifest(Cursor::new(payload)).unwrap(),
            r#"{"schemaVersion":"1.0.0"}"#
        );
    }
}
