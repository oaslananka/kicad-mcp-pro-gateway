use std::error::Error;
use std::path::PathBuf;

use companion_policy::{TomlToolRegistry, ToolCatalogSnapshot, UpstreamEffectManifest};

fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        println!("reconcile-upstream-effect-manifest: Strictly validate and compare a reviewed upstream effect manifest.");
        println!("Usage: reconcile-upstream-effect-manifest <tool-effect-manifest.json>");
        return Ok(());
    }
    if args.len() != 1 {
        return Err("usage: reconcile-upstream-effect-manifest <tool-effect-manifest.json>".into());
    }

    let path = PathBuf::from(&args[0]);
    let json = std::fs::read_to_string(&path)?;
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
