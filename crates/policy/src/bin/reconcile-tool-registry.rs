use std::error::Error;
use std::path::PathBuf;

use companion_policy::{TomlToolRegistry, ToolCatalogSnapshot};

fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        println!(
            "reconcile-tool-registry: Automates upstream tool snapshot refresh and coverage audit."
        );
        println!("Usage: reconcile-tool-registry <tools-reference.generated.md> <source-sha> [output.toml]");
        return Ok(());
    }
    if !(2..=3).contains(&args.len()) {
        return Err(
            "usage: reconcile-tool-registry <tools-reference.generated.md> <source-sha> [output.toml]"
                .into(),
        );
    }

    let source_path = PathBuf::from(&args[0]);
    let source_sha = &args[1];
    let markdown = std::fs::read_to_string(&source_path)?;
    let snapshot = ToolCatalogSnapshot::from_tools_reference_markdown(
        "oaslananka/kicad-mcp-pro",
        "main",
        source_sha,
        &markdown,
    )?;
    let registry = TomlToolRegistry::try_embedded()?;
    let report = registry.coverage_against(&snapshot);

    let snapshot_toml = snapshot.to_toml_pretty()?;
    if let Some(output) = args.get(2) {
        std::fs::write(output, snapshot_toml)?;
    } else {
        print!("{snapshot_toml}");
    }

    println!(
        "catalog={} registry={} classified={} unclassified={} stale={} effect_modelled={} effect_unmodelled={}",
        report.catalog_total,
        report.registry_total,
        report.classified.len(),
        report.unclassified.len(),
        report.stale.len(),
        report.effect_modelled.len(),
        report.effect_unmodelled.len()
    );
    if !report.unclassified.is_empty() {
        eprintln!(
            "unclassified/new tools (default DENY): {}",
            report.unclassified.join(", ")
        );
    }
    if !report.stale.is_empty() {
        eprintln!("stale registry entries: {}", report.stale.join(", "));
    }
    Ok(())
}
