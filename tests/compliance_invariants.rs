//! Cross-standard compliance invariants.
//!
//! Properties that must hold for every standard at once, so a new standard
//! or a refactored checker cannot quietly break them.

use clap::ValueEnum;
use sbom_tools::parse_sbom_str;
use sbom_tools::quality::{ComplianceChecker, ComplianceResult, StandardSelector};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn as_of() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
        .expect("valid timestamp")
        .with_timezone(&chrono::Utc)
}

fn check(raw: &str, selector: StandardSelector) -> ComplianceResult {
    let sbom = parse_sbom_str(raw).expect("fixture parses");
    ComplianceChecker::new(selector.level())
        .with_as_of(as_of())
        .check(&sbom)
}

fn fixture(rel: &str) -> String {
    std::fs::read_to_string(format!("{FIXTURES_DIR}/{rel}"))
        .unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// Standards that judge a software inventory. The crypto profiles judge
/// cryptographic assets with their own inventory gates, the AI profiles are
/// not applicable without ML content, and EUCC checks certification
/// references rather than components.
fn inventory_standards() -> Vec<StandardSelector> {
    StandardSelector::value_variants()
        .iter()
        .copied()
        .filter(|s| {
            !matches!(
                s,
                StandardSelector::Cnsa2
                    | StandardSelector::Pqc
                    | StandardSelector::AiAct
                    | StandardSelector::BsiAi
                    | StandardSelector::Eucc
            )
        })
        .collect()
}

/// Zero package-scoped components never yields a silent pass (review
/// finding V3): an empty document, a file-only document and a crypto-only
/// CBOM used to pass up to seven standards, scoring like perfect SBOMs.
#[test]
fn no_package_inventory_is_never_compliant() {
    let documents = [
        (
            "empty CycloneDX",
            fixture("compliance/regressions/v3-empty-inventory.cdx.json"),
        ),
        (
            "file-only SPDX",
            fixture("compliance/regressions/v3-file-only.spdx.json"),
        ),
        (
            "crypto-only CBOM",
            fixture("cyclonedx/cbom-1.7-sparse-ike.cdx.json"),
        ),
    ];
    let mut passes = Vec::new();
    for (label, raw) in &documents {
        for selector in inventory_standards() {
            let result = check(raw, selector);
            if result.is_compliant {
                passes.push(format!("{selector} passed the {label} document"));
            }
        }
    }
    assert!(
        passes.is_empty(),
        "silent passes:\n  {}",
        passes.join("\n  ")
    );
}

/// The primary component is inventory: a leaf application with no
/// dependencies must not draw an inventory-absent finding.
#[test]
fn a_lone_primary_component_is_an_inventory() {
    let raw = r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": "2026-10-01T00:00:00Z",
            "component": {
                "type": "application",
                "bom-ref": "app",
                "name": "app",
                "version": "1.0.0",
                "purl": "pkg:generic/app@1.0.0"
            }
        },
        "components": []
    }"#;
    for selector in inventory_standards() {
        let result = check(raw, selector);
        let inventory: Vec<&str> = result
            .violations
            .iter()
            .filter(|v| v.message.contains("SBOM lists no"))
            .map(|v| v.rule_id)
            .collect();
        assert!(
            inventory.is_empty(),
            "{selector}: a lone primary component drew {inventory:?}"
        );
    }
}
