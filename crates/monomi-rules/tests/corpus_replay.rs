//! Replay test against historically-malicious npm tarballs.
//!
//! The tarballs themselves are gitignored (`fixtures/corpus/*.tgz`)
//! because they literally are malware. Populate the corpus with
//! `scripts/fetch_corpus.sh` and then run:
//!
//!   cargo test -p monomi-rules --test corpus_replay -- --ignored --nocapture
//!
//! The test is marked `#[ignore]` so plain `cargo test` skips it;
//! CI opts in.
//!
//! Each manifest entry declares `must_fire_any` (rule IDs at least
//! one of which must hit) and optionally `must_not_fire` (rule IDs
//! that MUST NOT hit — used by the `event-stream` baseline to assert
//! we don't blow up on a benign wrapper).

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use monomi_core::{
    AnalysisCtx, ArtifactId, Corpus, Ecosystem, EcosystemId, HashAlgo, Integrity, Tarball,
};
use monomi_npm::NpmEcosystem;
use monomi_rules::{default_ruleset, run};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Manifest {
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    id: String,
    #[allow(dead_code)]
    package: String,
    #[allow(dead_code)]
    version: String,
    tarball: String,
    #[allow(dead_code)]
    url: String,
    #[allow(dead_code)]
    note: String,
    #[serde(default)]
    must_fire_any: Vec<String>,
    #[serde(default)]
    must_not_fire: Vec<String>,
}

fn corpus_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR = crates/monomi-rules
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/corpus")
        .canonicalize()
        .expect("fixtures/corpus exists (mkdir -p was run by scripts/fetch_corpus.sh)")
}

fn load_manifest() -> Manifest {
    let path = corpus_dir().join("manifest.json");
    let text = fs::read_to_string(&path).expect("read manifest.json");
    serde_json::from_str(&text).expect("parse manifest.json")
}

fn fired_rules(tar_bytes: Vec<u8>) -> BTreeSet<String> {
    let tar = Tarball {
        source_url: None,
        bytes: tar_bytes,
    };
    let eco = NpmEcosystem::new();
    let manifest = eco.parse_manifest(&tar).expect("parse_manifest");
    let lifecycle = eco
        .lifecycle_entrypoints(&tar, &manifest)
        .expect("lifecycle");
    let entries = eco.walk(&tar).expect("walk");
    let artifact = ArtifactId {
        ecosystem: EcosystemId::Npm,
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        integrity: Integrity::from_bytes(HashAlgo::Sha512, &tar.bytes),
    };
    let corpus = Corpus::default();
    let ctx = AnalysisCtx {
        artifact: &artifact,
        manifest: &manifest,
        lifecycle: &lifecycle,
        entries: &entries,
        diff: None,
        registry: None,
        corpus: &corpus,
    };
    run(&default_ruleset(), &ctx)
        .stage1
        .findings
        .into_iter()
        .map(|f| f.rule_id)
        .collect()
}

#[test]
#[ignore = "requires populated corpus — run scripts/fetch_corpus.sh first"]
fn replay_against_known_malicious_corpus() {
    let manifest = load_manifest();
    let dir = corpus_dir();

    let mut checked = 0usize;
    let mut missing = Vec::new();
    let mut failures = Vec::new();

    for entry in &manifest.entries {
        let path = dir.join(&entry.tarball);
        let Ok(bytes) = fs::read(&path) else {
            missing.push(entry.id.clone());
            continue;
        };
        checked += 1;
        let fired = fired_rules(bytes);
        println!("== {} ==", entry.id);
        for r in &fired {
            println!("  fired: {r}");
        }

        if !entry.must_fire_any.is_empty()
            && !entry
                .must_fire_any
                .iter()
                .any(|r| fired.contains(r.as_str()))
        {
            failures.push(format!(
                "{}: expected at least one of {:?} to fire, got {:?}",
                entry.id, entry.must_fire_any, fired
            ));
        }
        for forbidden in &entry.must_not_fire {
            if fired.contains(forbidden.as_str()) {
                failures.push(format!(
                    "{}: rule {} fired but was declared must_not_fire",
                    entry.id, forbidden
                ));
            }
        }
    }

    if checked == 0 {
        // No-op rather than panic: npm has unpublished most of the
        // canonical historical incidents, so a fresh
        // `scripts/fetch_corpus.sh` run can legitimately produce
        // zero tarballs. The test still serves as a shape probe —
        // when an entry IS present, it must replay correctly.
        eprintln!(
            "no corpus tarballs available in {} — see scripts/fetch_corpus.sh \
             for sources (registry unpublishes most malicious versions)",
            dir.display()
        );
        return;
    }
    if !missing.is_empty() {
        eprintln!(
            "skipped {} entries (tarball not fetched): {:?}",
            missing.len(),
            missing
        );
    }
    assert!(
        failures.is_empty(),
        "{} replay assertion(s) failed:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    println!(
        "replay corpus: {} checked, {} skipped, 0 failures",
        checked,
        missing.len()
    );
}
