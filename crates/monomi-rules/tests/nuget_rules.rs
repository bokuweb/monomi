//! End-to-end NuGet-rule tests against synthetic `.nupkg` archives.

use std::io::Write;

use monomi_core::{
    AnalysisCtx, ArtifactId, Corpus, Ecosystem, EcosystemId, HashAlgo, Integrity, Stage1Verdict,
};
use monomi_nuget::NugetEcosystem;
use monomi_rules::{default_ruleset, run};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

fn build_nupkg(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zw = ZipWriter::new(cursor);
        let opts: SimpleFileOptions =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (p, data) in files {
            zw.start_file(*p, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap();
    }
    buf
}

fn analyze(bytes: Vec<u8>) -> monomi_core::Stage1Result {
    let tar = monomi_core::Tarball {
        source_url: None,
        bytes,
    };
    let eco = NugetEcosystem::new();
    let manifest = eco.parse_manifest(&tar).unwrap();
    let lifecycle = eco.lifecycle_entrypoints(&tar, &manifest).unwrap();
    let entries = eco.walk(&tar).unwrap();
    let artifact = ArtifactId {
        ecosystem: EcosystemId::Nuget,
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
        ast: None,
    };
    run(&default_ruleset(), &ctx).stage1
}

const NUSPEC: &str = r#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Demo.Pkg</id>
    <version>1.0.0</version>
  </metadata>
</package>"#;

#[test]
fn tools_dll_alongside_install_ps1_fires_nuget003() {
    let bytes = build_nupkg(&[
        ("Demo.Pkg.nuspec", NUSPEC.as_bytes()),
        ("tools/install.ps1", b"Write-Host 'installing'"),
        // MZ magic so classify() tags as NativeBinary too.
        ("tools/payload.dll", b"MZ\x90\x00fake-pe-payload"),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"NUGET003"), "expected NUGET003, got {ids:?}");
}

#[test]
fn tools_dll_without_install_ps1_is_clean_for_nuget003() {
    // Without an install hook the DLL is just a normal CLI tool ship.
    let bytes = build_nupkg(&[
        ("Demo.Pkg.nuspec", NUSPEC.as_bytes()),
        ("tools/tool.dll", b"MZ\x90\x00fake-pe"),
    ]);
    let s = analyze(bytes);
    assert!(
        s.findings.iter().all(|f| f.rule_id != "NUGET003"),
        "false-positive NUGET003: {:?}",
        s.findings
    );
}

#[test]
fn bidi_override_in_nuget_source_is_blocked() {
    let bytes = build_nupkg(&[
        ("Demo.Pkg.nuspec", NUSPEC.as_bytes()),
        // U+202E RLO inside a content file shipped in the package.
        ("content/script.cs", "// \u{202E} hidden".as_bytes()),
    ]);
    let s = analyze(bytes);
    let ids: Vec<_> = s.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        ids.contains(&"NPM022"),
        "expected NPM022 (cross-eco), got {ids:?}"
    );
    assert_eq!(s.verdict, Stage1Verdict::Malicious);
}
