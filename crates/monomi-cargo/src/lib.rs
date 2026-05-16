//! cargo / crates.io `Ecosystem` implementation.
//!
//! - Fetches `https://static.crates.io/crates/<name>/<name>-<ver>.crate`
//!   (a gzip-tar with a single `<name>-<ver>/` top-level directory).
//! - Parses `Cargo.toml` for the canonical manifest view.
//! - Surfaces `build.rs` (and any `package.build` override) as the
//!   sole `InstallTime` lifecycle entry: cargo runs it before the
//!   crate is consumed, so it is the analog of npm's postinstall.
//! - Does NOT surface proc-macro execution as a lifecycle entry yet
//!   (every dependent crate triggers it; modeling that needs a
//!   resolve-graph view that lives outside the per-crate scope).

use std::collections::BTreeMap;
use std::io::Read;

use async_trait::async_trait;
use flate2::read::GzDecoder;
use monomi_core::{
    artifact::{EcosystemId, HashAlgo, Integrity},
    ecosystem::{Ecosystem, LifecycleEntry, LifecycleKind, RegistryMetadata, Tarball},
    entry::{Entry, EntryKind},
    error::{Error, Result},
    manifest::Manifest,
};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_total_uncompressed: u64,
    pub max_entries: usize,
    pub max_entry_size: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_total_uncompressed: 100 * 1024 * 1024,
            max_entries: 50_000,
            max_entry_size: 50 * 1024 * 1024,
        }
    }
}

pub struct CargoEcosystem {
    /// Base for the binary `.crate` download.
    /// Default `https://static.crates.io/crates`.
    crate_base: String,
    http: reqwest::Client,
    limits: Limits,
}

impl Default for CargoEcosystem {
    fn default() -> Self {
        Self::new()
    }
}

impl CargoEcosystem {
    pub fn new() -> Self {
        Self {
            crate_base: "https://static.crates.io/crates".to_string(),
            http: reqwest::Client::builder()
                .user_agent(concat!("monomi/", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("reqwest client"),
            limits: Limits::default(),
        }
    }

    pub fn with_crate_base(mut self, base: impl Into<String>) -> Self {
        self.crate_base = base.into().trim_end_matches('/').to_string();
        self
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

#[async_trait]
impl Ecosystem for CargoEcosystem {
    fn id(&self) -> EcosystemId {
        EcosystemId::Cargo
    }

    async fn fetch(&self, name: &str, version: &str) -> Result<Tarball> {
        let url = format!(
            "{base}/{name}/{name}-{version}.crate",
            base = self.crate_base
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

    async fn fetch_registry_metadata(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Option<RegistryMetadata>> {
        // `https://crates.io/api/v1/crates/<name>` returns the
        // crate-level `created_at`, the full version array with
        // per-version `created_at` and `published_by.login`, plus
        // the owners list. One round-trip.
        let url = format!("https://crates.io/api/v1/crates/{name}");
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

        let mut meta = RegistryMetadata::default();
        if let Some(crate_obj) = json.get("crate") {
            if let Some(s) = crate_obj.get("created_at").and_then(|v| v.as_str()) {
                if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(s) {
                    meta.package_created_at = Some(ts.with_timezone(&chrono::Utc));
                }
            }
        }
        if let Some(versions) = json.get("versions").and_then(|v| v.as_array()) {
            meta.total_versions = Some(versions.len() as u32);
            for v in versions {
                let Some(num) = v.get("num").and_then(|x| x.as_str()) else {
                    continue;
                };
                let Some(s) = v.get("created_at").and_then(|x| x.as_str()) else {
                    continue;
                };
                let Ok(ts) = chrono::DateTime::parse_from_rfc3339(s) else {
                    continue;
                };
                let ts = ts.with_timezone(&chrono::Utc);
                if num == version {
                    meta.published_at = Some(ts);
                    if let Some(by) = v
                        .get("published_by")
                        .and_then(|p| p.get("login"))
                        .and_then(|n| n.as_str())
                    {
                        meta.published_by = Some(by.to_string());
                    }
                }
                meta.version_publish_times.insert(num.to_string(), ts);
            }
        }
        // Owners are a separate endpoint
        // (`/api/v1/crates/<name>/owners`); skip the extra round-trip
        // for V1 and leave maintainers empty.
        Ok(Some(meta))
    }

    async fn latest_version(&self, name: &str) -> Result<Option<String>> {
        // crates.io REST API: returns `crate.max_stable_version`
        // when at least one stable release exists, else
        // `max_version` (may be a prerelease).
        let url = format!("https://crates.io/api/v1/crates/{name}");
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
        let cr = json.get("crate");
        let stable = cr
            .and_then(|c| c.get("max_stable_version"))
            .and_then(|v| v.as_str());
        let max = cr
            .and_then(|c| c.get("max_version"))
            .and_then(|v| v.as_str());
        Ok(stable.or(max).map(ToString::to_string))
    }

    fn integrity(&self, tar: &Tarball) -> Integrity {
        // The cargo registry uses SHA-256 of the .crate file (this is
        // the `checksum` field in Cargo.lock and the `cksum` in the
        // sparse index).
        Integrity::from_bytes(HashAlgo::Sha256, &tar.bytes)
    }

    fn parse_manifest(&self, tar: &Tarball) -> Result<Manifest> {
        let cargo_toml = read_named(tar, "Cargo.toml", &self.limits)?
            .ok_or_else(|| Error::Manifest("Cargo.toml missing".into()))?;
        let cargo_toml_str = std::str::from_utf8(&cargo_toml)
            .map_err(|e| Error::Manifest(format!("Cargo.toml: {e}")))?;
        let raw_toml: toml::Value = cargo_toml_str
            .parse()
            .map_err(|e| Error::Manifest(format!("Cargo.toml: {e}")))?;

        let pkg = raw_toml
            .get("package")
            .ok_or_else(|| Error::Manifest("Cargo.toml has no [package] table".into()))?;

        let name = pkg
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let repository = pkg
            .get("repository")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let homepage = pkg
            .get("homepage")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);

        // [[bin]] entries: name + path. We surface them so the
        // shared NativeBinaryUndeclared rule (if extended to cargo)
        // has somewhere to consult.
        let mut bin = BTreeMap::new();
        if let Some(arr) = raw_toml.get("bin").and_then(|v| v.as_array()) {
            for b in arr {
                let n = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let p = b.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if !n.is_empty() && !p.is_empty() {
                    bin.insert(n.to_string(), p.to_string());
                }
            }
        }

        // `package.build` can override the conventional `build.rs`.
        let mut scripts = BTreeMap::new();
        if let Some(b) = pkg.get("build").and_then(|v| v.as_str()) {
            scripts.insert("build".to_string(), b.to_string());
        }

        let mut dependencies = BTreeMap::new();
        for table in ["dependencies", "build-dependencies", "dev-dependencies"] {
            if let Some(t) = raw_toml.get(table).and_then(|v| v.as_table()) {
                for (k, v) in t {
                    let req = match v {
                        toml::Value::String(s) => s.clone(),
                        toml::Value::Table(t) => t
                            .get("version")
                            .and_then(|x| x.as_str())
                            .unwrap_or("*")
                            .to_string(),
                        _ => "*".to_string(),
                    };
                    dependencies.insert(k.clone(), req);
                }
            }
        }

        // Re-serialize to serde_json::Value so the generic Manifest
        // can keep the raw structure available to rules.
        let raw_json = toml_to_json(&raw_toml);

        Ok(Manifest {
            name,
            version,
            repository,
            homepage,
            bin,
            scripts,
            dependencies,
            raw: raw_json,
        })
    }

    fn lifecycle_entrypoints(
        &self,
        tar: &Tarball,
        manifest: &Manifest,
    ) -> Result<Vec<LifecycleEntry>> {
        // Pick `package.build` if set, else conventional `build.rs`.
        let path_in_pkg = manifest
            .scripts
            .get("build")
            .cloned()
            .unwrap_or_else(|| "build.rs".to_string());
        let bytes = read_named(tar, &path_in_pkg, &self.limits)?;
        let mut out = Vec::new();
        if let Some(body) = bytes {
            let body_text = String::from_utf8_lossy(&body).into_owned();
            out.push(LifecycleEntry {
                name: "build".to_string(),
                kind: LifecycleKind::InstallTime,
                body: body_text,
                path: Some(path_in_pkg),
            });
        }
        Ok(out)
    }

    fn walk(&self, tar: &Tarball) -> Result<Vec<Entry>> {
        walk_crate(tar, &self.limits)
    }
}

/// Read one logical file (path relative to the package root) from a
/// `.crate` tarball.
///
/// `.crate` archives wrap everything under a single
/// `<name>-<version>/` directory which we strip transparently.
fn read_named(tar: &Tarball, logical: &str, limits: &Limits) -> Result<Option<Vec<u8>>> {
    for entry in walk_crate(tar, limits)? {
        if entry.path == logical {
            return Ok(Some(entry.bytes));
        }
    }
    Ok(None)
}

fn walk_crate(tar: &Tarball, limits: &Limits) -> Result<Vec<Entry>> {
    let gz = GzDecoder::new(tar.bytes.as_slice());
    let mut archive = tar::Archive::new(gz);
    let mut out = Vec::new();
    let mut total: u64 = 0;
    let mut top_prefix: Option<String> = None;

    for entry in archive
        .entries()
        .map_err(|e| Error::InvalidTarball(e.to_string()))?
    {
        let mut entry = entry.map_err(|e| Error::InvalidTarball(e.to_string()))?;
        if !matches!(entry.header().entry_type(), tar::EntryType::Regular) {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| Error::InvalidTarball(e.to_string()))?
            .to_string_lossy()
            .to_string();
        if path.contains("..") || path.starts_with('/') {
            return Err(Error::InvalidTarball(format!("unsafe path: {path}")));
        }
        // Strip the `<name>-<version>/` prefix. We lock it on the
        // first regular entry seen and refuse files whose prefix
        // differs (malformed .crate).
        let logical = match &top_prefix {
            Some(p) => match path.strip_prefix(p) {
                Some(rest) => rest.to_string(),
                None => {
                    return Err(Error::InvalidTarball(format!(
                        "unexpected top prefix in entry: {path}"
                    )))
                }
            },
            None => {
                let first = path
                    .split_once('/')
                    .map(|(head, _)| head.to_string())
                    .unwrap_or_default();
                if first.is_empty() {
                    return Err(Error::InvalidTarball(format!(
                        "entry at archive root: {path}"
                    )));
                }
                let with_slash = format!("{first}/");
                let rest = path.strip_prefix(&with_slash).unwrap_or(&path).to_string();
                top_prefix = Some(with_slash);
                rest
            }
        };

        let size = entry
            .header()
            .size()
            .map_err(|e| Error::InvalidTarball(e.to_string()))?;
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
            .map_err(|e| Error::InvalidTarball(e.to_string()))?;
        let kind = classify(&logical, &bytes);
        out.push(Entry {
            path: logical,
            kind,
            size,
            bytes,
        });
    }
    Ok(out)
}

fn classify(path: &str, bytes: &[u8]) -> EntryKind {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".rs") {
        return EntryKind::RustSource;
    }
    if lower.ends_with(".toml") {
        return EntryKind::Toml;
    }
    if lower.ends_with(".json") {
        return EntryKind::Json;
    }
    if lower.ends_with(".wasm") || is_native_binary(bytes) {
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

/// Best-effort TOML → JSON for embedding in `Manifest.raw`.
fn toml_to_json(v: &toml::Value) -> serde_json::Value {
    match v {
        toml::Value::String(s) => serde_json::Value::String(s.clone()),
        toml::Value::Integer(i) => serde_json::Value::Number((*i).into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        toml::Value::Boolean(b) => serde_json::Value::Bool(*b),
        toml::Value::Datetime(d) => serde_json::Value::String(d.to_string()),
        toml::Value::Array(a) => serde_json::Value::Array(a.iter().map(toml_to_json).collect()),
        toml::Value::Table(t) => serde_json::Value::Object(
            t.iter()
                .map(|(k, v)| (k.clone(), toml_to_json(v)))
                .collect(),
        ),
    }
}

pub fn load_crate_from_path(path: &std::path::Path) -> Result<Tarball> {
    let bytes = std::fs::read(path)?;
    Ok(Tarball {
        source_url: None,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
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

    #[test]
    fn parses_manifest_and_lifecycle() {
        let cargo_toml = br#"
[package]
name = "demo"
version = "0.1.0"
repository = "https://example.com/demo"

[dependencies]
serde = "1"
        "#;
        let build_rs = b"fn main() { println!(\"hello\"); }";
        let bytes = build_crate(
            "demo-0.1.0",
            &[
                ("Cargo.toml", cargo_toml.as_slice()),
                ("build.rs", build_rs.as_slice()),
                ("src/lib.rs", b"pub fn hi() {}".as_slice()),
            ],
        );
        let tar = monomi_core::Tarball {
            source_url: None,
            bytes,
        };
        let eco = CargoEcosystem::new();
        let m = eco.parse_manifest(&tar).unwrap();
        assert_eq!(m.name, "demo");
        assert_eq!(m.version, "0.1.0");
        assert_eq!(m.repository.as_deref(), Some("https://example.com/demo"));
        assert_eq!(m.dependencies.get("serde").map(String::as_str), Some("1"));

        let life = eco.lifecycle_entrypoints(&tar, &m).unwrap();
        assert_eq!(life.len(), 1);
        assert_eq!(life[0].name, "build");
        assert!(life[0].body.contains("hello"));
        assert_eq!(life[0].path.as_deref(), Some("build.rs"));

        let entries = eco.walk(&tar).unwrap();
        assert!(entries
            .iter()
            .any(|e| e.path == "src/lib.rs" && e.kind == EntryKind::RustSource));
        assert!(entries
            .iter()
            .any(|e| e.path == "Cargo.toml" && e.kind == EntryKind::Toml));
    }

    #[test]
    fn integrity_is_sha256() {
        let tar = monomi_core::Tarball {
            source_url: None,
            bytes: b"hi".to_vec(),
        };
        let i = CargoEcosystem::new().integrity(&tar);
        assert_eq!(i.algo, HashAlgo::Sha256);
        assert!(i.sri().starts_with("sha256-"));
    }

    #[test]
    fn package_build_override_is_honored() {
        let cargo_toml = br#"
[package]
name = "x"
version = "0.0.1"
build = "custom-build.rs"
        "#;
        let bytes = build_crate(
            "x-0.0.1",
            &[
                ("Cargo.toml", cargo_toml.as_slice()),
                ("custom-build.rs", b"fn main() {}".as_slice()),
            ],
        );
        let tar = monomi_core::Tarball {
            source_url: None,
            bytes,
        };
        let eco = CargoEcosystem::new();
        let m = eco.parse_manifest(&tar).unwrap();
        let life = eco.lifecycle_entrypoints(&tar, &m).unwrap();
        assert_eq!(life.len(), 1);
        assert_eq!(life[0].path.as_deref(), Some("custom-build.rs"));
    }

    #[test]
    fn no_build_rs_is_no_lifecycle() {
        let cargo_toml = br#"
[package]
name = "no-build"
version = "0.0.1"
        "#;
        let bytes = build_crate(
            "no-build-0.0.1",
            &[
                ("Cargo.toml", cargo_toml.as_slice()),
                ("src/lib.rs", b"pub fn x() {}".as_slice()),
            ],
        );
        let tar = monomi_core::Tarball {
            source_url: None,
            bytes,
        };
        let eco = CargoEcosystem::new();
        let m = eco.parse_manifest(&tar).unwrap();
        assert!(eco.lifecycle_entrypoints(&tar, &m).unwrap().is_empty());
    }
}
