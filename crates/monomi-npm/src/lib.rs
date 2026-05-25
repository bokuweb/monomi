//! npm `Ecosystem` implementation.
//!
//! - Fetches `<registry>/<name>/<version>` packument to resolve the
//!   tarball URL, then fetches the .tgz.
//! - Walks the .tgz in-memory with size limits.
//! - Parses `package.json` for the canonical manifest view and
//!   surfaces lifecycle scripts (`preinstall` / `install` /
//!   `postinstall` / `prepare`).

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

/// Hard limits against malicious tarballs. Conservative defaults;
/// callers can construct `NpmEcosystem::with_limits` to raise them.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_total_uncompressed: u64,
    pub max_entries: usize,
    pub max_entry_size: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_total_uncompressed: 100 * 1024 * 1024, // 100 MiB
            max_entries: 50_000,
            max_entry_size: 50 * 1024 * 1024, // 50 MiB per file
        }
    }
}

pub struct NpmEcosystem {
    registry: String,
    http: reqwest::Client,
    limits: Limits,
}

impl Default for NpmEcosystem {
    fn default() -> Self {
        Self::new()
    }
}

impl NpmEcosystem {
    pub fn new() -> Self {
        Self {
            registry: "https://registry.npmjs.org".to_string(),
            http: reqwest::Client::builder()
                .user_agent(concat!("monomi/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("reqwest client"),
            limits: Limits::default(),
        }
    }

    pub fn with_registry(mut self, registry: impl Into<String>) -> Self {
        self.registry = registry.into();
        self
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// GET with 429/5xx retry + `Retry-After` honouring. Keeps the
    /// feed daemon healthy under npm's not-quite-documented rate
    /// limits — the registry returns 429 with a `Retry-After`
    /// header (sometimes in seconds, sometimes as HTTP-date) when
    /// you push too hard on the change stream + tarball fetches.
    async fn get_with_retry(&self, url: &str) -> Result<reqwest::Response> {
        const MAX_ATTEMPTS: u32 = 6;
        let mut attempt: u32 = 0;
        loop {
            let resp = self
                .http
                .get(url)
                .send()
                .await
                .map_err(|e| Error::Fetch(format!("{url}: {e}")))?;
            let status = resp.status();
            let retryable = status == reqwest::StatusCode::TOO_MANY_REQUESTS
                || (status.is_server_error() && status != reqwest::StatusCode::NOT_IMPLEMENTED);
            if retryable && attempt < MAX_ATTEMPTS - 1 {
                let retry_after = resp
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or_else(|| {
                        // Exponential backoff: 1, 2, 4, 8, 16, 32 s
                        1u64 << attempt.min(5)
                    });
                tracing::warn!(
                    %url,
                    %status,
                    retry_after,
                    attempt,
                    "transient registry error; backing off"
                );
                tokio::time::sleep(std::time::Duration::from_secs(retry_after)).await;
                attempt += 1;
                continue;
            }
            return Ok(resp);
        }
    }
}

#[async_trait]
impl Ecosystem for NpmEcosystem {
    fn id(&self) -> EcosystemId {
        EcosystemId::Npm
    }

    async fn fetch(&self, name: &str, version: &str) -> Result<Tarball> {
        let url = format!(
            "{}/{}/{}",
            self.registry.trim_end_matches('/'),
            encode_pkg_name(name),
            version
        );
        let resp = self.get_with_retry(&url).await?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::NotFound(format!("{name}@{version}")));
        }
        if !status.is_success() {
            return Err(Error::Fetch(format!("{url}: HTTP {status}")));
        }
        let meta: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Fetch(format!("{url}: {e}")))?;
        let tarball_url = meta
            .get("dist")
            .and_then(|d| d.get("tarball"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| Error::Fetch(format!("{url}: missing dist.tarball")))?
            .to_string();

        let tar_resp = self.get_with_retry(&tarball_url).await?;
        let status = tar_resp.status();
        if !status.is_success() {
            return Err(Error::Fetch(format!("{tarball_url}: HTTP {status}")));
        }
        let bytes = tar_resp
            .bytes()
            .await
            .map_err(|e| Error::Fetch(format!("{tarball_url}: {e}")))?
            .to_vec();

        Ok(Tarball {
            source_url: Some(tarball_url),
            bytes,
        })
    }

    async fn fetch_registry_metadata(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Option<RegistryMetadata>> {
        // Packument GET — has `time` map (per-version publish
        // timestamps), `maintainers` list, and the `_npmUser`
        // field on each version document. Single round-trip; the
        // analyzer caches the result per package via AnalysisCtx.
        let url = format!(
            "{}/{}",
            self.registry.trim_end_matches('/'),
            encode_pkg_name(name)
        );
        let resp = self.get_with_retry(&url).await?;
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
        if let Some(serde_json::Value::Object(times)) = json.get("time") {
            for (k, v) in times {
                let Some(s) = v.as_str() else { continue };
                let Ok(ts) = chrono::DateTime::parse_from_rfc3339(s) else {
                    continue;
                };
                let ts = ts.with_timezone(&chrono::Utc);
                if k == "created" {
                    meta.package_created_at = Some(ts);
                } else if k == "modified" {
                    // npm uses "modified" as the package-level last
                    // touch; we don't surface it separately.
                } else {
                    if k == version {
                        meta.published_at = Some(ts);
                    }
                    meta.version_publish_times.insert(k.clone(), ts);
                }
            }
        }
        if let Some(serde_json::Value::Array(arr)) = json.get("maintainers") {
            for m in arr {
                if let Some(name) = m.get("name").and_then(|v| v.as_str()) {
                    meta.maintainers.push(name.to_string());
                }
            }
        }
        if let Some(serde_json::Value::Object(versions)) = json.get("versions") {
            meta.total_versions = Some(versions.len() as u32);
            if let Some(vdoc) = versions.get(version) {
                if let Some(u) = vdoc
                    .get("_npmUser")
                    .and_then(|u| u.get("name"))
                    .and_then(|n| n.as_str())
                {
                    meta.published_by = Some(u.to_string());
                }
            }
        }
        Ok(Some(meta))
    }

    async fn latest_version(&self, name: &str) -> Result<Option<String>> {
        // Packument GET — `dist-tags.latest` is the conventional
        // "latest stable" pointer (excluded from prereleases by
        // convention).
        let url = format!(
            "{}/{}",
            self.registry.trim_end_matches('/'),
            encode_pkg_name(name)
        );
        let resp = self.get_with_retry(&url).await?;
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
        Ok(json
            .get("dist-tags")
            .and_then(|d| d.get("latest"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string))
    }

    fn integrity(&self, tar: &Tarball) -> Integrity {
        // npm's SRI on tarballs is sha512 of the .tgz bytes.
        Integrity::from_bytes(HashAlgo::Sha512, &tar.bytes)
    }

    fn parse_manifest(&self, tar: &Tarball) -> Result<Manifest> {
        let pkg_json = read_single_file(tar, "package.json", &self.limits)?
            .ok_or_else(|| Error::Manifest("package.json missing".into()))?;
        let raw: serde_json::Value = serde_json::from_slice(&pkg_json)
            .map_err(|e| Error::Manifest(format!("package.json: {e}")))?;

        let name = raw
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let version = raw
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let repository = raw.get("repository").and_then(|r| match r {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Object(o) => o
                .get("url")
                .and_then(|u| u.as_str())
                .map(ToString::to_string),
            _ => None,
        });
        let homepage = raw
            .get("homepage")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);

        let mut bin = BTreeMap::new();
        match raw.get("bin") {
            Some(serde_json::Value::String(s)) => {
                bin.insert(name.clone(), s.clone());
            }
            Some(serde_json::Value::Object(o)) => {
                for (k, v) in o {
                    if let Some(s) = v.as_str() {
                        bin.insert(k.clone(), s.to_string());
                    }
                }
            }
            _ => {}
        }

        let mut scripts = BTreeMap::new();
        if let Some(serde_json::Value::Object(o)) = raw.get("scripts") {
            for (k, v) in o {
                if let Some(s) = v.as_str() {
                    scripts.insert(k.clone(), s.to_string());
                }
            }
        }

        let mut dependencies = BTreeMap::new();
        for field in ["dependencies", "optionalDependencies", "peerDependencies"] {
            if let Some(serde_json::Value::Object(o)) = raw.get(field) {
                for (k, v) in o {
                    if let Some(s) = v.as_str() {
                        dependencies.insert(k.clone(), s.to_string());
                    }
                }
            }
        }

        Ok(Manifest {
            name,
            version,
            repository,
            homepage,
            bin,
            scripts,
            dependencies,
            raw,
        })
    }

    fn lifecycle_entrypoints(
        &self,
        _tar: &Tarball,
        manifest: &Manifest,
    ) -> Result<Vec<LifecycleEntry>> {
        const INSTALL_HOOKS: &[&str] = &["preinstall", "install", "postinstall", "prepare"];
        const PUBLISH_HOOKS: &[&str] = &["prepublish", "prepublishOnly", "publish", "postpublish"];

        let mut out = Vec::new();
        for (name, body) in &manifest.scripts {
            let kind = if INSTALL_HOOKS.contains(&name.as_str()) {
                LifecycleKind::InstallTime
            } else if PUBLISH_HOOKS.contains(&name.as_str()) {
                LifecycleKind::PublishTime
            } else {
                continue;
            };
            out.push(LifecycleEntry {
                name: name.clone(),
                kind,
                body: body.clone(),
                path: None,
            });
        }
        Ok(out)
    }

    fn walk(&self, tar: &Tarball) -> Result<Vec<Entry>> {
        let gz = GzDecoder::new(tar.bytes.as_slice());
        let mut archive = tar::Archive::new(gz);
        let mut out = Vec::new();
        let mut total: u64 = 0;

        for entry in archive
            .entries()
            .map_err(|e| Error::InvalidTarball(e.to_string()))?
        {
            let mut entry = entry.map_err(|e| Error::InvalidTarball(e.to_string()))?;
            let header = entry.header().clone();
            if !matches!(header.entry_type(), tar::EntryType::Regular) {
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
            // Strip the leading `package/` directory npm wraps everything in.
            let logical = path
                .strip_prefix("package/")
                .map(ToString::to_string)
                .unwrap_or(path);

            let size = header
                .size()
                .map_err(|e| Error::InvalidTarball(e.to_string()))?;
            if size > self.limits.max_entry_size {
                return Err(Error::Oversized {
                    what: "entry",
                    size,
                    limit: self.limits.max_entry_size,
                });
            }
            total = total.saturating_add(size);
            if total > self.limits.max_total_uncompressed {
                return Err(Error::Oversized {
                    what: "total",
                    size: total,
                    limit: self.limits.max_total_uncompressed,
                });
            }
            if out.len() >= self.limits.max_entries {
                return Err(Error::Oversized {
                    what: "entries",
                    size: out.len() as u64 + 1,
                    limit: self.limits.max_entries as u64,
                });
            }

            let mut bytes = Vec::with_capacity(size as usize);
            entry
                .read_to_end(&mut bytes)
                .map_err(|e| Error::InvalidTarball(e.to_string()))?;
            let kind = classify(&logical, &bytes);
            let mode = header.mode().ok();
            out.push(Entry {
                path: logical,
                kind,
                size,
                bytes,
                mode,
            });
        }
        Ok(out)
    }
}

fn classify(path: &str, bytes: &[u8]) -> EntryKind {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".js")
        || lower.ends_with(".mjs")
        || lower.ends_with(".cjs")
        || lower.ends_with(".ts")
        || lower.ends_with(".tsx")
        || lower.ends_with(".jsx")
    {
        return EntryKind::JsSource;
    }
    if lower.ends_with(".json") {
        return EntryKind::Json;
    }
    if lower.ends_with(".node") || lower.ends_with(".wasm") || is_native_binary(bytes) {
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
            | Some([0xCF, 0xFA, 0xED, 0xFE])  // Mach-O 64
            | Some([0xCE, 0xFA, 0xED, 0xFE])  // Mach-O 32
            | Some([0xCA, 0xFE, 0xBA, 0xBE])  // Mach-O FAT
            | Some([b'M', b'Z', _, _])
    )
}

fn encode_pkg_name(name: &str) -> String {
    // Scoped packages need the `/` URL-encoded.
    name.replace('/', "%2F")
}

/// Read one named entry from the tarball without walking everything.
fn read_single_file(tar: &Tarball, logical: &str, limits: &Limits) -> Result<Option<Vec<u8>>> {
    let target = format!("package/{logical}");
    let gz = GzDecoder::new(tar.bytes.as_slice());
    let mut archive = tar::Archive::new(gz);
    for entry in archive
        .entries()
        .map_err(|e| Error::InvalidTarball(e.to_string()))?
    {
        let mut entry = entry.map_err(|e| Error::InvalidTarball(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| Error::InvalidTarball(e.to_string()))?
            .to_string_lossy()
            .to_string();
        if path == target {
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
            let mut bytes = Vec::with_capacity(size as usize);
            entry
                .read_to_end(&mut bytes)
                .map_err(|e| Error::InvalidTarball(e.to_string()))?;
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

/// Read a tarball from disk into a `Tarball` value.
pub fn load_tarball_from_path(path: &std::path::Path) -> Result<Tarball> {
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

    fn build_tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = Builder::new(&mut gz);
            for (path, data) in files {
                let mut h = Header::new_gnu();
                h.set_path(path).unwrap();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                builder.append(&h, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    #[test]
    fn parse_basic_manifest_and_walk() {
        let pkg = r#"{
            "name": "demo",
            "version": "1.0.0",
            "scripts": { "postinstall": "node ./hook.js" },
            "dependencies": { "left-pad": "^1.0.0" },
            "repository": { "url": "https://example.com/demo" }
        }"#;
        let hook = "console.log('hi');";
        let bytes = build_tgz(&[
            ("package/package.json", pkg.as_bytes()),
            ("package/hook.js", hook.as_bytes()),
        ]);
        let tar = Tarball {
            source_url: None,
            bytes,
        };
        let eco = NpmEcosystem::new();
        let manifest = eco.parse_manifest(&tar).unwrap();
        assert_eq!(manifest.name, "demo");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(
            manifest.scripts.get("postinstall").map(String::as_str),
            Some("node ./hook.js")
        );
        assert_eq!(
            manifest.repository.as_deref(),
            Some("https://example.com/demo")
        );

        let entries = eco.walk(&tar).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.path == "hook.js" && e.kind == EntryKind::JsSource));
        assert!(entries
            .iter()
            .any(|e| e.path == "package.json" && e.kind == EntryKind::Json));

        let life = eco.lifecycle_entrypoints(&tar, &manifest).unwrap();
        assert_eq!(life.len(), 1);
        assert_eq!(life[0].name, "postinstall");
        assert!(matches!(life[0].kind, LifecycleKind::InstallTime));
    }

    // Path-traversal rejection is asserted in production via `walk()`'s
    // explicit `path.contains("..") || path.starts_with('/')` check;
    // synthesizing such a tarball requires a hand-rolled archive
    // (the `tar` crate's `Builder` refuses to write unsafe paths)
    // — covered by fixture tests in a follow-up.

    #[test]
    fn integrity_is_stable_sha512() {
        let tar = Tarball {
            source_url: None,
            bytes: b"hello".to_vec(),
        };
        let i = NpmEcosystem::new().integrity(&tar);
        assert_eq!(i.algo, HashAlgo::Sha512);
        // Just check it round-trips through SRI.
        let sri = i.sri();
        assert!(sri.starts_with("sha512-"));
    }
}
