//! PyPI `Ecosystem` implementation (sdist focus).
//!
//! V1 covers **source distributions** (`.tar.gz` sdists) because that
//! is where the install-time RCE risk lives:
//!
//! - `setup.py` runs verbatim during `pip install`.
//! - `pyproject.toml`'s `build-system.build-backend` runs whatever
//!   non-stdlib code it points at.
//!
//! Wheels (`.whl`) ship pre-built `.dist-info/METADATA` and do not
//! execute code at install time (the metadata of interest is the
//! same; we can add wheel parsing later).
//!
//! Fetch path:
//!
//! 1. `https://pypi.org/pypi/<pkg>/<ver>/json` — Warehouse JSON for
//!    the specific version, lists `urls[]` entries with
//!    `packagetype == "sdist"` and a `digests.sha256`.
//! 2. Download the first sdist URL; integrity = SHA-256.

use std::collections::BTreeMap;
use std::io::Read;

use async_trait::async_trait;
use flate2::read::GzDecoder;
use monomi_core::{
    artifact::{EcosystemId, HashAlgo, Integrity},
    ecosystem::{Ecosystem, LifecycleEntry, LifecycleKind, Tarball},
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

pub struct PypiEcosystem {
    index: String,
    http: reqwest::Client,
    limits: Limits,
}

impl Default for PypiEcosystem {
    fn default() -> Self {
        Self::new()
    }
}

impl PypiEcosystem {
    pub fn new() -> Self {
        Self {
            index: "https://pypi.org".to_string(),
            http: reqwest::Client::builder()
                .user_agent(concat!("monomi/", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("reqwest client"),
            limits: Limits::default(),
        }
    }

    pub fn with_index(mut self, base: impl Into<String>) -> Self {
        self.index = base.into().trim_end_matches('/').to_string();
        self
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

#[async_trait]
impl Ecosystem for PypiEcosystem {
    fn id(&self) -> EcosystemId {
        EcosystemId::Pypi
    }

    async fn fetch(&self, name: &str, version: &str) -> Result<Tarball> {
        let url = format!(
            "{base}/pypi/{name}/{version}/json",
            base = self.index.trim_end_matches('/')
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
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Fetch(format!("{url}: {e}")))?;
        let urls = json
            .get("urls")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::Fetch(format!("{url}: missing urls[] in Warehouse JSON")))?;
        let sdist = urls
            .iter()
            .find(|u| u.get("packagetype").and_then(|p| p.as_str()) == Some("sdist"))
            .ok_or_else(|| {
                Error::NotFound(format!(
                    "{name}@{version}: no sdist available (wheels only)"
                ))
            })?;
        let download_url = sdist
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Fetch(format!("{url}: sdist entry has no url")))?
            .to_string();
        let filename = sdist.get("filename").and_then(|v| v.as_str()).unwrap_or("");

        // Reject formats we cannot walk yet (.zip sdists exist for
        // some legacy packages). The gzip-tar code path is the only
        // one we support.
        if !filename.ends_with(".tar.gz") && !filename.ends_with(".tgz") {
            return Err(Error::Other(format!(
                "{name}@{version}: unsupported sdist container `{filename}` (tar.gz only)"
            )));
        }
        let bytes = self
            .http
            .get(&download_url)
            .send()
            .await
            .map_err(|e| Error::Fetch(format!("{download_url}: {e}")))?
            .error_for_status()
            .map_err(|e| Error::Fetch(format!("{download_url}: {e}")))?
            .bytes()
            .await
            .map_err(|e| Error::Fetch(format!("{download_url}: {e}")))?
            .to_vec();
        Ok(Tarball {
            source_url: Some(download_url),
            bytes,
        })
    }

    async fn latest_version(&self, name: &str) -> Result<Option<String>> {
        // Warehouse top-level packument: `info.version` is the
        // current "latest" PyPI advertises for the package.
        let url = format!(
            "{base}/pypi/{name}/json",
            base = self.index.trim_end_matches('/')
        );
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
        Ok(json
            .get("info")
            .and_then(|i| i.get("version"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string))
    }

    fn integrity(&self, tar: &Tarball) -> Integrity {
        // PyPI's `digests.sha256` is SHA-256 of the file bytes.
        Integrity::from_bytes(HashAlgo::Sha256, &tar.bytes)
    }

    fn parse_manifest(&self, tar: &Tarball) -> Result<Manifest> {
        let entries = walk_sdist(tar, &self.limits)?;
        let pyproject_bytes = entries
            .iter()
            .find(|e| e.path == "pyproject.toml")
            .map(|e| e.bytes.clone());
        let setup_py_present = entries.iter().any(|e| e.path == "setup.py");
        let setup_cfg_bytes = entries
            .iter()
            .find(|e| e.path == "setup.cfg")
            .map(|e| e.bytes.clone());

        let mut name = String::new();
        let mut version = String::new();
        let mut repository = None;
        let mut homepage = None;
        let mut dependencies: BTreeMap<String, String> = BTreeMap::new();
        let mut scripts: BTreeMap<String, String> = BTreeMap::new();
        let mut raw_json = serde_json::Value::Null;

        // Prefer PEP 621 metadata in pyproject.toml.
        if let Some(bytes) = &pyproject_bytes {
            if let Ok(s) = std::str::from_utf8(bytes) {
                if let Ok(toml_val) = s.parse::<toml::Value>() {
                    if let Some(proj) = toml_val.get("project") {
                        name = proj
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        version = proj
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        if let Some(urls) = proj.get("urls").and_then(|v| v.as_table()) {
                            for (k, v) in urls {
                                if let Some(u) = v.as_str() {
                                    let key = k.to_ascii_lowercase();
                                    if repository.is_none()
                                        && (key.contains("repository") || key.contains("source"))
                                    {
                                        repository = Some(u.to_string());
                                    }
                                    if homepage.is_none()
                                        && (key.contains("homepage") || key.contains("home"))
                                    {
                                        homepage = Some(u.to_string());
                                    }
                                }
                            }
                        }
                        if let Some(deps) = proj.get("dependencies").and_then(|v| v.as_array()) {
                            for d in deps {
                                if let Some(s) = d.as_str() {
                                    // PEP 508 requirement; key on the
                                    // first identifier-ish prefix.
                                    let key = s
                                        .split(|c: char| {
                                            !(c.is_alphanumeric() || c == '_' || c == '-')
                                        })
                                        .next()
                                        .unwrap_or("")
                                        .to_string();
                                    if !key.is_empty() {
                                        dependencies.insert(key, s.to_string());
                                    }
                                }
                            }
                        }
                    }
                    if let Some(bs) = toml_val.get("build-system") {
                        if let Some(be) = bs.get("build-backend").and_then(|v| v.as_str()) {
                            scripts.insert("build-backend".to_string(), be.to_string());
                        }
                    }
                    raw_json = toml_to_json(&toml_val);
                }
            }
        }

        // PKG-INFO fallback for sdists that have no pyproject.toml
        // (or it has neither `project.name` nor `project.version`).
        if (name.is_empty() || version.is_empty()) && entries.iter().any(|e| e.path == "PKG-INFO") {
            if let Some(pkg_info) = entries.iter().find(|e| e.path == "PKG-INFO") {
                if let Ok(s) = std::str::from_utf8(&pkg_info.bytes) {
                    parse_pkg_info(s, &mut name, &mut version, &mut homepage);
                }
            }
        }

        // Surface that setup.py is present so the rule registry can
        // see it via `manifest.scripts` even when there is no
        // pyproject.toml build-backend declared.
        if setup_py_present {
            scripts
                .entry("setup".to_string())
                .or_insert_with(|| "setup.py".to_string());
        }
        if setup_cfg_bytes.is_some() {
            scripts
                .entry("setup-cfg".to_string())
                .or_insert_with(|| "setup.cfg".to_string());
        }

        Ok(Manifest {
            name,
            version,
            repository,
            homepage,
            bin: BTreeMap::new(),
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
        let entries = walk_sdist(tar, &self.limits)?;
        let mut out = Vec::new();

        if let Some(setup_py) = entries.iter().find(|e| e.path == "setup.py") {
            let body = String::from_utf8_lossy(&setup_py.bytes).into_owned();
            out.push(LifecycleEntry {
                name: "setup.py".into(),
                kind: LifecycleKind::InstallTime,
                body,
                path: Some("setup.py".into()),
            });
        }
        // Non-stdlib build-backend → arbitrary code runs at install.
        if let Some(be) = manifest.scripts.get("build-backend") {
            if !is_stdlib_build_backend(be) {
                out.push(LifecycleEntry {
                    name: "build-backend".into(),
                    kind: LifecycleKind::InstallTime,
                    body: format!("build-backend = {be}"),
                    path: Some("pyproject.toml".into()),
                });
            }
        }
        Ok(out)
    }

    fn walk(&self, tar: &Tarball) -> Result<Vec<Entry>> {
        walk_sdist(tar, &self.limits)
    }
}

fn is_stdlib_build_backend(be: &str) -> bool {
    // Distutils/setuptools shipped with the Python stdlib (or installed
    // by default with pip) are the only "trusted" backends. Anything
    // else is an arbitrary library that runs during install.
    matches!(
        be.trim(),
        "setuptools.build_meta"
            | "setuptools.build_meta:__legacy__"
            | "flit_core.buildapi"
            | "hatchling.build"
            | "poetry.core.masonry.api"
            | "pdm.backend"
            | "maturin"
    )
}

fn walk_sdist(tar: &Tarball, limits: &Limits) -> Result<Vec<Entry>> {
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
        // Strip the `<pkg>-<ver>/` top-level directory shared by
        // every well-formed sdist.
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
    if lower.ends_with(".py") {
        return EntryKind::PySource;
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

fn parse_pkg_info(
    text: &str,
    name: &mut String,
    version: &mut String,
    homepage: &mut Option<String>,
) {
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if name.is_empty() && k.eq_ignore_ascii_case("Name") {
                *name = v.to_string();
            } else if version.is_empty() && k.eq_ignore_ascii_case("Version") {
                *version = v.to_string();
            } else if homepage.is_none() && k.eq_ignore_ascii_case("Home-page") {
                *homepage = Some(v.to_string());
            }
        }
    }
}

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

pub fn load_sdist_from_path(path: &std::path::Path) -> Result<Tarball> {
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

    #[test]
    fn parses_pyproject_and_surfaces_setup_py() {
        let pyproject = br#"
[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests>=2.0", "click<9"]

[project.urls]
Repository = "https://example.com/demo.git"

[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
        "#;
        let setup_py = b"from setuptools import setup\nsetup()\n";
        let bytes = build_sdist(
            "demo-0.1.0",
            &[
                ("pyproject.toml", pyproject.as_slice()),
                ("setup.py", setup_py.as_slice()),
                ("demo/__init__.py", b"VERSION = '0.1.0'".as_slice()),
            ],
        );
        let tar = monomi_core::Tarball {
            source_url: None,
            bytes,
        };
        let eco = PypiEcosystem::new();
        let m = eco.parse_manifest(&tar).unwrap();
        assert_eq!(m.name, "demo");
        assert_eq!(m.version, "0.1.0");
        assert_eq!(
            m.repository.as_deref(),
            Some("https://example.com/demo.git")
        );
        assert!(m.dependencies.contains_key("requests"));
        assert!(m.dependencies.contains_key("click"));

        let life = eco.lifecycle_entrypoints(&tar, &m).unwrap();
        // setup.py present → InstallTime. setuptools.build_meta is
        // stdlib-trusted → no extra build-backend lifecycle.
        assert_eq!(life.len(), 1);
        assert_eq!(life[0].name, "setup.py");

        let walked = eco.walk(&tar).unwrap();
        assert!(walked
            .iter()
            .any(|e| e.path == "demo/__init__.py" && e.kind == EntryKind::PySource));
        assert!(walked
            .iter()
            .any(|e| e.path == "pyproject.toml" && e.kind == EntryKind::Toml));
    }

    #[test]
    fn non_stdlib_build_backend_is_a_lifecycle_entry() {
        let pyproject = br#"
[project]
name = "x"
version = "0.0.1"

[build-system]
requires = ["evil-backend"]
build-backend = "evil_backend.api"
        "#;
        let bytes = build_sdist("x-0.0.1", &[("pyproject.toml", pyproject.as_slice())]);
        let tar = monomi_core::Tarball {
            source_url: None,
            bytes,
        };
        let eco = PypiEcosystem::new();
        let m = eco.parse_manifest(&tar).unwrap();
        let life = eco.lifecycle_entrypoints(&tar, &m).unwrap();
        assert_eq!(life.len(), 1);
        assert_eq!(life[0].name, "build-backend");
        assert!(life[0].body.contains("evil_backend.api"));
    }

    #[test]
    fn falls_back_to_pkg_info_when_no_pyproject() {
        let pkg_info =
            b"Metadata-Version: 1.0\nName: legacy\nVersion: 0.0.3\nHome-page: https://x.example\n";
        let bytes = build_sdist(
            "legacy-0.0.3",
            &[
                ("PKG-INFO", pkg_info.as_slice()),
                (
                    "setup.py",
                    b"from setuptools import setup\nsetup(name='legacy', version='0.0.3')\n"
                        .as_slice(),
                ),
            ],
        );
        let tar = monomi_core::Tarball {
            source_url: None,
            bytes,
        };
        let m = PypiEcosystem::new().parse_manifest(&tar).unwrap();
        assert_eq!(m.name, "legacy");
        assert_eq!(m.version, "0.0.3");
        assert_eq!(m.homepage.as_deref(), Some("https://x.example"));
    }

    #[test]
    fn integrity_is_sha256() {
        let tar = monomi_core::Tarball {
            source_url: None,
            bytes: b"hi".to_vec(),
        };
        let i = PypiEcosystem::new().integrity(&tar);
        assert_eq!(i.algo, HashAlgo::Sha256);
        assert!(i.sri().starts_with("sha256-"));
    }
}
