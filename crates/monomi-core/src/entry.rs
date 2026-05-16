use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// JavaScript / TypeScript source file.
    JsSource,
    /// Rust source file (.rs).
    RustSource,
    /// Python source file (.py).
    PySource,
    /// JSON config (package.json, tsconfig.json, etc).
    Json,
    /// TOML config (Cargo.toml, pyproject.toml, etc).
    Toml,
    /// Native binary (Mach-O, ELF, PE, .node, .wasm).
    NativeBinary,
    /// Generic text we didn't classify further.
    Text,
    /// Generic binary blob.
    Binary,
}

impl EntryKind {
    /// True for `EntryKind`s that ecosystem-agnostic text-literal
    /// rules (cloud-metadata host, exfil endpoint, persistence path)
    /// should scan. Centralized so each new ecosystem only has to
    /// add a variant here, not touch every rule.
    pub fn is_scannable_source(self) -> bool {
        matches!(
            self,
            EntryKind::JsSource
                | EntryKind::RustSource
                | EntryKind::PySource
                | EntryKind::Text
                | EntryKind::Json
                | EntryKind::Toml
        )
    }
}

/// A single entry from an extracted tarball.
///
/// `bytes` is held in-memory; the caller (Ecosystem impl) enforces
/// per-entry size limits before constructing this.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Path within the package, relative to the tarball root (typically
    /// stripped of the leading `package/` prefix for npm).
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    pub bytes: Vec<u8>,
}

impl Entry {
    pub fn text(&self) -> Option<&str> {
        std::str::from_utf8(&self.bytes).ok()
    }
}
