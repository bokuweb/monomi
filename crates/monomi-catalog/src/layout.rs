use base64::Engine;
use monomi_core::{ArtifactId, EcosystemId, Integrity};
use serde::{Deserialize, Serialize};

use crate::{CatalogError, Result};

/// Compute the primary content-addressed path for a verdict.
///
/// `verdicts/by-integrity/<algo>/<aa>/<rest>.json`
///
/// `aa` is the first two hex chars of the digest (base64url-decoded
/// then hex-encoded), so a flat directory never exceeds 256 children.
pub fn by_integrity_path(integrity: &Integrity) -> Result<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&integrity.digest_b64)
        .map_err(|e| CatalogError::InvalidIntegrity(format!("base64: {e}")))?;
    if raw.is_empty() {
        return Err(CatalogError::InvalidIntegrity("empty digest".into()));
    }
    let hex = hex_encode(&raw);
    let (head, tail) = hex.split_at(2);
    Ok(format!(
        "verdicts/by-integrity/{algo}/{head}/{tail}.json",
        algo = integrity.algo.name(),
    ))
}

/// Convenience-pointer path keyed by (ecosystem, name, version).
///
/// `verdicts/<eco>/<name>/<version>.json`. Scoped npm names like
/// `@scope/pkg` are kept as a single path segment (the `/` is
/// URL-encoded so registries don't need a per-scope directory level).
pub fn nv_pointer_path(eco: EcosystemId, name: &str, version: &str) -> String {
    let safe_name = name.replace('@', "%40").replace('/', "%2F");
    format!(
        "verdicts/{eco}/{name}/{version}.json",
        eco = eco.as_str(),
        name = safe_name,
        version = version,
    )
}

/// Rolling index of recently-published verdicts (24h window).
pub fn latest_index_path() -> &'static str {
    "index/latest.jsonl"
}

/// On-disk body of an N+V pointer file. Tiny so the pointer GET is
/// almost free, and forwards the caller to the canonical hash path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvPointer {
    pub artifact: ArtifactId,
    /// Catalog-relative path of the canonical verdict
    /// (`verdicts/by-integrity/...`).
    pub verdict_path: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use monomi_core::HashAlgo;

    #[test]
    fn by_integrity_path_shards_by_first_byte() {
        // sha512("") = cf83e1357...
        let i = Integrity::from_bytes(HashAlgo::Sha512, b"");
        let p = by_integrity_path(&i).unwrap();
        assert!(p.starts_with("verdicts/by-integrity/sha512/cf/"));
        assert!(p.ends_with(".json"));
        // The shard prefix is exactly 2 hex chars.
        let shard = p
            .strip_prefix("verdicts/by-integrity/sha512/")
            .unwrap()
            .split('/')
            .next()
            .unwrap();
        assert_eq!(shard.len(), 2);
    }

    #[test]
    fn nv_pointer_handles_scope() {
        let p = nv_pointer_path(EcosystemId::Npm, "@scope/pkg", "1.0.0");
        assert_eq!(p, "verdicts/npm/%40scope%2Fpkg/1.0.0.json");
    }

    #[test]
    fn invalid_integrity_rejected() {
        let i = Integrity {
            algo: HashAlgo::Sha512,
            digest_b64: "@@not base64@@".into(),
        };
        assert!(by_integrity_path(&i).is_err());
    }
}
