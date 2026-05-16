use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EcosystemId {
    Npm,
    Cargo,
    Pypi,
    Nuget,
}

impl EcosystemId {
    pub fn as_str(self) -> &'static str {
        match self {
            EcosystemId::Npm => "npm",
            EcosystemId::Cargo => "cargo",
            EcosystemId::Pypi => "pypi",
            EcosystemId::Nuget => "nuget",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgo {
    Sha256,
    Sha512,
}

impl HashAlgo {
    pub fn name(self) -> &'static str {
        match self {
            HashAlgo::Sha256 => "sha256",
            HashAlgo::Sha512 => "sha512",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Integrity {
    pub algo: HashAlgo,
    /// Standard base64 (not base64url), matching npm's SRI form.
    pub digest_b64: String,
}

impl Integrity {
    pub fn sri(&self) -> String {
        format!("{}-{}", self.algo.name(), self.digest_b64)
    }

    pub fn from_bytes(algo: HashAlgo, bytes: &[u8]) -> Self {
        let digest = match algo {
            HashAlgo::Sha256 => {
                let mut h = Sha256::new();
                h.update(bytes);
                h.finalize().to_vec()
            }
            HashAlgo::Sha512 => {
                let mut h = Sha512::new();
                h.update(bytes);
                h.finalize().to_vec()
            }
        };
        Self {
            algo,
            digest_b64: base64::engine::general_purpose::STANDARD.encode(digest),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactId {
    pub ecosystem: EcosystemId,
    pub name: String,
    pub version: String,
    pub integrity: Integrity,
}
