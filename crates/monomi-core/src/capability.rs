//! Structured "what can this package do" summary.
//!
//! A `Capability` is a coarse, machine-comparable label that rules
//! attach to the findings they emit. Aggregated onto `Stage1Result`,
//! the resulting `CapabilitySet` becomes a stable summary of the
//! package's observed behavior that downstream consumers — and, in
//! particular, the version-over-version diff rule (M8) — can compare
//! across versions.
//!
//! Capabilities are intentionally coarse. The goal is not to enumerate
//! every API a package touches; it is to give "did this package gain a
//! new dangerous capability vs the previous version?" a precise
//! answer.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// A structured behavior label. `BTreeSet` ordering is used as the
/// canonical serialization order so diffs are stable.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    // ---- lifecycle ----
    /// Any install-time hook is declared (preinstall, install,
    /// postinstall, prepare for npm; build.rs for cargo; setup.py /
    /// PEP 517 backend for pypi; install.ps1 for nuget).
    LifecycleInstall,
    /// Publish-time hook declared (prepublishOnly etc).
    LifecyclePublish,

    // ---- network ----
    /// High-level HTTP client used (fetch / axios / got / node-fetch /
    /// `http(s).get` / `http(s).request`).
    NetHttp,
    /// `XMLHttpRequest` used.
    NetXhr,
    /// Raw socket APIs (`net`, `tls`, `dgram`).
    NetRawSocket,
    /// DNS lookup/resolve.
    NetDns,
    /// Network call observed inside an install-time lifecycle hook.
    /// Stronger signal than `NetHttp` on its own.
    InstallTimeNetwork,

    // ---- process / shell ----
    /// `child_process.spawn / exec / execSync / fork` or shell-out
    /// from a non-lifecycle context.
    ProcSpawn,
    /// Shell-out observed inside an install-time lifecycle hook.
    InstallTimeShell,

    // ---- filesystem ----
    /// `fs.readFile*` / `fs.open*` / `fs.createReadStream` etc.
    FsRead,
    /// Read targeting a sensitive path literal (`~/.ssh/`, `~/.aws/`,
    /// `~/.npmrc`, browser profile, wallet path …).
    FsReadSensitive,
    /// Write targeting a persistence location (LaunchAgents, systemd
    /// user units, crontab, registry run keys …).
    FsWritePersistence,
    /// Self-deleting payload (`fs.unlinkSync(__filename)` shape).
    SelfDelete,

    // ---- env / config ----
    /// Bulk enumeration of `process.env` (Object.keys / entries /
    /// spread / for-in).
    EnvBulkEnum,
    /// Reads a specific high-value env var by name (`NPM_TOKEN`,
    /// `GITHUB_TOKEN`, `AWS_*`, …).
    EnvSecretLookup,

    // ---- dynamic code ----
    /// `eval` / `new Function` / `vm.runIn*`.
    DynamicEval,
    /// `require()` / `import()` with a non-literal argument.
    DynamicRequire,
    /// Large encoded blob (base64/hex, > 1 KB) embedded in source.
    EncodedPayload,

    // ---- binaries / native ----
    /// Bundled `.node` / `.wasm` / Mach-O / ELF / PE not declared in
    /// `bin` / `binary`.
    NativeBinary,

    // ---- domain-specific ----
    /// References cryptocurrency wallet artifacts (Exodus, MetaMask
    /// extension id, `wallet.dat`, seed phrases, …).
    WalletAccess,
    /// Cryptocurrency-miner indicators (stratum URL, known pool host,
    /// CoinHive, Monero address).
    CryptoMiner,
    /// Time-bomb: activation gated on a future date.
    TimeBomb,
    /// Trojan-source bidi override / zero-width / mixed-script
    /// identifier.
    TrojanSource,
}

/// Canonical aggregation of capabilities. `BTreeSet` is used because
/// stable iteration order keeps verdict JSON byte-for-byte
/// reproducible.
pub type CapabilitySet = BTreeSet<Capability>;

impl Capability {
    /// Capabilities that, when *newly* introduced in a version vs the
    /// previous one, are decisive on their own. Used by the M8 diff
    /// rule.
    pub fn is_decisive_on_introduction(self) -> bool {
        matches!(
            self,
            Capability::InstallTimeNetwork
                | Capability::InstallTimeShell
                | Capability::SelfDelete
                | Capability::CryptoMiner
                | Capability::WalletAccess
                | Capability::FsWritePersistence
        )
    }
}
