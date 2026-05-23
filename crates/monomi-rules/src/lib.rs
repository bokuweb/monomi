//! Stage 1 deterministic rules.
//!
//! Initial slice from `architecture.md`'s V1 table:
//! - `NPM001`  any lifecycle script present (Info)
//! - `NPM005`  large base64/hex blob + `eval`/`Function`/`vm.runIn*` (Critical)
//! - `NPM006`  hardcoded cloud-metadata host (Critical)
//!
//! More rules will land per the V1 table.

mod bundled_deps;
mod cargo_build_rs;
mod cargo_include_payload;
mod cargo_proc_macro;
mod cargo_proc_macro_source;
mod chmod_executable;
mod cloud_metadata;
mod corpus;
mod crypto_miner;
mod dangerous_apis;
mod destructive_fs;
mod dns_exfil;
mod dynamic_require;
mod encoded_url;
mod env_exfil_flow;
mod env_harvest;
mod eval_atob;
mod eval_blob;
mod files_mismatch;
mod hidden_unicode;
mod install_http;
mod known_exfil;
mod lifecycle_present;
mod main_module_branch;
mod metadata_smuggling;
mod minified_no_source;
mod native_binary;
mod nuget_install_ps1;
mod nuget_tools_dll;
mod persistence_paths;
mod privesc_paths;
mod publish_time;
mod pypi_setup;
mod raw_github_fetch;
mod recency;
mod registry_write;
mod require_cache_mutation;
mod runner;
mod secret_material;
mod self_delete;
mod setuid_binary;
mod shell_pipe;
mod time_bomb;
mod token_theft;
mod typosquat;
mod v8_internal;
mod wallet_drainer;

pub use bundled_deps::BundleDependenciesDeclared;
pub use cargo_build_rs::{BuildRsDangerousApi, BuildRsPresent};
pub use cargo_include_payload::BuildRsIncludePayload;
pub use cargo_proc_macro::ProcMacroCrate;
pub use cargo_proc_macro_source::{ProcMacroFsAccess, ProcMacroNetAccess, ProcMacroProcessSpawn};
pub use chmod_executable::InstallTimeChmodExec;
pub use cloud_metadata::CloudMetadataLiteral;
pub use corpus::default_corpus;
pub use crypto_miner::CryptoMinerLiteral;
pub use dangerous_apis::DangerousLifecycleApi;
pub use destructive_fs::DestructiveFsTraversal;
pub use dns_exfil::DnsExfil;
pub use dynamic_require::DynamicRequire;
pub use encoded_url::EncodedUrlBytes;
pub use env_exfil_flow::EnvExfilFlow;
pub use env_harvest::EnvHarvest;
pub use eval_atob::EvalAtobChain;
pub use eval_blob::EvalLargeBlob;
pub use files_mismatch::FilesFieldMismatch;
pub use hidden_unicode::HiddenUnicode;
pub use install_http::InstallTimeOutboundHttp;
pub use known_exfil::KnownExfilEndpoint;
pub use lifecycle_present::LifecyclePresent;
pub use main_module_branch::MainModuleBranch;
pub use metadata_smuggling::MetadataPayloadSmuggling;
pub use minified_no_source::MinifiedNoSource;
pub use native_binary::NativeBinaryUndeclared;
pub use nuget_install_ps1::{InstallPs1DangerousApi, InstallPs1Present};
pub use nuget_tools_dll::ToolsNativeBinary;
pub use persistence_paths::PersistencePathLiteral;
pub use privesc_paths::PrivescPathLiteral;
pub use publish_time::PublishTimeHostility;
pub use pypi_setup::{SetupPyDangerousApi, SetupPyPresent};
pub use raw_github_fetch::RawScmFetch;
pub use recency::RecencySignals;
pub use registry_write::InstallTimeRegistryWrite;
pub use require_cache_mutation::RequireCacheMutation;
pub use runner::{run, RunOutcome, RULESET_VERSION};
pub use secret_material::SecretMaterialLiteral;
pub use self_delete::SelfDeletePayload;
pub use setuid_binary::SetuidBinaryInTarball;
pub use shell_pipe::LifecycleShellPipe;
pub use time_bomb::TimeBombActivation;
pub use token_theft::CiTokenTheft;
pub use typosquat::TyposquatCandidate;
pub use v8_internal::V8InternalAccess;
pub use wallet_drainer::WalletDrainerLiteral;

use monomi_core::Rule;

/// All Stage 1 rules that ship with monomi V1.
///
/// The `Rule::applies_to(ecosystem)` filter takes care of routing
/// each rule to only the registries it makes sense for, so a single
/// shared ruleset can serve npm + cargo (and future ecosystems).
pub fn default_ruleset() -> Vec<Box<dyn Rule>> {
    vec![
        // npm-only
        Box::new(LifecyclePresent),
        Box::new(DangerousLifecycleApi),
        Box::new(EnvHarvest),
        Box::new(EvalLargeBlob::default()),
        Box::new(NativeBinaryUndeclared),
        Box::new(WalletDrainerLiteral),
        Box::new(CiTokenTheft),
        Box::new(BundleDependenciesDeclared),
        Box::new(DynamicRequire),
        Box::new(TyposquatCandidate::default()),
        Box::new(EncodedUrlBytes),
        Box::new(RecencySignals::default()),
        Box::new(RawScmFetch),
        Box::new(SelfDeletePayload),
        Box::new(LifecycleShellPipe),
        Box::new(EvalAtobChain),
        Box::new(FilesFieldMismatch::default()),
        Box::new(HiddenUnicode),
        Box::new(InstallTimeOutboundHttp),
        Box::new(CryptoMinerLiteral),
        Box::new(DnsExfil),
        Box::new(MetadataPayloadSmuggling),
        Box::new(PublishTimeHostility),
        Box::new(TimeBombActivation),
        // M13a — CVE-retrospective cluster
        Box::new(SecretMaterialLiteral),
        Box::new(InstallTimeRegistryWrite),
        Box::new(InstallTimeChmodExec),
        // M13c — dataflow-lite (NPM041)
        Box::new(EnvExfilFlow),
        // M13b — CVE-retrospective cluster (continued: NPM037-046)
        Box::new(MainModuleBranch),
        Box::new(RequireCacheMutation),
        Box::new(DestructiveFsTraversal),
        Box::new(V8InternalAccess),
        Box::new(SetuidBinaryInTarball),
        // plan.md threat-model item 5 — source divergence
        Box::new(MinifiedNoSource),
        // cargo-only
        Box::new(BuildRsPresent),
        Box::new(BuildRsDangerousApi),
        Box::new(ProcMacroCrate),
        Box::new(BuildRsIncludePayload),
        // M11 — proc-macro source surface
        Box::new(ProcMacroProcessSpawn),
        Box::new(ProcMacroFsAccess),
        Box::new(ProcMacroNetAccess),
        // pypi-only
        Box::new(SetupPyPresent),
        Box::new(SetupPyDangerousApi),
        // nuget-only
        Box::new(InstallPs1Present),
        Box::new(InstallPs1DangerousApi),
        Box::new(ToolsNativeBinary),
        // ecosystem-agnostic literal patterns
        Box::new(CloudMetadataLiteral),
        Box::new(KnownExfilEndpoint),
        Box::new(PersistencePathLiteral),
        Box::new(PrivescPathLiteral),
    ]
}
