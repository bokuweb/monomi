use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use monomi_cargo::CargoEcosystem;
use monomi_catalog::{CatalogReader, HttpCatalogReader, LocalDirCatalog};
use monomi_core::{EcosystemId, Status, Verdict};
use monomi_feed::backfill::BackfillItem;
use monomi_feed::FeedConfig;
use monomi_llm::{
    Adjudicator, AnthropicAdjudicator, BudgetConfig, BudgetedAdjudicator, NoopAdjudicator,
    OpenAiCompatAdjudicator, TokenBudget,
};
use monomi_npm::{load_tarball_from_path, NpmEcosystem};
use monomi_nuget::NugetEcosystem;
use monomi_pipeline::analyze;
use monomi_pypi::PypiEcosystem;

#[derive(Parser, Debug)]
#[command(name = "monomi", version, about = "Two-stage supply-chain analyzer")]
struct Cli {
    /// Skip Stage 2 (LLM) even if a provider is configured.
    #[arg(long, global = true)]
    stage1_only: bool,

    /// LLM provider for Stage 2.
    ///
    /// `auto` (default) picks the first available of:
    ///   anthropic  (if ANTHROPIC_API_KEY is set)
    ///   ollama     (if OLLAMA_HOST is set)
    ///   openai     (if OPENAI_API_KEY is set)
    ///   none       (otherwise — Stage 1 only)
    #[arg(long, global = true, value_enum, default_value_t = LlmProvider::Auto)]
    llm: LlmProvider,

    /// Override the LLM model.
    #[arg(long, global = true)]
    llm_model: Option<String>,

    /// Override the LLM base URL (OpenAI-compatible providers).
    #[arg(long, global = true)]
    llm_base_url: Option<String>,

    /// Hourly input-token cap for Stage 2 (0 disables the cap).
    #[arg(long, global = true, default_value_t = 500_000)]
    llm_hourly_input_tokens: u32,

    /// Daily input-token cap for Stage 2 (0 disables the cap).
    #[arg(long, global = true, default_value_t = 5_000_000)]
    llm_daily_input_tokens: u32,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum LlmProvider {
    Auto,
    None,
    Anthropic,
    Openai,
    Ollama,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Scan a local tarball file (`.tgz`).
    Scan {
        path: PathBuf,
        #[arg(long)]
        publish_to: Option<PathBuf>,
    },
    /// Fetch `<name>@<version>` from npm and scan it.
    ScanNpm {
        spec: String,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        publish_to: Option<PathBuf>,
        /// Optional local catalog directory. When supplied, the M8
        /// capability-diff pass runs against the previous versions
        /// of this package recorded in the catalog (block-grade
        /// "this version newly gained a dangerous capability"
        /// signal). Skipped silently when the catalog has no
        /// matching prior verdicts.
        #[arg(long)]
        catalog_dir: Option<PathBuf>,
    },
    /// Fetch `<name>@<version>` from crates.io and scan it.
    ScanCargo {
        spec: String,
        /// Override the `.crate` download base.
        /// Defaults to `https://static.crates.io/crates`.
        #[arg(long)]
        crate_base: Option<String>,
        #[arg(long)]
        publish_to: Option<PathBuf>,
    },
    /// Fetch `<name>==<version>` from PyPI (sdist) and scan it.
    ScanPypi {
        /// `<name>@<version>` or `<name>==<version>`.
        spec: String,
        /// Override the Warehouse index base.
        /// Defaults to `https://pypi.org`.
        #[arg(long)]
        index: Option<String>,
        #[arg(long)]
        publish_to: Option<PathBuf>,
    },
    /// Fetch `<id>@<version>` from NuGet (`.nupkg`) and scan it.
    ScanNuget {
        spec: String,
        /// Override the flat-container base.
        /// Defaults to `https://api.nuget.org/v3-flatcontainer`.
        #[arg(long)]
        flat_base: Option<String>,
        #[arg(long)]
        publish_to: Option<PathBuf>,
    },
    /// Write a verdict JSON file into a catalog directory.
    Publish {
        verdict: PathBuf,
        #[arg(long)]
        catalog_dir: PathBuf,
    },
    /// Look up a verdict in a catalog.
    Lookup {
        spec: String,
        #[arg(long)]
        catalog_dir: Option<PathBuf>,
        #[arg(long, conflicts_with = "catalog_dir")]
        catalog_url: Option<String>,
    },
    /// Subscribe to npm's `_changes` and analyze every new publish.
    Feed {
        /// Catalog directory. `<catalog>/feed-state.json` holds the cursor.
        #[arg(long)]
        catalog_dir: PathBuf,
        /// Maximum in-flight analyses.
        #[arg(long, default_value_t = 4)]
        max_concurrent: usize,
        /// Optional starting sequence (overrides the cursor when set).
        #[arg(long)]
        since: Option<u64>,
        /// Override the `_changes` URL.
        #[arg(long, default_value = "https://replicate.npmjs.com/registry/_changes")]
        changes_url: String,
        /// Override the registry URL.
        #[arg(long, default_value = "https://registry.npmjs.org")]
        registry_url: String,
    },
    /// Compare two versions of a package — capability and finding deltas.
    ///
    /// Each side is resolved in order: catalog first (if `--catalog-dir`
    /// or `--catalog-url` is given), then registry fetch + Stage 1 scan.
    /// Both sides MUST resolve to the same package name. Stage 2 is
    /// skipped by default (this is a static-comparison view); pass
    /// `--with-stage2` to include LLM verdicts on each side.
    Diff {
        /// Which registry to query.
        #[arg(long, value_enum, default_value_t = DiffEco::Npm)]
        ecosystem: DiffEco,
        /// First version: `<name>@<version>` or `<version>` if `--name`.
        a: String,
        /// Second version: same shape as `a`.
        b: String,
        /// Shared package name when `a` and `b` are bare versions.
        #[arg(long)]
        name: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = DiffFormat::Text)]
        format: DiffFormat,
        /// Prefer this catalog before re-scanning.
        #[arg(long)]
        catalog_dir: Option<PathBuf>,
        /// HTTP catalog (e.g. R2 bucket) checked when --catalog-dir absent.
        #[arg(long, conflicts_with = "catalog_dir")]
        catalog_url: Option<String>,
        /// Run Stage 2 (LLM) on each side. Off by default — diffing is
        /// a Stage 1 view, and Stage 2 doubles the cost & token spend.
        #[arg(long)]
        with_stage2: bool,
    },
    /// Analyze an explicit list of packages (one per line).
    Backfill {
        /// File with `<name>` or `<name>@<version>` per line; `-` for stdin.
        list: PathBuf,
        /// Which registry to query.
        #[arg(long, value_enum, default_value_t = BackfillEco::Npm)]
        ecosystem: BackfillEco,
        #[arg(long)]
        catalog_dir: PathBuf,
        #[arg(long, default_value_t = 4)]
        max_concurrent: usize,
        /// Override the registry URL. Defaults per-ecosystem:
        ///   npm   → https://registry.npmjs.org
        ///   cargo → https://static.crates.io/crates
        ///   pypi  → https://pypi.org
        #[arg(long)]
        registry_url: Option<String>,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum BackfillEco {
    Npm,
    Cargo,
    Pypi,
    Nuget,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum DiffEco {
    Npm,
    Cargo,
    Pypi,
    Nuget,
}

impl DiffEco {
    fn id(self) -> EcosystemId {
        match self {
            DiffEco::Npm => EcosystemId::Npm,
            DiffEco::Cargo => EcosystemId::Cargo,
            DiffEco::Pypi => EcosystemId::Pypi,
            DiffEco::Nuget => EcosystemId::Nuget,
        }
    }
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum DiffFormat {
    Text,
    Json,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match real_main(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

async fn real_main(cli: Cli) -> Result<ExitCode> {
    let adjudicator = pick_adjudicator(&cli);

    match cli.cmd {
        Cmd::Scan { path, publish_to } => {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.to_ascii_lowercase());
            let v = match ext.as_deref() {
                Some("crate") => {
                    let eco = CargoEcosystem::new();
                    let tar = monomi_cargo::load_crate_from_path(&path)
                        .with_context(|| format!("read {}", path.display()))?;
                    analyze(&eco, tar, adjudicator.as_ref()).await?
                }
                Some("nupkg") => {
                    let eco = NugetEcosystem::new();
                    let tar = monomi_nuget::load_nupkg_from_path(&path)
                        .with_context(|| format!("read {}", path.display()))?;
                    analyze(&eco, tar, adjudicator.as_ref()).await?
                }
                _ => {
                    let eco = NpmEcosystem::new();
                    let tar = load_tarball_from_path(&path)
                        .with_context(|| format!("read {}", path.display()))?;
                    analyze(&eco, tar, adjudicator.as_ref()).await?
                }
            };
            publish_if_requested(&v, publish_to).await?;
            print_and_exit(v)
        }
        Cmd::ScanNpm {
            spec,
            registry,
            publish_to,
            catalog_dir,
        } => {
            let (name, version) = parse_spec(&spec)?;
            let mut eco = NpmEcosystem::new();
            if let Some(r) = registry {
                eco = eco.with_registry(r);
            }
            let tar = monomi_core::Ecosystem::fetch(&eco, &name, &version)
                .await
                .with_context(|| format!("fetch {name}@{version}"))?;
            let v = match catalog_dir {
                Some(dir) => {
                    let catalog = LocalDirCatalog::new(dir);
                    monomi_pipeline::analyze_with_catalog(
                        &eco,
                        tar,
                        adjudicator.as_ref(),
                        &catalog,
                        monomi_pipeline::DEFAULT_BASELINE_WINDOW,
                    )
                    .await?
                }
                None => analyze(&eco, tar, adjudicator.as_ref()).await?,
            };
            publish_if_requested(&v, publish_to).await?;
            print_and_exit(v)
        }
        Cmd::ScanCargo {
            spec,
            crate_base,
            publish_to,
        } => {
            let (name, version) = parse_spec(&spec)?;
            let mut eco = CargoEcosystem::new();
            if let Some(b) = crate_base {
                eco = eco.with_crate_base(b);
            }
            let tar = monomi_core::Ecosystem::fetch(&eco, &name, &version)
                .await
                .with_context(|| format!("fetch {name}@{version}"))?;
            let v = analyze(&eco, tar, adjudicator.as_ref()).await?;
            publish_if_requested(&v, publish_to).await?;
            print_and_exit(v)
        }
        Cmd::ScanPypi {
            spec,
            index,
            publish_to,
        } => {
            // Accept both `name@version` and the more pythonic
            // `name==version`. Normalize to `@`-separated.
            let normalized = spec.replacen("==", "@", 1);
            let (name, version) = parse_spec(&normalized)?;
            let mut eco = PypiEcosystem::new();
            if let Some(i) = index {
                eco = eco.with_index(i);
            }
            let tar = monomi_core::Ecosystem::fetch(&eco, &name, &version)
                .await
                .with_context(|| format!("fetch {name}@{version}"))?;
            let v = analyze(&eco, tar, adjudicator.as_ref()).await?;
            publish_if_requested(&v, publish_to).await?;
            print_and_exit(v)
        }
        Cmd::ScanNuget {
            spec,
            flat_base,
            publish_to,
        } => {
            let (name, version) = parse_spec(&spec)?;
            let mut eco = NugetEcosystem::new();
            if let Some(b) = flat_base {
                eco = eco.with_flat_base(b);
            }
            let tar = monomi_core::Ecosystem::fetch(&eco, &name, &version)
                .await
                .with_context(|| format!("fetch {name}@{version}"))?;
            let v = analyze(&eco, tar, adjudicator.as_ref()).await?;
            publish_if_requested(&v, publish_to).await?;
            print_and_exit(v)
        }
        Cmd::Publish {
            verdict,
            catalog_dir,
        } => {
            use monomi_catalog::CatalogWriter;
            let body =
                std::fs::read(&verdict).with_context(|| format!("read {}", verdict.display()))?;
            let v: Verdict = serde_json::from_slice(&body).context("parse verdict json")?;
            LocalDirCatalog::new(catalog_dir)
                .put_verdict(&v)
                .await
                .context("publish verdict")?;
            eprintln!("ok");
            Ok(ExitCode::from(0))
        }
        Cmd::Lookup {
            spec,
            catalog_dir,
            catalog_url,
        } => {
            let (name, version) = parse_spec(&spec)?;
            let reader: Box<dyn CatalogReader> = match (catalog_dir, catalog_url) {
                (Some(d), _) => Box::new(LocalDirCatalog::new(d)),
                (None, Some(u)) => Box::new(HttpCatalogReader::new(u)),
                (None, None) => return Err(anyhow!("provide --catalog-dir or --catalog-url")),
            };
            let v = reader
                .lookup_by_nv(EcosystemId::Npm, &name, &version)
                .await
                .context("catalog lookup")?;
            match v {
                Some(verdict) => print_and_exit(verdict),
                None => {
                    eprintln!("not found: {name}@{version}");
                    Ok(ExitCode::from(3))
                }
            }
        }
        Cmd::Feed {
            catalog_dir,
            max_concurrent,
            since,
            changes_url,
            registry_url,
        } => {
            let state_path = catalog_dir.join("feed-state.json");
            let catalog: Arc<dyn monomi_feed::worker::CatalogReadWrite> =
                Arc::new(LocalDirCatalog::new(catalog_dir));
            let mut cfg = FeedConfig::npm_defaults(state_path);
            cfg.changes_url = changes_url;
            cfg.registry_url = registry_url;
            cfg.max_concurrent = max_concurrent;
            cfg.since = since;
            monomi_feed::run(cfg, catalog, adjudicator).await?;
            Ok(ExitCode::from(0))
        }
        Cmd::Diff {
            ecosystem,
            a,
            b,
            name,
            format,
            catalog_dir,
            catalog_url,
            with_stage2,
        } => {
            let (name_a, ver_a) = parse_diff_spec(&a, name.as_deref())?;
            let (name_b, ver_b) = parse_diff_spec(&b, name.as_deref())?;
            if name_a != name_b {
                return Err(anyhow!(
                    "diff requires the same package on both sides; got `{name_a}` vs `{name_b}`"
                ));
            }
            let catalog_reader: Option<Box<dyn CatalogReader>> = match (&catalog_dir, &catalog_url)
            {
                (Some(d), _) => Some(Box::new(LocalDirCatalog::new(d.clone()))),
                (None, Some(u)) => Some(Box::new(HttpCatalogReader::new(u.clone()))),
                (None, None) => None,
            };
            let stage2_adj: &dyn monomi_llm::Adjudicator = if with_stage2 {
                adjudicator.as_ref()
            } else {
                &monomi_llm::NoopAdjudicator
            };
            let va = resolve_verdict_for_diff(
                ecosystem,
                &name_a,
                &ver_a,
                catalog_reader.as_deref(),
                stage2_adj,
            )
            .await
            .with_context(|| format!("resolve `{name_a}@{ver_a}`"))?;
            let vb = resolve_verdict_for_diff(
                ecosystem,
                &name_b,
                &ver_b,
                catalog_reader.as_deref(),
                stage2_adj,
            )
            .await
            .with_context(|| format!("resolve `{name_b}@{ver_b}`"))?;
            let d = monomi_pipeline::diff_verdicts(&va, &vb);
            match format {
                DiffFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&d)?);
                }
                DiffFormat::Text => render_diff_text(&d),
            }
            // Exit code: 0 if no functional change, 1 if status got
            // worse (Clean → Warn/Block, Warn → Block).
            let worse = matches!(
                (va.final_verdict.status, vb.final_verdict.status),
                (Status::Clean, Status::Warn | Status::Block) | (Status::Warn, Status::Block)
            );
            Ok(ExitCode::from(if worse { 1 } else { 0 }))
        }
        Cmd::Backfill {
            list,
            ecosystem,
            catalog_dir,
            max_concurrent,
            registry_url,
        } => {
            let items = read_backfill_list(&list)?;
            let catalog: Arc<dyn monomi_feed::worker::CatalogReadWrite> =
                Arc::new(LocalDirCatalog::new(catalog_dir));
            let stats = match ecosystem {
                BackfillEco::Npm => {
                    let mut eco = NpmEcosystem::new();
                    if let Some(u) = registry_url {
                        eco = eco.with_registry(u);
                    }
                    monomi_feed::backfill::run(eco, items, max_concurrent, catalog, adjudicator)
                        .await?
                }
                BackfillEco::Cargo => {
                    let mut eco = CargoEcosystem::new();
                    if let Some(u) = registry_url {
                        eco = eco.with_crate_base(u);
                    }
                    monomi_feed::backfill::run(eco, items, max_concurrent, catalog, adjudicator)
                        .await?
                }
                BackfillEco::Pypi => {
                    let mut eco = PypiEcosystem::new();
                    if let Some(u) = registry_url {
                        eco = eco.with_index(u);
                    }
                    monomi_feed::backfill::run(eco, items, max_concurrent, catalog, adjudicator)
                        .await?
                }
                BackfillEco::Nuget => {
                    let mut eco = NugetEcosystem::new();
                    if let Some(u) = registry_url {
                        eco = eco.with_flat_base(u);
                    }
                    monomi_feed::backfill::run(eco, items, max_concurrent, catalog, adjudicator)
                        .await?
                }
            };
            eprintln!(
                "backfill ({:?}): analyzed={} already_present={} missing={} failed={}",
                ecosystem, stats.analyzed, stats.already_present, stats.missing, stats.failed
            );
            Ok(if stats.failed > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::from(0)
            })
        }
    }
}

async fn publish_if_requested(v: &Verdict, dir: Option<PathBuf>) -> Result<()> {
    use monomi_catalog::CatalogWriter;
    if let Some(dir) = dir {
        LocalDirCatalog::new(dir)
            .put_verdict(v)
            .await
            .context("publish verdict")?;
    }
    Ok(())
}

fn print_and_exit(v: Verdict) -> Result<ExitCode> {
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(match v.final_verdict.status {
        Status::Clean | Status::Warn => ExitCode::from(0),
        Status::Block => ExitCode::from(1),
    })
}

fn read_backfill_list(path: &std::path::Path) -> Result<Vec<BackfillItem>> {
    let text = if path == std::path::Path::new("-") {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    } else {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
    };
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, version) = match line.rfind('@').filter(|i| *i > 0) {
            Some(at) => {
                let (n, v) = line.split_at(at);
                (n.to_string(), Some(v[1..].to_string()))
            }
            None => (line.to_string(), None),
        };
        out.push(BackfillItem { name, version });
    }
    Ok(out)
}

fn pick_adjudicator(cli: &Cli) -> Arc<dyn Adjudicator> {
    if cli.stage1_only {
        return Arc::new(NoopAdjudicator);
    }
    let provider = match cli.llm {
        LlmProvider::Auto => auto_detect_provider(),
        p => p,
    };
    let inner = build_adjudicator(
        provider,
        cli.llm_model.as_deref(),
        cli.llm_base_url.as_deref(),
    );
    // Wrap with a per-process token budget unless both caps are
    // explicitly disabled with 0.
    if cli.llm_hourly_input_tokens == 0 && cli.llm_daily_input_tokens == 0 {
        return inner;
    }
    // 0 means "no cap on this axis" — translate to u32::MAX so the
    // arithmetic in TokenBudget doesn't have to special-case it.
    let cfg = BudgetConfig {
        hourly_input_tokens: cap_or_max(cli.llm_hourly_input_tokens),
        hourly_output_tokens: cap_or_max(cli.llm_hourly_input_tokens / 16),
        daily_input_tokens: cap_or_max(cli.llm_daily_input_tokens),
        daily_output_tokens: cap_or_max(cli.llm_daily_input_tokens / 16),
        per_call_output_reserve: 1024,
    };
    let budget = Arc::new(TokenBudget::new(cfg));
    Arc::new(BudgetedAdjudicator::new(inner, budget))
}

fn cap_or_max(n: u32) -> u32 {
    if n == 0 {
        u32::MAX
    } else {
        n
    }
}

fn auto_detect_provider() -> LlmProvider {
    if env_nonempty("ANTHROPIC_API_KEY") {
        LlmProvider::Anthropic
    } else if env_nonempty("OLLAMA_HOST") {
        LlmProvider::Ollama
    } else if env_nonempty("OPENAI_API_KEY") {
        LlmProvider::Openai
    } else {
        LlmProvider::None
    }
}

fn env_nonempty(k: &str) -> bool {
    std::env::var(k).map(|v| !v.is_empty()).unwrap_or(false)
}

fn build_adjudicator(
    provider: LlmProvider,
    model_override: Option<&str>,
    base_url_override: Option<&str>,
) -> Arc<dyn Adjudicator> {
    match provider {
        LlmProvider::Auto | LlmProvider::None => Arc::new(NoopAdjudicator),

        LlmProvider::Anthropic => match std::env::var("ANTHROPIC_API_KEY") {
            Ok(k) if !k.is_empty() => {
                let mut a = AnthropicAdjudicator::new(k);
                if let Some(m) = model_override {
                    a = a.with_model(m);
                }
                Arc::new(a)
            }
            _ => {
                tracing::warn!("ANTHROPIC_API_KEY not set; falling back to Stage 1 only");
                Arc::new(NoopAdjudicator)
            }
        },

        LlmProvider::Openai => {
            let key = std::env::var("OPENAI_API_KEY")
                .ok()
                .filter(|k| !k.is_empty());
            if key.is_none() {
                tracing::warn!("OPENAI_API_KEY not set; falling back to Stage 1 only");
                return Arc::new(NoopAdjudicator);
            }
            let base = base_url_override
                .map(str::to_string)
                .or_else(|| std::env::var("OPENAI_BASE_URL").ok())
                .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
            let model = model_override
                .map(str::to_string)
                .or_else(|| std::env::var("OPENAI_MODEL").ok())
                .unwrap_or_else(|| "gpt-4.1-mini".to_string());
            Arc::new(OpenAiCompatAdjudicator::new(base, key, model))
        }

        LlmProvider::Ollama => {
            let model = model_override
                .map(str::to_string)
                .or_else(|| std::env::var("OLLAMA_MODEL").ok())
                .unwrap_or_else(|| "llama3.1".to_string());
            let adj = match base_url_override {
                Some(b) => OpenAiCompatAdjudicator::new(b, None, model),
                None => OpenAiCompatAdjudicator::ollama(model),
            };
            Arc::new(adj)
        }
    }
}

fn parse_spec(s: &str) -> Result<(String, String)> {
    let at = s
        .rfind('@')
        .filter(|i| *i > 0)
        .ok_or_else(|| anyhow!("expected `<name>@<version>`, got `{s}`"))?;
    let (name, version_with_at) = s.split_at(at);
    Ok((name.to_string(), version_with_at[1..].to_string()))
}

/// Parse a `monomi diff` side: either `<name>@<version>` (`name`
/// argument ignored), or a bare `<version>` paired with `--name`.
fn parse_diff_spec(s: &str, shared_name: Option<&str>) -> Result<(String, String)> {
    if s.contains('@') {
        parse_spec(s)
    } else if let Some(n) = shared_name {
        Ok((n.to_string(), s.to_string()))
    } else {
        Err(anyhow!(
            "version `{s}` has no `@`; pass `<name>@<version>` or use `--name`"
        ))
    }
}

/// Resolve a verdict for the diff: catalog first when available,
/// otherwise fetch the tarball and scan. Stage 2 is honored when
/// the caller passes a real adjudicator (the diff path uses
/// `NoopAdjudicator` by default).
async fn resolve_verdict_for_diff(
    eco: DiffEco,
    name: &str,
    version: &str,
    catalog: Option<&dyn CatalogReader>,
    adjudicator: &dyn monomi_llm::Adjudicator,
) -> Result<Verdict> {
    if let Some(c) = catalog {
        if let Some(v) = c.lookup_by_nv(eco.id(), name, version).await? {
            return Ok(v);
        }
    }
    // Catalog miss (or no catalog): scan fresh.
    match eco {
        DiffEco::Npm => {
            let e = NpmEcosystem::new();
            let tar = monomi_core::Ecosystem::fetch(&e, name, version).await?;
            Ok(analyze(&e, tar, adjudicator).await?)
        }
        DiffEco::Cargo => {
            let e = CargoEcosystem::new();
            let tar = monomi_core::Ecosystem::fetch(&e, name, version).await?;
            Ok(analyze(&e, tar, adjudicator).await?)
        }
        DiffEco::Pypi => {
            let e = PypiEcosystem::new();
            let tar = monomi_core::Ecosystem::fetch(&e, name, version).await?;
            Ok(analyze(&e, tar, adjudicator).await?)
        }
        DiffEco::Nuget => {
            let e = NugetEcosystem::new();
            let tar = monomi_core::Ecosystem::fetch(&e, name, version).await?;
            Ok(analyze(&e, tar, adjudicator).await?)
        }
    }
}

/// Human-readable text rendering for `monomi diff`. Designed to be
/// readable in a terminal without color escapes — sakimori scrapes
/// our stdout in CI, and pre-coloring breaks that.
fn render_diff_text(d: &monomi_pipeline::VerdictDiff) {
    println!("{}@{} → {}@{}", d.a.name, d.a.version, d.b.name, d.b.version);
    println!(
        "  stage1 verdict : {:?} → {:?}{}",
        d.a.stage1_verdict,
        d.b.stage1_verdict,
        if d.stage1_verdict_changed { "  *" } else { "" }
    );
    println!(
        "  final status   : {:?} → {:?}{}",
        d.a.final_status,
        d.b.final_status,
        if d.final_status_changed { "  *" } else { "" }
    );
    println!(
        "  score          : {} → {}  ({:+})",
        d.a.score, d.b.score, d.score_delta
    );
    println!(
        "  findings       : {} → {}",
        d.a.finding_count, d.b.finding_count
    );
    println!(
        "  capabilities   : {} → {}",
        d.a.capability_count, d.b.capability_count
    );

    if !d.capabilities.introduced.is_empty() {
        println!();
        println!("capabilities introduced in {}:", d.b.version);
        for c in &d.capabilities.introduced {
            let flag = if c.is_decisive_on_introduction() {
                " [decisive-on-introduction]"
            } else {
                ""
            };
            println!("  + {c:?}{flag}");
        }
    }
    if !d.capabilities.removed.is_empty() {
        println!();
        println!("capabilities removed in {}:", d.b.version);
        for c in &d.capabilities.removed {
            println!("  - {c:?}");
        }
    }
    if !d.findings.added.is_empty() {
        println!();
        println!("rules newly firing in {}:", d.b.version);
        for r in &d.findings.added {
            println!("  + {} ({:?})", r.rule_id, r.severity);
        }
    }
    if !d.findings.removed.is_empty() {
        println!();
        println!("rules no longer firing in {}:", d.b.version);
        for r in &d.findings.removed {
            println!("  - {} ({:?})", r.rule_id, r.severity);
        }
    }
    if !d.findings.severity_changes.is_empty() {
        println!();
        println!("severity changes:");
        for c in &d.findings.severity_changes {
            println!("  {} : {:?} → {:?}", c.rule_id, c.from, c.to);
        }
    }
    if d.capabilities.introduced.is_empty()
        && d.capabilities.removed.is_empty()
        && d.findings.added.is_empty()
        && d.findings.removed.is_empty()
        && d.findings.severity_changes.is_empty()
    {
        println!();
        println!("no functional change in detection surface.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_spec() {
        let (n, v) = parse_spec("left-pad@1.3.0").unwrap();
        assert_eq!(n, "left-pad");
        assert_eq!(v, "1.3.0");
    }

    #[test]
    fn parses_scoped_spec() {
        let (n, v) = parse_spec("@scope/pkg@2.0.0-rc.1").unwrap();
        assert_eq!(n, "@scope/pkg");
        assert_eq!(v, "2.0.0-rc.1");
    }

    #[test]
    fn rejects_unversioned_spec() {
        assert!(parse_spec("left-pad").is_err());
    }
}
