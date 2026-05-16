# monomi — architecture

Companion to `plan.md`. This document is concrete enough that you
could start typing crates from it.

## Crate layout

```
monomi/
├── Cargo.toml                 # workspace
├── crates/
│   ├── monomi-core/           # ecosystem-neutral types, Verdict,
│   │                          #   Rule trait, analysis context
│   ├── monomi-rules/          # all Stage 1 rule implementations,
│   │                          #   indexed by ecosystem
│   ├── monomi-npm/            # npm Ecosystem impl: tarball fetch,
│   │                          #   package.json parsing, lifecycle
│   │                          #   extraction, JS-specific walkers
│   ├── monomi-cargo/          # (V2) crates.io Ecosystem impl
│   ├── monomi-pypi/           # (V3)
│   ├── monomi-nuget/          # (V4)
│   ├── monomi-llm/            # Stage 2 client (Anthropic SDK
│   │                          #   wrapper, context builder, schema)
│   ├── monomi-catalog/        # R2 reader + writer, verdict layout,
│   │                          #   index file management
│   ├── monomi-feed/           # registry change-stream daemon
│   ├── monomi-cli/            # `monomi` binary (scan / publish /
│   │                          #   replay / serve)
│   └── monomi-api/            # (optional) HTTP server for
│                              #   on-demand cache-miss analysis
└── fixtures/                  # tarballs: synthetic + replays of
                               #   public malicious packages
```

Keep ecosystem crates isolated so an npm-only build (the V1 distribution)
doesn't have to compile cargo/pypi parsers.

## Core types (`monomi-core`)

```rust
pub struct Verdict {
    pub schema_version: u32,                 // bump on breaking change
    pub artifact: ArtifactId,                // ecosystem + name + ver + integrity
    pub analyzed_at: DateTime<Utc>,
    pub analyzer_version: String,            // monomi version that produced this
    pub ruleset_version: String,             // bump on rule add/remove/semantic change
    pub stage1: Stage1Result,
    pub stage2: Option<Stage2Result>,        // None if Stage 1 was decisive
    pub final_verdict: FinalVerdict,
}

pub struct ArtifactId {
    pub ecosystem: Ecosystem,                // Npm | Cargo | Pypi | Nuget
    pub name: String,
    pub version: String,
    pub integrity: Integrity,                // algorithm + digest
}

pub struct Integrity {
    pub algo: HashAlgo,                      // Sha256 | Sha512
    pub digest_b64: String,                  // base64 (SRI form for npm)
}

pub struct Stage1Result {
    pub findings: Vec<Finding>,
    pub score: u32,                          // sum of finding severities
    pub verdict: Stage1Verdict,              // Clean | Suspicious | Malicious
}

pub struct Finding {
    pub rule_id: &'static str,               // "NPM001"
    pub severity: Severity,                  // Info | Low | Med | High | Critical
    pub category: Category,                  // LifecycleScript | Exfil | Persistence | ...
    pub locations: Vec<Location>,            // file + line range
    pub excerpt: Option<String>,             // capped snippet
    pub message: String,
    pub defers_to_stage2: bool,              // hint: this finding wants LLM review
}

pub struct Stage2Result {
    pub model: String,                       // "claude-opus-4-7"
    pub verdict: Stage2Verdict,
    pub confidence: f32,
    pub reasoning: String,                   // brief, capped
    pub indicators: Vec<String>,
    pub recommended_action: RecommendedAction, // Allow | Warn | Block
    pub tokens_in: u32,
    pub tokens_out: u32,
}

pub struct FinalVerdict {
    pub status: Status,                      // Clean | Warn | Block
    pub confidence: f32,
    pub source: VerdictSource,               // Stage1 | Stage2 | StageMerged
}
```

## The `Ecosystem` trait

The integration point for every package source. Everything
ecosystem-specific lives behind this.

```rust
#[async_trait]
pub trait Ecosystem: Send + Sync {
    fn id(&self) -> EcosystemId;

    /// Fetch the canonical artifact bytes for a (name, version).
    async fn fetch(&self, name: &str, version: &str) -> Result<Tarball>;

    /// Compute integrity for an already-fetched tarball,
    /// using the ecosystem's canonical hash algorithm.
    fn integrity(&self, tar: &Tarball) -> Integrity;

    /// Parse the manifest (package.json / Cargo.toml / pyproject.toml).
    fn parse_manifest(&self, tar: &Tarball) -> Result<Manifest>;

    /// Extract lifecycle entry points (scripts the package manager
    /// will execute on install / build).
    fn lifecycle_entrypoints(&self, tar: &Tarball, manifest: &Manifest)
        -> Vec<LifecycleEntry>;

    /// Walk the tarball, classifying each entry. Source files get
    /// language-aware parsing where it matters; data files get
    /// content-type classification only.
    fn walk(&self, tar: &Tarball) -> Box<dyn Iterator<Item = Entry> + '_>;

    /// Optional: produce a diff vs the previous version of the same
    /// package. Used for "version N+1 suddenly grew 10x" signals
    /// and as Stage 2 context. Implementations may return None.
    async fn diff_against_previous(&self, current: &Tarball, name: &str)
        -> Result<Option<PackageDiff>>;
}
```

A `LifecycleEntry` is generic on purpose — for npm it's a script body
string; for cargo it's a path to `build.rs`; for pypi it's a
`setup.py` reference or a build-backend identifier. Rules see
"this is an install-time entry point and here's its body/path."

## The `Rule` trait

```rust
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn category(&self) -> Category;
    fn applies_to(&self, eco: EcosystemId) -> bool;
    fn evaluate(&self, ctx: &AnalysisCtx) -> Vec<Finding>;
}

pub struct AnalysisCtx<'a> {
    pub artifact: &'a ArtifactId,
    pub manifest: &'a Manifest,
    pub lifecycle: &'a [LifecycleEntry],
    pub entries: &'a [Entry],                // pre-walked
    pub diff: Option<&'a PackageDiff>,
    pub corpus: &'a Corpus,                  // top-N package names, exfil endpoints
}
```

Rules are stateless and parallelizable. The analyzer runs them
concurrently over the same `AnalysisCtx`, collects findings,
computes the score, and decides the Stage 1 verdict.

## Initial npm rule set (V1)

| ID      | Severity | Defer? | What it checks |
|---------|----------|--------|----------------|
| NPM001  | Info     | no     | Any lifecycle script present |
| NPM002  | High     | yes    | Lifecycle body uses `child_process` / `spawn` / `exec` |
| NPM003  | High     | yes    | Lifecycle body imports `net`/`dns`/`http(s)`/`tls` |
| NPM004  | High     | yes    | Iterates `process.env` (Object.keys/entries/spread) |
| NPM005  | Critical | no     | Large base64/hex literal (>1 KB) + `eval`/`Function`/`vm.runIn*` nearby |
| NPM006  | Critical | no     | Hardcoded cloud-metadata host: `169.254.169.254`, `metadata.google.internal`, Azure IMDS |
| NPM007  | Critical | no     | Known exfil endpoint literal: `webhook.site`, `oast.fun`, `requestbin.*`, Discord/Slack webhook patterns |
| NPM008  | Critical | no     | String literal referencing `~/.ssh/`, `~/.aws/`, `~/.npmrc`, `~/Library/LaunchAgents/`, `/etc/systemd/`, `crontab` |
| NPM009  | High     | yes    | Bundled `.node` / `.wasm` / Mach-O / ELF binary not declared in `bin`/`binary` |
| NPM010  | Med      | yes    | `dist/` is minified, no source map, repo URL missing or 404 |
| NPM011  | Med      | yes    | New `bin` entry added vs previous version |
| NPM012  | Med      | yes    | Typosquat: edit distance ≤ 2 to a top-1k package name AND version age < 30 days |
| NPM013  | High     | yes    | First publish under a maintainer added < 14 days ago |
| NPM014  | Med      | yes    | Size growth > 5x vs previous version OR new files under `lib/`/`dist/` not present in linked repo at the tagged commit |
| NPM015  | High     | yes    | `require()` / dynamic `import()` with non-literal arg, in proximity to base64/eval |

"Defer? = no" means a single hit is enough to mark **Malicious** at
Stage 1. "Defer? = yes" means hits count toward score and trigger
Stage 2 above a threshold.

Score thresholds (initial, will tune):
- 0 → Clean
- 1–6 → Suspicious (Stage 2 may downgrade to Clean)
- 7+ → Malicious-candidate (Stage 2 must explicitly downgrade to
  override; default action = Block)
- Any Critical with `defers_to_stage2: false` → Malicious, no Stage 2

## Stage 2 (`monomi-llm`)

```rust
pub struct LlmAnalyzer {
    client: AnthropicClient,
    model: String,                // "claude-opus-4-7"
    max_input_tokens: u32,        // hard cap, e.g. 30_000
    max_output_tokens: u32,       // 1_500
    cache: Arc<dyn VerdictCache>, // catalog-backed
}

impl LlmAnalyzer {
    pub async fn adjudicate(
        &self,
        artifact: &ArtifactId,
        stage1: &Stage1Result,
        ctx: &Stage2Context,      // bounded excerpts, diff, metadata
    ) -> Result<Stage2Result>;
}
```

Context-builder responsibilities:
- Include *full* lifecycle script bodies (these are short and the
  whole point of the analysis).
- For each Stage 1 finding, include ±20 lines of surrounding source.
- Include the manifest's `name`, `version`, `dependencies` keys
  (values redacted to length), `maintainers`, `repository`,
  `publishedAt`, size, file count.
- If `diff_against_previous` succeeded: include the file-name list
  of added/removed/changed files and a size delta. Do NOT include
  full diffs unless within budget.
- Hard-stop at `max_input_tokens`; if not enough budget to include
  all lifecycle bodies, emit Stage2Result `{verdict: suspicious,
  confidence: 0.0, recommended_action: warn, reasoning: "context too
  large for adjudication"}` rather than truncating arbitrarily.

Forced output schema via Anthropic tool-use; the tool's input schema
matches `Stage2Result`'s on-the-wire shape. Reject (= fail-open to
Stage 1) any response that doesn't conform.

LLM hygiene:
- **Never** send tarball bytes directly — only parsed/excerpted text.
- Strip `process.env.*` values if any are present in source (they
  shouldn't be, but defensive).
- Per-package timeout (e.g. 30s); on timeout, fall back to Stage 1.
- Verdict is cached by *artifact integrity*, never by `(name, version)`,
  so a republished different-bytes package gets re-analyzed.

## Catalog (`monomi-catalog`)

R2 layout repeated from plan.md for reference:

```
verdicts/by-integrity/<sha512-b64url[..2]>/<rest>.json
verdicts/npm/<name>/<version>.json                 # convenience pointer
rules/version.json
rules/<id>.yaml                                    # if/when YAML rules land
index/latest.jsonl                                 # rolling 24h
index/by-day/<YYYY-MM-DD>.jsonl
```

Reader API (used by sakimori proxy):

```rust
pub struct Catalog { /* R2 client, edge-cache config */ }

impl Catalog {
    pub async fn lookup_by_integrity(&self, i: &Integrity)
        -> Result<Option<Verdict>>;

    pub async fn lookup_by_nv(&self, eco: EcosystemId, name: &str, version: &str)
        -> Result<Option<Verdict>>;
}
```

The convenience pointer (`verdicts/npm/<name>/<version>.json`) is a
small JSON file containing just `{ "integrity": "...", "verdict_url":
"..." }` so callers without the lockfile-integrity hash can still find
the verdict via name+version.

Writer:
- Used only by `monomi-feed` and `monomi-cli publish`.
- Idempotent: writing the same verdict twice is a no-op (compare
  body hashes first).
- Appends to `index/latest.jsonl` via a small atomic compose-on-write
  pattern (R2 supports conditional writes).

## Feed (`monomi-feed`)

Daemon binary. Responsibilities:

1. Subscribe to npm's change stream. Two viable transports:
   - CouchDB `_changes` feed on `replicate.npmjs.com`
     (longstanding, rate-limited, free).
   - libraries.io / ecosyste.ms firehose (third-party, easier
     filtering).
   V1 picks CouchDB direct to avoid third-party dependency.
2. For each new `(name, version)`:
   - Dedup against R2 (already analyzed?).
   - Fetch tarball through the same proxy infrastructure (so we
     dogfood sakimori's filter — handy for catching our own bugs).
   - Run analyzer.
   - Write verdict + index entry.
3. Persist cursor (sequence number) to R2 so restarts resume.
4. Rate-limit: respect the registry's etiquette (1 conn, ≤2 rps).
5. Backfill mode (`monomi feed backfill --top 5000`) walks npm
   download stats for warm-start coverage on day one.

Single-binary, single-process for V1. Scale to a small queue (R2 +
worker pool) only if registry velocity demands it.

## CLI (`monomi-cli`)

```
monomi scan <tarball-or-dir>              # local file or extracted pkg
monomi scan-npm <name>@<version>          # fetch + scan, no R2 write
monomi explain <integrity-or-name@ver>    # render verdict + reasoning
monomi publish <verdict.json>             # upload to R2 (auth required)
monomi feed run                           # start the daemon
monomi feed backfill --top <N>
monomi serve                              # start monomi-api HTTP server
monomi rules list                         # dump active ruleset + versions
```

`scan` and `scan-npm` work fully offline (no R2, no LLM) when given
`--stage1-only`. This is the air-gapped CI mode.

## HTTP API (`monomi-api`, optional)

Stateless front-end over the analyzer. Useful when sakimori encounters
a cache miss and prefers a synchronous answer over fail-open.

```
GET  /v1/verdict/by-integrity/{algo}/{digest}     -> 200 Verdict | 404
GET  /v1/verdict/npm/{name}/{version}             -> 200 Verdict | 404
POST /v1/analyze                                   -> 200 Verdict
       body: { ecosystem, name, version, integrity? }
       runs Stage 1 inline (and Stage 2 if budget allows), writes
       to R2, returns the verdict.
```

Backed by the same `Catalog` + `Ecosystem` + `LlmAnalyzer` stack as
the CLI — the HTTP layer is just a thin shell.

## Concurrency & failure model

- Analyzer is a pure function of `(tarball bytes, ruleset version)`
  for Stage 1. Trivially parallelizable across packages.
- Stage 2 is rate-limited by the Anthropic API; the feed daemon
  bounds concurrent LLM calls via a semaphore.
- R2 writes use If-None-Match where supported to prevent
  double-publication races between feed instances.
- Every failure mode (registry 5xx, LLM timeout, R2 write rejection)
  must log enough to replay deterministically.

## Versioning

- `schema_version` on `Verdict` bumps when the JSON shape changes
  incompatibly. Readers must skip-and-warn on unknown major.
- `ruleset_version` is a semver string baked into the binary at
  build time, derived from a checked-in `RULESET_VERSION` constant.
  A verdict's ruleset_version tells consumers whether it's worth
  re-analyzing under a newer set.
- `analyzer_version` = monomi crate version. Backfill jobs can use
  this to selectively re-analyze old verdicts after a rule change.

## Security posture of monomi itself

We analyze hostile inputs. Reasonable hardening:

- Tarball extraction is **never to disk** — in-memory, with hard
  size limits (e.g. reject > 100 MB; reject > 50_000 entries; reject
  any entry path containing `..` or absolute).
- All language-specific parsers (JS for npm, Rust for cargo, Python
  AST for pypi) run in-process but with bounded recursion and
  bounded source size per file.
- No `eval` of analyzed code, ever, under any flag. Pattern matching
  only.
- Stage 2 LLM calls send *text*, never raw bytes; the context
  builder is the one place that decides what leaves the host.
- The feed daemon and the analyzer don't need network access beyond
  the registry, R2, and the Anthropic API. Run under sakimori in
  production for self-dogfooded egress filtering.
