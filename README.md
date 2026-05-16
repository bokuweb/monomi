# monomi 物見

> **monomi** (物見): *a scout*. Runs ahead of the line that
> [**sakimori**](https://github.com/bokuweb/sakimori) (防人) holds —
> looking over published packages before they reach a developer's
> machine.

A two-stage supply-chain analyzer for **npm**, **crates.io**,
**PyPI**, and **NuGet**. Stage 1 is fast deterministic Rust rules over the
published tarball; Stage 2 escalates ambiguous cases to an LLM
(Claude / Ollama / LM Studio / OpenAI). Verdicts are persisted in
a Cloudflare R2 catalog keyed by tarball integrity hash, so
consumers (primarily sakimori's HTTPS proxy) can answer
"is this artifact safe to admit?" with a single object-store GET.

See [plan.md](plan.md) for the design rationale and
[architecture.md](architecture.md) for the concrete crate layout.

## Status

✅ Working end-to-end for npm + cargo + PyPI + NuGet:

- Stage 1 deterministic rules (32 rules)
- Stage 2 LLM adjudicator with fail-open semantics
- Content-addressed R2 catalog layout (writes to filesystem;
  `rclone`/`aws s3 sync` to R2)
- npm `_changes` continuous feed daemon
- Ecosystem-agnostic backfill

## Install

```bash
cargo install --git https://github.com/bokuweb/monomi monomi-cli
# Provides the `monomi` binary.
```

## CLI overview

```text
monomi scan <tarball>                       # local .tgz or .crate
monomi scan-npm <name>@<version>            # fetch from npm + scan
monomi scan-cargo <name>@<version>          # fetch from crates.io + scan
monomi scan-pypi <name>==<version>          # fetch from PyPI sdist + scan
monomi scan-nuget <id>@<version>            # fetch from NuGet .nupkg + scan
monomi feed --catalog-dir <dir>             # daemon: subscribe to npm _changes
monomi backfill <list> --ecosystem npm|cargo|pypi|nuget --catalog-dir <dir>
monomi publish <verdict.json> --catalog-dir <dir>
monomi lookup <name>@<version> --catalog-dir <dir>   # local catalog
monomi lookup <name>@<version> --catalog-url <url>   # HTTP/R2 catalog
```

Add `--stage1-only` to any command to skip the LLM step.

## One-shot scan

```bash
$ monomi scan-npm left-pad@1.3.0 --stage1-only
{
  "artifact": {
    "ecosystem": "npm",
    "name": "left-pad",
    "version": "1.3.0",
    "integrity": { "algo": "sha512", "digest_b64": "XI5MPzVNAp…" }
  },
  "stage1": { "findings": [], "score": 0, "verdict": "clean" },
  "final_verdict": { "status": "clean", "confidence": 0.9 }
}
# Exit code: 0 clean/warn, 1 block, 2 error
```

## Stage 2 — LLM adjudication

monomi auto-detects which LLM provider to use from environment vars
(precedence: `ANTHROPIC_API_KEY` → `OLLAMA_HOST` → `OPENAI_API_KEY`).
Force a specific provider with `--llm`:

```bash
# Anthropic (default if ANTHROPIC_API_KEY is set)
export ANTHROPIC_API_KEY=sk-ant-...
monomi scan-npm some-pkg@1.0.0

# Local Ollama
export OLLAMA_HOST=http://localhost:11434
monomi --llm ollama --llm-model llama3.1 scan-npm some-pkg@1.0.0

# Any OpenAI-compatible endpoint (vLLM, LM Studio, etc.)
monomi --llm openai \
       --llm-base-url http://localhost:1234/v1 \
       --llm-model qwen2.5-coder \
       scan-npm some-pkg@1.0.0
```

Stage 2 is only invoked when Stage 1 finds something genuinely
ambiguous; clean and decisively-malicious cases short-circuit.

## Building the catalog (R2)

`monomi` writes verdicts to a directory in the canonical R2 layout.
The intended workflow is to write locally and mirror to R2:

```bash
# 1. Warm-start from a list of packages
echo -e "left-pad\nlodash\nexpress" \
  | monomi backfill - --ecosystem npm --catalog-dir ./catalog

# 2. Run the npm change-stream daemon for ongoing updates
monomi feed --catalog-dir ./catalog --max-concurrent 8 &

# 3. Mirror to R2 (any S3-compatible target works)
rclone sync ./catalog r2:my-bucket/ --transfers=16
# OR
aws s3 sync ./catalog s3://my-bucket/ --endpoint-url https://<acct>.r2.cloudflarestorage.com
```

The catalog layout:

```text
catalog/
├── verdicts/by-integrity/<algo>/<aa>/<rest>.json   # primary lookup
├── verdicts/<eco>/<name>/<version>.json            # convenience pointer
├── index/latest.jsonl                              # rolling feed
└── feed-state.json                                 # _changes cursor
```

## Reading from the catalog

```bash
# Local
monomi lookup left-pad@1.3.0 --catalog-dir ./catalog

# Public R2 / any HTTP base URL
monomi lookup left-pad@1.3.0 --catalog-url https://catalog.example.com
```

Library consumers (such as sakimori's proxy) use `monomi-catalog`'s
`HttpCatalogReader` directly:

```rust
use monomi_catalog::{CatalogReader, HttpCatalogReader};

let reader = HttpCatalogReader::new("https://catalog.example.com");
if let Some(v) = reader.lookup_by_integrity(&integrity).await? {
    if v.final_verdict.status == Status::Block {
        return forbidden_403();
    }
}
```

## Rules

Stage 1 ships with 12 rules. Decisive Critical findings cause an
immediate **block** verdict; everything else defers to Stage 2.

| ID         | Severity | Decisive? | What it catches |
|------------|----------|-----------|-----------------|
| `NPM001`   | Info     | no        | Any install lifecycle script |
| `NPM002`   | High     | defer     | Lifecycle uses `child_process`/net |
| `NPM004`   | High     | defer     | `process.env` bulk enumeration |
| `NPM005`   | Critical | yes       | Large base64/hex blob + `eval` |
| `NPM009`   | High     | defer     | Undeclared native binary |
| `NPM010`   | Critical | yes       | Crypto-wallet drainer literal (Exodus / MetaMask ext-id / `wallet.dat` …) |
| `NPM011`   | Critical | yes (lifecycle) / defer (source) | CI / registry token theft (`NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*`) |
| `NPM012`   | High     | defer     | `bundleDependencies` declared (hides deps from `npm audit`) |
| `NPM013`   | High     | defer     | Dynamic `require()` / `import()` with non-literal arg |
| `NPM014`   | High     | defer     | Typosquat candidate (edit distance ≤ 2 to popular name + recent publish) |
| `NPM015`   | Critical | yes       | Encoded `http` byte sequence (URL hidden as `[104, 116, 116, 112, …]`) |
| `NPM016`   | Med/High | defer     | Publish-recency: brand-new package OR fresh version on an established package |
| `NPM017`   | Critical | yes (lifecycle) / defer (source) | Fetch from `raw.githubusercontent.com` / Gist / GitLab raw / codeload |
| `NPM018`   | Critical | yes       | Self-deleting payload (`fs.unlinkSync(__filename)`) |
| `NPM019`   | Critical | yes       | `curl ... \| sh` / `eval $(curl ...)` in install-time script |
| `NPM020`   | Critical | yes       | `eval(atob(...))` / `new Function(atob(...))()` chain |
| `NPM021`   | High     | defer     | Tarball ships files outside the `files` allow-list |
| `NPM023`   | High     | defer     | Install-time outbound HTTP/fetch (`https.get` / `axios.get` / …) |
| **`NPM022`** \* | Critical/High | bidi=yes / zw=defer | Trojan Source bidi override / zero-width / mixed-script identifier |
| **`NPM024`** \* | Critical | yes       | Crypto-miner indicators (`stratum+tcp://`, known pools, CoinHive, XMR addr) |
| `CARGO001` | Info     | no        | `build.rs` present |
| `CARGO002` | High     | defer     | build.rs uses `Command::new` etc. |
| **`CARGO003`** | High | defer     | Crate is a proc-macro (compile-time code in every downstream crate) |
| **`CARGO004`** | High | defer     | build.rs uses `include_bytes!` / `include_str!` to embed file at compile time |
| `PYPI001`  | Info     | no        | `setup.py` or non-stdlib build-backend |
| `PYPI002`  | High     | defer     | setup.py uses `subprocess`/`socket` etc. |
| `NUGET001` | Info     | no        | `tools/install.ps1` / `init.ps1` present |
| `NUGET002` | High     | defer     | install.ps1 uses `Invoke-WebRequest` / `IEX` etc. |
| **`NUGET003`** | High | defer     | Native DLL/EXE in `tools/` alongside install.ps1 |
| `NPM006` * | Critical | yes       | Hardcoded cloud-metadata IP |
| `NPM007` * | Critical | yes       | Known exfil endpoint (webhook.site, Discord, etc.) |
| `NPM008` * | High     | defer     | Sensitive-path literal (~/.ssh/, LaunchAgents, …) |

\* These literal-pattern rules fire on every ecosystem (the
`NPM` prefix is historical).

## Architecture in one paragraph

`monomi-core` defines the `Ecosystem` and `Rule` traits.
`monomi-{npm,cargo,pypi,nuget}` are ecosystem clients (fetch +
manifest + walk + lifecycle extraction). `monomi-rules` is the
shared rule set. `monomi-pipeline` wires Stage 1 + Stage 2 +
verdict merge. `monomi-llm` is the Stage 2 adjudicator (Anthropic,
OpenAI-compatible including Ollama / LM Studio, plus a Noop for
offline mode). `monomi-catalog` is the content-addressed verdict
store (`LocalDirCatalog` + `HttpCatalogReader`). `monomi-feed` is
the npm change-stream daemon + multi-ecosystem backfill.
`monomi-cli` ties them together.

## Limitations

- npm `_changes` is the only continuous feed (cargo and PyPI have
  no equivalent push stream; use `backfill` for those).
- `monomi-catalog` writes to a filesystem only; direct R2 SDK
  writes are deferred to a future feature gate. `rclone` / `aws s3
  sync` covers production needs without bundling an AWS SDK.
- PyPI ecosystem covers sdists only (`.tar.gz`); wheel parsing
  comes later.
- proc-macro execution risk for cargo is not modeled per-crate
  yet (it needs a resolve-graph view).
- NuGet `tools/install.ps1` only runs under legacy
  `packages.config`; modern `PackageReference` ignores them. The
  proxy can't tell which consumer will pick up the package, so
  monomi flags them anyway.

## License

MIT OR Apache-2.0
