# monomi — plan

> 物見 (monomi): a scout. Runs *ahead* of the line that **sakimori** holds,
> looking over published packages before they reach a developer's machine.

## What this is

A two-stage supply-chain static analyzer for package registries. Stage 1 is
fast deterministic Rust rules over the published tarball; Stage 2 escalates
ambiguous cases to an LLM for judgment. Verdicts are persisted in a
Cloudflare R2 catalog keyed by tarball integrity hash, so consumers
(primarily **sakimori**'s proxy) can answer "is this artifact safe to
admit?" with a single object-store GET.

First ecosystem: **npm**. Designed from day one to extend to **cargo**,
**PyPI**, **NuGet** as separate `Ecosystem` implementations.

## Why this exists (positioning)

Socket, Snyk, Phylum and friends already do exhaustive post-publish
scanning. We do **not** try to beat them at coverage — they win on data
volume, rule corpus, and FP-tuning resources accumulated over years.

monomi takes a different shape, picked specifically because the dominant
incumbents structurally can't fill it:

- **Block-grade signals, not warnings.** Output is consumed by sakimori's
  HTTPS proxy at fetch time. Verdicts must be high-precision enough to
  return `403` on, not just "show a warning in a dashboard." This forces
  rule selection toward low-FP heuristics and away from the broad-coverage
  signals SaaS scanners can afford.
- **Local-completable.** Proxy hot path must work offline / air-gapped.
  R2 catalog is a cache for the common case; the Rust analyzer ships in
  the same binary as monomi-cli so a sealed CI runner can analyze a
  tarball with zero network.
- **Open ruleset.** Socket's rules are proprietary. monomi's are versioned
  YAML/Rust in the repo, contributable by researchers, citable in audits.
- **LLM as second opinion, not first.** Pure-LLM scanners are expensive,
  slow, and hallucinate. Stage 1 keeps token spend bounded and turns the
  LLM into an *adjudicator* of pre-filtered candidates, not a primary
  classifier.
- **Pairs with runtime signal.** sakimori already knows attribution
  (which package manager started the fetch), execution mode (ephemeral
  vs persistent), and what the resulting process actually did on the
  network/FS. monomi's static finding joined with sakimori's dynamic
  observation is a signal neither side can produce alone.

What we are explicitly **not** building:

- A dashboard UI / SaaS console.
- A `npm audit` replacement (vulnerability database lookup — that's OSV +
  sakimori-hub's job).
- A typosquat / maintainer-reputation graph at Socket scale. We'll have
  a *minimal* version of those signals; matching Socket's coverage is
  not the goal.

## Threat model (what we want to catch in V1)

Ordered by what would actually have stopped real 2024–2026 incidents.

1. **Install-time RCE via lifecycle scripts** (Shai-Hulud family,
   `event-stream` lineage). `preinstall`/`install`/`postinstall`/`prepare`
   that spawn processes, open sockets, harvest env vars, or eval
   base64'd blobs.
2. **Credential / token exfiltration at runtime.** Cloud metadata IPs,
   known exfil endpoints (webhook.site, oast.fun, discord webhooks),
   `~/.ssh`/`~/.aws`/`~/.npmrc` reads at module top-level.
3. **Persistence writes.** LaunchAgents / systemd-user / crontab /
   shell-rc / `authorized_keys` references in code.
4. **Obfuscation + dynamic execution.** Large base64/hex blobs +
   `eval` / `new Function` / `require()` with non-literal arg.
5. **Dist/source divergence.** Published `dist/` is minified, no source
   map, no matching repo source — i.e. you can't read what runs.
6. **Bundled native artifacts not declared.** `.node` / `.wasm` /
   raw binaries shipped without `"bin"` / `"binary"` field.
7. **Lightweight typosquat + age signal.** Edit distance ≤ 2 to a
   top-1k package AND publish age < 30 days. Conservative on purpose.

Explicitly out of scope for V1 (covered by other layers or future work):

- GHA cache poisoning (TanStack vector) — that's `sakimori actions
  audit` + `sakimori deps verify-cache`, workflow-side problems.
- CVE / advisory lookup — OSV via `sakimori advisories scan`.
- Reproducible-build proofs — distinct project.

## Two-stage pipeline

```
                                    ┌──────────────────────────┐
 tarball ──► Stage 1 (Rust rules) ──┤  clean → write verdict   │
                                    │  malicious → write verdict│
                                    │  ambiguous ──► Stage 2 ──►│ verdict
                                    └──────────────────────────┘
                                                  │
                                                  ▼
                                          Cloudflare R2
                                       (content-addressed)
```

**Stage 1: Rust analyzer.** Reads the tarball, walks files, applies the
rule set. Produces `Stage1Result { findings: Vec<Finding>, score: u32,
verdict: Clean | Suspicious | Malicious }`. Deterministic, reproducible,
no network beyond the registry fetch itself.

- **Clean** (no rule fired, score == 0): write verdict, done.
- **Malicious** (any single high-confidence rule fired — e.g.
  hardcoded cloud-metadata IP inside a `postinstall` body): write
  verdict, done. No need to ask an LLM whether stealing IAM creds is
  bad.
- **Suspicious** (mid-score, multiple weak signals, or rules that
  explicitly defer to Stage 2 — e.g. "lifecycle script with
  `child_process` but body looks plausibly legit"): escalate.

**Stage 2: LLM adjudication.** A single Claude call per suspicious
package with:

- Package metadata (name, version, publish time, maintainer change?,
  size growth vs prev).
- Stage 1 findings (which rules fired, with line refs).
- *Bounded* source excerpts: lifecycle script bodies in full, plus
  the smallest context around each Stage 1 hit (capped at e.g. 8 KB
  total).
- Diff vs previous version's same files when applicable.

Structured output (forced via tool-use schema):
```json
{
  "verdict": "clean" | "suspicious" | "malicious",
  "confidence": 0.0,
  "reasoning": "...",
  "indicators": ["..."],
  "recommended_action": "allow" | "warn" | "block"
}
```

LLM rules:
- **Cached by tarball integrity hash.** Same artifact never re-analyzed.
- **Fail-open.** LLM error / timeout → fall back to Stage 1 verdict,
  log the failure. Never block on LLM availability.
- **Token-budget capped per call.** Refuse to send packages whose
  context would exceed N tokens; fall back to "Suspicious, manual
  review needed" verdict.

## R2 catalog as the distribution layer

R2 (S3-compatible, no egress fee) is the public read surface. Layout:

```
r2://monomi/
  verdicts/by-integrity/<sha512-b64url[0..2]>/<rest>.json   # primary lookup
  verdicts/npm/<name>/<version>.json                         # convenience
  rules/version.json                                          # ruleset metadata
  rules/<id>.yaml                                             # individual rule defs (or rust-baked, indexed here)
  index/latest.jsonl                                          # append-only feed of new verdicts (24h window)
  index/by-day/<YYYY-MM-DD>.jsonl                             # archival
```

Lockfiles already carry SRI integrity (`sha512-…`), so **the proxy can
look up a verdict with the exact hash it's about to admit**, no name
resolution needed. This also means a republished-same-bytes package
reuses the verdict for free.

Read path:
1. sakimori proxy intercepts tarball fetch.
2. Computes/extracts integrity hash.
3. `GET r2://monomi/verdicts/by-integrity/<...>.json` (Cloudflare
   edge-cached, ~10 ms typical).
4. Verdict says `block` → 403 to client. `allow` / `warn` → forward,
   surface warning in sakimori's step summary.

Write path:
1. `monomi-feed` subscribes to npm's change stream
   (`registry.npmjs.org/_changes` via CouchDB replication, or a
   libraries.io firehose).
2. New `(name, version)` → fetch tarball → Stage 1 → maybe Stage 2 →
   `PUT` verdict to R2 + append to `index/latest.jsonl`.
3. Backfill mode: walk top-N packages from npm download stats; analyze
   all versions for warm-start coverage.

On cache miss (proxy asks for an artifact the feed hasn't analyzed yet),
the proxy can either:
- (a) fail-open with a warning, log the miss for backfill, or
- (b) call a small `monomi-api` HTTP endpoint that runs Stage 1
  inline and returns a synchronous verdict.

V1 ships (a) for simplicity; (b) is optional and depends on whether
the feed lag becomes a real problem in practice.

## Ecosystem extension path

The Rust `Ecosystem` trait (see architecture.md) is the only thing that
should change per ecosystem. Order:

1. **npm** — V1, this plan.
2. **crates.io** — V2. Stage 1 rules differ (no lifecycle scripts in
   the same shape; `build.rs` is the analog, plus `[package.metadata]`
   tricks and proc-macro execution at compile time).
3. **PyPI** — V3. `setup.py`, `pyproject.toml` build-backend, wheel
   `*.dist-info/RECORD` divergence.
4. **NuGet** — V4. `tools/install.ps1` lifecycle equivalents, MSBuild
   `.targets` injection.

Each ecosystem reuses the same R2 catalog, Stage 2 LLM client, and
verdict schema. Only the file-walker, lifecycle-extractor, and a few
rules are per-ecosystem.

## Integration with sakimori

monomi is independent (own repo, own release cadence, own crate), but
its first consumer is sakimori. Touchpoints:

- **Proxy hot path** — adds an R2 lookup step in `proxy::handle_request`
  for npm tarball URLs. Behind `--use-monomi` flag initially; default-on
  once latency is measured in production.
- **`sakimori deps check`** — for each lockfile entry, augment the
  release-age check with a monomi verdict lookup. Verdict severity
  flows into the CLI exit code.
- **`sakimori advisories scan`** — when an `InstallEvent` matches an
  OSV advisory, also fetch the monomi verdict for that exact integrity
  so the alert can say "this is the version OSV flagged, AND monomi
  Stage 2 marked it malicious on publish day."

monomi remains usable standalone (`monomi scan ./some.tgz`) without
sakimori.

## Milestones

**M0 — skeleton (1–2 weeks).** Workspace layout, `Ecosystem` trait,
npm tarball fetch + walk, three trivial rules (lifecycle present,
eval+base64, hardcoded `169.254.169.254`), JSON verdict to stdout,
no R2 yet.

**M1 — full npm Stage 1 (2–3 weeks).** All ~15 V1 rules implemented,
fixture test corpus (synthetic + replays of known malicious npm
packages from public archives), CLI usable for ad-hoc scans.

**M2 — Stage 2 LLM (1–2 weeks).** Claude tool-use integration,
context-builder with token cap, response-validating schema, verdict
merge logic, caching by integrity hash.

**M3 — R2 catalog (1 week).** Writer (verdict → R2), reader crate
(consumers fetch by integrity), index file generation. Public bucket
or signed-URL bucket — decide based on cost model.

**M4 — npm feed daemon (1–2 weeks).** Change-stream subscriber, work
queue, rate limiting against the registry, restartable cursor.
Backfill mode for top-N.

**M5 — sakimori proxy integration (1 week).** R2 lookup in
`handle_request`, flag-gated, latency telemetry. End-to-end demo:
publish a synthetic malicious package, observe sakimori 403 on
install.

**M6 — crates.io ecosystem (2–3 weeks).** Repeat the npm pattern.

**M7 — Capability set extraction (1–2 weeks).** Rules emit a structured
`Capability` alongside human-readable findings. The set is aggregated
onto `Stage1Result` and persisted in the verdict. This is the
foundation for M8: a stable, machine-comparable summary of *what a
package can do* (lifecycle hooks, net.fetch/xhr, child_process,
fs.read on sensitive paths, env bulk enumeration, dynamic eval,
native binary, persistence writes, …). Initial set is enumerated in
`monomi-core::capability`; rules opt in non-breakingly by attaching
capabilities to the findings they already emit.

**M8 — Version-over-version diff signals.** *DONE.* The current
scan's `CapabilitySet` is diffed against two baselines fetched
from the catalog — the immediate previous version, and the union
of the last N (default 5) publish-time-ordered versions — and a
post-Stage1 pass emits `NPM030 — capability newly introduced`
(one finding per introduced capability). Severity scales with
capability kind: `SelfDelete` / `CryptoMiner` / `WalletAccess` /
`FsWritePersistence` are decisive on introduction; everything
else defers to Stage 2 (avoids FPs from `node-gyp`,
`prebuild-install`, Playwright/Prisma engine downloads, etc.).
The pass abstains on poisoned (Malicious) baselines and on
incomplete (pre-M7) baselines, recording a structured
`DiffOutcome` in the verdict for coverage telemetry. The CLI
opt-in is `monomi scan-npm ... --catalog-dir <dir>`; the feed
daemon uses its existing catalog automatically. See `ISSUES.md`
for items deferred from M8.

**M9 — AST-grade source analysis (3–4 weeks).** Replace the regex-
based detectors in `NPM002 / NPM013 / NPM023` with `swc_ecma_parser`
call-graph extraction in `monomi-npm::analysis::js`. Constant-fold
literal concatenation and `Buffer.from(.., 'base64')` one to two
levels to defeat split-string evasion. Same shape for PyPI later
via `rustpython-parser`. Output feeds the capability set from M7.

**M10 — Maintainer + publish-cluster signals (1 week).** Extend
`fetch_registry_metadata` consumers with two new rules:
`NPM031 — publisher changed vs prior versions` (account-takeover
shape), and `NPM032 — same maintainer published N other packages
within window` (worm-style propagation, detected in `monomi-feed`
with a sliding window over `_changes`). Both are high-precision and
were observed in real-world npm incidents (e.g. Shai-Hulud, the
2024 ctx/`@solana/...` takeovers).

## Open questions (decide before M3)

- **Cost model for R2.** Public bucket = free reads, but anyone can
  drive up our request counts. Signed URLs + a tiny edge worker is
  probably the answer; cost depends on `monomi-feed` write volume.
- **Rule format.** All-Rust (fast, type-safe, but every rule needs a
  PR + release) vs YAML-loaded (contributor-friendly but slower and
  needs a sandbox). Likely answer: Rust for V1, revisit when
  contributor demand appears.
- **LLM provider abstraction.** Hard-code Claude for V1 (we're the
  primary consumer and have the API key). If we ever ship as a
  library for others, add a trait.
- **What "malicious" means at Stage 1.** Need a written policy doc for
  what scores rise to "block-grade" so the proxy integration is
  predictable. Probably a separate `severity.md` in M2.
