# Open issues / followups

Tracked during M8 design (capability-diff). Items are deferred from
M8 itself but should be picked up next.

## Adopted in M8

- **Implement as post-Stage1 pass, not as a `Rule`.** Rules emit
  capabilities; a rule that *reads* the aggregated set would have
  ordering problems with rules that contribute to it. The diff
  runs after `runner::run` has produced the full `Stage1Result`.
- **`CapabilityBaseline` struct**, not `Option<&CapabilitySet>`:
  carries the capability set, the baseline versions consulted,
  the strategy used, and a `complete` provenance flag.
- **Two signals.** `new_vs_immediate_prev` and
  `new_vs_recent_union` are reported separately; the latter is
  higher-confidence (capability absent from *every* recent
  version).
- **Capability provenance marker.** New
  `capabilities_complete: bool` on `Stage1Result`. Empty set on a
  pre-M7 verdict (where the field defaults) is treated as
  "unknown", not as "no capabilities". M8 skips the diff when
  baseline provenance is unknown.
- **Publish-time sort with deterministic tie-break.** Sort by
  `(published_at, version)`, exclude current version, skip
  versions without timestamps, log when history is degraded.
- **Decisive set narrowed.** Per codex review, only
  `SelfDelete`, `CryptoMiner`, `WalletAccess`,
  `FsWritePersistence` remain decisive-on-introduction.
  `InstallTimeNetwork` and `InstallTimeShell` move to
  High+defer-to-Stage2 (false-positive risk from `node-gyp`,
  `prebuild-install`, Playwright/Prisma/sharp browser/engine
  downloads, and legitimate shell-based postinstalls).
- **Don't trust a poisoned baseline.** If the baseline verdict's
  Stage1 was already Malicious, NPM030 logs the situation and
  abstains rather than producing a meaningless empty diff.

## Adopted from second codex pass

- **Coverage telemetry shipped with M8.** A structured
  `DiffOutcome` lives on `Stage1Result` so we can tell apart
  "diff produced", "abstained: poisoned baseline", "abstained:
  baseline incomplete", and "not attempted" from the verdict
  alone.
- **"Exclude current version" uses exact identity (name +
  version)**, not timestamp comparison.
- **`capabilities_complete = true` is set on every fresh M8 run**
  even when the set is empty — the boolean means "this analyzer
  actually computed capabilities", not "the package has
  capabilities".
- **Baselines mark `complete = false`** when any version inside
  the intended window is skipped (missing timestamp / verdict).

## Deferred from M8 (followups)

- **Combination-based severity bumps.** Newly-introduced *pairs*
  are stronger than the sum of parts:
  - `EnvSecretLookup` + `NetHttp` / `InstallTimeNetwork` → Critical
  - `DynamicEval` + `EncodedPayload` → Critical
  - `NativeBinary` + `LifecycleInstall` + `InstallTimeNetwork` → Critical
  - `FsReadSensitive` + `NetHttp` → Critical
  Implement as a follow-up rule `NPM033` over the diff output.

- **Grouped summary finding.** One `Finding` per introduced
  capability is fine for machine consumers (sakimori) but noisy
  in the CLI. Add a single rolled-up summary alongside.

- **Time-based baseline.** `recent_union` of the last N publishes
  is fooled when all N were compromised in minutes (Shai-Hulud
  shape). Add a secondary baseline: "last version older than 24h
  / 7d" and intersect.

- **Package rename / scope-change handling.** `@scope/pkg`
  ownership flips and package resurrection need their own signal;
  M8 just doesn't compare across renamed names (we trust the
  registry's notion of "name").

- **Coverage telemetry.** NPM030 silently abstains when baseline
  isn't available; we need a counter for "diff attempted vs diff
  produced" so we can tell whether the rule is actually
  protecting anyone.

- **Stage 2 context enrichment.** When NPM030 defers, the LLM
  currently sees only the new capabilities. Also pass: baseline
  versions, prior verdict status, the specific findings that
  contributed each capability, package age. Today's
  `Stage2Context` is the bottleneck.

- **Schema versioning hardening.** `capabilities_complete: bool`
  is a one-bit signal. If we ever extend the capability vocabulary
  again, downstream catalogs may have *partial* capability
  computation. Reserve a `capabilities_schema_version: u32` for
  the next bump.
