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
  Implement as a follow-up rule (note: `NPM033`/etc. IDs are
  reserved by the CVE-retrospective cluster below — pick a fresh
  slot when this lands).

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

## CVE-retrospective rules (npm incident post-mortems)

Mapping of past real-world npm supply-chain incidents to rules
that, in retrospect, would have caught them at publish time.
Ordered by post-mortem-precision (= "this signal alone would
have flagged the malicious version, no FP context required").
IDs are reserved here; some ship in this PR (marked **[M13a]**)
and the rest land as part of M13.

- **`NPM033` (cryptocurrency private-key / mnemonic / seed-phrase
  literals)** **[M13a — shipped in this PR]**
  Source mentions `*_PRIVATE_KEY`, `MNEMONIC`, `SEED_PHRASE`,
  BIP-39 wordlist references, raw 0x-prefixed 64-hex literals
  (Ethereum private key shape), Solana/Bitcoin private-key byte
  patterns. Reference incidents: `@solana/web3.js` 2024
  phishing-driven hijack, electron-native-notify, multiple
  `bignum*` typosquats. Capability:
  `EnvSecretLookup` + `WalletAccess`. Severity: Critical/defer.

- **`NPM034` (npm CLI invocation inside install lifecycle)**
  **[M13a — shipped in this PR]**
  `npm publish` / `npm token` / `npm login` / `npm whoami` /
  `npx` shelled out from a `preinstall` / `install` /
  `postinstall` script. Reference incident: Shai-Hulud worm 2024
  (compromised packages re-publish their owner's other
  packages). Capability: `InstallTimeShell` + new
  `RegistryWrite` capability. Severity: Critical/decisive.

- **`NPM035` (Linux privesc / recon path literals)**
  **[M13a — shipped in this PR]**
  Source mentions `/etc/shadow`, `/etc/passwd`,
  `/proc/self/environ`, `/proc/*/cmdline`, `/root/`, or
  `/var/log/auth*`. Reference: generic recon shape seen across
  miner/bot family payloads dropped by malicious npm packages.
  Capability: `FsReadSensitive`. Severity: High/defer.

- **`NPM036` (chmod-to-executable inside install lifecycle)**
  **[M13a — shipped in this PR]**
  `fs.chmodSync(p, 0o755)` / `chmod +x` shelled out from a
  lifecycle script, especially when `p` was the target of a
  preceding `fs.writeFile` or download. Reference: every
  fetch-and-run shape (ua-parser-js, coa/rc 2021).
  Capability: `InstallTimeShell` + `NativeBinary`. Severity:
  High/defer.

- **`NPM037` (runtime branches on `require.main.filename` /
  `process.mainModule`)** **[M13b — shipped in this PR]**
  Source reads `require.main.filename` / `process.mainModule`
  and string-matches its value against a literal package name
  list. Reference incident: event-stream / flatmap-stream 2018,
  payload only fired when consumed by `copay-dash`. Capability:
  `DynamicEval` + `TimeBomb` (gated activation). Severity:
  High/defer. Two-prong match (main-module read + package-name
  comparison) keeps FPs out of `require.main === module` CLI
  patterns.

- **`NPM038` (`require.cache[...]` mutation / module hijacking)**
  **[M13b — shipped in this PR]**
  Source writes to `require.cache[...]` or `delete require.cache[...]`.
  Module-substitution attack. Both `require.cache` and
  `Module._cache` shapes are covered. Capability:
  `DynamicRequire` + `DynamicEval`. Severity: High/defer.

- **`NPM039` (mass file deletion shape, beyond
  `fs.unlinkSync(__filename)`)** **[M13b — shipped in this PR]**
  `fs.rm*`/`rimraf`/`rm -rf` over a *traversal*
  (`os.homedir()`, `process.cwd()`, `process.env.HOME`,
  root-anchored paths). Reference: node-ipc/peacenotwar 2022.
  Capability: `DestructiveFs` (new, decisive on introduction).
  Severity: Critical/decisive. Two-prong (destructive call +
  traversal seed in same file) keeps FPs off legitimate
  `rimraf('./dist')` build cleanup.

- **`NPM040` (tarball ↔ git-tag divergence)** — see M12.

- **`NPM041` (dataflow-lite token taint)** — see M15.

- **`NPM042` (maintainer email-domain expiry)** — see M16.

- **`NPM043` (version inflation / dependency confusion)**
  Published version is dramatically higher than the prior
  version sequence (e.g. `0.4.2 → 99.99.99`). Reference:
  Alex Birsan 2021 dependency-confusion paper, ongoing daily
  attacks against private-registry name shadows. Severity:
  Medium/defer.

- **`NPM044` (`process.dlopen` / `process.binding` / V8 internals)**
  **[M13b — shipped in this PR]**
  Direct V8 internal access (`process.dlopen`, `process.binding`,
  `process._linkedBinding`, `process._rawDebug`). Extremely
  unusual outside Node-core-replacement libraries. Capability:
  `V8Internal` (new) + `DynamicEval`. Severity: High/defer.

- **`NPM045` (geolocation-gated destructive branches)**
  Source reads `process.env.LANG` / `Intl.DateTimeFormat`
  resolved locale / `dns.lookup`-derived IP and conditionally
  enters a destructive code path. Reference: node-ipc
  protestware. Severity: Critical/defer.

- **`NPM046` (SetUID / SetGID binary in tarball)**
  **[M13b — shipped in this PR]**
  Any file in the tarball whose tar header carries mode bits
  `0o4000`/`0o2000`. Applies to npm, cargo (.crate) and PyPI
  sdist (all tar-based). Capability: `SetuidBinary` (new,
  decisive on introduction). Severity: Critical/decisive.
  Required plumbing `mode: Option<u32>` through `Entry`.

- **`NPM047` (`crypto.createDecipheriv` with hardcoded key)**
  `createDecipheriv` / `createDecipher` call whose key argument
  is a literal `Buffer.from(<hex/base64>)`. Pairs with
  `NPM005`/`NPM020`. Severity: High/defer.

- **`NPM048` (maintainer recently added, < 14 d before publish)**
  Already partially covered by `NPM016`; this variant looks at
  the *maintainer-add* timestamp from `/-/user/`, not the
  package-create timestamp. Severity: Medium/defer.

- **`NPM049` (CI-only payload)**
  Conditional execution gated by `process.env.CI` /
  `GITHUB_ACTIONS` / `JENKINS_URL` / `BUILD_ID` and reaches
  network/secret-grab. Severity: High/defer.

## Capability vocabulary follow-ups

The M13a/b clusters introduce these new capabilities not in M7's set:

- `RegistryWrite` (M13a) — code performs (or shells out to) a
  registry-side write: `npm publish`, `npm token create`,
  `cargo publish`, `twine upload`. Decisive on introduction.
- `SecretMaterial` (M13a) — references cryptocurrency private-key,
  mnemonic, or seed-phrase shapes. Decisive on introduction.
- `DestructiveFs` (M13b) — mass file deletion shape paired with
  a homedir/cwd/root traversal seed. Decisive on introduction.
- `SetuidBinary` (M13b) — file in tarball with setuid/setgid
  mode bits. Decisive on introduction.
- `V8Internal` (M13b) — direct V8/Node-core internal access
  (`process.dlopen`, `process.binding`). Not decisive (some
  legitimate Node-core-replacement libraries use it); pairs
  with `DynamicEval` and defers to Stage 2.

These extend `Capability` (additive — old verdicts still
deserialize via `serde(default)`).
