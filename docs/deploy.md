# Deploying the monomi feed daemon

End-to-end recipe for running the npm change-stream subscriber as a
long-lived process and mirroring its verdict catalog to Cloudflare
R2 (or any S3-compatible target).

Two flavours are covered:

- **Server deployment** — dedicated VM / container, systemd as PID 1.
  Estimated setup: ~30 minutes.
- **Local desktop deployment** — run on your own Mac / Linux box
  alongside Ollama for free Stage 2. Estimated setup: ~15 minutes.

Pick the desktop path if you have a GPU or M-series Mac and want
to skip the Anthropic API bill; pick the server path for headless
operation.

The flow we build:

```text
 ┌────────────────────┐    every 60s     ┌─────────────────┐
 │ monomi feed daemon │ ───────────────▶ │ rclone sync     │ ──▶ Cloudflare R2
 │ (writes to /var/   │   (systemd       │ (uploads new    │     (public bucket
 │  lib/monomi)       │    .timer)       │  verdicts only) │      or CDN-fronted)
 └────────────────────┘                  └─────────────────┘
```

The daemon is intentionally **filesystem-only**; the upload step is
its own process, which means an outage in either side doesn't take
down the other.

## Step 1 — Cloudflare R2 setup

1. Cloudflare dashboard → **R2** → **Create bucket**. Pick a name
   (`monomi-catalog` below) and a region close to where most of
   your sakimori proxies live.

2. **Make it public** if the catalog will be read directly by
   consumers, *or* leave it private and put a Cloudflare Worker /
   CDN in front. Public is simpler; private + Worker is what you
   want if you intend to rate-limit consumer reads.

3. R2 dashboard → **Manage API tokens** → **Create token**:

   - Permissions: **Object Read & Write**
   - Scope: the bucket you just created
   - Save the **Access Key ID** and **Secret Access Key**; note the
     **endpoint URL** (looks like `https://<accountid>.r2.cloudflarestorage.com`).

## Step 2 — Install rclone and configure the R2 remote

```bash
# Debian/Ubuntu
sudo apt install rclone
# or: curl https://rclone.org/install.sh | sudo bash
```

```bash
rclone config
```

Pick:

- `n` (new remote)
- name: `r2`
- storage: `s3`
- provider: `Cloudflare`
- env_auth: `false`
- access_key_id: *(from step 1)*
- secret_access_key: *(from step 1)*
- region: `auto`
- endpoint: `https://<accountid>.r2.cloudflarestorage.com`
- skip the rest with `<enter>` (defaults are fine)

Smoke test:

```bash
echo hello | rclone rcat r2:monomi-catalog/_ping
rclone cat r2:monomi-catalog/_ping
rclone delete r2:monomi-catalog/_ping
```

## Step 3 — Install monomi

Build a release binary on the host (or copy a pre-built one):

```bash
# Native build
git clone https://github.com/bokuweb/monomi
cd monomi
cargo build --release -p monomi-cli
sudo install -m 755 target/release/monomi /usr/local/bin/monomi
```

## Step 4 — Provision local state directory

```bash
# Dedicated unprivileged user keeps blast radius low.
sudo useradd --system --home-dir /var/lib/monomi --create-home --shell /usr/sbin/nologin monomi
sudo install -d -o monomi -g monomi -m 750 /var/lib/monomi/catalog
```

## Step 5 — Warm-start the catalog (optional but recommended)

The change-stream feed only sees packages that publish *after* the
daemon starts. Bootstrap with a backfill of the top-N packages so
the catalog is useful from day one. A short list of npm top-1000
names from `https://anvaka.github.io/npmrank/` or your own download
stats works fine.

```bash
sudo -u monomi monomi --stage1-only backfill \
  /path/to/npm-top-1000.txt \
  --ecosystem npm \
  --catalog-dir /var/lib/monomi/catalog \
  --max-concurrent 8
```

`--stage1-only` keeps the warm-start free; the LLM kicks in later
during the live feed.

## Step 6 — systemd unit for the feed daemon

```ini
# /etc/systemd/system/monomi-feed.service
[Unit]
Description=monomi npm _changes feed
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=monomi
Group=monomi
WorkingDirectory=/var/lib/monomi
ExecStart=/usr/local/bin/monomi feed \
  --catalog-dir /var/lib/monomi/catalog \
  --max-concurrent 4
Environment=RUST_LOG=info
Environment=ANTHROPIC_API_KEY=sk-ant-...
# Budget caps: defaults are 500k input/h, 5M input/day. Tune here.
# Environment=...
Restart=always
RestartSec=15
# Graceful shutdown — give it time to drain workers + checkpoint.
TimeoutStopSec=120

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/monomi

[Install]
WantedBy=multi-user.target
```

If you don't want Stage 2 LLM at all, drop the `ANTHROPIC_API_KEY`
line — `monomi feed` auto-detects and falls back to Noop. Or pass
`--stage1-only` on the command.

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now monomi-feed
sudo journalctl -u monomi-feed -f
```

You should see `starting feed url=https://replicate.npmjs.com/...
since=Some(<N>) max_concurrent=4` followed by per-change
`analyzed and published` log lines.

## Step 7 — systemd timer for the R2 sync

The daemon writes to `/var/lib/monomi/catalog`. A small sync timer
mirrors that tree to R2 every minute. The atomic `write_atomic`
helper used by `LocalDirCatalog` means we never sync half-written
files.

```ini
# /etc/systemd/system/monomi-sync.service
[Unit]
Description=monomi → R2 sync
After=network-online.target

[Service]
Type=oneshot
User=monomi
Group=monomi
# `--checksum` makes rclone skip files whose content already matches
# in R2, so the per-minute run only uploads actually-new verdicts.
# Exclude the feed cursor: keeping it server-side is rarely useful
# and risks ping-pong with a second host.
ExecStart=/usr/bin/rclone sync \
  /var/lib/monomi/catalog \
  r2:monomi-catalog \
  --checksum \
  --transfers 16 \
  --checkers 32 \
  --exclude feed-state.json \
  --exclude '*.tmp'
```

```ini
# /etc/systemd/system/monomi-sync.timer
[Unit]
Description=monomi → R2 sync (every 60s)

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=10s

[Install]
WantedBy=timers.target
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now monomi-sync.timer
sudo systemctl list-timers monomi-sync
```

## Step 8 — Sanity-check the live catalog

After the daemon has been running a few minutes:

```bash
# Local: catalog has files
find /var/lib/monomi/catalog -type f | head

# R2: same files mirrored
rclone ls r2:monomi-catalog | head

# Resolve a real-world clean package via the catalog the proxy
# will use:
monomi lookup left-pad@1.3.0 \
  --catalog-url https://<your-r2-public-url>
```

If `lookup` returns the verdict JSON, you're done — the catalog is
populated and consumable by a sakimori proxy.

## Operational notes

### Logs

The daemon logs to stderr; systemd captures it via journald.
Filter by verdict status to spot interesting publishes:

```bash
journalctl -u monomi-feed -f --output cat \
  | rg '"status":"(warn|block)"'
```

### Resuming after long downtime

The cursor (`/var/lib/monomi/catalog/feed-state.json`) is
filesystem-local. After hours of downtime the daemon resumes from
the recorded `last_seq` and replays everything it missed. The
in-flight dedup + 429 backoff prevent overload. Expect a small
ramp window where the worker semaphore is constantly saturated.

If the cursor is *days* old you may prefer to start fresh — delete
the file and the daemon will tail the current head of the feed.

### Stage 2 cost monitoring

Set `RUST_LOG=info` and watch for the `stage 2 budget exhausted;
declining` warning. If you see it regularly, either raise the
`--llm-hourly-input-tokens` / `--llm-daily-input-tokens` flags or
drop down to `--stage1-only` for the daemon and run Stage 2 on
demand from the proxy side.

### Disk space

A typical verdict is ~5 KB JSON. npm publishes ~5,000 versions per
day → roughly 25 MB/day, 9 GB/year of *local* state. Plus the
content-addressed shards are highly compressible (LocalDirCatalog
writes pretty-printed JSON). Numbers stay manageable for a year
without rotation; for a long-running deployment consider compressing
`verdicts/by-integrity/*` periodically or rolling the
`index/latest.jsonl` to daily files (`index/by-day/YYYY-MM-DD.jsonl`).

### Backup of `feed-state.json`

The only piece of state that *cannot* be reconstructed from R2 is
the change-feed cursor. If you wipe the host you'll re-tail from
the current head and miss the gap. Snapshot
`/var/lib/monomi/catalog/feed-state.json` to a separate location
once an hour if you want zero-loss recovery.

### Multiple feed hosts

Don't. Run a single feed daemon per catalog — the cursor file is
single-writer. For HA, run one active + one cold standby and
fail over by switching which host owns the cursor.

### CDN in front of R2 (optional)

If the catalog will be read by hundreds of sakimori proxies in the
fleet, front it with a Cloudflare CDN or Worker:

- The lookup path is `verdicts/by-integrity/<algo>/<aa>/<rest>.json`
  — fully content-addressed, infinite cache TTL.
- The convenience pointer `verdicts/<eco>/<name>/<version>.json`
  changes when re-analysis lands; cache TTL ~5 minutes.
- The index `index/latest.jsonl` is append-only; cache TTL 30s.

## Troubleshooting

**`stage 2 adjudication failed: transport: ...timeout...`** —
Anthropic / OpenAI took >60s. We fail open; the Stage 1 verdict
ships. Persistent? Lower `--max-concurrent`.

**`changes stream error: HTTP 429`** — npm rate-limited us. The
retry helper handles in-flight requests but the long-poll
`_changes` connection itself doesn't have a Retry-After. Restart
the unit and the daemon will reconnect.

**`registry fetch failed at seq N`** — single-package failure;
logged, dropped, next seq picked up. Investigate only if a single
name keeps recurring.

**rclone uploads everything every minute** — your filesystem
mtimes might differ from R2 timestamps. The `--checksum` flag
forces content comparison; if you removed it, add it back.

**Daemon won't shut down on `systemctl stop`** — `TimeoutStopSec`
must be > worst-case worker drain (in-flight LLM call + tarball
fetch). Default `90s` works for the standard tuning; bump to
`300s` if you raised `--max-concurrent` past 16.

---

# Local desktop deployment (Mac / Linux with Ollama)

Use this path if you want to run the daemon on your own machine
alongside a local LLM (Ollama / LM Studio). Trade-off: feed pauses
while the box is asleep / off — `feed-state.json` checkpoints the
cursor so a restart resumes from where it stopped, but if you're
asleep for 8 hours the catch-up burst will take several minutes.

## Prerequisites

- Disk ~5 GB free for the catalog (1.5 GB/year of growth + headroom)
- One of:
  - **M-series Mac**: Apple silicon runs `llama3.1:8b` quantized
    comfortably via Ollama
  - **Linux with GPU**: 8 GB+ VRAM for a Q4-quantized 8B model
  - **Linux CPU-only**: doable but slow; consider a smaller model
    (`llama3.2:3b`) or set the budget low and accept partial Stage 2
- Ollama installed and the model pulled:
  ```bash
  ollama pull llama3.1     # or llama3.2:3b on CPU-only hosts
  ollama serve             # if not already running as a service
  ```

## Install monomi + state directory

```bash
git clone https://github.com/bokuweb/monomi ~/src/monomi
cd ~/src/monomi
cargo build --release -p monomi-cli

# Keep the binary somewhere stable.
mkdir -p ~/.local/bin
cp target/release/monomi ~/.local/bin/monomi
# Make sure ~/.local/bin is on PATH (most shells already do this).

mkdir -p ~/monomi/catalog
```

Warm-start the catalog with `monomi --stage1-only backfill` exactly
as in the server section above.

## rclone for R2

Same setup as the server section: `rclone config`, name the remote
`r2`. The smoke-test commands all work without sudo.

## macOS — launchd

Two LaunchAgents: one for the feed daemon, one for the periodic R2
sync. Both live under `~/Library/LaunchAgents/` so they run as
*your* user (no root, no system-wide install).

**`~/Library/LaunchAgents/com.monomi.feed.plist`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.monomi.feed</string>

  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOU/.local/bin/monomi</string>
    <string>feed</string>
    <string>--catalog-dir</string>
    <string>/Users/YOU/monomi/catalog</string>
    <string>--max-concurrent</string>
    <string>4</string>
  </array>

  <key>EnvironmentVariables</key>
  <dict>
    <key>RUST_LOG</key>
    <string>info</string>
    <!-- Ollama auto-detect: monomi picks it up when OLLAMA_HOST
         is set (or http://localhost:11434 is reachable). -->
    <key>OLLAMA_HOST</key>
    <string>http://localhost:11434</string>
    <key>OLLAMA_MODEL</key>
    <string>llama3.1</string>
  </dict>

  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>

  <!-- launchd doesn't have a "graceful stop timeout" like systemd,
       so we pass SIGTERM and wait the default 20s. If you raised
       max_concurrent, bump ExitTimeOut. -->
  <key>ExitTimeOut</key>
  <integer>120</integer>

  <key>StandardOutPath</key>
  <string>/Users/YOU/monomi/feed.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/YOU/monomi/feed.log</string>

  <key>WorkingDirectory</key>
  <string>/Users/YOU/monomi</string>
</dict>
</plist>
```

**`~/Library/LaunchAgents/com.monomi.sync.plist`** (timer)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.monomi.sync</string>

  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/rclone</string>
    <string>sync</string>
    <string>/Users/YOU/monomi/catalog</string>
    <string>r2:monomi-catalog</string>
    <string>--checksum</string>
    <string>--transfers</string><string>16</string>
    <string>--checkers</string><string>32</string>
    <string>--exclude</string><string>feed-state.json</string>
    <string>--exclude</string><string>*.tmp</string>
  </array>

  <key>StartInterval</key>
  <integer>60</integer>

  <key>RunAtLoad</key>
  <true/>

  <key>StandardOutPath</key>
  <string>/Users/YOU/monomi/sync.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/YOU/monomi/sync.log</string>
</dict>
</plist>
```

Adjust the rclone path (`/usr/local/bin/rclone` on Intel Mac, your
distribution's path on Linux).

Load:

```bash
# Substitute your username for YOU in both files first, then:
launchctl load   ~/Library/LaunchAgents/com.monomi.feed.plist
launchctl load   ~/Library/LaunchAgents/com.monomi.sync.plist

# Check status
launchctl list | grep com.monomi
tail -f ~/monomi/feed.log
```

To stop / unload:

```bash
launchctl unload ~/Library/LaunchAgents/com.monomi.feed.plist
launchctl unload ~/Library/LaunchAgents/com.monomi.sync.plist
```

### macOS sleep / wake notes

- LaunchAgents are paused while the Mac is asleep; they resume on
  wake. The `_changes` long-poll connection drops on sleep and the
  daemon reconnects from the persisted cursor, so no data loss.
- If you'd like to also keep running while *logged out*, switch
  from `~/Library/LaunchAgents` to `/Library/LaunchDaemons` and
  load with `sudo launchctl bootstrap system <plist>`. Most desktop
  users don't need this.
- Ollama also goes to sleep with the system; this is fine — Stage
  2 calls during the catch-up burst will simply timeout once and
  fail open until Ollama comes back.

## Linux — systemd `--user`

systemd's per-user instance can keep services running as your user
without needing root. The catch: a normal user systemd manager
stops when your last login session ends. The fix is one command:

```bash
sudo loginctl enable-linger $USER   # services keep running after logout
```

**`~/.config/systemd/user/monomi-feed.service`**

```ini
[Unit]
Description=monomi npm _changes feed (user)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%h/monomi
ExecStart=%h/.local/bin/monomi feed \
  --catalog-dir %h/monomi/catalog \
  --max-concurrent 4
Environment=RUST_LOG=info
Environment=OLLAMA_HOST=http://localhost:11434
Environment=OLLAMA_MODEL=llama3.1
Restart=always
RestartSec=15
TimeoutStopSec=120

[Install]
WantedBy=default.target
```

**`~/.config/systemd/user/monomi-sync.service`**

```ini
[Unit]
Description=monomi → R2 sync (user)

[Service]
Type=oneshot
ExecStart=/usr/bin/rclone sync \
  %h/monomi/catalog \
  r2:monomi-catalog \
  --checksum \
  --transfers 16 \
  --checkers 32 \
  --exclude feed-state.json \
  --exclude '*.tmp'
```

**`~/.config/systemd/user/monomi-sync.timer`**

```ini
[Unit]
Description=monomi → R2 sync (every 60s)

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=10s

[Install]
WantedBy=timers.target
```

Enable:

```bash
systemctl --user daemon-reload
systemctl --user enable --now monomi-feed.service
systemctl --user enable --now monomi-sync.timer

journalctl --user -u monomi-feed -f
systemctl --user list-timers monomi-sync
```

### Linux suspend / wake notes

- Like macOS, the daemon pauses on suspend and reconnects on wake.
- `loginctl enable-linger` is one-time; you don't need to redo it.
- If Ollama runs as a separate systemd-user service, declare a
  dependency in the feed unit: `After=ollama.service` /
  `Requires=ollama.service`.

## Verifying the local setup

```bash
# Confirm Ollama is actually being asked
journalctl --user -u monomi-feed -f --output cat \
  | rg 'stage 2'

# Or on macOS
tail -f ~/monomi/feed.log | grep 'stage 2'

# After a couple minutes, check the catalog is filling up:
find ~/monomi/catalog/verdicts -name '*.json' | wc -l

# And R2 has the same files:
rclone size r2:monomi-catalog
```

## Raspberry Pi specifics

The Pi is the natural fit for monomi's "always-on, low-power"
shape — the feed daemon is mostly I/O wait. Notes that go beyond
the generic Linux setup above:

### Hardware recommendations

| Model | Verdict |
|---|---|
| **Pi 5 / 8 GB** | ◎ Stage 2 with `qwen2.5:3b` works at ~3-5 tok/s; comfortable margin for everything |
| **Pi 5 / 4 GB** | ◯ Stage 1 only is fine; Stage 2 needs a 1-2B model |
| **Pi 4 / 8 GB** | ◯ Stage 2 works on slow small models; main bottleneck is memory bandwidth |
| **Pi 4 / 4 GB** | △ Stage 1 only recommended; Ollama + 3B model can OOM under load |
| **Pi 4 / 2 GB**, **Pi 3** | × Stage 1 only, and even that is tight if you also run other services |
| **Pi Zero 2 W** | × Stage 1 only and even that is borderline |

**Storage**: don't use an SD card for the catalog. `LocalDirCatalog`
writes thousands of small files per day, and SD cards (a) have
abysmal random-write throughput and (b) wear out fast. Mount a
USB 3 SSD (or NVMe via the Pi 5 PCIe slot) at `~/monomi/` and the
problem evaporates.

**Cooling**: the daemon idles at ~2% CPU but Ollama bursts to
100% during Stage 2. Active cooling (case fan or the official Pi 5
cooler) keeps you out of thermal throttling.

### Build (or grab) an ARM binary

Building Rust on the Pi works but takes ~10–15 minutes. Faster:
cross-compile on a dev box once and `scp` the binary.

**Cross-compile from a Linux x86_64 host:**

```bash
# One-time setup
rustup target add aarch64-unknown-linux-gnu      # Pi 4/5 64-bit
sudo apt install gcc-aarch64-linux-gnu

cat >> ~/.cargo/config.toml <<'EOF'
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"
EOF

# Build
cd ~/src/monomi
cargo build --release --target aarch64-unknown-linux-gnu -p monomi-cli
scp target/aarch64-unknown-linux-gnu/release/monomi pi@PI_HOST:~/.local/bin/
```

**Cross-compile from a Mac (using `cross`):**

```bash
cargo install cross
cd ~/src/monomi
cross build --release --target aarch64-unknown-linux-gnu -p monomi-cli
```

**Or just build on the Pi:** `cargo build --release -p monomi-cli`
in a tmux session and walk away. Subsequent rebuilds are fast.

### Stage 2 on the Pi — three honest options

Stage 2 is the only resource-hungry part. Pick by Pi model:

**Option A: Stage 1 only** (recommended for Pi 4 / smaller)

```ini
# In monomi-feed.service
ExecStart=%h/.local/bin/monomi feed \
  --catalog-dir %h/monomi/catalog \
  --stage1-only \
  --max-concurrent 2
```

Drops to ~50 MB RAM and ~5% CPU steady. Catalog gets decisive
verdicts (14 of the 32 rules are block-grade on their own); the
defer-to-stage2 ones land as Suspicious / Warn. About 80 % of
real-world supply-chain attacks get caught by Stage 1 alone.

**Option B: Tiny model with Ollama** (Pi 5 / 8 GB)

```bash
ollama pull qwen2.5:3b      # ~2 GB on disk, ~3 GB RAM loaded
# or smaller still:
ollama pull qwen2.5:1.5b    # ~1 GB on disk
```

In the systemd unit, set:

```ini
Environment=OLLAMA_HOST=http://localhost:11434
Environment=OLLAMA_MODEL=qwen2.5:3b
```

Roughly 5-15 minutes per Stage 2 call on Pi 5 CPU-only. monomi's
Stage 2 fires ~6 times per hour on the live npm feed, so the math
works — but if a burst of suspicious packages lands, the LLM
becomes a queue. Lower `--max-concurrent` to 2 so you don't pile
on Ollama requests.

**Option C: Stage 1 on Pi, Stage 2 elsewhere** (hybrid)

Run feed in `--stage1-only` on the Pi, then on your laptop / Mac
periodically pull Suspicious verdicts from R2 and re-adjudicate
with a heavier model. Requires the `monomi upgrade-stage2`
subcommand which is in the roadmap but not shipped yet.

### Minimum daemon footprint

After ~24 hours running the feed (Stage 1 only) on a Pi 4 with
an SSD:

| Resource | Steady state |
|---|---|
| RAM | 40-60 MB resident (mostly tokio + reqwest pools) |
| CPU | ~3% average, spikes to ~15% on each analyze |
| Network | ~50 MB/h in (mostly tarballs), ~5 MB/h out (R2 syncs) |
| Disk write | ~5 MB/h (catalog), bursty during R2 sync |
| Power | adds ~0.3 W over idle Pi 4 |

### Pi-specific systemd tweaks

The standard `monomi-feed.service` from the Linux section works
unchanged. Two optional additions for Pi:

```ini
[Service]
# Lower I/O priority so the daemon doesn't block interactive use.
IOSchedulingClass=best-effort
IOSchedulingPriority=7

# Auto-restart on OOM (Pi RAM is tight; ensures we recover).
OOMPolicy=continue
```

Also worth running monomi under `cgroup` memory limits if the Pi
hosts other services:

```ini
[Service]
MemoryHigh=256M
MemoryMax=512M
```

If you hit `MemoryMax`, systemd kills the daemon and the cursor
makes recovery clean.

### One-time SSD mount (Pi 5 with NVMe HAT, similar for USB SSD)

```bash
# Find the device
lsblk

# Format once
sudo mkfs.ext4 /dev/nvme0n1

# Auto-mount at boot via /etc/fstab
echo "UUID=$(sudo blkid -s UUID -o value /dev/nvme0n1) /home/pi/monomi ext4 defaults,noatime 0 2" \
  | sudo tee -a /etc/fstab
sudo mount -a
sudo chown -R pi:pi /home/pi/monomi
```

`noatime` saves a write per file read — small wins matter on flash.

## Free-tier reality check

The local-desktop variant is genuinely free — no hosted VM, no
LLM bill, just R2 storage at ~$0.27/year for the catalog. The
only ongoing cost is your machine being on, and the only failure
mode is your machine being off (which the cursor handles
gracefully on next boot).
