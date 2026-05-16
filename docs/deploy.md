# Deploying the monomi feed daemon

End-to-end recipe for running the npm change-stream subscriber as a
long-lived process and mirroring its verdict catalog to Cloudflare
R2 (or any S3-compatible target). Estimated wall-clock setup time:
**~30 minutes** including R2 account work.

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
