#!/usr/bin/env bash
# Fetch the replay corpus declared in fixtures/corpus/manifest.json.
#
# The tarballs are gitignored — they literally are malware. This script
# downloads them from the public npm registry into fixtures/corpus/ so
# `cargo test --test corpus_replay -- --ignored` has something to run.
#
# NOTE: npm proactively unpublishes confirmed-malicious versions, so most
# historical incidents (ua-parser-js@0.7.29, event-stream wrapper of
# flatmap-stream, etc.) now return 404 from the registry. To still
# populate the corpus you currently need a mirror that snapshotted the
# versions before takedown — community options include:
#   - https://github.com/ossf/malicious-packages  (metadata only)
#   - http://web.archive.org/  (best-effort, sometimes has the tarball)
#   - Snyk Advisor / Phylum's research archive (account required)
# Wire one in by adding a fallback URL field to manifest.json entries.
#
# Usage:
#   scripts/fetch_corpus.sh           # fetch all
#   scripts/fetch_corpus.sh <id>...   # fetch a subset by manifest id

set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
manifest="$here/fixtures/corpus/manifest.json"
out_dir="$here/fixtures/corpus"

if [[ ! -f "$manifest" ]]; then
    echo "manifest not found: $manifest" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required" >&2
    exit 1
fi

mkdir -p "$out_dir"

filter='.entries[]'
if [[ $# -gt 0 ]]; then
    # Build a select() over the requested ids.
    ids="$(printf '"%s",' "$@" | sed 's/,$//')"
    filter=".entries[] | select(.id as \$i | [$ids] | index(\$i))"
fi

count=0
jq -r "$filter | .url + \"\\t\" + .tarball" "$manifest" \
    | while IFS=$'\t' read -r url tarball; do
        dest="$out_dir/$tarball"
        if [[ -s "$dest" ]]; then
            echo "have   $tarball"
            continue
        fi
        echo "fetch  $url"
        if ! curl -fsSL -o "$dest.partial" "$url"; then
            echo "  WARN: fetch failed (package may have been unpublished)" >&2
            rm -f "$dest.partial"
            continue
        fi
        mv "$dest.partial" "$dest"
        count=$((count + 1))
    done

echo "done."
