//! CouchDB-style `_changes` continuous-feed parser.
//!
//! Yields one `ChangeRow` per line. Heartbeat lines (empty) are
//! filtered out. Reconnects are the caller's responsibility.

use futures_util::StreamExt;
use serde::Deserialize;

use crate::{FeedError, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct ChangeRow {
    /// CouchDB sequence number. npm's replicate.npmjs.com emits these
    /// as integers; some compatible servers emit strings, so accept
    /// both via `u64`-only parsing for now (npm format).
    pub seq: u64,
    /// Package name (CouchDB doc id).
    pub id: String,
    #[serde(default)]
    pub deleted: bool,
}

pub struct Changes {
    rx: tokio::sync::mpsc::Receiver<Result<ChangeRow>>,
    _task: tokio::task::JoinHandle<()>,
}

impl Changes {
    /// Open a continuous `_changes` stream.
    ///
    /// `since` may be `None` (start from `0`) or a sequence number
    /// previously written by `Cursor`.
    pub async fn open(base_url: &str, since: Option<u64>) -> Result<Self> {
        let url = build_url(base_url, since);
        let client = reqwest::Client::builder()
            .user_agent(concat!("monomi-feed/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| FeedError::Http(e.to_string()))?;

        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| FeedError::Http(format!("{url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(FeedError::Http(format!("{url}: HTTP {}", resp.status())));
        }

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<ChangeRow>>(256);
        let task = tokio::spawn(async move {
            let mut stream = resp.bytes_stream();
            let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
            while let Some(chunk) = stream.next().await {
                match chunk {
                    Ok(bytes) => {
                        buf.extend_from_slice(&bytes);
                        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
                            let line: Vec<u8> = buf.drain(..=nl).collect();
                            let line = &line[..line.len().saturating_sub(1)];
                            if line.is_empty() {
                                continue; // heartbeat
                            }
                            match serde_json::from_slice::<ChangeRow>(line) {
                                Ok(row) => {
                                    if tx.send(Ok(row)).await.is_err() {
                                        return;
                                    }
                                }
                                Err(_) => {
                                    // CouchDB occasionally emits
                                    // `{"last_seq":N}` or similar
                                    // bookkeeping lines we don't model.
                                    // Skip silently.
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(FeedError::Http(format!("stream: {e}")))).await;
                        return;
                    }
                }
            }
        });

        Ok(Self { rx, _task: task })
    }

    pub async fn next(&mut self) -> Option<Result<ChangeRow>> {
        self.rx.recv().await
    }
}

fn build_url(base_url: &str, since: Option<u64>) -> String {
    let base = base_url.trim_end_matches('/');
    let since = since.map(|s| s.to_string()).unwrap_or_else(|| "0".into());
    format!("{base}?feed=continuous&include_docs=false&heartbeat=30000&since={since}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_url_with_since() {
        let u = build_url("https://replicate.npmjs.com/registry/_changes", Some(42));
        assert!(u.contains("since=42"));
        assert!(u.contains("feed=continuous"));
        assert!(u.contains("heartbeat=30000"));
    }

    #[test]
    fn deserializes_change_row() {
        let row: ChangeRow =
            serde_json::from_str(r#"{"seq":7,"id":"left-pad","changes":[{"rev":"1-x"}]}"#).unwrap();
        assert_eq!(row.seq, 7);
        assert_eq!(row.id, "left-pad");
        assert!(!row.deleted);
    }
}
