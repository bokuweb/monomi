//! The verdict catalog — content-addressed storage of `Verdict` JSON.
//!
//! Layout (see architecture.md):
//!
//! ```text
//! verdicts/by-integrity/<algo>/<bb>/<rest>.json   # primary key
//! verdicts/<eco>/<name>/<version>.json            # convenience pointer
//! index/latest.jsonl                              # rolling feed (24h)
//! ```
//!
//! Two concrete backends ship in V1:
//!
//! - `LocalDirCatalog` — read + write against a filesystem tree.
//!   Tests use this; production writers (`monomi publish`, `monomi-feed`)
//!   use it as a staging directory, then push to R2 with `rclone` /
//!   `aws s3 sync`. Keeps this crate free of any S3 SDK dependency.
//! - `HttpCatalogReader` — pure-`reqwest` reader against a public
//!   (or signed-URL-fronted) base URL. This is what `sakimori`'s proxy
//!   uses for the hot-path lookup.
//!
//! A future `monomi-catalog-s3` feature can add a direct-write S3
//! backend; not in V1 to keep the dep graph small.

mod error;
mod http_reader;
mod layout;
mod local_dir;
mod traits;

pub use error::{CatalogError, Result};
pub use http_reader::HttpCatalogReader;
pub use layout::{by_integrity_path, latest_index_path, nv_pointer_path, NvPointer};
pub use local_dir::LocalDirCatalog;
pub use traits::{CatalogReader, CatalogWriter};
