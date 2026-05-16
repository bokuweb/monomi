use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid tarball: {0}")]
    InvalidTarball(String),

    #[error("manifest parse: {0}")]
    Manifest(String),

    #[error("registry fetch: {0}")]
    Fetch(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("oversized: {what} ({size} > {limit})")]
    Oversized {
        what: &'static str,
        size: u64,
        limit: u64,
    },

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
