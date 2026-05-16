use thiserror::Error;

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(String),
    #[error("not found")]
    NotFound,
    #[error("invalid integrity: {0}")]
    InvalidIntegrity(String),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, CatalogError>;
